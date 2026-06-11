"""
BusinessLogicScanner — standalone utility class for detecting business logic flaws.

Does NOT extend ScannerBase. Provides six specialised testers that run against
recon data and return finding dicts compatible with DeduplicationEngine.

Testers:
  - WorkflowAnalyser:           Build state graphs from multi-step flows
  - FlowBypassTester:           Step skip, reorder, and repeat detection
  - RaceConditionTester:        Concurrent request race condition detection
  - PriceManipulationTester:    Negative quantity, price override, coupon stacking
  - CheckoutLogicTester:        Gift-card race, payment bypass, price consistency, invoice manipulation
"""

import itertools
import json
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from models.business_flow import AbusePattern, WorkflowCategory

from modules.utils import (
    finding, safe_get, safe_post, log, Colors,
    VerificationStage,
)


# ── Data structures ──────────────────────────────────────────────────────


@dataclass
class WorkflowNode:
    url: str
    page_type: str = ""  # checkout, register, coupon, transfer, generic
    forms: list[dict] = field(default_factory=list)


@dataclass
class WorkflowEdge:
    source: str  # source URL
    target: str  # target URL
    trigger: str = "navigate"  # navigate | form_submit
    form_data: dict | None = None


@dataclass
class WorkflowGraph:
    nodes: dict[str, WorkflowNode] = field(default_factory=dict)
    edges: list[WorkflowEdge] = field(default_factory=list)
    checkout_flows: list[list[str]] = field(default_factory=list)
    registration_flows: list[list[str]] = field(default_factory=list)
    coupon_flows: list[list[str]] = field(default_factory=list)
    transfer_flows: list[list[str]] = field(default_factory=list)

    def add_node(self, url: str, page_type: str = "", forms: list | None = None):
        if url not in self.nodes:
            self.nodes[url] = WorkflowNode(url=url, page_type=page_type, forms=forms or [])

    def add_edge(self, source: str, target: str, trigger: str = "navigate", form_data: dict | None = None):
        self.edges.append(WorkflowEdge(source=source, target=target, trigger=trigger, form_data=form_data))


@dataclass
class BypassResult:
    vuln_type: str = "Business Logic Flaw"
    title: str = ""
    url: str = ""
    severity: str = "high"
    details: str = ""
    evidence: str = ""
    parameter: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    verification_stage: str = "validated"
    step_skipped: str = ""
    step_expected: str = ""
    accessibility: str = ""  # true/false/semi


@dataclass
class RaceResult:
    url: str = ""
    data: dict | None = None
    concurrent_count: int = 10
    success_count: int = 0
    vulnerable: bool = False
    evidence: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    severity: str = "high"


@dataclass
class CheckoutResult:
    url: str = ""
    subtype: str = ""  # gift_card_race, payment_bypass, price_inconsistency, invoice_manipulation
    vulnerable: bool = False
    severity: str = "high"
    details: str = ""
    evidence: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)


# ── Flow keywords ─────────────────────────────────────────────────────────

_CHECKOUT_KEYWORDS = {"cart", "checkout", "payment", "confirm", "order", "review", "billing", "shipping", "complete"}
_REGISTER_KEYWORDS = {"register", "signup", "create-account", "sign-up", "create_account", "join", "invite"}
_COUPON_KEYWORDS = {"coupon", "discount", "promo", "referral", "promocode", "promo-code", "gift-card", "voucher"}
_TRANSFER_KEYWORDS = {"transfer", "fund", "withdraw", "deposit", "send", "pay", "tip", "donate", "refund"}

_RACE_TRIGGER_WORDS = {"redeem", "apply", "transfer", "submit", "vote", "claim", "purchase", "buy", "checkout", "confirm"}


# ── WorkflowAnalyser ─────────────────────────────────────────────────────


class WorkflowAnalyser:
    """Build directed state graphs from recon data."""

    def build_state_graph(
        self,
        urls: list[str],
        forms: list[dict],
        session: Any,
    ) -> WorkflowGraph:
        graph = WorkflowGraph()

        # ── Add all URLs as nodes ──────────────────────────────────────
        for url in urls:
            page_type = self._classify_url(url)
            matched_forms = [f for f in forms if self._form_matches_url(f, url)]
            graph.add_node(url, page_type=page_type, forms=matched_forms)

        # ── Form-based edges: action follows from a page ───────────────
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            if not action:
                continue
            resolved_action = urljoin(urls[0] if urls else "", action)
            if resolved_action not in graph.nodes:
                pt = self._classify_url(resolved_action)
                graph.add_node(resolved_action, page_type=pt, forms=[form])

            for node_url in graph.nodes:
                if node_url != resolved_action:
                    form_data = self._form_to_data(form)
                    graph.add_edge(node_url, resolved_action, trigger="form_submit", form_data=form_data)

        # ── Redirect chain edges ───────────────────────────────────────
        try:
            chain_edges = self._detect_redirect_chains(urls, session)
            for src, dst in chain_edges:
                if src not in graph.nodes:
                    graph.add_node(src, page_type=self._classify_url(src))
                if dst not in graph.nodes:
                    graph.add_node(dst, page_type=self._classify_url(dst))
                graph.add_edge(src, dst, trigger="redirect")
        except Exception:
            pass

        # ── Identify multi-step flows ──────────────────────────────────
        graph.checkout_flows = self._find_flows(graph, _CHECKOUT_KEYWORDS)
        graph.registration_flows = self._find_flows(graph, _REGISTER_KEYWORDS)
        graph.coupon_flows = self._find_flows(graph, _COUPON_KEYWORDS)
        graph.transfer_flows = self._find_flows(graph, _TRANSFER_KEYWORDS)

        return graph

    # ── Internal helpers ────────────────────────────────────────────────

    @staticmethod
    def _classify_url(url: str) -> str:
        path = urlparse(url).path.lower()
        for kw in _CHECKOUT_KEYWORDS:
            if kw in path:
                return "checkout"
        for kw in _REGISTER_KEYWORDS:
            if kw in path:
                return "register"
        for kw in _COUPON_KEYWORDS:
            if kw in path:
                return "coupon"
        for kw in _TRANSFER_KEYWORDS:
            if kw in path:
                return "transfer"
        return "generic"

    @staticmethod
    def _form_matches_url(form: dict, url: str) -> bool:
        action = form.get("action", "")
        if not action:
            return False
        path = urlparse(url).path
        return action in path or path in action

    @staticmethod
    def _form_to_data(form: dict) -> dict:
        data = {}
        for field in form.get("fields", []):
            name = field.get("name")
            if name:
                data[name] = field.get("value", "")
        return data

    @staticmethod
    def _detect_redirect_chains(urls: list[str], session: Any) -> list[tuple[str, str]]:
        """Fetch each URL (HEAD) and record redirect source → target."""
        chains = []
        for url in urls[:20]:  # Limit to avoid excessive requests
            try:
                resp = safe_get(session, url, allow_redirects=False, timeout=8)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if location:
                        resolved = urljoin(url, location)
                        chains.append((url, resolved))
            except Exception:
                continue
        return chains

    @staticmethod
    def _find_flows(graph: WorkflowGraph, keywords: set[str]) -> list[list[str]]:
        """BFS from any node matching keywords, collecting consecutive keyword paths."""
        flows = []
        for node_url, node in graph.nodes.items():
            if node.page_type in keywords or any(kw in node_url.lower() for kw in keywords):
                path = [node_url]
                visited = {node_url}
                queue: deque[tuple[str, list[str]]] = deque()
                queue.append((node_url, path))
                while queue:
                    current, trail = queue.popleft()
                    for edge in graph.edges:
                        if edge.source == current and edge.target not in visited:
                            next_url = edge.target
                            next_node = graph.nodes.get(next_url)
                            next_type = next_node.page_type if next_node else ""
                            if next_type in keywords or any(kw in next_url.lower() for kw in keywords):
                                new_trail = trail + [next_url]
                                visited.add(next_url)
                                if len(new_trail) >= 2:
                                    flows.append(new_trail)
                                queue.append((next_url, new_trail))
        # Deduplicate and return longest chains
        seen = set()
        unique = []
        for f in sorted(flows, key=len, reverse=True):
            key = " -> ".join(f)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


# ── FlowBypassTester ─────────────────────────────────────────────────────


class FlowBypassTester:
    """Test for step-skip, step-reorder, and step-repeat vulnerabilities."""

    def __init__(self, session: Any, timeout: int = 10):
        self.session = session
        self.timeout = timeout

    def test_step_skip(self, graph: WorkflowGraph, session: Any | None = None) -> list[BypassResult]:
        """Try to skip intermediate steps in multi-step flows."""
        results: list[BypassResult] = []
        sess = session or self.session
        all_flows = (
            graph.checkout_flows + graph.registration_flows +
            graph.coupon_flows + graph.transfer_flows
        )
        seen = set()

        for flow in all_flows:
            if len(flow) < 3:
                continue
            # Skip the middle step(s) — go from first to last
            first = flow[0]
            last = flow[-1]
            skip_key = f"{first}->{last}"
            if skip_key in seen:
                continue
            seen.add(skip_key)

            accessibility = self._try_direct_access(first, last, sess)
            if accessibility:
                ev = (
                    f"Accessed final state '{last}' directly from '{first}' "
                    f"without completing intermediate step(s): {' -> '.join(flow[1:-1])}"
                )
                steps = [
                    f"Start at: {first}",
                    f"Attempt direct navigation to: {last}",
                    f"Observe: " + (
                        "Full access granted — no authentication/authorization for intermediate steps"
                        if accessibility == "true"
                        else "Partial access — some state missing but no redirect to prerequisite"
                    ),
                    "Suggest implementing state-machine validation that enforces step ordering",
                ]
                results.append(BypassResult(
                    title=f"Business Logic: Step-Skip in {' -> '.join(flow)}",
                    url=last,
                    severity="high",
                    details=f"Multi-step flow allows skipping intermediate steps: {ev}",
                    evidence=ev,
                    steps_to_reproduce=steps,
                    step_skipped=" -> ".join(flow[1:-1]),
                    step_expected=flow[1],
                    accessibility="true" if accessibility == "true" else "semi",
                ))

        return results

    def test_step_reorder(self, graph: WorkflowGraph, session: Any | None = None) -> list[BypassResult]:
        """Try performing steps out of order."""
        results: list[BypassResult] = []
        sess = session or self.session
        all_flows = (
            graph.checkout_flows + graph.registration_flows +
            graph.coupon_flows + graph.transfer_flows
        )

        for flow in all_flows:
            if len(flow) < 3:
                continue
            # Try last step before first (e.g., apply coupon after checkout)
            last = flow[-1]
            mid = flow[len(flow) // 2]

            for attempt_url, label in [(mid, f"mid-step {mid}"), (last, f"final-step {last}")]:
                accessibility = self._try_direct_access(flow[0], attempt_url, sess)
                if accessibility:
                    ev = (
                        f"Step reorder possible: accessed '{attempt_url}' before completing "
                        f"prerequisites in flow: {' -> '.join(flow)}"
                    )
                    steps = [
                        f"Flow normally: {' -> '.join(flow)}",
                        f"Attempt reorder: access {attempt_url} before completing earlier steps",
                        f"Observe: " + (
                            "Step accessible — flow ordering not enforced"
                            if accessibility == "true"
                            else "Partially accessible — constraints missing"
                        ),
                        "Enforce server-side state-machine validation across all steps",
                    ]
                    results.append(BypassResult(
                        title=f"Business Logic: Step-Reorder in {' -> '.join(flow)}",
                        url=attempt_url,
                        severity="high",
                        details=ev,
                        evidence=ev,
                        steps_to_reproduce=steps,
                        step_skipped="",
                        step_expected=flow[0],
                        accessibility="true" if accessibility == "true" else "semi",
                    ))

        return results

    def test_step_repeat(self, graph: WorkflowGraph, session: Any | None = None) -> list[BypassResult]:
        """Try repeating steps (same coupon twice, register same user, etc.)."""
        results: list[BypassResult] = []
        sess = session or self.session
        all_flows = (
            graph.checkout_flows + graph.registration_flows +
            graph.coupon_flows + graph.transfer_flows
        )
        seen_tests = set()

        for flow in all_flows:
            for edge in graph.edges:
                if edge.source not in flow and edge.target not in flow:
                    continue
                if not edge.form_data:
                    continue
                test_key = f"{edge.source}::{edge.target}::{json.dumps(edge.form_data, sort_keys=True)}"
                if test_key in seen_tests:
                    continue
                seen_tests.add(test_key)

                try:
                    # First submission
                    r1 = safe_post(sess, edge.target, data=edge.form_data, timeout=self.timeout)
                    # Second identical submission
                    r2 = safe_post(sess, edge.target, data=edge.form_data, timeout=self.timeout)

                    if r1 and r2 and r2.status_code in (200, 201, 202) and r2.status_code == r1.status_code:
                        body_keywords = ["success", "applied", "created", "confirmed", "thank"]
                        body1 = (r1.text or "").lower()
                        body2 = (r2.text or "").lower()
                        both_success = any(kw in body1 for kw in body_keywords) and any(kw in body2 for kw in body_keywords)
                        if both_success:
                            ev = (
                                f"Repeat action succeeded: {edge.target} accepted duplicate "
                                f"submission of {edge.form_data}"
                            )
                            steps = [
                                f"POST {edge.target} with data: {edge.form_data}",
                                f"Repeat POST {edge.target} with identical data",
                                f"Observe: both requests returned success — idempotency not enforced",
                                "Implement idempotency keys or server-side deduplication for state-changing operations",
                            ]
                            results.append(BypassResult(
                                title=f"Business Logic: Step-Repeat at {edge.target}",
                                url=edge.target,
                                severity="medium",
                                details=ev,
                                evidence=ev,
                                steps_to_reproduce=steps,
                                parameter=",".join(edge.form_data.keys()),
                                accessibility="true",
                            ))
                except Exception:
                    continue

        return results

    # ── Internal ─────────────────────────────────────────────────────────

    def _try_direct_access(self, from_url: str, target_url: str, session: Any) -> str | None:
        """Try accessing target_url from from_url's referrer context.
        Returns 'true' (fully accessible), 'semi' (partial), or None (blocked)."""
        try:
            resp = safe_get(
                session, target_url, timeout=self.timeout,
                headers={"Referer": from_url},
                allow_redirects=False,
            )
        except Exception:
            return None
        if resp is None:
            return None
        if resp.status_code in (200, 201, 202, 204):
            body_lower = (resp.text or "").lower()
            # Check for access-denied indicators
            blocked_indicators = {"access denied", "forbidden", "unauthorized", "login required",
                                  "please log in", "not authorized", "permission denied"}
            if any(ind in body_lower for ind in blocked_indicators):
                return "semi"
            return "true"
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "").lower()
            # Redirect back to start = blocked
            if from_url.lower() in location or "login" in location:
                return None
            return "semi"
        return None


# ── RaceConditionTester ──────────────────────────────────────────────────


class RaceConditionTester:
    """Concurrent request race condition detection."""

    def __init__(self, session: Any, timeout: int = 10):
        self.session = session
        self.timeout = timeout

    def test_race_condition(
        self,
        url: str,
        data: dict | None = None,
        concurrent_count: int = 10,
        session: Any | None = None,
        method: str = "POST",
    ) -> RaceResult:
        """Send concurrent_count identical requests and count successes."""
        sess = session or self.session
        success_count = 0
        errors = 0
        responses: list[int] = []
        lock = threading.Lock()

        def fire():
            nonlocal success_count, errors
            try:
                if method.upper() == "POST":
                    resp = safe_post(sess, url, data=data or {}, timeout=self.timeout)
                else:
                    resp = safe_get(sess, url, timeout=self.timeout)
                with lock:
                    responses.append(resp.status_code if resp else 0)
                    if resp and resp.status_code in (200, 201, 202, 204):
                        body = (resp.text or "").lower()
                        success_keywords = {"success", "applied", "created", "confirmed",
                                           "redeemed", "transferred", "claimed", "completed"}
                        if any(kw in body for kw in success_keywords):
                            success_count += 1
            except Exception:
                with lock:
                    errors += 1

        threads = []
        for _ in range(concurrent_count):
            t = threading.Thread(target=fire, daemon=True)
            threads.append(t)
            t.start()

        # Fire all at once by staggering start
        for t in threads:
            t.join()

        vulnerable = success_count > 1
        evidence_parts = [
            f"URL: {url}",
            f"Method: {method}",
            f"Concurrent requests: {concurrent_count}",
            f"Successful responses: {success_count}",
            f"HTTP statuses: {responses}",
            f"Errors: {errors}",
        ]
        if vulnerable:
            evidence_parts.append("VULNERABLE: Resource was consumed more than once by concurrent requests")

        steps = [
            f"Send {concurrent_count} concurrent {method.upper()} requests to {url}",
            {
                "data": data
            } if data else {},
            f"Check how many succeeded (>{1} suggests race condition)",
            "If vulnerable, implement database-level locking or idempotency keys",
        ]
        steps = [str(s) for s in steps]

        return RaceResult(
            url=url,
            data=data,
            concurrent_count=concurrent_count,
            success_count=success_count,
            vulnerable=vulnerable,
            evidence="\n".join(evidence_parts),
            steps_to_reproduce=steps,
            severity="critical" if vulnerable else "info",
        )

    def find_race_candidates(self, urls: list[str], forms: list[dict]) -> list[str]:
        """Identify endpoints likely to be race condition targets."""
        candidates: list[str] = []
        seen = set()

        for url in urls:
            path = urlparse(url).path.lower()
            path_segments = path.split("/")
            if any(t in path_segments for t in _RACE_TRIGGER_WORDS):
                if url not in seen:
                    candidates.append(url)
                    seen.add(url)

        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            if method != "POST":
                continue
            if not action:
                continue
            fields = form.get("fields", [])
            field_names = [f.get("name", "").lower() for f in fields if f.get("name")]

            # Forms with hidden quantity/amount fields
            has_quantity = any(n in ("quantity", "amount", "qty", "count", "price") for n in field_names)
            # Forms with idempotency-like fields (nonce, idempotency_key, etc.)
            has_nonce = any("nonce" in n or "token" in n or "idempot" in n or "csrf" in n for n in field_names)

            if has_quantity or has_nonce:
                resolved = urljoin(urls[0] if urls else "", action) if not action.startswith("http") else action
                if resolved not in seen:
                    candidates.append(resolved)
                    seen.add(resolved)

            # POST endpoints with single-action semantics
            action_path = urlparse(action).path.lower()
            path_segments = action_path.split("/")
            if any(t in path_segments for t in _RACE_TRIGGER_WORDS):
                resolved = urljoin(urls[0] if urls else "", action) if not action.startswith("http") else action
                if resolved not in seen:
                    candidates.append(resolved)
                    seen.add(resolved)

        return candidates


# ── PriceManipulationTester ──────────────────────────────────────────────


class PriceManipulationTester:
    """Test for price manipulation vulnerabilities."""

    def __init__(self, session: Any, timeout: int = 10):
        self.session = session
        self.timeout = timeout

    # ── Price-related field names ───────────────────────────────────────

    PRICE_FIELDS = {"price", "amount", "total", "subtotal", "discount", "fee",
                    "tax", "shipping", "grand_total", "unit_price", "cost",
                    "value", "charge", "payment_amount", "currency_amount"}

    # ── Negative quantity ───────────────────────────────────────────────

    def test_negative_quantity(self, url: str, form_data: dict, session: Any | None = None) -> bool:
        """Submit negative quantities in purchase forms.
        Returns True if total appears to decrease (vulnerable)."""
        sess = session or self.session
        qty_fields = [k for k in form_data if k.lower() in ("quantity", "qty", "count", "amount", "num", "number")]

        for field in qty_fields:
            original_value = form_data[field]
            try:
                original_int = int(original_value) if original_value else 1
            except (ValueError, TypeError):
                continue

            negative_payloads = [str(-abs(original_int)), str(-abs(original_int) - 1), "-1", "-999"]
            for neg_val in negative_payloads:
                modified = dict(form_data)
                modified[field] = neg_val
                try:
                    resp = safe_post(sess, url, data=modified, timeout=self.timeout)
                    if resp and resp.status_code in (200, 201, 202):
                        body = (resp.text or "").lower()
                        # Check if total decreased or went negative
                        total_indicators = {"negative", "credit", "-$", "refund", "reduced",
                                           "total", "-0.", "decreased"}
                        if any(ind in body for ind in total_indicators):
                            return True
                        # Check for error messages that suggest validation exists
                        error_indicators = {"invalid quantity", "positive", "greater than", "minimum", "must be"}
                        if any(ind in body for ind in error_indicators):
                            continue
                        # If no error and we got a success response, likely vulnerable
                        if any(kw in body for kw in ("success", "added", "updated", "checkout", "order", "cart")):
                            return True
                except Exception:
                    continue

        return False

    # ── Price override ──────────────────────────────────────────────────

    def test_price_override(self, url: str, field_name: str, session: Any | None = None) -> bool:
        """Try overriding price fields in POST data.
        Returns True if price override succeeded."""
        sess = session or self.session

        # Try various price override values
        override_values = ["0", "0.01", "1", "-1", "-100", "999999"]
        # Try adding unexpected price parameters
        for price_field in self.PRICE_FIELDS:
            for value in override_values:
                payload = {price_field: value, field_name: "test"}
                try:
                    resp = safe_post(sess, url, data=payload, timeout=self.timeout)
                    if resp and resp.status_code in (200, 201, 202):
                        body = (resp.text or "").lower()
                        success_kw = {"success", "order", "checkout", "confirmed", "complete", "receipt"}
                        if any(kw in body for kw in success_kw):
                            return True
                except Exception:
                    continue

        return False

    # ── Coupon stacking ─────────────────────────────────────────────────

    def test_coupon_stacking(self, url: str, form_data: dict, session: Any | None = None) -> bool:
        """Apply multiple coupons or same coupon twice.
        Returns True if coupon stacking is possible."""
        sess = session or self.session
        coupon_fields = [k for k in form_data if any(cw in k.lower() for cw in ("coupon", "promo", "discount", "voucher", "code", "gift"))]

        if not coupon_fields:
            coupon_fields = ["coupon", "promo_code", "discount_code"]

        vulnerable = False

        for field in coupon_fields:
            original_code = form_data.get(field, "")

            # Try applying same code twice (if we have a code)
            if original_code:
                payload = dict(form_data)
                payload[field] = original_code
                try:
                    r1 = safe_post(sess, url, data=payload, timeout=self.timeout)
                    r2 = safe_post(sess, url, data=payload, timeout=self.timeout)
                    if r1 and r2 and r2.status_code in (200, 201, 202):
                        body2 = (r2.text or "").lower()
                        if "already" not in body2 and any(kw in body2 for kw in ("applied", "discount", "reduced")):
                            vulnerable = True
                except Exception:
                    pass

            # Try stacking multiple different coupon codes
            stack_codes = ["TEST10", "WELCOME20", "DISCOUNT50", "SAVE100", "FREESHIP",
                          "TRY10", "NEWUSER", "FIRSTORDER", "10OFF", "20OFF"]
            for code in stack_codes:
                try:
                    payload = dict(form_data)
                    payload[field] = code
                    resp = safe_post(sess, url, data=payload, timeout=self.timeout)
                    if resp and resp.status_code in (200, 201, 202):
                        body = (resp.text or "").lower()
                        if any(kw in body for kw in ("applied", "discount", "reduced", "save", "off")):
                            vulnerable = True
                except Exception:
                    continue

            # Try expired/invalid coupon codes with special characters
            special_codes = ["' OR 1=1--", "${7*7}", "{{7*7}}", "<script>", "../../etc/passwd",
                            "NULL", "undefined", "NaN", "0", "true", "false"]
            for code in special_codes:
                try:
                    payload = dict(form_data)
                    payload[field] = code
                    resp = safe_post(sess, url, data=payload, timeout=self.timeout)
                    if resp and resp.status_code in (200, 201, 202):
                        body = (resp.text or "").lower()
                        if any(kw in body for kw in ("applied", "discount", "reduced", "save")):
                            vulnerable = True
                except Exception:
                    continue

        return vulnerable


# ── CheckoutLogicTester ──────────────────────────────────────────────────


class CheckoutLogicTester:
    """Checkout-specific logic flaw detection.

    Tests for:
      - Gift card / credit balance race conditions
      - Checkout payment step bypass
      - Price consistency across multi-step checkout
      - Invoice amount manipulation post-checkout
    """

    def __init__(self, session: Any, timeout: int = 10):
        self.session = session
        self.timeout = timeout

    # ── Gift card / credit balance race ──────────────────────────────────

    def test_gift_card_race(
        self,
        url: str,
        form_data: dict | None = None,
        session: Any | None = None,
        concurrent_count: int = 10,
    ) -> CheckoutResult:
        """Redeem same gift-card/coupon code concurrently across threads."""
        sess = session or self.session
        card_fields = [k for k in (form_data or {})
                       if any(w in k.lower() for w in ("gift", "card", "code", "voucher", "coupon"))]
        if not card_fields:
            return CheckoutResult(url=url, subtype="gift_card_race", vulnerable=False)

        success_count = 0
        errors = 0
        lock = threading.Lock()

        def redeem():
            nonlocal success_count, errors
            try:
                resp = safe_post(sess, url, data=form_data or {}, timeout=self.timeout)
                if resp and resp.status_code in (200, 201, 202):
                    body = (resp.text or "").lower()
                    ok_words = {"success", "applied", "redeemed", "credited", "confirmed", "balance"}
                    if any(w in body for w in ok_words):
                        with lock:
                            success_count += 1
            except Exception:
                with lock:
                    errors += 1

        threads = []
        for _ in range(concurrent_count):
            t = threading.Thread(target=redeem, daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        vulnerable = success_count > 1
        if not vulnerable:
            return CheckoutResult(url=url, subtype="gift_card_race", vulnerable=False)

        return CheckoutResult(
            url=url,
            subtype="gift_card_race",
            vulnerable=True,
            severity="critical",
            details=(
                "Gift card or coupon code was redeemed successfully "
                + str(success_count) + " out of " + str(concurrent_count)
                + " concurrent attempts — balance is not being deducted atomically"
            ),
            evidence=(
                "Concurrent redeems: " + str(concurrent_count)
                + " | Succeeded: " + str(success_count)
                + " | Errors: " + str(errors)
                + " | URL: " + url
            ),
            steps_to_reproduce=[
                "Obtain a valid gift card or coupon code.",
                "Send " + str(concurrent_count) + " concurrent POST requests to " + url
                + " with the code in the request body.",
                "Check how many requests succeed — if >1, the balance was consumed multiple times.",
                "Implement atomic database-level locking or idempotency keys per code.",
            ],
        )

    # ── Checkout payment step bypass ─────────────────────────────────────

    def test_checkout_payment_bypass(
        self,
        checkout_urls: list[str],
        graph: WorkflowGraph,
        session: Any | None = None,
    ) -> list[CheckoutResult]:
        """Try accessing order confirmation without completing payment step."""
        sess = session or self.session
        results: list[CheckoutResult] = []

        for flow in graph.checkout_flows:
            if len(flow) < 2:
                continue
            payment_step = None
            confirm_step = None
            for url in flow:
                lower = url.lower()
                if any(w in lower for w in ("pay", "payment", "bill", "charge")):
                    payment_step = url
                if any(w in lower for w in ("confirm", "complete", "receipt", "success", "thank")):
                    confirm_step = url
            if payment_step and confirm_step:
                try:
                    resp = safe_get(sess, confirm_step, timeout=self.timeout, raise_for_status=False)
                    if resp and resp.status_code in (200, 201, 202):
                        body = (resp.text or "").lower()
                        skip_words = {"order", "confirmed", "complete", "receipt", "thank you", "success"}
                        if any(w in body for w in skip_words):
                            results.append(CheckoutResult(
                                url=confirm_step,
                                subtype="payment_bypass",
                                vulnerable=True,
                                severity="critical",
                                details=(
                                    "Order confirmation page at " + confirm_step
                                    + " is accessible without completing the payment step at "
                                    + payment_step
                                ),
                                evidence=(
                                    "Accessed confirmation URL directly: " + confirm_step
                                    + " | HTTP " + str(resp.status_code)
                                ),
                                steps_to_reproduce=[
                                    "Identify the checkout flow: payment → confirmation.",
                                    "Send a GET request directly to " + confirm_step
                                    + " without completing payment at " + payment_step + ".",
                                    "If the confirmation page loads with order details, "
                                    "the payment step is bypassable.",
                                    "Implement server-side state validation that ensures "
                                    "payment is completed before serving the confirmation page.",
                                ],
                            ))
                except Exception:
                    pass

        return results

    # ── Price consistency across checkout steps ──────────────────────────

    def test_price_consistency(
        self,
        checkout_urls: list[str],
        graph: WorkflowGraph,
        session: Any | None = None,
    ) -> list[CheckoutResult]:
        """Detect price changes between cart and confirmation steps."""
        sess = session or self.session
        results: list[CheckoutResult] = []

        price_pattern = re.compile(
            r'(?:price|total|amount|subtotal|grand_total|cost|charge)[":\s]*([\d,]+\.?\d*)',
            re.IGNORECASE,
        )

        for flow in graph.checkout_flows:
            if len(flow) < 2:
                continue
            prices: dict[str, float] = {}
            for url in flow:
                try:
                    resp = safe_get(sess, url, timeout=self.timeout, raise_for_status=False)
                    if resp and resp.status_code == 200:
                        matches = price_pattern.findall(resp.text or "")
                        if matches:
                            cleaned = matches[-1].replace(",", "")
                            try:
                                prices[url] = float(cleaned)
                            except ValueError:
                                pass
                except Exception:
                    pass

            if len(prices) >= 2:
                values = list(prices.values())
                if max(values) != min(values):
                    differing = [u for u, v in prices.items() if v != values[0]]
                    results.append(CheckoutResult(
                        url=differing[0] if differing else flow[-1],
                        subtype="price_inconsistency",
                        vulnerable=True,
                        severity="high",
                        details=(
                            "Price changed across checkout steps: " + str(prices)
                            + " — indicates possible client-side price computation"
                        ),
                        evidence="Prices per step: " + str(prices),
                        steps_to_reproduce=[
                            "Walk through the checkout flow step by step.",
                            "Record the displayed price at each step.",
                            "If the price differs between steps, the total may be "
                            "computed client-side and can be manipulated.",
                            "Ensure the final price is always computed server-side "
                            "at the confirmation step.",
                        ],
                    ))

        return results

    # ── Invoice manipulation post-checkout ───────────────────────────────

    def test_invoice_manipulation(
        self,
        urls: list[str],
        session: Any | None = None,
    ) -> list[CheckoutResult]:
        """Check if invoice/order amounts can be modified after creation."""
        sess = session or self.session
        results: list[CheckoutResult] = []
        invoice_pattern = re.compile(
            r'(?:invoice|order|receipt|bill)/(\d+)',
            re.IGNORECASE,
        )

        for url in urls:
            match = invoice_pattern.search(url)
            if not match:
                continue
            invoice_id = match.group(1)
            price_override_fields = PriceManipulationTester.PRICE_FIELDS
            for field in list(price_override_fields)[:5]:
                payload = {field: "0", "invoice_id": invoice_id, "id": invoice_id}
                try:
                    resp = safe_post(sess, url, data=payload, timeout=self.timeout, raise_for_status=False)
                    if resp and resp.status_code in (200, 201, 202):
                        body = (resp.text or "").lower()
                        if any(w in body for w in ("updated", "modified", "success", "changed", "adjusted")):
                            results.append(CheckoutResult(
                                url=url,
                                subtype="invoice_manipulation",
                                vulnerable=True,
                                severity="critical",
                                details=(
                                    "Invoice " + invoice_id + " amount was modified "
                                    "post-checkout via parameter " + field + "=0"
                                ),
                                evidence=(
                                    "POST to " + url + " with {" + field + ": 0} "
                                    "returned HTTP " + str(resp.status_code)
                                ),
                                steps_to_reproduce=[
                                    "Complete a purchase and note the invoice/order ID.",
                                    "Send a POST request to " + url
                                    + " with the invoice ID and a modified price field.",
                                    "If the server accepts the modification, "
                                    "the invoice can be manipulated post-checkout.",
                                    "Implement server-side finalisation of invoices "
                                    "that prevents post-creation modification.",
                                ],
                            ))
                            break
                except Exception:
                    pass

        return results


# ── BusinessLogicScanner ─────────────────────────────────────────────────


class BusinessLogicScanner:
    """Standalone business logic vulnerability scanner.

    Does not extend ScannerBase. Returns finding dicts compatible with
    DeduplicationEngine. Run via run_all() or individual testers.
    """

    SCANNER_NAME = "business_logic"
    SCANNER_MATURITY = 2

    def __init__(self, config: dict | None = None, session: Any = None, recon: dict | None = None):
        self.config = config or {}
        self.session = session
        self.recon = recon or {}
        self.timeout = self.config.get("timeout", 10)

        self.workflow = WorkflowAnalyser()
        self.flow_bypass = FlowBypassTester(self.session, self.timeout)
        self.race = RaceConditionTester(self.session, self.timeout)
        self.price = PriceManipulationTester(self.session, self.timeout)
        self.checkout = CheckoutLogicTester(self.session, self.timeout)

    def run_all(
        self,
        urls: list[str],
        forms: list[dict],
        session: Any | None = None,
        concurrent_count: int = 10,
    ) -> list[dict]:
        """Run all testers against the target. Returns list of finding dicts."""
        findings: list[dict] = []
        sess = session or self.session
        if not sess:
            return findings

        # ── 1. Build workflow graph ─────────────────────────────────────
        graph = self.workflow.build_state_graph(urls, forms, sess)

        # ── 2. Flow bypass tests ────────────────────────────────────────
        skip_results = self.flow_bypass.test_step_skip(graph, sess)
        for r in skip_results:
            f = self._bypass_to_finding(r)
            if f:
                findings.append(f)

        reorder_results = self.flow_bypass.test_step_reorder(graph, sess)
        for r in reorder_results:
            f = self._bypass_to_finding(r)
            if f:
                findings.append(f)

        repeat_results = self.flow_bypass.test_step_repeat(graph, sess)
        for r in repeat_results:
            f = self._bypass_to_finding(r)
            if f:
                findings.append(f)

        # ── 3. Race condition tests ─────────────────────────────────────
        race_candidates = self.race.find_race_candidates(urls, forms)
        for candidate in race_candidates:
            # Try to find form data for this URL
            form_data = None
            for form in forms:
                action = form.get("action", "")
                resolved = urljoin(urls[0] if urls else "", action) if action else ""
                if resolved == candidate or action in candidate:
                    form_data = {f.get("name", ""): f.get("value", "") for f in form.get("fields", []) if f.get("name")}
                    break
            race_result = self.race.test_race_condition(
                candidate, data=form_data, concurrent_count=concurrent_count, session=sess,
            )
            f = self._race_to_finding(race_result)
            if f:
                findings.append(f)

        # ── 4. Price manipulation tests ─────────────────────────────────
        tested_price_urls = set()
        for form in forms:
            action = form.get("action", "")
            if not action:
                continue
            resolved = urljoin(urls[0] if urls else "", action) if not action.startswith("http") else action
            if resolved in tested_price_urls:
                continue
            tested_price_urls.add(resolved)

            form_data = {f.get("name", ""): f.get("value", "") for f in form.get("fields", []) if f.get("name")}
            if not form_data:
                continue

            # Negative quantity
            try:
                if self.price.test_negative_quantity(resolved, form_data, sess):
                    f = self._price_finding("Negative Quantity", resolved, form_data)
                    if f:
                        findings.append(f)
            except Exception:
                pass

            # Price override — test each param name
            for field_name in form_data:
                try:
                    if self.price.test_price_override(resolved, field_name, sess):
                        f = self._price_finding("Price Override", resolved, {field_name: form_data[field_name]})
                        if f:
                            findings.append(f)
                except Exception:
                    pass

            # Coupon stacking
            try:
                if self.price.test_coupon_stacking(resolved, form_data, sess):
                    f = self._price_finding("Coupon Stacking", resolved, form_data)
                    if f:
                        findings.append(f)
            except Exception:
                pass

        # ── 5. Checkout-specific tests ────────────────────────────────────
        checkout_urls = [u for u in urls if any(kw in u.lower() for kw in _CHECKOUT_KEYWORDS)]

        try:
            # Gift card / credit balance race
            for form in forms:
                action = form.get("action", "")
                if not action:
                    continue
                resolved = urljoin(urls[0] if urls else "", action) if not action.startswith("http") else action
                form_data = {f.get("name", ""): f.get("value", "") for f in form.get("fields", []) if f.get("name")}
                if form_data:
                    result = self.checkout.test_gift_card_race(resolved, form_data, sess, concurrent_count)
                    if result.vulnerable:
                        f = self._checkout_finding(result)
                        if f:
                            findings.append(f)

            # Payment step bypass
            bypass_results = self.checkout.test_checkout_payment_bypass(checkout_urls, graph, sess)
            for r in bypass_results:
                f = self._checkout_finding(r)
                if f:
                    findings.append(f)

            # Price consistency
            consistency_results = self.checkout.test_price_consistency(checkout_urls, graph, sess)
            for r in consistency_results:
                f = self._checkout_finding(r)
                if f:
                    findings.append(f)

            # Invoice manipulation
            invoice_results = self.checkout.test_invoice_manipulation(urls, sess)
            for r in invoice_results:
                f = self._checkout_finding(r)
                if f:
                    findings.append(f)
        except Exception:
            pass

        return findings

    # ── Finding builders ─────────────────────────────────────────────────

    @staticmethod
    def _bypass_to_finding(r: BypassResult) -> dict | None:
        if not r or not r.url:
            return None
        f = finding(
            vuln_type=r.vuln_type,
            url=r.url,
            severity=r.severity,
            details=r.details,
            evidence=r.evidence,
            steps_to_reproduce=r.steps_to_reproduce,
            verification_stage=r.verification_stage,
            parameter=r.parameter,
        )
        if f is None:
            return None
        f["title"] = r.title
        f["step_skipped"] = r.step_skipped
        f["step_expected"] = r.step_expected
        f["accessibility"] = r.accessibility
        # Map to AbusePattern based on title/type
        if "step-skip" in r.title.lower() or "step_skip" in r.title.lower():
            f["abuse_pattern"] = AbusePattern.STEP_SKIP.value
        elif "step-reorder" in r.title.lower() or "step_reorder" in r.title.lower():
            f["abuse_pattern"] = AbusePattern.STEP_REORDER.value
        elif "step-repeat" in r.title.lower() or "step_repeat" in r.title.lower():
            f["abuse_pattern"] = AbusePattern.STEP_REPEAT.value
        return f.to_dict()

    @staticmethod
    def _race_to_finding(r: RaceResult) -> dict | None:
        if not r or not r.url:
            return None
        if not r.vulnerable:
            return None
        f = finding(
            vuln_type="Race Condition",
            url=r.url,
            severity=r.severity,
            details=f"Concurrent requests succeeded {r.success_count}/{r.concurrent_count} times",
            evidence=r.evidence,
            steps_to_reproduce=r.steps_to_reproduce,
            verification_stage="validated",
        )
        if f is None:
            return None
        f["success_count"] = r.success_count
        f["concurrent_count"] = r.concurrent_count
        f["abuse_pattern"] = AbusePattern.RACE_CONDITION.value
        return f.to_dict()

    @staticmethod
    def _checkout_finding(self, r: CheckoutResult) -> dict | None:
        if not r or not r.url or not r.vulnerable:
            return None
        pattern_map = {
            "gift_card_race": AbusePattern.RACE_CONDITION,
            "payment_bypass": AbusePattern.STEP_SKIP,
            "price_inconsistency": AbusePattern.PRICE_OVERRIDE,
            "invoice_manipulation": AbusePattern.INVOICE_MANIPULATION,
        }
        f = finding(
            vuln_type="Business Logic: " + r.subtype.replace("_", " ").title(),
            url=r.url,
            severity=r.severity,
            details=r.details,
            evidence=r.evidence,
            steps_to_reproduce=r.steps_to_reproduce,
            verification_stage="validated",
        )
        if f is None:
            return None
        f["abuse_pattern"] = pattern_map.get(r.subtype, AbusePattern.BILLING_PARAMETER_INJECTION).value
        return f.to_dict()

    @staticmethod
    def _price_finding(subtype: str, url: str, form_data: dict) -> dict | None:
        details_map = {
            "Negative Quantity": (
                "Application accepted negative quantity values, potentially "
                "allowing attackers to receive credit instead of being charged"
            ),
            "Price Override": (
                "Price field was overridden in POST data — application accepted "
                "user-supplied price values instead of server-computed values"
            ),
            "Coupon Stacking": (
                "Multiple coupons applied or same coupon applied multiple times, "
                "bypassing intended one-per-order restrictions"
            ),
        }
        evidence_map = {
            "Negative Quantity": f"Submitted negative quantity to {url} with data: {form_data}",
            "Price Override": f"Manipulated price parameter in POST to {url}",
            "Coupon Stacking": f"Stacked coupons at {url} with data: {form_data}",
        }
        steps_map = {
            "Negative Quantity": [
                f"POST to {url} with negative quantity",
                f"Data: {form_data}",
                "Observe: total decreased or credit applied",
                "Validate that the application rejects negative quantities server-side",
            ],
            "Price Override": [
                f"POST to {url} with modified price parameter",
                f"Data: {form_data}",
                "Observe: price override accepted",
                "Ensure price is computed server-side, never accepted from client",
            ],
            "Coupon Stacking": [
                f"Apply multiple coupons at {url}",
                "Try same coupon code twice",
                "Try expired/invalid codes with special characters",
                "Implement one-coupon-per-order enforcement",
            ],
        }
        severity = "critical" if subtype == "Price Override" else "high"
        f = finding(
            vuln_type=f"Business Logic: {subtype}",
            url=url,
            severity=severity,
            details=details_map.get(subtype, ""),
            evidence=evidence_map.get(subtype, ""),
            steps_to_reproduce=steps_map.get(subtype, []),
            verification_stage="validated",
        )
        if f is None:
            return None
        pattern_map = {
            "Negative Quantity": AbusePattern.NEGATIVE_QUANTITY,
            "Price Override": AbusePattern.PRICE_OVERRIDE,
            "Coupon Stacking": AbusePattern.COUPON_STACKING,
        }
        f["abuse_pattern"] = pattern_map.get(subtype, AbusePattern.BILLING_PARAMETER_INJECTION).value
        return f.to_dict()

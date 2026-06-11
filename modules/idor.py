"""
IdorScanner — Insecure Direct Object Reference / BOLA detection.

Scans discovered URLs and form parameters for ID-like values (numeric,
UUID, email, username, base64, JWT), then tests for horizontal privilege
escalation, sequential enumeration, and encoded-ID manipulation.
"""

import base64
import json
import re
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

from models.finding import Finding
from modules.scanner_base import ScannerModuleBase
from modules.utils import (
    make_session, safe_get, safe_post, finding, log, Colors, _build_curl,
    build_role_sessions, get_role_session,
    safe_cookies_dict,
)
from models.evidence import AuthorizationComparisonEvidence, CompositeEvidence, EvidenceStatus

# ── ID parameter patterns ──────────────────────────────────────────────────────

ID_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("numeric", re.compile(
        r"[?&](?:id|userId|user_id|account|accountId|account_id|"
        r"org|orgId|org_id|uid|gid|pid|item|itemId|page|number|"
        r"num|asset|ref|document|doc|file|ticket|order|invoice|"
        r"customer|client|product|group|role|team|project|object)"
        r"(?:=|%3D)(\d+)",
        re.IGNORECASE,
    )),
    ("uuid", re.compile(
        r"(?:=|%3D)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{4}-[0-9a-f]{12})",
        re.IGNORECASE,
    )),
    ("email", re.compile(
        r"[?&](?:email|mail|user|account|contact|login)"
        r"(?:=|%3D)([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        re.IGNORECASE,
    )),
    ("username", re.compile(
        r"[?&](?:username|user|name|login|handle|nick|account)"
        r"(?:=|%3D)([a-zA-Z][a-zA-Z0-9_.-]{2,})",
        re.IGNORECASE,
    )),
    ("base64", re.compile(
        r"(?:=|%3D)([A-Za-z0-9+/]{20,}={0,2})",
    )),
    ("jwt", re.compile(
        r"(?:=|%3D)(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
    )),
]

# Fields to probe in form bodies
FORM_ID_FIELDS = [
    "id", "user_id", "userId", "account", "accountId", "uid",
    "customer_id", "product_id", "order_id", "ticket_id", "ref",
]

SEQUENTIAL_DELTAS = [-1, 1, -100, 100]

# Cross-resource type ID substitution patterns
# e.g. accessing /orders/123 with /user/123 or /api/v2/accounts/123
CROSS_RESOURCE_PATTERNS = [
    ("/users/{id}", "/orders/{id}"),
    ("/users/{id}", "/api/v1/users/{id}"),
    ("/api/v1/users/{id}", "/api/v2/users/{id}"),
    ("/users/{id}/profile", "/users/{id}/settings"),
    ("/accounts/{id}", "/orders?user_id={id}"),
    ("/customers/{id}", "/invoices?customer={id}"),
]

# Mass assignment fields to test (fields that should be read-only)
MASS_ASSIGNMENT_FIELDS = [
    "owner_id", "user_id", "userId", "role", "roles", "admin",
    "is_admin", "is_admin", "permissions", "group", "groups",
    "account_type", "plan", "tier", "subscription",
    "creator_id", "author_id", "created_by", "updated_by",
    "locked", "locked_by", "deleted", "disabled",
]

# ── Scanner class ──────────────────────────────────────────────────────────────

class IdorScanner(ScannerModuleBase):
    """Scanner for Insecure Direct Object Reference vulnerabilities."""

    def __init__(self, config: dict, recon_data: dict, container=None):
        super().__init__(config, recon_data, container=container)
        self.cookies_alt: Optional[dict] = self._parse_cookies_alt()
        self.session_alt: Any = None
        if self.cookies_alt:
            self.session_alt = make_session(config)
            self.session_alt.cookies.update(self.cookies_alt)

        # Phase 5: role-based sessions for ownership validation
        self.role_sessions = build_role_sessions(config, base_session=self.session)
        self.current_role = config.get("role", None) or "default"

    # ── Helpers ───────────────────────────────────────────────────────────

    def _parse_cookies_alt(self) -> Optional[dict]:
        cookies_str = self.config.get("cookies_alt", "")
        if not cookies_str:
            return None
        cookies: dict[str, str] = {}
        for part in cookies_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    def _try_decode_base64(self, value: str) -> Optional[str]:
        try:
            decoded = base64.b64decode(value).decode("utf-8", errors="ignore")
            if decoded and any(c.isalpha() for c in decoded):
                return decoded
        except Exception:
            pass
        return None

    def _try_decode_jwt(self, value: str) -> Optional[dict]:
        parts = value.split(".")
        if len(parts) != 3:
            return None
        try:
            payload_b64 = parts[1]
            missing = len(payload_b64) % 4
            if missing:
                payload_b64 += "=" * (4 - missing)
            decoded = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
            return decoded
        except Exception:
            return None

    def _find_user_id_refs(self, decoded: str) -> list[str]:
        """Return substrings that look like numeric IDs or known ID field values."""
        found: list[str] = []
        for match in re.finditer(r'"(?:id|user_id|userId|uid|account|role|group)"\s*:\s*"?(\d+)"?', decoded):
            found.append(match.group(1))
        for match in re.finditer(r'(?<![A-Za-z0-9])(\d{2,9})(?![A-Za-z0-9])', decoded):
            found.append(match.group(1))
        return found

    # ── Candidate discovery ───────────────────────────────────────────────

    def _find_id_parameters(self) -> list[dict]:
        """Scan all discovered URLs and form fields for ID-like values."""
        candidates: list[dict] = []
        seen: set[tuple[str, str]] = set()

        # URL parameters
        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for param, values in query_params.items():
                val = values[0] if values else ""
                if not val:
                    continue
                id_type = self._classify_param(param, val)
                if id_type:
                    key = (param, val)
                    if key not in seen:
                        seen.add(key)
                        candidates.append({
                            "source": "url",
                            "url": url,
                            "param": param,
                            "value": val,
                            "type": id_type,
                            "method": "GET",
                        })

            # Path-based IDs (/users/123)
            path_match = re.search(
                r"/(?:users|accounts|orgs|organisations|entities|"
                r"customers|products|orders|tickets|items|documents|"
                r"files|profiles)/(\d+)",
                url, re.IGNORECASE,
            )
            if path_match:
                val = path_match.group(1)
                key = ("__path__", val)
                if key not in seen:
                    seen.add(key)
                    candidates.append({
                        "source": "url_path",
                        "url": url,
                        "param": "__path__",
                        "value": val,
                        "type": "numeric",
                        "method": "GET",
                    })

        # Form fields
        for form in self.recon.get("forms", []):
            action = form.get("action", "")
            if action and not self._in_scope(action):
                continue
            method = form.get("method", "get").upper()
            for field in form.get("fields", []):
                fname = field.get("name", "")
                fvalue = field.get("value", "")
                if fname.lower() in FORM_ID_FIELDS and fvalue:
                    id_type = self._classify_param(fname, fvalue)
                    key = (fname, fvalue)
                    if key not in seen:
                        seen.add(key)
                        candidates.append({
                            "source": "form",
                            "url": action or self.base_url,
                            "param": fname,
                            "value": fvalue,
                            "type": id_type or "numeric",
                            "method": method,
                            "form": form,
                        })

        # Fuzzed parameters from recon — active params discovered by
        # parameter fuzzing, injected as URL-source candidates
        for fuzz_url, fuzz_params in self.recon.get("fuzzed_params", {}).items():
            if not self._in_scope(fuzz_url):
                continue
            for param_name in fuzz_params:
                key = (param_name, "fuzzed")
                if key not in seen:
                    seen.add(key)
                    candidates.append({
                        "source": "fuzzed",
                        "url": fuzz_url,
                        "param": param_name,
                        "value": "1",
                        "type": self._classify_param(param_name, "1") or "numeric",
                        "method": "GET",
                    })

        return candidates

    def _classify_param(self, param: str, value: str) -> Optional[str]:
        """Classify a parameter value by ID type."""
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", value, re.IGNORECASE):
            return "uuid"
        if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            return "email"
        if re.match(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", value):
            return "jwt"
        if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", value):
            decoded = self._try_decode_base64(value)
            if decoded:
                return "base64"
        if value.isdigit() and 0 < len(value) <= 12:
            return "numeric"
        return None

    # ── Horizontal privilege escalation ───────────────────────────────────

    def scan_horizontal_privesc(self, findings: list[dict], candidates: list[dict]) -> None:
        """Replay each candidate request with a second user's session
        (--cookies-alt). A 200 response with different content suggests
        horizontal privilege escalation.
        """
        if not self.session_alt:
            return

        for c in candidates:
            url = c["url"]
            if c["source"] == "url_path":
                url = url

            resp_self = safe_get(
                self.session, url, self.timeout, raise_for_status=False,
            )
            if not resp_self or resp_self.status_code != 200:
                continue

            resp_alt = safe_get(
                self.session_alt, url, self.timeout, raise_for_status=False,
            )
            if not resp_alt or resp_alt.status_code != 200:
                continue

            similarity = self._jaccard_similarity(resp_self.text, resp_alt.text)
            if similarity < 0.85:
                f_dict = finding(
                    "IDOR - Horizontal Privilege Escalation",
                    url, "critical",
                    f"Parameter '{c['param']}' ({c['type']}) returned HTTP 200 "
                    f"for second user with differing content.",
                    f"Second user accessed: {resp_alt.text[:120]}",
                    verification_stage="validated",
                    parameter=c['param'],
                    request=_build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=resp_alt.text[:500],
                    steps_to_reproduce=[
                        f"Authenticate as primary user and send GET request to {url}",
                        f"Note the response length ({len(resp_self.text)} chars) and status ({resp_self.status_code})",
                        f"Replace session with second user's credentials",
                        f"Send GET request to the same URL {url}",
                        f"Observe that HTTP {resp_alt.status_code} is returned with {len(resp_alt.text)} chars — content differs from primary user",
                        "This confirms horizontal privilege escalation: the endpoint returns different users' data without ownership verification",
                    ],
                )
                if f_dict:
                    ev = AuthorizationComparisonEvidence(
                        original_user="primary",
                        target_user="secondary",
                        original_status=resp_self.status_code,
                        target_status=resp_alt.status_code,
                        content_different=True,
                        ownership_violated=True,
                        original_body_excerpt=resp_self.text[:300],
                        target_body_excerpt=resp_alt.text[:300],
                        description=f"Horizontal privilege escalation: secondary user accessed {url}",
                        status=EvidenceStatus.VERIFIED,
                    )
                    ev_list = f_dict.get("evidence", [])
                    if isinstance(ev_list, str):
                        ev_list = [ev_list] if ev_list else []
                    ev_list.append(ev)
                    f_dict["evidence"] = ev_list
                    if hasattr(self, '_container') and self._container and self._container.evidence_engine:
                        self._container.evidence_engine.store(ev)
                        self._container.evidence_engine.link_to_finding(ev, f_dict.get("fingerprint", ""))
                    self._append_finding(findings, f_dict)
                log(f"  [IDOR Horiz] {url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)

    # ── Sequential ID enumeration ─────────────────────────────────────────

    def scan_sequential_enum(self, findings: list[dict], candidates: list[dict]) -> None:
        """For numeric ID candidates, test ID ±1 and ID ±100."""
        for c in candidates:
            if c["type"] not in ("numeric", "base64"):
                continue
            self._test_sequential(findings, c)

    def _test_sequential(self, findings: list[dict], c: dict) -> None:
        original_val = c["value"]
        if c["type"] == "base64":
            decoded = self._try_decode_base64(original_val)
            if not decoded:
                return
            user_ids = self._find_user_id_refs(decoded)
            if not user_ids:
                return
            for uid in user_ids[:2]:
                for delta in SEQUENTIAL_DELTAS:
                    try:
                        new_uid = str(int(uid) + delta)
                        new_decoded = decoded.replace(uid, new_uid, 1)
                        new_val = base64.b64encode(new_decoded.encode()).decode()
                        self._replay_and_check(findings, c, original_val, new_val)
                    except ValueError:
                        continue
            return

        if not original_val.isdigit():
            return
        for delta in SEQUENTIAL_DELTAS:
            try:
                new_val = str(int(original_val) + delta)
            except ValueError:
                continue
            self._replay_and_check(findings, c, original_val, new_val)

    def _replay_and_check(self, findings: list[dict], c: dict,
                          original_val: str, new_val: str) -> None:
        """Replace the parameter value and check if the mutated resource is
        accessible, indicating an IDOR."""
        url = c["url"]
        param = c["param"]

        if c["source"] == "form":
            self._test_form_field(findings, c, original_val, new_val)
            return

        if param == "__path__":
            original_url = url
            test_url = url.replace(original_val, new_val, 1)
        else:
            original_url = self._inject_param(url, param, original_val)
            test_url = self._inject_param(url, param, new_val)

        baseline = safe_get(
            self.session, original_url, self.timeout, raise_for_status=False,
        )
        if not baseline or baseline.status_code != 200:
            return
        baseline_len = len(baseline.text)

        resp = safe_get(
            self.session, test_url, self.timeout, raise_for_status=False,
        )
        from modules.utils import _build_curl
        if not resp:
            return

        if (resp.status_code == 200
                and len(resp.text) > 300
                and abs(len(resp.text) - baseline_len) < 5000
                and resp.text != baseline.text):
            f = finding(
                "IDOR - Insecure Direct Object Reference",
                test_url, "critical",
                f"Parameter '{param}' changed from {original_val} to {new_val} "
                f"and returned accessible content.",
                f"HTTP {resp.status_code} - Response length: {len(resp.text)}",
                verification_stage="validated",
                parameter=param,
                request=_build_curl("GET", test_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)) if hasattr(self, 'session') else f"GET {test_url}",
                response_excerpt=resp.text[:500],
                steps_to_reproduce=[
                    f"Send GET request to {test_url} with parameter '{param}'={new_val}",
                    "Observe that the endpoint returns accessible content, indicating an insecure direct object reference",
                ],
            )
            # ── Semantic response analysis ──────────────────────────────────────
            if self.container and hasattr(self.container, 'semantic_analyzer'):
                try:
                    sa = self.container.semantic_analyzer
                    analysis = sa.analyze_idor_pair(
                        original_response=baseline.text,
                        target_response=resp.text,
                    )
                    if analysis.get("idor_detected") or analysis.get("patterns_found"):
                        if isinstance(f, dict):
                            f["_semantic_analysis"] = analysis
                        else:
                            object.__setattr__(f, "_semantic_analysis", analysis)
                except Exception:
                    pass
            self._append_finding(findings, f)
            log(f"  [IDOR Seq] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)

    def _test_form_field(self, findings: list[dict], c: dict,
                         original_val: str, new_val: str) -> None:
        form = c.get("form")
        if not form:
            return
        action = form.get("action", c["url"])
        method = form.get("method", "get").upper()
        field_name = c["param"]

        data = {
            f["name"]: (new_val if f["name"] == field_name else f.get("value", "test"))
            for f in form.get("fields", [])
            if f.get("name")
        }

        if method == "POST":
            resp = safe_post(self.session, action, data, self.timeout, raise_for_status=False)
        else:
            test_url = action + "?" + "&".join(f"{k}={v}" for k, v in data.items())
            resp = safe_get(self.session, test_url, self.timeout, raise_for_status=False)

        if resp and resp.status_code == 200 and len(resp.text) > 300:
            f = finding(
                "IDOR - Insecure Direct Object Reference",
                action, "critical",
                f"Form field '{field_name}' changed from {original_val} to {new_val} "
                f"and returned accessible content.",
                f"HTTP {resp.status_code}",
                verification_stage="validated",
                parameter=field_name,
                request=_build_curl(method, action, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)) if hasattr(self, 'session') else f"{method} {action}",
                response_excerpt=resp.text[:500],
                steps_to_reproduce=[
                    f"Submit {method} request to {action} with form field '{field_name}'={new_val}",
                    "Observe that the endpoint returns accessible content, indicating an insecure direct object reference",
                ],
            )
            # ── Semantic response analysis ──────────────────────────────────
            if self.container and hasattr(self.container, 'semantic_analyzer'):
                try:
                    sa = self.container.semantic_analyzer
                    result = sa.classify_response(resp.text, url=action)
                    if result and result.matched_patterns:
                        if isinstance(f, dict):
                            f["_semantic_analysis"] = result
                        else:
                            object.__setattr__(f, "_semantic_analysis", result)
                except Exception:
                    pass
            self._append_finding(findings, f)
            log(f"  [IDOR Form] {action[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)

    # ── Encoded ID manipulation (base64 / JWT) ────────────────────────────

    def scan_encoded_id_manipulation(self, findings: list[dict], candidates: list[dict]) -> None:
        """Detect base64 or JWT-encoded IDs, decode, modify, re-encode, replay."""
        for c in candidates:
            if c["type"] == "base64":
                self._test_base64_manipulation(findings, c)
            elif c["type"] == "jwt":
                self._test_jwt_manipulation(findings, c)

    def _test_base64_manipulation(self, findings: list[dict], c: dict) -> None:
        value = c["value"]
        decoded = self._try_decode_base64(value)
        if not decoded:
            return
        user_ids = self._find_user_id_refs(decoded)
        if not user_ids:
            return

        for uid in user_ids[:2]:
            try:
                new_uid = str(int(uid) + 1)
            except ValueError:
                continue
            if uid not in decoded:
                continue
            new_decoded = decoded.replace(uid, new_uid, 1)
            new_val = base64.b64encode(new_decoded.encode()).decode()
            self._replay_and_check(findings, c, value, new_val)

    def _test_jwt_manipulation(self, findings: list[dict], c: dict) -> None:
        value = c["value"]
        payload = self._try_decode_jwt(value)
        if not payload:
            return

        user_keys = ["id", "user_id", "userId", "sub", "uid", "account", "role", "group"]
        target_key = None
        target_val = None
        for key in user_keys:
            if key in payload and isinstance(payload[key], (int, str)):
                target_key = key
                target_val = payload[key]
                break

        if target_key is None:
            return

        try:
            new_val = str(int(str(target_val)) + 1)
        except (ValueError, TypeError):
            return

        modified = dict(payload)
        modified[target_key] = int(new_val) if isinstance(target_val, int) else new_val
        new_payload_b64 = base64.urlsafe_b64encode(
            json.dumps(modified).encode()
        ).decode().rstrip("=")
        parts = value.split(".")
        forged_jwt = f"{parts[0]}.{new_payload_b64}.{parts[2]}"

        self._replay_and_check(findings, c, value, forged_jwt)

    # ── Ownership validation (Phase 5) ────────────────────────────────────

    @staticmethod
    def _jaccard_similarity(text_a: str, text_b: str) -> float:
        """Compute Jaccard similarity on whitespace-tokenised word sets."""
        set_a = set(text_a.lower().split())
        set_b = set(text_b.lower().split())
        if not set_a and not set_b:
            return 1.0
        intersection = set_a & set_b
        union = set_a | set_b
        return len(intersection) / len(union) if union else 0.0

    def verify_ownership(self, findings: list[dict], candidates: list[dict]) -> None:
        """Explicit User A ↔ User B ownership comparison.
        
        For each candidate, sends the request as two different roles and
        compares responses. A 200 with different content indicates a
        verified IDOR (not merely detected).
        """
        if len(self.role_sessions) < 2:
            return

        roles = list(self.role_sessions.keys())
        default_role = self.current_role if self.current_role in self.role_sessions else roles[0]
        other_roles = [r for r in roles if r != default_role and r != "alt"]
        if not other_roles:
            return

        alt_role = other_roles[0]

        for c in candidates[:20]:
            url = c["url"]
            param = c["param"]

            if c["source"] == "form":
                continue

            test_url = url
            if param != "__path__":
                test_url = self._inject_param(url, param, c["value"])

            resp_a = safe_get(
                self.role_sessions[default_role], test_url,
                self.timeout, raise_for_status=False,
            )
            if not resp_a or resp_a.status_code != 200:
                continue

            resp_b = safe_get(
                self.role_sessions[alt_role], test_url,
                self.timeout, raise_for_status=False,
            )
            if not resp_b or resp_b.status_code != 200:
                continue

            similarity = self._jaccard_similarity(resp_a.text, resp_b.text)
            body_diff = similarity < 0.85
            if body_diff and len(resp_b.text) > 300:
                auth_evidence = AuthorizationComparisonEvidence(
                    original_user=default_role,
                    target_user=alt_role,
                    original_status=resp_a.status_code,
                    target_status=resp_b.status_code,
                    content_different=True,
                    ownership_violated=True,
                    original_body_excerpt=resp_a.text[:300],
                    target_body_excerpt=resp_b.text[:300],
                    description=f"Authorization check: {default_role} vs {alt_role} @ {test_url} — violation",
                    status=EvidenceStatus.VERIFIED,
                )
                f_dict = finding(
                    "IDOR - Ownership Verification",
                    test_url, "critical",
                    f"Parameter '{param}' accessible by both '{default_role}' and "
                    f"'{alt_role}' with differing content — verified ownership violation.",
                    f"Role A ({default_role}): {len(resp_a.text)} chars | "
                    f"Role B ({alt_role}): {len(resp_b.text)} chars",
                    verification_stage="verified",
                    parameter=param,
                    request=_build_curl("GET", test_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=resp_b.text[:500],
                    steps_to_reproduce=[
                        f"Authenticate as '{alt_role}'",
                        f"Send GET request to {test_url}",
                        "Observe that the endpoint returns another user's private data",
                        f"Compare with '{default_role}' response — content differs, confirming IDOR",
                    ],
                )
                if f_dict:
                    ev_list = f_dict.get("evidence", [])
                    if isinstance(ev_list, str):
                        ev_list = [ev_list] if ev_list else []
                    ev_list.append(auth_evidence)
                    f_dict["evidence"] = ev_list
                    # Update reproduction steps for submission readiness
                    f_dict["steps_to_reproduce"] = [
                        f"Authenticate as '{default_role}' (provide session token or cookie)",
                        f"Send GET request to {test_url} as '{default_role}' and note the response (HTTP {resp_a.status_code}, {len(resp_a.text)} chars)",
                        f"Replace the session token with '{alt_role}'s token",
                        f"Send GET request to the same URL {test_url} as '{alt_role}'",
                        f"Observe that the endpoint returns HTTP {resp_b.status_code} with {len(resp_b.text)} chars — different from '{default_role}'s response",
                        "This confirms an ownership violation — the server returns different users' data based on authentication context rather than resource ownership",
                    ]
                    if hasattr(self, '_container') and self._container and self._container.evidence_engine:
                        fp = self._container.evidence_engine.store(auth_evidence)
                        self._container.evidence_engine.link_to_finding(auth_evidence, f_dict.get("fingerprint", ""))
                    self._append_finding(findings, f_dict)
                log(f"  [IDOR Owner] {test_url[:80]} — {default_role} vs {alt_role}",
                    Colors.RED, verbose_only=True, verbose=self.verbose)

    # ── UUID prediction / enumeration ────────────────────────────────────

    def scan_uuid_enumeration(self, findings: list[dict], candidates: list[dict]) -> None:
        """For UUID-type ID candidates, try adjacent UUIDs by modifying
        the last character group (e.g., ...-0001 → ...-0002) and checking
        if the mutated resource is accessible.
        
        Real UUID prediction attacks exploit version-4 UUIDs' temporal
        or sequential components. We test the most common patterns:
        incrementing last group, flipping a character, and known
        sequential patterns from poorly-implemented UUID generators.
        """
        import uuid as uuid_lib
        for c in candidates:
            if c["type"] != "uuid":
                continue
            val = c["value"]
            # Try common UUID mutations:
            mutations = []
            try:
                u = uuid_lib.UUID(val)
                # Version-4 UUIDs: increment the clock_seq (last group)
                groups = val.split("-")
                if len(groups) == 5:
                    # Increment last group
                    last = groups[4]
                    if last.isalnum():
                        for delta in [1, 2, -1]:
                            try:
                                incremented = hex(int(last, 16) + delta)[2:].zfill(len(last))[:len(last)]
                                mutated = "-".join(groups[:4] + [incremented])
                                mutations.append(mutated)
                            except (ValueError, OverflowError):
                                continue
                    # Flip a character in group 3-4
                    for group_idx in [3, 4]:
                        g = groups[group_idx]
                        for char_pos in range(min(2, len(g))):
                            for flip_char in "0123456789abcdef":
                                if g[char_pos] != flip_char:
                                    flipped = g[:char_pos] + flip_char + g[char_pos+1:]
                                    mutated = list(groups)
                                    mutated[group_idx] = flipped
                                    mutations.append("-".join(mutated))
            except (ValueError, AttributeError):
                continue

            for mutated_val in mutations[:5]:
                self._replay_and_check(findings, c, val, mutated_val)

    # ── Cross-resource type ID substitution ──────────────────────────────

    def scan_cross_resource_idor(self, findings: list[dict], candidates: list[dict]) -> None:
        """Test if a user ID from one resource type works on another.
        
        Example: if /users/123 returns user data, check if /orders?user_id=123
        also works — order enumeration using the user ID discovered from
        the user profile endpoint. Or substitute the user's numeric ID as
        an admin_id or owner_id on different resource types.
        """
        for c in candidates:
            if c["type"] not in ("numeric", "uuid", "email"):
                continue
            val = c["value"]
            for pattern_from, pattern_to in CROSS_RESOURCE_PATTERNS:
                # Check if candidate URL matches pattern_from
                url = c["url"]
                if val not in url:
                    continue
                if pattern_from.replace("{id}", val) not in url:
                    continue
                # Build cross-resource URL
                cross_url = pattern_to.replace("{id}", val)
                full_cross = urljoin(url, cross_url)
                if not self._in_scope(full_cross):
                    continue
                resp = safe_get(self.session, full_cross, self.timeout,
                                raise_for_status=False)
                if resp and resp.status_code == 200 and len(resp.text) > 300:
                    f_dict = finding(
                        "IDOR - Cross-Resource Access",
                        full_cross, "critical",
                        f"User ID '{val}' from '{c['source']}' works on "
                        f"a different resource type: {full_cross}",
                        f"HTTP {resp.status_code} - {len(resp.text)} bytes",
                        verification_stage="validated",
                        parameter=c['param'],
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[
                            f"Get user ID {val} from {url}",
                            f"Use the same ID on a different resource: {full_cross}",
                            "Observe that the cross-resource access returns user data",
                            "This confirms the user ID is predictable and cross-resource access is possible",
                        ],
                    )
                    if f_dict:
                        self._append_finding(findings, f_dict)
                        log(f"  [IDOR Cross] {full_cross[:80]}", Colors.RED,
                            verbose_only=True, verbose=self.verbose)

    # ── Mass assignment testing ─────────────────────────────────────────

    def scan_mass_assignment(self, findings: list[dict]) -> None:
        """Test POST/PUT endpoints by sending read-only fields in the
        request body to see if they are accepted (mass assignment).
        
        E.g., sending {"owner_id": "another_user_id", "admin": true}
        in a profile update endpoint.
        """
        for form in self.recon.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            if method not in ("POST", "PUT", "PATCH"):
                continue
            if not action or not self._in_scope(action):
                continue
            fields = form.get("fields", [])
            existing_names = {f.get("name", "") for f in fields if f.get("name")}
            for ma_field in MASS_ASSIGNMENT_FIELDS:
                if ma_field in existing_names:
                    continue  # Already tested by normal form submission
                for test_value in ["another_user", "true", "1", "admin"]:
                    data = {}
                    for f in fields:
                        name = f.get("name", "")
                        data[name] = f.get("value", "test") or "test"
                    data[ma_field] = test_value
                    resp = safe_post(self.session, action, data=data,
                                     timeout=self.timeout,
                                     raise_for_status=False)
                    if resp and resp.status_code in (200, 201, 202):
                        # Check if the mass assignment field affected the response
                        marker = f'"{ma_field}"'
                        if marker in (resp.text or ""):
                            f_dict = finding(
                                "IDOR - Mass Assignment",
                                action, "high",
                                f"Endpoint accepts mass-assignment field "
                                f"'{ma_field}={test_value}' — read-only "
                                f"field was accepted in POST body",
                                f"Field '{ma_field}' accepted with value '{test_value}' "
                                f"(HTTP {resp.status_code})",
                                verification_stage="validated",
                                parameter=ma_field,
                                response_excerpt=(resp.text or "")[:500],
                                steps_to_reproduce=[
                                    f"Send POST to {action} with '{ma_field}={test_value}'",
                                    f"Observe that the read-only field is accepted — "
                                    f"HTTP {resp.status_code}",
                                    "An attacker can escalate privileges by modifying ",
                                    f"fields like {ma_field}",
                                ],
                            )
                            if f_dict:
                                self._append_finding(findings, f_dict)
                                log(f"  [IDOR MassAssign] {ma_field}={test_value} @ {action[:80]}",
                                    Colors.RED, verbose_only=True, verbose=self.verbose)
                            break

    # ── Stateful IDOR: create-then-access (Phase 5) ──────────────────────

    def scan_stateful_idor(self, findings: list[dict]) -> None:
        """Create a resource as one role, then test access as other roles.

        Identifies POST endpoints from forms and OpenAPI data, creates
        a resource with the default role, extracts the new resource ID
        from the response, and then tests GET/access with alternative
        roles. Catches IDORs that only manifest after resource creation
        (e.g., create a document as User A, then read it as User B).
        """
        if len(self.role_sessions) < 2:
            return

        roles = list(self.role_sessions.keys())
        default_role = self.current_role if self.current_role in self.role_sessions else roles[0]
        other_roles = [r for r in roles if r != default_role and r != "alt"]
        if not other_roles:
            return

        create_targets = self._find_stateful_create_targets()
        if not create_targets:
            return

        log(f"  [IDOR] Found {len(create_targets)} stateful create target(s)",
            Colors.CYAN, verbose_only=True, verbose=self.verbose)

        default_sess = self.role_sessions[default_role]

        for target in create_targets[:10]:
            url = target["url"]
            method = target.get("method", "POST")
            body = target.get("body", {})

            resp = self._try_stateful_create(default_sess, url, method, body)
            if resp is None:
                continue

            created_id = self._extract_created_id(resp.text, url)
            if not created_id:
                continue

            log(f"  [IDOR] Created resource @ {url} → id={created_id}",
                Colors.CYAN, verbose_only=True, verbose=self.verbose)

            for alt_role in other_roles:
                alt_sess = self.role_sessions[alt_role]
                self._try_stateful_access(findings, created_id, url,
                                          default_role, alt_role,
                                          default_sess, alt_sess)

    def _find_stateful_create_targets(self) -> list[dict]:
        """Find POST endpoints that likely create resources.

        Sources:
          1. Forms with POST method from recon_data
          2. OpenAPI POST endpoints from DiscoveryStore (``api_model`` records)
          3. Known creation path patterns (/api/*/create, /api/*/new)
        """
        targets: list[dict] = []
        seen_urls: set[str] = set()

        for form in self.recon.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            if method != "POST" or not action or not self._in_scope(action):
                continue
            if action in seen_urls:
                continue
            seen_urls.add(action)
            fields = form.get("fields", [])
            body = {f["name"]: (f.get("value", "test") or "test")
                    for f in fields if f.get("name")}
            targets.append({"url": action, "method": "POST", "body": body})

        if self.container and hasattr(self.container, 'discovery_store'):
            store = self.container.discovery_store
            for rec in store.get_by_category("api_model"):
                extra = rec.get("extra", {})
                if extra.get("method") != "POST":
                    continue
                api_url = self.base_url + extra.get("path", "")
                if not api_url or not self._in_scope(api_url):
                    continue
                if api_url in seen_urls:
                    continue
                seen_urls.add(api_url)
                targets.append({"url": api_url, "method": "POST", "body": {}})

        create_paths = ("/create", "/new", "/add", "/register", "/signup")
        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            path_lower = urlparse(url).path.lower()
            if any(cp in path_lower for cp in create_paths):
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                targets.append({"url": url, "method": "POST", "body": {}})

        return targets

    def _try_stateful_create(self, session: Any, url: str, method: str,
                             body: dict) -> Any | None:
        """Attempt to create a resource via POST.

        Returns the response on success (2xx), None otherwise.
        """
        try:
            if body:
                resp = session.post(url, json=body, timeout=self.timeout)
            else:
                resp = session.post(url, json={"name": "test", "title": "test"},
                                    timeout=self.timeout)
            if resp and resp.status_code in (200, 201, 202):
                return resp
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_created_id(response_text: str, url: str) -> str | None:
        """Extract a newly created resource ID from a JSON response.

        Looks for ``"id"``, ``"resourceId"``, ``"uid"`` at the top level
        or nested in a ``"data"`` / ``"result"`` wrapper. Returns None if
        no ID can be extracted.
        """
        if not response_text:
            return None
        try:
            parsed = json.loads(response_text)
        except (json.JSONDecodeError, ValueError):
            match = re.search(r'"id"\s*:\s*"?(\\d+)"?', response_text)
            return match.group(1) if match else None

        if isinstance(parsed, dict):
            for key in ("id", "resourceId", "resource_id", "uid", "ID"):
                val = parsed.get(key)
                if val is not None:
                    return str(val)
            data = parsed.get("data") or parsed.get("result")
            if isinstance(data, dict):
                for key in ("id", "resourceId", "resource_id", "uid", "ID"):
                    val = data.get(key)
                    if val is not None:
                        return str(val)
        return None

    def _try_stateful_access(self, findings: list[dict], created_id: str,
                              create_url: str, default_role: str, alt_role: str,
                              default_sess: Any, alt_sess: Any) -> None:
        """Try to access the created resource with an alternative role.

        Tests:
          1. GET on the created resource URL (if ID is in the path)
          2. GET with ID as a query parameter
          3. DELETE on the resource URL
        """
        access_urls = self._build_access_urls(create_url, created_id)
        alt_findings: list[dict] = []

        for access_url, access_method, desc in access_urls:
            resp_default = self._try_gql_method(default_sess, access_url, access_method)
            resp_alt = self._try_gql_method(alt_sess, access_url, access_method)

            if resp_default is None or resp_alt is None:
                continue

            if resp_alt.status_code == 200 and resp_default.status_code != 200:
                self._append_stateful_finding(findings, created_id, create_url,
                                               access_url, access_method, desc,
                                               default_role, alt_role,
                                               resp_default, resp_alt)
                alt_findings.append(True)
            elif resp_alt.status_code == 200 and resp_default.status_code == 200:
                similarity = self._jaccard_similarity(
                    resp_default.text, resp_alt.text)
                if similarity < 0.85 and len(resp_alt.text) > 300:
                    self._append_stateful_finding(findings, created_id, create_url,
                                                   access_url, access_method, desc,
                                                   default_role, alt_role,
                                                   resp_default, resp_alt)
                    alt_findings.append(True)

    @staticmethod
    def _build_access_urls(url: str, created_id: str) -> list[tuple[str, str, str]]:
        """Build candidate access URLs for testing with the created ID."""
        candidates: list[tuple[str, str, str]] = []
        base = url.rstrip("/")

        if base.endswith(("/create", "/new", "/add")):
            parent = base.rsplit("/", 1)[0]
        else:
            parent = base

        candidates.append((f"{parent}/{created_id}", "GET",
                           f"GET resource by ID ({created_id})"))
        candidates.append((f"{parent}/{created_id}", "DELETE",
                           f"DELETE resource by ID ({created_id})"))
        candidates.append((f"{url}?id={created_id}", "GET",
                           "GET with query param id"))
        candidates.append((f"{url}?resourceId={created_id}", "GET",
                           "GET with query param resourceId"))
        if "?" in url:
            candidates.append((f"{url}&id={created_id}", "GET",
                               "GET with appended id param"))
        return candidates

    @staticmethod
    def _try_gql_method(session: Any, url: str, method: str) -> Any | None:
        """Send an HTTP request and return the response, or None on failure."""
        try:
            if method == "GET":
                return session.get(url, timeout=30)
            elif method == "DELETE":
                return session.delete(url, timeout=30)
            elif method == "POST":
                return session.post(url, timeout=30)
            return None
        except Exception:
            return None

    def _append_stateful_finding(self, findings: list[dict], created_id: str,
                                  create_url: str, access_url: str,
                                  access_method: str, desc: str,
                                  default_role: str, alt_role: str,
                                  resp_a: Any, resp_b: Any) -> None:
        """Create and append a stateful IDOR finding."""
        f_dict = finding(
            "IDOR - Stateful Resource Access",
            access_url, "critical",
            f"Resource created at '{create_url}' (id={created_id}) by "
            f"'{default_role}' is accessible via '{access_method}' by "
            f"'{alt_role}' — stateful IDOR: create-then-access.",
            f"Role A ({default_role}): HTTP {resp_a.status_code} | "
            f"Role B ({alt_role}): HTTP {resp_b.status_code} | "
            f"Access: {desc}",
            verification_stage="validated",
            request=_build_curl(access_method, access_url,
                                dict(self.session.headers),
                                cookies=safe_cookies_dict(self.session.cookies)),
            response_excerpt=resp_b.text[:500],
            steps_to_reproduce=[
                f"Authenticate as '{default_role}'",
                f"Send POST to {create_url} to create a resource",
                f"Note the created resource ID: {created_id}",
                f"Authenticate as '{alt_role}'",
                f"Send {access_method} to {access_url}",
                "Observe that the resource created by another user is accessible",
            ],
        )
        if f_dict:
            self._append_finding(findings, f_dict)
            log(f"  [IDOR Stateful] {access_method} {access_url[:80]} — "
                f"{alt_role} accessed resource created by {default_role}",
                Colors.RED, verbose_only=True, verbose=self.verbose)

    # ── Passive scan (zero additional requests) ────────────────────────────

    def scan_passive(self, findings: list[dict], candidates: list[dict]) -> None:
        """Report discovered ID-like parameters without making additional requests.
        
        Useful for passive-mode bounty scans where payload injection is prohibited.
        Produces lower-confidence findings but avoids any active probing."""
        for c in candidates:
            url = c["url"]
            param = c["param"]
            id_type = c["type"]
            value = c["value"]

            f_dict = finding(
                "IDOR - Potential Insecure Direct Object Reference",
                url, "medium",
                f"Parameter '{param}' contains {id_type} identifier: {value[:50]} — "
                f"suggests direct object reference pattern that may allow unauthorized access",
                f"Parameter '{param}'={value[:80]} (type: {id_type})",
                verification_stage="detected",
                parameter=param,
                response_excerpt=f"Discovered via passive URL analysis: {param}={value[:80]} (type: {id_type})",
                steps_to_reproduce=[
                    f"Identify the endpoint at {url}",
                    f"Note parameter '{param}' with value '{value[:60]}' (type: {id_type})",
                    "If the application uses numeric or UUID-based references, try replacing with another user's value",
                    "Compare responses to check if different users' data is accessible",
                ],
            )
            if f_dict:
                self._append_finding(findings, f_dict)
                log(f"  [IDOR Passive] {param}={value[:40]} @ {url[:60]} ({id_type})",
                    Colors.YELLOW, verbose_only=True, verbose=self.verbose)

    # ── Orchestrator ──────────────────────────────────────────────────────

    def run_all(self) -> list[Finding]:
        """Run all IDOR detection scans."""
        findings: list[Finding] = []
        candidates = self._find_id_parameters()

        if candidates:
            log(f"  [IDOR] Found {len(candidates)} ID candidate(s)", Colors.CYAN,
                verbose_only=True, verbose=self.verbose)

        self.scan_passive(findings, candidates)
        if not self.config.get("passive"):
            self.scan_horizontal_privesc(findings, candidates)
            self.scan_sequential_enum(findings, candidates)
            self.scan_encoded_id_manipulation(findings, candidates)
            self.scan_uuid_enumeration(findings, candidates)
            self.scan_cross_resource_idor(findings, candidates)
            self.scan_mass_assignment(findings)
            self.verify_ownership(findings, candidates)
            self.scan_stateful_idor(findings)

        # Bundle evidence items per finding into CompositeEvidence
        for fdict in findings:
            ev_list = fdict.get("evidence", [])
            if isinstance(ev_list, str):
                ev_list = [ev_list]
            if isinstance(ev_list, list) and len(ev_list) > 1:
                child_descs = []
                for ev in ev_list:
                    if hasattr(ev, "description"):
                        child_descs.append(ev.description)
                    elif isinstance(ev, dict):
                        child_descs.append(ev.get("description", str(ev)))
                    else:
                        child_descs.append(str(ev))
                composite = CompositeEvidence(
                    child_descriptions=child_descs,
                    evidence_count=len(ev_list),
                    description=f"Composite evidence: {len(ev_list)} items for {fdict.get('parameter', 'IDOR')}",
                    status=EvidenceStatus.VERIFIED,
                )
                ev_list.append(composite)
                fdict["evidence"] = ev_list
                if hasattr(self, '_container') and self._container and self._container.evidence_engine:
                    self._container.evidence_engine.store(composite)
                    self._container.evidence_engine.link_to_finding(composite, fdict.get("fingerprint", ""))

        return self._deduplicate(findings)

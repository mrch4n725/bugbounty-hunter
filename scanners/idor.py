"""
IdorScanner — real ScannerBase implementation using DiscoveryStore and build_role_sessions().

Lifecycle:
  DETECTED:   ID parameter identified in URL or DiscoveryStore
  VALIDATED:  Different roles get different 200 responses
  EXPLOITABLE: Ownership violation confirmed with AuthorizationComparisonEvidence
  VERIFIED:   (not applicable — OOB not relevant for IDOR)

Maturity: Level 3 (real auth comparison, ownership evidence)
"""

import re
from typing import Any
from urllib.parse import urlparse, parse_qs

from models.finding import Finding
from models.evidence import (
    AuthorizationComparisonEvidence, EvidenceStatus, HttpRequestEvidence,
    HttpResponseEvidence, ResponseDiffEvidence,
)
from modules.utils import (
    build_role_sessions, safe_get, finding, log, Colors, _build_curl,
    VerificationStage, safe_cookies_dict,
)
from scanners.base import ScannerBase

ID_PARAM_NAMES = {
    "id", "user_id", "userId", "uid", "account", "account_id",
    "org", "org_id", "customer", "customer_id", "product_id",
    "order_id", "ticket_id", "document_id", "file_id", "item_id",
    "resource", "resource_id", "target", "target_id",
}

ID_PATH_PATTERN = re.compile(
    r"/(?:users|accounts|orgs|organisations|customers|products|"
    r"orders|tickets|items|documents|profiles|projects)/"
    r"(\d+|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
    re.IGNORECASE,
)


class IdorScanner(ScannerBase):
    SCANNER_NAME = "idor"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = False

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        role_sessions = build_role_sessions(self.config, base_session=self.session)
        if len(role_sessions) < 2:
            log("  [IDOR] Skipping — fewer than 2 role sessions available", Colors.YELLOW,
                verbose_only=True, verbose=self.verbose)
            return self._get_findings()

        roles = list(role_sessions.keys())
        default_role = roles[0]
        other_roles = roles[1:]

        candidates = self._discover_candidates(urls)
        log(f"  [IDOR] Testing {len(candidates)} candidate endpoint(s) across {len(roles)} role(s)",
            Colors.CYAN, verbose_only=True, verbose=self.verbose)

        tested: set[str] = set()
        for candidate in candidates:
            test_url = candidate["test_url"]
            if test_url in tested:
                continue
            tested.add(test_url)
            self._test_endpoint(test_url, candidate, role_sessions, default_role, other_roles)

        # Stateful IDOR: create resource as default role, probe with others
        self._test_stateful_idor(role_sessions, default_role, other_roles, urls)

        return self._get_findings()

    def _discover_candidates(self, urls: list[str]) -> list[dict]:
        """Discover candidate URL+parameter pairs from recon and DiscoveryStore."""
        candidates: list[dict] = []
        seen: set[tuple[str, str]] = set()

        for url in urls:
            if not self._in_scope(url):
                continue
            parsed = urlparse(url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            for param, values in query.items():
                if param.lower() in ID_PARAM_NAMES:
                    val = values[0] if values else "1"
                    key = (url, param)
                    if key not in seen:
                        seen.add(key)
                        candidates.append({
                            "test_url": url,
                            "param": param,
                            "value": val,
                            "source": "url_param",
                        })

            path_match = ID_PATH_PATTERN.search(url)
            if path_match:
                val = path_match.group(1)
                key = (url, "__path__")
                if key not in seen:
                    seen.add(key)
                    candidates.append({
                        "test_url": url,
                        "param": "__path__",
                        "value": val,
                        "source": "url_path",
                    })

        # Pull candidate IDs from DiscoveryStore
        if self.container and hasattr(self.container, "discovery_store"):
            store = self.container.discovery_store
            try:
                for uuid_rec in store.get_by_category("uuid"):
                    val = uuid_rec.get("value", "")
                    src = uuid_rec.get("source_url", "")
                    if val and src and self._in_scope(src):
                        key = (src, "__discovery_uuid")
                        if key not in seen:
                            seen.add(key)
                            candidates.append({
                                "test_url": src,
                                "param": "id",
                                "value": val,
                                "source": "discovery_store_uuid",
                            })
                for num_rec in store.get_by_category("numeric_id"):
                    val = num_rec.get("value", "")
                    src = num_rec.get("source_url", "")
                    if val and src and self._in_scope(src):
                        key = (src, "__discovery_num")
                        if key not in seen:
                            seen.add(key)
                            candidates.append({
                                "test_url": src,
                                "param": "id",
                                "value": val,
                                "source": "discovery_store_numeric",
                            })
            except Exception:
                pass

        return candidates

    def _test_endpoint(
        self, test_url: str, candidate: dict, role_sessions: dict,
        default_role: str, other_roles: list[str],
    ) -> None:
        """Compare response across roles for a single endpoint."""
        default_sess = role_sessions[default_role]
        fp = None

        try:
            resp_a = default_sess.get(test_url, timeout=15, allow_redirects=False)
        except Exception:
            return

        if resp_a.status_code not in (200, 403, 401):
            return

        req_ev = HttpRequestEvidence(
            method="GET", url=test_url,
            headers=dict(resp_a.request.headers) if resp_a.request else {},
            description=f"IDOR probe as {default_role}: {test_url}",
            status=EvidenceStatus.COLLECTED,
        )
        resp_a_ev = HttpResponseEvidence(
            status_code=resp_a.status_code,
            headers=dict(resp_a.headers),
            body=resp_a.text[:4000],
            description=f"Response as {default_role}: {test_url}",
            status=EvidenceStatus.COLLECTED,
        )

        body_a = resp_a.text or ""
        status_a = resp_a.status_code
        success_count = 0

        for alt_role in other_roles:
            alt_sess = role_sessions[alt_role]
            try:
                resp_b = alt_sess.get(test_url, timeout=10, allow_redirects=False)
            except Exception:
                continue

            body_b = resp_b.text or ""
            status_b = resp_b.status_code

            violation = False
            if status_a == 200 and status_b == 200 and body_a != body_b:
                violation = True
            elif status_a != 200 and status_b == 200:
                violation = True

            if violation:
                success_count += 1
                authz_ev = AuthorizationComparisonEvidence(
                    url=test_url,
                    original_role=default_role,
                    target_role=alt_role,
                    original_status=status_a,
                    target_status=status_b,
                    original_body_excerpt=body_a[:500],
                    target_body_excerpt=body_b[:500],
                    body_diff_detected=True,
                    description=(
                        f"IDOR: {alt_role} response differs from {default_role} "
                        f"at {test_url} (param={candidate['param']})"
                    ),
                    status=EvidenceStatus.ANALYZED,
                )

                sev = "critical" if status_a != 200 else "high"
                stage = "exploitable" if status_a != 200 else "validated"
                f = finding(
                    vuln_type="IDOR - Insecure Direct Object Reference",
                    url=test_url,
                    severity=sev,
                    details=(
                        f"Parameter '{candidate['param']}' ({candidate['source']}): "
                        f"{alt_role} got HTTP {status_b} vs {default_role} got HTTP {status_a} "
                        f"— across-role response differs"
                    ),
                    evidence=f"{alt_role}: HTTP {status_b} vs {default_role}: HTTP {status_a}",
                    verification_stage=stage,
                    parameter=candidate["param"],
                    request=_build_curl("GET", test_url, dict(self.session.headers),
                                        cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=body_b[:500],
                    steps_to_reproduce=[
                        f"Authenticate as '{default_role}' and send GET to {test_url}",
                        f"Observe response: HTTP {status_a}",
                        f"Change to '{alt_role}' session",
                        f"Send GET to same URL {test_url}",
                        f"Observe response: HTTP {status_b} — different from '{default_role}'",
                        "This confirms an insecure direct object reference: "
                        "the endpoint returns different users' data without ownership enforcement",
                    ],
                )
                if f:
                    ev_list = f.get("evidence", [])
                    if isinstance(ev_list, str):
                        ev_list = [ev_list] if ev_list else []
                    ev_list.append(authz_ev)
                    f["evidence"] = ev_list
                    if self.evidence_engine:
                        self.evidence_engine.store(authz_ev)
                        self.evidence_engine.link_to_finding(authz_ev, f.get("fingerprint", ""))
                    self._enrich_finding(f, 2, stage)
                    self._add_finding(f)
                    log(f"  [IDOR] {test_url[:80]} — {default_role} vs {alt_role}",
                        Colors.RED, verbose_only=True, verbose=self.verbose)

        if success_count == 0 and status_a in (200, 403, 401):
            try:
                resp_record = role_sessions[default_role].get(test_url, timeout=10, allow_redirects=False)
                if resp_record and resp_record.status_code == 200:
                    if self.container and hasattr(self.container, "discovery_store"):
                        from urllib.parse import urlparse as up
                        path_val = ID_PATH_PATTERN.search(test_url)
                        if path_val:
                            store = self.container.discovery_store
                            try:
                                store.add("numeric_id", path_val.group(1), test_url)
                            except Exception:
                                pass
            except Exception:
                pass

    def _test_stateful_idor(
        self, role_sessions: dict, default_role: str, other_roles: list[str],
        urls: list[str],
    ) -> None:
        """Create resources as default role, probe access with others."""
        create_targets = self._find_create_targets(urls)
        if not create_targets:
            return

        default_sess = role_sessions[default_role]
        for target in create_targets[:5]:
            try:
                resp = default_sess.post(
                    target["url"],
                    json=target.get("body", {"name": "test", "title": "test"}),
                    timeout=15,
                )
            except Exception:
                continue
            if not resp or resp.status_code not in (200, 201):
                continue

            created_id = self._extract_id(resp.text)
            if not created_id:
                continue

            for alt_role in other_roles:
                alt_sess = role_sessions[alt_role]
                for suffix in (f"/{created_id}", f"?id={created_id}"):
                    probe_url = target["url"].rstrip("/") + suffix
                    try:
                        resp_b = alt_sess.get(probe_url, timeout=10, allow_redirects=False)
                    except Exception:
                        continue
                    if resp_b and resp_b.status_code == 200 and len(resp_b.text) > 100:
                        f = finding(
                            vuln_type="IDOR - Stateful Resource Access",
                            url=probe_url,
                            severity="critical",
                            details=(
                                f"Resource created by '{default_role}' at "
                                f"{target['url']} (id={created_id}) accessible "
                                f"by '{alt_role}' via GET"
                            ),
                            evidence=f"Created by {default_role}, accessed by {alt_role}",
                            verification_stage="validated",
                            parameter="__stateful__",
                            response_excerpt=resp_b.text[:500],
                            steps_to_reproduce=[
                                f"Authenticate as '{default_role}' and POST to {target['url']}",
                                f"Note created resource ID: {created_id}",
                                f"Authenticate as '{alt_role}'",
                                f"GET {probe_url}",
                                "Observe that the resource created by another role is accessible",
                                "This confirms a stateful IDOR: create-then-access across roles",
                            ],
                        )
                        if f:
                            self._enrich_finding(f, 0, "validated")
                            self._add_finding(f)
                            log(f"  [IDOR Stateful] {probe_url[:80]} — {alt_role} accessed resource of {default_role}",
                                Colors.RED, verbose_only=True, verbose=self.verbose)

    def _find_create_targets(self, urls: list[str]) -> list[dict]:
        targets: list[dict] = []
        seen: set[str] = set()
        for form in self.recon.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            if method != "POST" or not action or not self._in_scope(action):
                continue
            if action in seen:
                continue
            seen.add(action)
            fields = form.get("fields", [])
            body = {f["name"]: (f.get("value", "test") or "test")
                    for f in fields if f.get("name")}
            targets.append({"url": action, "body": body})

        create_paths = ("/create", "/new", "/add", "/register", "/signup")
        for url in urls:
            if not self._in_scope(url):
                continue
            path_lower = urlparse(url).path.lower()
            if any(cp in path_lower for cp in create_paths):
                if url in seen:
                    continue
                seen.add(url)
                targets.append({"url": url, "body": {}})

        return targets

    @staticmethod
    def _extract_id(text: str) -> str | None:
        if not text:
            return None
        try:
            import json
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                for key in ("id", "resourceId", "resource_id", "uid", "ID"):
                    val = parsed.get(key)
                    if val is not None:
                        return str(val)
                for wrapper in ("data", "result"):
                    wrapped = parsed.get(wrapper)
                    if isinstance(wrapped, dict):
                        for key in ("id", "resourceId", "uid"):
                            val = wrapped.get(key)
                            if val is not None:
                                return str(val)
        except (json.JSONDecodeError, ValueError):
            match = re.search(r'"id"\s*:\s*"?(\d+)"?', text)
            if match:
                return match.group(1)
        return None

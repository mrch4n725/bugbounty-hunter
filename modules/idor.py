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

            if resp_alt.text != resp_self.text:
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
                    if not isinstance(f_dict.get("evidence", []), list):
                        f_dict["evidence"] = [str(f_dict.get("evidence", ""))]
                    f_dict["evidence"].append(ev)
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
            self._append_finding(findings, finding(
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
            ))
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
            self._append_finding(findings, finding(
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
            ))
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

            if resp_b.text != resp_a.text and len(resp_b.text) > 300:
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
                    if not isinstance(f_dict.get("evidence", []), list):
                        f_dict["evidence"] = [str(f_dict.get("evidence", ""))]
                    f_dict["evidence"].append(auth_evidence)
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
            self.verify_ownership(findings, candidates)

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

"""
AuthorizationEngine — Proves authorization failures with evidence-driven role comparison.

Capabilities:
- Horizontal Access Control: User A → User B (same privilege level, different identity)
- Vertical Access Control: User → Admin (different privilege levels)
- Role Matrix Testing: Exhaustive pairwise (Guest, User, Manager, Admin)
- Ownership Validation: Before/after with body comparison proving violation

Integrates with:
- ValidationEngine: for individual compare requests
- EvidenceEngine: stores AuthorizationComparisonEvidence
- Finding model: creates submission-ready findings
- RootCauseAggregator: findings map to "Missing Authorization Check"

Success Criteria: Authorization findings are evidence-driven and submission-ready.
"""

import re
import threading
import time
from typing import Any
from urllib.parse import urlparse, parse_qs

from modules.utils import (
    safe_get, safe_post, finding, _build_curl, log, Colors, build_role_sessions,
)
from models.evidence import (
    AuthorizationComparisonEvidence, EvidenceStatus, EvidenceType,
)
from engines.validation_engine import ValidationEngine
from engines.evidence_engine import EvidenceEngine
from engines.differential_auth import DifferentialAuthorizationEngine


# ── URL patterns for authorization-relevant endpoints ────────────────────

_ID_IN_PATH = re.compile(
    r'/(?:users?|accounts?|profiles?|customers?|members?|'
    r'clients?|employees?|patients?|orders?|invoices?|'
    r'transactions?|documents?|files?|messages?|'
    r'posts?|comments?|tickets?|items?|products?)/'
    r'\d+',
    re.IGNORECASE,
)

_API_PATH = re.compile(r'/api/|/v\d+/|/rest/|/graphql', re.IGNORECASE)

_ID_PARAMS = {
    'id', 'user_id', 'userId', 'account_id', 'customer_id',
    'profile_id', 'member_id', 'client_id', 'employee_id',
    'patient_id', 'order_id', 'invoice_id', 'transaction_id',
    'document_id', 'file_id', 'message_id', 'post_id',
    'comment_id', 'ticket_id', 'item_id', 'product_id',
    'uid', 'uuid', 'token', 'key', 'ref', 'reference',
    'owner', 'owner_id', 'created_by', 'userId', 'accountId',
    'customerId', 'profileId', 'resource_id', 'resourceId',
}

_ROLE_HIERARCHY: dict[str, int] = {
    'admin': 4, 'root': 4, 'superadmin': 4, 'super_admin': 4,
    'manager': 3, 'moderator': 3, 'editor': 3,
    'user': 2, 'member': 2, 'customer': 2, 'subscriber': 2,
    'guest': 1, 'anonymous': 1, 'public': 1, 'anon': 1,
}


def _role_level(role_name: str) -> int:
    """Return a numeric privilege level for a role name (higher = more privileged)."""
    lower = role_name.lower().strip()
    return _ROLE_HIERARCHY.get(lower, 2)


def _is_auth_candidate(url: str) -> bool:
    """Check if a URL is worth authorization testing."""
    parsed = urlparse(url)
    path = parsed.path

    if _ID_IN_PATH.search(path):
        return True

    if _API_PATH.search(path):
        return True

    params = parse_qs(parsed.query)
    if params:
        for p in params:
            if p.lower() in _ID_PARAMS:
                return True

    return False


def _find_id_param(url: str) -> str:
    """Extract the most likely ID parameter name from a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for p in params:
        if p.lower() in _ID_PARAMS:
            return p

    path_segments = parsed.path.strip('/').split('/')
    for seg in path_segments:
        if seg.isdigit():
            return '__path__'

    return ''


class AuthorizationEngine:
    """Proves authorization failures with evidence-driven role comparison.

    Usage:
        engine = AuthorizationEngine(config, role_sessions, validation, evidence)
        findings = engine.run_scans(discovered_urls)

    Each finding includes:
    - AuthorizationComparisonEvidence (before/after, response diffs)
    - Steps to reproduce with curl commands
    - Confidence score based on validation status
    - Root cause label for RootCauseAggregator
    """

    def __init__(
        self,
        config: dict,
        role_sessions: dict[str, Any] | None = None,
        validation_engine: ValidationEngine | None = None,
        evidence_engine: EvidenceEngine | None = None,
    ):
        self.config = config
        self.role_sessions = role_sessions or {}
        self.validation = validation_engine or ValidationEngine(config)
        self.evidence_engine = evidence_engine or EvidenceEngine()
        self.timeout = config.get("timeout", 10)
        self.verbose = config.get("verbose", False)
        self.target = config.get("target", "").rstrip("/")
        self._lock = threading.Lock()

    def test_endpoint(
        self,
        url: str,
        original_role: str,
        target_role: str,
        method: str = "GET",
        data: dict | None = None,
    ) -> AuthorizationComparisonEvidence | None:
        """Test a single endpoint between two roles.

        Returns AuthorizationComparisonEvidence on success, None on failure.
        The evidence captures status codes, body excerpts, content diff, and
        whether an ownership violation was detected.
        """
        orig_session = self.role_sessions.get(original_role)
        targ_session = self.role_sessions.get(target_role)
        if not orig_session or not targ_session:
            return None

        try:
            if method.upper() == "POST":
                resp_orig = safe_post(orig_session, url, data or {},
                                      timeout=self.timeout, raise_for_status=False)
                resp_targ = safe_post(targ_session, url, data or {},
                                      timeout=self.timeout, raise_for_status=False)
            else:
                resp_orig = safe_get(orig_session, url,
                                     timeout=self.timeout, raise_for_status=False)
                resp_targ = safe_get(targ_session, url,
                                     timeout=self.timeout, raise_for_status=False)
        except Exception:
            return None

        if not resp_orig or not resp_targ:
            return None

        # Field-level comparison via DifferentialAuthorizationEngine
        diff_engine = DifferentialAuthorizationEngine()
        diff_result = diff_engine.compare_http(resp_orig, resp_targ)

        content_diff = diff_result.body_diff_detected
        same_status = not diff_result.status_diff
        sensitive_leaks = diff_result.sensitive_field_leaks

        ownership_violation = (
            content_diff
            and same_status
            and resp_targ.status_code == 200
        ) or any(d.sensitivity == "ownership" for d in sensitive_leaks)

        has_data_leak = any(
            d.sensitivity in ("financial", "credential", "pii", "internal")
            for d in sensitive_leaks
        )

        if ownership_violation or has_data_leak:
            ev_status = EvidenceStatus.VERIFIED
            leak_desc = ""
            if has_data_leak:
                leak_types = {d.sensitivity for d in sensitive_leaks}
                leak_fields = [d.field_path for d in sensitive_leaks]
                leak_desc = f" — field-level leak: {', '.join(leak_types)} in {', '.join(leak_fields[:5])}"
            description = (
                f"Authorization violation: {original_role} \u2192 {target_role} "
                f"@ {url}{leak_desc}"
            )
        elif content_diff:
            ev_status = EvidenceStatus.COLLECTED
            description = (
                f"Authorization check: {original_role} vs {target_role} "
                f"@ {url} \u2014 content differs, requires validation"
            )
        else:
            ev_status = EvidenceStatus.FAILED
            description = (
                f"Authorization check: {original_role} vs {target_role} "
                f"@ {url} \u2014 no violation detected"
            )

        return AuthorizationComparisonEvidence(
            original_user=original_role,
            target_user=target_role,
            original_status=resp_orig.status_code,
            target_status=resp_targ.status_code,
            content_different=content_diff,
            ownership_violated=ownership_violation,
            original_body_excerpt=resp_orig.text[:200],
            target_body_excerpt=resp_targ.text[:200],
            description=description,
            status=ev_status,
        )

    def _classify_violation(
        self,
        original_role: str,
        target_role: str,
        evidence: AuthorizationComparisonEvidence,
    ) -> tuple[str, str]:
        """Classify the violation type and severity.

        Uses DifferentialAuthorizationEngine for field-level awareness.
        Returns (vuln_type, severity).
        """
        orig_level = _role_level(original_role)
        targ_level = _role_level(target_role)

        if evidence.ownership_violated:
            if orig_level != targ_level:
                return ("Authorization - Vertical", "critical")
            return ("Authorization - Ownership Violation", "critical")

        if evidence.content_different:
            if orig_level != targ_level:
                return ("Authorization - Vertical", "high")
            return ("Authorization - Horizontal", "high")

        if evidence.target_status not in (403, 401) and evidence.original_status != evidence.target_status:
            return ("Authorization - Status Bypass", "high")

        return ("Authorization - Checked", "medium")

    def _build_finding(
        self,
        evidence: AuthorizationComparisonEvidence,
        url: str,
        parameter: str = "",
        method: str = "GET",
        data: dict | None = None,
    ) -> dict | None:
        """Build a submission-ready finding from authorization evidence."""
        if not evidence or evidence.status == EvidenceStatus.FAILED:
            return None

        vuln_type, severity = self._classify_violation(
            evidence.original_user, evidence.target_user, evidence
        )

        verification_stage = (
            "verified" if evidence.ownership_violated
            else "validated" if evidence.content_different
            else "detected"
        )

        # Build curl for original request
        orig_session = self.role_sessions.get(evidence.original_user)
        curl = _build_curl(
            method, url,
            dict(orig_session.headers) if orig_session else {},
            data=data,
        )

        diff_indicator = "content differs" if evidence.content_different else "same content"

        details = (
            f"Role '{evidence.target_user}' can access {evidence.original_user}'s data at {url}. "
            f"Original ({evidence.original_user}): HTTP {evidence.original_status}, "
            f"{len(evidence.original_body_excerpt)} chars. "
            f"Target ({evidence.target_user}): HTTP {evidence.target_status}, "
            f"{len(evidence.target_body_excerpt)} chars. "
            f"Verdict: {diff_indicator}, "
            f"{'ownership VIOLATED' if evidence.ownership_violated else 'no violation detected'}."
        )

        body_diff_flag = "yes" if evidence.content_different else "no"
        ownership_flag = "yes" if evidence.ownership_violated else "no"

        steps = [
            f"Authenticate as '{evidence.original_user}' (provide session token or cookie)",
            f"Send {method.upper()} request to {url}",
            f"Observe the response: HTTP {evidence.original_status} ({len(evidence.original_body_excerpt)} chars)",
            f"Now authenticate as '{evidence.target_user}'",
            f"Send {method.upper()} request to the same URL {url}",
            f"Observe the response: HTTP {evidence.target_status} ({len(evidence.target_body_excerpt)} chars)",
            f"Compare responses: body differs = {body_diff_flag}, ownership violated = {ownership_flag}",
        ]
        if evidence.ownership_violated:
            steps.append(
                f"The endpoint returns different data based on authentication context "
                f"rather than resource ownership \u2014 this confirms the authorization bypass"
            )

        f = finding(
            vuln_type=vuln_type,
            url=url,
            severity=severity,
            details=details,
            evidence=str(
                f"Ownership comparison: {evidence.original_user} vs "
                f"{evidence.target_user} @ {url}"
            ),
            verification_stage=verification_stage,
            parameter=parameter,
            request=curl,
            response_excerpt=evidence.target_body_excerpt,
            steps_to_reproduce=steps,
        )

        if not f:
            return None

        existing = f.get("evidence", [])
        if isinstance(existing, str):
            existing = [existing] if existing else []
        f["evidence"] = existing + [evidence]
        f["root_cause"] = "Missing Authorization Check"

        if self.evidence_engine:
            try:
                fp = self.evidence_engine.store(evidence)
                finding_fp = f.get("fingerprint", "")
                if fp and finding_fp:
                    self.evidence_engine.link_to_finding(evidence, finding_fp)
            except Exception:
                pass

        return f

    def _test_role_pair(
        self,
        url: str,
        role_a: str,
        role_b: str,
        findings: list[dict],
        checked: set[tuple[str, str, str]],
        method: str = "GET",
        data: dict | None = None,
    ) -> None:
        """Test a pair of roles against a URL and append findings."""
        key = (url, role_a, role_b)
        if key in checked:
            return
        checked.add(key)

        ev = self.test_endpoint(url, role_a, role_b, method=method, data=data)
        if ev and ev.status != EvidenceStatus.FAILED:
            param = _find_id_param(url)
            f = self._build_finding(ev, url, parameter=param, method=method, data=data)
            if f:
                findings.append(f)

    def run_scans(
        self,
        urls: list[str],
        methods: list[str] | None = None,
    ) -> list[dict]:
        """Main entry point: run all authorization tests across URLs.

        Tests each authorization-relevant URL with each pair of roles.
        Horizontal: pairs of roles at the same privilege level.
        Vertical: pairs of roles at different privilege levels.
        Ownership: flags when content differs with same 200 status.

        Args:
            urls: List of discovered URLs to test.
            methods: HTTP methods to test (default: ["GET"]).

        Returns:
            List of submission-ready finding dicts.
        """
        findings: list[dict] = []
        roles = list(self.role_sessions.keys())

        if len(roles) < 2:
            log("[*] AuthorizationEngine needs >= 2 roles (use --auth-header)",
                Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            return findings

        auth_urls = [u for u in urls if _is_auth_candidate(u)]
        if not auth_urls:
            log("[*] No authorization-relevant URLs found", Colors.YELLOW,
                verbose_only=True, verbose=self.verbose)
            return findings

        if self.verbose:
            log(f"[*] AuthorizationEngine: testing {len(auth_urls)} URLs across {len(roles)} roles",
                Colors.CYAN)

        _methods = methods or ["GET"]
        checked: set[tuple[str, str, str]] = set()

        for url in auth_urls:
            for method in _methods:
                for i in range(len(roles)):
                    for j in range(i + 1, len(roles)):
                        self._test_role_pair(
                            url, roles[i], roles[j],
                            findings, checked,
                            method=method,
                        )

        if findings and self.verbose:
            log(f"[!] AuthorizationEngine: {len(findings)} authorization finding(s)",
                Colors.RED)

        return findings

    def run_horizontal(self, urls: list[str]) -> list[dict]:
        """Test only horizontal access: same-level role pairs."""
        findings: list[dict] = []
        roles = list(self.role_sessions.keys())

        if len(roles) < 2:
            return findings

        auth_urls = [u for u in urls if _is_auth_candidate(u)]
        checked: set[tuple[str, str, str]] = set()

        for url in auth_urls:
            for i in range(len(roles)):
                for j in range(i + 1, len(roles)):
                    if _role_level(roles[i]) == _role_level(roles[j]):
                        self._test_role_pair(
                            url, roles[i], roles[j], findings, checked
                        )

        return findings

    def run_vertical(self, urls: list[str]) -> list[dict]:
        """Test only vertical access: different-level role pairs.

        Tests low-priv roles against high-priv roles to detect privilege escalation.
        """
        findings: list[dict] = []
        roles = list(self.role_sessions.keys())

        if len(roles) < 2:
            return findings

        auth_urls = [u for u in urls if _is_auth_candidate(u)]
        checked: set[tuple[str, str, str]] = set()

        for url in auth_urls:
            for i in range(len(roles)):
                for j in range(i + 1, len(roles)):
                    if _role_level(roles[i]) != _role_level(roles[j]):
                        self._test_role_pair(
                            url, roles[i], roles[j], findings, checked
                        )

        return findings

    def verify_ownership(
        self,
        url: str,
        owner_role: str,
        attacker_role: str,
    ) -> dict | None:
        """Prove ownership violation for a single URL between two specific roles.

        This is the most definitive test — it produces VERIFIED evidence when
        both roles receive HTTP 200 with differing body content.

        Returns a finding dict or None.
        """
        ev = self.test_endpoint(url, owner_role, attacker_role)
        if not ev or ev.status == EvidenceStatus.FAILED:
            return None
        return self._build_finding(ev, url)




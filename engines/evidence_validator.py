from typing import Any, ClassVar

from models.evidence import EvidenceType
from models.finding import Finding


class EvidenceCompletenessValidator:
    """Validates findings have sufficient evidence for their vulnerability class.

    Minimum evidence requirements are defined per vulnerability type. Findings
    that lack required evidence get:
    - confidence_score reduced by CONFIDENCE_PENALTY (capped at 0)
    - verification_stage set to PARTIALLY_VALIDATED
    - A confidence_reason explaining the gap
    """

    CONFIDENCE_PENALTY = 15

    # vuln_type keyword → required EvidenceType set.
    # Ordered with longer keys first so specific matches take priority.
    REQUIREMENTS: ClassVar[list[tuple[str, set[EvidenceType]]]] = [
        # ── Critical/high-impact classes need strong evidence ──────────
        ("local file inclusion",   {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("missing rate limiting",  {EvidenceType.HTTP_REQUEST, EvidenceType.TIMING_PROOF}),
        ("confirmed ssti",         {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("confirmed sqli",         {EvidenceType.HTTP_REQUEST, EvidenceType.OOB_CALLBACK}),
        ("confirmed ssrf",         {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("command injection",      {EvidenceType.HTTP_REQUEST, EvidenceType.OOB_CALLBACK}),
        ("cmd_injection",          {EvidenceType.HTTP_REQUEST, EvidenceType.OOB_CALLBACK}),
        ("blind xss",              {EvidenceType.OOB_CALLBACK}),
        ("sql injection",          {EvidenceType.HTTP_REQUEST, EvidenceType.TIMING_PROOF}),
        ("exposed sensitive file", {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("sensitive data",         {EvidenceType.HTTP_REQUEST, EvidenceType.SECRET_VALIDATION, EvidenceType.RESPONSE_EXCERPT}),
        ("exposed js secret",      {EvidenceType.HTTP_REQUEST, EvidenceType.SECRET_VALIDATION}),
        ("subdomain_takeover",     {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("directory_fuzz",         {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("directory listing",      {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("open redirect",          {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("open_redirect",          {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("insecure form action",   {EvidenceType.HTTP_REQUEST}),
        ("insecure forms",         {EvidenceType.HTTP_REQUEST}),
        ("weak content security",  {EvidenceType.HTTP_REQUEST}),
        ("missing security",       {EvidenceType.HTTP_REQUEST}),
        ("information disclosure", {EvidenceType.HTTP_REQUEST}),
        ("insecure cookie",        {EvidenceType.HTTP_REQUEST}),
        ("http_methods",           {EvidenceType.HTTP_REQUEST}),
        ("dangerous http methods", {EvidenceType.HTTP_REQUEST}),
        ("rate_limiting",          {EvidenceType.HTTP_REQUEST, EvidenceType.TIMING_PROOF}),
        ("mass assignment",        {EvidenceType.HTTP_REQUEST}),
        # ── Authorization / IDOR ───────────────────────────────────────
        ("authorization",          {EvidenceType.HTTP_REQUEST, EvidenceType.AUTHORIZATION_COMPARISON}),
        ("idor",                   {EvidenceType.HTTP_REQUEST, EvidenceType.AUTHORIZATION_COMPARISON, EvidenceType.RESPONSE_EXCERPT}),
        ("bola",                   {EvidenceType.HTTP_REQUEST, EvidenceType.AUTHORIZATION_COMPARISON}),
        # ── Server-side injection ──────────────────────────────────────
        ("ssrf",                   {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("ssti",                   {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("xxe",                    {EvidenceType.HTTP_REQUEST, EvidenceType.OOB_CALLBACK}),
        ("lfi",                    {EvidenceType.HTTP_REQUEST, EvidenceType.RESPONSE_EXCERPT}),
        ("sqli",                   {EvidenceType.HTTP_REQUEST, EvidenceType.TIMING_PROOF}),
        # ── XSS variants ───────────────────────────────────────────────
        ("dom xss",                {EvidenceType.HTTP_REQUEST, EvidenceType.BROWSER_EXECUTION}),
        ("dom-based xss",          {EvidenceType.HTTP_REQUEST, EvidenceType.BROWSER_EXECUTION}),
        ("confirmed xss",          {EvidenceType.HTTP_REQUEST, EvidenceType.BROWSER_EXECUTION}),
        ("reflected xss",          {EvidenceType.HTTP_REQUEST, EvidenceType.BROWSER_EXECUTION}),
        ("xss",                    {EvidenceType.HTTP_REQUEST, EvidenceType.BROWSER_EXECUTION}),
        # ── Configurational / informational ────────────────────────────
        ("graphql",                {EvidenceType.HTTP_REQUEST, EvidenceType.GRAPHQL_SCHEMA}),
        ("clickjacking",           {EvidenceType.HTTP_REQUEST}),
        ("csrf",                   {EvidenceType.HTTP_REQUEST}),
        ("openapi",                {EvidenceType.HTTP_REQUEST}),
        ("chained",                {EvidenceType.HTTP_REQUEST}),
    ]

    # Vuln types that are exempt from validation (informational only)
    EXEMPT_TYPES: ClassVar[set[str]] = {
        "forbidden path",
        "authentication required path",
        "second-order injection",
    }

    @classmethod
    def _get_requirements(cls, vuln_type: str) -> set[EvidenceType] | None:
        """Find matching requirements for a vuln_type string.

        Matches by keyword containment (case-insensitive), with longer
        keys checked first to handle hierarchical types like
        'Missing Security Header: X-Frame-Options' matching 'missing security'.
        """
        lowered = vuln_type.lower()
        for key, reqs in cls.REQUIREMENTS:
            if key in lowered:
                return reqs
        return None

    @classmethod
    def _get_present_types(cls, finding: Finding) -> set[EvidenceType]:
        """Collect unique EvidenceType values from a finding's evidence list."""
        present: set[EvidenceType] = set()
        for ev in (finding.evidence or []):
            if isinstance(ev, str):
                continue
            if hasattr(ev, "evidence_type") and isinstance(ev.evidence_type, EvidenceType):
                present.add(ev.evidence_type)
        # Also check legacy request/response fields as implicit HTTP_REQUEST evidence
        if finding.request:
            present.add(EvidenceType.HTTP_REQUEST)
        if finding.response_excerpt:
            present.add(EvidenceType.RESPONSE_EXCERPT)
        return present

    @classmethod
    def validate(cls, finding: Finding) -> Finding:
        """Validate a single finding's evidence completeness.

        Idempotent: if the finding was already penalised (has an ``evidence
        incomplete`` reason), returns immediately to prevent double-penalty
        when called from both the pipeline (``main.py``) and the reporter
        (``ReporterBase``).

        Mutates the Finding in place (confidence_score, verification_stage,
        confidence_reasons) and returns it.
        """
        vuln_type = (finding.vuln_type or finding.title or "").lower()
        if not vuln_type:
            return finding

        # Idempotency: skip if already penalised
        if any("evidence incomplete" in r for r in finding.confidence_reasons):
            return finding

        # Check exemption
        for exempt in cls.EXEMPT_TYPES:
            if exempt in vuln_type:
                return finding

        required = cls._get_requirements(vuln_type)
        if required is None:
            return finding

        present = cls._get_present_types(finding)
        missing = required - present

        if not missing:
            return finding

        # Evidence is incomplete — apply penalties
        missing_names = ", ".join(sorted(m.value for m in missing))
        reason = f"-{cls.CONFIDENCE_PENALTY} evidence incomplete: missing {missing_names}"

        # Reduce confidence (floor at 0)
        new_score = max(0, (finding.confidence_score or 25) - cls.CONFIDENCE_PENALTY)
        finding.confidence_score = new_score

        # Mark as partially validated
        from models.finding import VerificationStage
        finding.verification_stage = VerificationStage.PARTIALLY_VALIDATED.value

        finding.confidence_reasons.append(reason)
        return finding

    @classmethod
    def validate_all(cls, findings: list[Finding]) -> list[Finding]:
        """Validate all findings in a list."""
        return [cls.validate(f) for f in findings]

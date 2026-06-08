"""
RootCauseAggregator — Groups findings by shared root cause.

Exposes:
    RootCauseAggregator: Aggregation engine.
    RootCauseGroup: Container for a grouped set of findings.
    normalize_endpoint: URL path normalization (IDs/UUIDs → {id}/{uuid}).
    ROOT_CAUSE_MAP: Mapping from vuln_type → root cause label.
"""

import re
from typing import Any, Optional

from models.finding import Finding, compute_root_cause_fingerprint
from modules.utils import log, Colors


# ── Root cause mapping ──────────────────────────────────────────────────────

ROOT_CAUSE_MAP: dict[str, str] = {
    "xss": "Improper Input Sanitization",
    "reflected xss": "Improper Input Sanitization",
    "stored xss": "Improper Input Sanitization",
    "dom xss": "Improper Input Sanitization",
    "dom-based xss": "Improper Input Sanitization",
    "sqli": "Improper Input Sanitization",
    "sql injection": "Improper Input Sanitization",
    "blind sqli": "Improper Input Sanitization",
    "ssti": "Improper Input Sanitization",
    "lfi": "Improper Input Sanitization",
    "command injection": "Improper Input Sanitization",
    "cmd_injection": "Improper Input Sanitization",
    "xxe": "Improper XML Parsing Configuration",
    "ssrf": "Server-Side Request Validation Missing",
    "open_redirect": "Improper Redirect Validation",
    "open redirect": "Improper Redirect Validation",
    "idor": "Missing Authorization Check",
    "potential idor": "Missing Authorization Check",
    "csrf": "Missing CSRF Protection",
    "clickjacking": "Missing Framing Protection",
    "headers": "Insecure Security Headers",
    "missing security header": "Insecure Security Headers",
    "insecure_forms": "Insecure Form Configuration",
    "insecure forms": "Insecure Form Configuration",
    "blind_xss": "Improper Input Sanitization",
    "blind xss": "Improper Input Sanitization",
    "rate_limiting": "Insufficient Rate Limiting",
    "rate limiting": "Insufficient Rate Limiting",
    "graphql auth bypass": "Missing Authorization Check",
    "graphql": "Excessive GraphQL Schema Exposure",
    "sensitive_data": "Sensitive Information Exposure",
    "sensitive data": "Sensitive Information Exposure",
    "exposed js secret": "Sensitive Information Exposure",
    "exposed_files": "Sensitive Files Exposed",
    "exposed files": "Sensitive Files Exposed",
    "subdomain_takeover": "DNS Configuration Vulnerability",
    "subdomain takeover": "DNS Configuration Vulnerability",
    "http_methods": "Insecure HTTP Method Configuration",
    "http methods": "Insecure HTTP Method Configuration",
    "directory_fuzz": "Information Disclosure via Directory Listing",
    "dirb": "Information Disclosure via Directory Listing",
    "openapi": "Excessive API Schema Exposure",
    "api": "API Security Misconfiguration",
    "bola": "Missing Authorization Check",
    "mass assignment": "API Security Misconfiguration",
    "authorization bypass": "Missing Authorization Check",
    "auth bypass": "Missing Authorization Check",
    "authorization - ownership violation": "Missing Authorization Check",
    "authorization - horizontal": "Missing Authorization Check",
    "authorization - vertical": "Missing Authorization Check",
    "authorization - role matrix": "Missing Authorization Check",
    "insecure cookie": "Insecure Cookie Configuration",
    "weak csp": "Weak Content Security Policy",
    "server disclosure": "Information Disclosure via Server Metadata",
}

UNKNOWN_ROOT_CAUSE = "Uncategorized Vulnerability"


# ── Endpoint normalization ──────────────────────────────────────────────────

_ENDPOINT_ID_PATTERNS = [
    (re.compile(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE), '/{uuid}'),
    (re.compile(r'/\d+'), '/{id}'),
    (re.compile(r'/[0-9a-fA-F]{24}'), '/{oid}'),    # MongoDB ObjectId
    (re.compile(r'/[0-9a-fA-F]{32}'), '/{hash}'),   # MD5
    (re.compile(r'/[0-9a-fA-F]{40}'), '/{sha1}'),   # SHA1
    (re.compile(r'/[0-9a-fA-F]{64}'), '/{sha256}'), # SHA256
    (re.compile(r'/[\w\-]+@[\w\-]+'), '/{email}'),  # email
    (re.compile(r'/[A-Z0-9]{5,}(?=[/\?#]|$)', re.IGNORECASE), '/{token}'),  # alphanumeric tokens
]


def normalize_endpoint(url: str) -> str:
    """Normalize a URL path by replacing dynamic segments with placeholders.

    Strips query strings and fragments, then replaces UUIDs, numeric IDs,
    hashes, emails, and tokens with canonical placeholders.
    """
    path = url.split("?")[0].split("#")[0]
    path = path.rstrip("/")
    for pattern, replacement in _ENDPOINT_ID_PATTERNS:
        path = pattern.sub(replacement, path)
    return path


# ── Root cause classification ──────────────────────────────────────────────

def classify_root_cause(finding: Finding) -> str:
    """Determine the root cause label for a finding based on its vuln_type."""
    if finding.root_cause:
        return finding.root_cause
    vt = (finding.vuln_type or "").lower().strip()
    title = (finding.title or "").lower().strip()
    for key in ROOT_CAUSE_MAP:
        if vt == key or vt.startswith(key) or key in vt:
            return ROOT_CAUSE_MAP[key]
        if title == key or title.startswith(key) or key in title:
            return ROOT_CAUSE_MAP[key]
    return UNKNOWN_ROOT_CAUSE


# ── RootCauseGroup ──────────────────────────────────────────────────────────

class RootCauseGroup:
    """A group of findings sharing the same root cause.

    Attributes:
        root_cause: Human-readable root cause label.
        fingerprint: SHA-256 fingerprint of the root cause.
        findings: The Finding instances in this group.
        severity: Highest severity among findings.
        confidence: Average confidence score.
        affected_endpoints: Deduplicated, normalized endpoint paths.
        affected_urls: All original URLs in the group.
        vulnerability_types: Distinct vuln_type values.
        count: Number of findings.
        evidence_summary: Short summary of verification stages.
    """

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, root_cause: str, fingerprint: str, findings: list[Finding]):
        self.root_cause = root_cause
        self.fingerprint = fingerprint
        self.findings = findings
        self.severity = self._aggregate_severity()
        self.confidence = self._aggregate_confidence()
        self.affected_endpoints = self._aggregate_endpoints()
        self.affected_urls = sorted({f.url for f in findings if f.url})
        self.vulnerability_types = sorted({f.vuln_type for f in findings if f.vuln_type})
        self.count = len(findings)
        self.evidence_summary = self._build_summary()

    def _aggregate_severity(self) -> str:
        best = "info"
        best_order = self.SEVERITY_ORDER["info"]
        for f in self.findings:
            order = self.SEVERITY_ORDER.get(f.severity, 4)
            if order < best_order:
                best_order = order
                best = f.severity
        return best

    def _aggregate_confidence(self) -> float:
        scores = [f.confidence_score for f in self.findings if f.confidence_score is not None]
        return sum(scores) / len(scores) if scores else 0.0

    def _aggregate_endpoints(self) -> list[str]:
        seen: set[str] = set()
        eps: list[str] = []
        for f in self.findings:
            ep = normalize_endpoint(f.url)
            if ep not in seen:
                seen.add(ep)
                eps.append(ep)
        return sorted(eps)

    def _build_summary(self) -> str:
        stages = sorted({f.verification_stage for f in self.findings if f.verification_stage})
        return (
            f"Vulnerability types: {', '.join(self.vulnerability_types)} | "
            f"Severity: {self.severity} | "
            f"Verification stages: {', '.join(st.capitalize() for st in stages)} | "
            f"Total findings: {self.count}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_cause": self.root_cause,
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "confidence": round(self.confidence, 1),
            "count": self.count,
            "affected_endpoints": self.affected_endpoints,
            "affected_urls": self.affected_urls,
            "vulnerability_types": self.vulnerability_types,
            "evidence_summary": self.evidence_summary,
            "finding_fingerprints": [f.fingerprint for f in self.findings],
        }


# ── RootCauseAggregator ─────────────────────────────────────────────────────

class RootCauseAggregator:
    """Aggregates findings by shared root cause.

    Usage:
        aggregator = RootCauseAggregator()
        groups = aggregator.aggregate(findings)
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.verbose = self.config.get("verbose", False)

    def aggregate(self, findings: list[Finding]) -> list[RootCauseGroup]:
        """Classify, fingerprint, and group findings by root cause.

        Mutates each finding in-place to set ``root_cause`` and
        ``root_cause_fingerprint`` if not already set, then builds
        ``RootCauseGroup`` objects.
        """
        self._classify_findings(findings)
        groups: dict[str, list[Finding]] = {}
        for f in findings:
            fp = f.root_cause_fingerprint
            groups.setdefault(fp, []).append(f)

        result: list[RootCauseGroup] = []
        for fp, members in groups.items():
            rc = members[0].root_cause
            group = RootCauseGroup(rc, fp, members)
            result.append(group)
            # Set grouped_urls on each member for backward compat
            for m in members:
                m.grouped_urls = group.affected_urls
            if self.verbose:
                log(f"  [RootCause] {rc}: {group.count} findings across {len(group.affected_endpoints)} endpoints",
                    Colors.CYAN)

        result.sort(key=lambda g: g.count, reverse=True)
        return result

    def _classify_findings(self, findings: list[Finding]) -> None:
        """Set root_cause and root_cause_fingerprint on every finding."""
        for f in findings:
            if not f.root_cause:
                f.root_cause = classify_root_cause(f)
            if not f.root_cause_fingerprint:
                f.root_cause_fingerprint = compute_root_cause_fingerprint(
                    f.vuln_type, f.root_cause
                )

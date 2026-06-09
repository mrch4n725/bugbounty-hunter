from models.finding import Finding
from models.duplicate import DuplicateRisk, LIKELY_DUPLICATE, MODERATE_RISK, POTENTIALLY_NOVEL
from engines.root_cause import ROOT_CAUSE_MAP


COMMON_BUG_CLASSES: dict[str, list[str]] = {
    "Improper Input Sanitization": [
        "xss", "sqli", "ssti", "lfi", "command injection", "cmd_injection",
    ],
    "Missing Authorization Check": [
        "idor", "authorization", "bola", "graphql auth bypass",
    ],
    "Insecure Security Headers": [
        "headers", "missing security header", "clickjacking",
    ],
    "Sensitive Information Exposure": [
        "sensitive_data", "exposed js secret", "exposed files",
    ],
}


class DuplicateRiskEngine:
    """Estimates the likelihood that a finding is already known.

    Uses:
    - Root cause commonality
    - Asset type popularity
    - Common bug classes
    - Historical findings

    This is for PRIORITIZATION only — never suppresses findings automatically.
    """

    def __init__(self, historical_findings: list[Finding] | None = None):
        self.historical = historical_findings or []

    def estimate(self, finding: Finding) -> DuplicateRisk:
        reasons: list[str] = []
        risk_score = 0.0

        root_cause = (finding.root_cause or "").lower()
        vuln_type = (finding.vuln_type or "").lower()

        for rc, vulns in COMMON_BUG_CLASSES.items():
            if root_cause == rc.lower() or any(v in vuln_type for v in vulns):
                risk_score += 0.2
                reasons.append(f"Common bug class: {rc}")
                break

        url_lower = finding.url.lower()
        common_endpoints = [
            "/api/", "/graphql", "/login", "/auth",
            "/.env", "/wp-admin", "/admin",
        ]
        ep_match = next((ep for ep in common_endpoints if ep in url_lower), None)
        if ep_match:
            risk_score += 0.15
            reasons.append(f"Well-known target path: {ep_match}")

        if self.historical:
            matches = self._find_historical_matches(finding)
            n_matches = len(matches)
            if n_matches > 0:
                risk_score += min(0.4, n_matches * 0.15)
                reasons.append(f"Found {n_matches} similar historical finding(s)")
                for m in matches[:3]:
                    reasons.append(f"Similar to: {m.vuln_type} @ {m.url}")

        vuln_type_lower = (finding.vuln_type or "").lower()
        highly_scanned = ["xss", "sqli", "open redirect", "open_redirect", "csrf", "headers", "clickjacking"]
        if any(v in vuln_type_lower for v in highly_scanned):
            risk_score += 0.1
            reasons.append(f"Highly scanned bug class: {vuln_type_lower}")

        if risk_score >= 0.6:
            likelihood = LIKELY_DUPLICATE
        elif risk_score >= 0.3:
            likelihood = MODERATE_RISK
        else:
            likelihood = POTENTIALLY_NOVEL

        return DuplicateRisk(
            likelihood=likelihood,
            confidence=min(1.0, risk_score),
            similar_findings=[f.fingerprint for f in self._find_historical_matches(finding)[:5]],
            reasons=reasons[:5],
        )

    def estimate_all(self, findings: list[Finding]) -> dict[str, DuplicateRisk]:
        return {
            f.fingerprint: self.estimate(f)
            for f in findings
            if f.fingerprint
        }

    def _find_historical_matches(self, finding: Finding) -> list[Finding]:
        matches = []
        for hf in self.historical:
            score = 0
            if hf.vuln_type.lower() == (finding.vuln_type or "").lower():
                score += 1
            if hf.root_cause.lower() == (finding.root_cause or "").lower():
                score += 1
            if hf.url == finding.url:
                score += 1
            if score >= 2:
                matches.append(hf)
        return matches

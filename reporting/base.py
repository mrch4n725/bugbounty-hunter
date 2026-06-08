import hashlib
import html
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from modules.utils import log, Colors, _build_curl
from models.finding import Finding
from engines.root_cause import RootCauseAggregator, RootCauseGroup
from engines.evidence_validator import EvidenceCompletenessValidator


CVSS_BY_SEVERITY: Dict[str, float] = {
    "critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0,
}

CVSS_VECTORS: Dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "low": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "info": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}

IMPACT_MATRIX: Dict[str, tuple] = {
    "xss":               (2, 5, 0, "Account takeover via session theft, phishing, or UI redressing"),
    "reflected xss":     (2, 5, 0, "Session theft, phishing via reflected payload in URL"),
    "confirmed xss":     (2, 5, 0, "Verified script execution in victim browser context"),
    "dom xss":           (2, 5, 0, "Client-side sink injection able to bypass WAF filters"),
    "sqli":              (5, 4, 2, "Full database exfiltration, authentication bypass, data integrity loss"),
    "sql injection":     (5, 4, 2, "Full database exfiltration, authentication bypass, data integrity loss"),
    "confirmed sqli":    (5, 4, 2, "OOB-confirmed SQL injection with data exfiltration capability"),
    "lfi":               (4, 0, 0, "Source code disclosure, credential leak, path traversal data access"),
    "ssrf":              (4, 0, 4, "Internal network scanning, cloud metadata access, pivot to internal services"),
    "confirmed ssrf":    (4, 0, 4, "OOB-confirmed SSRF — cloud metadata access or callback received"),
    "xxe":               (5, 0, 3, "File disclosure, SSRF pivot, denial of service, data exfiltration"),
    "ssti":              (4, 0, 2, "Server-side template injection leading to RCE or data access"),
    "cmd_injection":     (5, 5, 5, "Full server compromise, lateral movement, data destruction or exfiltration"),
    "command injection": (5, 5, 5, "Full server compromise, lateral movement, data destruction or exfiltration"),
    "blind_xss":         (2, 4, 0, "Session hijacking of privileged users, admin panel compromise"),
    "open_redirect":     (0, 2, 0, "Phishing, Bypassing URL allowlists, OAuth token theft"),
    "csrf":              (0, 3, 0, "State-changing actions on behalf of authenticated users"),
    "idor":              (5, 3, 0, "Unauthorized access to other users' private data, privilege escalation"),
    "graphql":           (4, 2, 1, "Data disclosure via introspection, batch attacks, query depth abuse"),
    "sensitive_data":    (5, 0, 0, "Secrets in source/response enable lateral attacks, cloud compromise"),
    "sensitive data":    (5, 0, 0, "Secrets in source/response enable lateral attacks, cloud compromise"),
    "exposed js secret": (4, 0, 0, "Hardcoded API keys, tokens, or credentials in client-side source"),
    "headers":           (0, 0, 0, "Increased attack surface, missing clickjacking/HSTS protection"),
    "clickjacking":      (0, 0, 0, "UI redressing, mouse-jacking — chained with XSS for account takeover"),
    "subdomain_takeover": (0, 2, 0, "Brand impersonation, phishing, credential harvesting"),
    "http_methods":      (0, 0, 1, "Unrestricted HTTP methods allow file upload or endpoint tampering"),
    "insecure_forms":    (0, 1, 0, "Forms submitted over HTTP allowing MITM data interception"),
    "exposed_files":     (4, 0, 0, "Sensitive config files, .env, .git, or backups exposed publicly"),
    "rate_limiting":     (0, 0, 0, "No rate limiting enables brute force, credential stuffing, or DoS"),
    "api":               (3, 1, 1, "API misconfiguration enables data leak, mass assignment, or BOLA"),
    "bola":              (5, 3, 0, "Broken Object Level Authorization — unauthorized object access"),
    "mass assignment":   (2, 1, 0, "Mass assignment enables privilege escalation via extra fields"),
    "potential idor":    (3, 2, 0, "IDOR via parameter tampering returns accessible resource"),
    "missing security header": (0, 0, 0, "Missing headers increase attack surface for common web attacks"),
    "weak csp":          (0, 0, 0, "Permissive Content-Security-Policy weakens XSS protections"),
    "insecure cookie":   (0, 0, 0, "Cookies missing Secure/HttpOnly/SameSite flags"),
    "server disclosure": (0, 0, 0, "Server header reveals software versions aiding targeted attacks"),
}

IMPACT_VULN_EXAMPLES: Dict[str, str] = {
    "xss":             "alert(1) in browser context",
    "sqli":            "UNION-based data extraction or blind boolean inference",
    "lfi":             "/etc/passwd read or log poisoning -> RCE",
    "ssrf":            "Cloud metadata endpoint (169.254.169.254) access",
    "xxe":             "Out-of-band file read + callback confirmation",
    "cmd_injection":   "uid= output or OOB nslookup callback",
    "blind_xss":       "Interactsh callback from admin browser",
    "open_redirect":   "Redirect to attacker-controlled origin",
    "csrfs":           "No CSRF token on state-changing endpoints",
    "idor":            "Parameter tampering reveals other users' data",
    "graphql":         "Introspection query returns full schema",
    "sensitive_data":  "Valid AWS key with live STS caller identity",
    "subdomain_takeover": "DNS CNAME points to unclaimed cloud service",
}

DATA_EXPOSURE_LABELS = {0: "None", 1: "Low (metadata)", 2: "Medium (limited data)", 3: "High (sensitive data)", 4: "Very High (credentials/keys)", 5: "Critical (full access)"}
ATO_LABELS = {0: "No risk", 1: "Low", 2: "Medium", 3: "High", 4: "Very High", 5: "Immediate takeover possible"}
RCE_LABELS = {0: "No risk", 1: "Low", 2: "Medium", 3: "High", 4: "Very High", 5: "Immediate RCE"}


REMEDIATION_MATRIX: Dict[str, str] = {
    "xss": "Apply context-aware output encoding (HTML entity, JS string, CSS, URL). "
           "Use Content-Security-Policy headers. Validate input on both client and server sides. "
           "For reflected XSS: ensure user input is never rendered unsanitized in HTTP responses. "
           "For stored XSS: sanitize on output, not input storage. "
           "For DOM XSS: avoid dangerous sink methods (innerHTML, document.write, eval).",
    "sqli": "Use parameterized queries / prepared statements. Apply strict input validation "
            "allowing only expected character classes. Use an ORM layer that handles parameterization. "
            "Least-privilege database accounts. WAF rules for SQL injection patterns.",
    "sql injection": "Use parameterized queries / prepared statements. Apply strict input validation "
                     "allowing only expected character classes. Use an ORM layer that handles parameterization. "
                     "Least-privilege database accounts. WAF rules for SQL injection patterns.",
    "lfi": "Validate and sanitize file paths. Use a whitelist of allowed files. Disable path traversal "
           "sequences (../). Run application with least file-system privileges. Use a database or "
           "secure storage instead of direct file inclusion.",
    "ssrf": "Restrict outbound network access from the application server. Validate and whitelist "
            "allowed URLs/schemes. Block access to private IP ranges (169.254.0.0/16, 10.0.0.0/8, "
            "172.16.0.0/12, 192.168.0.0/16). Use a URL parser that rejects unexpected schemes.",
    "xxe": "Disable XML external entity processing in your XML parser. Use less complex data formats "
           "like JSON. If XML is required, configure the parser to disable DTDs and external entities.",
    "ssti": "Never render user input as template content. Use sandboxed template engines. "
            "Apply context-aware escaping. Validate input against expected patterns.",
    "cmd_injection": "Avoid passing user input to system commands. Use language-native APIs instead "
                     "of shell commands. Apply strict input validation and allowlisting. "
                     "Run with least OS privileges.",
    "command injection": "Avoid passing user input to system commands. Use language-native APIs instead "
                        "of shell commands. Apply strict input validation and allowlisting. "
                        "Run with least OS privileges.",
    "blind_xss": "Apply Content-Security-Policy with strict script-src. Use X-XSS-Protection headers. "
                 "Sanitize all user-controlled input before rendering. Monitor for unexpected HTTP callbacks.",
    "open_redirect": "Avoid redirect parameters in URLs. If needed, use a hardcoded mapping of "
                     "allowed destinations instead of accepting arbitrary URLs. Validate the "
                     "redirect target matches an allowed allowlist.",
    "csrf": "Implement anti-CSRF tokens on all state-changing endpoints. Use SameSite cookies "
            "(Strict or Lax). Require re-authentication for sensitive actions. "
            "Check Origin/Referer headers on the server side.",
    "idor": "Implement proper authorization checks for every resource access. Use indirect "
            "object references (mapped IDs). Verify user ownership for every requested resource. "
            "Apply the principle of least privilege on all API endpoints.",
    "graphql": "Disable introspection in production. Implement query cost analysis and depth limiting. "
               "Rate-limit queries per user/IP. Apply field-level authorization. "
               "Use persisted queries to limit allowed operations.",
    "sensitive_data": "Remove secrets from client-side code and logs. Use environment variables "
                      "or a secrets manager (AWS Secrets Manager, HashiCorp Vault). "
                      "Rotate exposed credentials immediately.",
    "sensitive data": "Remove secrets from client-side code and logs. Use environment variables "
                     "or a secrets manager (AWS Secrets Manager, HashiCorp Vault). "
                     "Rotate exposed credentials immediately.",
    "exposed js secret": "Remove hardcoded secrets from JavaScript bundles. Use server-side proxies "
                        "with proper authentication. Rotate the exposed credential and revoke it.",
    "headers": "Set security headers: Strict-Transport-Security, X-Content-Type-Options, "
               "X-Frame-Options, Content-Security-Policy, X-XSS-Protection, Referrer-Policy.",
    "clickjacking": "Set X-Frame-Options: DENY or SAMEORIGIN. Use Content-Security-Policy "
                    "frame-ancestors directive. Implement SameSite cookies.",
    "subdomain_takeover": "Remove the DNS CNAME record pointing to the external service. "
                          "Or claim the external service (cloud host, CDN, S3 bucket). "
                          "Monitor for dangling DNS records regularly.",
    "http_methods": "Restrict HTTP methods per endpoint. Disable PUT/DELETE on read-only endpoints. "
                    "Use HEAD and OPTIONS only where needed. Return 405 Method Not Allowed for "
                    "unsupported methods.",
    "insecure_forms": "Serve forms over HTTPS only. Set form action to HTTPS URL. "
                      "Use HSTS preload to enforce HTTPS across the domain.",
    "exposed_files": "Remove sensitive files from public web root. Deny access to .git, .env, "
                     "backup files via web server config. Store secrets outside webroot.",
    "rate_limiting": "Implement rate limiting on authentication endpoints (login, register, "
                     "password reset). Use exponential backoff account lockout. "
                     "Consider CAPTCHA after N failed attempts per IP/user.",
    "api": "Apply authentication and authorization on every API endpoint. Implement rate limiting. "
           "Validate request schemas. Use proper HTTP status codes for errors. "
           "Disable unnecessary HTTP methods. Log all security-relevant events.",
    "bola": "Implement proper authorization checks for every object access. "
            "Use indirect object references. Verify ownership before serving resources. "
            "Apply consistent access control across all API endpoints.",
    "mass assignment": "Use DTOs (Data Transfer Objects) to control which fields can be updated. "
                       "Do not bind request bodies directly to ORM entities. "
                       "Explicitly allowlist modifiable fields.",
    "potential idor": "Implement authorization checks for the affected parameter. "
                      "Use indirect object references. Verify that the requesting user "
                      "owns the resource.",
    "missing security header": "Set missing security headers. See the headers finding for "
                               "the full list of recommended security headers.",
    "weak csp": "Tighten Content-Security-Policy: remove 'unsafe-inline' and 'unsafe-eval' "
                "where possible. Use nonces or hashes for inline scripts.",
    "insecure cookie": "Set Secure, HttpOnly, and SameSite flags on all cookies. "
                       "Use __Host- prefix for cookies that must be origin-bound.",
    "server disclosure": "Remove or obfuscate server version headers. Use a reverse proxy "
                         "to strip or normalize response headers.",
    "missing rate limiting": "Implement rate limiting on the affected endpoint. "
                            "Use sliding window or token bucket algorithms. "
                            "Return 429 Too Many Requests with Retry-After header.",
}


def assess_finding_impact(finding: Union[Dict[str, Any], Finding]) -> Union[Dict[str, Any], Finding]:
    title = (finding.get("title") or finding.get("details") or "").lower()
    sev = finding.get("severity", "info").lower()
    matrix_entry = None
    for key in IMPACT_MATRIX:
        if title.startswith(key) or key in title:
            matrix_entry = IMPACT_MATRIX[key]
            break
    if not matrix_entry:
        finding_type = (finding.get("vuln_type") or "").lower()
        for key in IMPACT_MATRIX:
            if finding_type.startswith(key) or key in finding_type:
                matrix_entry = IMPACT_MATRIX[key]
                break
    if not matrix_entry:
        data_exp, ato, rce = {
            "critical": (5, 5, 5), "high": (4, 3, 2),
            "medium": (2, 1, 0), "low": (1, 0, 0),
        }.get(sev, (0, 0, 0))
    else:
        data_exp, ato, rce, biz_impact = matrix_entry
        finding["business_impact"] = biz_impact

    finding.setdefault("impact_assessment", {})
    ia = finding["impact_assessment"]
    ia["data_exposure"] = {"score": data_exp, "label": DATA_EXPOSURE_LABELS.get(data_exp, "Unknown")}
    ia["account_takeover_potential"] = {"score": ato, "label": ATO_LABELS.get(ato, "Unknown")}
    ia["rce_potential"] = {"score": rce, "label": RCE_LABELS.get(rce, "Unknown")}

    demonstrated = finding.get("demonstrated_impact", "").strip()
    is_theoretical = finding.get("verification_stage") in ("detected",)
    ia["demonstrated_impact"] = demonstrated or (
        "None yet — theoretical risk only (reflection confirmed, execution not verified)"
        if is_theoretical
        else IMPACT_VULN_EXAMPLES.get(title.split(" ")[0].lower() if title else "", "See evidence")
    )

    parts = []
    if biz_impact := finding.get("business_impact"):
        parts.append(f"Business: {biz_impact}")
    parts.append(f"Data exposure: {ia['data_exposure']['label']}")
    parts.append(f"ATO potential: {ia['account_takeover_potential']['label']}")
    parts.append(f"RCE potential: {ia['rce_potential']['label']}")
    parts.append(f"Demonstrated: {ia['demonstrated_impact']}")
    ia["narrative"] = " | ".join(parts)
    return finding


def group_by_root_cause(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group findings by their root-cause fingerprint (if present), falling back to vuln_type."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        rc = f.get("root_cause") or f.get("fingerprint", "")
        if not rc:
            rc = f.get("vuln_type", f.get("type", "unknown"))
        groups.setdefault(rc, []).append(f)

    # Enrich each group with merged metadata
    enriched: Dict[str, List[Dict[str, Any]]] = {}
    for rc, members in groups.items():
        grouped_urls = sorted({m.get("url", "") for m in members if m.get("url")})
        max_sev = max((m.get("severity", "info").lower() for m in members),
                      key=lambda s: ["info", "low", "medium", "high", "critical"].index(s)
                      if s in ["info", "low", "medium", "high", "critical"] else 0)
        max_stage = "verified" if any(m.get("verification_stage", "").lower() == "verified" for m in members) else \
                    "exploitable" if any(m.get("verification_stage", "").lower() == "exploitable" for m in members) else \
                    "validated" if any(m.get("verification_stage", "").lower() == "validated" for m in members) else \
                    "detected"
        max_confidence = max((m.get("confidence_score", 0) or 0 for m in members), default=0)

        for m in members:
            m["grouped_urls"] = grouped_urls
            m["group_severity"] = max_sev
            m["group_verification_stage"] = max_stage
            m["group_confidence"] = max_confidence

        enriched[rc] = members
    return enriched


class ReporterBase:
    SEVERITY_COLORS = {
        'critical': '#e74c3c', 'high': '#e67e22', 'medium': '#f1c40f',
        'low': '#3498db', 'info': '#95a5a6'
    }
    SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

    def __init__(self, config: Dict[str, Any],
                 findings: Union[List[Dict[str, Any]], List[Finding]],
                 recon_data: Dict[str, Any],
                 js_data: Optional[Dict[str, Any]] = None,
                 container=None):
        self.config = config
        self.container = container
        self.evidence_engine = container.evidence_engine if container else None
        # Normalize all findings to Finding instances
        normalized: list[Finding] = []
        for f in findings:
            if isinstance(f, Finding):
                normalized.append(f)
            elif isinstance(f, dict):
                normalized.append(Finding.from_dict(f))
            else:
                normalized.append(Finding.from_dict({"type": "unknown", "url": str(f)}))
        # Enrich with evidence-engine linked evidence
        enriched = self._enrich_finding_evidence(normalized)
        # Apply impact assessment (mutates finding in-place for dict-compat fields)
        impacted: list[Finding] = [assess_finding_impact(f) for f in enriched]
        # Evidence completeness validation — catches weak findings
        self.findings: list[Finding] = EvidenceCompletenessValidator.validate_all(impacted)
        # Root-cause aggregation
        aggregator = RootCauseAggregator(config)
        self.root_cause_groups: list[RootCauseGroup] = aggregator.aggregate(self.findings)
        self.recon_data = recon_data or {}
        self.js_data = js_data or {}
        self.target = config.get('target', 'target')
        self.timestamp = config.get('timestamp', datetime.now().strftime('%Y%m%d_%H%M%S'))
        self.output_dir = config.get('output_dir', './reports')
        self.report_format = config.get('report_format', 'html').lower()

    def _enrich_finding_evidence(self, findings: list[Finding]) -> list[Finding]:
        """Enrich each finding with evidence linked via EvidenceEngine.

        Looks up evidence by fingerprint first (what scanners use to link),
        then falls back to Finding.id.
        """
        if not self.evidence_engine:
            return findings
        for f in findings:
            # Try fingerprint first (scanners link evidence by fingerprint),
            # then by Finding.id (uuid7)
            linked = (
                self.evidence_engine.get_evidence(f.fingerprint)
                or self.evidence_engine.get_evidence(f.id)
            )
            if linked:
                if isinstance(f.evidence, str):
                    f.evidence = [f.evidence] if f.evidence else []
                existing_ids = {id(e) for e in f.evidence}
                for ev in linked:
                    if id(ev) not in existing_ids:
                        f.evidence.append(ev)
        return findings

    def _sanitize_target(self) -> str:
        safe = self.target.replace('https://', '').replace('http://', '').replace('/', '_')
        safe = safe.replace(':', '_').replace('?', '_').replace('&', '_')
        safe = safe.replace('.', '_').replace('#', '_')
        return safe

    def _get_report_path(self, ext: str, suffix: str | None = None) -> str:
        safe = self._sanitize_target()
        suffix_part = f".{suffix}" if suffix else ""
        return os.path.join(self.output_dir, f"{safe}_{self.timestamp}{suffix_part}.{ext}")

    def _sort_findings(self) -> List[Dict[str, Any]]:
        def sort_key(x):
            ps = x.get("priority_score")
            return -ps if ps is not None else self.SEVERITY_ORDER.get(x.get('severity', 'info').lower(), 4)
        return sorted(self.findings, key=sort_key)

    def _dedupe_findings(self) -> List[Dict[str, Any]]:
        seen = set()
        deduped = []
        for f in self.findings:
            fp = f.get("fingerprint", "")
            if not fp:
                fp = str(hash((f.get('title', ''), f.get('url', ''), f.get('severity', ''))))
            if fp not in seen:
                seen.add(fp)
                deduped.append(f)
        return deduped

    def _get_severity_counts(self) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in self.findings:
            sev = f.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _get_confirmed_counts(self) -> Dict[str, int]:
        confirmed_stages = {"verified", "exploitable", "validated"}
        c = sum(1 for f in self.findings if f.get("verification_stage", "").lower() in confirmed_stages)
        return {"confirmed": c, "unconfirmed": len(self.findings) - c}

    def _get_confidence_breakdown(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"confirmed": 0, "high": 0, "likely": 0, "unverified": 0}
        for f in self.findings:
            score = f.get("confidence_score")
            if score is None:
                counts["unverified"] += 1
            elif score >= 86:
                counts["confirmed"] += 1
            elif score >= 61:
                counts["high"] += 1
            elif score >= 31:
                counts["likely"] += 1
            else:
                counts["unverified"] += 1
        return counts

    def _get_verification_breakdown(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"detected": 0, "partially_validated": 0, "validated": 0, "exploitable": 0, "verified": 0}
        for f in self.findings:
            stage = f.get("verification_stage", "detected").lower()
            if stage in counts:
                counts[stage] += 1
        return counts

    def _get_historical_breakdown(self) -> dict[str, int]:
        counts: dict[str, int] = {
            "new": 0, "previously_seen": 0, "regressed": 0,
            "resolved": 0, "improved": 0, "degraded": 0,
        }
        for f in self.findings:
            hist = f.get("historical", {}) if isinstance(f, dict) else getattr(f, "historical", {})
            cls = hist.get("classification", "") if isinstance(hist, dict) else ""
            if cls in counts:
                counts[cls] += 1
        return counts

    def _has_history(self) -> bool:
        return bool(self._get_historical_breakdown().get("previously_seen", 0) +
                    self._get_historical_breakdown().get("regressed", 0))

    def _get_affected_component(self, url: str) -> str:
        cleaned = url.split("?")[0].split("#")[0]
        path = cleaned.rstrip("/")
        parts = [p for p in path.split("/") if p]
        if not parts:
            return "root"
        candidates = [p for p in parts if not p.startswith("http") and "." not in p]
        if len(candidates) >= 2:
            return "/".join(candidates[-2:])
        return candidates[-1] if candidates else (parts[-1] if parts else "root")

    def _get_cvss_score(self, finding: Dict[str, Any]) -> float:
        score = finding.get("cvss_score")
        if score is not None:
            return float(score)
        base = CVSS_BY_SEVERITY.get(finding.get("severity", "info").lower(), 0.0)
        # Adjust by verification stage: more confidence = higher score
        stage = str(finding.get("verification_stage", "detected")).lower()
        multipliers = {
            "verified": 1.0,
            "exploitable": 1.0,
            "validated": 0.85,
            "detected": 0.7,
            "partially_validated": 0.8,
        }
        return round(base * multipliers.get(stage, 0.7), 1)

    def _get_cvss_vector(self, finding: Dict[str, Any]) -> str:
        vec = finding.get("cvss_vector")
        if vec:
            return str(vec)
        base_vec = CVSS_VECTORS.get(finding.get("severity", "info").lower(),
                                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        # Adjust PR (Privileges Required) based on authentication context
        if finding.get("auth_header") or finding.get("cookies"):
            base_vec = base_vec.replace("/PR:N/", "/PR:L/")
        return base_vec

    def _severity_rating(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        return "None"

    def _finding_to_report_dict(self, f: Any) -> Dict[str, Any]:
        """Convert Finding to full report dict, preserving dynamic fields."""
        if isinstance(f, dict):
            return f
        result = f.to_dict()
        # Compute CVSS if not set
        if result.get("cvss_score") is None:
            result["cvss_score"] = self._get_cvss_score(f)
            result["cvss_vector"] = self._get_cvss_vector(f)
            result["cvss_rating"] = self._severity_rating(result["cvss_score"])
        # Compute remediation if not set
        if not result.get("remediation"):
            result["remediation"] = self._build_remediation(f)
        # Compute impact if not set
        if not result.get("impact"):
            result["impact"] = self._build_impact_narrative(f)
        # Preserve dynamic attributes set by assess_finding_impact / group_by_root_cause
        for attr in ('impact_assessment', 'confirmed', 'priority_score',
                     'group_severity', 'group_verification_stage', 'group_confidence',
                     'component', 'request_response', 'what_is_it', 'grouped_urls',
                     'business_impact', 'demonstrated_impact', 'historical'):
            if hasattr(f, attr):
                val = getattr(f, attr)
                if val is not None and val != "":
                    result[attr] = val
        return result

    def _findings_as_dicts(self, findings: Optional[List] = None) -> List[Dict[str, Any]]:
        if findings is None:
            findings = self.findings
        return [self._finding_to_report_dict(f) for f in findings]

    def _format_evidence(self, evidence: Any, max_lines: int = 15) -> str:
        if not evidence:
            return ""
        text = str(evidence)
        lines = text.splitlines()
        if len(lines) > max_lines:
            lines = lines[:max_lines] + ["... (truncated)"]
        return "\n".join(lines)

    def _build_executive_summary(self) -> str:
        sev = self._get_severity_counts()
        ver = self._get_verification_breakdown()
        conf = self._get_confidence_breakdown()
        hist = self._get_historical_breakdown()
        total = len(self.findings)

        # Top 3 most severe exploitable findings
        sorted_f = sorted(
            [f for f in self.findings if f.get("severity", "info").lower() in ("critical", "high")],
            key=lambda x: -(x.get("confidence_score", 0) or 0)
        )
        top_lines = []
        for f in sorted_f[:3]:
            title = f.get("title", "Finding")
            url = f.get("url", "")
            stage = f.get("verification_stage", "detected").replace("_", " ").title()
            score = f.get("confidence_score", 0)
            top_lines.append(f"- [{f.get('severity', 'INFO').upper()}] {title} @ {url} ({stage}, {score:.0f}/100)")

        top_text = "\n".join(top_lines) if top_lines else "  None"
        verified = ver.get("verified", 0)
        exploitable = ver.get("exploitable", 0)

        history_line = ""
        if any(v > 0 for v in hist.values()):
            parts = []
            if hist.get("new", 0):
                parts.append(f"New: {hist['new']}")
            if hist.get("previously_seen", 0):
                parts.append(f"Previously Seen: {hist['previously_seen']}")
            if hist.get("regressed", 0):
                parts.append(f"Regressed: {hist['regressed']}")
            if hist.get("improved", 0):
                parts.append(f"Improved: {hist['improved']}")
            if hist.get("degraded", 0):
                parts.append(f"Degraded: {hist['degraded']}")
            if hist.get("resolved", 0):
                parts.append(f"Resolved: {hist['resolved']}")
            if parts:
                history_line = f"Historical: {' | '.join(parts)}\n"

        return (
            f"Executive Summary\n"
            f"{'=' * 60}\n"
            f"Target: {self.target}\n"
            f"Scan Date: {self.timestamp}\n"
            f"Total Findings: {total}\n"
            f"Severity: Critical {sev.get('critical',0)} | High {sev.get('high',0)} | "
            f"Medium {sev.get('medium',0)} | Low {sev.get('low',0)} | Info {sev.get('info',0)}\n"
            f"Verification: Verified {verified} | Exploitable {exploitable} | "
            f"Validated {ver.get('validated',0)} | Partially Validated {ver.get('partially_validated',0)} | "
            f"Detected {ver.get('detected',0)}\n"
            f"Confidence: Confirmed {conf.get('confirmed',0)} | High {conf.get('high',0)} | "
            f"Likely {conf.get('likely',0)} | Unverified {conf.get('unverified',0)}\n"
            f"{history_line}"
            f"Top Critical/High Findings:\n{top_text}\n"
        )

    def _format_structured_impact(self, f: Any) -> str:
        ia = f.get("impact_assessment", {})
        if not ia:
            return ""
        parts = [
            f"Data Exposure: {ia.get('data_exposure', {}).get('label', 'N/A')}",
            f"ATO Potential: {ia.get('account_takeover_potential', {}).get('label', 'N/A')}",
            f"RCE Potential: {ia.get('rce_potential', {}).get('label', 'N/A')}",
        ]
        if ia.get("demonstrated_impact"):
            parts.append(f"Demonstrated: {ia['demonstrated_impact']}")
        return " | ".join(parts)

    def _build_curl_command(self, finding: Dict[str, Any]) -> str:
        req = finding.get("request", "")
        if req.startswith("curl"):
            return req
        url = finding.get("url", "")
        method = "POST" if finding.get("parameter") and "form" in finding.get("details", "").lower() else "GET"
        return _build_curl(method, url, {})

    def _build_impact_narrative(self, finding: Dict[str, Any]) -> str:
        what = finding.get("what_is_it") or finding.get("details", "")
        impact = finding.get("impact", "")
        sev = finding.get("severity", "info").lower()
        url = finding.get("url", "the affected endpoint")
        param = finding.get("parameter", "")
        evidence = finding.get("evidence", "")
        if isinstance(evidence, list):
            evidence = " ".join(str(e) for e in evidence)

        if impact:
            try:
                return impact.format(url=url, parameter=param, evidence=evidence)
            except KeyError:
                pass

        vuln_type = (finding.get("title") or "").lower()
        biz_impact = ""
        for key in IMPACT_MATRIX:
            if key in vuln_type:
                me = IMPACT_MATRIX.get(key)
                biz_impact = me[3] if me and len(me) > 3 else ""
                break

        param_str = f" via parameter `{param}`" if param else ""
        biz_line = f" Business impact: {biz_impact}." if biz_impact else ""
        ev_line = f" Evidence: {evidence[:120]}." if evidence else ""

        templates = {
            "critical": (
                f"This vulnerability at `{url}`{param_str} poses a severe risk to "
                f"confidentiality, integrity, and availability. Successful exploitation "
                f"could lead to complete compromise of the application, including arbitrary "
                f"code execution, data exfiltration, or full account takeover.{biz_line}{ev_line}"
            ),
            "high": (
                f"This vulnerability at `{url}`{param_str} can lead to significant "
                f"data disclosure, privilege escalation, or partial system compromise. "
                f"Immediate remediation is strongly recommended.{biz_line}{ev_line}"
            ),
            "medium": (
                f"Exploitation of `{url}`{param_str} may lead to limited information "
                f"disclosure, minor privilege escalation, or degraded security posture. "
                f"Should be addressed in the next maintenance cycle.{biz_line}{ev_line}"
            ),
            "low": (
                f"Limited practical impact at `{url}`{param_str} under normal conditions. "
                f"Risk is minimal but may be chained with other vulnerabilities.{ev_line}"
            ),
        }
        return templates.get(sev, f"See details for impact information at `{url}`.{ev_line}")

    def _build_remediation(self, finding: Union[Dict[str, Any], Finding]) -> str:
        rem = finding.get("remediation") or finding.get("recommendation", "")
        if rem:
            return rem
        vuln_type = (finding.get("title") or finding.get("details") or "").lower()
        # Check REMEDIATION_MATRIX first
        for key in REMEDIATION_MATRIX:
            if key in vuln_type:
                return REMEDIATION_MATRIX[key]
        finding_type = (finding.get("vuln_type") or "").lower()
        for key in REMEDIATION_MATRIX:
            if key in finding_type:
                return REMEDIATION_MATRIX[key]
        url = finding.get("url", "the affected endpoint")
        fallbacks = {
            "critical": f"Immediately review and fix the root cause at `{url}`. "
                        "Apply input validation, output encoding, proper authentication "
                        "checks, and access controls. Conduct a focused security review "
                        "of the affected component.",
            "high": f"Review and fix the vulnerability at `{url}`. Apply appropriate security "
                    "controls such as input sanitization, parameterized queries, "
                    "or access control hardening.",
            "medium": f"Review the affected functionality at `{url}` and apply standard security "
                      "best practices including input validation and proper authorization checks.",
        }
        return fallbacks.get(finding.get("severity", "").lower(),
                             f"Follow security best practices for `{url}`.")

    def _confidence_badge_html(self, score: Optional[float]) -> str:
        if score is None:
            return '<span style="color:#95a5a6">—</span>'
        score_class = "high" if score >= 61 else ("medium" if score >= 31 else "low")
        colors = {"low": "#e74c3c", "medium": "#f1c40f", "high": "#2ecc71"}
        return f'<span style="color:{colors[score_class]};font-weight:bold">{score:.0f}</span>'

    def _verification_badge_html(self, stage: Optional[str]) -> str:
        if not stage:
            return '<span style="color:#95a5a6">—</span>'
        colors = {"detected": "#e74c3c", "partially_validated": "#9b59b6", "validated": "#f39c12", "exploitable": "#2ecc71", "verified": "#27ae60"}
        color = colors.get(stage.lower(), "#95a5a6")
        label = stage.replace("_", " ").title()
        return f'<span style="color:{color};font-weight:bold">{label}</span>'

    # ── Root Cause Aggregation Utilities ─────────────────────────────────

    def root_cause_groups_to_dicts(self) -> list[Dict[str, Any]]:
        """Convert RootCauseGroup objects to serializable dicts."""
        return [g.to_dict() for g in self.root_cause_groups]

    def _rc_group_severity_color(self, severity: str) -> str:
        return self.SEVERITY_COLORS.get(severity, '#95a5a6')

    def _rc_group_severity_badge_html(self, severity: str) -> str:
        return f'<span class="sev-badge sev-{severity}" style="background:{self.SEVERITY_COLORS.get(severity, "#95a5a6")}">{severity.upper()}</span>'

    def _render_root_cause_sections_html(self) -> str:
        """Render root cause aggregation sections for HTML reports.
        Returns HTML string to insert before individual findings.
        """
        if not self.root_cause_groups or len(self.root_cause_groups) <= 1:
            return ""
        parts = ['<section id="root-causes">',
                 '<h2>Root Cause Summary</h2>',
                 '<p class="text2" style="margin-bottom:16px">Findings grouped by shared root cause — '
                 f'{len(self.root_cause_groups)} root causes across {len(self.findings)} findings.</p>']
        for group in self.root_cause_groups:
            color = self._rc_group_severity_color(group.severity)
            parts.append(f'<div class="finding-card {group.severity}" style="margin-bottom:16px">')
            parts.append('<div class="finding-header">')
            parts.append(f'<span class="finding-title" style="border-left:3px solid {color};padding-left:8px">{html.escape(group.root_cause)}</span>')
            parts.append('<span class="finding-meta">')
            parts.append(self._rc_group_severity_badge_html(group.severity))
            parts.append(f'<span class="conf-badge conf-high" style="background:{color};color:#fff">{group.count} findings</span>')
            parts.append(f'<span class="stage-badge">{len(group.affected_endpoints)} endpoints</span>')
            parts.append('</span></div>')
            parts.append('<div class="finding-body">')
            parts.append(f'<div class="row"><strong>Root Cause:</strong> {html.escape(group.root_cause)}</div>')
            parts.append(f'<div class="row"><strong>Confidence:</strong> {group.confidence:.0f}/100</div>')
            parts.append(f'<div class="row"><strong>Evidence:</strong> {html.escape(group.evidence_summary)}</div>')
            parts.append(f'<div class="row"><strong>Vulnerability Types:</strong> {", ".join(html.escape(t) for t in group.vulnerability_types)}</div>')
            parts.append(f'<div class="row"><strong>Affected Endpoints ({len(group.affected_endpoints)}):</strong></div>')
            parts.append('<ul style="margin:4px 0 12px 20px;font-family:\'Courier New\',monospace;font-size:.85em">')
            for ep in group.affected_endpoints:
                parts.append(f'<li>{html.escape(ep)}</li>')
            parts.append('</ul>')
            parts.append('</div></div>')
        parts.append('</section>')
        return "\n".join(parts)

    def _render_root_cause_sections_txt(self) -> str:
        """Render root cause aggregation for text reports."""
        if not self.root_cause_groups or len(self.root_cause_groups) <= 1:
            return ""
        lines = [
            "=" * 70,
            "ROOT CAUSE SUMMARY",
            "=" * 70,
            f"Findings grouped by root cause: {len(self.root_cause_groups)} groups across {len(self.findings)} findings",
            "",
        ]
        for i, group in enumerate(self.root_cause_groups, 1):
            lines.append(f"  {i}. {group.root_cause.upper()} [{group.severity.upper()}]")
            lines.append(f"     Confidence: {group.confidence:.0f}/100")
            lines.append(f"     Findings: {group.count} | Endpoints: {len(group.affected_endpoints)}")
            lines.append(f"     Vulnerability types: {', '.join(group.vulnerability_types)}")
            lines.append(f"     Affected Endpoints:")
            for ep in group.affected_endpoints:
                lines.append(f"       - {ep}")
            lines.append("")
        lines.append("-" * 70)
        return "\n".join(lines)

    def _render_root_cause_sections_md(self) -> str:
        """Render root cause aggregation for Markdown/ChatGPT reports."""
        if not self.root_cause_groups or len(self.root_cause_groups) <= 1:
            return ""
        lines = [
            "---",
            "## Root Cause Summary",
            "",
            f"Findings grouped by shared root cause: {len(self.root_cause_groups)} groups across {len(self.findings)} findings.",
            "",
        ]
        for group in self.root_cause_groups:
            lines.append(f"### {group.root_cause}")
            lines.append(f"**Severity:** {group.severity.upper()} | **Findings:** {group.count} | **Confidence:** {group.confidence:.0f}/100")
            lines.append(f"**Vulnerability Types:** {', '.join(group.vulnerability_types)}")
            lines.append("**Affected Endpoints:**")
            for ep in group.affected_endpoints:
                lines.append(f"- `{ep}`")
            lines.append("")
        lines.append("---")
        lines.append("")
        return "\n".join(lines)

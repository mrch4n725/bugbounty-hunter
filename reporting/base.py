import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.utils import log, Colors, _build_curl


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


def assess_finding_impact(finding: Dict[str, Any]) -> Dict[str, Any]:
    title = (finding.get("title") or finding.get("details") or "").lower()
    sev = finding.get("severity", "info").lower()
    matrix_entry = None
    for key in IMPACT_MATRIX:
        if title.startswith(key) or key in title:
            matrix_entry = IMPACT_MATRIX[key]
            break
    if not matrix_entry:
        finding_type = (finding.get("type") or "").lower()
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

    def __init__(self, config: Dict[str, Any], findings: List[Dict[str, Any]],
                 recon_data: Dict[str, Any], js_data: Optional[Dict[str, Any]] = None):
        self.config = config
        self.findings = [assess_finding_impact(f) for f in findings]
        self.recon_data = recon_data or {}
        self.js_data = js_data or {}
        self.target = config.get('target', 'target')
        self.timestamp = config.get('timestamp', datetime.now().strftime('%Y%m%d_%H%M%S'))
        self.output_dir = config.get('output_dir', './reports')
        self.report_format = config.get('report_format', 'html').lower()

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
            key = (f.get('title', ''), f.get('url', ''), f.get('severity', ''),
                   f.get('details', ''), f.get('evidence', ''))
            if key not in seen:
                seen.add(key)
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
        c = sum(1 for f in self.findings if f.get("confirmed"))
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
        counts: Dict[str, int] = {"detected": 0, "validated": 0, "exploitable": 0}
        for f in self.findings:
            stage = f.get("verification_stage", "detected").lower()
            if stage in counts:
                counts[stage] += 1
        return counts

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
        return CVSS_BY_SEVERITY.get(finding.get("severity", "info").lower(), 0.0)

    def _get_cvss_vector(self, finding: Dict[str, Any]) -> str:
        vec = finding.get("cvss_vector")
        if vec:
            return str(vec)
        return CVSS_VECTORS.get(finding.get("severity", "info").lower(),
                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")

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

    def _format_evidence(self, evidence: Any, max_lines: int = 15) -> str:
        if not evidence:
            return ""
        text = str(evidence)
        lines = text.splitlines()
        if len(lines) > max_lines:
            lines = lines[:max_lines] + ["... (truncated)"]
        return "\n".join(lines)

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

        if impact:
            return impact.format(url=url, parameter=param, evidence=evidence)

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

    def _build_remediation(self, finding: Dict[str, Any]) -> str:
        rem = finding.get("remediation") or finding.get("recommendation", "")
        if rem:
            return rem.format(url=finding.get("url", "the affected endpoint"),
                              parameter=finding.get("parameter", ""),
                              evidence=finding.get("evidence", ""))
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
        colors = {"detected": "#e74c3c", "validated": "#f39c12", "exploitable": "#2ecc71"}
        color = colors.get(stage.lower(), "#95a5a6")
        return f'<span style="color:{color};font-weight:bold">{stage.title()}</span>'

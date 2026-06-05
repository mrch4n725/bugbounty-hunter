import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


# Severity → CVSS 3.1 base score mapping (fallback when finding lacks cvss_score)
CVSS_BY_SEVERITY: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
}

CVSS_VECTORS: Dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "low": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "info": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}


# ── Impact assessment matrix ────────────────────────────────────────────────────
# Maps vulnerability type → (data_exposure, ato_potential, rce_potential, biz_impact_desc)
IMPACT_MATRIX: Dict[str, tuple] = {
    "xss":             (2, 5, 0, "Account takeover via session theft, phishing, or UI redressing"),
    "sqli":            (5, 4, 2, "Full database exfiltration, authentication bypass, data integrity loss"),
    "lfi":             (4, 0, 0, "Source code disclosure, credential leak, path traversal data access"),
    "ssrf":            (4, 0, 4, "Internal network scanning, cloud metadata access, pivot to internal services"),
    "xxe":             (5, 0, 3, "File disclosure, SSRF pivot, denial of service, data exfiltration"),
    "cmd_injection":   (5, 5, 5, "Full server compromise, lateral movement, data destruction or exfiltration"),
    "blind_xss":       (2, 4, 0, "Session hijacking of privileged users, admin panel compromise"),
    "open_redirect":   (0, 2, 0, "Phishing, Bypassing URL allowlists, OAuth token theft"),
    "csrf":            (0, 3, 0, "State-changing actions on behalf of authenticated users"),
    "idor":            (5, 3, 0, "Unauthorized access to other users' private data, privilege escalation"),
    "graphql":         (4, 2, 1, "Data disclosure via introspection, batch attacks, query depth abuse"),
    "sensitive_data":  (5, 0, 0, "Secrets in source/response enable lateral attacks, cloud compromise"),
    "headers":         (0, 0, 0, "Increased attack surface, missing clickjacking/HSTS protection"),
    "clickjacking":    (0, 0, 0, "UI redressing, mouse-jacking — chained with XSS for account takeover"),
    "subdomain_takeover": (0, 2, 0, "Brand impersonation, phishing, credential harvesting"),
    "command_injection": (5, 5, 5, "Full server compromise, lateral movement, data destruction or exfiltration"),
}

IMPACT_VULN_EXAMPLES: Dict[str, str] = {
    "xss":             "alert(1) in browser context",
    "sqli":            "UNION-based data extraction or blind boolean inference",
    "lfi":             "/etc/passwd read or log poisoning → RCE",
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
    """Assess and enrich a finding with detailed impact analysis."""
    title = (finding.get("title") or finding.get("details") or "").lower()
    vuln_type = title.split(" ")[0].lower() if title else ""
    sev = finding.get("severity", "info").lower()

    matrix_entry = None
    # best-match vuln type
    for key in IMPACT_MATRIX:
        if key in title or title.startswith(key):
            matrix_entry = IMPACT_MATRIX[key]
            break
    if not matrix_entry:
        # fallback by severity
        data_exp, ato, rce = {
            "critical": (5, 5, 5),
            "high": (4, 3, 2),
            "medium": (2, 1, 0),
            "low": (1, 0, 0),
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
        else IMPACT_VULN_EXAMPLES.get(vuln_type, "See evidence")
    )

    # combine into overall textual impact
    parts = []
    if biz_impact := finding.get("business_impact"):
        parts.append(f"Business: {biz_impact}")
    parts.append(f"Data exposure: {ia['data_exposure']['label']}")
    parts.append(f"ATO potential: {ia['account_takeover_potential']['label']}")
    parts.append(f"RCE potential: {ia['rce_potential']['label']}")
    parts.append(f"Demonstrated: {ia['demonstrated_impact']}")
    ia["narrative"] = " | ".join(parts)

    return finding


class Reporter:
    """
    Generates vulnerability scan reports in multiple formats (HTML, JSON, TXT, Markdown, HackerOne, Bugcrowd).
    
    Attributes:
        config (Dict): Configuration dictionary containing target, output_dir, timestamp, report_format
        findings (List): List of vulnerability findings
        recon_data (Dict): Reconnaissance data containing subdomains and URLs
    """
    
    # Severity color mapping
    SEVERITY_COLORS = {
        'critical': '#e74c3c',
        'high': '#e67e22',
        'medium': '#f1c40f',
        'low': '#3498db',
        'info': '#95a5a6'
    }
    
    # Severity order for sorting
    SEVERITY_ORDER = {
        'critical': 0,
        'high': 1,
        'medium': 2,
        'low': 3,
        'info': 4
    }
    
    def __init__(self, config: Dict[str, Any], findings: List[Dict[str, Any]], recon_data: Dict[str, Any]):
        """
        Initialize the Reporter.
        
        Args:
            config (Dict): Configuration dictionary with target, output_dir, timestamp, report_format
            findings (List): List of vulnerability findings
            recon_data (Dict): Reconnaissance data with subdomains and URLs
        """
        self.config = config
        self.findings = findings
        self.recon_data = recon_data or {}
        self.target = config.get('target', 'target')
        self.timestamp = config.get('timestamp', datetime.now().strftime('%Y%m%d_%H%M%S'))
        self.output_dir = config.get('output_dir', './reports')
        self.report_format = config.get('report_format', 'html').lower()

        # Run impact assessment on all findings
        self.findings = [assess_finding_impact(f) for f in self.findings]
        
    def _sanitize_target(self) -> str:
        """
        Sanitize target name by removing special characters.
        
        Returns:
            str: Sanitized target name
        """
        safe_target = self.target.replace('https://', '').replace('http://', '').replace('/', '_')
        safe_target = safe_target.replace(':', '_').replace('?', '_').replace('&', '_')
        safe_target = safe_target.replace('.', '_').replace('#', '_')
        return safe_target

    def _get_report_path(self, file_extension: str, suffix: str | None = None) -> str:
        safe_target = self._sanitize_target()
        suffix_part = f".{suffix}" if suffix else ""
        filename = f"{safe_target}_{self.timestamp}{suffix_part}.{file_extension}"
        return os.path.join(self.output_dir, filename)
    
    def _sort_findings(self) -> List[Dict[str, Any]]:
        """
        Sort findings by severity level.
        
        Returns:
            List: Sorted findings list
        """
        return sorted(self.findings, key=lambda x: self.SEVERITY_ORDER.get(x.get('severity', 'info').lower(), 4))
    
    def _dedupe_findings(self) -> List[Dict[str, Any]]:
        """
        Remove obvious duplicate findings while preserving order.
        """
        seen = set()
        deduped = []
        for finding in self.findings:
            key = (
                finding.get('title', ''),
                finding.get('url', ''),
                finding.get('severity', ''),
                finding.get('details', ''),
                finding.get('evidence', ''),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        return deduped

    def _get_severity_counts(self) -> Dict[str, int]:
        """
        Count findings by severity level.
        
        Returns:
            Dict: Dictionary with severity counts
        """
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in self.findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _get_confirmed_counts(self) -> Dict[str, int]:
        """Return (confirmed, unconfirmed) counts."""
        confirmed = sum(1 for f in self.findings if f.get("confirmed"))
        return {"confirmed": confirmed, "unconfirmed": len(self.findings) - confirmed}

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

    def _create_findings_table_html(self, sorted_findings: List[Dict[str, Any]]) -> str:
        if not sorted_findings:
            return '<div class="empty-message">No vulnerabilities found.</div>'
        
        rows = '<table><thead><tr><th>Title</th><th>URL</th><th>Severity</th><th>Confidence</th><th>Verification</th><th>Details</th></tr></thead><tbody>'
        for finding in sorted_findings:
            severity = finding.get('severity', 'info').lower()
            confidence_score = finding.get('confidence_score')
            verification_stage = finding.get('verification_stage', '')
            evidence_strength = finding.get('evidence_strength', '')
            fpr = finding.get('false_positive_risk', '')
            details = finding.get('details', 'N/A')
            evidence = finding.get('evidence', '')
            validation_steps = finding.get('validation_steps', [])
            recommendation = finding.get('recommendation', '')
            details_html = f"<div>{details}</div>"
            if evidence:
                details_html += f"<div><strong>Evidence:</strong> {evidence}</div>"
            if validation_steps:
                steps = "<br>".join(f"▸ {s}" for s in validation_steps[:5])
                details_html += f"<div><strong>Validation:</strong><br>{steps}</div>"
            if recommendation:
                details_html += f"<div><strong>Recommendation:</strong> {recommendation}</div>"
            if fpr:
                details_html += f"<div><strong>FP Risk:</strong> {fpr}</div>"

            rows += f'''<tr>
                    <td>{finding.get('title', 'N/A')}</td>
                    <td><span class="url">{finding.get('url', 'N/A')}</span></td>
                    <td><span class="severity-badge severity-{severity}">{severity.upper()}</span></td>
                    <td style="text-align:center">{self._confidence_badge_html(confidence_score)}</td>
                    <td style="text-align:center">{self._verification_badge_html(verification_stage)}</td>
                    <td><div class="detail-text">{details_html}</div></td>
                </tr>'''
        rows += '</tbody></table>'
        return rows
    
    def _create_subdomains_section_html(self, subdomains: List[str]) -> str:
        """
        Create HTML section for discovered subdomains.
        
        Args:
            subdomains (List): List of discovered subdomains
            
        Returns:
            str: HTML section content
        """
        if not subdomains:
            return ''
        
        content = '<section><h2>Discovered Subdomains</h2><ul>'
        for subdomain in subdomains:
            content += f'<li><span class="url">{subdomain}</span></li>'
        content += '</ul></section>'
        return content
    
    def _create_urls_section_html(self, urls: List[str]) -> str:
        """
        Create HTML section for discovered URLs.
        
        Args:
            urls (List): List of discovered URLs
            
        Returns:
            str: HTML section content
        """
        if not urls:
            return ''
        
        content = '<section><h2>Discovered URLs</h2><ul>'
        for url in urls:
            content += f'<li><span class="url">{url}</span></li>'
        content += '</ul></section>'
        return content

    def _create_config_section_html(self) -> str:
        """
        Create HTML section for scan configuration.
        """
        modules = self.config.get('modules', [])
        module_params = self.config.get('module_params', {})
        config_items = [
            f"Target: <strong>{self.target}</strong>",
            f"Format: <strong>{self.report_format.upper()}</strong>",
            f"Modules: <strong>{', '.join(modules)}</strong>",
            f"Threads: <strong>{self.config.get('threads')}</strong>",
            f"Timeout: <strong>{self.config.get('timeout')}s</strong>",
            f"Crawl Depth: <strong>{self.config.get('crawl_depth')}</strong>",
            f"Max URLs: <strong>{self.config.get('max_urls')}</strong>",
            f"Retries: <strong>{self.config.get('retries')}</strong>",
            f"Passive Mode: <strong>{self.config.get('passive')}</strong>",
            f"Module Parameters: <strong>{module_params}</strong>",
        ]
        items = ''.join(f'<li>{item}</li>' for item in config_items)
        return f'<section><h2>Scan Configuration</h2><ul>{items}</ul></section>'
    
    def _create_html_report(self) -> str:
        """
        Generate HTML report with dark theme.
        
        Returns:
            str: HTML report content
        """
        sorted_findings = self._sort_findings()
        severity_counts = self._get_severity_counts()
        confirm_counts = self._get_confirmed_counts()
        confidence_breakdown = self._get_confidence_breakdown()
        verification_breakdown = self._get_verification_breakdown()
        subdomains = self.recon_data.get('subdomains', [])
        urls = self.recon_data.get('urls', [])
        
        findings_table = self._create_findings_table_html(sorted_findings)
        config_section = self._create_config_section_html()
        subdomains_section = self._create_subdomains_section_html(subdomains)
        urls_section = self._create_urls_section_html(urls)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {self.target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            background-color: #1a1a1a;
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        header {{
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #333;
            padding-bottom: 20px;
        }}
        
        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            color: #fff;
        }}
        
        .timestamp {{
            color: #999;
            font-size: 0.9em;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .card {{
            background: #2a2a2a;
            border-left: 5px solid;
            padding: 20px;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }}
        
        .card.critical {{
            border-left-color: {self.SEVERITY_COLORS['critical']};
        }}
        
        .card.high {{
            border-left-color: {self.SEVERITY_COLORS['high']};
        }}
        
        .card.medium {{
            border-left-color: {self.SEVERITY_COLORS['medium']};
        }}
        
        .card.low {{
            border-left-color: {self.SEVERITY_COLORS['low']};
        }}
        
        .card.info {{
            border-left-color: {self.SEVERITY_COLORS['info']};
        }}
        
        .card-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .card-label {{
            font-size: 0.9em;
            color: #999;
            text-transform: uppercase;
        }}
        
        section {{
            margin-bottom: 40px;
            background: #2a2a2a;
            padding: 20px;
            border-radius: 4px;
        }}
        
        section h2 {{
            font-size: 1.8em;
            margin-bottom: 20px;
            border-bottom: 2px solid #444;
            padding-bottom: 10px;
            color: #fff;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        table thead {{
            background-color: #333;
        }}
        
        table th {{
            padding: 12px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #444;
        }}
        
        table td {{
            padding: 12px;
            border-bottom: 1px solid #444;
        }}
        
        table tr:hover {{
            background-color: #333;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }}
        
        .severity-critical {{
            background-color: {self.SEVERITY_COLORS['critical']};
            color: white;
        }}
        
        .severity-high {{
            background-color: {self.SEVERITY_COLORS['high']};
            color: white;
        }}
        
        .severity-medium {{
            background-color: {self.SEVERITY_COLORS['medium']};
            color: black;
        }}
        
        .severity-low {{
            background-color: {self.SEVERITY_COLORS['low']};
            color: white;
        }}
        
        .severity-info {{
            background-color: {self.SEVERITY_COLORS['info']};
            color: white;
        }}
        
        .detail-text {{
            font-size: 0.9em;
            color: #ccc;
            word-break: break-word;
        }}
        
        .url {{
            font-family: 'Courier New', monospace;
            background-color: #1a1a1a;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.85em;
        }}
        
        .empty-message {{
            color: #999;
            font-style: italic;
            padding: 20px;
            text-align: center;
        }}
        
        ul {{
            margin-left: 20px;
        }}
        
        li {{
            margin-bottom: 8px;
            color: #ccc;
        }}
        
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #333;
            color: #999;
            font-size: 0.85em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 Bug Bounty Report</h1>
            <p class="timestamp">Target: <strong>{self.target}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <section class="summary">
            <div class="card critical">
                <div class="card-label">Critical</div>
                <div class="card-value">{severity_counts['critical']}</div>
            </div>
            <div class="card high">
                <div class="card-label">High</div>
                <div class="card-value">{severity_counts['high']}</div>
            </div>
            <div class="card medium">
                <div class="card-label">Medium</div>
                <div class="card-value">{severity_counts['medium']}</div>
            </div>
            <div class="card low">
                <div class="card-label">Low</div>
                <div class="card-value">{severity_counts['low']}</div>
            </div>
            <div class="card info">
                <div class="card-label">Info</div>
                <div class="card-value">{severity_counts['info']}</div>
            </div>
            <div class="card" style="background:#2a2a2a;border-left:5px solid #2ecc71;padding:20px;border-radius:4px">
                <div class="card-label">Confirmed</div>
                <div class="card-value">{confirm_counts['confirmed']}</div>
            </div>
            <div class="card" style="background:#2a2a2a;border-left:5px solid #e74c3c;padding:20px;border-radius:4px">
                <div class="card-label">Unconfirmed</div>
                <div class="card-value">{confirm_counts['unconfirmed']}</div>
            </div>
            <div class="card" style="background:#2a2a2a;border-left:5px solid #2ecc71;padding:20px;border-radius:4px">
                <div class="card-label">Confirmed</div>
                <div class="card-value">{confidence_breakdown['confirmed']}</div>
            </div>
            <div class="card" style="background:#2a2a2a;border-left:5px solid #f39c12;padding:20px;border-radius:4px">
                <div class="card-label">Validated</div>
                <div class="card-value">{verification_breakdown['validated']}</div>
            </div>
            <div class="card" style="background:#2a2a2a;border-left:5px solid #e74c3c;padding:20px;border-radius:4px">
                <div class="card-label">Detected</div>
                <div class="card-value">{verification_breakdown['detected']}</div>
            </div>
            <div class="card" style="background:#2a2a2a;border-left:5px solid #9b59b6;padding:20px;border-radius:4px">
                <div class="card-label">Exploitable</div>
                <div class="card-value">{verification_breakdown['exploitable']}</div>
            </div>
        </section>
        
        {config_section}
        <section>
            <h2>Vulnerability Findings</h2>
            {findings_table}
        </section>
        
        {subdomains_section}
        {urls_section}
        
        <footer>
            <p>This report was generated by BugBounty Hunter</p>
        </footer>
    </div>
</body>
</html>"""
        
        return html_content
    
    def _create_json_report(self) -> str:
        """
        Generate JSON report with structured data.
        
        Returns:
            str: JSON report content
        """
        sorted_findings = self._sort_findings()
        severity_counts = self._get_severity_counts()
        confirm_counts = self._get_confirmed_counts()
        confidence_breakdown = self._get_confidence_breakdown()
        verification_breakdown = self._get_verification_breakdown()
        
        report_data = {
            'metadata': {
                'target': self.target,
                'timestamp': self.timestamp,
                'report_date': datetime.now().isoformat(),
                'total_findings': len(self.findings)
            },
            'scan_config': {
                'modules': self.config.get('modules', []),
                'report_format': self.config.get('report_format'),
                'threads': self.config.get('threads'),
                'timeout': self.config.get('timeout'),
                'crawl_depth': self.config.get('crawl_depth'),
                'passive': self.config.get('passive'),
                'verify_ssl': self.config.get('verify_ssl'),
                'proxy': self.config.get('proxy'),
                'retries': self.config.get('retries'),
                'module_params': self.config.get('module_params', {})
            },
            'summary': {
                'severity': severity_counts,
                'confidence': confidence_breakdown,
                'verification_stage': verification_breakdown,
            },
            'verification': confirm_counts,
            'findings': sorted_findings,
            'recon_data': {
                'subdomains': self.recon_data.get('subdomains', []),
                'urls': self.recon_data.get('urls', [])
            }
        }
        
        return json.dumps(report_data, indent=2)
    
    def _create_txt_report(self) -> str:
        """
        Generate plain text report.
        
        Returns:
            str: Text report content
        """
        sorted_findings = self._sort_findings()
        severity_counts = self._get_severity_counts()
        confirm_counts = self._get_confirmed_counts()
        subdomains = self.recon_data.get('subdomains', [])
        urls = self.recon_data.get('urls', [])
        
        txt_content = f"""
{'='*80}
BUG BOUNTY REPORT
{'='*80}

Target: {self.target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Timestamp: {self.timestamp}
Modules: {', '.join(self.config.get('modules', []))}
Threads: {self.config.get('threads')}
Timeout: {self.config.get('timeout')}s
Retries: {self.config.get('retries')}
Crawl Depth: {self.config.get('crawl_depth')}
Max URLs: {self.config.get('max_urls')}
Passive Mode: {self.config.get('passive')}
Module Parameters: {self.config.get('module_params', {})}

{'='*80}
SUMMARY
{'='*80}

Critical: {severity_counts['critical']}
High: {severity_counts['high']}
Medium: {severity_counts['medium']}
Low: {severity_counts['low']}
Info: {severity_counts['info']}

Total Findings: {len(self.findings)}
Confirmed: {confirm_counts['confirmed']}
Unconfirmed: {confirm_counts['unconfirmed']}

{'='*80}
VULNERABILITY FINDINGS
{'='*80}

"""
        
        if not sorted_findings:
            txt_content += "\nNo vulnerabilities found.\n"
        else:
            for i, finding in enumerate(sorted_findings, 1):
                score = finding.get('confidence_score')
                score_str = f"{score:.0f}/100" if score is not None else "—"
                stage = finding.get('verification_stage', '').title() or "—"
                fpr = finding.get('false_positive_risk', '')
                evidence_strength = finding.get('evidence_strength', '')
                txt_content += f"""
[{i}] {finding.get('title', 'N/A')}
    Severity    : {finding.get('severity', 'N/A').upper()}
    Confidence  : {score_str}
    Verification: {stage}
    FP Risk     : {fpr or '—'}
    Evidence    : {evidence_strength or '—'}
    URL         : {finding.get('url', 'N/A')}
    Details     : {finding.get('details', 'N/A')}
"""
                if finding.get('evidence'):
                    txt_content += f"    Raw Evidence: {finding['evidence'][:200]}\n"
                validation_steps = finding.get('validation_steps', [])
                if validation_steps:
                    for vs in validation_steps[:5]:
                        txt_content += f"    ⬩ {vs}\n"
                if finding.get('impact'):
                    txt_content += f"    Impact: {finding['impact']}\n"
                if finding.get('recommendation'):
                    txt_content += f"    Fix    : {finding['recommendation']}\n"
                txt_content += "\n"
        
        if subdomains:
            txt_content += f"""
{'='*80}
DISCOVERED SUBDOMAINS ({len(subdomains)})
{'='*80}

"""
            for subdomain in subdomains:
                txt_content += f"  - {subdomain}\n"
        
        if urls:
            txt_content += f"""
{'='*80}
DISCOVERED URLS ({len(urls)})
{'='*80}

"""
            for url in urls:
                txt_content += f"  - {url}\n"
        
        txt_content += f"""
{'='*80}
End of Report
{'='*80}
"""
        
        return txt_content
    
    # ------------------------------------------------------------------
    # Markdown-per-finding report generation
    # ------------------------------------------------------------------

    @staticmethod
    def _get_affected_component(url: str) -> str:
        """Extract a meaningful component name from a URL path."""
        cleaned = url.split("?")[0].split("#")[0]
        path = cleaned.rstrip("/")
        parts = [p for p in path.split("/") if p]
        # Skip protocol/host parts: try to return last 2 meaningful path segments
        if not parts:
            return "root"
        # Heuristic: skip TLD-looking parts if the URL is short
        candidates = [p for p in parts if not p.startswith("http") and "." not in p]
        if len(candidates) >= 2:
            return "/".join(candidates[-2:])
        if candidates:
            return candidates[-1]
        # Last resort – return the final path segment as-is
        return parts[-1] if parts else "root"

    def _get_cvss_score(self, finding: Dict[str, Any]) -> float:
        sev = finding.get("severity", "info").lower()
        score = finding.get("cvss_score")
        if score is not None:
            return float(score)
        return CVSS_BY_SEVERITY.get(sev, 0.0)

    def _get_cvss_vector(self, finding: Dict[str, Any]) -> str:
        sev = finding.get("severity", "info").lower()
        vec = finding.get("cvss_vector")
        if vec:
            return str(vec)
        return CVSS_VECTORS.get(sev, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")

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

    def _build_impact_narrative(self, finding: Dict[str, Any]) -> str:
        """Construct an impact paragraph from available metadata."""
        what = finding.get("what_is_it") or finding.get("details", "")
        impact = finding.get("impact", "")
        sev = finding.get("severity", "info").lower()

        if impact:
            return impact
        # Fallback template-based impact
        templates = {
            "critical": "This vulnerability poses a severe risk to the confidentiality, "
                       "integrity, and availability of the affected system. "
                       "Successful exploitation could lead to complete compromise of the "
                       "application, including arbitrary code execution, data exfiltration, "
                       "or full account takeover.",
            "high": "This vulnerability can lead to significant data disclosure, "
                    "privilege escalation, or partial system compromise. "
                    "Immediate remediation is strongly recommended.",
            "medium": "Exploitation may lead to limited information disclosure, "
                      "minor privilege escalation, or degraded security posture. "
                      "Should be addressed in the next maintenance cycle.",
            "low": "Limited practical impact under normal conditions. "
                   "Risk is minimal but may be chained with other vulnerabilities.",
        }
        return templates.get(sev, "See details for impact information.")

    def _build_remediation(self, finding: Dict[str, Any]) -> str:
        rem = finding.get("remediation") or finding.get("recommendation", "")
        if rem:
            return rem
        # Generic fallback per severity
        fallbacks = {
            "critical": "Immediately review and fix the root cause. "
                        "Apply input validation, output encoding, proper authentication "
                        "checks, and access controls. Conduct a focused security review "
                        "of the affected component.",
            "high": "Review and fix the vulnerability. Apply appropriate security "
                    "controls such as input sanitization, parameterized queries, "
                    "or access control hardening.",
            "medium": "Review the affected functionality and apply standard security "
                      "best practices including input validation and proper authorization checks.",
        }
        return fallbacks.get(finding.get("severity", "").lower(),
                             "Follow security best practices for the affected component.")

    def _call_triage_assist(self, finding: Dict[str, Any]) -> Dict[str, str]:
        """Use OpenAI to enhance the impact narrative if the API key is set."""
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            return {}
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            prompt = (
                f"You are a senior application security engineer triaging findings.\n\n"
                f"Vulnerability: {finding.get('title', 'Unknown')}\n"
                f"Severity: {finding.get('severity', 'info').upper()}\n"
                f"URL: {finding.get('url', 'N/A')}\n"
                f"Details: {finding.get('details', 'N/A')}\n"
                f"Evidence: {finding.get('evidence', 'N/A')}\n\n"
                f"Return a JSON object with exactly two keys:\n"
                f"  - impact: a 2–4 sentence business-impact description\n"
                f"  - remediation: a 2–4 sentence actionable fix recommendation\n"
                f"Return ONLY the JSON object, no markdown fences."
            )
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=500,
            )
            text = resp.choices[0].message.content.strip()
            # Attempt to strip any accidental markdown fences
            if text.startswith("```"):
                text = text.split("\n", 1)[-1]
                text = text.rsplit("```", 1)[0].strip()
            result = json.loads(text)
            if not isinstance(result, dict):
                return {}
            return {k: v for k, v in result.items() if isinstance(v, str)}
        except ImportError:
            pass
        except Exception:
            pass
        return {}

    def _create_markdown_report(self) -> str:
        """Generate one Markdown file per finding and return the output directory path."""
        md_dir = os.path.join(self.output_dir, "markdown")
        Path(md_dir).mkdir(parents=True, exist_ok=True)

        sorted_findings = self._sort_findings()
        triage_assist_enabled = self.config.get("triage_assist", False)

        for finding in sorted_findings:
            cvss_score = self._get_cvss_score(finding)
            cvss_vector = self._get_cvss_vector(finding)
            rating = self._severity_rating(cvss_score)
            component = self._get_affected_component(finding.get("url", ""))
            confirmed = finding.get("confirmed", False)

            # Optionally enhance with LLM
            if triage_assist_enabled:
                llm = self._call_triage_assist(finding)
            else:
                llm = {}

            impact = llm.get("impact") or self._build_impact_narrative(finding)
            remediation = llm.get("remediation") or self._build_remediation(finding)

            # Steps to reproduce – build from available metadata
            details = finding.get("details", "")
            evidence = self._format_evidence(finding.get("evidence", ""))
            steps = f"""
1.  Navigate to the affected endpoint: `{finding.get('url', 'N/A')}`
2.  {details}
3.  Observe the evidence below to confirm the vulnerability.
"""
            if evidence:
                steps += f"\n## Evidence\n\n```\n{evidence}\n```\n"

            vuln_type = finding.get("title", "finding").replace(" ", "_").replace("/", "_")
            safe_target = self._sanitize_target()
            filename = f"{vuln_type}_{safe_target}.md"
            filepath = os.path.join(md_dir, filename)

            score = finding.get('confidence_score')
            score_str = f"{score:.0f}/100" if score is not None else "—"
            stage = finding.get('verification_stage', '').title() or "—"
            fpr = finding.get('false_positive_risk', '')
            evidence_strength = finding.get('evidence_strength', '')
            validation_steps = finding.get('validation_steps', [])
            grouped_urls = finding.get('grouped_urls', [])

            content = f"""# {finding.get('title', 'Vulnerability Report')}

**Target:** `{self.target}`
**Component:** `{component}`
**Severity:** {finding.get('severity', 'info').upper()}
**Confidence:** {score_str}
**Verification Stage:** {stage}
**Evidence Strength:** {evidence_strength or '—'}
**False Positive Risk:** {fpr or '—'}
**Confirmed:** {"Yes" if confirmed else "No"}
**CVSS Score:** {cvss_score} ({rating})
**CVSS Vector:** `{cvss_vector}`

---

## Summary

{finding.get('what_is_it') or details}

## Steps to Reproduce
{steps}
"""
            if validation_steps:
                content += "## Validation Steps\n\n"
                for i, vs in enumerate(validation_steps, 1):
                    content += f"{i}. {vs}\n"
                content += "\n"
            if grouped_urls:
                content += "## Affected URLs\n\n"
                for gu in grouped_urls:
                    content += f"- {gu}\n"
                content += "\n"

            content += f"""## Impact

{impact}

## Recommended Fix

{remediation}
"""
            if finding.get("references"):
                refs = finding["references"]
                if isinstance(refs, list):
                    refs = "\n".join(f"- {r}" for r in refs)
                content += f"\n## References\n\n{refs}\n"

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)

        return md_dir

    def _hackerone_vuln_section(self, f: Dict[str, Any]) -> str:
        """Generate one vulnerability section in HackerOne submission format."""
        sev = f.get("severity", "info").upper()
        title = f.get("title") or f.get("details", "Untitled")
        component = f.get("component") or f.get("url", self.target)
        what = f.get("what_is_it") or f.get("details", "")
        impact_narrative = f.get("impact_assessment", {}).get("narrative", "")
        steps = f.get("validation_steps") or f.get("steps_to_reproduce", "")
        if isinstance(steps, list):
            steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
        evidence = f.get("proof") or f.get("evidence") or f.get("request_response", "")
        if isinstance(evidence, dict):
            evidence = json.dumps(evidence, indent=2)
        remediation = f.get("remediation") or f.get("recommendation", "")

        grouped = f.get("grouped_urls", [])
        affected_urls = "\n".join(f"- {u}" for u in grouped) if grouped else f"- {f.get('url', self.target)}"

        ia = f.get("impact_assessment", {})
        fp_risk = f.get("false_positive_risk", "")

        return f"""### {title}

**Severity:** {sev}
**Component:** {component}
**CVSS:** {f.get('cvss_score', '—')} ({f.get('cvss_rating', '—')})

#### Summary
{what}

#### Affected URLs
{affected_urls}

#### Steps to Reproduce
{steps}

#### Evidence
```
{self._format_evidence(evidence, 50)}
```

#### Impact
{impact_narrative}

#### Recommended Fix
{remediation}

#### False Positive Risk
{fp_risk}

---
"""

    def _generate_hackerone_report(self) -> str:
        """Generate a HackerOne-ready markdown report with all findings."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        high_sev = [f for f in self.findings if f.get("severity", "info").lower() in ("critical", "high")]
        medium_sev = [f for f in self.findings if f.get("severity", "info").lower() == "medium"]
        low_sev = [f for f in self.findings if f.get("severity", "info").lower() in ("low", "info")]

        sections = []
        for label, group in [("Critical & High", high_sev), ("Medium", medium_sev), ("Low & Info", low_sev)]:
            if not group:
                continue
            sections.append(f"## {label} Severity Findings\n")
            for f in group:
                sections.append(self._hackerone_vuln_section(f))

        total = len(self.findings)
        body = "\n".join(sections) if sections else "No vulnerabilities detected during this scan."

        return f"""# Bug Bounty Report: {self.target}

**Generated:** {now}
**Tool:** BugBounty-Hunter
**Total Findings:** {total}

---

{body}

## Summary

This report was automatically generated by BugBounty-Hunter. \
Each finding includes severity, CVSS score, reproduction steps, evidence, and impact assessment. \
Please verify each finding before submitting.

---

*Report generated by BugBounty-Hunter — https://github.com/anomalyco/bugbounty-hunter*
"""

    def _generate_bugcrowd_report(self) -> str:
        """Generate a Bugcrowd-ready markdown report."""
        # Bugcrowd prefers per-finding submissions; generate a summary + per-finding details
        now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

        summary_rows = []
        for i, f in enumerate(self.findings, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title") or f.get("details", "Untitled")
            url = f.get("url", self.target)
            stage = f.get("verification_stage", "").title() or "Detected"
            confidence = f.get("confidence_score")
            cs = f"{confidence:.0f}/100" if confidence is not None else "—"
            summary_rows.append(f"| {i} | {title} | {sev} | `{url}` | {stage} | {cs} |")

        summary_table = "\n".join(summary_rows) if summary_rows else "No findings."

        per_finding = []
        for i, f in enumerate(self.findings, 1):
            title = f.get("title") or f.get("details", "Untitled")
            sev = f.get("severity", "info").upper()
            what = f.get("what_is_it") or f.get("details", "")
            impact = f.get("impact_assessment", {}).get("narrative", "")
            steps = f.get("validation_steps") or f.get("steps_to_reproduce", "")
            if isinstance(steps, list):
                steps = "\n".join(f"{j+1}. {s}" for j, s in enumerate(steps))
            remed = f.get("remediation") or f.get("recommendation", "")
            evidence = f.get("proof") or f.get("evidence", "")
            if isinstance(evidence, dict):
                evidence = json.dumps(evidence, indent=2)

            grouped = f.get("grouped_urls", [])
            urls = "\n".join(f"- {u}" for u in grouped) if grouped else f"- {f.get('url', self.target)}"

            per_finding.append(f"""## Finding #{i}: {title}

| Field | Value |
|-------|-------|
| Severity | {sev} |
| URL | `{f.get('url', self.target)}` |
| Verification Stage | {f.get('verification_stage', '').title() or 'Detected'} |
| Confidence | {cs} |
| CVSS | {f.get('cvss_score', '—')} ({f.get('cvss_rating', '—')}) |

### Description
{what}

### Affected URLs
{urls}

### Steps to Reproduce
{steps}

### Evidence
```
{self._format_evidence(evidence, 50)}
```

### Impact
{impact}

### Remediation
{remed}

---
""")

        body = "\n".join(per_finding) if per_finding else "No vulnerabilities detected."

        return f"""# Bugcrowd Submission: {self.target}

**Generated:** {now}
**Tool:** BugBounty-Hunter
**Total Findings:** {len(self.findings)}

## Finding Summary

| # | Title | Severity | URL | Stage | Confidence |
|---|-------|----------|-----|-------|------------|
{summary_table}

---

{body}

---

*Report generated by BugBounty-Hunter — https://github.com/anomalyco/bugbounty-hunter*
"""

    def generate(self, suffix: str | None = None) -> str:
        """
        Generate report in specified format and save to file.
        
        Args:
            suffix: Optional suffix to append to the report filename.

        Returns:
            str: Path to generated report file
            
        Raises:
            ValueError: If report format is not supported
            IOError: If report file cannot be written
        """
        try:
            # Create output directory if it doesn't exist
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
            
            self.findings = self._dedupe_findings()
            # Determine report format
            if self.report_format == 'html':
                report_content = self._create_html_report()
                file_extension = 'html'
                file_path = self._get_report_path(file_extension, suffix)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
            elif self.report_format == 'json':
                report_content = self._create_json_report()
                file_extension = 'json'
                file_path = self._get_report_path(file_extension, suffix)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
            elif self.report_format == 'txt':
                report_content = self._create_txt_report()
                file_extension = 'txt'
                file_path = self._get_report_path(file_extension, suffix)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
            elif self.report_format == 'markdown-report':
                file_path = self._create_markdown_report()
            elif self.report_format == 'hackerone':
                report_content = self._generate_hackerone_report()
                file_extension = 'md'
                file_path = self._get_report_path(file_extension, suffix)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
            elif self.report_format == 'bugcrowd':
                report_content = self._generate_bugcrowd_report()
                file_extension = 'md'
                file_path = self._get_report_path(file_extension, suffix)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
            else:
                raise ValueError(f"Unsupported report format: {self.report_format}")
            
            return file_path
            
        except Exception as e:
            raise IOError(f"Error generating report: {str(e)}")


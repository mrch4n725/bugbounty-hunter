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
        Generate HTML report with Chart.js donut chart, filter buttons,
        collapsible finding cards, dark/light toggle, and JS intelligence section.
        """
        sorted_findings = self._sort_findings()
        severity_counts = self._get_severity_counts()
        confidence_breakdown = self._get_confidence_breakdown()
        verification_breakdown = self._get_verification_breakdown()
        subdomains = self.recon_data.get('subdomains', [])
        urls = self.recon_data.get('urls', [])
        js_endpoints = self.recon_data.get('js_endpoints', [])
        js_urls = self.recon_data.get('js_urls', [])

        config_section = self._create_config_section_html()
        subdomains_section = self._create_subdomains_section_html(subdomains)
        urls_section = self._create_urls_section_html(urls)
        js_section = self._create_js_section_html(js_endpoints, js_urls)

        total = sum(severity_counts.values())
        cards_html = self._build_stat_cards_html(severity_counts, verification_breakdown)
        findings_cards = self._build_finding_cards_html(sorted_findings)

        sev_json = json.dumps(severity_counts)
        ver_json = json.dumps(verification_breakdown)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {self.target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        :root {{
            --bg: #0f0f0f;
            --surface: #1e1e1e;
            --surface2: #2a2a2a;
            --text: #e0e0e0;
            --text2: #999;
            --border: #333;
            --critical: #e74c3c;
            --high: #e67e22;
            --medium: #f1c40f;
            --low: #3498db;
            --info: #95a5a6;
            --confirmed: #2ecc71;
        }}
        .light {{
            --bg: #f5f5f5;
            --surface: #ffffff;
            --surface2: #f0f0f0;
            --text: #222;
            --text2: #666;
            --border: #ddd;
        }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: 'Segoe UI', system-ui, sans-serif;
            line-height: 1.6;
            padding: 20px;
            transition: background .3s, color .3s;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ text-align: center; margin-bottom: 40px; border-bottom: 2px solid var(--border); padding-bottom: 20px; }}
        header h1 {{ font-size: 2.2em; color: var(--text); }}
        .timestamp {{ color: var(--text2); font-size: .9em; }}

        .top-bar {{ display: flex; justify-content: flex-end; gap: 10px; margin-bottom: 20px; }}
        .theme-btn {{
            background: var(--surface2); color: var(--text); border: 1px solid var(--border);
            padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: .85em;
        }}
        .theme-btn:hover {{ opacity: .8; }}

        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 40px; }}
        .stat-card {{
            background: var(--surface); border-radius: 8px; padding: 16px; text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,.2); border-top: 4px solid var(--border);
        }}
        .stat-card .val {{ font-size: 2em; font-weight: 700; }}
        .stat-card .lbl {{ font-size: .8em; color: var(--text2); text-transform: uppercase; letter-spacing: .5px; }}
        .stat-card.crit {{ border-top-color: var(--critical); }} .stat-card.crit .val {{ color: var(--critical); }}
        .stat-card.high {{ border-top-color: var(--high); }} .stat-card.high .val {{ color: var(--high); }}
        .stat-card.med {{ border-top-color: var(--medium); }} .stat-card.med .val {{ color: var(--medium); }}
        .stat-card.low {{ border-top-color: var(--low); }} .stat-card.low .val {{ color: var(--low); }}
        .stat-card.info {{ border-top-color: var(--info); }} .stat-card.info .val {{ color: var(--info); }}
        .stat-card.conf {{ border-top-color: var(--confirmed); }} .stat-card.conf .val {{ color: var(--confirmed); }}
        .stat-card.exploit {{ border-top-color: #9b59b6; }} .stat-card.exploit .val {{ color: #9b59b6; }}
        .stat-card.detect {{ border-top-color: #e74c3c; }} .stat-card.detect .val {{ color: #e74c3c; }}
        .stat-card.valid {{ border-top-color: #f39c12; }} .stat-card.valid .val {{ color: #f39c12; }}

        .chart-row {{ display: flex; gap: 20px; margin-bottom: 40px; flex-wrap: wrap; }}
        .chart-box {{
            background: var(--surface); border-radius: 8px; padding: 20px; flex: 1; min-width: 280px;
            box-shadow: 0 2px 8px rgba(0,0,0,.2); position: relative; height: 300px;
        }}
        .chart-box canvas {{ max-height: 240px; }}

        section {{ margin-bottom: 40px; background: var(--surface); padding: 24px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.2); }}
        section h2 {{ font-size: 1.5em; margin-bottom: 16px; border-bottom: 2px solid var(--border); padding-bottom: 8px; }}

        .filters {{ display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }}
        .filter-btn {{
            background: var(--surface2); color: var(--text2); border: 1px solid var(--border);
            padding: 6px 14px; border-radius: 20px; cursor: pointer; font-size: .8em; transition: all .2s;
        }}
        .filter-btn:hover {{ opacity: .8; }}
        .filter-btn.active {{ background: var(--border); color: var(--text); border-color: var(--text2); }}

        .finding-card {{
            background: var(--surface2); border-radius: 6px; margin-bottom: 12px;
            border-left: 4px solid var(--border); overflow: hidden;
        }}
        .finding-card.critical {{ border-left-color: var(--critical); }}
        .finding-card.high {{ border-left-color: var(--high); }}
        .finding-card.medium {{ border-left-color: var(--medium); }}
        .finding-card.low {{ border-left-color: var(--low); }}
        .finding-card.info {{ border-left-color: var(--info); }}

        .finding-header {{
            padding: 14px 16px; cursor: pointer; display: flex; align-items: center;
            justify-content: space-between; flex-wrap: wrap; gap: 8px;
        }}
        .finding-header:hover {{ background: rgba(255,255,255,.03); }}
        .finding-title {{ font-weight: 600; font-size: .95em; flex: 1; min-width: 160px; }}
        .finding-meta {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
        .sev-badge {{
            display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: .75em;
            font-weight: 700; text-transform: uppercase;
        }}
        .sev-critical {{ background: var(--critical); color: #fff; }}
        .sev-high {{ background: var(--high); color: #fff; }}
        .sev-medium {{ background: var(--medium); color: #000; }}
        .sev-low {{ background: var(--low); color: #fff; }}
        .sev-info {{ background: var(--info); color: #fff; }}
        .conf-badge {{ padding: 2px 8px; border-radius: 10px; font-size: .75em; font-weight: 600; }}
        .conf-high {{ background: #2ecc71; color: #fff; }}
        .conf-mid {{ background: #f39c12; color: #000; }}
        .conf-low {{ background: #e74c3c; color: #fff; }}
        .stage-badge {{ padding: 2px 8px; border-radius: 10px; font-size: .75em; color: var(--text2); border: 1px solid var(--border); }}

        .finding-body {{ padding: 0 16px 16px; display: none; }}
        .finding-card.open .finding-body {{ display: block; }}
        .finding-body .row {{ margin-bottom: 8px; font-size: .88em; }}
        .finding-body .row strong {{ color: var(--text2); min-width: 90px; display: inline-block; }}
        .finding-body .url {{ font-family: 'Courier New', monospace; word-break: break-all; font-size: .85em; }}
        .finding-body .evidence {{ background: var(--bg); padding: 8px 12px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: .82em; word-break: break-all; margin-top: 4px; }}
        .finding-body .steps {{ margin: 4px 0; padding-left: 16px; }}
        .finding-body .steps li {{ margin-bottom: 4px; font-size: .85em; }}
        .copy-btn {{
            background: var(--surface); color: var(--text2); border: 1px solid var(--border);
            padding: 3px 10px; border-radius: 4px; cursor: pointer; font-size: .78em;
        }}
        .copy-btn:hover {{ background: var(--border); }}

        .recon-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }}
        .recon-grid .url {{ display: block; padding: 6px 10px; background: var(--surface2); border-radius: 4px; font-size: .82em; word-break: break-all; }}

        footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 2px solid var(--border); color: var(--text2); font-size: .85em; }}
        .empty-message {{ color: var(--text2); font-style: italic; padding: 20px; text-align: center; }}

        @media (max-width: 600px) {{
            .summary {{ grid-template-columns: repeat(2, 1fr); }}
            .finding-header {{ flex-direction: column; align-items: flex-start; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Bug Bounty Report</h1>
            <p class="timestamp">Target: <strong>{self.target}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="top-bar">
            <button class="theme-btn" onclick="toggleTheme()">Toggle Theme</button>
        </div>

        <section class="summary">
            {cards_html}
        </section>

        <div class="chart-row">
            <div class="chart-box">
                <canvas id="sevChart"></canvas>
            </div>
            <div class="chart-box">
                <canvas id="verChart"></canvas>
            </div>
        </div>

        {config_section}

        <section>
            <h2>Findings <span style="font-size:.6em;color:var(--text2)">({total})</span></h2>
            <div class="filters" id="filters">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="critical">Critical</button>
                <button class="filter-btn" data-filter="high">High</button>
                <button class="filter-btn" data-filter="medium">Medium</button>
                <button class="filter-btn" data-filter="low">Low</button>
                <button class="filter-btn" data-filter="info">Info</button>
                <button class="filter-btn" data-filter="exploitable">Exploitable</button>
                <button class="filter-btn" data-filter="validated">Validated</button>
                <button class="filter-btn" data-filter="detected">Detected</button>
            </div>
            <div id="findingsContainer">
                {findings_cards if sorted_findings else '<div class="empty-message">No vulnerabilities found.</div>'}
            </div>
        </section>

        {subdomains_section}
        {urls_section}
        {js_section}

        <footer>
            <p>Generated by BugBounty Hunter — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>

    <script>
        var sevData = {sev_json};
        var verData = {ver_json};

        var sevCtx = document.getElementById('sevChart').getContext('2d');
        new Chart(sevCtx, {{
            type: 'doughnut',
            data: {{
                labels: Object.keys(sevData).filter(k => sevData[k] > 0).map(k => k.charAt(0).toUpperCase() + k.slice(1)),
                datasets: [{{
                    data: Object.values(sevData).filter(v => v > 0),
                    backgroundColor: ['#e74c3c','#e67e22','#f1c40f','#3498db','#95a5a6'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true, maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'right', labels: {{ color: '#999' }} }} }}
            }}
        }});

        var verCtx = document.getElementById('verChart').getContext('2d');
        new Chart(verCtx, {{
            type: 'doughnut',
            data: {{
                labels: Object.keys(verData).filter(k => verData[k] > 0).map(k => k.charAt(0).toUpperCase() + k.slice(1)),
                datasets: [{{
                    data: Object.values(verData).filter(v => v > 0),
                    backgroundColor: ['#e74c3c','#f39c12','#2ecc71','#9b59b6'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true, maintainAspectRatio: false,
                plugins: {{ legend: {{ position: 'right', labels: {{ color: '#999' }} }} }}
            }}
        }});

        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', function() {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                var filter = this.dataset.filter;
                document.querySelectorAll('.finding-card').forEach(card => {{
                    if (filter === 'all') {{ card.style.display = ''; return; }}
                    var show = card.dataset.severity === filter || card.dataset.stage === filter;
                    card.style.display = show ? '' : 'none';
                }});
            }});
        }});

        // Collapsible cards
        document.querySelectorAll('.finding-header').forEach(hdr => {{
            hdr.addEventListener('click', function() {{
                this.parentElement.classList.toggle('open');
            }});
        }});

        // Theme toggle
        function toggleTheme() {{
            document.body.classList.toggle('light');
        }}

        // Copy URL
        function copyUrl(url) {{
            navigator.clipboard.writeText(url).then(() => {{
                var btn = event.target;
                var orig = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => btn.textContent = orig, 1200);
            }});
        }}
    </script>
</body>
</html>"""
        return html_content

    def _build_stat_cards_html(self, sev: Dict[str, int], ver: Dict[str, int]) -> str:
        cards = ""
        sev_map = [("crit", "critical", "Critical"), ("high", "high", "High"), ("med", "medium", "Medium"),
                   ("low", "low", "Low"), ("info", "info", "Info")]
        for cls, key, label in sev_map:
            cards += f'<div class="stat-card {cls}"><div class="val">{sev.get(key, 0)}</div><div class="lbl">{label}</div></div>'
        cards += f'<div class="stat-card conf"><div class="val">{ver.get("exploitable", 0)}</div><div class="lbl">Exploitable</div></div>'
        cards += f'<div class="stat-card valid"><div class="val">{ver.get("validated", 0)}</div><div class="lbl">Validated</div></div>'
        cards += f'<div class="stat-card detect"><div class="val">{ver.get("detected", 0)}</div><div class="lbl">Detected</div></div>'
        return cards

    def _build_finding_cards_html(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return '<div class="empty-message">No vulnerabilities found.</div>'
        html = ""
        for f in findings:
            sev = f.get("severity", "info").lower()
            stage = f.get("verification_stage", "detected").lower()
            score = f.get("confidence_score", 0)
            evidence = f.get("evidence", "")
            details = f.get("details", "")
            vuln_url = f.get("url", "")
            fpr = f.get("false_positive_risk", "")
            cvss = f.get("cvss_score", "")
            steps = f.get("validation_steps", [])

            sev_class = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}.get(sev, "info")
            conf_class = "high" if score >= 61 else ("mid" if score >= 31 else "low")
            stage_label = stage.title()

            steps_html = ""
            if steps:
                items = "".join(f"<li>{s}</li>" for s in steps[:5])
                steps_html = f'<div class="row"><strong>Steps:</strong><ol class="steps">{items}</ol></div>'

            evidence_html = ""
            if evidence:
                evidence_html = f'<div class="row"><strong>Evidence:</strong><div class="evidence">{evidence[:300]}</div></div>'

            cvss_html = f'<span>CVSS: {cvss:.1f}</span>' if isinstance(cvss, (int, float)) else ""

            html += f'''<div class="finding-card {sev_class}" data-severity="{sev}" data-stage="{stage}">
                <div class="finding-header">
                    <div class="finding-title">{f.get("title", "Finding")}</div>
                    <div class="finding-meta">
                        <span class="sev-badge sev-{sev_class}">{sev.upper()}</span>
                        <span class="conf-badge conf-{conf_class}">{score:.0f}%</span>
                        <span class="stage-badge">{stage_label}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="row"><strong>URL:</strong> <span class="url">{vuln_url}</span> <button class="copy-btn" onclick="copyUrl('{vuln_url.replace("'", "\\'")}')">Copy URL</button></div>
                    <div class="row"><strong>Details:</strong> {details}</div>
                    {evidence_html}
                    {steps_html}
                    <div class="row"><strong>FP Risk:</strong> {fpr.title() if fpr else "—"} {cvss_html}</div>
                </div>
            </div>'''
        return html

    def _create_js_section_html(self, js_endpoints: List[str], js_urls: List[str]) -> str:
        if not js_endpoints and not js_urls:
            return ""
        html = '<section><h2>JavaScript Intelligence</h2>'
        if js_urls:
            html += '<div style="margin-bottom:12px"><strong>JS Bundles:</strong></div><div class="recon-grid">'
            for u in js_urls[:30]:
                html += f'<span class="url">{u}</span>'
            html += '</div>'
        if js_endpoints:
            html += '<div style="margin:12px 0 8px"><strong>Discovered JS Endpoints:</strong></div><div class="recon-grid">'
            for ep in js_endpoints[:40]:
                html += f'<span class="url">{ep}</span>'
            html += '</div>'
        html += '</section>'
        return html
    
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


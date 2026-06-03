import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


class Reporter:
    """
    Generates vulnerability scan reports in multiple formats (HTML, JSON, TXT).
    
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
    
    def _sort_findings(self) -> List[Dict[str, Any]]:
        """
        Sort findings by severity level.
        
        Returns:
            List: Sorted findings list
        """
        return sorted(self.findings, key=lambda x: self.SEVERITY_ORDER.get(x.get('severity', 'info').lower(), 4))
    
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
    
    def _create_findings_table_html(self, sorted_findings: List[Dict[str, Any]]) -> str:
        """
        Create HTML table rows for findings.
        
        Args:
            sorted_findings (List): Sorted list of findings
            
        Returns:
            str: HTML table content
        """
        if not sorted_findings:
            return '<div class="empty-message">No vulnerabilities found.</div>'
        
        rows = '<table><thead><tr><th>Title</th><th>URL</th><th>Severity</th><th>Details</th></tr></thead><tbody>'
        for finding in sorted_findings:
            severity = finding.get('severity', 'info').lower()
            rows += f'''<tr>
                    <td>{finding.get('title', 'N/A')}</td>
                    <td><span class="url">{finding.get('url', 'N/A')}</span></td>
                    <td><span class="severity-badge severity-{severity}">{severity.upper()}</span></td>
                    <td><span class="detail-text">{finding.get('details', 'N/A')}</span></td>
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
    
    def _create_html_report(self) -> str:
        """
        Generate HTML report with dark theme.
        
        Returns:
            str: HTML report content
        """
        sorted_findings = self._sort_findings()
        severity_counts = self._get_severity_counts()
        subdomains = self.recon_data.get('subdomains', [])
        urls = self.recon_data.get('urls', [])
        
        findings_table = self._create_findings_table_html(sorted_findings)
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
        </section>
        
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
        
        report_data = {
            'metadata': {
                'target': self.target,
                'timestamp': self.timestamp,
                'report_date': datetime.now().isoformat(),
                'total_findings': len(self.findings)
            },
            'summary': severity_counts,
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
        subdomains = self.recon_data.get('subdomains', [])
        urls = self.recon_data.get('urls', [])
        
        txt_content = f"""
{'='*80}
BUG BOUNTY REPORT
{'='*80}

Target: {self.target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Timestamp: {self.timestamp}

{'='*80}
SUMMARY
{'='*80}

Critical: {severity_counts['critical']}
High: {severity_counts['high']}
Medium: {severity_counts['medium']}
Low: {severity_counts['low']}
Info: {severity_counts['info']}

Total Findings: {len(self.findings)}

{'='*80}
VULNERABILITY FINDINGS
{'='*80}

"""
        
        if not sorted_findings:
            txt_content += "\nNo vulnerabilities found.\n"
        else:
            for i, finding in enumerate(sorted_findings, 1):
                txt_content += f"""
[{i}] {finding.get('title', 'N/A')}
    Severity: {finding.get('severity', 'N/A').upper()}
    URL: {finding.get('url', 'N/A')}
    Details: {finding.get('details', 'N/A')}
"""
        
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
    
    def generate(self) -> str:
        """
        Generate report in specified format and save to file.
        
        Returns:
            str: Path to generated report file
            
        Raises:
            ValueError: If report format is not supported
            IOError: If report file cannot be written
        """
        try:
            # Create output directory if it doesn't exist
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
            
            # Determine report format
            if self.report_format == 'html':
                report_content = self._create_html_report()
                file_extension = 'html'
            elif self.report_format == 'json':
                report_content = self._create_json_report()
                file_extension = 'json'
            elif self.report_format == 'txt':
                report_content = self._create_txt_report()
                file_extension = 'txt'
            else:
                raise ValueError(f"Unsupported report format: {self.report_format}")
            
            # Generate filename
            safe_target = self._sanitize_target()
            filename = f"{safe_target}_{self.timestamp}.{file_extension}"
            file_path = os.path.join(self.output_dir, filename)
            
            # Write report to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return file_path
            
        except Exception as e:
            raise IOError(f"Error generating report: {str(e)}")


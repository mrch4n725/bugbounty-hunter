from datetime import datetime
from typing import Any, Dict

from reporting.base import ReporterBase


class TXTReporter(ReporterBase):
    def render(self) -> str:
        sorted_findings = self._sort_findings()
        severity_counts = self._get_severity_counts()
        subdomains = self.recon_data.get('subdomains', [])
        urls = self.recon_data.get('urls', [])

        lines = [
            '=' * 80,
            'BUG BOUNTY REPORT',
            '=' * 80,
            '',
            f'Target: {self.target}',
            f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            f'Timestamp: {self.timestamp}',
            f'Modules: {", ".join(self.config.get("modules", []))}',
            f'Threads: {self.config.get("threads")}',
            f'Timeout: {self.config.get("timeout")}s',
            f'Retries: {self.config.get("retries")}',
            f'Crawl Depth: {self.config.get("crawl_depth")}',
            f'Max URLs: {self.config.get("max_urls")}',
            f'Passive Mode: {self.config.get("passive")}',
            '',
            '=' * 80,
            'SUMMARY',
            '=' * 80,
            '',
            f'Critical: {severity_counts["critical"]}',
            f'High: {severity_counts["high"]}',
            f'Medium: {severity_counts["medium"]}',
            f'Low: {severity_counts["low"]}',
            f'Info: {severity_counts["info"]}',
            '',
            f'Total Findings: {len(self.findings)}',
            '',
            '=' * 80,
            'VULNERABILITY FINDINGS',
            '=' * 80,
        ]

        if not sorted_findings:
            lines.append('\nNo vulnerabilities found.\n')
        else:
            for i, f in enumerate(sorted_findings, 1):
                score = f.get('confidence_score')
                score_str = f"{score:.0f}/100" if score is not None else "—"
                stage = f.get('verification_stage', '').title() or "—"
                fpr = f.get('false_positive_risk', '')
                lines.extend([
                    '',
                    f'[{i}] {f.get("title", "N/A")}',
                    f'    Severity    : {f.get("severity", "N/A").upper()}',
                    f'    Confidence  : {score_str}',
                    f'    Verification: {stage}',
                    f'    FP Risk     : {fpr or "—"}',
                    f'    URL         : {f.get("url", "N/A")}',
                    f'    Parameter   : {f.get("parameter", "N/A")}',
                    f'    Details     : {f.get("details", "N/A")}',
                ])
                if f.get('evidence'):
                    lines.append(f"    Raw Evidence: {f['evidence'][:200]}")
                if f.get('request'):
                    lines.append(f"    Request     : {f['request']}")
                if f.get('response_excerpt'):
                    lines.append(f"    Response    : {f['response_excerpt'][:300]}")
                if f.get('screenshot_path'):
                    lines.append(f"    Screenshot  : {f['screenshot_path']}")
                steps = f.get('validation_steps') or f.get('steps_to_reproduce', [])
                if steps:
                    for s in steps[:5]:
                        lines.append(f"    ⬩ {s}")

        if subdomains:
            lines.extend(['', '=' * 80, f'DISCOVERED SUBDOMAINS ({len(subdomains)})', '=' * 80, ''])
            for sub in subdomains:
                lines.append(f"  - {sub}")

        if urls:
            lines.extend(['', '=' * 80, f'DISCOVERED URLS ({len(urls)})', '=' * 80, ''])
            for url in urls:
                lines.append(f"  - {url}")

        lines.extend(['', '=' * 80, 'End of Report', '=' * 80, ''])
        return '\n'.join(lines)

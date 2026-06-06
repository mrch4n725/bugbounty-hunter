import hashlib
import json
from datetime import datetime
from typing import Any, Dict

from reporting.base import ReporterBase


class TXTReporter(ReporterBase):
    def _get_evidence_txt(self, finding: Any) -> str:
        evidence = finding.get("evidence", "")
        if not evidence:
            return ""
        if isinstance(evidence, list):
            parts = []
            for i, ev in enumerate(evidence):
                if hasattr(ev, 'to_dict'):
                    ev_text = json.dumps(ev.to_dict(), indent=2)
                else:
                    ev_text = str(ev)
                desc = getattr(ev, 'description', f'Evidence #{i+1}') if hasattr(ev, 'description') else f'Evidence #{i+1}'
                parts.append(f"    {desc}:\n{self._indent(ev_text[:300], 4)}")
            return "\n".join(parts)
        return f"    Raw Evidence: {str(evidence)[:200]}"

    def _indent(self, text: str, spaces: int = 4) -> str:
        prefix = " " * spaces
        return "\n".join(f"{prefix}{line}" for line in text.splitlines())

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
                cvss_score = self._get_cvss_score(f)
                cvss_rating = self._severity_rating(cvss_score)
                impact = self._build_impact_narrative(f)
                remediation = self._build_remediation(f)
                lines.extend([
                    '',
                    '─' * 80,
                    f'[{i}] {f.get("title", "N/A")}',
                    '─' * 80,
                    f'    Severity    : {f.get("severity", "N/A").upper()}',
                    f'    Confidence  : {score_str}',
                    f'    Verification: {stage}',
                    f'    CVSS        : {cvss_score:.1f} ({cvss_rating})',
                    f'    FP Risk     : {fpr or "—"}',
                    f'    URL         : {f.get("url", "N/A")}',
                    f'    Parameter   : {f.get("parameter", "N/A")}',
                    f'    Details     : {f.get("details", "N/A")}',
                ])
                ev_txt = self._get_evidence_txt(f)
                if ev_txt:
                    lines.append(f'    Evidence    : {ev_txt}')
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
                lines.append(f'    Impact      : {impact[:200]}...' if len(impact) > 200 else f'    Impact      : {impact}')
                lines.append(f'    Remediation : {remediation[:200]}...' if len(remediation) > 200 else f'    Remediation : {remediation}')

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

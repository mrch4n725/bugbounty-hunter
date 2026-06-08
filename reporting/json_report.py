import json
from datetime import datetime
from typing import Any, Dict

from reporting.base import ReporterBase


class JSONReporter(ReporterBase):
    def render(self) -> str:
        sorted_findings = self._sort_findings()
        severity_counts = self._get_severity_counts()
        confirm_counts = self._get_confirmed_counts()
        confidence_breakdown = self._get_confidence_breakdown()
        verification_breakdown = self._get_verification_breakdown()

        report_data: Dict[str, Any] = {
            'metadata': {
                'target': self.target,
                'timestamp': self.timestamp,
                'report_date': datetime.now().isoformat(),
                'total_findings': len(self.findings),
                'tool': 'BugBounty-Hunter',
                'report_format': 'JSON',
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
                'module_params': self.config.get('module_params', {}),
            },
            'summary': {
                'severity': severity_counts,
                'confidence': confidence_breakdown,
                'verification_stage': verification_breakdown,
                'confirmed': confirm_counts.get('confirmed', 0),
                'total': len(self.findings),
            },
            'root_cause_groups': self.root_cause_groups_to_dicts(),
            'findings': self._findings_as_dicts(sorted_findings),
            'recon_data': {
                'subdomains': self.recon_data.get('subdomains', []),
                'urls': self.recon_data.get('urls', []),
            },
            'js_intelligence': {
                'secrets': self.js_data.get('secrets', []),
                'endpoints': self.js_data.get('endpoints', []),
                'hidden_endpoints': self.js_data.get('hidden_endpoints', []),
                'env_vars': self.js_data.get('env_vars', []),
            },
        }
        return json.dumps(report_data, indent=2)

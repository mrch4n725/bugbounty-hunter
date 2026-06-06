"""
Legacy reporter wrapper — delegates to reporting/ package.

Maintains full backward compatibility with existing code that imports
from modules.reporter import Reporter.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path

from modules.utils import log, Colors
from reporting import (
    ReporterBase, assess_finding_impact,
    HTMLReporter, JSONReporter, TXTReporter,
    MarkdownReporter, HackerOneReporter, BugcrowdReporter,
    ChatGPTReporter,
    CVSS_BY_SEVERITY, CVSS_VECTORS, IMPACT_MATRIX,
    group_by_root_cause,
)


class Reporter:
    """
    Generates vulnerability scan reports in multiple formats.
    Delegates to format-specific reporters in the reporting/ package.
    
    Attributes:
        config (Dict): Configuration dictionary
        findings (List): Vulnerability findings
        recon_data (Dict): Reconnaissance data
        js_data (Dict): JS Intelligence scan data
    """

    # Expose constants at module level for backward compat
    SEVERITY_COLORS = ReporterBase.SEVERITY_COLORS
    SEVERITY_ORDER = ReporterBase.SEVERITY_ORDER

    def __init__(self, config: Dict[str, Any], findings: List[Dict[str, Any]],
                 recon_data: Dict[str, Any], js_data: Optional[Dict[str, Any]] = None,
                 container=None):
        self.config = config
        self.findings = findings
        self.recon_data = recon_data or {}
        self.js_data = js_data or {}
        self.container = container
        self.target = config.get('target', 'target')
        self.timestamp = config.get('timestamp', ReporterBase(
            config, findings, recon_data, js_data
        ).timestamp)
        self.output_dir = config.get('output_dir', './reports')
        self.report_format = config.get('report_format', 'html').lower()

    def _resolve_format(self) -> ReporterBase:
        """Return the format-specific reporter instance."""
        kwargs = dict(container=self.container)
        if self.report_format == 'html':
            return HTMLReporter(self.config, self.findings, self.recon_data, self.js_data, **kwargs)
        elif self.report_format == 'json':
            return JSONReporter(self.config, self.findings, self.recon_data, self.js_data, **kwargs)
        elif self.report_format == 'txt':
            return TXTReporter(self.config, self.findings, self.recon_data, self.js_data, **kwargs)
        elif self.report_format == 'markdown-report':
            return MarkdownReporter(self.config, self.findings, self.recon_data, self.js_data, **kwargs)
        elif self.report_format == 'hackerone':
            return HackerOneReporter(self.config, self.findings, self.recon_data, self.js_data, **kwargs)
        elif self.report_format == 'bugcrowd':
            return BugcrowdReporter(self.config, self.findings, self.recon_data, self.js_data, **kwargs)
        elif self.report_format == 'chatgpt':
            return ChatGPTReporter(self.config, self.findings, self.recon_data, self.js_data, **kwargs)
        else:
            raise ValueError(f"Unsupported report format: {self.report_format}")

    def generate(self, suffix: str | None = None) -> str:
        """
        Generate report in specified format and save to file.
        
        Args:
            suffix: Optional suffix to append to the filename

        Returns:
            str: Path to generated report file
        """
        try:
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
            reporter = self._resolve_format()
            reporter.findings = reporter._dedupe_findings()

            # Apply root-cause grouping when enabled
            if self.config.get("group_by_root_cause", False):
                group_by_root_cause(reporter.findings)

            report_content = reporter.render()
            file_extension = {
                'html': 'html', 'json': 'json', 'txt': 'txt',
                'hackerone': 'md', 'bugcrowd': 'md', 'chatgpt': 'md',
            }.get(self.report_format)

            if self.report_format == 'markdown-report':
                return report_content  # returns directory path

            file_path = reporter._get_report_path(file_extension, suffix)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(report_content)

            log(f"  [Report] {self.report_format.upper()} report written to {file_path}",
                Colors.GREEN)
            return file_path

        except Exception as e:
            raise IOError(f"Error generating report: {str(e)}")

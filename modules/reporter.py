"""
Legacy reporter wrapper — delegates to reporting/ package.

Maintains full backward compatibility with existing code that imports
from modules.reporter import Reporter.
"""

import json
import os
import shutil
from typing import Any, Dict, List, Optional
from pathlib import Path

from modules.utils import log, Colors
from engines.root_cause import RootCauseAggregator
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

            # Collect screenshot artifacts into output_dir/screenshots/
            artifacts_dir = os.path.join(self.output_dir, "screenshots")
            for f in reporter.findings:
                for path_attr in ("screenshot_path",):
                    src = f.get(path_attr, "")
                    if not src or not os.path.isfile(src):
                        continue
                    try:
                        os.makedirs(artifacts_dir, exist_ok=True)
                        dst = os.path.join(artifacts_dir, os.path.basename(src))
                        if os.path.abspath(src) != os.path.abspath(dst):
                            shutil.copy2(src, dst)
                    except Exception:
                        pass
                ev_list = f.get("evidence", "")
                if isinstance(ev_list, list):
                    for ev in ev_list:
                        for ev_attr in ("screenshot_path", "file_path"):
                            ev_path = getattr(ev, ev_attr, "") if hasattr(ev, ev_attr) else ""
                            if not ev_path or not os.path.isfile(ev_path):
                                continue
                            try:
                                os.makedirs(artifacts_dir, exist_ok=True)
                                dst = os.path.join(artifacts_dir, os.path.basename(ev_path))
                                if os.path.abspath(ev_path) != os.path.abspath(dst):
                                    shutil.copy2(ev_path, dst)
                            except Exception:
                                pass

            # Re-aggregate root cause groups after dedup (ReporterBase.__init__
            # computed them from the pre-dedup list, making them stale).
            aggregator = RootCauseAggregator(self.config)
            reporter.root_cause_groups = aggregator.aggregate(reporter.findings)

            # Legacy opt-in grouping — adds root_cause_group metadata to findings
            if self.config.get("group_by_root_cause", False):
                group_by_root_cause(reporter.findings)

            result = reporter.render()
            file_extension = {
                'html': 'html', 'json': 'json', 'txt': 'txt',
                'hackerone': 'md', 'bugcrowd': 'md', 'chatgpt': 'md',
            }.get(self.report_format)

            if self.report_format == 'markdown-report':
                return result  # returns directory path

            # ChatGPTReporter.render() writes its own file and returns the path
            if self.report_format == 'chatgpt':
                file_path = result
            else:
                file_path = reporter._get_report_path(file_extension, suffix)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(result)
            self.config["_last_report_path"] = file_path

            log(f"  [Report] {self.report_format.upper()} report written to {file_path}",
                Colors.GREEN)

            # Always write a machine-readable findings.json alongside the report
            findings_path = os.path.join(
                self.output_dir,
                f"{reporter._sanitize_target()}_{self.timestamp}_findings.json"
            )
            self.config["_last_findings_path"] = findings_path
            try:
                findings_export = []
                for f in reporter.findings:
                    evidence_raw = f.get("evidence", "")
                    if isinstance(evidence_raw, list):
                        evidence_serialised = [
                            (ev.to_dict() if hasattr(ev, 'to_dict') else str(ev))
                            for ev in evidence_raw
                        ]
                    else:
                        evidence_serialised = str(evidence_raw) if evidence_raw else ""

                    steps = f.get("steps_to_reproduce", [])
                    if not isinstance(steps, list):
                        steps = [str(steps)] if steps else []

                    export = {
                        "title":              f.get("title", ""),
                        "vuln_type":          f.get("vuln_type", ""),
                        "severity":           f.get("severity", "info"),
                        "url":                f.get("url", ""),
                        "parameter":          f.get("parameter", ""),
                        "verification_stage": f.get("verification_stage", "detected"),
                        "confidence_score":   f.get("confidence_score", 0),
                        "false_positive_risk": f.get("false_positive_risk", ""),
                        "fingerprint":        f.get("fingerprint", ""),
                        "root_cause":         f.get("root_cause", ""),
                        "root_cause_fingerprint": f.get("root_cause_fingerprint", ""),
                        "details":            f.get("details", ""),
                        "steps_to_reproduce": steps,
                        "evidence":           evidence_serialised,
                        "request":            f.get("request", "")[:3000],
                        "response_excerpt":   f.get("response_excerpt", "")[:2000],
                        "screenshot_path":    f.get("screenshot_path", ""),
                        "cvss_score":         reporter._get_cvss_score(f),
                        "cvss_vector":        reporter._get_cvss_vector(f),
                        "impact":             reporter._build_impact_narrative(f),
                        "remediation":        reporter._build_remediation(f),
                    }
                    # Engine-enriched fields
                    for engine_field in ("replay_bundle", "finding_state",
                                         "impact_assessment", "chains", "chain_impact",
                                         "duplicate_risk", "consensus_result",
                                         "confidence_reasons", "replay_regression"):
                        val = f.get(engine_field)
                        if val is not None:
                            export[engine_field] = val
                    findings_export.append(export)
                with open(findings_path, 'w', encoding='utf-8') as jf:
                    json.dump({
                        "target": self.target,
                        "generated": self.timestamp,
                        "total": len(findings_export),
                        "findings": findings_export,
                    }, jf, indent=2, ensure_ascii=False)
                log(f"  [Findings] JSON data saved: {findings_path}", Colors.CYAN)
            except Exception as e:
                log(f"  [!] Could not write findings.json: {e}", Colors.YELLOW)

            return file_path

        except Exception as e:
            raise IOError(f"Error generating report: {str(e)}")

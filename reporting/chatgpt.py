import json
import os
from typing import Any

from reporting.base import ReporterBase


class ChatGPTReporter(ReporterBase):
    """Single-file markdown report optimized for ChatGPT ingestion.

    Key design choices for LLM-friendliness:
    - YAML frontmatter with structured summary (parsed as structured data by LLMs)
    - Consistent per-finding sections with ## N. Title headers
    - Colon-delimited key-value fields for easy parsing
    - JSON block for raw finding data
    - All findings in one file for single copy-paste
    """

    def render(self) -> str:
        sorted_findings = self._sort_findings()
        sev = self._get_severity_counts()
        ver = self._get_verification_breakdown()

        frontmatter_lines = [
            "---",
            "scan_report: true",
            f"target: {self.target}",
            f"generated: {self.timestamp}",
            f"total_findings: {len(sorted_findings)}",
        ]
        for key in ("critical", "high", "medium", "low", "info"):
            if sev.get(key, 0):
                frontmatter_lines.append(f"severity_{key}: {sev[key]}")
        for key in ("detected", "validated", "exploitable"):
            if ver.get(key, 0):
                frontmatter_lines.append(f"stage_{key}: {ver[key]}")
        frontmatter_lines.append("---\n")

        content = "\n".join(frontmatter_lines)

        for i, f in enumerate(sorted_findings, 1):
            title = f.get("title", f.get("vuln_type", "Finding"))
            sev_val = f.get("severity", "info").upper()
            url = f.get("url", "")
            details = f.get("details", "")
            stage = f.get("verification_stage", "detected").title()
            score = f.get("confidence_score", 0)
            fpr = f.get("false_positive_risk", "")
            param = f.get("parameter", "")
            response_excerpt = f.get("response_excerpt", "")
            request = f.get("request", "")
            steps = f.get("steps_to_reproduce", [])
            evidence_raw = f.get("evidence", "")

            content += f"## {i}. {title}\n\n"
            content += f"Severity: {sev_val}\n"
            content += f"URL: {url}\n"
            if param:
                content += f"Parameter: {param}\n"
            content += f"Verification Stage: {stage}\n"
            content += f"Confidence: {score:.0f}/100\n"
            content += f"False Positive Risk: {fpr or 'N/A'}\n\n"

            content += f"### Description\n\n{details}\n\n"

            if steps:
                content += "### Steps to Reproduce\n\n"
                for j, s in enumerate(steps, 1):
                    content += f"{j}. {s}\n"
                content += "\n"

            if evidence_raw:
                content += "### Evidence\n\n"
                evidence_str = str(evidence_raw)
                content += f"```\n{evidence_str[:2000]}\n```\n\n"

            if request:
                content += "### Request\n\n"
                content += f"```\n{request[:2000]}\n```\n\n"

            if response_excerpt:
                content += "### Response Excerpt\n\n"
                content += f"```\n{response_excerpt[:2000]}\n```\n\n"

            impact = self._build_impact_narrative(f)
            remediation = self._build_remediation(f)
            content += f"### Impact\n\n{impact}\n\n"
            content += f"### Remediation\n\n{remediation}\n\n"

            content += "---\n\n"

        # Raw JSON data block for structured LLM parsing
        content += "## Raw Finding Data\n\n```json\n"
        raw_data = []
        for f in sorted_findings:
            entry = {
                "title": f.get("title", ""),
                "vuln_type": f.get("vuln_type", ""),
                "severity": f.get("severity", "info"),
                "url": f.get("url", ""),
                "parameter": f.get("parameter", ""),
                "verification_stage": f.get("verification_stage", "detected"),
                "confidence_score": f.get("confidence_score", 0),
                "false_positive_risk": f.get("false_positive_risk", ""),
                "cvss_score": self._get_cvss_score(f),
            }
            raw_data.append(entry)
        content += json.dumps({"findings": raw_data}, indent=2)
        content += "\n```\n"

        filepath = os.path.join(self.output_dir, self._get_chatgpt_filename())
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    def _get_chatgpt_filename(self) -> str:
        safe = self._sanitize_target()
        return f"{safe}_{self.timestamp}_chatgpt.md"

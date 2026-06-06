import hashlib
import os
from pathlib import Path
from typing import Any, Dict

from reporting.base import ReporterBase


class MarkdownReporter(ReporterBase):
    def render(self) -> str:
        md_dir = os.path.join(self.output_dir, "markdown")
        Path(md_dir).mkdir(parents=True, exist_ok=True)

        sorted_findings = self._sort_findings()
        for finding in sorted_findings:
            cvss_score = self._get_cvss_score(finding)
            cvss_vector = self._get_cvss_vector(finding)
            rating = self._severity_rating(cvss_score)
            component = self._get_affected_component(finding.get("url", ""))
            impact = self._build_impact_narrative(finding)
            remediation = self._build_remediation(finding)

            details = finding.get("details", "")
            evidence = self._format_evidence(finding.get("evidence", ""))
            request = finding.get("request", "")
            response_excerpt = finding.get("response_excerpt", "")
            steps_to_reproduce = finding.get("steps_to_reproduce", [])

            steps = f"""
1.  Navigate to the affected endpoint: `{finding.get('url', 'N/A')}`
2.  {details}
3.  Observe the evidence below to confirm the vulnerability.
"""
            if steps_to_reproduce:
                steps_lines = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps_to_reproduce))
                steps += f"\n## Detailed Steps to Reproduce\n\n{steps_lines}\n"
            if evidence:
                steps += f"\n## Evidence\n\n```\n{evidence}\n```\n"
            if request:
                steps += f"\n## Request\n\n```\n{request}\n```\n"
            if response_excerpt:
                steps += f"\n## Response Excerpt\n\n```\n{response_excerpt}\n```\n"

            vuln_type = finding.get("title", "finding").replace(" ", "_").replace("/", "_")
            safe_target = self._sanitize_target()
            url_hash = hashlib.md5(finding.get("url", "").encode()).hexdigest()[:8]
            filename = f"{vuln_type}_{safe_target}_{url_hash}.md"
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

import hashlib
import os
from pathlib import Path
from typing import Any, Dict

from reporting.base import ReporterBase


class MarkdownReporter(ReporterBase):
    def _get_evidence_markdown(self, finding: Any) -> str:
        """Render evidence as markdown blocks, handling both list and string formats."""
        evidence = finding.get("evidence", "")
        if not evidence:
            return "*No evidence collected.*"
        if isinstance(evidence, list):
            parts = []
            for i, ev in enumerate(evidence):
                if hasattr(ev, 'to_dict'):
                    ev_text = json.dumps(ev.to_dict(), indent=2)
                else:
                    ev_text = str(ev)
                desc = getattr(ev, 'description', f'Evidence #{i+1}') if hasattr(ev, 'description') else f'Evidence #{i+1}'
                parts.append(f"> **{desc}**\n```\n{ev_text}\n```")
            return "\n\n".join(parts)
        return f"```\n{evidence}\n```"

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
            evidence_md = self._get_evidence_markdown(finding)
            request = finding.get("request", "")
            response_excerpt = finding.get("response_excerpt", "")
            steps_to_reproduce = finding.get("steps_to_reproduce", [])

            steps = ""
            if steps_to_reproduce:
                steps_lines = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps_to_reproduce))
                steps = f"{steps_lines}\n"
            if not steps:
                steps = f"1. Navigate to the affected endpoint: `{finding.get('url', 'N/A')}`\n2. {details}\n3. Observe the evidence below to confirm the vulnerability.\n"

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
**CVSS:** {cvss_score:.1f} ({rating})
**CVSS Vector:** `{cvss_vector}`
**Verification Stage:** {stage}
**Evidence Strength:** {evidence_strength or '—'}
**False Positive Risk:** {fpr or '—'}

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

            content += f"""## Evidence

{evidence_md}

## Request

```\n{request}\n```\n""" if request else ""

            if response_excerpt:
                content += f"## Response Excerpt\n\n```\n{response_excerpt}\n```\n\n"

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

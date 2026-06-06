import json
from datetime import datetime
from typing import Any, Dict

from reporting.base import ReporterBase


class BugcrowdReporter(ReporterBase):
    def render(self) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

        summary_rows = []
        for i, f in enumerate(self.findings, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title") or f.get("details", "Untitled")
            url = f.get("url", self.target)
            stage = f.get("verification_stage", "").title() or "Detected"
            confidence = f.get("confidence_score")
            cs = f"{confidence:.0f}/100" if confidence is not None else "—"
            cvss_score = self._get_cvss_score(f)
            cvss_rating = self._severity_rating(cvss_score)
            summary_rows.append(f"| {i} | {title} | {sev} | `{url}` | {stage} | {cs} | {cvss_score:.1f} ({cvss_rating}) |")

        summary_header = "| # | Title | Severity | URL | Stage | Confidence | CVSS |"
        summary_sep = "|---|-------|----------|-----|-------|------------|------|"
        summary_table = "\n".join(summary_rows) if summary_rows else "| No findings. |"

        per_finding = []
        for i, f in enumerate(self.findings, 1):
            title = f.get("title") or f.get("details", "Untitled")
            sev = f.get("severity", "info").upper()
            what = f.get("what_is_it") or f.get("details", "")
            impact_narrative = self._build_impact_narrative(f)
            steps = f.get("validation_steps") or f.get("steps_to_reproduce", "")
            if isinstance(steps, list):
                steps = "\n".join(f"{j+1}. {s}" for j, s in enumerate(steps))
            remed = f.get("remediation") or f.get("recommendation", "")
            remed = remed or self._build_remediation(f)
            evidence = (
                getattr(f, 'evidence', None)
                if not isinstance(f, dict)
                else f.get("evidence", "")
            )
            if not evidence:
                evidence = f.get("proof") or f.get("request_response", "")
            if isinstance(evidence, dict):
                evidence = json.dumps(evidence, indent=2)
            elif isinstance(evidence, list):
                evidence_parts = []
                for j, ev in enumerate(evidence):
                    ev_type = ev.__class__.__name__ if hasattr(ev, '__class__') else ""
                    desc = getattr(ev, 'description', f'Evidence #{j+1}') if hasattr(ev, 'description') else f'Evidence #{j+1}'
                    if ev_type == "HttpRequestEvidence":
                        curl = getattr(ev, 'curl_command', '') or getattr(ev, 'method', '') + ' ' + getattr(ev, 'url', '')
                        evidence_parts.append(f"> **{desc}**\n```\n{curl}\n```")
                    elif ev_type == "BrowserExecutionEvidence":
                        scr = getattr(ev, 'screenshot_path', '')
                        ctx = getattr(ev, 'execution_context', '')
                        alert = getattr(ev, 'alert_fired', False)
                        dom = getattr(ev, 'dom_mutation', False)
                        status = "✅ Executed" if alert or dom else "❌ Not executed"
                        scr_line = f"\n![Screenshot]({scr})" if scr else ""
                        evidence_parts.append(f"> **{desc}** — {status}\n> Context: {ctx}{scr_line}")
                    elif ev_type == "AuthorizationComparisonEvidence":
                        orig_user = getattr(ev, 'original_user', '')
                        tgt_user = getattr(ev, 'target_user', '')
                        violated = getattr(ev, 'ownership_violated', False)
                        orig_status = getattr(ev, 'original_status', 0)
                        tgt_status = getattr(ev, 'target_status', 0)
                        body_diff = getattr(ev, 'content_different', False)
                        orig_body = getattr(ev, 'original_body_excerpt', '')
                        tgt_body = getattr(ev, 'target_body_excerpt', '')
                        lines = [
                            f"> **{desc}** — {'⚠️ Ownership Violation' if violated else 'No violation'}",
                            f"> HTTP {orig_status} ({orig_user})  →  HTTP {tgt_status} ({tgt_user})",
                        ]
                        if body_diff:
                            lines.append(f"> Body differs: {body_diff}")
                        if orig_body:
                            lines.append(f"> Original excerpt: `{orig_body[:200]}`")
                        if tgt_body:
                            lines.append(f"> Target excerpt: `{tgt_body[:200]}`")
                        evidence_parts.append("\n".join(lines))
                    elif ev_type == "TimingEvidence":
                        triggered = getattr(ev, 'triggered_time_ms', 0.0)
                        baseline = getattr(ev, 'baseline_time_ms', 0.0)
                        evidence_parts.append(f"> **{desc}**\n> Baseline: {baseline:.1f}ms | Actual: {triggered:.1f}ms | Diff: {triggered-baseline:.1f}ms")
                    elif ev_type == "OOBCallbackEvidence":
                        cb_type = getattr(ev, 'callback_type', 'unknown')
                        cb_host = getattr(ev, 'callback_host', '')
                        cb_token = getattr(ev, 'callback_token', '')
                        cb_time = getattr(ev, 'interaction_time', '')
                        cb_raw = getattr(ev, 'raw_data', '')
                        meta = f" | Host: {cb_host} | Token: {cb_token}" if cb_host else ""
                        time_line = f" | Time: {cb_time}" if cb_time else ""
                        evidence_parts.append(f"> **{desc}** ({cb_type}{meta}{time_line})\n```\n{str(cb_raw)[:500]}\n```")
                    elif ev_type == "GraphQLSchemaEvidence":
                        schema = getattr(ev, 'schema_preview', '')
                        q_count = getattr(ev, 'query_count', 0)
                        m_count = getattr(ev, 'mutation_count', 0)
                        evidence_parts.append(f"> **{desc}** ({q_count} queries, {m_count} mutations)\n```\n{str(schema)[:800]}\n```")
                    else:
                        if hasattr(ev, 'to_dict'):
                            ev_text = json.dumps(ev.to_dict(), indent=2)
                        else:
                            ev_text = str(ev)
                        evidence_parts.append(f"> **{desc}**\n```\n{ev_text}\n```")
                evidence = "\n".join(evidence_parts) if evidence_parts else ""

            confidence = f.get("confidence_score")
            cs = f"{confidence:.0f}/100" if confidence is not None else "—"

            cvss_score = self._get_cvss_score(f)
            cvss_vector = self._get_cvss_vector(f)
            cvss_rating = self._severity_rating(cvss_score)

            grouped = f.get("grouped_urls", [])
            urls = "\n".join(f"- {u}" for u in grouped) if grouped else f"- {f.get('url', self.target)}"

            screenshot_path = f.get("screenshot_path", "")
            screenshot_line = f"\n**Screenshot:** {screenshot_path}\n" if screenshot_path else ""
            response_excerpt = f.get("response_excerpt", "")

            per_finding.append(f"""## Finding #{i}: {title}

| Field | Value |
|-------|-------|
| Severity | {sev} |
| URL | `{f.get('url', self.target)}` |
| Verification Stage | {f.get('verification_stage', '').title() or 'Detected'} |
| Confidence | {cs} |
| CVSS | {cvss_score:.1f} ({cvss_rating}) |
| CVSS Vector | `{cvss_vector}` |
| Parameter | `{f.get('parameter', '—')}` |
| False Positive Risk | {f.get('false_positive_risk', '—')} |

### Description
{what}

### Affected URLs
{urls}

### Evidence
{evidence if evidence else "*No evidence collected.*"}

### Request
```
{self._build_curl_command(f)}
```
{"### Response Excerpt\n```\n" + response_excerpt + "\n```\n" if response_excerpt else ""}{screenshot_line}
### Steps to Reproduce
{steps or "1. Send a request to the affected endpoint to reproduce the vulnerability."}

### Impact
{impact_narrative}

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

{summary_header}
{summary_sep}
{summary_table}

---

{body}

---

*Report generated by BugBounty-Hunter — https://github.com/anomalyco/bugbounty-hunter*
"""

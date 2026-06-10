import base64
import html as html_mod
import json
import os
import re
from pathlib import Path
from typing import Any

from models.evidence import (
    AuthorizationComparisonEvidence,
    BrowserExecutionEvidence,
    CommandExecutionEvidence,
    CompositeEvidence,
    EvidenceBase,
    GraphQLSchemaEvidence,
    HttpRequestEvidence,
    HttpResponseEvidence,
    ImpactEvidence,
    OOBCallbackEvidence,
    OwnershipEvidence,
    ResponseDiffEvidence,
    ResponseExcerptEvidence,
    ScreenshotEvidence,
    TimingEvidence,
)
from models.evidence_bundle import EvidenceBundle
from models.finding import Finding

PAGE_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
:root {
    --bg: #0f0f0f; --surface: #1e1e1e; --surface2: #2a2a2a;
    --text: #e0e0e0; --text2: #999; --border: #333;
    --critical: #e74c3c; --high: #e67e22; --medium: #f1c40f;
    --low: #3498db; --info: #95a5a6; --confirmed: #2ecc71;
}
body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; padding: 20px; }
.container { max-width: 960px; margin: 0 auto; }
header { text-align: center; margin-bottom: 32px; border-bottom: 2px solid var(--border); padding-bottom: 20px; }
header h1 { font-size: 1.8em; }
.timestamp { color: var(--text2); font-size: .85em; }
.sev-badge { display: inline-block; padding: 4px 16px; border-radius: 16px; font-size: .8em; font-weight: 700; text-transform: uppercase; }
.sev-critical { background: var(--critical); color: #fff; }
.sev-high { background: var(--high); color: #fff; }
.sev-medium { background: var(--medium); color: #000; }
.sev-low { background: var(--low); color: #fff; }
.sev-info { background: var(--info); color: #fff; }
.top-meta { display: flex; gap: 12px; justify-content: center; align-items: center; flex-wrap: wrap; margin: 12px 0; }
.meta-chip { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 4px 12px; font-size: .82em; color: var(--text2); }
.meta-chip strong { color: var(--text); }
.section { background: var(--surface); border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,.3); }
.section h2 { font-size: 1.15em; margin-bottom: 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; color: var(--text); }
.section h3 { font-size: 1em; margin: 12px 0 8px; color: var(--text); }
.row { margin-bottom: 6px; font-size: .88em; }
.row strong { color: var(--text2); min-width: 90px; display: inline-block; }
.url { font-family: 'Courier New', monospace; word-break: break-all; font-size: .85em; }
pre { background: var(--bg); padding: 10px 14px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: .82em; word-break: break-all; overflow-x: auto; margin-top: 4px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; }
details { margin: 6px 0; }
details summary { cursor: pointer; color: var(--text2); font-size: .85em; padding: 4px 0; }
details summary:hover { color: var(--text); }
details summary strong { color: var(--text); }
.evidence-box { background: var(--bg); padding: 10px 14px; border-radius: 4px; font-size: .82em; word-break: break-all; margin: 4px 0; max-height: 350px; overflow-y: auto; }
ol.steps { margin: 4px 0; padding-left: 20px; }
ol.steps li { margin-bottom: 4px; font-size: .85em; }
.copy-btn { background: var(--surface2); color: var(--text2); border: 1px solid var(--border); padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: .78em; }
.copy-btn:hover { background: var(--border); color: var(--text); }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px; }
.meta-item { background: var(--surface2); border-radius: 4px; padding: 8px 12px; }
.meta-item .label { color: var(--text2); font-size: .75em; text-transform: uppercase; letter-spacing: .4px; }
.meta-item .value { font-size: .88em; font-weight: 600; margin-top: 2px; }
.strength-bar { height: 6px; border-radius: 3px; margin: 8px 0; }
.conf-high { color: #2ecc71; }
.conf-mid { color: #f39c12; }
.conf-low { color: #e74c3c; }
.head-table { width: 100%; border-collapse: collapse; font-size: .82em; margin: 4px 0; }
.head-table th, .head-table td { border: 1px solid var(--border); padding: 3px 8px; text-align: left; }
.head-table th { background: var(--surface2); color: var(--text2); }
img.embed-screenshot { max-width: 100%; max-height: 400px; border: 1px solid var(--border); border-radius: 4px; margin: 8px 0; cursor: zoom-in; }
.status-ok { color: #2ecc71; }
.status-fail { color: #e74c3c; }
footer { text-align: center; margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--text2); font-size: .82em; }
"""

SEVERITY_COLORS = {
    "critical": "#e74c3c", "high": "#e67e22", "medium": "#f1c40f",
    "low": "#3498db", "info": "#95a5a6",
}

STAGE_COLORS = {
    "detected": "#e74c3c", "partially_validated": "#9b59b6",
    "validated": "#f39c12", "exploitable": "#2ecc71", "verified": "#27ae60",
}


def _slug(vuln_type: str) -> str:
    s = vuln_type.lower().replace(" ", "_").replace("/", "_")
    return re.sub(r"[^a-z0-9_]", "", s)


def _h(text: str) -> str:
    return html_mod.escape(str(text))


def _render_http_request(ev: HttpRequestEvidence) -> str:
    method = _h(ev.method)
    url = _h(ev.url)
    body = _h(ev.body)
    curl = _h(ev.curl_command) if ev.curl_command else f"curl -X {method} \"{ev.url}\""
    headers_html = ""
    if ev.headers:
        rows = "".join(
            f"<tr><td>{_h(k)}</td><td>{_h(v)}</td></tr>"
            for k, v in ev.headers.items()
        )
        headers_html = f"""
        <details><summary>Headers ({len(ev.headers)})</summary>
        <table class="head-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>
        </details>"""
    body_html = f"<pre>{body}</pre>" if body else ""
    return f"""<details open><summary>{_h(ev.description)}</summary>
    <div class="evidence-box">
    <div class="row"><strong>Method:</strong> {method}</div>
    <div class="row"><strong>URL:</strong> <span class="url">{url}</span></div>
    {headers_html}
    {body_html}
    <div class="row" style="margin-top:8px"><button class="copy-btn" onclick="copyText(this,'{_h(curl).replace("'","\\'")}')">Copy cURL</button></div>
    </div></details>"""


def _render_http_response(ev: HttpResponseEvidence) -> str:
    headers_html = ""
    if ev.headers:
        rows = "".join(
            f"<tr><td>{_h(k)}</td><td>{_h(v)}</td></tr>"
            for k, v in ev.headers.items()
        )
        headers_html = f"""
        <details><summary>Headers ({len(ev.headers)})</summary>
        <table class="head-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>
        </details>"""
    body_pre = f"<pre>{_h(ev.body_excerpt[:2000])}</pre>" if ev.body_excerpt else ""
    return f"""<details open><summary>{_h(ev.description)}</summary>
    <div class="evidence-box">
    <div class="row"><strong>Status:</strong> <span class="{'status-ok' if 200 <= ev.status_code < 300 else 'status-fail'}">{ev.status_code}</span></div>
    <div class="row"><strong>Body length:</strong> {ev.body_length} bytes</div>
    {headers_html}
    {body_pre}
    </div></details>"""


def _render_response_excerpt(ev: ResponseExcerptEvidence) -> str:
    ctx = f" — {_h(ev.context)}" if ev.context else ""
    return f"""<details open><summary>{_h(ev.description)}{ctx}</summary>
    <pre>{_h(ev.excerpt[:2000])}</pre></details>"""


def _render_browser_execution(ev: BrowserExecutionEvidence) -> str:
    executed = ev.alert_fired or ev.dom_mutation
    status = "✓ Executed" if executed else "✗ Not executed"
    status_cls = "status-ok" if executed else "status-fail"
    ctx = _h(ev.execution_context) if ev.execution_context else ""
    ctx_html = f"<div class=\"row\">{ctx}</div>" if ctx else ""
    scr_html = ""
    if ev.screenshot_path:
        path = ev.screenshot_path
        if os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
                ext = path.rsplit(".", 1)[-1].lower()
                mime = "image/png" if ext == "png" else "image/jpeg"
                scr_html = f'<img class="embed-screenshot" src="data:{mime};base64,{b64}" alt="Browser screenshot">'
            except Exception:
                scr_html = ""
    return f"""<details open><summary>{_h(ev.description)} — <strong class="{status_cls}">{status}</strong></summary>
    <div class="evidence-box">
    {ctx_html}
    {scr_html}
    </div></details>"""


def _render_screenshot(ev: ScreenshotEvidence) -> str:
    if ev.base64_data:
        mime = _h(ev.mime_type)
        return f"""<details open><summary>{_h(ev.description)}</summary>
        <img class="embed-screenshot" src="data:{mime};base64,{ev.base64_data}" alt="Screenshot"></details>"""
    if ev.file_path and os.path.isfile(ev.file_path):
        try:
            with open(ev.file_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            ext = ev.file_path.rsplit(".", 1)[-1].lower()
            mime = "image/png" if ext == "png" else "image/jpeg"
            return f"""<details open><summary>{_h(ev.description)}</summary>
            <img class="embed-screenshot" src="data:{mime};base64,{b64}" alt="Screenshot"></details>"""
        except Exception:
            pass
    return f"<details><summary>{_h(ev.description)}</summary><div class=\"evidence-box\">Screenshot not available</div></details>"


def _render_timing(ev: TimingEvidence) -> str:
    delta = ev.triggered_time_ms - ev.baseline_time_ms
    color = "status-ok" if delta > ev.delay_threshold_ms else "status-fail"
    return f"""<details open><summary>{_h(ev.description)}</summary>
    <div class="evidence-box">
    <div class="row"><strong>Baseline:</strong> {ev.baseline_time_ms:.1f}ms</div>
    <div class="row"><strong>Triggered:</strong> {ev.triggered_time_ms:.1f}ms</div>
    <div class="row"><strong>Delta:</strong> <span class="{color}">{delta:+.1f}ms</span></div>
    <div class="row"><strong>Threshold:</strong> {ev.delay_threshold_ms:.0f}ms</div>
    <div class="row"><strong>Attempts:</strong> {ev.total_attempts}</div>
    </div></details>"""


def _render_oob_callback(ev: OOBCallbackEvidence) -> str:
    return f"""<details open><summary>{_h(ev.description)}</summary>
    <div class="evidence-box">
    <div class="row"><strong>Callback type:</strong> {_h(ev.callback_type)}</div>
    <div class="row"><strong>Host:</strong> {_h(ev.callback_host)}</div>
    <div class="row"><strong>Token:</strong> <span class="url">{_h(ev.callback_token)}</span></div>
    <div class="row"><strong>Interaction time:</strong> {_h(ev.interaction_time)}</div>
    <details><summary>Raw data</summary><pre>{_h(ev.raw_data[:2000])}</pre></details>
    </div></details>"""


def _render_authz_comparison(ev: AuthorizationComparisonEvidence) -> str:
    violated = ev.ownership_violated
    badge = "✓ Violation" if violated else "No violation"
    badge_cls = "status-ok" if violated else ""
    return f"""<details open><summary>{_h(ev.description)} — <strong class="{badge_cls}">{badge}</strong></summary>
    <div class="evidence-box">
    <div class="row"><strong>Original user:</strong> {_h(ev.original_user)} → HTTP {ev.original_status}</div>
    <div class="row"><strong>Target user:</strong> {_h(ev.target_user)} → HTTP {ev.target_status}</div>
    <div class="row"><strong>Content different:</strong> {ev.content_different}</div>
    <details><summary>Original response excerpt</summary><pre>{_h(ev.original_body_excerpt[:500])}</pre></details>
    <details><summary>Target response excerpt</summary><pre>{_h(ev.target_body_excerpt[:500])}</pre></details>
    </div></details>"""


def _render_command_execution(ev: CommandExecutionEvidence) -> str:
    return f"""<details open><summary>{_h(ev.description)}</summary>
    <div class="evidence-box">
    <div class="row"><strong>Command:</strong> <pre style="display:inline">{_h(ev.command)}</pre></div>
    <div class="row"><strong>Shell chars:</strong> {", ".join(_h(c) for c in (ev.shell_chars_detected or []))}</div>
    <div class="row"><strong>Exit code:</strong> {ev.exit_code_observed}</div>
    <div class="row"><strong>Timing delay:</strong> {ev.timing_delay_ms:.0f}ms</div>
    <details><summary>Output excerpt</summary><pre>{_h(ev.output_excerpt[:2000])}</pre></details>
    </div></details>"""


def _render_graphql_schema(ev: GraphQLSchemaEvidence) -> str:
    return f"""<details open><summary>{_h(ev.description)}</summary>
    <div class="evidence-box">
    <div class="row"><strong>Queries:</strong> {ev.query_count}</div>
    <div class="row"><strong>Mutations:</strong> {ev.mutation_count}</div>
    <div class="row"><strong>Operation:</strong> {_h(ev.operation_name)}</div>
    <details><summary>Schema preview</summary><pre>{_h(ev.schema_preview[:2000])}</pre></details>
    <details><summary>Introspection query</summary><pre>{_h(ev.query_text[:1000])}</pre></details>
    </div></details>"""


def _render_response_diff(ev: ResponseDiffEvidence) -> str:
    return f"""<details open><summary>{_h(ev.description)}</summary>
    <div class="evidence-box">
    <div class="row"><strong>Param:</strong> {_h(ev.trigger_param)}</div>
    <div class="row"><strong>Baseline:</strong> HTTP {ev.baseline_status}</div>
    <div class="row"><strong>Triggered:</strong> HTTP {ev.triggered_status}</div>
    <div class="row"><strong>Content delta:</strong> {ev.content_length_diff:+d} bytes</div>
    <details><summary>Baseline body</summary><pre>{_h(ev.baseline_body_excerpt[:500])}</pre></details>
    <details><summary>Triggered body</summary><pre>{_h(ev.triggered_body_excerpt[:500])}</pre></details>
    </div></details>"""


def _render_composite(ev: CompositeEvidence) -> str:
    items = "".join(f"<li>{_h(d)}</li>" for d in (ev.child_descriptions or []))
    return f"""<details><summary>{_h(ev.description)}</summary>
    <div class="evidence-box">
    <div class="row"><strong>Sub-evidences:</strong> {ev.evidence_count or len(ev.child_descriptions or [])}</div>
    <ul style="margin:4px 0 0 16px;font-size:.85em">{items}</ul>
    </div></details>"""


def _render_ownership(ev: OwnershipEvidence) -> str:
    badge = "✓ Violation" if ev.ownership_violated else "No violation"
    badge_cls = "status-ok" if ev.ownership_violated else ""
    return f"""<details open><summary>{_h(ev.description)} — <strong class="{badge_cls}">{badge}</strong></summary>
    <div class="evidence-box">
    <div class="row"><strong>Original owner:</strong> {_h(ev.original_owner)}</div>
    <div class="row"><strong>Claiming identity:</strong> {_h(ev.claiming_identity)}</div>
    <div class="row"><strong>Resource:</strong> {_h(ev.resource_identifier)}</div>
    <div class="row"><strong>Proof type:</strong> {_h(ev.proof_type)}</div>
    <div class="row"><strong>Access granted:</strong> {ev.access_granted}</div>
    <div class="row"><strong>User context:</strong> {_h(ev.user_context)}</div>
    </div></details>"""


def _render_impact(ev: ImpactEvidence) -> str:
    badge = "Demonstrated" if ev.demonstrated else "Theoretical"
    badge_cls = "status-ok" if ev.demonstrated else ""
    return f"""<details open><summary>{_h(ev.description)} — <strong class="{badge_cls}">{badge}</strong></summary>
    <div class="evidence-box">
    <div class="row"><strong>Impact type:</strong> {_h(ev.impact_type)}</div>
    <div class="row"><strong>Severity confirmed:</strong> {ev.severity_confirmed}</div>
    <div class="row"><strong>Business impact:</strong> {_h(ev.business_impact)}</div>
    <div class="row"><strong>Attack scenario:</strong> {_h(ev.attack_scenario)}</div>
    <div class="row"><strong>Exploitation proof:</strong> {_h(ev.exploitation_proof)}</div>
    </div></details>"""


def _render_evidence(ev: Any) -> str:
    ev_type = ev.__class__.__name__ if hasattr(ev, "__class__") else ""
    if ev_type == "HttpRequestEvidence":
        return _render_http_request(ev)
    if ev_type == "HttpResponseEvidence":
        return _render_http_response(ev)
    if ev_type == "ResponseExcerptEvidence":
        return _render_response_excerpt(ev)
    if ev_type == "BrowserExecutionEvidence":
        return _render_browser_execution(ev)
    if ev_type == "ScreenshotEvidence":
        return _render_screenshot(ev)
    if ev_type == "TimingEvidence":
        return _render_timing(ev)
    if ev_type == "OOBCallbackEvidence":
        return _render_oob_callback(ev)
    if ev_type == "AuthorizationComparisonEvidence":
        return _render_authz_comparison(ev)
    if ev_type == "CommandExecutionEvidence":
        return _render_command_execution(ev)
    if ev_type == "GraphQLSchemaEvidence":
        return _render_graphql_schema(ev)
    if ev_type == "ResponseDiffEvidence":
        return _render_response_diff(ev)
    if ev_type == "CompositeEvidence":
        return _render_composite(ev)
    if ev_type == "OwnershipEvidence":
        return _render_ownership(ev)
    if ev_type == "ImpactEvidence":
        return _render_impact(ev)
    if hasattr(ev, "to_dict"):
        text = json.dumps(ev.to_dict(), indent=2)
    else:
        text = str(ev)
    return f"<details><summary>{_h(getattr(ev, 'description', 'Evidence'))}</summary><pre>{_h(text[:2000])}</pre></details>"


class PerFindingExporter:
    """Per-finding evidence export renderer.

    Generates self-contained HTML pages for individual findings with
    full evidence rendering, bundle metadata, reproduction steps,
    curl commands, and JSON-LD for LLM parsing.
    """

    def export_single(
        self,
        finding: Finding,
        output_dir: str,
        evidence_bundle: EvidenceBundle | None = None,
        include_screenshots: bool = True,
    ) -> str:
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        slug = _slug(finding.vuln_type)
        short_fp = finding.fingerprint[:12] if finding.fingerprint else "unknown"
        filename = f"{short_fp}_{slug}.html"
        filepath = os.path.join(output_dir, filename)

        sev = (finding.severity or "info").lower()
        stage = (finding.verification_stage or "detected").lower()
        score = finding.confidence_score or 0
        conf_class = "conf-high" if score >= 61 else ("conf-mid" if score >= 31 else "conf-low")

        # ── Evidence rendering ──
        evidence_list = finding.evidence or []
        if isinstance(evidence_list, str):
            evidence_list = [evidence_list] if evidence_list else []
        evidence_html = ""
        if evidence_list:
            parts = []
            for ev in evidence_list:
                if not isinstance(ev, EvidenceBase):
                    if hasattr(ev, "to_dict"):
                        text = json.dumps(ev.to_dict(), indent=2)
                    else:
                        text = str(ev)
                    parts.append(f"<details><summary>Raw evidence</summary><pre>{_h(text[:2000])}</pre></details>")
                    continue
                parts.append(_render_evidence(ev))
            evidence_html = "".join(parts)
        else:
            raw_ev = getattr(finding, "evidence", "")
            if isinstance(raw_ev, str) and raw_ev:
                evidence_html = f"<pre>{_h(raw_ev[:2000])}</pre>"

        # ── Steps to reproduce ──
        steps = finding.reproduction_steps or []
        if isinstance(steps, str):
            steps = [steps]
        steps_html = ""
        if steps:
            items = "".join(f"<li>{_h(s)}</li>" for s in steps)
            steps_html = f"<ol class=\"steps\">{items}</ol>"

        # ── Curl command ──
        curl_cmd = finding.curl_command or ""
        if not curl_cmd and finding.request and finding.request.startswith("curl"):
            curl_cmd = finding.request
        curl_html = ""
        if curl_cmd:
            e_curl = _h(curl_cmd)
            curl_html = f'<div class="row"><strong>cURL:</strong><pre>{e_curl}</pre><button class="copy-btn" onclick="copyText(this,\'{e_curl.replace("'","\\'")}\')">Copy</button></div>'

        # ── Bundle metadata ──
        bundle_html = ""
        if evidence_bundle:
            bundle = evidence_bundle
            strength_colors = {
                "very_strong": "#2ecc71", "strong": "#27ae60",
                "medium": "#f39c12", "weak": "#e74c3c",
            }
            color = strength_colors.get(bundle.overall_strength, "#95a5a6")
            cats = []
            for cat, indices in bundle.categories.items():
                if indices:
                    cats.append(f"{cat}: {len(indices)}")
            cat_line = " | ".join(cats)
            ready = '<span style="background:#2ecc71;color:#fff;padding:2px 10px;border-radius:12px;font-size:.75em;font-weight:700">SUBMISSION READY</span>' if bundle.submission_ready else ""  # noqa: E501
            bundle_html = f"""
            <div class="section">
            <h2>Evidence Bundle</h2>
            <div class="meta-grid">
            <div class="meta-item"><div class="label">Strength</div><div class="value" style="color:{color}">{bundle.overall_strength.replace("_"," ").title()}</div></div>
            <div class="meta-item"><div class="label">Completeness</div><div class="value">{bundle.completeness_score:.0%}</div></div>
            <div class="meta-item"><div class="label">Categories</div><div class="value" style="font-size:.78em">{cat_line}</div></div>
            <div class="meta-item"><div class="label">Evidence count</div><div class="value">{len(bundle.evidence)}</div></div>
            </div>
            {ready}
            </div>"""

        # ── Impact narrative ──
        impact_text = finding.impact or finding.details or "See evidence for impact details."
        e_impact = _h(impact_text)

        # ── Remediation ──
        remediation = finding.remediation or ""
        e_remediation = _h(remediation)

        # ── Metadata fields ──
        cvss_score = finding.cvss_score
        cvss_vector = finding.cvss_vector or ""
        cvss_line = f"CVSS {cvss_score:.1f}" if cvss_score is not None else "N/A"
        vector_line = f" ({cvss_vector})" if cvss_vector else ""

        # ── Confidence reasons ──
        reasons_html = ""
        reasons = getattr(finding, "confidence_reasons", None) or []
        if reasons and isinstance(reasons, list):
            items = "".join(
                f"<li style=\"color:{'#2ecc71' if r.startswith('+') else '#cc5555'}\">{_h(r)}</li>"
                for r in reasons
            )
            reasons_html = f"<div class=\"row\"><strong>Confidence Reasons:</strong><ul style=\"margin:2px 0;padding-left:20px\">{items}</ul></div>"

        # ── JSON-LD ──
        jsonld_data = {
            "@context": "https://schema.org",
            "@type": "Report",
            "name": f"Finding: {finding.title}",
            "vuln_type": finding.vuln_type,
            "severity": sev,
            "url": finding.url,
            "parameter": finding.parameter,
            "verification_stage": stage,
            "confidence_score": score,
            "confidence_label": finding.confidence_label,
            "finding_state": finding.finding_state,
            "evidence_strength": finding.evidence_strength,
            "false_positive_risk": finding.false_positive_risk,
            "fingerprint": finding.fingerprint,
            "timestamp": finding.timestamp,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "target": finding.target,
        }
        if evidence_bundle:
            jsonld_data["evidence_bundle"] = {
                "strength": evidence_bundle.overall_strength,
                "completeness_score": evidence_bundle.completeness_score,
                "submission_ready": evidence_bundle.submission_ready,
            }
        jsonld_html_raw = json.dumps(jsonld_data, indent=2).replace("</script>", "<\\/script>")

        page = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Finding: {_h(finding.title)}</title>
    <style>{PAGE_CSS}</style>
    <script type="application/ld+json">
{jsonld_html_raw}
    </script>
</head>
<body>
    <div class="container">
        <header>
            <h1>{_h(finding.title)}</h1>
            <div class="top-meta">
                <span class="sev-badge sev-{sev}">{sev.upper()}</span>
                <span class="meta-chip"><strong>Confidence:</strong> <span class="{conf_class}">{score:.0f}/100</span></span>
                <span class="meta-chip"><strong>Stage:</strong> <span style="color:{STAGE_COLORS.get(stage, '#95a5a6')}">{stage.replace("_"," ").title()}</span></span>
                <span class="meta-chip"><strong>State:</strong> {_h(finding.finding_state.replace("_"," ").title())}</span>
            </div>
            <div class="top-meta">
                <span class="meta-chip"><strong>Evidence:</strong> {_h(finding.evidence_strength.title())}</span>
                <span class="meta-chip"><strong>FP Risk:</strong> <span class="{'status-ok' if finding.false_positive_risk == 'low' else 'conf-mid' if finding.false_positive_risk == 'medium' else 'status-fail'}">{_h(finding.false_positive_risk.title())}</span></span>
                <span class="meta-chip"><strong>{cvss_line}{vector_line}</strong></span>
            </div>
        </header>

        <div class="section">
            <h2>Finding Details</h2>
            <div class="meta-grid">
                <div class="meta-item"><div class="label">URL</div><div class="value url">{_h(finding.url)}</div></div>
                <div class="meta-item"><div class="label">Parameter</div><div class="value">{_h(finding.parameter) or "N/A"}</div></div>
                <div class="meta-item"><div class="label">Fingerprint</div><div class="value" style="font-family:monospace;font-size:.78em">{_h(finding.fingerprint)}</div></div>
                <div class="meta-item"><div class="label">Timestamp</div><div class="value">{_h(finding.timestamp)}</div></div>
                <div class="meta-item"><div class="label">Vulnerability Type</div><div class="value">{_h(finding.vuln_type)}</div></div>
                <div class="meta-item"><div class="label">Signal Count</div><div class="value">{getattr(finding, 'signal_count', 1)}</div></div>
            </div>
        </div>

        <div class="section">
            <h2>Description</h2>
            <p style="font-size:.9em">{_h(finding.details)}</p>
        </div>

        <div class="section">
            <h2>Impact</h2>
            <p style="font-size:.9em">{e_impact}</p>
        </div>

        {bundle_html}

        <div class="section">
            <h2>Reproduction Steps</h2>
            {steps_html or '<p style="color:var(--text2);font-size:.85em">No reproduction steps provided.</p>'}
        </div>

        {curl_html}

        <div class="section">
            <h2>Evidence</h2>
            {evidence_html or '<p style="color:var(--text2);font-size:.85em">No evidence recorded.</p>'}
        </div>

        <div class="section">
            <h2>Remediation</h2>
            <p style="font-size:.9em">{e_remediation or 'No remediation guidance provided.'}</p>
        </div>

        {reasons_html}

    </div>
    <footer>
        Generated by BugBounty Hunter — Per-Finding Export
    </footer>
    <script>
    function copyText(btn, text) {{
        navigator.clipboard.writeText(text).then(function() {{
            var orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(function() {{ btn.textContent = orig; }}, 1200);
        }}).catch(function() {{}});
    }}
    </script>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(page)
        return filepath

    def export_all(
        self,
        findings: list[Finding],
        output_dir: str,
        evidence_bundles: dict[str, EvidenceBundle] | None = None,
    ) -> list[str]:
        paths: list[str] = []
        index_items: list[str] = []
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        for rank, finding in enumerate(findings, start=1):
            bundle = None
            if evidence_bundles and finding.fingerprint in evidence_bundles:
                bundle = evidence_bundles[finding.fingerprint]
            filepath = self.export_single(finding, output_dir, evidence_bundle=bundle)
            paths.append(filepath)

            short_fp = finding.fingerprint[:12] if finding.fingerprint else "unknown"
            index_items.append(
                f'<tr><td>{rank}</td>'
                f'<td><span class="sev-badge sev-{(finding.severity or "info").lower()}">{(finding.severity or "info").upper()}</span></td>'
                f'<td><a href="{_h(os.path.basename(filepath))}">{_h(finding.title)}</a></td>'
                f'<td class="url">{_h(finding.url[:80])}</td>'
                f'<td style="font-family:monospace;font-size:.78em">{_h(short_fp)}</td>'
                f'<td>{_h(finding.vuln_type)}</td></tr>'
            )

        index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Findings Index</title>
    <style>{PAGE_CSS}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Findings Index</h1>
            <p class="timestamp">{len(findings)} findings exported</p>
        </header>
        <div class="section">
            <table class="head-table">
                <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>URL</th><th>Fingerprint</th><th>Type</th></tr></thead>
                <tbody>{"".join(index_items)}</tbody>
            </table>
        </div>
    </div>
    <footer>
        Generated by BugBounty Hunter — Per-Finding Export
    </footer>
</body>
</html>"""

        index_path = os.path.join(output_dir, "index.html")
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(index_html)

        return paths

    def export_by_severity(
        self,
        findings: list[Finding],
        output_dir: str,
        evidence_bundles: dict[str, EvidenceBundle] | None = None,
    ) -> dict[str, list[str]]:
        groups: dict[str, list[Finding]] = {}
        for f in findings:
            sev = (f.severity or "info").lower()
            groups.setdefault(sev, []).append(f)

        result: dict[str, list[str]] = {}
        for sev, sev_findings in groups.items():
            sev_dir = os.path.join(output_dir, sev)
            Path(sev_dir).mkdir(parents=True, exist_ok=True)
            result[sev] = self.export_all(sev_findings, sev_dir, evidence_bundles)

        sev_index_items = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in result:
                count = len(result[sev])
                sev_index_items.append(
                    f'<tr><td><span class="sev-badge sev-{sev}">{sev.upper()}</span></td>'
                    f'<td>{count}</td>'
                    f'<td><a href="{sev}/index.html">View {count} finding{"s" if count != 1 else ""}</a></td></tr>'
                )

        sev_index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Findings by Severity</title>
    <style>{PAGE_CSS}</style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Findings by Severity</h1>
            <p class="timestamp">{len(findings)} findings across {len(result)} severity groups</p>
        </header>
        <div class="section">
            <table class="head-table">
                <thead><tr><th>Severity</th><th>Count</th><th>Link</th></tr></thead>
                <tbody>{"".join(sev_index_items)}</tbody>
            </table>
        </div>
    </div>
    <footer>
        Generated by BugBounty Hunter — Per-Finding Export
    </footer>
</body>
</html>"""

        sev_index_path = os.path.join(output_dir, "index.html")
        with open(sev_index_path, "w", encoding="utf-8") as f:
            f.write(sev_index_html)

        return result

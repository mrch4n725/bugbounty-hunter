import json
import html
from datetime import datetime
from typing import Any, Dict, List, Optional

from reporting.base import ReporterBase


REPORT_CSS = """
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
        --bg: #0f0f0f; --surface: #1e1e1e; --surface2: #2a2a2a;
        --text: #e0e0e0; --text2: #999; --border: #333;
        --critical: #e74c3c; --high: #e67e22; --medium: #f1c40f;
        --low: #3498db; --info: #95a5a6; --confirmed: #2ecc71;
    }
    .light {
        --bg: #f5f5f5; --surface: #ffffff; --surface2: #f0f0f0;
        --text: #222; --text2: #666; --border: #ddd;
    }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; padding: 20px; transition: background .3s, color .3s; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { text-align: center; margin-bottom: 40px; border-bottom: 2px solid var(--border); padding-bottom: 20px; }
    header h1 { font-size: 2.2em; color: var(--text); }
    .timestamp { color: var(--text2); font-size: .9em; }
    .top-bar { display: flex; justify-content: flex-end; gap: 10px; margin-bottom: 20px; }
    .theme-btn { background: var(--surface2); color: var(--text); border: 1px solid var(--border); padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: .85em; }
    .theme-btn:hover { opacity: .8; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 40px; }
    .stat-card { background: var(--surface); border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,.2); border-top: 4px solid var(--border); }
    .stat-card .val { font-size: 2em; font-weight: 700; }
    .stat-card .lbl { font-size: .8em; color: var(--text2); text-transform: uppercase; letter-spacing: .5px; }
    .stat-card.crit { border-top-color: var(--critical); } .stat-card.crit .val { color: var(--critical); }
    .stat-card.high { border-top-color: var(--high); } .stat-card.high .val { color: var(--high); }
    .stat-card.med { border-top-color: var(--medium); } .stat-card.med .val { color: var(--medium); }
    .stat-card.low { border-top-color: var(--low); } .stat-card.low .val { color: var(--low); }
    .stat-card.info { border-top-color: var(--info); } .stat-card.info .val { color: var(--info); }
    .stat-card.conf { border-top-color: var(--confirmed); } .stat-card.conf .val { color: var(--confirmed); }
    .stat-card.exploit { border-top-color: #9b59b6; } .stat-card.exploit .val { color: #9b59b6; }
    .stat-card.detect { border-top-color: #e74c3c; } .stat-card.detect .val { color: #e74c3c; }
    .stat-card.valid { border-top-color: #f39c12; } .stat-card.valid .val { color: #f39c12; }
    .chart-row { display: flex; gap: 20px; margin-bottom: 40px; flex-wrap: wrap; }
    .chart-box { background: var(--surface); border-radius: 8px; padding: 20px; flex: 1; min-width: 280px; box-shadow: 0 2px 8px rgba(0,0,0,.2); position: relative; height: 300px; }
    .chart-box canvas { max-height: 240px; }
    section { margin-bottom: 40px; background: var(--surface); padding: 24px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.2); }
    section h2 { font-size: 1.5em; margin-bottom: 16px; border-bottom: 2px solid var(--border); padding-bottom: 8px; }
    .filters { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
    .filter-btn { background: var(--surface2); color: var(--text2); border: 1px solid var(--border); padding: 6px 14px; border-radius: 20px; cursor: pointer; font-size: .8em; transition: all .2s; }
    .filter-btn:hover { opacity: .8; }
    .filter-btn.active { background: var(--border); color: var(--text); border-color: var(--text2); }
    .finding-card { background: var(--surface2); border-radius: 6px; margin-bottom: 12px; border-left: 4px solid var(--border); overflow: hidden; }
    .finding-card.critical { border-left-color: var(--critical); }
    .finding-card.high { border-left-color: var(--high); }
    .finding-card.medium { border-left-color: var(--medium); }
    .finding-card.low { border-left-color: var(--low); }
    .finding-card.info { border-left-color: var(--info); }
    .finding-header { padding: 14px 16px; cursor: pointer; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
    .finding-header:hover { background: rgba(255,255,255,.03); }
    .finding-title { font-weight: 600; font-size: .95em; flex: 1; min-width: 160px; }
    .finding-meta { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .sev-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: .75em; font-weight: 700; text-transform: uppercase; }
    .sev-critical { background: var(--critical); color: #fff; }
    .sev-high { background: var(--high); color: #fff; }
    .sev-medium { background: var(--medium); color: #000; }
    .sev-low { background: var(--low); color: #fff; }
    .sev-info { background: var(--info); color: #fff; }
    .conf-badge { padding: 2px 8px; border-radius: 10px; font-size: .75em; font-weight: 600; }
    .conf-high { background: #2ecc71; color: #fff; }
    .conf-mid { background: #f39c12; color: #000; }
    .conf-low { background: #e74c3c; color: #fff; }
    .stage-badge { padding: 2px 8px; border-radius: 10px; font-size: .75em; color: var(--text2); border: 1px solid var(--border); }
    .finding-body { padding: 0 16px 16px; display: none; }
    .finding-card.open .finding-body { display: block; }
    .finding-body .row { margin-bottom: 8px; font-size: .88em; }
    .finding-body .row strong { color: var(--text2); min-width: 90px; display: inline-block; }
    .finding-body .url { font-family: 'Courier New', monospace; word-break: break-all; font-size: .85em; }
    .finding-body .evidence { background: var(--bg); padding: 8px 12px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: .82em; word-break: break-all; margin-top: 4px; max-height: 400px; overflow-y: auto; }
    .finding-body .steps { margin: 4px 0; padding-left: 16px; }
    .finding-body .steps li { margin-bottom: 4px; font-size: .85em; }
    .finding-body details { margin: 4px 0; }
    .finding-body details summary { cursor: pointer; color: var(--text2); font-size: .85em; }
    .finding-body details summary:hover { color: var(--text); }
    .finding-body pre { white-space: pre-wrap; word-break: break-all; font-size: .82em; max-height: 300px; overflow-y: auto; }
    .copy-btn { background: var(--surface); color: var(--text2); border: 1px solid var(--border); padding: 3px 10px; border-radius: 4px; cursor: pointer; font-size: .78em; }
    .copy-btn:hover { background: var(--border); }
    .recon-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; }
    .recon-grid .url { display: block; padding: 6px 10px; background: var(--surface2); border-radius: 4px; font-size: .82em; word-break: break-all; }
    footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 2px solid var(--border); color: var(--text2); font-size: .85em; }
    .empty-message { color: var(--text2); font-style: italic; padding: 20px; text-align: center; }
    @media (max-width: 600px) { .summary { grid-template-columns: repeat(2, 1fr); } .finding-header { flex-direction: column; align-items: flex-start; } }
"""


class HTMLReporter(ReporterBase):
    def render(self) -> str:
        sorted_findings = self._sort_findings()
        severity_counts = self._get_severity_counts()
        verification_breakdown = self._get_verification_breakdown()
        subdomains = self.recon_data.get('subdomains', [])
        urls = self.recon_data.get('urls', [])

        config_section = self._create_config_section_html()
        subdomains_section = self._create_subdomains_section_html(subdomains)
        urls_section = self._create_urls_section_html(urls)
        js_section = self._create_js_section_html(self.js_data)

        cards_html = self._build_stat_cards_html(severity_counts, verification_breakdown)
        findings_cards = self._build_finding_cards_html(sorted_findings)

        sev_json = json.dumps(severity_counts)
        ver_json = json.dumps(verification_breakdown)

        # ── JSON-LD structured data for LLM parsing ─────────────────────
        jsonld_data = {
            "@context": "https://schema.org",
            "@type": "Report",
            "name": f"Bug Bounty Report - {self.target}",
            "target": self.target,
            "dateCreated": datetime.now().isoformat(),
            "severity_counts": severity_counts,
            "verification_breakdown": verification_breakdown,
            "historical_breakdown": self._get_historical_breakdown() if hasattr(self, '_get_historical_breakdown') else {},
            "findings": [
                {
                    "title": f.get("title", ""),
                    "vuln_type": f.get("vuln_type", f.get("type", "")),
                    "severity": f.get("severity", "info"),
                    "url": f.get("url", ""),
                    "parameter": f.get("parameter", ""),
                    "verification_stage": f.get("verification_stage", "detected"),
                    "confidence_score": f.get("confidence_score", 0),
                    "false_positive_risk": f.get("false_positive_risk", ""),
                    "confidence_reasons": f.get("confidence_reasons", []),
                    "cvss_score": self._get_cvss_score(f),
                    "historical_classification": (
                        f.get("historical", {}).get("classification", "")
                        if isinstance(f, dict)
                        else getattr(f, "historical", {}).get("classification", "")
                    ),
                }
                for f in sorted_findings
            ],
        }
        jsonld_html = json.dumps(jsonld_data, indent=2).replace("</script>", "<\\/script>")

        ai_summary_section = self._create_ai_summary_section_html(sorted_findings, severity_counts, verification_breakdown)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {self.target}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>{REPORT_CSS}</style>
    <script type="application/ld+json">
{jsonld_html}
    </script>
</head>
<body>
    <div class="container">
        <header>
            <h1>Bug Bounty Report</h1>
            <p class="timestamp">Target: <strong>{self.target}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        <div class="top-bar">
            <button class="theme-btn" onclick="toggleTheme()">Toggle Theme</button>
            <button class="theme-btn" id="copyAllAI">Copy All for AI</button>
        </div>
        <section class="summary">{cards_html}</section>
        <div class="chart-row">
            <div class="chart-box"><canvas id="sevChart"></canvas></div>
            <div class="chart-box"><canvas id="verChart"></canvas></div>
        </div>
        {config_section}
        {ai_summary_section}
        {self._render_root_cause_sections_html()}
        <section>
            <h2>Findings <span style="font-size:.6em;color:var(--text2)">({sum(severity_counts.values())})</span></h2>
            <div class="filters" id="filters">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="critical">Critical</button>
                <button class="filter-btn" data-filter="high">High</button>
                <button class="filter-btn" data-filter="medium">Medium</button>
                <button class="filter-btn" data-filter="low">Low</button>
                <button class="filter-btn" data-filter="info">Info</button>
                <button class="filter-btn" data-filter="exploitable">Exploitable</button>
                <button class="filter-btn" data-filter="validated">Validated</button>
                <button class="filter-btn" data-filter="partially_validated">Partial</button>
                <button class="filter-btn" data-filter="detected">Detected</button>
            </div>
            <div id="findingsContainer">{findings_cards if sorted_findings else '<div class="empty-message">No vulnerabilities found.</div>'}</div>
        </section>
        {subdomains_section}
        {urls_section}
        {js_section}
        <footer><p>Generated by BugBounty Hunter — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p></footer>
    </div>
    <script>
        var sevData = {sev_json};
        var verData = {ver_json};
        var sevCtx = document.getElementById('sevChart').getContext('2d');
        new Chart(sevCtx, {{type:'doughnut',data:{{labels:Object.keys(sevData).filter(k=>sevData[k]>0).map(k=>k.charAt(0).toUpperCase()+k.slice(1)),datasets:[{{data:Object.values(sevData).filter(v=>v>0),backgroundColor:['#e74c3c','#e67e22','#f1c40f','#3498db','#95a5a6'],borderWidth:0}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{position:'right',labels:{{color:'#999'}}}}}}}}}});
        var verCtx = document.getElementById('verChart').getContext('2d');
        new Chart(verCtx, {{type:'doughnut',data:{{labels:Object.keys(verData).filter(k=>verData[k]>0).map(k=>k.charAt(0).toUpperCase()+k.slice(1)),datasets:[{{data:Object.values(verData).filter(v=>v>0),backgroundColor:['#e74c3c','#f39c12','#3498db','#2ecc71','#9b59b6'],borderWidth:0}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{position:'right',labels:{{color:'#999'}}}}}}}}}});
        document.querySelectorAll('.filter-btn').forEach(btn=>{{btn.addEventListener('click',function(){{document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));this.classList.add('active');var filter=this.dataset.filter;document.querySelectorAll('.finding-card').forEach(card=>{{if(filter==='all'){{card.style.display='';return;}}var show=card.dataset.severity===filter||card.dataset.stage===filter;card.style.display=show?'':'none';}});}});}});
        document.querySelectorAll('.finding-header').forEach(hdr=>{{hdr.addEventListener('click',function(){{this.parentElement.classList.toggle('open');}});}});
        function toggleTheme(){{document.body.classList.toggle('light');}}
        function copyUrl(url){{navigator.clipboard.writeText(url).then(()=>{{var btn=event.target;var orig=btn.textContent;btn.textContent='Copied!';setTimeout(()=>btn.textContent=orig,1200);}});}}
        function copyCurl(cmd){{navigator.clipboard.writeText(cmd).then(()=>{{var btn=event.target;var orig=btn.textContent;btn.textContent='Copied!';setTimeout(()=>btn.textContent=orig,1200);}});}}
        document.getElementById('copyAllAI').addEventListener('click', function() {{
            var all = Array.from(document.querySelectorAll('.ai-copy-data'))
                .map(function(el) {{ return el.textContent; }})
                .join('\\n\\n' + '='.repeat(60) + '\\n\\n');
            navigator.clipboard.writeText(all).catch(function(){{}});
            var btn = this;
            btn.textContent = 'Copied!';
            setTimeout(function(){{ btn.textContent = 'Copy All for AI'; }}, 1500);
        }});
    </script>
</body>
</html>"""

    def _build_stat_cards_html(self, sev: Dict[str, int], ver: Dict[str, int]) -> str:
        cards = ""
        for cls, key, label in [("crit","critical","Critical"),("high","high","High"),("med","medium","Medium"),("low","low","Low"),("info","info","Info")]:
            cards += f'<div class="stat-card {cls}"><div class="val">{sev.get(key,0)}</div><div class="lbl">{label}</div></div>'
        cards += f'<div class="stat-card conf"><div class="val">{ver.get("exploitable",0)}</div><div class="lbl">Exploitable</div></div>'
        cards += f'<div class="stat-card valid"><div class="val">{ver.get("validated",0)}</div><div class="lbl">Validated</div></div>'
        cards += f'<div class="stat-card detect"><div class="val">{ver.get("detected",0)}</div><div class="lbl">Detected</div></div>'
        cards += f'<div class="stat-card valid" style="border-top-color:#9b59b6"><div class="val" style="color:#9b59b6">{ver.get("partially_validated",0)}</div><div class="lbl">Partial</div></div>'
        hist = self._get_historical_breakdown() if hasattr(self, '_get_historical_breakdown') else {}
        if any(v > 0 for v in hist.values()):
            for cls, color in [("previously_seen","#3498db"),("regressed","#e74c3c"),("improved","#2ecc71"),("degraded","#e67e22")]:
                val = hist.get(cls, 0)
                if val:
                    cards += f'<div class="stat-card" style="border-top-color:{color}"><div class="val" style="color:{color}">{val}</div><div class="lbl" style="color:{color}80">{cls.replace("_"," ").title()}</div></div>'
        return cards

    def _get_history_badge_html(self, f: Any) -> str:
        hist = f.get("historical", {}) if isinstance(f, dict) else getattr(f, "historical", {})
        if not hist or not isinstance(hist, dict):
            return ""
        cls = hist.get("classification", "")
        if not cls or cls == "new":
            return ""
        label = hist.get("label", cls.replace("_", " ").title())
        color_map = {
            "previously_seen": "#3498db",
            "regressed": "#e74c3c",
            "improved": "#2ecc71",
            "degraded": "#e67e22",
            "resolved": "#95a5a6",
        }
        color = color_map.get(cls, "#95a5a6")
        return f'<span class="hist-badge" style="background:{color}20;color:{color};border:1px solid {color}40;border-radius:3px;padding:1px 6px;font-size:.75em;margin-left:4px">{html.escape(label)}</span>'

    def _get_evidence_html(self, f: Any) -> str:
        """Render evidence from Finding (list) or legacy (string) format.
        
        Uses type-specific rendering for known evidence subclasses:
        - HttpRequestEvidence: collapsible request detail
        - BrowserExecutionEvidence: screenshot + execution context
        - ScreenshotEvidence: inline image
        - TimingEvidence: timing delta display
        - OOBCallbackEvidence: callback detail
        - AuthorizationComparisonEvidence: side-by-side comparison
        - GraphQLSchemaEvidence: schema preview
        """
        # Access f.evidence directly for Finding instances. For plain dicts,
        # fall back to f.get("evidence", [])
        evidence = (
            getattr(f, 'evidence', None)
            if not isinstance(f, dict)
            else f.get("evidence", "")
        )
        if evidence is None:
            evidence = ""
        if isinstance(evidence, list):
            parts = []
            for i, ev in enumerate(evidence):
                ev_type = ev.__class__.__name__ if hasattr(ev, '__class__') else ""
                desc = getattr(ev, 'description', f'Evidence #{i+1}') if hasattr(ev, 'description') else f'Evidence #{i+1}'
                e_desc = html.escape(desc)

                if ev_type == "HttpRequestEvidence":
                    curl = getattr(ev, 'curl_command', '') or getattr(ev, 'method', '') + ' ' + getattr(ev, 'url', '')
                    e_curl = html.escape(curl)
                    parts.append(
                        f'<details><summary>{e_desc}</summary>'
                        f'<div class="row"><strong>Reproduction Request:</strong></div>'
                        f'<pre class="evidence">{e_curl}</pre></details>'
                    )
                elif ev_type == "BrowserExecutionEvidence":
                    scr_path = getattr(ev, 'screenshot_path', '')
                    ctx = getattr(ev, 'execution_context', '')
                    alert = getattr(ev, 'alert_fired', False)
                    dom = getattr(ev, 'dom_mutation', False)
                    status = "✓ Executed" if alert or dom else "✗ Not executed"
                    e_ctx = html.escape(ctx)
                    scr_html = ""
                    if scr_path and ReporterBase._validate_screenshot_path(scr_path):
                        scr_html = f'<br><a href="{html.escape(scr_path)}" target="_blank"><img src="{html.escape(scr_path)}" alt="Browser screenshot" style="max-width:100%;max-height:300px;border:1px solid var(--border);border-radius:4px"></a>'
                    parts.append(
                        f'<details open><summary>{e_desc} — <strong>{status}</strong></summary>'
                        f'<div class="evidence">{e_ctx}{scr_html}</div></details>'
                    )
                elif ev_type == "ScreenshotEvidence":
                    scr_path = getattr(ev, 'file_path', '')
                    if scr_path and ReporterBase._validate_screenshot_path(scr_path):
                        parts.append(
                            f'<details open><summary>{e_desc}</summary>'
                            f'<a href="{html.escape(scr_path)}" target="_blank"><img src="{html.escape(scr_path)}" alt="Screenshot" style="max-width:100%;max-height:300px;border:1px solid var(--border);border-radius:4px"></a></details>'
                        )
                    else:
                        parts.append(f'<details><summary>{e_desc}</summary><div class="evidence">Screenshot data embedded</div></details>')
                elif ev_type == "TimingEvidence":
                    triggered = getattr(ev, 'triggered_time_ms', 0.0)
                    baseline = getattr(ev, 'baseline_time_ms', 0.0)
                    parts.append(
                        f'<details open><summary>{e_desc}</summary>'
                        f'<div class="evidence">Baseline: {baseline:.1f}ms | Actual: {triggered:.1f}ms | Diff: {triggered - baseline:.1f}ms</div></details>'
                    )
                elif ev_type == "OOBCallbackEvidence":
                    cb_type = getattr(ev, 'callback_type', 'unknown')
                    cb_host = getattr(ev, 'callback_host', '')
                    cb_token = getattr(ev, 'callback_token', '')
                    cb_time = getattr(ev, 'interaction_time', '')
                    cb_raw = getattr(ev, 'raw_data', '')
                    e_cb_raw = html.escape(str(cb_raw)[:500])
                    meta = f"Host: {cb_host} | Token: {cb_token}" if cb_host else ""
                    time_line = f" | Time: {cb_time}" if cb_time else ""
                    parts.append(
                        f'<details open><summary>{e_desc} ({cb_type})</summary>'
                        f'<div class="evidence"><code>{meta}{time_line}</code></div>'
                        f'<pre class="evidence">{e_cb_raw}</pre></details>'
                    )
                elif ev_type == "AuthorizationComparisonEvidence":
                    orig_user = getattr(ev, 'original_user', '')
                    tgt_user = getattr(ev, 'target_user', '')
                    orig_status = getattr(ev, 'original_status', 0)
                    tgt_status = getattr(ev, 'target_status', 0)
                    content_diff = getattr(ev, 'content_different', False)
                    violated = getattr(ev, 'ownership_violated', False)
                    orig_body = getattr(ev, 'original_body_excerpt', '')
                    tgt_body = getattr(ev, 'target_body_excerpt', '')
                    e_orig = html.escape(orig_body[:2000])
                    e_tgt = html.escape(tgt_body[:2000])
                    parts.append(
                        f'<details open><summary>{e_desc} {"✓ Violation" if violated else "No violation"}</summary>'
                        f'<div class="evidence">'
                        f'<p><strong>User:</strong> {html.escape(orig_user)} → HTTP {orig_status} | '
                        f'<strong>User:</strong> {html.escape(tgt_user)} → HTTP {tgt_status} | '
                        f'<strong>Content different:</strong> {content_diff}</p>'
                        f'<div style="display:flex;gap:1rem;flex-wrap:wrap;">'
                        f'<div style="flex:1;min-width:300px;">'
                        f'<h4 style="margin:0 0 0.25rem">Original ({html.escape(orig_user)})</h4>'
                        f'<pre style="background:#fdf6f6;border:1px solid #e0c0c0;border-radius:4px;padding:0.5rem;max-height:400px;overflow:auto;font-size:0.85rem;">{e_orig}</pre>'
                        f'</div>'
                        f'<div style="flex:1;min-width:300px;">'
                        f'<h4 style="margin:0 0 0.25rem">Target ({html.escape(tgt_user)})</h4>'
                        f'<pre style="background:#f6fdf6;border:1px solid #c0e0c0;border-radius:4px;padding:0.5rem;max-height:400px;overflow:auto;font-size:0.85rem;">{e_tgt}</pre>'
                        f'</div>'
                        f'</div>'
                        f'</div></details>'
                    )
                elif ev_type == "GraphQLSchemaEvidence":
                    schema = getattr(ev, 'schema_preview', '')
                    q_count = getattr(ev, 'query_count', 0)
                    m_count = getattr(ev, 'mutation_count', 0)
                    e_schema = html.escape(str(schema)[:1000])
                    parts.append(
                        f'<details><summary>{e_desc} ({q_count} queries, {m_count} mutations)</summary>'
                        f'<pre class="evidence">{e_schema}</pre></details>'
                    )
                elif ev_type == "OwnershipEvidence":
                    violated = getattr(ev, 'ownership_violated', False)
                    orig_owner = html.escape(getattr(ev, 'original_owner', ''))
                    claiming = html.escape(getattr(ev, 'claiming_identity', ''))
                    proof_type = html.escape(getattr(ev, 'proof_type', ''))
                    resource = html.escape(getattr(ev, 'resource_identifier', ''))
                    badge = '✓ Violation' if violated else 'No violation'
                    parts.append(
                        f'<details open><summary>{e_desc} — {badge}</summary>'
                        f'<div class="evidence">'
                        f'<p><strong>Original owner:</strong> {html.escape(orig_owner)}</p>'
                        f'<p><strong>Claiming identity:</strong> {html.escape(claiming)}</p>'
                        f'<p><strong>Proof type:</strong> {proof_type}</p>'
                        f'<p><strong>Resource:</strong> {resource}</p>'
                        f'</div></details>'
                    )
                elif ev_type == "ImpactEvidence":
                    impact_type = html.escape(getattr(ev, 'impact_type', ''))
                    demonstrated = getattr(ev, 'demonstrated', False)
                    severity_confirmed = getattr(ev, 'severity_confirmed', False)
                    business_impact = html.escape(getattr(ev, 'business_impact', ''))
                    exploit_proof = html.escape(getattr(ev, 'exploitation_proof', ''))
                    attack_scenario = html.escape(getattr(ev, 'attack_scenario', ''))
                    badge = 'Demonstrated' if demonstrated else 'Theoretical'
                    parts.append(
                        f'<details open><summary>{e_desc} — {badge}</summary>'
                        f'<div class="evidence">'
                        f'<p><strong>Impact type:</strong> {impact_type}</p>'
                        f'<p><strong>Severity confirmed:</strong> {severity_confirmed}</p>'
                        f'<p><strong>Business impact:</strong> {business_impact}</p>'
                        f'<p><strong>Attack scenario:</strong> {attack_scenario}</p>'
                        f'<p><strong>Exploitation proof:</strong> {exploit_proof}</p>'
                        f'</div></details>'
                    )
                else:
                    if hasattr(ev, 'to_dict'):
                        ev_text = json.dumps(ev.to_dict(), indent=2)
                    else:
                        ev_text = str(ev)
                    e_text = html.escape(ev_text)
                    parts.append(
                        f'<details><summary>{e_desc} ({len(ev_text)} chars)</summary>'
                        f'<div class="evidence">{e_text}</div></details>'
                    )
            if not parts:
                return ""
            return f'<div class="row"><strong>Evidence:</strong>{"".join(parts)}</div>'
        e_evidence = html.escape(evidence)
        return f'<div class="row"><strong>Evidence:</strong><details><summary>View evidence ({len(evidence)} chars)</summary><div class="evidence">{e_evidence}</div></details></div>'

    @staticmethod
    def _get_structured_impact_html(f: Any) -> str:
        ia = f.get("impact_assessment", {})
        if not ia:
            return ""
        parts = []
        if ia.get("data_exposure", {}).get("label"):
            parts.append(f'<span style="color:var(--text2);font-size:.85em">Data Exposure: {ia["data_exposure"]["label"]}</span>')
        if ia.get("account_takeover_potential", {}).get("label"):
            parts.append(f'<span style="color:var(--text2);font-size:.85em">ATO: {ia["account_takeover_potential"]["label"]}</span>')
        if ia.get("rce_potential", {}).get("label"):
            parts.append(f'<span style="color:var(--text2);font-size:.85em">RCE: {ia["rce_potential"]["label"]}</span>')
        if not parts:
            return ""
        return f'<div class="row"><strong>Structured Impact:</strong> {" | ".join(parts)}</div>'

    @staticmethod
    def _format_duplicate_risk_html(f: Any) -> str:
        dr = f.get("duplicate_risk", {}) if isinstance(f, dict) else getattr(f, "duplicate_risk", {})
        if not dr or not isinstance(dr, dict):
            return ""
        likelihood = dr.get("likelihood", "")
        labels = {"potentially_novel": "Potentially Novel", "moderate_risk": "Moderate Risk", "likely_duplicate": "Likely Duplicate"}
        label = labels.get(likelihood, likelihood.replace("_", " ").title())
        colors = {"potentially_novel": "#2ecc71", "moderate_risk": "#f39c12", "likely_duplicate": "#e74c3c"}
        color = colors.get(likelihood, "#95a5a6")
        return f'<div class="row"><strong>Duplicate Risk:</strong> <span style="color:{color};font-weight:600">{label}</span></div>'

    @staticmethod
    def _format_consensus_html(f: Any) -> str:
        cr = f.get("consensus_result", {}) if isinstance(f, dict) else getattr(f, "consensus_result", {})
        if not cr or not isinstance(cr, dict):
            return ""
        level = cr.get("consensus_level", "")
        score = cr.get("final_score", 0)
        if not level:
            return ""
        colors = {"strong": "#2ecc71", "moderate": "#f39c12", "weak": "#e74c3c", "none": "#95a5a6"}
        color = colors.get(level, "#95a5a6")
        return f'<div class="row"><strong>Consensus:</strong> <span style="color:{color};font-weight:600">{level}</span> ({score}/100)</div>'

    @staticmethod
    def _get_confidence_reasons_html(f: Any) -> str:
        reasons = f.get("confidence_reasons")
        if not reasons or not isinstance(reasons, list) or len(reasons) == 0:
            return ""
        items = "".join(
            f'<li style="color:{"green" if r.startswith("+") else "#cc5555"}">{html.escape(r)}</li>'
            for r in reasons
        )
        return f'<div class="row"><strong>Confidence Reasons:</strong><ul style="margin:2px 0;padding-left:20px">{items}</ul></div>'

    def _build_finding_cards_html(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return '<div class="empty-message">No vulnerabilities found.</div>'
        html_out = ""
        for f in findings:
            sev = f.get("severity", "info").lower()
            stage = f.get("verification_stage", "detected").lower()
            score = f.get("confidence_score", 0)
            details = f.get("details", "")
            vuln_url = f.get("url", "")
            fpr = f.get("false_positive_risk", "")
            cvss = f.get("cvss_score", "")
            steps = f.get("validation_steps", [])
            request = f.get("request", "")
            response_excerpt = f.get("response_excerpt", "")
            screenshot_path = f.get("screenshot_path", "")
            steps_to_reproduce = f.get("steps_to_reproduce", [])
            param = f.get("parameter", "")
            title = f.get("title", "Finding")

            sev_class = {"critical":"critical","high":"high","medium":"medium","low":"low","info":"info"}.get(sev,"info")
            conf_class = "high" if score >= 61 else ("mid" if score >= 31 else "low")
            stage_label = stage.replace("_", " ").title()

            e_details = html.escape(details)
            e_vuln_url = html.escape(vuln_url)
            e_request = html.escape(request)
            e_response = html.escape(response_excerpt)
            e_fpr = html.escape(str(fpr).title() if fpr else "—")
            e_title = html.escape(title)

            steps_html = ""
            if steps:
                items = "".join(f"<li>{html.escape(s)}</li>" for s in steps[:5])
                steps_html = f'<div class="row"><strong>Steps:</strong><ol class="steps">{items}</ol></div>'

            evidence_html = self._get_evidence_html(f)

            # Evidence bundle / readiness
            bundle_strength = f.get("evidence_bundle_strength", "")
            bundle_completeness = f.get("evidence_bundle_completeness", 0)
            sub_ready = f.get("submission_ready", False)
            bundle_html = ""
            if bundle_strength:
                strength_color = {"very_strong": "#2ecc71", "strong": "#27ae60", "medium": "#f39c12", "weak": "#e74c3c"}.get(bundle_strength, "#95a5a6")
                ready_badge = ""
                if sub_ready:
                    ready_badge = '<span style="background:#2ecc71;color:#fff;padding:2px 10px;border-radius:12px;font-size:.75em;font-weight:700;margin-left:8px">READY</span>'
                bundle_html = f'<div class="row"><strong>Evidence Bundle:</strong> <span style="color:{strength_color};font-weight:600">{bundle_strength.replace("_"," ").title()}</span> ({bundle_completeness:.0%} completeness){ready_badge}</div>'

            request_html = ""
            if request:
                request_html = f'<div class="row"><strong>Request:</strong><pre class="evidence">{e_request}</pre></div>'

            response_html = ""
            if response_excerpt:
                response_html = f'<div class="row"><strong>Response:</strong><details><summary>View response excerpt ({len(response_excerpt)} chars)</summary><pre class="evidence">{e_response}</pre></details></div>'

            screenshot_html = ""
            if screenshot_path and ReporterBase._validate_screenshot_path(screenshot_path):
                screenshot_html = f'<div class="row"><strong>Validation Screenshot:</strong><details open><summary>View Playwright screenshot</summary><a href="{html.escape(screenshot_path)}" target="_blank"><img src="{html.escape(screenshot_path)}" alt="XSS execution screenshot" style="max-width:100%;border:1px solid var(--border);border-radius:4px;cursor:zoom-in" /></a></details></div>'

            steps_to_reproduce_html = ""
            if steps_to_reproduce:
                items = "".join(f"<li>{html.escape(s)}</li>" for s in steps_to_reproduce[:10])
                steps_to_reproduce_html = f'<div class="row"><strong>Steps to Reproduce:</strong><ol class="steps">{items}</ol></div>'

            curl_cmd = self._build_curl_command(f)
            cvss_score = self._get_cvss_score(f)
            cvss_vector = self._get_cvss_vector(f)
            cvss_rating = self._severity_rating(cvss_score)
            cvss_html = f'<span>CVSS: {cvss_score:.1f} ({cvss_rating})</span>' if cvss_score > 0 else ""

            impact_narrative = self._build_impact_narrative(f)
            e_impact = html.escape(impact_narrative)

            remediation = self._build_remediation(f)
            e_remediation = html.escape(remediation)

            # ── Build "Copy for AI" plain-text block ────────────────
            ai_lines = []
            ai_lines.append(f"FINDING: {title}")
            ai_lines.append(f"Severity: {sev.upper()}")
            ai_lines.append(f"URL: {vuln_url}")
            ai_lines.append(f"Parameter: {param or 'N/A'}")
            ai_lines.append(f"Stage: {stage_label}")
            ai_lines.append(f"Confidence: {score:.0f}/100")
            hist = f.get("historical", {}) if isinstance(f, dict) else getattr(f, "historical", {})
            if hist and isinstance(hist, dict) and hist.get("classification", "") not in ("", "new"):
                ai_lines.append(f"Historical: {hist.get('label', hist.get('classification', ''))}")
            ai_lines.append(f"False Positive Risk: {fpr or 'N/A'}")
            ai_lines.append(f"CVSS: {cvss_score:.1f}")
            ai_lines.append("")
            ai_lines.append("Description:")
            ai_lines.append(details)
            ai_lines.append("")
            if steps_to_reproduce:
                ai_lines.append("Steps to Reproduce:")
                for i, s in enumerate(steps_to_reproduce[:10], 1):
                    ai_lines.append(f"{i}. {s}")
                ai_lines.append("")
            evidence_raw = f.get("evidence", "")
            ai_evidence = ""
            if isinstance(evidence_raw, list):
                ev_parts = []
                for ev in evidence_raw:
                    if hasattr(ev, 'to_dict'):
                        ev_parts.append(str(ev.to_dict()))
                    else:
                        ev_parts.append(str(ev))
                ai_evidence = "\n".join(ev_parts)
            else:
                ai_evidence = str(evidence_raw) if evidence_raw else ""
            ai_lines.append("Evidence:")
            ai_lines.append(ai_evidence or "N/A")
            ai_lines.append("")
            ai_lines.append("Request:")
            ai_lines.append(request or "N/A")
            ai_lines.append("")
            ai_lines.append("Response Excerpt:")
            ai_lines.append((response_excerpt or "N/A")[:1000])
            ai_lines.append("")
            ai_lines.append("Impact:")
            ai_lines.append(impact_narrative)
            ai_lines.append("")
            ai_lines.append("Remediation:")
            ai_lines.append(remediation)
            ai_text = "\n".join(ai_lines)
            e_ai_text = html.escape(ai_text)

            html_out += f'''<div class="finding-card {sev_class}" data-severity="{sev}" data-stage="{stage}">
                <div class="finding-header">
                    <div class="finding-title">{e_title}</div>
                    <div class="finding-meta">
                        <span class="sev-badge sev-{sev_class}">{sev.upper()}</span>
                        <span class="conf-badge conf-{conf_class}">{score:.0f}%</span>
                        <span class="stage-badge">{stage_label}</span>
                        {self._get_history_badge_html(f)}
                    </div>
                </div>
                <div class="finding-body">
                    <div class="row"><strong>URL:</strong> <span class="url">{e_vuln_url}</span> <button class="copy-btn" data-copy="{html.escape(vuln_url, quote=True)}">Copy URL</button> <button class="copy-btn copy-curl" data-copy="{html.escape(curl_cmd, quote=True)}">Copy Curl</button> <button class="copy-btn copy-ai">Copy for AI</button></div>
                    {steps_to_reproduce_html}
                    <div class="row"><strong>Details:</strong> {e_details}</div>
                    {evidence_html}
                    {bundle_html}
                    {request_html}
                    {response_html}
                    {screenshot_html}
                    {steps_html}
                    <div class="row"><strong>FP Risk:</strong> {e_fpr} | {cvss_html}</div>
                    {self._get_confidence_reasons_html(f)}
                    {self._format_duplicate_risk_html(f)}
                    {self._format_consensus_html(f)}
                    <div class="row"><strong>Impact:</strong> {e_impact}</div>
                    {self._get_structured_impact_html(f)}
                    <div class="row"><strong>Remediation:</strong> {e_remediation}</div>
                    <span class="ai-copy-data" style="display:none">{e_ai_text}</span>
                </div>
            </div>'''

        html_out += '''<script>
document.addEventListener('click', function(e) {
    var btn = e.target.closest('.copy-btn');
    if (btn) {
        if (btn.classList.contains('copy-ai')) {
            var card = btn.closest('.finding-card');
            var txt = card.querySelector('.ai-copy-data').textContent;
            navigator.clipboard.writeText(txt).catch(function(){});
        } else {
            navigator.clipboard.writeText(btn.getAttribute('data-copy')).catch(function(){});
        }
    }
});
</script>'''
        return html_out

    def _create_ai_summary_section_html(self, findings: List[Dict[str, Any]],
                                         sev_counts: Dict[str, int],
                                         ver_breakdown: Dict[str, int]) -> str:
        crit = sev_counts.get("critical", 0)
        high = sev_counts.get("high", 0)
        med = sev_counts.get("medium", 0)
        low = sev_counts.get("low", 0)
        info = sev_counts.get("info", 0)
        exploitable = ver_breakdown.get("exploitable", 0)
        validated = ver_breakdown.get("validated", 0)
        detected = ver_breakdown.get("detected", 0)

        top_lines = []
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev not in ("critical", "high"):
                if len(top_lines) >= 5:
                    break
                continue
            title = f.get("title", "Finding")
            url = f.get("url", "")
            score = f.get("confidence_score", 0)
            stage = f.get("verification_stage", "detected").replace("_", " ").title()
            top_lines.append(f"- [{sev.upper()}] {title} @ {url} (Confidence: {score:.0f}/100, Stage: {stage})")
            if len(top_lines) >= 5:
                break

        top_findings_text = "\n".join(top_lines) if top_lines else "  None"

        summary_text = (
            f"Target: {self.target}\n"
            f"Scan date: {self.timestamp}\n"
            f"Total findings: {len(findings)}\n"
            f"Critical: {crit} | High: {high} | Medium: {med} | Low: {low} | Info: {info}\n"
            f"Exploitable: {exploitable} | Validated: {validated} | Detected: {detected}\n\n"
            f"Top findings:\n{top_findings_text}\n\n"
            f"Please assess these findings, identify false positives, and draft\n"
            f"HackerOne submission text for the exploitable and validated findings."
        )
        e_summary = html.escape(summary_text)

        return f'''<section>
      <h2>AI Summary <button class="theme-btn" style="font-size:.75em"
          onclick="document.getElementById('ai-summary-text').select();
                   navigator.clipboard.writeText(
                     document.getElementById('ai-summary-text').value)
                   .catch(function(){{}});">
        Copy Summary
      </button></h2>
      <textarea id="ai-summary-text" readonly
                style="width:100%;height:160px;background:var(--bg);
                       color:var(--text);border:1px solid var(--border);
                       border-radius:4px;padding:10px;font-family:monospace;
                       font-size:.82em;resize:vertical">{e_summary}</textarea>
    </section>'''

    def _create_subdomains_section_html(self, subdomains: List[str]) -> str:
        if not subdomains:
            return ''
        content = '<section><h2>Discovered Subdomains</h2><ul>'
        for sub in subdomains:
            content += f'<li><span class="url">{html.escape(sub)}</span></li>'
        return content + '</ul></section>'

    def _create_urls_section_html(self, urls: List[str]) -> str:
        if not urls:
            return ''
        content = '<section><h2>Discovered URLs</h2><ul>'
        for url in urls:
            content += f'<li><span class="url">{html.escape(url)}</span></li>'
        return content + '</ul></section>'

    def _create_config_section_html(self) -> str:
        items = ''.join(f'<li>{item}</li>' for item in [
            f"Target: <strong>{self.target}</strong>",
            f"Format: <strong>{self.report_format.upper()}</strong>",
            f"Modules: <strong>{', '.join(self.config.get('modules', []))}</strong>",
            f"Threads: <strong>{self.config.get('threads')}</strong>",
            f"Timeout: <strong>{self.config.get('timeout')}s</strong>",
            f"Crawl Depth: <strong>{self.config.get('crawl_depth')}</strong>",
            f"Max URLs: <strong>{self.config.get('max_urls')}</strong>",
            f"Retries: <strong>{self.config.get('retries')}</strong>",
            f"Passive Mode: <strong>{self.config.get('passive')}</strong>",
        ])
        return f'<section><h2>Scan Configuration</h2><ul>{items}</ul></section>'

    def _create_js_section_html(self, js_data: dict) -> str:
        secrets = js_data.get("secrets", [])
        endpoints = js_data.get("endpoints", [])
        hidden = js_data.get("hidden_endpoints", [])
        env_vars = js_data.get("env_vars", [])
        if not any([secrets, endpoints, hidden, env_vars]):
            return ""
        html_out = '<section><h2>JavaScript Intelligence</h2>'
        if secrets:
            html_out += '<h3 style="font-size:1.1em;margin:12px 0 8px;color:var(--text)">Discovered Secrets</h3><table><thead><tr><th>Type</th><th>Value</th><th>Source File</th><th>Validated</th></tr></thead><tbody>'
            for s in secrets:
                if s.get("confidence") == "none":
                    continue
                raw = s.get("value", "")
                val = (html.escape(raw[:40]) + "...") if len(raw) > 40 else html.escape(raw)
                source = html.escape(s.get("source_url", "").split("/")[-1] or s.get("source_url",""))
                s_type = html.escape(s.get("type",""))
                validated = s.get("validated")
                if validated == True:
                    badge = '<span style="color:#2ecc71;font-weight:bold">✓ Confirmed</span>'
                    row_class = 'style="background:rgba(46,204,113,.08)"'
                else:
                    badge = '<span style="color:#f1c40f;font-weight:bold">? Unverified</span>'
                    row_class = 'style="background:rgba(241,196,15,.06)"'
                html_out += f'<tr {row_class}><td>{s_type}</td><td style="font-family:monospace;font-size:.85em">{val}</td><td>{source}</td><td>{badge}</td></tr>'
            html_out += '</tbody></table>'
        all_eps = list(endpoints) + list(hidden)
        if all_eps:
            html_out += '<h3 style="font-size:1.1em;margin:20px 0 8px;color:var(--text)">Discovered Endpoints</h3><table><thead><tr><th>Type</th><th>Endpoint</th><th>Source File</th></tr></thead><tbody>'
            for ep in all_eps[:100]:
                ep_url = html.escape(ep.get("url",""))
                ep_type = html.escape(ep.get("type",""))
                source = html.escape(ep.get("source_url","").split("/")[-1] or "")
                style = 'style="color:#e67e22;"' if ep in hidden else ""
                html_out += f'<tr><td>{ep_type}</td><td {style} style="font-family:monospace;font-size:.85em;word-break:break-all">{ep_url}</td><td>{source}</td></tr>'
            html_out += '</tbody></table>'
        if env_vars:
            html_out += '<h3 style="font-size:1.1em;margin:20px 0 8px;color:var(--text)">Environment Variable References</h3><div class="recon-grid">'
            for ev in env_vars:
                html_out += f'<span class="url" style="font-size:.82em">{html.escape(ev.get("variable",""))}</span>'
            html_out += '</div>'
        html_out += '</section>'
        return html_out

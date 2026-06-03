"""
Reporter — generates HTML, JSON, and TXT reports from findings.
"""

import json
import os
from datetime import datetime


SEVERITY_COLOR = {
    "critical": "#e74c3c",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#3498db",
    "info":     "#95a5a6",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Reporter:
    def __init__(self, config: dict, findings: list[dict], recon_data: dict):
        self.config    = config
        self.findings  = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
        self.recon     = recon_data
        self.target    = config["target"]
        self.timestamp = config.get("timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.out_dir   = config.get("output_dir", "reports")
        self.fmt       = config.get("report_format", "html")

    def generate(self) -> str:
        os.makedirs(self.out_dir, exist_ok=True)
        safe_target = self.target.replace("https://", "").replace("http://", "").replace("/", "_")
        base = f"{self.out_dir}/{safe_target}_{self.timestamp}"

        if self.fmt == "html":
            path = f"{base}.html"
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._html())
        elif self.fmt == "json":
            path = f"{base}.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._json_data(), f, indent=2)
        else:
            path = f"{base}.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._txt())
        return path

    # ── JSON ──────────────────────────────────────────────────────────────

    def _json_data(self) -> dict:
        return {
            "meta": {
                "target":    self.target,
                "timestamp": self.timestamp,
                "tool":      "BugBounty Hunter",
            },
            "summary": self._summary(),
            "recon":   self.recon,
            "findings": self.findings,
        }

    def _summary(self) -> dict:
        s = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(self.findings)}
        for f in self.findings:
            sev = f.get("severity", "info")
            s[sev] = s.get(sev, 0) + 1
        return s

    # ── TXT ───────────────────────────────────────────────────────────────

    def _txt(self) -> str:
        lines = [
            "=" * 60,
            "  BUGBOUNTY HUNTER REPORT",
            f"  Target    : {self.target}",
            f"  Timestamp : {self.timestamp}",
            f"  Findings  : {len(self.findings)}",
            "=" * 60, "",
        ]
        summary = self._summary()
        lines += [
            "SUMMARY",
            f"  Critical : {summary['critical']}",
            f"  High     : {summary['high']}",
            f"  Medium   : {summary['medium']}",
            f"  Low      : {summary['low']}",
            "",
            "FINDINGS",
            "-" * 60,
        ]
        for i, f in enumerate(self.findings, 1):
            lines += [
                f"{i}. [{f['severity'].upper()}] {f['type']}",
                f"   URL     : {f['url']}",
                f"   Details : {f['details']}",
                f"   Evidence: {f.get('evidence', '')}",
                "",
            ]
        lines += [
            "RECON",
            f"  URLs discovered  : {len(self.recon.get('urls', []))}",
            f"  Subdomains found : {len(self.recon.get('subdomains', []))}",
            f"  Forms found      : {len(self.recon.get('forms', []))}",
        ]
        return "\n".join(lines)

    # ── HTML ──────────────────────────────────────────────────────────────

    def _html(self) -> str:
        summary = self._summary()

        def badge(sev):
            color = SEVERITY_COLOR.get(sev, "#999")
            return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;text-transform:uppercase">{sev}</span>'

        rows = ""
        for f in self.findings:
            rows += f"""
            <tr>
              <td>{badge(f['severity'])}</td>
              <td><strong>{f['type']}</strong></td>
              <td style="word-break:break-all;font-size:12px">{f['url']}</td>
              <td>{f['details']}</td>
              <td style="font-family:monospace;font-size:11px">{f.get('evidence','')}</td>
            </tr>"""

        subdomain_list = "".join(f"<li>{s}</li>" for s in self.recon.get("subdomains", []))
        url_list = "".join(
            f'<li style="font-size:12px">{u}</li>'
            for u in sorted(self.recon.get("urls", []))[:200]
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BugBounty Hunter Report — {self.target}</title>
<style>
  * {{ box-sizing: border-box; margin:0; padding:0 }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }}
  header {{ background: linear-gradient(135deg,#161b22,#1f2937); padding: 32px 40px; border-bottom: 1px solid #30363d }}
  header h1 {{ font-size: 26px; color: #58a6ff; margin-bottom:6px }}
  header p {{ color: #8b949e; font-size: 14px }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 40px }}
  .cards {{ display: grid; grid-template-columns: repeat(5,1fr); gap: 16px; margin-bottom: 32px }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px; text-align:center }}
  .card .num {{ font-size:36px; font-weight:700 }}
  .card .lbl {{ font-size:12px; color:#8b949e; margin-top:4px; text-transform:uppercase }}
  .card.critical .num {{ color:#e74c3c }}
  .card.high .num {{ color:#e67e22 }}
  .card.medium .num {{ color:#f1c40f }}
  .card.low .num {{ color:#3498db }}
  .card.total .num {{ color:#58a6ff }}
  h2 {{ font-size:18px; color:#58a6ff; margin:32px 0 12px; border-bottom:1px solid #30363d; padding-bottom:8px }}
  table {{ width:100%; border-collapse:collapse; background:#161b22; border-radius:8px; overflow:hidden }}
  th {{ background:#21262d; padding:12px 16px; text-align:left; font-size:12px; color:#8b949e; text-transform:uppercase; letter-spacing:.05em }}
  td {{ padding:12px 16px; border-top:1px solid #21262d; vertical-align:top; font-size:13px }}
  tr:hover td {{ background:#1c2128 }}
  .recon-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:24px }}
  .recon-box {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:20px }}
  .recon-box h3 {{ color:#8b949e; font-size:13px; text-transform:uppercase; letter-spacing:.05em; margin-bottom:12px }}
  .recon-box ul {{ list-style:none; max-height:200px; overflow-y:auto }}
  .recon-box ul li {{ padding:4px 0; border-bottom:1px solid #21262d; font-size:12px; color:#8b949e }}
  footer {{ text-align:center; padding:24px; color:#484f58; font-size:12px; border-top:1px solid #21262d; margin-top:40px }}
</style>
</head>
<body>
<header>
  <h1>🐛 BugBounty Hunter Report</h1>
  <p>Target: <strong style="color:#58a6ff">{self.target}</strong> &nbsp;|&nbsp; Generated: {self.timestamp}</p>
</header>
<div class="container">
  <div class="cards">
    <div class="card critical"><div class="num">{summary['critical']}</div><div class="lbl">Critical</div></div>
    <div class="card high"><div class="num">{summary['high']}</div><div class="lbl">High</div></div>
    <div class="card medium"><div class="num">{summary['medium']}</div><div class="lbl">Medium</div></div>
    <div class="card low"><div class="num">{summary['low']}</div><div class="lbl">Low</div></div>
    <div class="card total"><div class="num">{summary['total']}</div><div class="lbl">Total</div></div>
  </div>

  <h2>Findings</h2>
  {"<p style='color:#8b949e'>No vulnerabilities detected.</p>" if not self.findings else f'''
  <table>
    <thead><tr>
      <th>Severity</th><th>Type</th><th>URL</th><th>Details</th><th>Evidence</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>'''}

  <h2>Reconnaissance</h2>
  <div class="recon-grid">
    <div class="recon-box">
      <h3>Subdomains ({len(self.recon.get('subdomains',[]))})</h3>
      <ul>{subdomain_list or '<li>None found</li>'}</ul>
    </div>
    <div class="recon-box">
      <h3>Discovered URLs ({len(self.recon.get('urls',[]))})</h3>
      <ul>{url_list or '<li>None</li>'}</ul>
    </div>
  </div>
</div>
<footer>BugBounty Hunter — use responsibly on targets you are authorised to test</footer>
</body>
</html>"""

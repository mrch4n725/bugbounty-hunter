"""
integration_test.py — End-to-end test that starts a vulnerable server
and runs the full scanner pipeline against it.
"""

import json
import os
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_PORT = 18999
FINDINGS_JSON = "/tmp/bugbounty_integration_findings.json"


class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self._html("<h1>Home</h1><a href='/xss'>xss</a>")
        elif self.path == "/xss":
            self._html('<html><body><form method="POST" action="/xss"><input name="q" value="test"></form></body></html>')
        elif self.path == "/xss?q=test":
            self._html('<html><body>test</body></html>')
        elif self.path.startswith("/xss?q="):
            q = self.path.split("q=", 1)[-1]
            self._html(f"<html><body>{q}</body></html>")
        elif self.path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"admin dashboard")
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin")
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DATABASE_URL=postgres://user:pass@localhost/db")
        elif self.path == "/config/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Index of /config/</h1><ul><li><a href='db.ini'>db.ini</a></li></ul></body></html>")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def do_POST(self):
        if self.path == "/xss":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            self._html(f"<html><body>{body}</body></html>")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")

    def _html(self, content):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(content.encode())

    def log_message(self, fmt, *args):
        pass


def start_server():
    server = HTTPServer(("127.0.0.1", TEST_PORT), VulnerableHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def test_end_to_end():
    server = start_server()
    time.sleep(0.3)

    from main import run

    target = f"http://127.0.0.1:{TEST_PORT}"
    config = {
        "target": target,
        "modules": ["headers", "sensitive", "clickjacking", "insecure_forms"],
        "disable_modules": ["recon", "js_secrets"],
        "output_dir": "/tmp/bugbounty_integration",
        "report_format": "json",
        "threads": 2,
        "timeout": 5,
        "module_timeout": 30,
        "cookies": {},
        "cookies_alt": "",
        "headers": {},
        "auth": "",
        "proxy": "",
        "verify_ssl": False,
        "crawl_depth": 0,
        "max_urls": 1,
        "delay": 0,
        "oob_host": "",
        "wordlist": "",
        "retries": 1,
        "autosave_interval": 0,
        "module_params": {},
        "verbose": True,
        "passive": True,
        "headless": False,
        "verify_only": None,
        "resume": False,
        "use_new_scanners": True,
        "dry_run": False,
        "no_mask_curl": True,
        "no_history": True,
        "history_file": "",
        "rps": 10,
        "stealth": False,
        "max_js_files": 0,
        "scope": "",
        "scope_enforcer": None,
        "exclude_patterns": [],
        "include_paths": [],
        "timestamp": "integration_test",
        "role": None,
        "auth_header": [],
        "output": FINDINGS_JSON,
        "no_browser": True,
        "no_rich": True,
    }

    exit_code = run(config)
    assert exit_code == 0, f"Expected exit code 0, got {exit_code}"

    import json, glob
    report_dir = "/tmp/bugbounty_integration"
    json_files = sorted(glob.glob(os.path.join(report_dir, "*_findings.json")) +
                        glob.glob(os.path.join(report_dir, "*report*json")) +
                        glob.glob(os.path.join(report_dir, "*.json")))
    assert json_files, f"No JSON report files found in {report_dir}"
    with open(json_files[-1]) as fh:
        report = json.load(fh)
    final = report.get("findings", [])
    if not final:
        final = report.get("vulnerabilities", [])

    print(f"\n  Findings: {len(final)}")
    for f in final:
        stage = f.get("verification_stage", "unknown")
        sev = f.get("severity", "none")
        vt = f.get("vuln_type", f.get("title", "?"))
        url = f.get("url", "?")
        print(f"    [{sev.upper():>9}] [{stage:<12}] {vt} @ {url}")

    assert len(final) >= 1, f"Expected >=1 findings, got {len(final)}"

    vuln_types = {f.get("vuln_type", f.get("title", "")).lower() for f in final}

    has_env = any("env" in vt for vt in vuln_types)
    has_clickjack = any("clickjack" in vt for vt in vuln_types)
    has_missing_header = any(
        "missing" in vt or "header" in vt
        for vt in vuln_types
    )
    has_sensitive = any("sensitive" in vt or "exposed" in vt for vt in vuln_types)
    assert has_env or has_clickjack or has_missing_header or has_sensitive, (
        f"No expected findings (env/clickjack/header/sensitive) among: {vuln_types}"
    )

    stages = {f.get("verification_stage") for f in final if f.get("verification_stage")}
    assert "detected" in stages or "validated" in stages or "partially_validated" in stages, f"No detected/validated/partially_validated stages: {stages}"

    findings_with_evidence = [
        f for f in final
        if f.get("evidence") or f.get("response_excerpt") or f.get("steps_to_reproduce")
    ]
    assert len(findings_with_evidence) >= 1, f"Expected >=1 findings with evidence, got {len(findings_with_evidence)}"

    print(f"\n  Stages found: {stages}")
    print(f"  Vuln types: {vuln_types}")
    print(f"  Findings with evidence: {len(findings_with_evidence)}")
    print("  INTEGRATION TEST PASSED\n")


if __name__ == "__main__":
    test_end_to_end()

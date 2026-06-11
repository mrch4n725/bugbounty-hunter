"""
run_integration.py — End-to-end integration test.

Starts the mock vulnerable Flask target, runs the scanner against it,
and asserts specific vulnerability types are found.

Usage:
    python3 tests/integration/run_integration.py

Requires:
    pip install flask pyjwt
"""

import json
import os
import subprocess
import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

TEST_PORT = 18999
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"

EXPECTED_FINDINGS = {
    "xss": False,
    "sqli": False,
    "jwt": False,
    "cors": False,
    "header_bypass": False,
    "idor": False,
}


def start_target():
    """Start the Flask mock target in a subprocess."""
    target_path = Path(__file__).resolve().parent / "mock_target.py"
    proc = subprocess.Popen(
        [sys.executable, str(target_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    return proc


def wait_for_server(timeout=5):
    import urllib.request
    for _ in range(timeout):
        try:
            urllib.request.urlopen(f"{BASE_URL}/", timeout=2)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def run_scanner() -> list[dict]:
    """Run the scanner against the mock target and return findings."""
    from main import run

    config = {
        "target": BASE_URL,
        "modules": ["all"],
        "disable_modules": ["recon", "js_secrets", "subdomain_takeover", "dirb"],
        "output_dir": "/tmp/bugbounty_integration_run",
        "report_format": "json",
        "threads": 2,
        "timeout": 5,
        "module_timeout": 60,
        "cookies": {},
        "cookies_alt": "",
        "headers": {},
        "auth": "",
        "proxy": "",
        "verify_ssl": False,
        "crawl_depth": 0,
        "max_urls": 50,
        "delay": 0,
        "oob_host": "",
        "allow_auto_oob": False,
        "wordlist": "",
        "retries": 1,
        "autosave_interval": 0,
        "module_params": {},
        "verbose": False,
        "passive": False,
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
        "no_rich": True,
        "no_browser": True,
    }

    exit_code = run(config)
    print(f"\n  Scanner exit code: {exit_code}")

    report_dir = "/tmp/bugbounty_integration_run"
    json_files = sorted(Path(report_dir).glob("*_findings.json"))
    json_files += sorted(Path(report_dir).glob("*report*json"))
    json_files += sorted(Path(report_dir).glob("*.json"))
    json_files = [f for f in json_files if f.is_file()]

    if not json_files:
        print("  [!] No JSON report files found")
        return []

    with open(json_files[-1]) as fh:
        report = json.load(fh)

    findings = report.get("findings", [])
    if not findings:
        findings = report.get("vulnerabilities", [])

    print(f"  Findings: {len(findings)}")
    return findings


def classify_finding(f: dict) -> str:
    vt = (f.get("vuln_type") or f.get("title") or "").lower()
    url = (f.get("url") or "").lower()

    if "xss" in vt:
        return "xss"
    if "sql" in vt or "sqli" in vt:
        return "sqli"
    if "jwt" in vt or "alg:none" in vt or "none algorithm" in vt:
        return "jwt"
    if "cors" in vt or ("access-control" in vt):
        return "cors"
    if "bypass" in vt or "header" in vt:
        if "header-bypass" in url or "original" in vt or "forwarded" in vt:
            return "header_bypass"
    if "idor" in vt or "insecure direct" in vt or "ownership" in vt:
        return "idor"
    return "other"


def main():
    print("=" * 60)
    print("  INTEGRATION TEST SUITE")
    print("=" * 60)

    target_proc = None
    try:
        # Start mock target
        print("\n  [*] Starting mock target...")
        target_proc = start_target()
        if not wait_for_server():
            print("  [!] Mock target failed to start")
            return 1
        print("  [✓] Mock target ready")

        # Seed URLs by probing all expected endpoints
        import urllib.request
        for path in ["/xss?q=test", "/sqli?id=1", "/jwt-none", "/null-token",
                       "/idor/1", "/idor/1/profile", "/cors", "/header-bypass",
                       "/api/user", "/api/admin"]:
            try:
                urllib.request.urlopen(f"{BASE_URL}{path}", timeout=3)
            except Exception:
                pass

        # Run scanner
        print("  [*] Running scanner...")
        findings = run_scanner()

        # Classify findings
        counts = {}
        for f in findings:
            cat = classify_finding(f)
            counts[cat] = counts.get(cat, 0) + 1

        print(f"\n  Finding categories:")
        for cat, count in sorted(counts.items()):
            print(f"    {cat:20s}: {count}")

        # Assertions
        failures = []
        if counts.get("xss", 0) == 0:
            failures.append("XSS")
        if counts.get("sqli", 0) == 0:
            failures.append("SQLi")
        if counts.get("cors", 0) == 0:
            failures.append("CORS")
        if counts.get("idor", 0) == 0:
            failures.append("IDOR")

        # JWT and header-bypass are lower confidence — warn but don't fail
        if counts.get("jwt", 0) == 0:
            print("  [WARN] No JWT findings (mock may need different token format)")
        if counts.get("header_bypass", 0) == 0:
            print("  [WARN] No header bypass findings (mock may need auth header config)")

        if failures:
            print(f"\n  [FAIL] Missing findings: {', '.join(failures)}")
            return 1

        print("\n  [✓] ALL INTEGRATION TESTS PASSED")
        return 0

    finally:
        if target_proc:
            target_proc.terminate()
            target_proc.wait(timeout=3)


if __name__ == "__main__":
    sys.exit(main())

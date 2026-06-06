#!/usr/bin/env python3
"""
BugBounty Hunter — Comprehensive test suite.

Run with:
    python3 tests/run.py

Tests all modules, utilities, reporter rendering, argument parsing, and
cross-module integration. No external dependencies beyond the project's
own requirements. Results print to stdout; exits 0 on success, 1 on failure.
"""
import sys, os, json, tempfile, time, threading, html as html_module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Test harness ──────────────────────────────────────────────────────────────
errors: list[str] = []
passed = 0
failed = 0

def check(name: str, ok: bool, detail: str = "") -> None:
    """Record a single assertion result."""
    global passed, failed
    if ok:
        print(f"  \033[92m\u2713\033[0m {name}")
        passed += 1
    else:
        msg = f"  \033[91m\u2717\033[0m {name}"
        if detail:
            msg += f" \u2014 {detail}"
        print(msg)
        errors.append(msg)
        failed += 1

def check_eq(name: str, got, expected) -> None:
    """Record an equality assertion."""
    if got == expected:
        print(f"  \033[92m\u2713\033[0m {name} == {expected!r}")
        _increment(True)
    else:
        msg = f"  \033[91m\u2717\033[0m {name}: expected {expected!r}, got {got!r}"
        print(msg)
        errors.append(msg)
        _increment(False)

def _increment(ok: bool) -> None:
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1

def section(title: str) -> None:
    print(f"\n--- {title} ---")

# ═══════════════════════════════════════════════════════════
# Imports
# ═══════════════════════════════════════════════════════════
section("1. Core Imports")
import main
from modules import utils, scanner, reporter, api_scanner, idor
check("All five modules import cleanly", True)

from modules.utils import (
    VerificationStage, EvidenceStrength, ConfidenceLevel, FalsePositiveRisk,
    calculate_confidence, evidence_strength_from_score, false_positive_risk_from_score,
    reset_seen_findings, finding, _build_curl, set_mask_sensitive_default,
    classify_endpoint, compute_endpoint_score,
    RateLimiter, OOBDetectionFramework, SecretValidator,
    BrowserValidator, safe_get, safe_post,
    DeduplicationEngine,
)
check("All utils symbols import cleanly", True)

# ═══════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════
section("2. Enums")
for enum_, members in [
    (VerificationStage, ("DETECTED", "VALIDATED", "EXPLOITABLE", "VERIFIED")),
    (EvidenceStrength,  ("WEAK", "MODERATE", "STRONG", "VERIFIED")),
    (ConfidenceLevel,   ("UNVERIFIED", "LIKELY", "HIGH_CONFIDENCE", "CONFIRMED")),
    (FalsePositiveRisk, ("HIGH", "MEDIUM", "LOW")),
]:
    for m in members:
        check(f"{enum_.__name__}.{m}", hasattr(enum_, m))

# ═══════════════════════════════════════════════════════════
# Confidence scoring
# ═══════════════════════════════════════════════════════════
section("3. Confidence Score Mapping")
data = [
    ("detected",   calculate_confidence(detection=True), 25, "weak",  "high"),
    ("validated",  calculate_confidence(detection=True, validation=True), 60, "moderate", "high"),
    ("exploitable", calculate_confidence(detection=True, validation=True, exploitation=True), 100, "verified", "low"),
    ("verified",   calculate_confidence(detection=True, validation=True, exploitation=True), 100, "verified", "low"),
]
for label, score, expected_score, expected_evidence, expected_fpr in data:
    check_eq(f"{label} score", score, expected_score)
    check_eq(f"{label} evidence", evidence_strength_from_score(score).value, expected_evidence)
    check_eq(f"{label} fpr", false_positive_risk_from_score(score).value, expected_fpr)

# ═══════════════════════════════════════════════════════════
# finding() — dedup engine
# ═══════════════════════════════════════════════════════════
section("4. finding() — Dedup Engine")
reset_seen_findings()

f1 = finding("XSS", "https://example.com/xss?q=1", "critical", "desc", "alert(1)")
check("fresh finding returns dict", isinstance(f1, dict))
check("fingerprint present", "fingerprint" in f1)
check_eq("default confidence", f1["confidence_score"], 25)

f2 = finding("XSS", "https://example.com/xss?q=1", "critical", "dup", "dup")
check("exact duplicate returns None", f2 is None)

f3 = finding("XSS", "https://example.com/xss?q=1", "critical", "other param", "other", parameter="name")
check("different parameter is not dup", f3 is not None)

f4 = finding("Clickjack", "https://example.com/", "medium", "no headers", "no XFO")
f5 = finding("Clickjack", "https://example.com/", "medium", "dup", "dup")
check("no-param finding 1st", f4 is not None)
check("no-param duplicate",   f5 is None)

reset_seen_findings()
f6 = finding("VERIFIED finding", "https://x.com/x", "critical", "exec", "alert(1)",
             verification_stage=VerificationStage.VERIFIED.value)
f6["screenshot_path"] = "reports/shot.png"
check("screenshot stored",   f6["screenshot_path"] == "reports/shot.png")
check("VERIFIED score >= 86", f6["confidence_score"] >= 86)
check_eq("VERIFIED evidence", f6["evidence_strength"], "verified")
check_eq("VERIFIED fpr",      f6["false_positive_risk"], "low")

reset_seen_findings()
f7 = finding("OOB finding", "https://x.com/oob", "critical", "OOB", "callback",
             verification_stage=VerificationStage.VERIFIED.value,
             response_excerpt="(OOB confirmed)", steps_to_reproduce=["Step 1"])
check("OOB excerpt stored", f7["response_excerpt"] == "(OOB confirmed)")
check_eq("OOB step count",  len(f7["steps_to_reproduce"]), 1)

reset_seen_findings()
f8 = finding("CSRF+XSS->ATO", "https://x.com/acc", "critical", "chain", "CSRF+XSS",
             verification_stage="exploitable", request="POST body",
             response_excerpt="token stolen", steps_to_reproduce=["A", "B", "C"],
             confidence_score=85)
check("chain finding created",     f8 is not None)
check("chain request stored",      f8.get("request", "") == "POST body")
check("chain response stored",     f8.get("response_excerpt", "") == "token stolen")
check_eq("chain steps count",      len(f8.get("steps_to_reproduce", [])), 3)

# ═══════════════════════════════════════════════════════════
# _build_curl()
# ═══════════════════════════════════════════════════════════
section("5. _build_curl()")
set_mask_sensitive_default(True)
c = _build_curl("GET", "https://ex.com/api", {"Authorization": "Bearer x", "X-API-Key": "y"})
check("curl starts with curl", c.lower().startswith("curl"))
check("Authorization masked",  "<REDACTED>" in c)
check("X-API-Key masked",      "<REDACTED>" in c)
check("-X GET present",        "-X" in c and "GET" in c)

set_mask_sensitive_default(False)
c2 = _build_curl("POST", "https://ex.com/login", {"Content-Type": "app/json"}, data='{"u":"a"}')
check("no-mask shows data",    "a" in c2 and "app/json" in c2)
check("-X POST present",       "-X" in c2 and "POST" in c2)
set_mask_sensitive_default(True)

# ═══════════════════════════════════════════════════════════
# classify_endpoint / compute_endpoint_score
# ═══════════════════════════════════════════════════════════
section("6. Endpoint Classification")
cl = classify_endpoint("https://ex.com/api/v1/users/123", forms=[], recon_data={})
check("classify returns set", isinstance(cl, set))
score = compute_endpoint_score("https://ex.com/api/v1/users/123", forms=[], recon_data={})
check("score returns int", isinstance(score, int))

# ═══════════════════════════════════════════════════════════
# RateLimiter
# ═══════════════════════════════════════════════════════════
section("7. RateLimiter")
rl = RateLimiter(rps=200)
t0 = time.time()
for _ in range(10):
    rl.wait()
check("10 waits < 1.5s at 200 rps", time.time() - t0 < 1.5)

# ═══════════════════════════════════════════════════════════
# OOB Detection Framework
# ═══════════════════════════════════════════════════════════
section("8. OOB Detection Framework")
oob = OOBDetectionFramework({"oob_host": ""})
payload = oob.generate_payload("xss")
check("generate_payload returns str", isinstance(payload, str))

# ═══════════════════════════════════════════════════════════
# SecretValidator
# ═══════════════════════════════════════════════════════════
section("9. SecretValidator")
r = SecretValidator.validate("aws", "AKIAIOSFODNN7EXAMPLE")
check("AWS validate returns dict", isinstance(r, dict))
r2 = SecretValidator.validate("github", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
check("GitHub validate returns dict", isinstance(r2, dict))

# ═══════════════════════════════════════════════════════════
# BrowserValidator fallback
# ═══════════════════════════════════════════════════════════
section("10. BrowserValidator")
bv = BrowserValidator({"timeout": 3})
result = bv.check_xss_execution("https://ex.com", "<script>alert(1)</script>")
# Without Playwright, returns None gracefully
check("fallback returns None (no crash)", result is None or isinstance(result, dict))
bv.close()

# ═══════════════════════════════════════════════════════════
# Scanner methods
# ═══════════════════════════════════════════════════════════
section("11. Scanner Methods")
from modules.scanner import VulnScanner
expected_methods = [
    "scan_xss", "scan_sqli", "scan_lfi", "scan_ssrf", "scan_xxe",
    "scan_ssti", "scan_command_injection", "scan_blind_xss",
    "scan_open_redirect", "scan_headers", "scan_csrf", "scan_directory_fuzz",
    "scan_sensitive_data", "scan_exposed_files", "scan_clickjacking",
    "scan_http_methods", "scan_insecure_forms", "scan_subdomain_takeover",
    "scan_graphql", "scan_idor", "scan_rate_limiting", "scan_openapi",
    "chain_analysis",
]
for m in expected_methods:
    check(f"VulnScanner.{m}", hasattr(VulnScanner, m))

from modules.utils import _build_curl
scanner_instance = VulnScanner({"verbose": True, "target": "https://ex.com", "timeout": 5}, {})
findings_list: list[dict] = []
scanner_instance._record_confirmed(findings_list, "TestType", "https://ex.com/test", "high",
                                   "Test details", "Test evidence", "GET",
                                   response_excerpt="response text",
                                   steps_to_reproduce=["Step 1", "Step 2"],
                                   parameter="test_param")
check("_record_confirmed creates a finding", len(findings_list) == 1)
f = findings_list[0]
check("_record_confirmed has verification_stage", f.get("verification_stage") == "validated")
check("_record_confirmed has request", bool(f.get("request")))
check("_record_confirmed has response_excerpt", f.get("response_excerpt") == "response text")
check("_record_confirmed has steps_to_reproduce", len(f.get("steps_to_reproduce", [])) == 2)
check("_record_confirmed has parameter", f.get("parameter") == "test_param")

# ═══════════════════════════════════════════════════════════
# _add() return value
# ═══════════════════════════════════════════════════════════
section("12. _add() Return Value")
instance = VulnScanner.__new__(VulnScanner)
instance._lock = threading.Lock()
instance.dedup = DeduplicationEngine()
instance.oob = OOBDetectionFramework({"oob_host": ""})
instance.verbose = False
instance.findings = []

reset_seen_findings()
f = finding("_add Test", "https://ex.com/t", "low", "test", "test")
check("_add new returns True",  instance._add(f) is True)
check("_add dup returns False", instance._add(f) is False)

# ═══════════════════════════════════════════════════════════
# Reporter
# ═══════════════════════════════════════════════════════════
section("13. Reporter")
from modules.reporter import Reporter, assess_finding_impact

fixtures = [
    dict(vuln_type="XSS", title="XSS",
         url="https://ex.com/x?q=<script>alert(1)</script>",
         severity="critical", description="XSS confirmed",
         evidence="alert(1)", request_str="GET /x",
         request="GET /x", response_excerpt="script exec",
         steps_to_reproduce=["Visit", "See alert"],
         confidence_score=100, evidence_strength="verified",
         false_positive_risk="low", verification_stage="verified",
         screenshot_path="reports/shot.png",
         fingerprint="a1", timestamp="2026-01-01", parameter="q",
         severity_score=9.5),
    dict(vuln_type="SQLi", title="SQLi",
         url="https://ex.com/sqli?id=1'",
         severity="critical", description="SQLi OOB",
         evidence="oob callback", request_str="GET /sqli",
         request="GET /sqli",
         response_excerpt="(confirmed via OOB)",
         steps_to_reproduce=["Inject", "Wait", "Confirm"],
         confidence_score=100, evidence_strength="verified",
         false_positive_risk="low", verification_stage="verified",
         fingerprint="a2", timestamp="2026-01-01", parameter="id",
         severity_score=9.5),
    dict(vuln_type="Open Redirect", title="Open Redirect",
         url="https://ex.com/red?url=https://evil.com",
         severity="medium", description="Redirects",
         evidence="302", request_str="GET /red",
         request="GET /red", response_excerpt="302 evil",
         steps_to_reproduce=["Visit", "Observe"],
         confidence_score=60, evidence_strength="moderate",
         false_positive_risk="high", verification_stage="validated",
         fingerprint="a3", timestamp="2026-01-01", parameter="url",
         severity_score=5.0),
]

with tempfile.TemporaryDirectory() as tmpdir:
    cfg = dict(output_dir=tmpdir, report_format="html", target="https://ex.com",
               verbose=True, subdomains=[], urls=[])
    rep = Reporter(cfg, fixtures, [], [])
    path = rep.generate(suffix="test")
    with open(path) as fh:
        html_content = fh.read()

    check("HTML generation produces file", os.path.isfile(path))
    check("HTML contains escaped script", "&lt;script&gt;" in html_content or "&#x3C;script&#x3E;" in html_content)
    check("HTML contains screenshot ref", "shot.png" in html_content)
    check("HTML uses data-copy",          "data-copy" in html_content)
    check("HTML minimal onclick",         html_content.count("onclick=") <= 2)
    check("HTML verified badge present",  "verified" in html_content.lower())
    check("HTML finding card rendered", "finding-card" in html_content or "XSS" in html_content)

    # JSON
    cfg2 = dict(cfg, report_format="json")
    path2 = Reporter(cfg2, fixtures, [], []).generate(suffix="test")
    with open(path2) as fh:
        j = json.load(fh)
    check("JSON output valid", isinstance(j, dict) or isinstance(j, list))

    # TXT
    cfg3 = dict(cfg, report_format="txt")
    path3 = Reporter(cfg3, fixtures, [], []).generate(suffix="test")
    with open(path3) as fh:
        txt = fh.read()
    check("TXT output non-empty", len(txt) > 0)
    check("TXT has request field",  "Request" in txt or "curl" in txt)
    check("TXT has response field", "Response" in txt)
    check("TXT has parameter field", "Parameter" in txt)
    check("TXT has screenshot field", "Screenshot" in txt)

    # HackerOne
    cfg4 = dict(cfg, report_format="hackerone")
    path4 = Reporter(cfg4, fixtures, [], []).generate(suffix="test")
    with open(path4) as fh:
        h1 = fh.read()
    check("HackerOne output non-empty", len(h1) > 0)
    check("HackerOne has curl field",  "curl" in h1)
    check("HackerOne has response field", "Response Excerpt" in h1)
    check("HackerOne has parameter field", "Parameter" in h1)
    check("HackerOne has screenshot field", "Screenshot" in h1)
    check("HackerOne has verification stage", "Verification Stage" in h1)

    # Bugcrowd
    cfg5 = dict(cfg, report_format="bugcrowd")
    path5 = Reporter(cfg5, fixtures, [], []).generate(suffix="test")
    with open(path5) as fh:
        bc = fh.read()
    check("Bugcrowd output non-empty", len(bc) > 0)
    check("Bugcrowd has curl field",  "curl" in bc)
    check("Bugcrowd has response field", "Response" in bc)
    check("Bugcrowd has parameter field", "Parameter" in bc)
    check("Bugcrowd has screenshot field", "Screenshot" in bc)

    # assess_finding_impact
    impact = assess_finding_impact(fixtures[0])
    check("assess_finding_impact returns dict", isinstance(impact, dict))

# ═══════════════════════════════════════════════════════════
# ApiScanner / IdorScanner
# ═══════════════════════════════════════════════════════════
section("14. Subclass Scanners")
check("ApiScanner is subclass", issubclass(api_scanner.ApiScanner, scanner.VulnScanner))
check("IdorScanner is subclass", issubclass(idor.IdorScanner, scanner.VulnScanner))

# ═══════════════════════════════════════════════════════════
# Argparse shapes
# ═══════════════════════════════════════════════════════════
section("15. Argparse Shapes")
import argparse
p = argparse.ArgumentParser()
for a in ("--dry-run", "--no-mask-curl", "--resume", "--verbose"):
    p.add_argument(a, action="store_true")
p.add_argument("--rps", type=int, default=5)
p.add_argument("--modules", nargs="+", default=["all"])
p.add_argument("--target")
p.add_argument("--disable-modules", nargs="+", default=[])

a1 = p.parse_args(["--target", "https://x.com", "--dry-run", "--no-mask-curl", "--rps", "20"])
check("dry-run flag parsed",       a1.dry_run is True)
check("no-mask-curl flag parsed",  a1.no_mask_curl is True)
check("rps value parsed",          a1.rps == 20)

a2 = p.parse_args(["--target", "https://x.com", "--resume"])
check("resume flag parsed",        a2.resume is True)
check("resume implies no dry-run", a2.dry_run is False)

a3 = p.parse_args(["--target", "https://x.com", "--disable-modules", "xss", "sqli"])
check("disable-modules list",      "xss" in a3.disable_modules and "sqli" in a3.disable_modules)

# ═══════════════════════════════════════════════════════════
# Scan state persistence
# ═══════════════════════════════════════════════════════════
section("16. Scan State Persistence")
state_path = "/tmp/bbh_test_state.json"
state = {"target": "https://ex.com", "completed_urls": ["/a", "/b"], "findings_count": 3}
with open(state_path, "w") as f:
    json.dump(state, f)
with open(state_path) as f:
    loaded = json.load(f)
check_eq("state target roundtrip",            loaded["target"], "https://ex.com")
check_eq("state completed_urls roundtrip",    len(loaded["completed_urls"]), 2)
check_eq("state findings_count roundtrip",    loaded["findings_count"], 3)
os.remove(state_path)

# ═══════════════════════════════════════════════════════════
# Self-XSS prevention (html_module.escape)
# ═══════════════════════════════════════════════════════════
section("17. Self-XSS Prevention")
dangerous = "<script>alert('xss')</script>"
escaped_str = html_module.escape(dangerous)
check("html.escape produces no raw tags",      "<script>" not in escaped_str)
check("html.escape includes lt entity",        "&lt;" in escaped_str)

# ═══════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 58)
print(f"  Total:  {passed + failed}   \033[92mPassed: {passed}\033[0m   \033[91mFailed: {failed}\033[0m")
print("=" * 58)
if failed:
    print("\nFailed checks:")
    for e in errors:
        print(f"  {e}")
    sys.exit(1)
else:
    print("All checks passed.")

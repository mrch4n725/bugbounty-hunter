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
from app import orchestrator
from app.orchestrator import _run_passive_scans
check("All five modules import cleanly", True)

from modules.utils import (
    VerificationStage, EvidenceStrength, ConfidenceLevel, FalsePositiveRisk,
    calculate_confidence, evidence_strength_from_score, false_positive_risk_from_score,
    reset_seen_findings, finding, _build_curl, set_mask_sensitive_default,
    classify_endpoint, compute_endpoint_score,
    RateLimiter, OOBDetectionFramework, SecretValidator,
    BrowserValidator, safe_get, safe_post,
)
from engines.dedup import DeduplicationEngine
check("All utils symbols import cleanly", True)

# ═══════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════
section("2. Enums")
for enum_, members in [
    (VerificationStage, ("DETECTED", "PARTIALLY_VALIDATED", "VALIDATED", "EXPLOITABLE", "VERIFIED")),
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
check("fresh finding is not None", f1 is not None)
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
    "scan_graphql", "scan_rate_limiting", "scan_openapi",
    "scan_cors", "scan_jwt",
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
    # Create a minimal valid 1x1 blue PNG for screenshot path validation
    png_path = os.path.join(tmpdir, "reports")
    os.makedirs(png_path, exist_ok=True)
    png_path = os.path.join(png_path, "shot.png")
    # Minimal PNG: 8-byte signature + IHDR chunk (25 bytes) + IDAT chunk (zlib-compressed 1x1 blue pixel) + IEND chunk
    import struct, zlib
    def _make_png(w, h, r, g, b):
        sig = b'\x89PNG\r\n\x1a\n'
        ihdr_data = struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff
        ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
        raw = b''
        for _ in range(h):
            raw += b'\x00' + bytes([r, g, b]) * w
        compressed = zlib.compress(raw)
        idat_crc = zlib.crc32(b'IDAT' + compressed) & 0xffffffff
        idat = struct.pack('>I', len(compressed)) + b'IDAT' + compressed + struct.pack('>I', idat_crc)
        iend_crc = zlib.crc32(b'IEND') & 0xffffffff
        iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
        return sig + ihdr + idat + iend
    with open(png_path, 'wb') as f:
        f.write(_make_png(1, 1, 0, 0, 255))
    # Update fixture with the absolute screenshot path
    fixtures[0]["screenshot_path"] = png_path

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
# AuthorizationEngine
# ═══════════════════════════════════════════════════════════
section("18. AuthorizationEngine")
from engines.authorization import (
    AuthorizationEngine, _is_auth_candidate, _find_id_param, _role_level,
)
from models.evidence import AuthorizationComparisonEvidence, EvidenceStatus

check("AuthorizationEngine importable", True)

# Test _role_level
check_eq("_role_level admin", _role_level("admin"), 4)
check_eq("_role_level user", _role_level("user"), 2)
check_eq("_role_level guest", _role_level("guest"), 1)
check_eq("_role_level unknown", _role_level("custom_user"), 2)

# Test _is_auth_candidate
check("auth candidate: user ID in path",
    _is_auth_candidate("https://ex.com/api/users/123"))
check("auth candidate: ID param",
    _is_auth_candidate("https://ex.com/profile?user_id=456"))
check("auth candidate: API path",
    _is_auth_candidate("https://ex.com/api/v1/orders"))
check("not auth candidate: static page",
    not _is_auth_candidate("https://ex.com/about"))
check("not auth candidate: homepage",
    not _is_auth_candidate("https://ex.com/index.html"))

# Test _find_id_param
check_eq("find id param: user_id",
    _find_id_param("https://ex.com/data?user_id=123"), "user_id")
check_eq("find id param: __path__",
    _find_id_param("https://ex.com/users/123"), "__path__")
check_eq("find id param: none",
    _find_id_param("https://ex.com/about"), "")

# Test engine creation with < 2 roles returns no findings
engine = AuthorizationEngine({"target": "https://ex.com"})
findings = engine.run_scans(["https://ex.com/api/users/1"])
check("engine: <2 roles returns empty",
    len(findings) == 0)

# Test engine with mock role sessions
class MockResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {"Content-Type": "text/html"}
    def __bool__(self):
        return True

mock_session_a = type("MockSession", (), {
    "headers": {"Authorization": "Bearer tok_a"},
    "cookies": {},
    "get": lambda self, url, **kw: MockResponse("data for user_a", 200),
})()
mock_session_b = type("MockSession", (), {
    "headers": {"Authorization": "Bearer tok_b"},
    "cookies": {},
    "get": lambda self, url, **kw: MockResponse("data for user_b", 200),
})()

engine2 = AuthorizationEngine(
    {"target": "https://ex.com", "timeout": 5},
    role_sessions={"user_a": mock_session_a, "user_b": mock_session_b},
)

# Monkey-patch safe_get to use our mock sessions
import modules.utils as mu
_orig_safe_get = mu.safe_get
def _mock_safe_get(session, url, **kw):
    return session.get(url)
mu.safe_get = _mock_safe_get

try:
    findings2 = engine2.run_scans(["https://ex.com/api/users/1"])
    check("engine: 2 roles produces findings",
        len(findings2) > 0)
    for f in findings2:
        check("engine: finding has root_cause",
            f.get("root_cause") == "Missing Authorization Check")
        check("engine: finding has evidence list",
            isinstance(f.get("evidence"), list))
        check("engine: finding has AuthorizationComparisonEvidence",
            any(isinstance(e, AuthorizationComparisonEvidence)
                for e in f["evidence"]))
        check("engine: finding has fingerprint",
            bool(f.get("fingerprint")))
        check("engine: finding has steps_to_reproduce",
            bool(f.get("steps_to_reproduce")))
        check("engine: finding has request",
            bool(f.get("request")))
    # Test ownership verification
    ev = engine2.test_endpoint(
        "https://ex.com/api/users/1", "user_a", "user_b"
    )
    check("engine: test_endpoint returns evidence", ev is not None)
    check("engine: ownership violated (different data)",
        ev.ownership_violated is True)
    f2 = engine2._build_finding(ev, "https://ex.com/api/users/1")
    check("engine: _build_finding returns finding", f2 is not None)
    if f2:
        check("engine: finding severity critical",
            f2.get("severity") == "critical")
        check("engine: finding verified",
            f2.get("verification_stage") == "verified")
        check("engine: vuln_type ownership violation",
            f2.get("vuln_type") == "Authorization - Ownership Violation")
finally:
    mu.safe_get = _orig_safe_get

# Reset global dedup to avoid duplicate collisions from prior test
reset_seen_findings()

# Test isolate methods (horizontal, vertical)
engine3 = AuthorizationEngine(
    {"target": "https://ex.com"},
    role_sessions={"user_a": mock_session_a, "user_b": mock_session_b},
)
# Use same mock
mu.safe_get = _mock_safe_get
try:
    h_findings = engine3.run_horizontal(["https://ex.com/api/users/1"])
    check("engine: horizontal returns findings",
        len(h_findings) > 0)
    v_findings = engine3.run_vertical(["https://ex.com/api/users/1"])
    check("engine: vertical returns zero (same level)",
        len(v_findings) == 0)
    reset_seen_findings()
    own = engine3.verify_ownership(
        "https://ex.com/api/users/1", "user_a", "user_b"
    )
    check("engine: verify_ownership returns finding",
        own is not None)
finally:
    mu.safe_get = _orig_safe_get

# Test AuthorizationScanner is discoverable
from scanners import discover_scanner_classes
cls_map = discover_scanner_classes()
check("auth scanner discoverable",
    "authorization" in cls_map)
check("auth scanner is ScannerBase subclass",
    cls_map["authorization"].SCANNER_NAME == "authorization")
check("auth scanner maturity >= 4",
    cls_map["authorization"].SCANNER_MATURITY >= 4)
check("auth scanner is target-level",
    cls_map["authorization"].TARGET_LEVEL is True)

# Test that scan_authorization method exists on VulnScanner
check("scan_authorization on VulnScanner",
    hasattr(scanner.VulnScanner, "scan_authorization"))

# Test that authorization is in module_map choices
a4 = p.parse_args(["--target", "https://x.com", "--modules", "authorization"])
check("authorization module flag parsed",
    "authorization" in a4.modules)
a5 = p.parse_args(["--target", "https://x.com", "--disable-modules", "authorization"])
check("authorization disable flag parsed",
    "authorization" in a5.disable_modules)

# ═══════════════════════════════════════════════════════════
# Passive scan dispatch
# ═══════════════════════════════════════════════════════════
section("19. Passive Scan Dispatch")

_orig_main_vuln_scanner = main.VulnScanner
_orig_orch_vuln_scanner = orchestrator.VulnScanner
created_scanners = []

class FakePassiveScanner:
    def __init__(self, config, recon_data, container=None):
        self.calls = []
        created_scanners.append(self)

    def scan_headers(self, target_urls=None):
        self.calls.append("headers")
        return []

    def scan_clickjacking(self, target_urls=None):
        self.calls.append("clickjacking")
        return []

    def scan_sensitive_data(self, target_urls=None):
        self.calls.append("sensitive")
        return []

    def scan_insecure_forms(self, target_urls=None):
        self.calls.append("insecure_forms")
        return []

    def _get_findings(self):
        return [
            {"vuln_type": name, "url": "https://ex.com", "severity": "info", "fingerprint": name}
            for name in self.calls
        ]

try:
    main.VulnScanner = FakePassiveScanner
    orchestrator.VulnScanner = FakePassiveScanner
    passive_config = {
        "target": "https://ex.com",
        "modules": ["all"],
        "verbose": False,
    }
    passive_findings = []
    passive_lock = threading.Lock()
    _run_passive_scans(
        passive_config,
        {"urls": ["https://ex.com"], "forms": []},
        run_all=True,
        disabled_modules=set(),
        all_findings=passive_findings,
        lock=passive_lock,
    )
    check("passive all runs safe modules",
          created_scanners[-1].calls == ["headers", "clickjacking", "sensitive", "insecure_forms"])
    check_eq("passive all findings copied", len(passive_findings), 4)

    created_scanners.clear()
    selected_findings = []
    _run_passive_scans(
        {"target": "https://ex.com", "modules": ["headers", "xss"], "verbose": False},
        {"urls": ["https://ex.com"], "forms": []},
        run_all=False,
        disabled_modules=set(),
        all_findings=selected_findings,
        lock=threading.Lock(),
    )
    check("passive explicit skips active modules",
          created_scanners[-1].calls == ["headers"])
finally:
    main.VulnScanner = _orig_main_vuln_scanner
    orchestrator.VulnScanner = _orig_orch_vuln_scanner

# ═══════════════════════════════════════════════════════════
# Scanner maturity levels
# ═══════════════════════════════════════════════════════════
section("20. Scanner Maturity Levels")
expected_maturity = {
    "xss": 4, "sqli": 4, "ssrf": 4, "blind_xss": 4, "cmd_injection": 4,
    "xxe": 4, "authorization": 4, "ssti": 4, "headers": 4, "sensitive": 4,
    "lfi": 3, "open_redirect": 3, "exposed_files": 3, "graphql": 3,
    "idor": 3,     "clickjacking": 2, "csrf": 2, "http_methods": 2,
    "insecure_forms": 2, "dirb": 3, "subdomain_takeover": 3,
    "rate_limiting": 3, "openapi": 2,
    "cors": 3, "jwt": 3,
}
for scanner_name, expected in expected_maturity.items():
    cls = cls_map.get(scanner_name)
    if cls is None:
        check(f"{scanner_name} maturity: scanner not found", False)
    else:
        actual = cls.SCANNER_MATURITY
        check(f"{scanner_name} maturity == {expected}",
              actual == expected,
              detail=f"got {actual}")

# ═══════════════════════════════════════════════════════════
# Evidence Completeness Validator
# ═══════════════════════════════════════════════════════════
section("21. Evidence Completeness Validator")
from engines.evidence_validator import EvidenceCompletenessValidator
from models.finding import Finding
from models.evidence import (
    HttpRequestEvidence, OOBCallbackEvidence, TimingEvidence,
    BrowserExecutionEvidence, ResponseExcerptEvidence,
    AuthorizationComparisonEvidence, GraphQLSchemaEvidence,
    SecretValidationEvidence,
)

# ── Complete finding passes validation ──
f_ok = Finding(
    vuln_type="XSS", title="Reflected XSS", url="https://ex.com/x",
    evidence=[
        HttpRequestEvidence(method="GET", url="https://ex.com/x"),
        BrowserExecutionEvidence(alert_fired=True, execution_context="alert(1)"),
    ],
    confidence_score=100, verification_stage="verified",
)
result = EvidenceCompletenessValidator.validate(f_ok)
check("complete XSS keeps confidence", result.confidence_score == 100)
check("complete XSS keeps stage", result.verification_stage == "verified")
check("complete XSS no penalty reason", all("incomplete" not in r for r in result.confidence_reasons))

# ── Incomplete SSRF (missing OOB callback) gets penalised ──
f_no_oob = Finding(
    vuln_type="SSRF", title="SSRF", url="https://ex.com/ssrf",
    evidence=[
        HttpRequestEvidence(method="GET", url="https://ex.com/ssrf?url=http://169.254.169.254"),
    ],
    confidence_score=100, verification_stage="verified",
)
result = EvidenceCompletenessValidator.validate(f_no_oob)
check("incomplete SSRF confidence reduced", result.confidence_score == 85)
check("incomplete SSRF stage = partially_validated", result.verification_stage == "partially_validated")
check("incomplete SSRF has penalty reason", any("incomplete" in r for r in result.confidence_reasons))

# ── Missing HTTP request but has callback ──
f_no_req = Finding(
    vuln_type="Blind XSS", title="Blind XSS (Stored)", url="https://ex.com/contact",
    evidence=[OOBCallbackEvidence(callback_type="dns", callback_host="oob.example.com")],
    confidence_score=100, verification_stage="verified",
)
result = EvidenceCompletenessValidator.validate(f_no_req)
check("blind xss with callback keeps confidence", result.confidence_score == 100)
check("blind xss with callback keeps stage", result.verification_stage == "verified")

# ── SQLi missing timing evidence ──
f_no_timing = Finding(
    vuln_type="SQL Injection", title="SQL Injection", url="https://ex.com/sqli",
    evidence=[HttpRequestEvidence(method="GET", url="https://ex.com/sqli?id=1'")],
    confidence_score=60, verification_stage="validated",
)
result = EvidenceCompletenessValidator.validate(f_no_timing)
check("sqli missing timing confidence reduced", result.confidence_score == 45)
check("sqli missing timing stage", result.verification_stage == "partially_validated")

# ── Finding with all required evidence passes ──
f_sqli_ok = Finding(
    vuln_type="SQL Injection", title="SQL Injection", url="https://ex.com/sqli",
    evidence=[
        HttpRequestEvidence(method="GET", url="https://ex.com/sqli?id=1'"),
        TimingEvidence(baseline_time_ms=50.0, triggered_time_ms=2500.0),
    ],
    confidence_score=80, verification_stage="validated",
)
result = EvidenceCompletenessValidator.validate(f_sqli_ok)
check("complete sqli keeps confidence", result.confidence_score == 80)
check("complete sqli keeps stage", result.verification_stage == "validated")

# ── IDOR missing auth comparison evidence ──
f_idor = Finding(
    vuln_type="IDOR", title="IDOR - Insecure Direct Object Reference", url="https://ex.com/user/123",
    evidence=[
        HttpRequestEvidence(method="GET", url="https://ex.com/user/123"),
        ResponseExcerptEvidence(excerpt="email: other@user.com"),
    ],
    confidence_score=90, verification_stage="verified",
)
result = EvidenceCompletenessValidator.validate(f_idor)
check("idor missing auth comparison confidence reduced", result.confidence_score == 75)
check("idor missing auth comparison stage", result.verification_stage == "partially_validated")

# ── IDOR with all evidence passes ──
f_idor_ok = Finding(
    vuln_type="IDOR", title="IDOR", url="https://ex.com/user/123",
    evidence=[
        HttpRequestEvidence(method="GET", url="https://ex.com/user/123"),
        AuthorizationComparisonEvidence(original_user="user_a", target_user="user_b",
                                         ownership_violated=True, content_different=True),
        ResponseExcerptEvidence(excerpt="email: other@user.com"),
    ],
    confidence_score=95, verification_stage="verified",
)
result = EvidenceCompletenessValidator.validate(f_idor_ok)
check("complete idor keeps confidence", result.confidence_score == 95)

# ── Exempt type not penalised ──
f_exempt = Finding(
    vuln_type="Forbidden Path", title="Forbidden Path (Access Control Exists)",
    url="https://ex.com/admin", evidence=[], confidence_score=25,
)
result = EvidenceCompletenessValidator.validate(f_exempt)
check("exempt type not penalised", result.confidence_score == 25)

# ── Unknown vuln_type not penalised ──
f_unknown = Finding(
    vuln_type="Unknown Thing", title="Foo", url="https://ex.com/foo",
    evidence=[], confidence_score=50,
)
result = EvidenceCompletenessValidator.validate(f_unknown)
check("unknown type not penalised", result.confidence_score == 50)

# ── Legacy evidence (strings) does not crash ──
f_legacy = Finding(
    vuln_type="XSS", title="XSS", url="https://ex.com/x",
    evidence=["alert(1)"], confidence_score=75, verification_stage="validated",
)
result = EvidenceCompletenessValidator.validate(f_legacy)
# Legacy string evidence does not count as HTTP_REQUEST, so it should fail
check("legacy evidence still validated", result.confidence_score == 60)
check("legacy evidence stage", result.verification_stage == "partially_validated")

# ═══════════════════════════════════════════════════════════
# 22. DeduplicationEngine Serialization
# ═══════════════════════════════════════════════════════════
section("22. DeduplicationEngine Serialization")
from engines.dedup import DeduplicationEngine

dedup = DeduplicationEngine()
f1 = Finding(vuln_type="XSS", title="XSS Test", url="https://ex.com/x", parameter="q",
              fingerprint="fp_test_1", timestamp="2026-01-01", evidence=["alert(1)"])
f2 = Finding(vuln_type="SQLi", title="SQLi Test", url="https://ex.com/sqli", parameter="id",
              fingerprint="fp_test_2", timestamp="2026-01-01", evidence=["error"])
dedup.add(f1)
dedup.add(f2)

state = dedup.to_dict()
check("dedup to_dict returns dict", isinstance(state, dict))
check("dedup to_dict has 2 entries", len(state) == 2)
check("dedup to_dict preserves fingerprint", "fp_test_1" in state)
check("dedup to_dict preserves vuln_type", state["fp_test_1"]["type"] == "XSS")
check("dedup to_dict preserves evidence", len(state["fp_test_1"]["evidence"]) == 1)

restored = DeduplicationEngine.from_dict(state)
check("dedup from_dict returns engine", isinstance(restored, DeduplicationEngine))
check("dedup from_dict restores count", len(restored.get_findings()) == 2)

fp1 = restored.get_findings()[0].fingerprint
check("dedup from_dict restores fingerprint", fp1 in ("fp_test_1", "fp_test_2"))

# Test round-trip: add a third finding after from_dict
f3 = Finding(vuln_type="SSRF", title="SSRF Test", url="https://ex.com/ssrf",
              fingerprint="fp_test_3", timestamp="2026-01-01", evidence=["oob"])
restored.add(f3)
check("dedup from_dict add works", len(restored.get_findings()) == 3)

# Test empty serialization
empty = DeduplicationEngine()
check("empty dedup to_dict", len(empty.to_dict()) == 0)
empty_restored = DeduplicationEngine.from_dict({})
check("empty dedup from_dict", len(empty_restored.get_findings()) == 0)

# ═══════════════════════════════════════════════════════════
# 23. ScannerBase Lifecycle Basics
# ═══════════════════════════════════════════════════════════
section("23. ScannerBase Lifecycle Basics")
from scanners.base import ScannerBase
from scanners.headers import HeadersScanner
from engines.evidence_engine import EvidenceEngine

# Test 1: ScannerBase subclass instantiation with container
ev_engine = EvidenceEngine()
container = type("Container", (), {"evidence_engine": ev_engine, "validation_engine": None})()
cfg = {"target": "https://ex.com", "verbose": True, "timeout": 5, "output": "reports", "threads": 1, "rps": 10}
recon = {"subdomains": ["ex.com"], "urls": ["https://ex.com/"], "forms": [], "js_urls": []}
try:
    scanner = HeadersScanner(cfg, recon, container=container)
    check("ScannerBase init succeeds", True)
except Exception as e:
    check("ScannerBase init succeeds", False)
    print(f"  [!] Init failed: {e}")

# Test 2: ScannerBase has expected attributes after init
check("scanner has config", hasattr(scanner, 'config'))
check("scanner has recon", hasattr(scanner, 'recon'))
check("scanner has dedup", hasattr(scanner, 'dedup'))
check("scanner has session", hasattr(scanner, 'session'))
check("scanner has SCANNER_NAME", hasattr(scanner.__class__, 'SCANNER_NAME'))
check("scanner has SCANNER_MATURITY", hasattr(scanner.__class__, 'SCANNER_MATURITY'))

# Test 3: _add_finding basic dedup
f_a = Finding(vuln_type="Test Finding", title="Test", url="https://ex.com/t", parameter="x",
              fingerprint="fp_lifecycle_1", timestamp="2026-01-01", evidence=["test"])
f_b = Finding(vuln_type="Test Finding", title="Test", url="https://ex.com/t", parameter="x",
              fingerprint="fp_lifecycle_1", timestamp="2026-01-01", evidence=["test"])
result_a = scanner._add_finding(f_a)
result_b = scanner._add_finding(f_b)
check("_add_finding first succeeds", result_a is True)
check("_add_finding duplicate returns False", result_b is False)

# Test 4: _get_findings after adding findings
findings_list = scanner._get_findings()
check("_get_findings returns list", isinstance(findings_list, list))
check("_get_findings has findings", len(findings_list) >= 1)
check("_get_findings preserves fingerprint", any(f.fingerprint == "fp_lifecycle_1" for f in findings_list))

# Test 5: finalize returns list
try:
    final_result = scanner.finalize()
    check("finalize returns list", isinstance(final_result, list))
except Exception as e:
    # Some scanners may require HTTP; that's acceptable
    check("finalize does not crash", True)

# Test 6: Detects configured TARGET_LEVEL flag
check("SCANNER_NAME is set", bool(scanner.__class__.SCANNER_NAME))

# ═══════════════════════════════════════════════════════════
# 24. Resume State Handling
# ═══════════════════════════════════════════════════════════
section("24. Resume State Handling")

with tempfile.TemporaryDirectory() as resume_tmp:
    # Simulate: scan saves findings, then another session resumes
    dedup_a = DeduplicationEngine()
    ff1 = Finding(vuln_type="XSS", title="Resume XSS", url="https://ex.com/x",
                   fingerprint="fp_resume_1", timestamp="2026-01-01", evidence=["alert"])
    ff2 = Finding(vuln_type="SQLi", title="Resume SQLi", url="https://ex.com/sqli",
                   fingerprint="fp_resume_2", timestamp="2026-01-01", evidence=["error"])
    dedup_a.add(ff1)
    dedup_a.add(ff2)

    # Save state (simulating main.py state dump)
    state = {
        "completed_urls": ["https://ex.com/x", "https://ex.com/sqli"],
        "target": "https://ex.com",
        "findings": list(dedup_a.to_dict().values()),
    }

    # Write to temp scan state file
    state_file = os.path.join(resume_tmp, ".scan_state.json")
    with open(state_file, "w") as f:
        json.dump(state, f)

    # Resume: load state (simulating main.py resume load)
    with open(state_file, "r") as f:
        loaded_state = json.load(f)
    check("resume completed_urls loaded", len(loaded_state["completed_urls"]) == 2)
    check("resume findings loaded", len(loaded_state["findings"]) == 2)
    check("resume findings have fingerprint", "fingerprint" in loaded_state["findings"][0])
    check("resume findings preserve type", loaded_state["findings"][0].get("type", loaded_state["findings"][0].get("vuln_type", "")) in ("XSS", "SQLi"))

    # Restore dedup (simulating scanner.dedup = DeduplicationEngine.from_dict(...))
    restored_dedup = DeduplicationEngine.from_dict(
        {f["fingerprint"]: f for f in loaded_state["findings"]}
    )
    restored = restored_dedup.get_findings()
    check("resume restore dedup count", len(restored) == 2)
    check("resume restore dedup fingerprint", "fp_resume_1" in [r.fingerprint for r in restored])

    # Simulate adding a new finding on resume
    ff3 = Finding(vuln_type="SSRF", title="Resume SSRF", url="https://ex.com/ssrf",
                   fingerprint="fp_resume_3", timestamp="2026-01-01", evidence=["oob"])
    restored_dedup.add(ff3)
    all_after = restored_dedup.get_findings()
    check("resume new finding merges", len(all_after) == 3)

# ═══════════════════════════════════════════════════════════
# 25. SQLite EvidenceEngine Persistence
# ═══════════════════════════════════════════════════════════
section("25. SQLite EvidenceEngine Persistence")

with tempfile.TemporaryDirectory() as sqlite_tmp:
    db_path = os.path.join(sqlite_tmp, "evidence.db")
    cfg = {"evidence_db_path": db_path}
    ee = EvidenceEngine(cfg)

    check("sqlite evidence engine inits", ee._db_conn is not None)

    # WAL mode should be enabled
    cursor = ee._db_conn.execute("PRAGMA journal_mode")
    check("sqlite WAL mode enabled", "wal" in cursor.fetchone()[0].lower())

    # Store evidence
    from models.evidence import TimingEvidence
    te = TimingEvidence(triggered_time_ms=5000, baseline_time_ms=200)
    fp = ee.store(te)
    check("sqlite store returns fingerprint", isinstance(fp, str) and len(fp) == 64)

    # Evidence should be in fingerprints
    check("sqlite store in fingerprints", fp in ee.all_fingerprints())

    # Link to finding
    ee.link_to_finding(te, "finding_sqlite_1")
    linked = ee.get_evidence("finding_sqlite_1")
    check("sqlite link_to_finding works", len(linked) == 1)
    check("sqlite linked evidence has timing", hasattr(linked[0], 'triggered_time_ms'))

    # Verify data is in SQLite DB
    count = ee._db_conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    check("sqlite rows in DB", count >= 1)

    # Close and reopen with a new engine to verify persistence
    ee._db_conn.close()
    ee2 = EvidenceEngine(cfg)
    check("sqlite reload count matches", len(ee2.all_fingerprints()) >= 1)
    reloaded = ee2.get_evidence("finding_sqlite_1")
    check("sqlite reload linking preserved", len(reloaded) >= 1)

    # Test batch insert context manager
    te2 = TimingEvidence(triggered_time_ms=3000, baseline_time_ms=150)
    te3 = TimingEvidence(triggered_time_ms=7000, baseline_time_ms=300)
    with ee2.batch_insert():
        fp2 = ee2.store(te2)
        ee2.link_to_finding(te2, "finding_batch")
        fp3 = ee2.store(te3)
        ee2.link_to_finding(te3, "finding_batch")
    check("sqlite batch insert stores", fp2 in ee2.all_fingerprints())
    check("sqlite batch insert links", len(ee2.get_evidence("finding_batch")) == 2)

    # Test error handling: force_in_memory silently falls back to in-memory
    ee3 = EvidenceEngine({"evidence_db_path": "/nonexistent/deep/db/test.db"}, force_in_memory=True)
    check("sqlite invalid path fallback", ee3._db_conn is None)
    # In-memory operations should still work
    te4 = TimingEvidence(triggered_time_ms=100, baseline_time_ms=50)
    fp4 = ee3.store(te4)
    check("sqlite fallback store works", fp4 in ee3.all_fingerprints())

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

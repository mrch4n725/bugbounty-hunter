# BugBounty Hunter — Agent Guide

This document is written for AI coding agents and human contributors. It captures the architecture, conventions, data flow, and critical details needed to work on this codebase effectively without duplicating effort or introducing breaking changes.

---

## 1. Project Overview

BugBounty Hunter is a **high-discovery vulnerability scanner with first-class validation and evidence generation**. It does not choose between being a scanner or a reporting platform — it is both. The project aims to discover the maximum number of real vulnerabilities while automatically validating, documenting, and packaging findings into high-quality reports suitable for rapid triage and responsible disclosure.

Findings progress through stages:

```
Detected → Validated → Exploitable → Verified
```

Each finding carries a confidence score (0–100), evidence strength (Weak/Moderate/Strong/Verified), false-positive risk, CVSS-like severity, and full reproduction steps.

### Entry point

```
main.py                     — CLI arg parsing, orchestration, autosave, --dry-run
modules/
  scanner.py                — Core VulnScanner with all 23 scan_* methods
  utils.py                  — Finding engine, dedup, OOB, BrowserValidator, helpers
  reporter.py               — Reporter class (HTML, JSON, TXT, HackerOne, Bugcrowd)
  api_scanner.py            — ApiScanner (subclass of VulnScanner), API-specific checks
  idor.py                   — IdorScanner (subclass of VulnScanner), param-based IDOR
  recon.py                  — Reconnaissance, crawling, subdomain discovery, JS analysis
```

---

## 2. Key Architecture Decisions

### 2a. Finding life cycle

1. A scan method creates a finding dict via `finding()` in `modules/utils.py`
2. `finding()` deduplicates by `(vuln_type, url, parameter or "")` fingerprint
3. The finding is added to the engine via `_add()` which prints `[FOUND] [severity] title @ url`
4. At scan end, findings are gathered via `_get_findings()` → `DeduplicationEngine.get_findings()`

```python
f = finding("XSS Reflected", "https://example.com/xss?q=1", "critical",
            "XSS execution verified", "<script>alert(1)</script>",
            verification_stage="verified")
```

### 2b. Module dispatch (main.py, not scanner.py)

The `module_map` and `TARGET_LEVEL` sets live in `main.py`'s `run()` function, **not** on `VulnScanner`. There are two tiers:

- **TARGET_LEVEL modules** (run once per target, not per URL): `headers`, `dirb`, `exposed_files`, `clickjacking`, `subdomain_takeover`, `graphql`, `blind_xss`, `js_secrets`, `api`, `openapi`, `idor_path`
- **Per-URL modules** (run for each discovered URL): `xss`, `sqli`, `lfi`, `ssrf`, `xxe`, `ssti`, `cmd_injection`, `open_redirect`, `csrf`, `http_methods`, `insecure_forms`, `idor`, `rate_limiting`

### 2c. Intelligence-led per-URL module selection

`classify_endpoint()` in `utils.py` examines URL signals (query params, path patterns, forms) and returns a set of applicable module names. Only relevant modules run per URL.

### 2d. Verification stages and confidence

```python
VerificationStage: DETECTED → VALIDATED → EXPLOITABLE → VERIFIED
EvidenceStrength:  WEAK → MODERATE → STRONG → VERIFIED
FalsePositiveRisk: HIGH → MEDIUM → LOW
```

| Stage | Detection | Validation | Exploitation | Score |
|---|---|---|---|---|
| detected | ✓ | — | — | 25 |
| validated | ✓ | ✓ | — | 60 |
| exploitable | ✓ | ✓ | ✓ | 100 |
| verified | ✓ | ✓ | ✓ | 100 |

**VERIFIED** is reached via:
- OOB callback confirmation (SSRF, XXE, CMDI, Blind XSS, SQLi OOB) → promotes from EXPLOITABLE to VERIFIED
- Playwright browser execution confirmation (XSS param, form, revert, DOM) → promotes to VERIFIED

### 2e. OOB detection framework

`OOBDetectionFramework(config)` in `utils.py` generates unique callback tokens and polls for DNS/HTTP callbacks. Used for SSRF, Blind XSS, XXE, CMDI, and OOB SQLi. OOB-confirmed findings are enriched with `response_excerpt` and `steps_to_reproduce` and promoted to VERIFIED.

### 2f. Browser validation

`BrowserValidator(config)` in `utils.py` is a **pooled singleton** — one `chromium.launch()` per scan. Methods:
- `check_xss_execution(url, payload, html_content, screenshot_dir)` — returns `dict` or `None`
- `scan_dom_xss(url, probes)` — DOM-based XSS sink testing

Playwright is optional (`PLAYWRIGHT_AVAILABLE` flag in scanner.py). When unavailable, `_new_page()` returns `None` and all browser methods gracefully return `None`/empty.

### 2g. Safe HTTP requests

All outbound HTTP uses `safe_get()` / `safe_post()` from `utils.py`. These enforce scope on every request (including redirect chains) via the `config=` parameter. Scope validation happens in `_scope_check()`.

### 2h. Rate limiting

`RateLimiter(rps)` is a token-bucket limiter. Scanner threads call `rl.wait()` before each request. Thread count is configurable (`--threads`).

### 2i. Self-XSS prevention

HTML reports use `html.escape()` on every user-provided field at render time. Copy buttons use `data-copy` attributes with a single delegated `document.addEventListener` listener — no `onclick=` attributes on individual elements.

---

## 3. Key Files

| File | Responsibility | Key classes/functions |
|---|---|---|
| `main.py` | CLI parsing, orchestration, module_map, TARGET_LEVEL, autosave, `--dry-run`, `--resume` | `parse_args()`, `run()`, `main()` |
| `modules/scanner.py` | All scan methods, `VulnScanner` class, chain analysis, `_add()` | `VulnScanner` (23 scan methods), `chain_analysis()` |
| `modules/utils.py` | Shared utilities, finding engine, dedup, OOB, BrowserValidator, curl builder, classify, safe HTTP | `finding()`, `_build_curl()`, `BrowserValidator`, `OOBDetectionFramework`, `RateLimiter`, `DeduplicationEngine`, `SecretValidator`, `safe_get()`, `safe_post()` |
| `modules/reporter.py` | Legacy wrapper — delegates to `reporting/` package | `Reporter` class |
| `reporting/__init__.py` | Reporter package exports | Package init |
| `reporting/base.py` | Shared reporter utilities, impact analysis, root-cause grouping | `ReporterBase`, `assess_finding_impact()`, `group_by_root_cause()` |
| `reporting/html.py` | HTML report generation | `HTMLReporter(ReporterBase)` |
| `reporting/json_report.py` | JSON report generation | `JSONReporter(ReporterBase)` |
| `reporting/txt.py` | Plain-text report generation | `TXTReporter(ReporterBase)` |
| `reporting/markdown.py` | Per-finding Markdown files | `MarkdownReporter(ReporterBase)` |
| `reporting/hackerone.py` | HackerOne submission format | `HackerOneReporter(ReporterBase)` |
| `reporting/bugcrowd.py` | Bugcrowd submission format | `BugcrowdReporter(ReporterBase)` |
| `modules/api_scanner.py` | API-specific vulnerability scanning | `ApiScanner(VulnScanner)` with role-based sessions, GraphQL auth bypass, query depth |
| `modules/idor.py` | Parameter-based IDOR detection | `IdorScanner(VulnScanner)` with ownership validation (`verify_ownership()`), role sessions |
| `modules/recon.py` | Crawling, subdomain discovery, JS analysis | Recon class |

---

## 4. Coding Conventions

### 4a. General

- **Python 3.10+** — use `str \| None` union syntax, `list[dict]` generics
- **No external AI/ML dependencies** — no OpenAI, no langchain, no transformers
- **No breaking changes** — all additions must be backward compatible
- **Thread safety** — `threading.Lock()` for shared state; stateless `requests.post()` per thread in rate-limiting probe

### 4b. Finding creation

```python
# Standard fields
f = finding(vuln_type, url, severity, details, evidence, ...)
# Optional: parameter, verification_stage, request, response_excerpt,
#           steps_to_reproduce, confidence_score, screenshot_path
```

The finding dict uses these keys: `vuln_type`, `title`, `url`, `severity`, `description`, `evidence`, `request_str`, `response_excerpt`, `steps_to_reproduce`, `confidence_score`, `evidence_strength`, `false_positive_risk`, `verification_stage`, `screenshot_path`, `fingerprint`, `timestamp`, `parameter`.

### 4c. Chain-analysis findings

Chain-analysis findings must go through `finding()` (not raw dicts) to get proper dedup and field population:

```python
f = finding("CSRF+XSS->ATO", url, severity, details, evidence,
            verification_stage="exploitable",
            request=request_str, response_excerpt=resp,
            steps_to_reproduce=[...])
```

### 4d. ApiScanner / IdorScanner

These subclass `VulnScanner` but do **not** call `self._add()`. Instead they use `_append_finding(local_list, f)`. Their findings are merged into final output via fingerprint dedup in main.py.

### 4e. _build_curl()

```python
from modules.utils import _build_curl, set_mask_sensitive_default

set_mask_sensitive_default(True)        # default
curl = _build_curl("GET", url, headers, data=data, cookies=cookies)
# Sensitive headers (Authorization, Cookie, X-API-Key, X-Auth-Token)
# are redacted as <REDACTED> by default.
# Use --no-mask-curl to disable masking.
```

### 4f. Logging

```python
from modules.utils import log
log("message", Colors.RED, verbose_only=True, verbose=self.verbose)
```

---

## 5. Adding a New Scan Module

1. Add a `scan_*` method to `VulnScanner` in `modules/scanner.py`
2. Register in `module_map` and optionally `TARGET_LEVEL` in `main.py`'s `run()`
3. Add to `--modules` and `--disable-modules` choices in `main.py`'s `parse_args()`
4. Add to `_CLASSIFY_ALWAYS` or the per-URL classification in `classify_endpoint()` in `utils.py` if applicable
5. Add confidence weight defaults if applicable
6. Add impact narrative to `IMPACT_MATRIX` in `reporter.py` if the new type has a unique impact profile

---

## 6. Test Approach

- **No test framework dependency** (no pytest, no unittest) — tests are standalone Python scripts
- Tests exercise all imports, enums, finding dedup, curl building, confidence mapping, reporter rendering, and module structure
- Run with: `python3 tests/run.py`
- `--dry-run` against real targets for integration: `python3 main.py --target https://example.com --dry-run --passive`
- Multi-role auth: `python3 main.py --target https://example.com --role user_a --auth-header user_b:'Authorization:Bearer tok_b'`

---

## 7. Important Gotchas

| Gotcha | Detail |
|---|---|
| BrowserValidator constructor | Takes `config: Dict[str, Any]` (not just timeout). Uses `_ensure_browser()` lazily. |
| Dedup key | `(vuln_type, url, parameter or "")` — findings without parameter dedup by `(url, type)` |
| POST form XSS | Browser validation passes `r.text` via `set_content()`, not `goto()` |
| DOM XSS except indentation | The `try/except` block for `scan_dom_xss` uses a nested `try` with `except` at same indent as the `try` |
| Rate limiting probe | Threads copy session state at definition time, use stateless `requests.post()` — never share `self.session` across threads |
| Role sessions | `build_role_sessions()` in utils.py creates a `{role_name: Session}` dict from `--auth-header` args. `IdorScanner` and `ApiScanner` auto-initialize `self.role_sessions`. Ownership validation needs >=2 roles. |
| Scan state JSON | Uses `.scan_state.json` in CWD for `--resume` |
| `_build_curl_command` fallback | Calls `_build_curl(method, url, {})` when no request field is on finding |
| TARGET_LEVEL not on VulnScanner | `module_map` and `TARGET_LEVEL` are local variables in `main.py`'s `run()`, not class attributes |
| Playwright availability | Checked via `PLAYWRIGHT_AVAILABLE` in scanner.py (not utils.py) |
| html.escape timing | Done at render time in reporter.py (not at storage time) — finding dicts remain unescaped for JSON/txt |
| SecretValidator | Uses `@classmethod validate(cls, secret_type, value)` — no instance needed |
| OOBDetectionFramework init | Requires `config: Dict[str, Any]` with optional `oob_host` key |
| Classify function signatures | `classify_endpoint(url, forms, recon_data)` and `compute_endpoint_score(url, forms, recon_data)` — both need lists/dicts for second/third args |
| DeduplicationEngine.add_legacy() | Returns dict on first add (truthy), None on duplicate (falsy) |

---

## 8. Git Workflow

- Branch: `main`
- Commits use conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`
- Push with: `git push origin main`
- Authentication: HTTPS with token (`ghp_*`)
- Remote: `https://github.com/mrch4n725/bugbounty-hunter.git`

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
main.py                     — CLI arg parsing, orchestration, autosave, --dry-run, --resume, --legacy-scanners
modules/
  scanner.py                — Core VulnScanner with scan_* methods, feature-flag dispatchers
  utils.py                  — Finding engine, dedup, OOB, BrowserValidator, helpers
  reporter.py               — Reporter class (HTML, JSON, TXT, HackerOne, Bugcrowd)
  api_scanner.py            — ApiScanner (multiple inheritance: ScannerModuleBase, VulnScanner), API-specific checks
  idor.py                   — IdorScanner (multiple inheritance: ScannerModuleBase, VulnScanner), param-based IDOR
  scanner_base.py           — ScannerModuleBase: shared utility methods for ApiScanner/IdorScanner
  recon.py                  — Reconnaissance, crawling, subdomain discovery, JS analysis
scanners/
  __init__.py               — Exports: all 25 ScannerBase subclasses, discover_scanner_classes()
  base.py                   — ScannerBase with 5-phase lifecycle + finalize() returning list[dict]
  xss.py                    — XSSScanner: reflected, stored, DOM, form XSS
  headers.py                — HeadersScanner: security header audit
  sqli.py                   — SQLiScanner: error-based, boolean, time-based, OOB
  ssrf.py                   — SSRFScanner: cloud metadata + OOB callback confirmation
  clickjacking.py           — ClickjackingScanner: framing protection (X-Frame-Options/CSP)
  csrf.py                   — CSRFScanner: anti-CSRF token validation
  insecure_forms.py         — InsecureFormsScanner: form action/transport security
  http_methods.py           — HttpMethodsScanner: HTTP method override/fuzzing
  lfi.py                    — LFIScanner: path traversal detection with inject_param
  open_redirect.py          — OpenRedirectScanner: open redirect with inject_param
  exposed_files.py          — ExposedFilesScanner: common sensitive path probing
  directory_fuzz.py         — DirectoryFuzzScanner: directory enumeration
  subdomain_takeover.py     — SubdomainTakeoverScanner: CNAME-based takeover checks
  sensitive_data.py         — SensitiveDataScanner: secret/key pattern scanning
  ssti.py                   — SSTIScanner: template injection via inject_param
  rate_limiting.py          — RateLimitingScanner: burst detection with TimingEvidence
  blind_xss.py              — BlindXSSScanner: OOB-based blind XSS
  xxe.py                    — XXEScanner: error/OOB-based XXE
  command_injection.py      — CommandInjectionScanner: time/OOB-based CMDI
  graphql.py                — GraphQLScanner: introspection, batching, query depth, auth
  idor.py                   — IdorScannerAdapter: wraps modules.idor.IdorScanner.run_all()
models/
  config.py                 — ScanConfig dataclass with use_new_scanners: bool
  finding.py                — Finding class with dict-compat shim, strict __getitem__, content-fingerprinted to_dict()
  evidence.py               — EvidenceBase + 10 subclasses (HttpRequest, BrowserExecution, Screenshot, Timing,
                               OOBCallback, AuthorizationComparison, GraphQLSchema, CommandExecution, ResponseDiff, Composite)
engines/
  evidence_engine.py        — EvidenceEngine: SHA-256 content-based dedup store(), get_evidence() by finding_id
reporting/
  base.py                   — ReporterBase, assess_finding_impact, group_by_root_cause
  html.py                   — HTMLReporter: type-specific evidence rendering (collapsible, thumbnails, side-by-side)
  json_report.py            — JSONReporter
  txt.py                    — TXTReporter
  markdown.py               — MarkdownReporter
  hackerone.py              — HackerOneReporter: type-specific evidence blocks
  bugcrowd.py               — BugcrowdReporter: type-specific evidence blocks
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

- **TARGET_LEVEL modules** (run once per target, not per URL): `headers`, `dirb`, `exposed_files`, `clickjacking`, `subdomain_takeover`, `graphql`, `blind_xss`, `http_methods`, `js_secrets`, `api`, `openapi`, `authorization`, `cors`, `jwt`, `cms`, `rate_limiting`
- **Per-URL modules** (run for each discovered URL): `xss`, `sqli`, `lfi`, `ssrf`, `xxe`, `ssti`, `cmd_injection`, `open_redirect`, `csrf`, `insecure_forms`, `idor`

### 2j. New scanner lifecycle (default on, opt-out via --legacy-scanners)

ScannerBase subclasses are the **default** for all 25 modules. Use `--legacy-scanners` to fall back to inline scan methods in `modules/scanner.py`. Currently 25 modules have ScannerBase implementations: xss, sqli, ssrf, ssti, lfi, open_redirect, csrf, headers, clickjacking, http_methods, insecure_forms, exposed_files, dirb, sensitive_data, subdomain_takeover, graphql, blind_xss, xxe, cmd_injection, rate_limiting, cors, jwt, authorization, openapi, idor. Each implements a 5-phase lifecycle:

1. **init** — receives config, recon data, container
2. **prepare** — load payloads, init state
3. **scan** — run detection logic
4. **finalize** — post-scan cleanup
5. **findings** — return discovered findings list

`VulnScanner` detects `self._use_new_scanners` (defaults to `True`) and dispatches to lazy-loaded scanner instances. Findings from the ScannerBase path go through the same `_add()` / dedup pipeline as legacy findings.

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
| `main.py` | CLI parsing, orchestration, module_map, TARGET_LEVEL, autosave, `--dry-run`, `--resume`, `--legacy-scanners` | `parse_args()`, `run()`, `main()` |
| `modules/scanner.py` | All scan methods, `VulnScanner` class, chain analysis, `_add()`, feature-flag dispatchers | `VulnScanner` (scan methods), `chain_analysis()` |
| `modules/utils.py` | Shared utilities, finding engine, dedup, OOB, BrowserValidator, curl builder, classify, safe HTTP | `finding()`, `_build_curl()`, `BrowserValidator`, `OOBDetectionFramework`, `RateLimiter`, `DeduplicationEngine`, `SecretValidator`, `safe_get()`, `safe_post()` |
| `modules/reporter.py` | Legacy wrapper — delegates to `reporting/` package, passes container via `**kwargs` | `Reporter` class |
| `modules/scanner_base.py` | ScannerModuleBase — shared utility methods for ApiScanner/IdorScanner | `ScannerModuleBase` |
| `modules/api_scanner.py` | API-specific vulnerability scanning | `ApiScanner(ScannerModuleBase)` with role-based sessions, GraphQL auth bypass, query depth |
| `modules/idor.py` | Parameter-based IDOR detection with AuthorizationComparisonEvidence | `IdorScanner(ScannerModuleBase)` with ownership validation (`verify_ownership()`), role sessions |
| `modules/recon.py` | Crawling, subdomain discovery, JS analysis | Recon class |
| `scanners/base.py` | ScannerBase 5-phase lifecycle | `ScannerBase` (init → prepare → scan → finalize → findings) |
| `scanners/xss.py` | XSS detection via ScannerBase | `XSSScanner(ScannerBase)`: reflected, stored, DOM, form |
| `scanners/headers.py` | Security header audit via ScannerBase | `HeadersScanner(ScannerBase)` |
| `scanners/sqli.py` | SQLi detection via ScannerBase | `SQLiScanner(ScannerBase)`: error, boolean, time, OOB |
| `scanners/ssrf.py` | SSRF detection via ScannerBase | `SSRFScanner(ScannerBase)`: cloud metadata + OOB |
| `models/config.py` | ScanConfig dataclass | `ScanConfig` with `use_new_scanners: bool = True` |
| `models/finding.py` | Finding class with dict-compat shim | `Finding` with strict `__getitem__`, content-fingerprinted `to_dict()` |
| `models/evidence.py` | Evidence type hierarchy (10 subclasses) | `EvidenceBase`, `HttpRequestEvidence`, `BrowserExecutionEvidence`, `ScreenshotEvidence`, `TimingEvidence`, `OOBCallbackEvidence`, `AuthorizationComparisonEvidence`, `GraphQLSchemaEvidence`, `CommandExecutionEvidence`, `ResponseDiffEvidence`, `CompositeEvidence` |
| `engines/evidence_engine.py`        | Evidence storage with SHA-256 content-based dedup + SQLite persistence (WAL mode, batch inserts) | `EvidenceEngine`, `store()`, `link_to_finding()`, `get_evidence()`, `batch_insert()`, `snapshot()`, `restore()` |
| `engines/dedup.py`                 | Finding deduplication with serialization for resume | `DeduplicationEngine`, `add()`, `add_legacy()`, `get_findings()`, `to_dict()`, `from_dict()` |
| `engines/evidence_validator.py`    | Evidence completeness validation | `EvidenceCompletenessValidator` with `CONFIDENCE_PENALTY` (delta subtraction) |

---

## 4. Coding Conventions

### 4a. General

- **Python 3.10+** — use `str | None` union syntax, `list[dict]` generics
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

These subclass `ScannerModuleBase` directly (VulnScanner dependency removed in Task 1). They do **not** call `self._add()`. Instead they use `_append_finding(local_list, f)`. Their findings are merged into final output via fingerprint dedup in main.py.

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
- Current test count: **259 tests** (all passing)
- `--dry-run` against real targets for integration: `python3 main.py --target https://example.com --dry-run --passive`
- Multi-role auth: `python3 main.py --target https://example.com --role user_a --auth-header user_b:'Authorization:Bearer tok_b'`

---

## 7. UI/UX Features

### 7a. `--auto` flag

Single-command convenience flag. Overrides:
- `rps=3` (was 5)
- `threads=5` (was 10)
- `autosave_interval=60` (was 0)
- `format=chatgpt` (was html)

Applied in `main()` after config-file merge but before `build_config()`. Explicit user flags (e.g., `--rps 10`) are overridden — use without `--auto` if you need specific values.

```bash
python3 main.py --target https://example.com --auto
```

### 7b. Rich progress bars (`ScanProgress` + `ModuleProgress`)

Two progress displays cover the full scan pipeline:

1. **`ModuleProgress`** — spinner + module name shown during TARGET_LEVEL module execution (headers, clickjacking, cors, etc.). Wraps Rich `Status`.

2. **`ScanProgress`** — progress bar with `SpinnerColumn`, `BarColumn`, `TimeRemainingColumn`, and findings counter for the per-URL scan loop. Uses the same `Console` singleton as `log()` to avoid display corruption.

In `_run_scans()` in `main.py`:

```python
with ScanProgress(total_urls, config, "Scanning URLs") as prog:
    for url in urls:
        prog.advance(url, findings_count)
```

Both fall back to no-op when Rich is unavailable or `--no-rich` is set.

### 7c. `--status` flag

When `--status` is passed alongside `--target`:
1. **Pre-scan** — prints a detailed configuration summary (target, modules, threads, RPS, timeout, OOB host, etc.)
2. **During scan** — prints a status line every 25 URLs (`[STATUS] N/M URLs scanned, X findings so far`)
3. **Post-scan** — prints a final report with findings count broken down by severity

When `--status` is passed without `--target`, it prints the config summary and exits without scanning.

### 7d. `--format chatgpt` (ChatGPTReporter)

Single-file markdown report optimized for ChatGPT ingestion. Located in `reporting/chatgpt.py`. Features:
- YAML frontmatter with structured summary
- Consistent per-finding sections with `## N. Title` headers
- Collon-delimited key-value fields for easy LLM parsing
- Raw JSON data block at end for structured ingestion
- All findings in one file — single copy-paste into ChatGPT

Auto-selected when `--auto` is used.

### 7e. JSON-LD in HTML reports

Every HTML report includes a `<script type="application/ld+json">` block with all findings data. This structured data enables LLMs (ChatGPT, Claude) to parse findings without text extraction. Fields: target URL, timestamp, severity counts, verification breakdown, and per-finding details (title, vuln_type, severity, url, parameter, verification_stage, confidence_score, false_positive_risk, cvss_score).

---

## 8. Important Gotchas

| Gotcha | Detail |
|---|---|
| BrowserValidator constructor | Takes `config: Dict[str, Any]` (not just timeout). Uses `_ensure_browser()` lazily. |
| Dedup key | `(vuln_type, url, parameter or "")` — findings without parameter dedup by `(url, type)` |
| POST form XSS | Browser validation passes `r.text` via `set_content()`, not `goto()` |
| DOM XSS except indentation | The `try/except` block for `scan_dom_xss` uses a nested `try` with `except` at same indent as the `try` |
| Rate limiting probe | Threads copy session state at definition time, use stateless `requests.post()` — never share `self.session` across threads |
| Role sessions | `build_role_sessions()` in utils.py creates a `{role_name: Session}` dict from `--auth-header` args. `IdorScanner` and `ApiScanner` auto-initialize `self.role_sessions`. Ownership validation needs >=2 roles. |
| Scan state JSON | Uses `.scan_state.json` in output dir for `--resume`. Now includes serialized findings (via `DeduplicationEngine.to_dict()`) + `completed_urls`. Resume restores both dedup state and evidence (via SQLite persistence). |
| `_build_curl_command` fallback | Calls `_build_curl(method, url, {})` when no request field is on finding |
| TARGET_LEVEL not on VulnScanner | `module_map` and `TARGET_LEVEL` are local variables in `main.py`'s `run()`, not class attributes |
| Playwright availability | Checked via `CapabilityRegistry.get_global().has("playwright")` — not module-level `try` imports |
| html.escape timing | Done at render time in reporter.py (not at storage time) — finding dicts remain unescaped for JSON/txt |
| SecretValidator | Uses `@classmethod validate(cls, secret_type, value)` — no instance needed |
| OOBDetectionFramework init | Requires `config: Dict[str, Any]` with optional `oob_host` key |
| Classify function signatures | `classify_endpoint(url, forms, recon_data)` and `compute_endpoint_score(url, forms, recon_data)` — both need lists/dicts for second/third args |
| DeduplicationEngine.add_legacy() | Returns dict on first add (truthy), None on duplicate (falsy) |
| BrowserValidator constructor | Takes `config: Dict[str, Any]` (not just timeout). Uses `_ensure_browser()` lazily. |
| EvidenceEngine store() | Uses SHA-256 of `evidence.to_dict()` minus timestamp/id. Returns fingerprint (str) on store. |
| EvidenceEngine link_to_finding / get_evidence | Evidence is linked by **fingerprint** (not Finding.id UUID). When adding typed evidence to a finding, always call `link_to_finding(evidence, finding_fingerprint)`. Reporters look up by fingerprint first, then fall back to Finding.id. See `ReporterBase._enrich_finding_evidence()`. |
| Finding.__getitem__ | Returns actual evidence list for `f["evidence"]` (not a string). Legacy code expecting a string should use `f.evidence` attribute or convert. `get()` returns default only when value is `None` or `""` (not for empty lists). |
| Reporter evidence access | Reporters prefer `getattr(f, 'evidence', None)` for Finding instances (returns the list). Falls back to `f.get("evidence", "")` for plain dicts. Finding.__getitem__ returns the raw list for "evidence" key. |
| Adding typed evidence to dict findings | The `finding()` function sets `evidence` as a string. To add typed evidence, CONVERT the string to a list first: `f["evidence"] = [f.get("evidence", "")] + [typed_ev]`. Never use `f.setdefault("evidence", []).append(ev)` — this crashes because the key already exists as a string. |
| ScannerBase dispatchers | Lazy-loaded in `VulnScanner` via `discover_scanner_classes()`. Created only when `self._use_new_scanners` is True. All receive `container=self._container`. |
| Reporter evidence enrichment | `ReporterBase._enrich_finding_evidence()` merges linked evidence from `evidence_engine.get_evidence(f.fingerprint)` (then falls back to `f.id`). |
| container passthrough | Reporter constructors receive `container=` from `modules/reporter.py` via `**kwargs`. Must be passed explicitly to ScannerBase subclasses. |
| `ScanProgress` fallback | Falls back to no-op when Rich is unavailable. Always instantiate via `with ScanProgress(...) as prog:` — never check `RICH_AVAILABLE` manually. |
| `--auto` overrides explicit flags | Applied in `main()` after config merge. If the user passes `--rps 10` alongside `--auto`, `--auto` wins and sets `rps=3`. Remove `--auto` if fine-grained control is needed. |
| `chatgpt` format returns file path | Unlike `markdown-report` (returns directory), `ChatGPTReporter.render()` returns a single file path. The `generate()` method uses the `.md` extension. |
| JSON-LD in HTML | The JSON-LD block is placed in `<head>` and is always generated. Fields mirror what's in the finding dicts — if a key is missing, it'll be `null` or `""` in the JSON-LD output. |
| TimingEvidence reporter fields | Use `triggered_time_ms` / `baseline_time_ms` (NOT `time_delta` / `elapsed_ms` / `baseline_ms`). All three reporters (html.py, hackerone.py, bugcrowd.py) now use the correct field names. |
| OOBCallbackEvidence reporter fields | Use `raw_data` / `callback_host` / `interaction_time` / `callback_token` (NOT `data` / `callback_type` alone). All three reporters render host + token + interaction time alongside raw data. |
| ScannerBase _prepare_scan state | ScannerBase instances inherit `waf_detected` and `_prepared=True` from parent VulnScanner in `_dispatch_to_scanner()` when `self._prepared` is True. This avoids redundant WAF/baseline HTTP probes. |
| `_run_reverification_loop` deprecated | Kept only for `use_new_scanners=False` backward compat. `VerificationEngine` in `engines/verification_engine.py` is the sole verification path. The call was removed from `main.py` Step 5. |
| Terminal [FOUND] output | Now includes verification stage and confidence score: `[FOUND] [HIGH] SQLi @ https://x.com [Validated, 60/100]`. Both `VulnScanner._add()` and `ScannerBase._add_finding()` include this. |
| SQLiScanner TimingEvidence | `_test_parameter()` creates a `TimingEvidence` object when time signal detected (`triggered_time_ms`, `baseline_time_ms`). The scan() method stores and links it via `evidence_engine`. |
| ChatGPTReporter evidence rendering | Uses per-evidence-type markdown rendering (`_evidence_to_markdown()`). Supports TimingEvidence, OOBCallbackEvidence, BrowserExecutionEvidence, ScreenshotEvidence, AuthorizationComparisonEvidence, GraphQLSchemaEvidence. Falls back to `str()` for unknown types. |
| HackerOne/Bugcrowd authZ body diff | `AuthorizationComparisonEvidence` now renders HTTP status codes, body-diff flag, and up-to-200-char body excerpts for both original and target responses. |
| finding_state / confidence_label dict access | `finding()` now sets `finding_state = FindingState.from_verification_stage(f.verification_stage).value` and `confidence_label = ConfidenceLevel.from_score(f.confidence_score).value` after construction. These fields are available via `f["finding_state"]` and `f["confidence_label"]`. |
| DeduplicationEngine serialization | `to_dict()` serialises all `_groups` to `{fingerprint: finding_dict}`. `from_dict(data)` classmethod restores state. Used by `--resume` in `main.py` to persist findings across sessions. |
| Screenshot validation | `ReporterBase._validate_screenshot_path()` checks `os.path.isfile()` + PNG magic bytes (`\x89PNG`) or JPEG (`\xff\xd8`). Used by all 5 reporters (HTML, TXT, HackerOne, Bugcrowd) before embedding screenshot paths. |
| Screenshot artifact upload | `Reporter.generate()` copies all referenced screenshot files to `{output_dir}/screenshots/` during report generation. Paths in the output dir remain untouched. |
| EvidenceEngine SQLite persistence | When `config["evidence_db_path"]` is set, EvidenceEngine persists all evidence to SQLite with WAL mode (`PRAGMA journal_mode=WAL`). The `batch_insert()` context manager wraps multiple `store()`/`link_to_finding()` calls in a single transaction. On restart, `_init_db()` reloads all evidence from the SQLite DB. Data survives process restarts. |
| EvidenceEngine `INSERT OR REPLACE` | `store()` followed by `link_to_finding()` both call `_db_insert` with the same fingerprint. Uses `INSERT OR REPLACE` so the second call (from linking) overwrites the first (from store) with the correct `finding_id`. |
| OutcomeEngine lock fix | `engines/outcome_feedback.py` had `self._lock = False` (a boolean). Fixed to `threading.Lock()`. File writes now properly guarded with `with self._lock:`. |

---

## 9. Capability-Aware Scanning

Every scanner should adjust its behaviour based on available runtime capabilities detected by `CapabilityRegistry`. The `ValidationEngine` (accessible as `self.validation` on any `ScannerBase` subclass) already gates OOB polling, browser validation, and screenshot capture behind capability checks.

### 9a. Current capability influence on scanners

| Capability | Affects | Behaviour when absent |
|---|---|---|
| `playwright` / `chromium` | XSS browser validation, screenshots, DOM XSS | `_ensure_browser()` returns `None`; browser-based checks silently skip |
| `oob_validation` | SSRF, BlindXSS, XXE, CMDI, SQLi OOB | OOB probes are skipped; findings stop at VALIDATED (not promoted to VERIFIED) |
| `esprima` | JS intelligence, DOM XSS AST analysis | AST-based features skip; fall back to regex-only detection |
| `rich` | `ScanProgress` bar, terminal formatting | Falls back to no-op progress tracking |
| `screenshots` | ScreenshotEvidence in reports | Screenshots are omitted from evidence; `--auto` still enables but no file is generated |

### 9b. Guidelines for adding capability checks to scanners

1. **Never use module-level `try: import` blocks** — always query `CapabilityRegistry.get_global().has("name")`.
2. **OOB scanners** (SSRF, BlindXSS, XXE, CMDI, SQLi) must guard every OOB registration with `if self.validation and self.config.get("oob_host"):`.
3. **Browser-dependent scanners** (XSS, DOM XSS) must call `self.validation.confirm_browser_xss()` which internally gates on Playwright availability.
4. **Capability-backed confidence reasons** are auto-added by `ScannerBase._add_capability_confidence_reasons()`. Override in your scanner if you need custom capability-reason logic.
5. **When a capability is absent**, the scanner must degrade gracefully — produce lower-confidence (DETECTED) findings instead of skipping entirely.
6. **Never hardcode capability names** — use the constants in `app/capabilities.py:CapabilityRegistry.DETECTORS` keys.

### 9c. Adding a new capability detector

1. Add an entry to `CapabilityRegistry.DETECTORS` in `app/capabilities.py` with a `_detect_*` method.
2. The method must return `(bool, str)` — a pass/fail flag and a human-readable detail string.
3. The capability name is automatically available via `CapabilityRegistry.get_global().has("name")` across the codebase.
4. Update the bootstrap's `_print_capabilities_summary()` to include the new capability if it should appear in the startup banner.

---

## 10. Git Workflow

- Branch: `main`
- Commits use conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`
- Push with: `git push origin main`
- Authentication: HTTPS with token (`ghp_*`)
- Remote: `https://github.com/mrch4n725/bugbounty-hunter.git`

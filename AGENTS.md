# BugBounty Hunter — Agent Guide

This document is written for AI coding agents and human contributors. It captures the architecture, conventions, data flow, and critical details needed to work on this codebase effectively without duplicating effort or introducing breaking changes.

---

## 1. Project Overview

BugBounty Hunter is a **high-discovery vulnerability scanner with first-class validation and evidence generation**. It does not choose between being a scanner or a reporting platform — it is both. The project aims to discover the maximum number of real vulnerabilities while automatically validating, documenting, and packaging findings into high-quality reports suitable for rapid triage and responsible disclosure.

### Detection-first philosophy

The scanner prioritizes detection coverage above all else. Every vulnerability class has multiple independent detection signals that fire on different attack vectors. Validation, exploitation, and verification deepen confidence on top of the detection layer. This means:

- **All parameters are scanned** regardless of recon signals — recon-driven targeting reorders, never excludes
- **FP hardening pre-checks** run before probe dispatch to avoid wasted requests (baseline reflection checks, platform detection, parameter name gates)
- **Signal counting** tracks how many independent signals contributed to each finding; `signal_count` is stored on the finding for downstream metrics

Findings progress through stages:

```
Detected → Validated → Exploitable → Verified
```

Each finding carries a confidence score (0–100), evidence strength (Weak/Moderate/Strong/Verified), false-positive risk, CVSS-like severity, and full reproduction steps.

### Data flow

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
  recon_spa.py              — HeadlessReconBrowser: Playwright-based SPA spidering, XHR/fetch capture, runtime params
  external_intel.py         — ExternalIntelligenceGatherer: Shodan, crt.sh, Wayback Machine, GitHub leak search
  passive_import.py          — BurpXmlImporter, HarImporter, CharlesImporter: passive analysis from proxy exports
  mobile_import.py          — MobileApiImporter: Burp/Charles import for mobile API testing
scanners/
  __init__.py               — Exports: all ScannerBase subclasses, discover_scanner_classes()
  base.py                   — ScannerBase with 5-phase lifecycle + finalize() returning list[dict]
  xss.py                    — XSSScanner: reflected, stored, DOM, form, DOM fragment, JSON reflection, SVG XSS
  headers.py                — HeadersScanner: security header audit
  sqli.py                   — SQLiScanner: error-based, boolean, time-based, OOB, second-order, header, JSON body
  ssrf.py                   — SSRFScanner: cloud metadata + OOB callback, redirect DNS, protocol smuggling, DNS timing
  clickjacking.py           — ClickjackingScanner: framing protection (X-Frame-Options/CSP)
  csrf.py                   — CSRFScanner: anti-CSRF token validation
  insecure_forms.py         — InsecureFormsScanner: form action/transport security
  http_methods.py           — HttpMethodsScanner: HTTP method override/fuzzing
  lfi.py                    — LFIScanner: path traversal, log poisoning, zip slip, /proc/self
  open_redirect.py          — OpenRedirectScanner: open redirect with inject_param
  exposed_files.py          — ExposedFilesScanner: common sensitive path probing
  directory_fuzz.py         — DirectoryFuzzScanner: directory enumeration
  subdomain_takeover.py     — SubdomainTakeoverScanner: CNAME-based takeover checks
  sensitive_data.py         — SensitiveDataScanner: secret/key pattern scanning
  ssti.py                   — SSTIScanner: template injection, polyglot, filter bypass, error fingerprint
  rate_limiting.py          — RateLimitingScanner: burst detection with TimingEvidence
  blind_xss.py              — BlindXSSScanner: OOB-based blind XSS
  xxe.py                    — XXEScanner: error/OOB-based, XInclude, SVG upload, JSON-to-XML
  command_injection.py      — CommandInjectionScanner: time/OOB-based, argument injection, Windows CMDI
  graphql.py                — GraphQLScanner: introspection, batching, query depth, auth
  idor.py                   — IdorScannerAdapter: wraps modules.idor.IdorScanner.run_all()
  tech_specific.py          — TechSpecificScannerRegistry: framework-specific probes (WP, Spring, Rails, Laravel, GQL)
  smuggling.py              — RequestSmugglingScanner: CL.TE, TE.CL, TE.TE, HTTP/2 downgrade
  business_logic.py         — BusinessLogicScanner: workflow bypass, race conditions, price manipulation
models/
  config.py                 — ScanConfig dataclass with use_new_scanners: bool
  finding.py                — Finding class with dict-compat shim, strict __getitem__, content-fingerprinted to_dict()
  evidence.py               — EvidenceBase + 12 subclasses (HttpRequest, HttpResponse, ResponseExcerpt, Screenshot, Timing,
                               OOBCallback, AuthorizationComparison, GraphQLSchema, CommandExecution, ResponseDiff,
                               Composite, OwnershipEvidence, ImpactEvidence)
  evidence_bundle.py        — EvidenceBundle: groups evidence by category, computes quality score, submission readiness
  confidence.py             — ConfidenceFactors, ConfidenceContribution, ConfidenceResult
  escalation.py             — EscalationPath, EscalationResult
  metrics.py                — PipelineMetrics: total_signals, promoted counts, funnel, bottleneck, detection_coverage, validation_rate
engines/
  evidence_engine.py        — EvidenceEngine: SHA-256 content-based dedup store(), get_evidence() by finding_id
  submission_readiness.py   — SubmissionReadinessEngine: overrides mechanical from_verification_stage() with evidence-aware assessment
  consensus_engine.py       — ValidationConsensusEngine: pluggable validators, weighted consensus confidence scoring
  ownership_validator.py    — OwnershipValidator: validates ownership claims from AuthorizationComparisonEvidence
  impact_validator.py       — ImpactValidator: validates impact claims from exploitation-proof evidence
  confidence.py             — ConfidenceEngine: unified explainable scoring aggregating evidence quality + ownership + impact + consensus + investigation
  impact_escalation.py      — ImpactEscalationAnalyzer: per-vuln-type escalation maps for IDOR/SSRF/XSS/SQLi/SSTI/LFI/open_redirect/subdomain_takeover
  outcome_feedback.py       — OutcomeFeedbackEngine: thread-safe JSON Lines persistence, historical outcome tracking
  auth_session.py           — AuthSessionManager: OAuth flow, JWT refresh, multi-role sessions, CSRF extraction
  waf_evasion.py            — WafEvasionEngine: WAF fingerprinting, encoding/fragmentation strategy selection
  payload_intelligence.py   — PayloadIntelligenceEngine: effectiveness tracker, per-target context mutation
  semantic_analyzer.py      — SemanticResponseAnalyzer: PII/financial/credential detection, IDOR response comparison
  diff.py                   — ScanDiffEngine: JSON scan comparison, GitHub Actions annotations
  webhook.py                — WebhookNotifier: Slack/Discord posting for high-confidence findings
  audit_log.py              — AuditLogger: per-request CSV audit trail
  footprint.py              — FootprintManager: stealth/normal/aggressive profiles, UA rotation, request signing
  cross_scan_dedup.py       — CrossScanDatabase: SQLite-backed finding persistence across scans, regression detection
  discovery_store.py        — DiscoveryStore: SQLite-backed persistent store for cross-scan intelligence (UUIDs, IDs, roles, ownership hints)
  object_harvester.py       — ObjectHarvester: extracts UUIDs, numeric IDs, emails, JWT tokens, roles, private IPs from HTTP responses
  relationship_graph.py     — RelationshipGraph: infers ownership boundaries from DiscoveryStore data
  multi_account_discovery.py — MultiAccountDiscoveryEngine: cross-account replay across role pairs
  differential_auth.py      — DifferentialAuthorizationEngine: field-level JSON comparison with sensitivity classification
  authorization.py          — AuthorizationEngine: role-based access comparison, cross-account endpoint testing with evidence
  gql_auth.py               — GqlAuthorizationEngine: consumes stored GQL types/fields/relationships as ownership hints
  ownership_discovery.py    — OwnershipDiscoveryEngine: proactive ownership inference from response patterns, URL paths, JWT cross-references, OpenAPI models
  investigation.py          — InvestigationEngine: real HTTP/OOB/browser investigation with cross-account IDOR and differential auth strategies
reporting/
  base.py                   — ReporterBase, assess_finding_impact, group_by_root_cause
  html.py                   — HTMLReporter: type-specific evidence rendering (collapsible, thumbnails, side-by-side)
  json_report.py            — JSONReporter
  txt.py                    — TXTReporter
  prioritization.py         — SubmissionPrioritizer: ranked submission queue by severity/confidence/evidence/validation-rate
  per_finding.py            — PerFindingExporter: standalone per-finding HTML export with all evidence
version.py                  — __version__ = "1.0.0"
CHANGELOG.md                — Release history
```
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

### 2j. FP hardening pre-checks

Every new detection signal is paired with a pre-check gate that runs before the probe is dispatched:

- **Baseline reflection checks**: Send the payload to a param-free URL first; if it reflects, skip the probe (prevents false positives from global reflection)
- **Platform detection**: Check server banner, cookies, or known endpoints before dispatching platform-specific probes (e.g., Windows-only CMDI payloads skip on Linux servers)
- **Parameter name gates**: Skip probes on params that can't possibly accept the payload type (e.g., numeric-only IDs for SSTI)

These pre-checks prevent wasted HTTP requests and false-positive inflation.

### 2k. Signal counting

`signal_count` tracks how many independent detection signals contributed to a finding. It is passed explicitly to `_enrich_finding()` and stored on the finding object. This enables downstream metrics like detection/validation ratio and coverage analysis.

Signal count rules:
- XSS: reflected + DOM fragment + JSON reflection + SVG = up to 4
- SQLi: error + boolean + time + OOB + second-order + header + JSON body = up to 7
- SSRF: cloud metadata + redirect + protocol smuggling + DNS timing + OOB = up to 5
- CMDI: time + OOB + argument injection + Windows = up to 4
- XXE: in-band + error + XInclude + SVG + JSON-to-XML + OOB = up to 6

### 2l. Recon-driven parameter targeting

All parameters are scanned — recon signals only REORDER, never exclude. Targeting prioritizes:

| Scanner | Recon signal used | Priority params |
|---|---|---|
| XSS | JS endpoint context from `js_endpoints` and `js_urls` | Params referenced in JS files first |
| SQLi | RESTful path patterns + baseline timings | Numeric/ID params, slow-query params first |
| SSRF | URL-like param values from original query string | Params with `://` values, then name-matched |
| CMDI | Tool/file-path keyword matching | `cmd`, `exec`, `run`, `shell`, `file`, `path` etc. |
| XXE | XML endpoint detection + param name matching | `.xml`/`.soap` URLs, `xml`/`data`-named params |
| LFI | File-path keyword matching | `file`, `path`, `read`, `include`, `page` etc. |
| SSTI | Template-context keyword matching | `name`, `message`, `content`, `template`, `view` etc. |

### 2m. Per-vuln-type metrics breakdown

Post-scan, the `MetricsCollector` produces a per-vuln-type table (printed after pipeline funnel):

```
Vuln Type       Detected  Validated  Rate      Status
──────────────── ────────  ─────────  ─────     ────────────
xss             12        8          0.67      ✓
sqli            5         1          0.20      ← needs attention
```

Scanners with `validation_rate < 0.5` and `detected >= 2` are flagged for attention. This highlights modules where detection outpaces validation (high FP or low confidence).

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
| `scanners/xss.py` | XSS detection via ScannerBase | `XSSScanner(ScannerBase)`: reflected, stored, DOM, form, DOM fragment, JSON reflection, SVG XSS |
| `scanners/headers.py` | Security header audit via ScannerBase | `HeadersScanner(ScannerBase)` |
| `scanners/sqli.py` | SQLi detection via ScannerBase | `SQLiScanner(ScannerBase)`: error, boolean, time, OOB, second-order, header, JSON body |
| `scanners/ssrf.py` | SSRF detection via ScannerBase | `SSRFScanner(ScannerBase)`: cloud metadata + OOB, redirect DNS, protocol smuggling, DNS timing |
| `models/config.py` | ScanConfig dataclass | `ScanConfig` with `use_new_scanners: bool = True` |
| `models/finding.py` | Finding class with dict-compat shim | `Finding` with strict `__getitem__`, content-fingerprinted `to_dict()` |
| `models/evidence.py` | Evidence type hierarchy (12 subclasses) | `EvidenceBase`, `HttpRequestEvidence`, `BrowserExecutionEvidence`, `ScreenshotEvidence`, `TimingEvidence`, `OOBCallbackEvidence`, `AuthorizationComparisonEvidence`, `GraphQLSchemaEvidence`, `CommandExecutionEvidence`, `ResponseDiffEvidence`, `CompositeEvidence`, `OwnershipEvidence`, `ImpactEvidence` |
| `models/evidence_bundle.py` | Evidence bundle with categorization and quality scoring | `EvidenceBundle`, `BundleCategory` — `from_finding()`, `submission_ready` property |
| `engines/evidence_engine.py`        | Evidence storage with SHA-256 content-based dedup + SQLite persistence (WAL mode, batch inserts) | `EvidenceEngine`, `store()`, `link_to_finding()`, `get_evidence()`, `batch_insert()`, `snapshot()`, `restore()` |
| `engines/dedup.py`                 | Finding deduplication with serialization for resume | `DeduplicationEngine`, `add()`, `add_legacy()`, `get_findings()`, `to_dict()`, `from_dict()` |
| `engines/evidence_validator.py`    | Evidence completeness validation | `EvidenceCompletenessValidator` with `CONFIDENCE_PENALTY` (delta subtraction) |
| `engines/submission_readiness.py`  | Evidence-aware submission readiness assessment | `SubmissionReadinessEngine` — overrides mechanical stage → state mapping |
| `engines/consensus_engine.py`      | Pluggable validator consensus engine | `ValidationConsensusEngine`, `ValidatorVote`, `ConsensusResult` — weighted scoring with 3 built-in validators |
| `engines/ownership_validator.py`   | Ownership claim validation | `OwnershipValidator` — produces `OwnershipEvidence` from authz comparison |
| `engines/impact_validator.py`      | Impact claim validation | `ImpactValidator` — produces `ImpactEvidence` from exploitation-proof evidence |
| `engines/confidence.py`            | Unified explainable confidence scoring | `ConfidenceEngine` — aggregates evidence quality, ownership, impact, consensus, investigation depth into `ConfidenceResult` |
| `engines/impact_escalation.py`     | Per-vuln-type escalation path analysis | `ImpactEscalationAnalyzer` —ESCALATION_MAP with escalation paths for 7 vulnerability types |
| `engines/outcome_feedback.py`      | Historical outcome tracking | `OutcomeFeedbackEngine` — JSON Lines persistence, `record_outcome()`, `get_stats()`, `has_positive_outcome()` |
| `engines/evidence_validator.py`    | Evidence completeness validation | `EvidenceCompletenessValidator` with `CONFIDENCE_PENALTY` (delta subtraction) |
| `engines/discovery_store.py`       | Cross-scan intelligence persistence | `DiscoveryStore` — SQLite-backed (WAL), SHA-256 dedup, categories: numeric_id/uuid/email/jwt/role/ownership_hint |
| `engines/object_harvester.py`      | Object extraction from responses | `ObjectHarvester` — JSON-traversal + regex extraction, JWT claim decoding, stores into DiscoveryStore |
| `engines/relationship_graph.py`    | Ownership boundary inference | `RelationshipGraph` — maps URLs to harvested IDs, `get_ownership_boundaries()`, `get_auth_candidates()` |
| `engines/multi_account_discovery.py` | Cross-account replay | `MultiAccountDiscoveryEngine` — replays all URLs across role pairs for IDOR discovery |
| `engines/differential_auth.py`     | Field-level response comparison | `DifferentialAuthorizationEngine` — recursive JSON diff with sensitivity classification (pii/financial/credential/ownership/internal) |
| `engines/authorization.py`         | Role-based access comparison | `AuthorizationEngine` — tests endpoints across roles, produces AuthorizationComparisonEvidence |
| `engines/gql_auth.py`              | GQL schema auth intelligence | `GqlAuthorizationEngine` — reads stored GQL types/fields, builds ownership hints and relationships |
| `engines/ownership_discovery.py`   | Proactive ownership inference | `OwnershipDiscoveryEngine` — infers ownership from response JSON patterns, URL paths, JWT cross-refs, OpenAPI models |
| `engines/investigation.py`         | Multi-strategy investigation | `InvestigationEngine` — real HTTP/OOB/browser probes, cross-account IDOR, differential auth, 20+ strategies |
| `models/confidence.py`            | Confidence data model | `ConfidenceFactors`, `ConfidenceContribution`, `ConfidenceResult` |
| `models/escalation.py`            | Escalation data model | `EscalationPath`, `EscalationResult` |

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
- Current test count: **359 tests** (all passing)
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
| Finding.evidence normalization | `Finding.__post_init__` normalizes evidence to always be a `list`. If a string is passed, it becomes `[str]` or `[]` if empty. Downstream code can safely treat `Finding.evidence` as a list. For raw dicts (legacy code paths, reporters handling imports), still guard with `isinstance(evidence, str)`. |
| Reporter evidence access | Reporters prefer `getattr(f, 'evidence', None)` for Finding instances (returns the list). Falls back to `f.get("evidence", "")` for plain dicts. Finding.__getitem__ returns the raw list for "evidence" key. |
| Adding typed evidence to findings | Evidence is always a list on Finding instances. Append directly: `f.evidence.append(typed_ev)`. For raw dicts, use the safe pattern: `ev_list = f.get("evidence", [])` / `if isinstance(ev_list, str): ev_list = [ev_list] if ev_list else []` / `ev_list.append(typed_ev)` / `f["evidence"] = ev_list`. |
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
| BusinessLogicDiscoveryEngine wired post-OwnershipDiscovery | Runs after ownership discovery in orchestrator post-scan pipeline. Stores candidates in `config["_business_logic_candidates"]` for main.py consumption. |
| Candidate auto-investigation in main.py | High-yield candidates (yield_rank >= 0.5) are auto-investigated via `InvestigationEngine.investigate_candidate()` which creates lightweight Finding-like contexts from LogicAbuseCandidate fields. Runs within the `"investigation"` disabled_engines gate. |
| investigate_candidate Finding stub | Creates a fake Finding with fingerprint = SHA-256 of abuse_url. Evidence is stored under this fingerprint. The fake finding is not persisted or deduped — it's purely for investigation context. |
| BusinessLogicScanner abuse_pattern | Set via `f["abuse_pattern"] = AbusePattern.X.value` on Finding instances, stored as dynamic attribute. Serialized in `Finding.to_dict()` via `hasattr(self, "abuse_pattern")` check. Not a dataclass field — survives dict round-trips only via explicit hasattr in to_dict. |
| WorkflowRiskModel.has_form derived from steps | The risk assessment checks `any(s.has_form for s in wf.steps)` rather than a `BusinessWorkflow.has_form` field. Step has_form is set by form analysis. |
| Witness category used correctly | `get_by_category("witness")` is the correct call in DiscoveryStore. The category is `"witness"`, not `"witnesses"`. |
| Ownership/Impact evidence lost | `OwnershipValidator.validate()` and `ImpactValidator.validate()` return values were discarded in `main.py` (lines 836-848). The evidence objects were never attached to findings. **Fixed**: return values are now captured and appended to `finding.evidence`, then linked via `evidence_engine`. |
| ReplayEngine no-op | `ReplayEngine.build_bundle()` was never called from `main.py`, so `compare_across_scans()` always found zero bundles and regression detection was a silent no-op. **Fixed**: `build_bundle()` called for each finding before comparison. |
| InvestigationEngine real but shallow | `InvestigationEngine._execute_task()` now makes real HTTP requests (redirect follows, OOB callbacks, SSRF internal/cloud probes, SQLi timing/error detection, LFI path-traversal, SSTI template eval, open-redirect Location checks, IDOR probes). However `boolean_sqli` is still a no-op (empty `continue` branch). Confidence boosts remain hardcoded per strategy (not evidence-derived). IDOR investigation only checks `status==200` with no content comparison. |
| VerificationEngine dead code | `VerificationEngine` was imported and instantiated in `main.py` but `verify_all()` was never called. The instantiation was removed. OOB background poller + scanner-level validation is the current active verification path. |
| SPA recon bugs fixed | `_run_spa_recon()` in `main.py` had 3 bugs: (1) `xhr_endpoints` → `xhr_calls`, (2) `config_objects` with `.update()` → `js_endpoints` (list), (3) `detect_frameworks()` method didn't exist → now reads `tech_stack` from spider results. XHR/API endpoint URLs extracted from dict structures. |
| OutcomeFeedbackEngine loop closed | `record_outcome()` is now called for every finding in `orchestrator.py` right after confidence scoring. All findings are recorded as `"detected"` outcomes, populating `outcomes.jsonl` for future `has_positive_outcome()` checks. |
| Candidate exploitation in orchestrator | After business logic discovery, up to 10 top-ranked candidates are routed to `RaceConditionTester`, `PriceManipulationTester` for same-scan exploitation. Findings are tagged with `_from_candidate` attribute. Uses a `forms_by_action` lookup map to resolve abuse URLs to form data for tester probes. Wrapped in `try/except` in case session or imports fail. |
| Candidate exploitation dedup merge | Candidate-exploitation findings share dedup keys with normal BL scanner findings. `DeduplicationEngine.add()` now merges `_from_candidate` from incoming into existing findings, and upgrades verification_stage if the incoming is higher. The tag survives serialization via `Finding.to_dict()`/`from_dict()`. `investigate_candidate()` also tags its fake Finding with `_from_candidate`. |
| Container and Engine wiring gaps | `ValidationConsensusEngine` (consensus result set on findings but not rendered in reports), `DuplicateRiskEngine` (result set on finding but not in report output). OutcomeFeedbackEngine loop is now closed. |
| GraphQLAuthorizationMapper plan storage | `GraphQLAuthorizationMapper.store_plans()` stores plans with category `gql_auth_plan`. `main.py` reads `gql_auth_plan` from DiscoveryStore post-scan and logs high-confidence plans. Plans span 4 plan types: cross_tenant, ownership_violation, role_escalation, mutation_authorization. |
| GraphQL engine pipeline order | GQL auth pipeline (3 phases) runs in orchestrator after TARGET_LEVEL modules but before evidence validation. This means auth plans are available for cross-scan consumption but not same-scan. `main.py` reads plans post-scan for investigation queueing. |
| GraphQLRelationshipEngine classification | Uses 5 relationship types: BELONGS_TO, HAS_MANY, TENANT_OF, OWNS_THROUGH, MEMBER_OF + GQL_ASSOCIATION fallback. Classification is purely field-name-based (owner→BELONGS_TO, tenant_id→TENANT_OF, plural→HAS_MANY). Confidence scores range 0.4–0.8 based on keyword specificity. |
| GqlAuthorizationEngine preserved | The old `GqlAuthorizationEngine` is still importable at `engines.gql_auth` but no longer wired in orchestrator. The new pipeline (`GraphQLRelationshipEngine` → `GraphQLOwnershipDiscovery` → `GraphQLAuthorizationMapper`) is a superset. |
| Ownership chain inference | `GraphQLRelationshipEngine.infer_ownership_chains()` follows BELONGS_TO edges to length-2 chains. A→B and B→C produces A OWNS_THROUGH C via "field→field2". Chain confidence = product of both confidences × 0.8. |
| signal_count field | `_enrich_finding()` requires explicit `signal_count=` kwarg when called from scanners that report multiple signals. Defaults to 1 if not passed. Always pass the count when merging multiple detection signals into one finding. |
| Recon-driven param sort | `params.sort(key=...)` in scanner scan() methods sorts params in-place by recon priority. All params are still scanned — priority params go first. The sort is a no-op when recon data is absent. |
| Per-vuln-type metrics table | Printed after pipeline funnel. `validation_rate` is `validated / detected`. Scanners with rate < 0.5 and detected >= 2 get a `← needs attention` flag. Available via `MetricsCollector.per_vuln_type_table()`. |
| Subdomains auto-injected into scanner URLs | Live subdomains from DNS + crt.sh are automatically added to `self.urls` as `https://{sub}` + `http://{sub}` in `recon.run()`. No configuration needed. |
| JS endpoint injection into URL pool | Both `main.py`'s JS intelligence loop and the legacy `recon.mine_js_bundles()` path feed discovered JS endpoints + hidden endpoints into `recon_data["urls"]` for scanner consumption. |
| Param fuzzing expanded | No hardcoded 50-path cap — uses `max_fuzz_urls` config (default 200). Query-string URLs are no longer skipped — params are appended to existing query strings. Active params tracked in `_fuzzed_params` dict (`url → [param_names]`). |
| 401/403 bypass probing | `_probe_common_paths()` now probes blocked endpoints with 12 bypass header techniques (X-Forwarded-For, X-Original-URL, X-Rewrite-URL, X-Real-IP, X-ProxyUser-IP, X-Client-IP, Client-IP, X-Auth-Token, Basic auth). |
| GQL discovery expanded to 21+ paths | GraphQL endpoint discovery probes 21 static paths (was 9), plus 6 query-param paths (`/api?query={__typename}`), plus 6 WebSocket GQL paths. |
| `fuzzed_params` now consumed by IDOR scanner | `recon_data['fuzzed_params']` is now read by `IdorScanner._find_id_parameters()` — fuzzed params are added as IDOR candidates. |
| `html_comments` now consumed by orchestrator | `recon_data['html_comments']` is now consumed in `orchestrator.py` — URLs and params extracted from comments are injected into the scan URL pool. |
| `js_endpoints` returns used as boolean only | `recon_data['js_endpoints']` is only consumed by `classify_endpoint()` as a boolean signal (`is_json_api`). The actual endpoint URLs are fed into the URL pool via separate paths. |
| `authenticated` flag has no behavioral impact | The `recon_data['authenticated']` boolean is printed as a warning but no scanner changes its behavior based on it. |
| SPA Recon (`HeadlessReconBrowser`) not integrated | 965 lines of SPA analysis (XHR capture, form interaction, runtime params, framework detection) exist in `recon_spa.py` but `HeadlessReconBrowser` is never instantiated in `main.py`. The `--spa-recon` CLI flag exists but connects to nothing. |
| ConfidenceEngine + ImpactEscalationAnalyzer added | `ConfidenceEngine` in `engines/confidence.py` aggregates evidence quality + ownership + impact + consensus + investigation depth into unified explainable scoring. `ImpactEscalationAnalyzer` in `engines/impact_escalation.py` provides per-vuln-type escalation maps (IDOR/SSRF/XSS/SQLi/SSTI/LFI/open_redirect/subdomain_takeover). Both wired via container. |
| DiscoveryStore (SQLite) | `engines/discovery_store.py` — persistent store for cross-scan discovery intelligence. SQLite-backed with WAL mode. Uses SHA-256 fingerprinting for dedup. Records carry category, value, source_url, extra JSON blob, timestamps, hit_count. Access via `container.discovery_store`. Database path configurable via `discovery_db_path`. |
| ObjectHarvester | `engines/object_harvester.py` — extracts UUIDs, numeric IDs, emails, JWT tokens, roles, private IPs, API keys from HTTP response text. Stores into DiscoveryStore. Hooked into `ScannerBase._add_finding()` and `orchestrator.py` post-scan pipeline. Access via `container.object_harvester`. Also runs pre-scan on recon data (forms, JS files) before TARGET_LEVEL modules to feed early IDs into auth scanners. |
| RelationshipGraph | `engines/relationship_graph.py` — infers ownership boundaries from DiscoveryStore data. `get_ownership_boundaries()` returns URL pattern → ID mappings. `get_auth_candidates()` returns candidate endpoints for IDOR testing. Used by `AuthorizationScanner` to discover auth candidates. Access via `container.relationship_graph`. |
| Multi-Account Discovery Engine | `engines/multi_account_discovery.py` — `MultiAccountDiscoveryEngine` coordinates cross-account replay across role pairs. Uses `AuthorizationEngine.test_endpoint()` for pairwise comparisons. Discovers candidates via RelationshipGraph + recon_data. Wired into `main.py` after `run_scans()` when 2+ role sessions exist. |
| OwnershipDiscoveryEngine | `engines/ownership_discovery.py` — `OwnershipDiscoveryEngine` proactively infers ownership relationships from: (1) response JSON patterns linking IDs to owners, (2) URL path hierarchy patterns, (3) JWT sub claim cross-references with resources, (4) OpenAPI model properties, (5) schema patterns across the store. Runs in orchestrator post-scan pipeline. Stores results as `ownership_hint` and `ownership_relationship` records. |
| DifferentialAuthorizationEngine | `engines/differential_auth.py` — compares JSON responses field-by-field with sensitivity classification. Detects subtle auth flaws where both users get HTTP 200 but with different data (extra PII/financial/credential fields, missing fields, different values at ownership-sensitive keys). Integrated into `AuthorizationEngine.test_endpoint()`. |
| GqlAuthorizationEngine | `engines/gql_auth.py` — reads stored `gql_type`, `gql_field`, `gql_relationship` categories from DiscoveryStore. Feeds GQL-derived ownership hints (owner_id/creator/user fields) and type-to-type relationships back into the store for RelationshipGraph consumption. |
| Investigation cross-account IDOR | `InvestigationEngine` now has `cross_account_idor` strategy that compares responses across multiple role sessions with `AuthorizationComparisonEvidence`, and `differential_auth` strategy that does field-level JSON diff. Both produce high-confidence evidence even when status codes match. |
| Investigation → DiscoveryStore feedback | Post-investigation in `main.py`, confirmed findings (confidence >= 60, stage validated/verified) feed `confirmed_endpoint` and `validated_resource` records back into DiscoveryStore, closing the discover→learn→discover-more loop intra-scan. |
| Finding.to_dict() includes escalation | `Finding.to_dict()` serializes `_escalation_result` and `_best_escalation_path` dynamic attributes, visible in JSON and all report formats. |
| GQL auth uses real field selectors | `_build_gql_selection_set()` builds field selectors from discovered schema types instead of `{ __typename }`. `_test_query_auth()` uses discovered type fields for meaningful cross-role comparison. Candidate types inferred by stripping mutation name prefixes. |
| JWT decoding at harvest time | `ObjectHarvester._harvest_jwt_claims()` decodes JWT tokens: extracts `sub` (as uuid/numeric_id/email), `roles`/`groups` (as `role` records), `org_id`/`tenant_id` (as `ownership_hint` records). Done at harvest time, not query time. |
| AuthorizationScanner GQL integration | `scanners/authorization.py` now feeds GQL mutation endpoints from recon into the url pool, plus querying RelationshipGraph for auth candidates from DiscoveryStore. |
| JS intelligence keys recovered | 6 previously discarded JS intelligence keys are now populated and consumed: `feature_flags`, `hardcoded_values`, `internal_apis`, `tokens`, `suspicious_patterns`, `graphql_endpoints`. Internal/same-domain URLs from internal_apis and graphql_endpoints are fed into the scan URL pool. |
| Passive import merge_into_recon | `ImportResult.merge_into_recon(recon_data)` handles key-name differences (`parameters` → `params`, `tech_stack` → `technology`) and feeds `api_endpoint` URLs into the URL pool. Extra intelligence stored under `_imported_*` keys for downstream consumption. |
| OpenAPI/GQL endpoint injection | `ApiScanner.run_all()` now feeds discovered OpenAPI spec endpoints and GQL endpoints back into `recon_data["urls"]` so downstream scanners can consume them. |
| ObjectHarvester in ScannerBase | `ScannerBase._add_finding()` harvests objects from every finding's `response_excerpt` (when container has `object_harvester`). This means IDOR/SSRF/XSS/SQLi findings automatically contribute discovered IDs to the store. |

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

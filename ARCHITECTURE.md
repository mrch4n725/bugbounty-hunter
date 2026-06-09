# Architecture Assessment & Migration Plan

## Executive Summary

BugBounty Hunter has **two runtimes** that coexist in a layered hybrid:
the **Legacy Runtime** (`VulnScanner` inline methods in `modules/scanner.py`)
and the **New Runtime** (25 `ScannerBase` subclasses in `scanners/` +
`VerificationEngine` + `EvidenceEngine` + `ApplicationContainer`).

The new runtime is **functionally complete** — all 25 scanners exist, all 214
tests pass — and `main.py` routes through `module_map` dict
pointing to `VulnScanner.scan_*` methods. Every `scan_*` method is a router
that tries `_dispatch_to_scanner()` first, then falls back to its own inline
legacy logic.

**Goal:** Make the new architecture the *primary* execution path. Legacy code
remains as adapters for backward compatibility.

---

## 1. Current Architecture

```
main.py:main()
  │
  ├── bootstrap(config) → (capabilities, container)
  ├── _run_recon_if_needed() → recon_data
  ├── _run_scans()
  │   │
  │   ├── VulnScanner.__init__(config, recon_data, container)
  │   │     ├── DeduplicationEngine (shared dedup)
  │   │     ├── OOBDetectionFramework
  │   │     ├── BrowserValidator
  │   │     ├── ValidationEngine / EvidenceEngine (from container)
    │   │     └── ScannerBase lazy instances (25 classes via discover_scanner_classes)
  │   │
  │   ├── Build module_map {name: VulnScanner.scan_*}  ← LEGACY ORCHESTRATION
  │   ├── Run TARGET_LEVEL modules
  │   │     └── Each scan_*() calls _dispatch_to_scanner() → ScannerBase.scan()
  │   │                                            └─→ fallback to inline code
  │   ├── Score/sort URLs
  │   ├── For each URL:
  │   │     ├── classify_endpoint() → applicable modules
  │   │     └── per_url_modules[name](target_urls=[url])
  │   │           └── scan_*() → _dispatch_to_scanner() → ScannerBase.scan()
  │   │                                          └─→ fallback to inline code
│   └── Post-scan pipeline:
│         ├── _get_findings() → prioritize_findings()
│         ├── VerificationEngine.verify_all()
│         ├── chain_analysis()
│         ├── check_self_halt()
│         ├── DuplicateRiskEngine.assess()        ← dedup + risk scoring
│         ├── ImpactEngine.assess()               ← CVSS + impact narrative
│         ├── MetricsCollector.collect()           ← pipeline funnel + bottleneck
│         ├── compare_across_scans()               ← regression detection
│         │     └── result stored in config["_regressions"]
│         └── Merge with TARGET_LEVEL findings
  │
  └── Reporter.generate()
        └── modules/reporter.py (adapter) → reporting/ package
```

---

## 2. Dependency Analysis

### Layer 1: Core Models (no dependencies on other layers)

```
models/finding.py        → models/evidence.py
models/evidence.py       → (none)
models/config.py         → (none)
```

### Layer 2: Infrastructure / Engines

```
engines/validation_engine.py  → modules/utils.py, models/
engines/evidence_engine.py    → models/evidence.py
engines/verification_engine.py → modules/utils.py, models/finding.py
engines/oob_poller.py         → (std lib + callable)
```

### Layer 3: Scanner Layer

```
scanners/base.py          → modules/utils.py, engines/
scanners/xss.py           → scanners/base.py, modules/utils.py, models/
  ... (all 25 scanners)     (same pattern)
```

### Layer 4: Application Bootstrap

```
app/bootstrap.py          → app/container.py, app/capabilities.py
app/container.py          → app/capabilities.py, engines/
app/capabilities.py       → (std lib only)
```

### Layer 5: Orchestration (Legacy)

```
modules/scanner.py        → modules/utils.py, engines/, models/
  VulnScanner class — contains 26 scan_* methods + dispatchers
modules/api_scanner.py    → modules/scanner.py (subclass)
modules/idor.py           → modules/utils.py, models/
modules/reporter.py       → modules/utils.py, reporting/
main.py                   → all of the above
```

### Circular Dependencies

- `modules/utils.py` → `models/finding.py` → ✅ clean
- `modules/scanner.py` → `engines/` → `modules/utils.py` → ✅ acyclic but **deeply coupled**
- `scanners/base.py` → `modules/utils.py` → ✅ clean (shared utils only)

**No circular dependency exists**, but `modules/scanner.py` has 25 tightly
coupled inline scan methods that each import from `modules/utils.py` and
`engines/`.

---

## 3. Runtime Coexistence Map

| Component | Legacy | New | Hybrid | Notes |
|---|---|---|---|---|
| Scanner orchestration | `module_map` | — | ✅ | main.py routes through legacy names |
| XSS scanner | inline | `XSSScanner` | ✅ | _dispatch_to_scanner fallback |
| SQLi scanner | inline | `SQLiScanner` | ✅ | _dispatch_to_scanner fallback |
| SSRF scanner | inline | `SSRFScanner` | ✅ | _dispatch_to_scanner fallback |
| LFI scanner | inline | `LFIScanner` | ✅ | _dispatch_to_scanner fallback |
| SSTI scanner | inline | `SSTIScanner` | ✅ | _dispatch_to_scanner fallback |
| XXE scanner | inline | `XXEScanner` | ✅ | _dispatch_to_scanner fallback |
| CMDI scanner | inline | `CommandInjectionScanner` | ✅ | _dispatch_to_scanner fallback |
| Open redirect | inline | `OpenRedirectScanner` | ✅ | _dispatch_to_scanner fallback |
| Headers | inline | `HeadersScanner` | ✅ | _dispatch_to_scanner fallback |
| CSRF | inline | `CSRFScanner` | ✅ | _dispatch_to_scanner fallback |
| Clickjacking | inline | `ClickjackingScanner` | ✅ | _dispatch_to_scanner fallback |
| HTTP methods | inline | `HttpMethodsScanner` | ✅ | _dispatch_to_scanner fallback |
| Insecure forms | inline | `InsecureFormsScanner` | ✅ | _dispatch_to_scanner fallback |
| Directory fuzz | inline | `DirectoryFuzzScanner` | ✅ | _dispatch_to_scanner fallback |
| Exposed files | inline | `ExposedFilesScanner` | ✅ | _dispatch_to_scanner fallback |
| Subdomain takeover | inline | `SubdomainTakeoverScanner` | ✅ | _dispatch_to_scanner fallback |
| Sensitive data | inline | `SensitiveDataScanner` | ✅ | _dispatch_to_scanner fallback |
| Rate limiting | inline | `RateLimitingScanner` | ✅ | _dispatch_to_scanner fallback |
| Blind XSS | inline | `BlindXSSScanner` | ✅ | _dispatch_to_scanner fallback |
| GraphQL | inline | `GraphQLScanner` | ✅ | _dispatch_to_scanner fallback |
| IDOR | inline | `IdorScannerAdapter` | ✅ | _dispatch_to_scanner fallback |
| OpenAPI | inline | `OpenAPIScanner` | ✅ | _dispatch_to_scanner fallback |
| API scanner | `ApiScanner` | — | ✅ | separate class, no ScannerBase |
| Verification engine | `_run_reverification_loop` | `VerificationEngine` | ✅ | verification_engine.py used post-scan |
| Evidence engine | — | `EvidenceEngine` | ✅ | Only in new path |
| Dependency injection | — | `ApplicationContainer` | ✅ | Used by both paths |
| Reporter | `modules/reporter.py` | `reporting/` package | ✅ | Wrapper delegates to new |
| Payload definitions | `modules/scanner.py` | scanner-specific | ✅ | Duplicated |
| Deduplication | `DeduplicationEngine` (old) | `DeduplicationEngine` (new) | ✅ | Same class, now Finding-native |

### Key Finding

**Every single module is in the "Hybrid" state.** There is NO module that runs
exclusively on the new path. The `--legacy-scanners` flag controls whether
`_dispatch_to_scanner()` is called or not, but the orchestration always flows
through `VulnScanner.scan_*` methods in `modules/scanner.py`.

---

## 4. Target Architecture

```
main.py:main()
  │
  ├── bootstrap(config) → (capabilities, container)
  ├── _run_recon_if_needed() → recon_data
  ├── ScanOrchestrator(config, recon_data, container).run()
  │   │
  │   ├── discover_scanner_classes() → scanner registry
  │   ├── ScannerLifecycle:
  │   │     ├── init(scanner_cls, config, recon, container)
  │   │     ├── prepare()  (WAF, baselines, tech fingerprint)
  │   │     ├── scan(target_urls) → list[Finding]
  │   │     ├── validate(findings) → list[Finding]   ← VerificationEngine integrated
  │   │     └── finalize() → list[Finding]
  │   │
  │   ├── TARGET_LEVEL scanners run first
  │   ├── Per-URL scanners dispatched by classify_endpoint()
  │   ├── Chain analysis + self-halt
  │   │
  │   └── Findings → prioritize_findings()
  │
  ├── OOBBackgroundPoller (managed by container)
  └── Reporter.generate()
```

---

## 5. Migration Plan (4 Phases)

### Phase 1: ScanOrchestrator (main.py refactor)

**Goal:** Replace the `module_map` dict with a ScannerBase-first dispatch.

**Changes:**
1. Create `app/orchestrator.py` — `ScanOrchestrator` class that:
   - Calls `discover_scanner_classes()` to build the scanner registry
   - Separates TARGET_LEVEL from per-URL scanners via `cls.TARGET_LEVEL`
   - Handles `--modules` and `--disable-modules` filtering
   - Manages the per-URL loop with `classify_endpoint()`
   - Calls `inst.scan()` and `inst.finalize()` directly (no `_dispatch_to_scanner`)
   - Collects findings from `inst._get_findings()` (ScannerBase already has it)
   - Runs `VerificationEngine.verify_all()` as a separate step
   - Handles chain_analysis, check_self_halt, prioritize_findings

2. `main.py:_run_scans()` calls `ScanOrchestrator(config, recon_data, container).run()`

3. `VulnScanner.__init__` no longer creates ScannerBase instances (that moves to orchestrator)

**Result:** `main.py` is unaware of individual module names. Scanner discovery
is driven by the `scanners/` package.

### Phase 2: Strip Inline Logic from VulnScanner.scan_* Methods

**Goal:** Each `scan_*()` method becomes a thin adapter that delegates to
`_dispatch_to_scanner()` and does NOT fall back to inline logic.

**Changes:**
1. For each scan method, verify the ScannerBase subclass produces equivalent
   results (cross-check confidence scores, evidence types, dedup behavior)
2. Remove the inline fallback code block from each `scan_*()` method
3. Set `SCANNER_MATURITY >= 1` on all scanners (already done)

**Result:** `modules/scanner.py` scan methods become one-liners:
```python
def scan_xss(self, target_urls=None):
    return self._dispatch_to_scanner("xss", target_urls)
```

### Phase 3: Eliminate modules/scanner.py Indirection

**Goal:** Remove `VulnScanner.scan_*()` methods entirely. The orchestrator
calls ScannerBase subclasses directly.

**Changes:**
1. Move shared utilities from `VulnScanner` to `ScannerBase` or `modules/utils.py`:
   - `_inject_param` → `ScannerBase` or static util
   - `_run_threaded` → already on `ScannerBase`
   - `_load_payloads` → already on `ScannerBase`
   - `_detect_waf`, `_fingerprint_baselines`, `_fingerprint_tech` → already on `ScannerBase`
   - `_promote_finding_by_oob` → move to `VerificationEngine`
   - `_record_second_order`, `_check_second_order` → move to scanner-specific logic
   - Payload constants → YAML files or scanner-specific constants

2. ~~Remove dependency of `ApiScanner` and `modules/idor.IdorScanner` on
   `VulnScanner` (they subclass it) — make them standalone or provide mixins~~ ✅ DONE — ApiScanner/IdorScanner now inherit only from ScannerModuleBase (Task 1)

3. `VulnScanner` becomes empty or is removed entirely

4. `DeduplicationEngine` instance moves to `ScanOrchestrator` or remains
   shared at the container level

**Result:** `modules/scanner.py` is removed. No code depends on `VulnScanner`.

### Phase 4: Container-Owned Lifecycle

**Goal:** The `ApplicationContainer` owns the full lifecycle.

**Changes:**
1. `ApplicationContainer` creates `ScanOrchestrator` as a property
2. `ApplicationContainer.run_scan()` is the single entry point
3. `main.py` becomes:
   ```python
   capabilities, container = bootstrap(config)
   findings = container.run_scan(recon_data)
   Reporter(config, findings, recon_data, container=container).generate()
   ```
4. OOB poller lifecycle managed by container (start/stop)
5. Evidence engine is the sole evidence store; reporters read from it

**Result:** Clean layered architecture:
```
Bootstrap → Container → Scanner Lifecycle → Validation → Evidence → Reporting
```

---

## 6. Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| ScannerBase produces different findings than inline | Medium | Low | ScannerBase is now the default (`use_new_scanners=True`). `--legacy-scanners` available for comparison. |
| ApiScanner/IdorScanner depend on VulnScanner | High | Certain | Refactor to standalone classes or mixins (Phase 3) |
| Shared state (dedup, WAF detection) breaks | Medium | Low | Keep DeduplicationEngine at orchestrator level |
| `classify_endpoint()` needs ScannerBase metadata | Low | Low | Check `SCANNER_NAME` against classification set |
| Payload duplication causes inconsistent testing | Medium | Medium | Consolidate to YAML files or single source of truth |
| Regression from removing inline fallback | High | Medium | Add integration test mode: run both paths, diff findings |

---

## 7. Effort Estimate

| Phase | Files Changed | Estimated Effort | Dependencies |
|---|---|---|---|
| Phase 1: ScanOrchestrator | +`app/orchestrator.py`, main.py | 2-3 days | None |
| Phase 2: Strip inline logic | 25 scanner .py files + modules/scanner.py | 2-3 days | Phase 1 |
| Phase 3: Eliminate VulnScanner | `modules/scanner.py`, `modules/api_scanner.py`, `modules/idor.py`, `scanners/idor.py` | 3-4 days | Phase 1-2 |
| Phase 4: Container lifecycle | `app/container.py`, `main.py` | 1-2 days | Phase 3 |
| **Total** | ~25 files | 8-12 days | — |

---

## 8. Verification Strategy

1. After each phase, run `python3 tests/run.py` (214 tests must pass)
2. Phase 2 cross-check: add `--compare-scanners` mode that runs both
   `_dispatch_to_scanner()` AND inline logic, diffs findings, warns on mismatches
3. Full integration: `python3 main.py --target http://testphp.vulnweb.com --auto`
   — compare reports before and after each phase

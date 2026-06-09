# Validation Maturity Audit

## Scoring Key

Each scanner is assessed across five dimensions (0–5):

| Dimension | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| **Detection** | None | Naive pattern match | Structured detect() | Multi-signal detection | Context-aware detection | Chain/correlated detection |
| **Validation** | None | Manual review needed | Single confirm signal | Multi-signal confirm | Replay/independent confirm | Automated verified |
| **Evidence** | None | String evidence only | 1 typed evidence type | 2+ evidence types | Stored & linked via engine | Evidence drives confidence |
| **Reproduction** | None | Text steps | Parametrized steps | Multi-stage steps | Automated reproduction | Scripted PoC |
| **Confidence** | None | Hardcoded 100% | Threshold-based | Dynamic calculation | ML/score-based | Self-calibrating |

## Maturity Matrix

| # | Scanner | SCANNER_MATURITY | Detection | Validation | Evidence | Reproduction | Confidence | Typed Evidence | evidence_engine | Linked | Gaps |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | **XSS** | 4 | 4 | 5 | 4 | 3 | 1 | HttpRequest, HttpResponse, ResponseExcerpt, BrowserExecution, Screenshot | Yes | Yes | No confidence_score |
| 2 | **SQLi** | 4 | 4 | 4 | 4 | 2 | 1 | Timing, HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score; timing evidence only for time-based |
| 3 | **SSRF** | 4 | 4 | 3 | 2 | 2 | 3 | HttpRequest, ResponseExcerpt, OOBCallback | Yes | Yes | collect_evidence stores request+response evidence; OOB callback evidence stored and linked post-poll. Dynamic confidence scoring via _calculate_ssrf_confidence(). |
| 4 | **BlindXSS** | 4 | 3 | 4 | 4 | 3 | 1 | HttpRequest, OOBCallback | Yes | Yes | Fix 5 added HttpRequestEvidence for injection requests. OOB callback evidence stored and linked. |
| 5 | **CMDI** | 4 | 4 | 4 | 4 | 2 | 1 | Timing, HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |
| 6 | **XXE** | 4 | 4 | 4 | 4 | 2 | 1 | HttpRequest, ResponseExcerpt, OOBCallback | Yes | Yes | No confidence_score |
| 7 | **Authorization** | 4 | 4 | 4 | 5 | 3 | 1 | AuthorizationComparison | Yes | Yes | No confidence_score |
| 8 | **SSTI** | 4 | 3 | 3 | 2 | 3 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | collect_evidence stores request+response evidence for each stage. 3-stage pipeline (detect→validate→exploit) with evidence per stage. No dynamic confidence. |
| 9 | **SensitiveData** | 3 | 3 | 1 | 3 | 2 | 1 | HttpRequest, ResponseExcerpt, SecretValidation | Yes | Yes | Only pattern-matching; no validation beyond regex |
| 10 | **IDOR** | 3 | 3 | 3 | 4 | 3 | 1 | AuthorizationComparison (via modules/idor.py) | Yes | Yes | No confidence_score |
| 11 | **Headers** | 4 | 4 | 2 | 3 | 3 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | ⚡ Addressed — Fix 4 added HttpRequestEvidence + ResponseExcerptEvidence storage and linking. Multi-signal detection (missing headers, info disclosure, CSP, cookies, CORS). Context-aware reproduction. |
| 12 | **LFI** | 2 | 3 | 2 | 2 | 3 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |
| 13 | **OpenRedirect** | 3 | 3 | 2 | 2 | 3 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No dynamic confidence_score |
| 14 | **ExposedFiles** | 2 | 2 | 1 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |
| 15 | **GraphQL** | 2 | 3 | 1 | 2 | 2 | 1 | GraphQLSchema | Yes | Yes | No validation beyond introspection detection |
| 16 | **OpenAPI** | 2 | 2 | 1 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No validation beyond path discovery |
| 17 | **CSRF** | 2 | 2 | 0 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No actual request made during form analysis (passive); typed evidence stores request metadata and response excerpt |
| 18 | **Clickjacking** | 2 | 2 | 1 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | Header check only |
| 19 | **HttpMethods** | 2 | 2 | 1 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No validation beyond status code |
| 20 | **InsecureForms** | 2 | 2 | 0 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | Typed evidence stores form action metadata and response content |
| 21 | **DirectoryFuzz** | 3 | 2 | 1 | 2 | 2 | 1 | ResponseExcerpt | Yes | Yes | No HttpRequest evidence; only ResponseExcerpt stored |
| 22 | **SubdomainTakeover** | 3 | 2 | 0 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No dynamic confidence_score |
| 23 | **RateLimiting** | 3 | 2 | 1 | 2 | 2 | 1 | Timing | Yes | Yes | No dynamic confidence_score; TARGET_LEVEL (runs once per host, not per URL) |
| 24 | **CORS** | 3 | 3 | 2 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |
| 25 | **JWT** | 3 | 3 | 2 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |

## Summary Statistics

| Metric | Count | % |
|---|---|---|
| Total scanners | 25 | 100% |
| Maturity ≥ 4 (skip legacy) | 9 | 36% |
| Maturity = 3 | 8 | 32% |
| Maturity = 2 | 8 | 32% |
| Maturity = 1 | 0 | 0% |
| Use evidence_engine | 25 | 100% |
| Store typed evidence | 25 | 100% |
| **NO typed evidence** | **0** | **0%** |
| Link evidence to findings | 25 | 100% |
| Produce confidence_score | 1 | 4% |
| Produce evidence_strength | 0 | 0% |
| Produce false_positive_risk | 0 | 0% |

## Gap Analysis

### ✅ Resolved: SSRF (Maturity 4, zero evidence)

SSRF was previously flagged as having no typed evidence, but **this has been resolved**. The scanner now:

- Stores `HttpRequestEvidence` and `ResponseExcerptEvidence` via `collect_evidence()` for each metadata detection finding
- Stores `OOBCallbackEvidence` for OOB-confirmed findings, linked to the finding fingerprint
- Links all evidence to findings via `evidence_engine.link_to_finding()`
- Has dynamic confidence scoring via `_calculate_ssrf_confidence()` (the only scanner with non-hardcoded confidence)
- Reporters render type-specific evidence blocks for SSRF findings (collapsible OOB callback details, request/response evidence)

### ✅ Resolved: SSTI (Maturity 4, previously had no evidence)

SSTI's evidence gap has been closed. The scanner now:

- Creates `HttpRequestEvidence` and `ResponseExcerptEvidence` per detection via `collect_evidence()`
- Stores and links evidence for each of the 3 stages (detect, validate, exploit)
- Creates engine-fingerprint evidence in the validation phase
- Stores exploitation proof evidence when read-proof payloads succeed
- Links all evidence to findings via `evidence_engine.link_to_finding()`

### ✅ Resolved: Evidence-Starved Scanners

All scanners now store typed evidence via the evidence engine. The previously flagged gaps:

- ~~**SSRF** — now stores HttpRequest + ResponseExcerpt + OOBCallback evidence~~
- ~~**SSTI** — now stores HttpRequest + ResponseExcerpt evidence per stage~~
- ~~**Headers** — now stores HttpRequest + ResponseExcerpt evidence~~
- ~~**OpenRedirect** — now stores HttpRequest + ResponseExcerpt evidence~~
- ~~**CSRF** — now stores HttpRequest + ResponseExcerpt evidence~~
- ~~**InsecureForms** — now stores HttpRequest + ResponseExcerpt evidence~~
- ~~**DirectoryFuzz** — now stores ResponseExcerpt evidence~~
- ~~**SubdomainTakeover** — now stores HttpRequest + ResponseExcerpt evidence~~

All 25 scanners import from `models.evidence`, call `evidence_engine.store()` and `evidence_engine.link_to_finding()`.

**Fix**: Add `HttpRequestEvidence` + `ResponseExcerptEvidence` as a baseline for all of them.

### Universal Gap: Confidence Scoring

**Only SSRF** calculates a dynamic confidence score. Every other scanner hardcodes `confidence_score` to the `finding()` default (0). No scanner sets `evidence_strength` or `false_positive_risk` at creation time — these are left to factory defaults.

The `VerificationStage` is set correctly by most scanners, but the confidence/evidence strength/false-positive triad is entirely unpopulated.

**Partly addressed:** The `finding()` factory now auto-syncs `finding_state` from `VerificationStage` and `confidence_label` from `confidence_score` so that dict-style access (`f["finding_state"]`, `f["confidence_label"]`) returns populated values even when scanners don't set them explicitly.

### Reproduction Quality

All scanners produce `steps_to_reproduce`. Quality varies:
- **XSS, SSTI, OpenRedirect, LFI**: Use `generate_reproduction()` methods — consistent, parameterized
- **Most others**: Hardcoded 2-step lists — adequate but won't survive URL schema changes
- None produce automated reproduction (no `curl` commands in steps, no scripts)

## Prioritized Remediation Plan

### ✅ Phase 1-3: All Evidence Gaps Closed

SSRF, SSTI, Headers, OpenRedirect, CSRF, InsecureForms, DirectoryFuzz, and SubdomainTakeover all now store and link typed evidence via the evidence engine. See [the resolved gaps above](#-resolved-evidence-starved-scanners).

The evidence pipeline in `main.py` has also been fixed: findings are now enriched with linked evidence from the engine **before** `EvidenceCompletenessValidator.validate()` runs, so the validator correctly detects all `EvidenceType` values (including `TIMING_PROOF`, `OOB_CALLBACK`, `BROWSER_EXECUTION`) instead of relying solely on `request`/`response_excerpt` string fallbacks.

### Phase 4: Medium — Confidence Scoring (est. 2 hours)

Implement a shared confidence calculator (similar to SSRF's `_calculate_ssrf_confidence()`) on `ScannerBase`:

- Signal count → base score
- Verification stage multiplier (DETECTED=25, VALIDATED=60, EXPLOITABLE=100, VERIFIED=100)
- Evidence count → bonus
- False-positive risk → penalty

Make it a method on `ScannerBase` so all scanners inherit it.

### Phase 5: Low — Reproduction Quality (est. 2 hours)

Refactor all hardcoded 2-step `steps_to_reproduce` into `generate_reproduction()` methods (following XSS/SSTI/OpenRedirect pattern).

### Phase 6: Low — evidence_strength / false_positive_risk (est. 1 hour)

Map `VerificationStage` to `EvidenceStrength`:
- DETECTED → WEAK
- VALIDATED → MODERATE
- EXPLOITABLE → STRONG
- VERIFIED → VERIFIED

Add `false_positive_risk` heuristic based on vuln type and verification stage.

## Verification Lifecycle Coverage

This shows which scanners provide which verification stage, and whether it maps to real code paths:

| Stage | Description | Scanners that reach this stage |
|---|---|---|
| **DETECTED** | Signal found, no confirmation | All 25 |
| **VALIDATED** | Secondary signal confirms | XSS, SQLi, SSRF, CMDI, XXE, SSTI, IDOR, Headers (CORS), OpenRedirect, LFI, SensitiveData (partial), GraphQL (partial) |
| **EXPLOITABLE** | Safe exploitation proof | XSS, SQLi (time-based), CMDI, SSTI, SensitiveData (partial) |
| **VERIFIED** | OOB callback / browser execution | XSS (BrowserValidator), SQLi (OOB), SSRF (OOB), BlindXSS (OOB), CMDI (OOB), XXE (OOB), Authorization (role comparison) |

## Recommendation

**Immediate** (before next release):
1. Fix SSRF evidence gap — it claims maturity 4 but has zero evidence storage
2. Fix SSTI evidence gap — a 3-stage detection pipeline with no evidence is misleading

**Next sprint**:
3. Add evidence to remaining 5 low-maturity scanners
4. Implement shared confidence calculator
5. Standardize `generate_reproduction()` across all scanners

---

## Task Completion

| # | Task | Status | Module |
|---|---|---|---|
| 1 | Decouple ApiScanner/IdorScanner from VulnScanner | ✅ Done | `modules/api_scanner.py`, `modules/idor.py` |
| 2 | Standardise scan_* router methods (walrus → result check) | ✅ Done | `modules/scanner.py` |
| 3 | Wire ScanBudgetEngine output (sort by allocated_budget) | ✅ Done | `engines/scan_budget.py` |
| 4 | Add evidence_count to headers scanner findings | ✅ Done | `scanners/headers.py` |
| 5 | Sync finding_state/confidence_label on dict findings | ✅ Done | `modules/utils.py` |
| 6 | DuplicateRiskEngine + ImpactEngine in post-scan pipeline | ✅ Done | `main.py` |
| 7 | Replay regression detection | ✅ Done | `main.py` |
| 8 | Metrics output (pipeline funnel post-scan) | ✅ Done | `main.py` |
| 9 | Documentation updates | ✅ Done | AGENTS.md, README.md, ARCHITECTURE.md, AUDIT_VALIDATION_MATURITY.md |

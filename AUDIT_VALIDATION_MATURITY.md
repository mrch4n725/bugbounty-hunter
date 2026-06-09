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
| 3 | **SSRF** | 4 | 4 | 3 | 0 | 2 | 3 | **None** | **No** | **No** | **CRITICAL: No typed evidence at all** — uses only OOB poll but doesn't store OOBCallbackEvidence |
| 4 | **BlindXSS** | 4 | 3 | 4 | 4 | 3 | 1 | HttpRequest, OOBCallback | Yes | Yes | ⚡ Addressed — Fix 5 added HttpRequestEvidence for injection requests |
| 5 | **CMDI** | 4 | 4 | 4 | 4 | 2 | 1 | Timing, HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |
| 6 | **XXE** | 4 | 4 | 4 | 4 | 2 | 1 | HttpRequest, ResponseExcerpt, OOBCallback | Yes | Yes | No confidence_score |
| 7 | **Authorization** | 4 | 4 | 4 | 5 | 3 | 1 | AuthorizationComparison | Yes | Yes | No confidence_score |
| 8 | **SSTI** | 3 | 3 | 3 | 0 | 3 | 1 | **None** | **No** | **No** | **HIGH: No typed evidence at all** — uses 3-stage detect/validate/exploit but stores nothing |
| 9 | **SensitiveData** | 3 | 3 | 1 | 3 | 2 | 1 | HttpRequest, ResponseExcerpt, SecretValidation | Yes | Yes | Only pattern-matching; no validation beyond regex |
| 10 | **IDOR** | 3 | 3 | 3 | 4 | 3 | 1 | AuthorizationComparison (via modules/idor.py) | Yes | Yes | No confidence_score |
| 11 | **Headers** | 4 | 4 | 2 | 3 | 3 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | ⚡ Addressed — Fix 4 added HttpRequestEvidence + ResponseExcerptEvidence storage and linking. Multi-signal detection (missing headers, info disclosure, CSP, cookies, CORS). Context-aware reproduction. |
| 12 | **LFI** | 2 | 3 | 2 | 2 | 3 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |
| 13 | **OpenRedirect** | 2 | 3 | 2 | 0 | 3 | 1 | **None** | **No** | **No** | **HIGH: No typed evidence** — Location header stored as string only |
| 14 | **ExposedFiles** | 2 | 2 | 1 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |
| 15 | **GraphQL** | 2 | 3 | 1 | 2 | 2 | 1 | GraphQLSchema | Yes | Yes | No validation beyond introspection detection |
| 16 | **OpenAPI** | 2 | 2 | 1 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No validation beyond path discovery |
| 17 | **CSRF** | 1 | 2 | 0 | 0 | 2 | 1 | **None** | **No** | **No** | **HIGH: No typed evidence** — form structure analysis only, no actual request made |
| 18 | **Clickjacking** | 1 | 2 | 1 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | Header check only |
| 19 | **HttpMethods** | 1 | 2 | 1 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No validation beyond status code |
| 20 | **InsecureForms** | 1 | 2 | 0 | 0 | 2 | 1 | **None** | **No** | **No** | **HIGH: No typed evidence** — form structure analysis only |
| 21 | **DirectoryFuzz** | 1 | 2 | 1 | 0 | 2 | 1 | **None** | **No** | **No** | **HIGH: No typed evidence** — status code based only |
| 22 | **SubdomainTakeover** | 1 | 2 | 0 | 0 | 2 | 1 | **None** | **No** | **No** | **HIGH: No typed evidence** — signature string match only |
| 23 | **RateLimiting** | 1 | 2 | 1 | 2 | 2 | 1 | Timing | Yes | Yes | No confidence_score; now TARGET_LEVEL (runs once per host, not per URL) |
| 24 | **CORS** | 3 | 3 | 2 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |
| 25 | **JWT** | 3 | 3 | 2 | 2 | 2 | 1 | HttpRequest, ResponseExcerpt | Yes | Yes | No confidence_score |

## Summary Statistics

| Metric | Count | % |
|---|---|---|
| Total scanners | 25 | 100% |
| Maturity ≥ 4 (skip legacy) | 10 | 40% |
| Maturity = 3 | 10 | 40% |
| Maturity = 2 | 5 | 20% |
| Maturity = 1 | 0 | 0% |
| Use evidence_engine | 19 | 76% |
| Store typed evidence | 18 | 72% |
| **NO typed evidence** | **7** | **28%** |
| Link evidence to findings | 18 | 72% |
| Produce confidence_score | 1 | 4% |
| Produce evidence_strength | 0 | 0% |
| Produce false_positive_risk | 0 | 0% |

## Gap Analysis

### Critical Gap: SSRF (Maturity 4, zero evidence)

SSRF is marked as maturity 4 with OOB verification, but **does not store any typed evidence** via the evidence engine. The OOB detection polls for callbacks but never creates an `OOBCallbackEvidence` object. The findings are created as raw dicts with string evidence. This means:

- OOB-confirmed SSRF findings have no linkable evidence in the EvidenceEngine
- Reporters cannot render type-specific evidence blocks for SSRF (no collapsible OOB callback details, no request/response evidence)
- The OOB poll results are used solely for verification_stage promotion, not for evidence enrichment
- Compare with BlindXSS (also OOB-based, correctly stores `OOBCallbackEvidence` and links it)

**Fix**: Add `OOBCallbackEvidence`, `HttpRequestEvidence`, and `ResponseExcerptEvidence` storage + linking in `SSRFScanner.scan()`

### High Gap: SSTI (Maturity 3, zero evidence)

SSTI has a sophisticated 3-stage detection pipeline (detect → validate → exploit) but **stores no typed evidence**. The raw responses from each stage are discarded after processing. DetectionResults carry raw_response but it's never persisted.

**Fix**: Add `HttpRequestEvidence` for each payload sent, `ResponseExcerptEvidence` for each response, and optionally a `CompositeEvidence` packaging all three stages.

### High Gap: 6 Low-Maturity Scanners with No Evidence (1 fixed)

These scanners produce findings with string evidence only and never touch `evidence_engine`:

~~- **Headers** (was Maturity 2, now 4): Had CORS validation logic but didn't store evidence~~ ✅ **Fixed in Fix 4** — now stores HttpRequestEvidence + ResponseExcerptEvidence
- **OpenRedirect** (Maturity 3): Has `detect()` and `generate_reproduction()` but no evidence storage
- **CSRF** (Maturity 2), **InsecureForms** (Maturity 2), **DirectoryFuzz** (Maturity 3), **SubdomainTakeover** (Maturity 3): No evidence at all

**Fix**: Add `HttpRequestEvidence` + `ResponseExcerptEvidence` as a baseline for all of them.

### Universal Gap: Confidence Scoring

**Only SSRF** calculates a dynamic confidence score. Every other scanner hardcodes `confidence_score` to the `finding()` default (0). No scanner sets `evidence_strength` or `false_positive_risk` at creation time — these are left to factory defaults.

The `VerificationStage` is set correctly by most scanners, but the confidence/evidence strength/false-positive triad is entirely unpopulated.

### Reproduction Quality

All scanners produce `steps_to_reproduce`. Quality varies:
- **XSS, SSTI, OpenRedirect, LFI**: Use `generate_reproduction()` methods — consistent, parameterized
- **Most others**: Hardcoded 2-step lists — adequate but won't survive URL schema changes
- None produce automated reproduction (no `curl` commands in steps, no scripts)

## Prioritized Remediation Plan

### Phase 1: Critical — SSRF Evidence (est. 1 hour)

1. Add `from models.evidence import OOBCallbackEvidence, HttpRequestEvidence, ResponseExcerptEvidence` to `scanners/ssrf.py`
2. After metadata signature match: create and store `HttpRequestEvidence` + `ResponseExcerptEvidence`
3. After OOB callback: create and store `OOBCallbackEvidence` with `raw_data`, `callback_host`, `interaction_time`, `callback_token`
4. Link all evidence to finding fingerprint

### Phase 2: High — SSTI Evidence (est. 1.5 hours)

1. Import evidence types into `scanners/ssti.py`
2. Store `HttpRequestEvidence` + `ResponseExcerptEvidence` for each of the 3 stages (detect, validate, exploit)
3. Consider `CompositeEvidence` to bundle all 3 stages under one finding
4. Link to fingerprint

### Phase 3: Medium — Evidence-Starved Scanners (est. 30 min each = 2.5 hours)

✅ **Headers** — Fixed in Fix 4 (HttpRequestEvidence + ResponseExcerptEvidence stored and linked)

Remaining (5): OpenRedirect, CSRF, InsecureForms, DirectoryFuzz, SubdomainTakeover:

1. Import `HttpRequestEvidence`, `ResponseExcerptEvidence`
2. After each probe request: store evidence and link to finding
3. This is the `ScannerBase.finalize()` auto-evidence pattern already used by `base.py` — extend the pattern or call the base class

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

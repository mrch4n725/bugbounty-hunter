# Changelog

## 1.2.1 (2026-06-10)

### Candidate Exploitation & Outcome Feedback Loop Closure

- **Candidate exploitation** — Top 10 `LogicAbuseCandidate` abuse URLs are now routed to `BusinessLogicScanner` testers (`RaceConditionTester`, `PriceManipulationTester`, `FlowBypassTester`) for same-scan exploitation. Uses candidate's `likely_patterns` to pick the right tester and `abuse_parameter` for targeted probes. Race condition, price override, negative quantity, and coupon stacking patterns are exercised directly. Findings are tagged with `_from_candidate` for traceability.
- **OutcomeFeedbackEngine loop closed** — `record_outcome()` now called for every finding in the orchestrator post-scan pipeline (after confidence scoring). Records all findings as `"detected"` outcomes so future scans benefit from `has_positive_outcome()` checks. `outcomes.jsonl` is now populated automatically.
- **SPA recon bugs fixed** — `_run_spa_recon()` in `main.py` had 3 bugs preventing SPA data from merging into `recon_data`: (1) wrong key `xhr_endpoints` → `xhr_calls`, (2) wrong key `config_objects` → `js_endpoints` (list, not dict), (3) non-existent method `detect_frameworks()` → now reads `tech_stack` from spider results directly. XHR/API endpoint URLs are now extracted from their dict structures.
- **AGENTS.md updated** — Gotchas for candidate exploitation, outcome recording, and SPA recon fixes added.

## 1.2.0 (2026-06-10)

### Business Logic Discovery & Abuse Pattern Consolidation

- **BusinessLogicDiscoveryEngine wired into orchestrator** — `BusinessLogicDiscoveryEngine.run()` now runs in post-scan pipeline after ownership discovery, generating ranked `LogicAbuseCandidate` objects from URL patterns, form analysis, redirect chains, and DiscoveryStore intelligence.
- **Candidate auto-investigation** — `InvestigationEngine.investigate_candidate()` method added; high-yield candidates (yield_rank >= 0.5) are auto-investigated using their suggested strategies in `main.py` after regular investigation completes.
- **AbusePattern consolidation** — `BusinessLogicScanner` finding builders (`_bypass_to_finding`, `_race_to_finding`, `_price_finding`) now annotate findings with `abuse_pattern` field mapping to `AbusePattern` enum values (`step_skip`, `step_reorder`, `step_repeat`, `race_condition`, `price_override`, `negative_quantity`, `coupon_stacking`).
- **Abuse pattern serialization** — `Finding.to_dict()` now includes `abuse_pattern` dynamic attribute for all report formats.
- **55 new tests** — covers business flow models (WorkflowCategory, AbusePattern, WorkflowRiskModel, LogicAbuseCandidate), BusinessLogicDiscoveryEngine (URL patterns, form analysis, risk assessment, candidate generation, redirect chains, DiscoveryStore persistence), AbusePattern consolidation (all finding builder mappings), and InvestigationEngine.investigate_candidate. Total: 321/321 passing.

## 1.1.0 (2026-06-10)

### Authorization Intelligence Platform

- **OwnershipDiscoveryEngine** — new `engines/ownership_discovery.py`: proactive ownership inference from response JSON patterns (ID+owner_id in same object), URL path hierarchy, JWT sub cross-references, OpenAPI model properties, and cross-cutting schema patterns across DiscoveryStore. Wired into orchestrator post-scan pipeline.
- **Cross-account IDOR investigation** — `InvestigationEngine._exec_cross_account_idor()` compares responses across multiple role sessions with `AuthorizationComparisonEvidence`; detects both body-diff leaks and status-bypass patterns.
- **Differential auth investigation** — `InvestigationEngine._exec_differential_auth()` does recursive field-level JSON comparison with sensitivity classification (pii/financial/credential/ownership/internal) across roles.
- **Investigation → DiscoveryStore feedback** — confirmed findings (confidence >= 60, stage validated/verified) feed `confirmed_endpoint` and `validated_resource` records back into DiscoveryStore, closing the discover→learn→discover-more loop.
- **Pre-scan object harvesting** — `ObjectHarvester` runs on recon data (forms HTML, JS file responses) *before* TARGET_LEVEL modules, feeding early IDs into authorization scanners.
- **DifferentialAuthorizationEngine** — `engines/differential_auth.py`: recursive JSON field comparison with sensitivity classification. Integrated into `AuthorizationEngine.test_endpoint()`.
- **GqlAuthorizationEngine** — `engines/gql_auth.py`: reads stored GQL types/fields/relationships, feeds ownership hints and type-to-type relationships into DiscoveryStore for RelationshipGraph consumption.
- **MultiAccountDiscoveryEngine wired** — previously dead code (zero callers); added to `main.py` pipeline after `run_scans()` when 2+ role sessions exist.
- **JWT payload decoding at harvest time** — `ObjectHarvester._harvest_jwt_claims()` decodes JWT payloads: extracts `sub` as resource ID, `roles`/`groups` as role records, `org_id`/`tenant_id` as ownership hints.
- **Impact escalation surfaced** — `Finding.to_dict()` now serializes `_escalation_result` and `_best_escalation_path` for all report formats.
- **GQL auth testing with real field selectors** — `_build_gql_selection_set()` builds field selectors from discovered schema types; `_detect_gql_body_diff()` fixed for same-status body differences; `_test_query_auth()` uses discovered type fields.
- **Evidence normalization** — `Finding.__post_init__` normalizes `evidence` to always be a `list`. Removed 6 `isinstance(evidence, str)` guards across legacy code.

## 1.0.0 (2026-06-10)

### Major Features

- **AuthSessionManager** — OAuth flow automation, JWT refresh handling, multi-role session management (admin/user/unauthenticated), CSRF token extraction and injection, login sequence replay with template-based value extraction
- **WAF evasion layer** — WAF fingerprinting (Cloudflare, Akamai, ModSecurity, AWS WAF, F5, Imperva, Sucuri, Wordfence), encoding/fragmentation strategy selection per WAF type, payload variant generation (base64, hex, unicode, UTF-7, HTML entities, case permutation, whitespace fragmentation, null byte injection, comment injection)
- **Technology-aware scanner registry** — Framework-specific probe sets for WordPress (xmlrpc SSRF, user enumeration, plugin SQLi, debug log), Spring Boot (actuator exposure, SpEL injection, heapdump, Swagger), Rails (mass assignment, CSRF forgery, send_file traversal), Laravel (debug mode, .env exposure, queue injection), GraphQL (batch abuse, alias bypass, depth attack)
- **Semantic response analysis** — PII detection (emails, phones, SSNs, passports, DOB, national IDs, medical IDs), financial data detection (credit cards with Luhn, bank accounts, IBANs, SWIFT, invoices, payment tokens), credential/API key detection (password hashes, AWS/GitHub/OpenAI/Slack keys, JWTs, connection strings), IDOR pair comparison with user-context cross-referencing
- **Headless browser recon** — Playwright-based SPA spidering with XHR/fetch capture, runtime parameter discovery (window.__INITIAL_STATE__, __NUXT__, __NEXT_DATA__), form-to-API mapping, framework detection (React/Vue/Angular/Nuxt/Next), API endpoint capture with auth token extraction
- **External intelligence gatherer** — Shodan/Censys port and service discovery, crt.sh certificate transparency subdomain enumeration, Wayback Machine historical endpoint discovery, GitHub code leak search with API key/token/credential matching
- **Request smuggling scanner** — CL.TE, TE.CL, TE.TE obfuscation variants, HTTP/2 downgrade smuggling, raw TCP connection testing with SSL support, response differential analysis for confirmation
- **Business logic testing** — Workflow state-graph analyzer (form sequences, redirect chains, multi-step flows), race condition detection via concurrent request flooding, step-skip/reorder/repeat testing with state validation
- **Per-finding evidence export** — Single finding HTML export with all typed evidence, curl commands, reproduction steps, evidence bundle metadata, and copy-to-clipboard curl button
- **Submission prioritisation queue** — Combined severity/confidence/evidence-strength/validation-rate scoring, ranked submission queue, per-vuln-type detection-to-validation ratio integration
- **Payload intelligence tracker** — Payload effectiveness recording by tech stack and WAF profile, historical success-rate weighting, optimal-payload selection
- **Cross-scan finding database** — SHA-256 fingerprint persistence across scans, first-seen/last-seen/still-present tracking, regression detection for previously patched findings
- **Scan audit log** — Every request recorded with timestamp, method, URL, headers, status code to audit file
- **CI/CD modes** — JSON diff between scan outputs, GitHub Actions PR annotation formatter, Slack/Discord webhook for high-confidence findings
- **Mobile API mode** — Burp Suite XML export and Charles Proxy session ingestion, custom auth header normalisation, certificate pinning bypass marker handling
- **Passive analysis mode** — HAR file and Burp XML import, parameter/endpoint/response-pattern analysis, prioritised active-test candidate list generation
- **Operational security** — Footprint profile system (stealth/normal/aggressive), User-Agent rotation, scan delay jitter, request signing header support, IP rotation hooks

### Scanner Improvements

- **7 uplifted scanners** — XSS, SQLi, SSRF, LFI, SSTI, CMDI, XXE expanded with new detection signals, FP hardening pre-checks, signal counting, and recon-driven parameter targeting
- **Per-vuln-type metrics** — Detection coverage and validation rate tracking per vulnerability type with `needs attention` flagging
- **Recon-driven parameter targeting** — All parameters scanned; recon signals reorder priority (JS context, REST patterns, URL-like values, file-path keywords, template-context keywords)
- **Signal counting** — Independent detection signals tracked per finding (up to 7 for SQLi, 6 for XXE, 5 for SSRF, 4 for XSS/CMDI/LFI/SSTI)

### Evidence & Reporting

- **Evidence export** — Per-finding self-contained HTML with evidence bundle, curl commands, reproduction steps
- **Submission queue** — Ranked by combined score with severity/confidence/evidence-strength weighting
- **Audit log** — Per-request CSV audit trail in output directory

### Discovery Effectiveness Overhaul

- **Subdomain-to-scanner pipeline** — Live subdomains from DNS + crt.sh are now auto-injected into scanner URL pool as `https://{sub}` and `http://{sub}`, giving scanners full subdomain attack surface coverage
- **JS endpoint injection** — Both `main.py` JS intelligence loop and legacy `recon.mine_js_bundles()` path now feed discovered JS endpoints + hidden endpoints into scanner URL pool
- **Param fuzzing expansion** — Removed 50-path hard cap, removed query-string skip guard, added param appending for URLs with existing query strings, added `max_fuzz_urls` config (default 200)
- **GQL discovery boost** — Expanded from 9 to 21 static probe paths (Altair, Voyager, Playground, `/api/v3/graphql`), added 6 query-param-based GQL detection paths (`/api?query={__typename}`), added 6 WebSocket GQL subscription endpoints
- **401/403 bypass probing** — 12 header-based bypass techniques (X-Forwarded-For, X-Original-URL, X-Rewrite-URL, X-Real-IP, etc.) deployed during common path probing
- **Recon-to-IDOR param pipeline** — `_fuzzed_params` tracking dict added to `Recon` class, returned in `recon_data['fuzzed_params']` for scanner consumption
- **InvestigationEngine real execution** — All `_execute_task()` branches replaced simulations with real HTTP/OOB/browser/Playwright strategies (XSS, SSRF, SQLi timing, LFI, SSTI, open_redirect, IDOR, replay). `boolean_sqli` remains no-op pending implementation.
- **ConfidenceEngine** — New unified explainable confidence scoring engine aggregating evidence quality, ownership, impact, consensus, and investigation depth
- **ImpactEscalationAnalyzer** — Per-vuln-type escalation maps for IDOR, SSRF, XSS, SQLi, SSTI, LFI, open_redirect, and subdomain_takeover
- **OutcomeFeedbackEngine** — New engine with thread-safe JSON Lines persistence to `outcomes.jsonl`, wired into container and orchestrator post-scan pipeline
- **EvidenceQualityEngine enhanced** — 5-dimensional assessment (completeness, reproducibility, validation_strength, ownership_proof, impact_proof) with per-dimension assessors

### Fixes

- Fixed duplicate risk rendering in reports
- Fixed evidence enrichment fallback chain
- Fixed timing evidence field names across all reporter formats
- Fixed OwnershipEvidence and ImpactEvidence attachment in main.py
- Fixed ReplayEngine no-op (build_bundle now called before comparison)

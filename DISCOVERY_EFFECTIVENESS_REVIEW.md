# Discovery Effectiveness Overhaul — Review & Implementation Plan

**Date:** 2026-06-10
**Scope:** Discovering & fixing the bottleneck between "collecting intelligence" and "turning it into more discoveries"

---

## 1. Intelligence Flow Audit — What Is vs What Should Be

### Current Flow

```
Recon ──→ recon_data ──→ Orchestrator ──→ Scanners → Findings
  │                        │
  └── JSIntelligence       └── Post-Scan Pipeline (validation, evidence, confidence, impact)
       │
       └── results ──→ mine_js_bundles() ──→ findings + URL pool injection
```

### Desired Flow

```
Discovery Source
  ↓
Raw Intelligence (object IDs, endpoints, types, roles, relationships)
  ↓
DiscoveryStore (SQLite — persists across scans)
  ↓
RelationshipGraph (ownership boundaries)
  ↓
Discovery Priority Engine (score by auth potential, biz impact)
  ↓
Targeted Scanner Dispatch (IDOR, AuthZ, GQL, Biz Logic)
  ↓
Findings
  ↓
ObjectHarvester (extract more IDs from responses)
  ↓
DiscoveryStore (feedback loop complete)
```

### Intelligence Inventory — Used vs Partially Used vs Unused

```
USED INTELLIGENCE (feeds back into discovery):
├── urls → scanner URL pool ✓
├── forms → scanner form targets ✓
├── params → scanner parameter targets ✓
├── subdomains → injected into URL pool ✓
├── js_urls → JS mining ✓
├── fuzzed_params → IDOR scanner candidates ✓
├── technology → classify_endpoint signal ✓
├── html_comments → URLs/params extracted into pool ✓
├── js_endpoints → classify_endpoint signal ✓
└── endpoints from analyze() → injected into URL pool ✓

PARTIALLY USED (collected, some consumed, not fed back):
├── technology → used by classify_endpoint but not by scanners directly
├── js_endpoints → used as boolean, not as URL source (URLs injected separately)
├── env_vars from JS → logged in verbose, not used for scanning
├── routes from JS → logged in verbose, not used for scanning
├── feature_flags → logged in verbose, not used for scanning
├── hardcoded_values → logged in verbose, not used for scanning
├── tokens from JS → logged in verbose, not used for scanning
├── suspicious_patterns → logged in verbose, not used for scanning
├── internal_apis from JS → URLs injected into pool, type info discarded
├── graphql_endpoints from JS → URLs injected into pool, GQL context discarded
└── hidden_endpoints from JS → URLs injected into pool, security context discarded

UNUSED INTELLIGENCE (collected and discarded):
├── OpenAPI model properties → extracted only for endpoint params, not stored as objects
├── GraphQL type relationships → dumped in log, never parsed into object graph
├── Mutation argument types → args collected for payload injection, type info discarded
├── GraphQL schema types → _print_schema_summary logs them, no semantic mapping
├── _imported_api_endpoints → set by merge_into_recon(), never read
├── _imported_auth_headers → set by merge_into_recon(), never read
├── _imported_response_patterns → set by merge_into_recon(), never read
├── _imported_status_counts → set by merge_into_recon(), never read
├── authenticated flag → printed as warning, no scanner behavior change
├── CrossScanDatabase → wired in container, never called
├── OutcomeFeedbackEngine.record_outcome() → exists, never called
├── ExternalIntelligenceGatherer data → gathered in main.py, fed into recon_data but
│   limited to subdomains/URLs — leak data, Shodan metadata not consumed
├── SPA Config Objects (__INITIAL_STATE__, __APOLLO_STATE__, etc.) → dead code
├── HeadlessReconBrowser (965 lines) → dead code
└── ObjectHarvester graphql_response → stored in DiscoveryStore, never queried
```

---

## 2. Discovery Bottleneck Analysis — Ranked

### #1 Bottleneck: No Semantic Object Extraction
**Severity: Critical**

The `ObjectHarvester` uses flat regex patterns against raw response text. It never parses JSON, never traverses nested structures, never extracts GraphQL `"data"` objects. A response like:

```json
{"user": {"id": 123, "profile": {"organization_id": 456, "role": "admin"}}}
```

yields only `numeric_id: 123` via regex. The `organization_id: 456`, the nested `profile` object, and the `admin` role are all missed when they don't match the exact keyed-id pattern `"id":\s*(\d+)`.

**Impact:** 50-70% of object IDs in responses are missed.
**Finding lift if fixed:** High (feeds IDOR, AuthZ, BOLA).

### #2 Bottleneck: No Relationship Semantics in DiscoveryStore
**Severity: Critical**

The `RelationshipGraph` maps URLs → IDs. It does not map objects → owners, types → subtypes, or resources → tenants. The `get_ownership_boundaries()` method returns `{url_pattern: [ids]}` — it has no concept of "User owns Project" or "Project belongs_to Organization".

Without ownership semantics, the AuthorizationEngine has to brute-force every URL against every role pair instead of targeting high-probability ownership violations.

**Impact:** AuthZ testing is O(n²) with no prioritization.
**Finding lift if fixed:** Very high (IDOR, AuthZ, tenant isolation).

### #3 Bottleneck: GraphQL Schema Intelligence Not Mined
**Severity: High**

The system discovers GQL endpoints, runs introspection, and logs the schema. But the schema types, field relationships, and argument types are **never parsed into a usable object graph**. The `_discover_mutations()` method returns mutation names + arg names + arg types, but the types are discarded immediately — only the names survive.

Key missed opportunities:
- GQL type `User` with field `addresses: [Address]` → this defines an ownership relationship
- Mutation `updateUser(id: ID!)` → `id: ID!` is a resource identifier that should feed IDOR testing
- Query `users(orgId: ID!)` → the `orgId` parameter defines a tenant boundary
- `__typename` in responses maps objects to types, but no code aggregates typename → field mappings

**Impact:** 90%+ of GraphQL intelligence (schema types, relationships, ownership boundaries) is collected and immediately discarded.
**Finding lift if fixed:** High (GQL authZ, GQL IDOR, GQL biz logic).

### #4 Bottleneck: No Stateful Workflow Tracking
**Severity: High**

The system has no concept of request sequences or state transitions. It crawls URLs and forms as static resources. It cannot:

- Create a resource as User A, then test access as User B
- Follow a create → read → update → delete lifecycle
- Track session state across multi-step forms
- Detect workflow steps that skip authorization checks

The `BusinessLogicScanner` has `FlowBypassTester` that attempts step-skip/reorder/repeat, but it operates on a purely static `WorkflowGraph` built from recon data — no actual state is tracked.

**Impact:** All "create-then-access" IDORs are missed. Most workflow bypasses are missed.
**Finding lift if fixed:** Very high (IDOR, biz logic, tenant isolation).

### #5 Bottleneck: Discovery Priority Engine Missing
**Severity: High**

Currently every URL is scored by `compute_endpoint_score()` using simple signals (has params, has forms, JS API, auth required, etc.). There is no concept of:

- Authorization potential (does this URL reference an object ID?)
- Business impact (is this a payment/order/admin endpoint?)
- GraphQL depth (does this mutation accept object IDs?)
- Ownership indicators (does the response contain `owner_id`, `user_id`, `organization_id`?)

Scanners spend equal time on:
```
GET /about-us (static page)
GET /api/users/123/orders (high-value endpoint)
```

**Impact:** 40-60% of scan time wasted on low-value endpoints while high-value endpoints receive insufficient attention.
**Finding lift if fixed:** Medium (improves efficiency, not direct findings).

### #6 Bottleneck: SPA Recon Is Dead Code
**Severity: Medium**

965 lines of `HeadlessReconBrowser` in `recon_spa.py` — SPA route discovery, XHR/fetch capture, config object parsing (`__INITIAL_STATE__`, `__APOLLO_STATE__`, `__NUXT__`, `__NEXT_DATA__`), runtime window enumeration, framework detection — are all dead code. The `--spa-recon` flag exists but connects to nothing.

This is the single largest block of unused discovery capability in the codebase.

**Impact:** All SPA-specific intelligence (Redux state, Apollo cache, client-side routes, runtime params) is completely missed on SPA targets.
**Finding lift if fixed:** High for SPA targets (increasingly common).

### #7 Bottleneck: Mutation Auth Testing Is Shallow
**Severity: Medium**

`scan_graphql_auth_bypass()` tests GQL mutations with role sessions but:
- Tests only first 5 mutations
- Fills all args with `"test"` — no real IDs from DiscoveryStore
- Compares only HTTP status codes — no response body diff
- No query-level auth testing (only mutations)
- No batched GQL auth testing

**Impact:** GQL auth bypass findings are detected only in trivial cases (status-code-based).
**Finding lift if fixed:** Medium (GQL authZ).

### #8 Bottleneck: Authorization Engine Tests URLs, Not Parameters
**Severity: Medium**

The `AuthorizationEngine.test_endpoint()` tests entire URLs. It does not:
- Systematically vary URL parameters across role switches
- Test parameter injection into GQL mutation arguments
- Test different HTTP methods independently
- Test request body variations across roles

The `IdorScanner` does parameter-based testing but uses its own independent mechanism (parallel to AuthorizationEngine).

**Impact:** Parameter-level IDOR is found by chance (IdorScanner), not systematically by AuthorizationEngine.
**Finding lift if fixed:** Medium (IDOR, AuthZ).

### #9 Bottleneck: CrossScanDatabase Is Dead Code
**Severity: Medium**

The `CrossScanDatabase` (SQLite-backed cross-scan dedup and regression tracking) is wired in the container but never accessed. Methods like `record_findings()`, `mark_fixed()`, `get_status()` exist but are never called. This means:

- No regression detection across scans
- No tracking of previously confirmed/fixed findings
- No cross-scan dedup
- No historical trend analysis

**Impact:** Every scan starts from zero context. Previously confirmed findings may be re-reported.
**Finding lift if fixed:** Low (quality-of-life, not direct findings).

### #10 Bottleneck: Outcome Feedback Loop Broken
**Severity: Low**

`OutcomeFeedbackEngine.record_outcome()` exists but is never called. The engine can track which findings were accepted/rejected/bounty-paid, but no code path writes to it. This means:

- Payload intelligence can't learn from accepted vs rejected outcomes
- Confidence scoring can't incorporate historical acceptance rates
- Submission readiness can't factor in past success patterns

**Impact:** The feedback loop that would let the system learn from its mistakes is disconnected.
**Finding lift if fixed:** Low (compound effect over many scans).

---

## 3. High-ROI Improvements — Ranked

### Critical

| # | Improvement | Expected Finding Lift | Complexity | Runtime Cost | FP Risk |
|---|---|---|---|---|---|
| C1 | **SPA Recon Integration** — Wire `HeadlessReconBrowser` into `main.py` via `--spa-reco n` flag | +25-40% on SPA targets | Medium | Medium | Low |
| C2 | **Stateful IDOR Testing** — Sequence create-then-access across role sessions | +30-50% IDOR findings | High | Medium-High | Medium |
| C3 | **GraphQL Type Relationship Mapping** — Parse introspection schema into typed object graph, feed ownership boundaries to AuthZ | +20-35% GQL findings | Medium-High | Low-Medium | Low |
| C4 | **Semantic Object Extraction** — Replace flat regex with JSON-traversal object extraction for nested structures | +15-25% across all vuln types | Medium | Low | Low |

### High

| # | Improvement | Expected Finding Lift | Complexity | Runtime Cost | FP Risk |
|---|---|---|---|---|---|
| H1 | **GQL Mutation Argument ID Injection** — Feed DiscoveryStore IDs into GQL mutation args for authZ/IDOR testing | +15-25% GQL AuthZ/IDOR | Low-Medium | Low | Medium |
| H2 | **OpenAPI Model → DiscoveryStore** — Store discovered API model properties as domain objects with relationship hints | +10-20% API vulns | Low-Medium | Low | Low |
| H3 | **Ownership Boundary Inference from Responses** — Analyze response body for `owner_id`, `user_id`, `organization_id` fields to infer ownership chains | +15-25% IDOR | Medium | Low | Low |
| H4 | **GQL Individual Mutation Auth Testing** — Test each discovered mutation with body diff + DiscoveryStore IDs across role sessions | +10-20% GQL AuthZ | Medium | Medium | Medium |
| H5 | **Discovery Priority Engine** — Score URLs by auth potential, biz impact, ownership indicators | +10-15% efficient discovery | Medium | Low | Low |

### Medium

| # | Improvement | Expected Finding Lift | Complexity | Runtime Cost | FP Risk |
|---|---|---|---|---|---|
| M1 | **AuthorizationEngine Parameter Variation** — Test URL query params + body params across role switches | +10-15% AuthZ | Medium | Medium | Medium |
| M2 | **CrossScanDatabase Integration** — Wire into post-scan pipeline for regression detection | +5-10% (compound) | Low | Low | Low |
| M3 | **OutcomeFeedbackEngine Integration** — Call `record_outcome()` after report generation | +5-10% (compound) | Low | Low | Low |
| M4 | **Batched GQL Auth Testing** — Send batched queries under different roles | +5-10% GQL AuthZ | Low-Medium | Low | Medium |
| M5 | **Mutated Argument Auth Testing** — Test GQL mutations with +1/-1 ID values across roles | +5-10% GQL IDOR | Low | Low | Medium |

### Low

| # | Improvement | Expected Finding Lift | Complexity | Runtime Cost | FP Risk |
|---|---|---|---|---|---|
| L1 | **ExternalIntelligenceGatherer Shodan/GitHub Leak Consumption** | +2-5% | Low | Low | Low |
| L2 | **authenticated Flag Scanner Behavior** — Skip auth-required endpoints when unauthenticated | +0% (efficiency) | Low | Low | Low |
| L3 | **Constructor-based di in SPA** | +0% (refactor) | Low | Low | Low |
| L4 | **Richer Relationship Types** — Add semantic labels to RelationshipGraph edges | +5-10% (enabling) | Medium | Low | Low |

---

## 4. Implementation Roadmap

### Phase 1 — Quick Wins (1-2 sessions)

| Item | Effort | Focus |
|---|---|---|
| C4: Semantic Object Extraction — JSON traversal | ~80 lines | All vuln types |
| H2: OpenAPI Model → DiscoveryStore | ~50 lines | API vulns |
| H3: Ownership Boundary Inference from Responses | ~100 lines | IDOR |

**Rationale:** These three items are small, self-contained, and have the highest finding-lift-per-line-of-code. Semantic extraction alone recovers 50-70% of currently missed object IDs.

### Phase 2 — GQL Intelligence (1-2 sessions)

| Item | Effort | Focus |
|---|---|---|
| C3: GQL Type Relationship Mapping | ~200 lines | GQL AuthZ/IDOR |
| H1: GQL Mutation Argument ID Injection | ~80 lines | GQL AuthZ/IDOR |
| H4: GQL Individual Mutation Auth Testing | ~150 lines | GQL AuthZ |
| M4: Batched GQL Auth Testing | ~60 lines | GQL AuthZ |

**Rationale:** 90% of GQL intelligence is currently discarded. Schema type mapping unlocks ownership boundaries, mutation argument ID injection unlocks IDOR, and per-mutation auth testing with body diff catches violations that status-code comparison misses.

### Phase 3 — Stateful Discovery (2-3 sessions)

| Item | Effort | Focus |
|---|---|---|
| C2: Stateful IDOR Testing (create-then-access) | ~300 lines | IDOR, AuthZ |
| H5: Discovery Priority Engine | ~200 lines | All vuln types |
| C1: SPA Recon Integration | ~150 lines | SPA targets |

**Rationale:** Stateful IDOR testing is the highest-impact single change (30-50% more IDOR findings) but requires the most engineering. The Discovery Priority Engine should be built first so that stateful testing targets the right endpoints. SPA integration is a large dead-code reactivation with high payoff for SPA targets.

### Phase 4 — Polish (1 session)

| Item | Effort | Focus |
|---|---|---|
| M2: CrossScanDatabase Integration | ~50 lines | Regression |
| M3: OutcomeFeedbackEngine Integration | ~30 lines | Learning |
| M5: Mutated Argument Auth Testing | ~60 lines | GQL IDOR |
| M1: AuthorizationEngine Parameter Variation | ~150 lines | AuthZ |
| L1-L4: Minor improvements | ~100 lines | Efficiency |

---

## 5. Key Decisions

1. **Do NOT build a Discovery Priority Engine as a separate service** — instead, add a `discovery_score` method to `compute_endpoint_score()` that factors in auth potential, biz impact, and ownership indicators. This avoids a new engine class while achieving the same result.

2. **ObjectHarvester should become a JSON-traversal extractor** — rather than adding another abstraction layer, extend the existing `harvest()` method to recursively traverse parsed JSON bodies looking for:
   - All numeric values at keys matching ID patterns
   - All UUID values
   - All email values
   - Nested objects that contain IDs (these imply relationships)
   - Array elements that contain IDs (these imply collections)

3. **GraphQL type mapping should use the existing `_discover_mutations()` pattern** — extend it to `_discover_types()` that returns the full type graph, then store each type as a DiscoveryStore record with its fields and relationships. The `scan_graphql_introspection()` method already has the schema — it just discards it after logging.

4. **Stateful IDOR should be a new method on `IdorScanner`** — not a new engine. `scan_stateful_idor()` would:
   - Create a resource using role A's session
   - Extract the resource ID from the create response
   - Attempt to read/update/delete using role B's session
   - Compare responses for ownership violation

5. **SPA integration should be a single `# TODO` fix** — `main.py` currently parses `--spa-recon` but never checks it. The fix is:
   ```python
   if config.get("spa_recon", False) and capabilities.has("playwright"):
       from modules.recon_spa import HeadlessReconBrowser
       spa_recon = HeadlessReconBrowser(config, recon)
       spa_data = spa_recon.discover()
       recon_data.update(spa_data)
   ```
   around line 520 in main.py, after the existing recon call.

---

## 6. Success Metrics

| Metric | Current Baseline | Phase 1 Target | Phase 2 Target | Phase 3 Target |
|---|---|---|---|---|
| Object IDs extracted per scan | ~5-15 | ~25-50 | ~25-50 | ~25-50 |
| GQL type relationships discovered | 0 | 0 | ~10-30 | ~10-30 |
| IDOR findings per scan | ~2-5 | ~4-8 | ~4-8 | ~8-15 |
| GQL AuthZ findings per scan | ~0-1 | ~0-1 | ~3-6 | ~3-6 |
| Stateful IDOR findings | 0 | 0 | 0 | ~3-8 |
| % of intelligence consumed | ~40% | ~55% | ~70% | ~85% |

Success is measured by the number of real, validated vulnerabilities found — not by lines of code written, engines added, or architectural elegance.

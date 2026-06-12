# Authorization Intelligence Platform — Effectiveness Audit

> **Date:** 2026-06-12
> **Scope:** Complete authorization intelligence flow from discovery → storage → consumption → test generation → validation → finding
> **Goal:** Determine whether the existing architecture materially increases real vulnerability discovery

---

## Executive Summary

The Authorization Intelligence Platform has a **well-architected storage layer** (DiscoveryStore, SQLite-backed, SHA-256 dedup, cross-scan persistence) and a **promising multi-engine inference pipeline** (ObjectHarvester → RelationshipGraph → OwnershipDiscovery → AuthorizationEngine → InvestigationEngine). However, **the conversion rate from stored intelligence to actionable authorization tests is below 30%**.

Critical faults:

| # | Fault | Impact | Classification |
|---|---|---|---|
| 1 | OwnershipDiscoveryEngine results discarded intra-scan (`orchestrator.py:672`) | Zero ownership relationships flow to AuthorizationScanner same-scan | **Critical** |
| 2 | Orchestrator GQL auth tester calls wrong method (`tester.execute_plans(store=store)` → `TypeError`) | GQL auth plans never execute via orchestrator path | **Critical** |
| 3 | `InvestigationEngine.collect_evidence()` never called | All HTTP/Authorization/Timing/OOB evidence generated during investigation is **lost** — not persisted, not in reports | **Critical** |
| 4 | `confirmed_endpoint` / `validated_resource` stored but never consumed by AuthorizationScanner | Investigation feedback loop has no effect on same-scan or next-scan authorization testing | **High** |
| 5 | GQL auth pipeline runs AFTER AuthorizationScanner (post-scan) | GQL-derived ownership hints and auth plans always one scan behind | **High** |
| 6 | `modules/idor.py` only reads `api_model` from DiscoveryStore (ignores `numeric_id`, `uuid`, `ownership_hint`) | Half of stored intelligence invisible to legacy IDOR path | **High** |
| 7 | `InvestigationEngine._exec_differential_auth()` duplicates `DifferentialAuthorizationEngine` with inline keyword lists | Maintenance risk, two divergent sensitivity classifiers | **High** |
| 8 | MultiAccountDiscovery and AuthorizationScanner build separate role sessions | Potential session mismatch — different role sets tested | **Medium** |
| 9 | main.py GQL probe path is single-role only (no cross-role comparison) | Cannot detect authorization violations requiring pairwise comparison | **Medium** |
| 10 | `jwt`, `private_ip`, `api_key`, `graphql_response` categories stored but never consumed | Intelligence collected but zero tests generated | **Medium** |
| 11 | Legacy `GqlAuthorizationEngine` importable but unwired — dead code | Confusion risk, maintenance burden | **Low** |
| 12 | `PlanType.CROSS_OWNER` defined in enum but never used | Dead code in model layer | **Low** |

**Overall Assessment:** The platform has the *architecture* for high-quality authorization vulnerability discovery but *lacks the wiring* that converts stored intelligence into concrete tests. The platform currently discovers **~3x more authorization artifacts** than it creates findings from.

---

## Part 1 — Authorization Intelligence Flow Map

### Flow 1: ObjectHarvester → DiscoveryStore → RelationshipGraph → AuthorizationScanner

```
Harvest (pre-scan)
  forms, JS data
    ↓
ObjectHarvester.harvest()
  extracts: numeric_id, uuid, email, jwt, role, ownership_hint, ownership_relationship
    ↓
DiscoveryStore.record()  [9 categories stored]
  ┣━ numeric_id          → ⚡ RelationshipGraph.get_auth_candidates() → AuthorizationScanner → FINDINGS
  ┣━ uuid                → ⚡ RelationshipGraph.get_auth_candidates() → AuthorizationScanner → FINDINGS
  ┣━ email               → ⚡ RelationshipGraph.get_ownership_boundaries() → URL priority scoring
  ┣━ jwt                 → 🟡 UNUSED (no consumer queries this category)
  ┣━ role                → 🟡 UNUSED (no consumer queries this category)
  ┣━ ownership_hint      → ⚡ RelationshipGraph → AuthorizationScanner → FINDINGS (indirect)
  ┣━ ownership_relationship → ⚡ RelationshipGraph → AuthorizationScanner → FINDINGS (indirect)
  ┣━ private_ip          → 🟡 orchestrator reads → creates "Artifact: Internal IP" findings (informational only)
  ┣━ api_key             → 🟡 orchestrator reads → creates "Artifact: API Key" findings (informational only)
  ┗━ graphql_response    → 🟡 UNUSED (stored but never queried)
```

**Classification:** Partially Utilized (6 of 10 categories drive tests, but 4 are pure waste)

### Flow 2: ScannerBase._add_finding() → ObjectHarvester → DiscoveryStore → RelationshipGraph

```
ScannerBase._add_finding()
  response_excerpt from each finding
    ↓
ObjectHarvester.harvest()  [inline, during scanning]
  extracts IDs from every finding response
    ↓
DiscoveryStore.record()
  accumulates cross-scan intelligence
    ↓
RelationshipGraph → AuthorizationScanner
  [consumed on NEXT scan, not current — too late]
```

**Classification:** Partially Utilized (same-scan feedback loop exists only for URL priority, not test content)

### Flow 3: ApiScanner → DiscoveryStore → GQL Pipeline → Auth Plans → Testers

```
ApiScanner._store_gql_types()
  gql_type, gql_field, gql_relationship
    ↓
DiscoveryStore
    ↓
GraphQLRelationshipEngine (post-scan)
  → gql_inferred_relationship, gql_ownership_chain, role
    ↓
GraphQLOwnershipDiscovery (post-scan)
  → ownership_hint, ownership_relationship
    ↓
GraphQLAuthorizationMapper (post-scan)
  → gql_auth_plan [4 plan types]
    ↓
┣━ orchestrator.py: GraphQLAuthTester.execute_plans(store=store) ❌ BUG — wrong method
┗━ main.py: manual HTTP probe (single-role only) → "GQL Auth Bypass" findings
```

**Classification:** Partially Utilized (orchestrator path broken by bug; main.py path produces findings but misses real auth violations)

### Flow 4: AuthorizationEngine → Findings (direct, no store dependency)

```
Role sessions → AuthorizationEngine.run_scans()
  horizontal_idor, vertical_idor, ownership_violation, status_bypass
    ↓
AuthorizationComparisonEvidence
    ↓
Finding: "Authorization - Horizontal/Vertical/Ownership Violation/Status Bypass"
```

**Classification:** Fully Utilized (runs autonomously, produces findings, uses DifferentialAuthorizationEngine)

### Flow 5: MultiAccountDiscoveryEngine → Findings (post-scan)

```
RelationshipGraph.get_auth_candidates() + recon URLs
    ↓
MultiAccountDiscoveryEngine.run_cross_account_scan()
  horizontal + vertical testing across ALL role pairs
    ↓
AuthorizationEngine.test_endpoint()  (delegated)
    ↓
AuthorizationComparisonEvidence → Findings
```

**Classification:** Fully Utilized (runs, produces findings, though session management is separate from AuthorizationScanner)

### Flow 6: InvestigationEngine → Findings (post-scan, low-confidence only)

```
Low-confidence findings (< 60)
    ↓
InvestigationEngine.investigate_all()
  23 strategies: cross_account_idor, differential_auth, ownership_validation, etc.
    ↓
_apply_result() — boosts confidence, updates verification_stage
  BUT: evidence is LOST — collect_evidence() NEVER called
    ↓
Evidence generated (AuthorizationComparisonEvidence, TimingEvidence, etc.)
  sits in self._evidence_store — never linked to evidence_engine
```

**Classification:** Partially Utilized (confidence boosted, findings promoted, but evidence discarded)

---

## Part 2 — Discovery-to-Test Conversion Audit

### ObjectHarvester Discovery-to-Test Conversion

| Artifact | Discovery Method | Storage | Tests Generated | Conversion Rate |
|---|---|---|---|---|
| `numeric_id` | JSON traversal + regex | DiscoveryStore | → RelationshipGraph → AuthorizationScanner IDOR candidates | **Partial** |
| `uuid` | JSON traversal + regex | DiscoveryStore | → RelationshipGraph → AuthorizationScanner IDOR candidates | **Partial** |
| `email` | JSON traversal + regex | DiscoveryStore | → URL priority scoring only | **Low** |
| `jwt` | regex + JWT decode | DiscoveryStore | Claims extracted (sub→uuid/numeric_id/email, roles→role, org→ownership_hint) but JWT itself UNUSED | **None** |
| `role` | JSON traversal + JWT decode | DiscoveryStore | → GQL pipeline (role escalation plans) but only GQL path | **Low** |
| `private_ip` | regex | DiscoveryStore | → Informational "Artifact: Internal IP" finding | **Informational only** |
| `api_key` | regex | DiscoveryStore | → Informational "Artifact: API Key" finding | **Informational only** |
| `ownership_hint` | JSON traversal + JWT decode + OwnershipDiscovery | DiscoveryStore | → RelationshipGraph → AuthorizationScanner URL selection | **Partial** |
| `ownership_relationship` | JSON co-occurrence + OwnershipDiscovery | DiscoveryStore | → RelationshipGraph → AuthorizationScanner URL selection | **Partial** |
| `graphql_response` | Signal detection (`__typename`) | DiscoveryStore | → URL pool injection | **Low** |

**Gap: No artifact produces more than 1 test type.** A discovered `owner_id` should generate:
1. Cross-account replay (existing — via RelationshipGraph)
2. Cross-tenant replay (if tenant_id — missing)
3. Ownership boundary test (existing — via AuthorizationScanner)
4. Parameter-level IDOR with swapped owner value (missing — IdorScanner doesn't consume)
5. Business logic abuse candidate (existing — via BusinessLogicDiscovery)

### RelationshipGraph Discovery-to-Test Conversion

| Graph Output | Consumers | Tests Generated | Conversion Rate |
|---|---|---|---|
| `get_ownership_boundaries()` | Orchestrator (URL priority) | URL reordering only | **Low** |
| `get_auth_candidates()` | AuthorizationScanner, MultiAccountDiscovery, BusinessLogicDiscovery | URL addition to scan pool | **Medium** |
| `get_related_urls()` | No caller found | None | **None** |

**Gap: `get_ownership_boundaries()` produces URL→ID mappings but no engine generates parameter-level tests from them.** The mapping `{/api/users/123} → {owner_id: 456, tenant_id: 789}` should generate tests like:
- `POST /api/users with {owner_id: 789}` (cross-tenant)
- `GET /api/users/123 as user 456` (ownership bypass)
- These tests are **not generated**.

### OwnershipDiscovery Engine Conversion

| Discovery Method | Output | Same-Scan Consumption | Conversion Rate |
|---|---|---|---|
| Response pattern matching | `ownership_hint`, `ownership_relationship` | DROPPED (orchestrator.py:672 — `discovered` variable logged but not stored) | **None** |
| URL pattern matching | `ownership_hint` | DROPPED (same) | **None** |
| JWT cross-reference | `ownership_hint` | DROPPED (same) | **None** |
| OpenAPI model analysis | `ownership_relationship` | DROPPED (same) | **None** |
| Schema pattern discovery | `ownership_hint` | DROPPED (same) | **None** |

**Critical Gap: 100% of OwnershipDiscoveryEngine output is discarded same-scan.** The results persist via DiscoveryStore SQLite (because store.record() is called by `_store_record`) but the `orchestrator.py` caller never uses the returned `discovered` list. The data is available on the *next* scan but the current scan loses all benefit.

### MultiAccountDiscovery Conversion

| Artifact | Test Generated | Rate |
|---|---|---|
| All recon URLs | Cross-account replay across role pairs | **Fully** |
| Graph auth candidates | Cross-account replay across role pairs | **Fully** |
| DiscoveryStore ownership hints | Not consumed (only reads from RelationshipGraph, not directly from store) | **None** |
| Individual ID values | Not swapped into parameter positions (only URL-level replay) | **None** |

**Gap: MultiAccountDiscovery tests URL-level access but not parameter-level access.** A discovered `owner_id=456` should generate tests like `GET /api/resource?owner_id=123` (cross-account at parameter level), not just `GET /api/resource/456`.

### GraphQL Authorization Conversion

| Plan Type | Tests Generated | Validated? | Finding? |
|---|---|---|---|
| CROSS_TENANT | orchestrator: BUG (wrong method call) | No | No |
| CROSS_TENANT | main.py: single-role GQL POST | No cross-role comparison | Yes (high FP) |
| OWNERSHIP_VIOLATION | orchestrator: BUG | No | No |
| OWNERSHIP_VIOLATION | main.py: single-role GQL POST | No cross-role comparison | Yes (high FP) |
| ROLE_ESCALATION | orchestrator: BUG | No | No |
| ROLE_ESCALATION | main.py: single-role GQL POST | No cross-role comparison | Yes (high FP) |

**Critical Gap: Two execution paths — one broken, one single-role-only.** No path generates verified cross-role GQL authorization findings.

---

## Part 3 — Relationship Graph Effectiveness

### Summary

```
Relationships Stored:   ~45 types (gql_inferred_relationship, ownership_relationship, etc.)
Relationships Driving Discovery:  3 out of ~45
Conversion Rate:   ~7%
```

### What Works

| Relationship | Driven Test | Evidence |
|---|---|---|
| URL pattern with multiple IDs → IDOR candidate | AuthorizationScanner URL addition | `scanners/authorization.py:54` |
| URL pattern with multiple IDs → cross-account candidate | MultiAccountDiscoveryEngine URL addition | `engines/multi_account_discovery.py:51` |
| URL pattern with ownership hints → workflow annotation | BusinessLogicDiscoveryEngine risk boost | `engines/business_discovery.py:608` |

### What Does NOT Drive Discovery

| Stored Relationship | Why It Doesn't Drive Tests |
|---|---|
| `GQL_ASSOCIATION` (type A has field referencing type B) | Only classified, not converted to auth hypothesis |
| `OWNS_THROUGH` (A→B→C chain) | Only stored as `gql_ownership_chain`, never consumed |
| `MEMBER_OF` (User→Organization) | Only stored as `gql_inferred_relationship`, never consumed |
| `cross_cutting_owner` (same owner_key across URLs) | Only stored as `ownership_hint`, never consumed |
| `jwt_verified_owner` (JWT sub matches owner_id) | Only stored as `ownership_relationship`, never consumed |
| Ownership boundaries (URL→ID→Owner mappings) | Only `get_ownership_boundaries()` returns them — used only for URL ordering, not test content |

### Root Cause

The `RelationshipGraph` is a **read-only aggregator** that produces structured data, but no component systematically converts relationship data into parameter-level authorization tests. The graph says "URL X has IDs [1, 2, 3] belonging to users [A, B, C]" but no engine says "try GET /url/X as user B instead of user A."

---

## Part 4 — Multi-Account Effectiveness

### Candidate Generation

| Source | Candidates | Included? |
|---|---|---|
| Recon URLs | All discovered URLs | ✅ |
| RelationshipGraph auth candidates | URL patterns with multiple IDs | ✅ |
| DiscoveryStore ownership hints | ID→Owner mappings | ❌ NOT included |
| DiscoveryStore ownership_relationships | Resource→Owner pairs | ❌ NOT included |
| DiscoveryStore roles | Role values | ❌ NOT included |
| DiscoveryStore numeric_id/uuid | Specific ID values for parameter swapping | ❌ NOT included |

### Candidate Prioritization

**None.** All candidates are tested without priority scoring. This means:
- 10,000 recon URLs → 10,000 cross-account tests × N role pairs = massive HTTP volume
- No prioritization by IDOR likelihood, ownership signal, or severity potential

### Candidate Validation

| Test Type | Validation Method | Coverage |
|---|---|---|
| Horizontal (same-level roles) | `AuthorizationEngine.test_endpoint()` with `DifferentialAuthorizationEngine.compare_http()` | ✅ Full field-level diff |
| Vertical (different-level roles) | Same as horizontal | ✅ |
| Ownership violation | Content difference + same status + ownership sensitivity | ✅ |
| Parameter-level IDOR | **NOT TESTED** — only URL-level | ❌ |

### Gap: No Parameter-Level Cross-Account Testing

The MultiAccountDiscoveryEngine tests `GET /api/resource/123` as role A vs role B. It does NOT test:
- `GET /api/resource?user_id=456` (parameter-level ID substitution)
- `POST /api/resource with {"owner_id": 789}` (mass assignment cross-account)
- `GET /api/resource/123` with `X-Original-User: 456` (header-based auth bypass)

---

## Part 5 — GraphQL Authorization Effectiveness

### Schema Knowledge vs Authorization Tests

```
GraphQL Schema Discovery → FULLY WORKING (21+ paths, introspection parsing)
  ↓
Type/Field/Relationship Storage → FULLY WORKING (gql_type, gql_field, gql_relationship)
  ↓
Relationship Classification → FULLY WORKING (BELONGS_TO, TENANT_OF, HAS_MANY, etc.)
  ↓
Ownership Discovery → FULLY WORKING (4 discovery methods)
  ↓
Auth Plan Generation → FULLY WORKING (4 plan types, CROSS_TENANT, OWNERSHIP_VIOLATION, ROLE_ESCALATION, MUTATION_AUTH)
  ↓
Plan Execution → BROKEN (see below)
  ↓
Finding Generation → PARTIAL (single-role only, high false positive)
```

### The Two-Path Problem

**Path A (orchestrator):** `GraphQLAuthTester.execute_plans(store=store)` on line 891
- Bug: `execute_plans()` accepts `plans: list[AuthInvestigationPlan]`, not `store`
- Correct method: `execute_from_store(store=store)` (which exists and reads from DiscoveryStore)
- Result: **Always raises TypeError, silently caught by broad except**

**Path B (main.py):** Manual HTTP probe loop on lines 1644-1704
- Single session only — no cross-role comparison
- Checks `status == 200` AND `"data" in response` AND no errors
- Cannot distinguish "authorized access" from "authorization bypass"
- Result: **Produces findings but high false positive rate**

### Missing: Cross-Role GQL Comparison

No path sends GQL mutations as both attacker role and owner role and compares responses. The `GraphQLAuthTester` is designed to do this (and has `DifferentialAuthorizationEngine` integration) but the orchestrator wiring bug prevents it.

---

## Part 6 — Investigation Engine Integration

### Automatic Investigation Questions

| Question | Strategy | Status |
|---|---|---|
| Can another user access this? | `cross_account_idor` | ✅ Implemented — compares responses across role sessions |
| Can another role access this? | `horizontal_idor` / `vertical_idor` | ✅ Implemented — same-endpoint role comparison |
| Can another tenant access this? | (none) | ❌ No tenant-ID-aware strategy |
| Can ownership be bypassed? | `ownership_validation` | ✅ Implemented — checks DiscoveryStore ownership hints |
| Can permissions be escalated? | `vertical_idor` | ✅ Implemented — different privilege level testing |
| Can auth be bypassed entirely? | `replay_without_auth` | ✅ Implemented — removes auth headers |

### Critical Evidence Loss

The `_apply_result()` method (line 1043) updates `confidence_score`, `verification_stage`, `finding_state`, and `confidence_reasons` on the finding, but:

1. **Does NOT attach generated evidence** to the finding's evidence list
2. **Does NOT call `evidence_engine.store()` or `link_to_finding()`**
3. **`collect_evidence()` is NEVER called** from anywhere outside `investigation.py`

This means `AuthorizationComparisonEvidence`, `TimingEvidence`, `OOBCallbackEvidence`, `HttpRequestEvidence`, `HttpResponseEvidence` generated during investigation are **stored in `self._evidence_store` and abandoned**.

### Redundant Implementation

`InvestigationEngine._exec_differential_auth()` (line 888) has its own:
- `SENSITIVE_FIELD_KEYWORDS` dict (hardcoded sensitivity categories)
- Inline recursive JSON flattening
- Field diff logic

This duplicates `DifferentialAuthorizationEngine` from `engines/differential_auth.py`. The `AuthorizationEngine` (used by `AuthorizationScanner` and `MultiAccountDiscovery`) correctly delegates to `DifferentialAuthorizationEngine`.

---

## Part 7 — Authorization Discovery KPIs

### Recommended KPIs (Not Yet Instrumented)

The platform needs these metrics to measure effectiveness:

| KPI | Definition | Current Baseline | Target |
|---|---|---|---|
| **Authorization Tests Generated** | Number of cross-role HTTP comparisons executed | ~N × (role_pairs) × (candidate_urls) | Trackable, currently no counter |
| **Ownership Hypotheses Generated** | Number of `ownership_hint` or `ownership_relationship` records that are *consumed* by a test generator | 3 of ~45 relationship types consumed (7%) | ≥ 80% |
| **Cross-Account Replays Generated** | Number of `test_endpoint()` calls made by MultiAccountDiscovery | Countable from HTTP requests | Trackable, currently no counter |
| **Boundary Violations Detected** | Findings where verification_stage = "verified" AND vuln_type contains "Authorization" or "IDOR" | Countable from findings | Trackable |
| **IDOR Findings Produced** | Count of IDOR - * finding dicts | Current `len([f for f in findings if 'IDOR' in f.vuln_type])` | Increase |
| **Authorization Findings Produced** | Count of Authorization - * finding dicts | Current `len([f for f in findings if 'Authorization' in f.vuln_type])` | Increase |
| **Discovery-to-Test Conversion Rate** | `(consumed_relationship_types / stored_relationship_types) × 100` | ~7% (3/45) | ≥ 80% |
| **Intelligence Waste Rate** | `(unused_categories / total_categories) × 100` | 40% (4/10 categories unused: jwt, private_ip, api_key, graphql_response) | < 10% |

### What NOT to Measure

- ❌ "Relationships Stored" — intelligence volume is irrelevant without test generation
- ❌ "Objects Harvested" — more IDs ≠ more findings
- ❌ "GraphQL Types Found" — schema knowledge ≠ authorization tests
- ❌ "DiscoveryStore Record Count" — storage is cheap, the real cost is untested intelligence

---

## Part 8 — Dead Code & Dead Intelligence Audit

### Critical Dead Paths (blocking vulnerability discovery)

| Dead Path | Location | Impact | Fix |
|---|---|---|---|
| `tester.execute_plans(store=store)` | `orchestrator.py:891` | 100% of GQL auth plans never execute via orchestrator | Change to `execute_from_store(store=store)` |
| `OwnershipDiscoveryEngine.discover_all()` results dropped | `orchestrator.py:672` | Same-scan ownership intelligence isolated from all test generation | Call `store.record()` on each discovered relationship |
| `collect_evidence()` never called | `engines/investigation.py` | All investigation-generated evidence lost | Wire into `_apply_result()` or main.py post-investigation loop |

### High Dead Paths (significant intelligence waste)

| Dead Path | Location | Impact | Fix |
|---|---|---|---|
| `jwt`, `private_ip`, `api_key`, `graphql_response` categories | DiscoveryStore | 4 storage categories produce zero authorization tests | Add consumers or stop storing |
| `get_related_urls()` | `engines/relationship_graph.py` | Method exists but no caller | Wire into InvestigationEngine or remove |
| `PlanType.CROSS_OWNER` | `models/gql_auth.py` | Enum value defined but never produced by mapper | Use it or remove |
| `AuthorizationEngine._classify_violation()` docstring | `engines/authorization.py:239` | Mentions DifferentialAuthorizationEngine but actually reads pre-set booleans | Fix docstring or rewire |
| GQL probe path (main.py single-role) | `main.py:1644-1704` | Duplicate of buggy orchestrator path, but even the working version can't detect real auth violations | Replace with cross-role comparison |
| Role sessions built twice | `scanners/authorization.py:91` + `engines/multi_account_discovery.py:83` | Separate role session instances, potential config drift | Use shared sessions from config |

### Medium Dead Paths (wasted effort)

| Dead Path | Location | Impact | Fix |
|---|---|---|---|
| Legacy `GqlAuthorizationEngine` | `engines/gql_auth.py` | Importable but unwired; duplicates new pipeline | Remove or rewire |
| `_exec_differential_auth()` inline logic | `engines/investigation.py:888` | Duplicates `DifferentialAuthorizationEngine` | Delegate to the shared engine |
| `InvestigationEngine` not calling `AuthorizationEngine.test_endpoint()` | `engines/investigation.py` | Parallel reimplementation of cross-role comparison | Delegate to `AuthorizationEngine` |
| Orchestrator calls `get_ownership_boundaries()` twice | `orchestrator.py:225, 348` | Redundant call — second call only used for logging | Cache or remove duplicate |

### Low Dead Paths (minor)

| Dead Path | Location | Impact | Fix |
|---|---|---|---|
| `graphql_response` reading first 500 chars | `object_harvester.py` | Signal detection ignores rest of response | Remove or extend to full scan |
| `confirmed_endpoint` not in `compute_endpoint_score` | `modules/utils.py` | URL scoring ignores confirmed historical findings | Add category to scoring |
| `validated_resource` not consumed by IdorScanner | `modules/idor.py` | Cross-scan validated IDs not injected as IDOR candidates | Add `get_by_category("validated_resource")` to candidate discovery |

---

## Executive Assessment

### Scorecard (1-10, where 10 = maximally effective)

| Dimension | Score | Rationale |
|---|---|---|
| **Authorization Discovery** | 7/10 | ObjectHarvester extracts 9 categories from multiple sources; pre-scan + per-finding + post-scan coverage |
| **Ownership Discovery** | 5/10 | OwnershipDiscoveryEngine has 5 methods but results are discarded same-scan; GQL ownership pipeline runs too late |
| **Boundary Mapping** | 4/10 | RelationshipGraph builds ownership boundaries but no component converts them into parameter-level tests |
| **Multi-Account Testing** | 5/10 | MultiAccountDiscovery runs with full role pairs but only tests URL-level access; no parameter-level ID substitution |
| **GraphQL Authorization** | 2/10 | Full pipeline from discovery to plan generation, but plan execution is broken (orchestrator bug) or single-role-only (main.py) |
| **Discovery Feedback Loops** | 3/10 | confirmed_endpoint/validated_resource stored but never consumed; OwnershipDiscovery results dropped; investigation evidence lost |
| **Discovery-to-Test Conversion** | 3/10 | Only RelationshipGraph.get_auth_candidates() converts intelligence to tests; 40% of storage categories unused |
| **Overall** | **4/10** | Well-architected storage and inference, critically underwired test generation |

---

## High ROI Improvements (Ranked)

| Rank | Improvement | Expected Increase in Auth Findings | Effort | Risk |
|---|---|---|---|---|
| 1 | Fix orchestrator GQL auth tester call (`execute_plans` → `execute_from_store`) | **+40-60%** (unlocks GQL cross-role authorization testing) | 1 line | Low |
| 2 | Store OwnershipDiscoveryEngine results same-scan (call `store.record()` in `discover_all()`) | **+25-35%** (ownership relationships available to AuthorizationScanner) | 5 lines | Low |
| 3 | Wire `collect_evidence()` into main.py post-investigation loop | **+20-30%** (investigation evidence persisted and rendered in reports) | 15 lines | Low |
| 4 | Replace main.py single-role GQL probe with cross-role comparison | **+15-25%** (real auth bypass detection instead of 200+data heuristic) | 50 lines | Medium |
| 5 | Add `confirmed_endpoint` / `validated_resource` to RelationshipGraph query | **+10-20%** (known-vulnerable endpoints re-tested on subsequent scans) | 10 lines | Low |
| 6 | Reorder GQL auth pipeline to run BEFORE TARGET_LEVEL modules | **+10-15%** (same-scan GQL ownership hints available to AuthorizationScanner) | 20 lines | Medium |
| 7 | Add parameter-level ID substitution to MultiAccountDiscovery | **+10-15%** (swaps discovered owner_id/tenant_id values into params, not just URLs) | 80 lines | Medium |
| 8 | Feed DiscoveryStore roles into AuthorizationEngine role-level mapping | **+5-10%** (dynamic role-level detection instead of hardcoded admin/user/guest levels) | 30 lines | Medium |
| 9 | Unify `modules/idor.py` and `scanners/idor.py` code paths | **+5-10%** (merges DifferentialAuthorizationEngine + DiscoveryStore consumption) | 200 lines | High |
| 10 | Remove duplicate `_exec_differential_auth()` → delegate to `DifferentialAuthorizationEngine` | **+0-5%** (reduces maintenance risk, frees dev time) | 20 lines | Low |

### ROI-Weighted Priority

```
Fix orchestrator bug     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  Highest ROI / Lowest effort
Store ownership results  ━━━━━━━━━━━━━━━━━━━━━━━━━━━    High ROI / Low effort
Wire evidence collection ━━━━━━━━━━━━━━━━━━━━━━━━━      High ROI / Low effort
Cross-role GQL probe     ━━━━━━━━━━━━━━━━━━━━            Medium ROI / Medium effort
Consume confirmed_endpts ━━━━━━━━━━━━━━━━━━              Medium ROI / Low effort
Reorder GQL pipeline     ━━━━━━━━━━━━━━━                  Medium ROI / Medium effort
Parameter-level ID sub   ━━━━━━━━━━━                      Medium ROI / Medium effort
Feed roles to AuthEngine ━━━━━━━━                         Lower ROI / Medium effort
Unify IDOR paths         ━━━━━━                           Lower ROI / High effort
Remove dead code         ━━━━                             Cleanup / Low effort
```

---

## Final Roadmap

### Phase 1 — Fix Broken Wiring (1-2 days)

| Priority | Action | Files |
|---|---|---|
| P0 | Fix orchestrator GQL tester call | `orchestrator.py:891` |
| P0 | Store OwnershipDiscovery results same-scan | `orchestrator.py:672` (or `ownership_discovery.py:discover_all()`) |
| P0 | Wire investigation evidence collection | `main.py` post-investigation loop |
| P0 | Add `confirmed_endpoint` + `validated_resource` to RelationshipGraph queries | `engines/relationship_graph.py:get_auth_candidates()` |
| P1 | Replace main.py single-role GQL probe with cross-role comparison | `main.py:1644-1704` |

### Phase 2 — Close Intelligence Gaps (3-5 days)

| Priority | Action | Files |
|---|---|---|
| P1 | Reorder GQL auth pipeline to run before TARGET_LEVEL modules | `orchestrator.py:845-898` (move earlier) |
| P1 | Add parameter-level ID substitution to MultiAccountDiscovery | `engines/multi_account_discovery.py` |
| P1 | Feed DiscoveryStore roles into AuthorizationEngine role-level mapping | `engines/authorization.py:_role_level()` |
| P2 | De-duplicate `InvestigationEngine._exec_differential_auth()` → delegate to `DifferentialAuthorizationEngine` | `engines/investigation.py:888` |
| P2 | Add `jwt` category consumer (cross-reference JWT sub with discovery store IDs) | New consumer or extend existing |

### Phase 3 — Architectural Consolidation (1-2 weeks)

| Priority | Action | Files |
|---|---|---|
| P2 | Merge `modules/idor.py` and `scanners/idor.py` into single ScannerBase implementation | `modules/idor.py`, `scanners/idor.py` |
| P2 | Remove legacy `GqlAuthorizationEngine` | `engines/gql_auth.py` |
| P2 | Remove `PlanType.CROSS_OWNER` if unused | `models/gql_auth.py` |
| P3 | Instrument all KPIs (add counters to AuthorizationEngine, MultiAccountDiscovery, IdorScanner) | Cross-cutting |

### Phase 4 — Advanced Authorization Discovery (2-4 weeks)

| Priority | Action | Files |
|---|---|---|
| P3 | Add tenant-aware testing strategy to InvestigationEngine | `engines/investigation.py` |
| P3 | Add automatic JWT role→privilege-level mapping | `engines/authorization.py` |
| P3 | Cross-scan regression detection (compare ownership boundaries across scans) | `engines/diff.py` + `DiscoveryStore` |
| P3 | Automated discovery of authorization schema from response patterns | `OwnershipDiscoveryEngine` + new strategies |

---

## Success Criteria

After Phase 1, the following should hold:

```
GQL auth plans executed via orchestrator     → YES (cross-role, produces AuthorizationComparisonEvidence)
OwnershipDiscovery results used same-scan     → YES (stored in DiscoveryStore, consumed by AuthorizationScanner)
Investigation evidence in reports             → YES (linked to evidence_engine, rendered by reporters)
confirmed_endpoint drives re-testing          → YES (RelationshipGraph reads them)
GQL probe is cross-role                       → YES (compares attacker vs owner GQL responses)
```

After Phase 2:

```
Parameter-level IDOR generated from intelligence → YES (not just URL-level)
Role levels derived from discovery store          → YES (not hardcoded)
Intelligence waste rate < 15%                     → YES (3+ unused categories find consumers)
```

After Phase 3:

```
Single IDOR code path (ScannerBase)               → YES
All legacy GQL engine code removed                → YES
KPIs instrumented and logged to output             → YES
```

---

## Appendix: Signal Flow by Category

| DiscoveryStore Category | Producer | Consumer | Tests Generated | Status |
|---|---|---|---|---|
| `numeric_id` | ObjectHarvester | RelationshipGraph → AuthorizationScanner | URL candidate addition | ✅ Working |
| `uuid` | ObjectHarvester | RelationshipGraph → AuthorizationScanner | URL candidate addition | ✅ Working |
| `email` | ObjectHarvester | Orchestrator → URL priority scoring | Priority reordering only | ⚠️ Partial |
| `jwt` | ObjectHarvester | **None** | None | 🔴 Unused |
| `role` | ObjectHarvester + GQL pipeline | GQL pipeline (role escalation) | GQL plan generation | ⚠️ Partial (GQL only) |
| `ownership_hint` | ObjectHarvester + OwnershipDiscovery + GQL Ownership | RelationshipGraph → AuthorizationScanner | URL candidate addition | ✅ Working |
| `ownership_relationship` | ObjectHarvester + OwnershipDiscovery | RelationshipGraph → AuthorizationScanner | URL candidate addition | ✅ Working |
| `private_ip` | ObjectHarvester | Orchestrator → artifact finding | Informational only | 🔴 Unused for auth |
| `api_key` | ObjectHarvester | Orchestrator → artifact finding | Informational only | 🔴 Unused for auth |
| `graphql_response` | ObjectHarvester | URL pool injection | URL addition only | ⚠️ Partial |
| `gql_type` | ApiScanner | GQL RelationshipEngine → Mapper | Auth plan generation | ⚠️ Partial (plans not executed) |
| `gql_field` | ApiScanner | GQL RelationshipEngine → Mapper | Auth plan generation | ⚠️ Partial |
| `gql_relationship` | ApiScanner | GQL RelationshipEngine | Relationship classification only | ⚠️ Partial |
| `gql_inferred_relationship` | GQL RelationshipEngine | GQL OwnershipDiscovery → Mapper | Auth plan generation | ⚠️ Partial |
| `gql_ownership_chain` | GQL RelationshipEngine | **None** | None | 🔴 Unused |
| `gql_auth_plan` | GQL AuthorizationMapper | GraphQLAuthTester + main.py | Cross-role GQL probes | 🔴 Broken (orchestrator bug) |
| `confirmed_endpoint` | main.py (investigation feedback) | **None** | None | 🔴 Unused |
| `validated_resource` | main.py (investigation feedback) | **None** | None | 🔴 Unused |
| `api_model` | ApiScanner (OpenAPI) | IdorScanner | Stateful IDOR tests | ⚠️ Partial (POST only) |
| `api_property` | ApiScanner (OpenAPI) | OwnershipDiscovery (schema analysis) | Ownership hint generation | ⚠️ Partial |
| `business_workflow` | BusinessLogicDiscovery | BL candidate exploitation | Workflow abuse tests | ✅ Working |
| `candidate_yield` | Orchestrator | Investigation candidate queue | Investigation dispatch | ✅ Working |

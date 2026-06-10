# BugBounty-Hunter Authorization Intelligence Platform

## Architecture Review & Implementation Roadmap

---

## Part 1: Authorization Intelligence Audit

### Current State: What Intelligence Is Discovered

| Intelligence Type | Discovered By | Stored In | Consumers | Status |
|---|---|---|---|---|
| Numeric IDs | ObjectHarvester (JSON + regex) | DiscoveryStore | ApiScanner (GQL vars), RelationshipGraph | Used |
| UUIDs | ObjectHarvester (JSON + regex) | DiscoveryStore | RelationshipGraph | Used |
| Emails | ObjectHarvester (JSON + regex) | DiscoveryStore | RelationshipGraph | Used |
| Ownership hints | ObjectHarvester (JSON, `OWNER_KEYS`) | DiscoveryStore | RelationshipGraph, orchestrator | Used |
| Ownership relationships | ObjectHarvester (co-occurring id+owner) | DiscoveryStore | RelationshipGraph, orchestrator | Used |
| JWT tokens | ObjectHarvester (regex) | DiscoveryStore | No consumer | Unused |
| Roles | ObjectHarvester (JSON, `ROLE_KEYS`) | DiscoveryStore | No consumer | Unused |
| Private IPs | ObjectHarvester (regex) | DiscoveryStore | No consumer | Unused |
| API keys | ObjectHarvester (regex) | DiscoveryStore | No consumer | Unused |
| GQL types | ApiScanner (`_store_gql_types`) | DiscoveryStore | No consumer | Unused |
| GQL fields | ApiScanner (`_store_gql_types`) | DiscoveryStore | No consumer | Unused |
| GQL relationships | ApiScanner (`_store_gql_types`) | DiscoveryStore | No consumer | Unused |
| API models | ApiScanner (OpenAPI) | DiscoveryStore | IdorScanner (POST only) | Partially used |
| API properties | ApiScanner (OpenAPI) | DiscoveryStore | No consumer | Unused |
| GraphQL responses | ObjectHarvester (signal only) | DiscoveryStore | No consumer | Unused |
| Escalation paths | ImpactEscalationAnalyzer | Finding attributes | No consumer | Computed, invisible |
| AuthZ comparisons | AuthorizationEngine | EvidenceEngine | OwnershipValidator | Used |
| Cross-account replay | MultiAccountDiscoveryEngine | Returned list | No consumer | Dead code |

### Intelligence Flow: Current State

```
Recon → recon_data["urls", "forms", ...]
  ↓
JS Intelligence → js_data + recon_data["urls"]
  ↓
AuthorizationScanner (TARGET_LEVEL)
  └─→ queries RelationshipGraph.get_auth_candidates()
  └─→ produces AuthorizationComparisonEvidence
  └─→ stored in EvidenceEngine
  ↓
run_scans() (per-URL modules: IDOR, XSS, SQLi, etc.)
  ├─→ ScannerBase._add_finding() → ObjectHarvester → DiscoveryStore
  ├─→ ApiScanner._store_gql_types() → DiscoveryStore [UNUSED]
  └─→ ApiScanner._store_openapi_to_discovery_store() → DiscoveryStore
  ↓
orchestrator post-scan
  ├─→ ObjectHarvester.harvest() → DiscoveryStore (runs AFTER authz)
  ├─→ OwnershipValidator.validate() → OwnershipEvidence
  ├─→ ImpactValidator.validate() → ImpactEvidence
  ├─→ ImpactEscalationAnalyzer → _escalation_result [COMPUTED, INVISIBLE]
  └─→ OutcomeFeedbackEngine → outcomes.jsonl [NEVER CONSUMED]
  ↓
InvestigationEngine → confidence boosts [NO FEEDBACK TO DISCOVERY]
  ↓
Report generation
```

### Critical Gap: No Discover → Learn → Discover-More Loop

```
CURRENT:                          NEEDED:
Discover                           Discover
  ↓                                  ↓
Validate                          Learn (extract relationships)
  ↓                                  ↓
Report                           Discover More (new candidates)
                                    ↓
                                  Validate
                                    ↓
                                  Investigate
                                    ↓
                                  Report
```

---

## Part 2: Authorization Knowledge Graph Design

### Data Model

```python
@dataclass
class AuthorizationNode:
    """A principal, resource, or group in the authorization model."""
    node_type: Literal["user", "role", "organization", "tenant", "project",
                        "invoice", "resource", "group", "account"]
    identifier: str             # The ID value
    label: str                  # Human-readable name if known
    source_url: str             # Where this was discovered
    evidence_fingerprint: str   # Link to evidence
    attributes: dict            # Extra metadata (email, role_name, etc.)

@dataclass
class AuthorizationEdge:
    """A relationship between two nodes."""
    edge_type: Literal["owns", "belongs_to", "contains", "manages",
                        "invited_to", "shares_with", "administers",
                        "can_read", "can_write", "can_delete", "member_of"]
    source_node: AuthorizationNode
    target_node: AuthorizationNode
    confidence: float           # 0.0-1.0
    evidence_fingerprint: str   # Link to evidence
    discovery_method: str       # How this was inferred

@dataclass
class AuthorizationBoundary:
    """An inferred access boundary for a resource type."""
    resource_pattern: str       # URL pattern like /api/projects/{id}
    resource_type: str          # "project", "invoice", "user", etc.
    owner_field: str | None     # JSON field indicating owner
    role_field: str | None      # JSON field indicating role
    allowed_roles: list[str]    # Roles permitted to access
    boundary_type: Literal["user_isolation", "tenant_isolation",
                            "role_based", "ownership_based"]
```

### Storage

Extend DiscoveryStore with two new tables:

```sql
CREATE TABLE authz_nodes (
    fingerprint TEXT PRIMARY KEY,
    node_type TEXT NOT NULL,
    identifier TEXT NOT NULL,
    label TEXT,
    source_url TEXT,
    evidence_fingerprint TEXT,
    attributes TEXT,          -- JSON
    first_seen REAL,
    last_seen REAL
);

CREATE TABLE authz_edges (
    fingerprint TEXT PRIMARY KEY,
    edge_type TEXT NOT NULL,
    source_fingerprint TEXT NOT NULL REFERENCES authz_nodes(fingerprint),
    target_fingerprint TEXT NOT NULL REFERENCES authz_nodes(fingerprint),
    confidence REAL DEFAULT 0.5,
    evidence_fingerprint TEXT,
    discovery_method TEXT,
    first_seen REAL,
    last_seen REAL
);

CREATE TABLE authz_boundaries (
    fingerprint TEXT PRIMARY KEY,
    resource_pattern TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    owner_field TEXT,
    role_field TEXT,
    allowed_roles TEXT,        -- JSON array
    boundary_type TEXT NOT NULL,
    source_url TEXT,
    confidence REAL DEFAULT 0.5
);
```

---

## Part 3: Ownership Discovery Engine

### Current Weakness
`OwnershipValidator` is reactive — it can only validate ownership AFTER `AuthorizationComparisonEvidence` exists. It cannot proactively discover ownership.

### Design

```python
class OwnershipDiscoveryEngine:
    """Proactively discovers ownership before testing."""

    def discover_ownerships(
        self,
        recon_data: dict,
        store: DiscoveryStore,
        graph: RelationshipGraph,
    ) -> list[OwnershipSignal]:
        """Aggregate ownership signals from all sources."""
        signals = []
        signals.extend(self._from_response_patterns(recon_data))
        signals.extend(self._from_graphql_schema(store))
        signals.extend(self._from_openapi_spec(store))
        signals.extend(self._from_jwt_claims(store))
        signals.extend(self._from_html_patterns(recon_data))
        return signals

    def _from_response_patterns(self, recon_data) -> list[OwnershipSignal]:
        """Parse response excerpts for owner_id, created_by, assigned_to, etc.
        Does NOT wait for JSON parsing — also looks at raw response text for
        `"owner_id":` patterns even in non-JSON contexts."""

    def _from_graphql_schema(self, store) -> list[OwnershipSignal]:
        """Query DiscoveryStore for gql_field records where field names indicate
        ownership: owner, user, creator, organization, tenant."""

    def _from_openapi_spec(self, store) -> list[OwnershipSignal]:
        """Query api_property records where parameter names indicate ownership
        (owner_id, user_id, org_id, tenant_id) or where read-only fields
        suggest ownership (created_by, creator)."""

    def _from_jwt_claims(self, store) -> list[OwnershipSignal]:
        """Parse stored JWT tokens for sub, roles, org_id, tenant_id claims.
        Even expired JWTs encode the authorization model."""

    def build_ownership_hypothesis(
        self,
        signals: list[OwnershipSignal],
    ) -> OwnershipHypothesis:
        """Combine signals into testable hypothesis:
        Resource type X is owned by user_id field Y.
        Access by user Z to resource X without ownership is a violation."""
```

### Integration Points

| Integration | Where | When |
|---|---|---|
| Into Recon pipeline | `main.py` after JS/SPA recon | Before AuthorizationScanner runs |
| Into ObjectHarvester | Post-harvest enrichment | After each harvest batch |
| Into ScanPipeline | `orchestrator.py` before URL scoring | Pre-scan, feeds priority engine |
| Into AuthZScanner | As candidate source | TARGET_LEVEL module init |

---

## Part 4: Role Discovery Engine

### Current Weakness
Roles are harvested (`ROLE_KEYS`) and stored in DiscoveryStore, but no component consumes them. The `role` category is stored but never queried. JWT tokens (`jwt` category) contain role/claim data but are also never decoded or queried.

### Design

```python
@dataclass
class RoleModel:
    role_name: str
    source_url: str
    discovery_method: Literal["json_response", "jwt_claim", "html", "graphql", "api_response"]
    permissions: list[str]          # Extracted permission strings
    hierarchy_level: int | None    # Inferred level (admin=4, manager=3, etc.)
    evidence_fingerprint: str

class RoleDiscoveryEngine:
    def discover_roles(
        self,
        store: DiscoveryStore,
        recon_data: dict,
        jwt_decode: bool = True,
    ) -> list[RoleModel]:
        """Aggregate role intelligence from all sources."""
        roles = []
        roles.extend(self._from_stored_roles(store))          # Already harvested
        roles.extend(self._from_stored_jwts(store, jwt_decode))  # JWT payloads
        roles.extend(self._from_response_headers(recon_data))    # X-Roles, etc.
        roles.extend(self._from_url_patterns(recon_data))        # /admin/, /api/v1/
        roles.extend(self._from_gql_types(store))               # GQL directive patterns
        return roles

    def _from_stored_jwts(self, store, decode: bool) -> list[RoleModel]:
        """Fetch jwt records from DiscoveryStore, base64-decode payload,
        extract sub, roles, permissions, org_id, tenant_id."""

    def infer_hierarchy(self, roles: list[RoleModel]) -> dict[str, int]:
        """Build role hierarchy from naming conventions:
        admin > manager > editor > member > viewer > guest
        Also uses HTTP status differences (403 vs 200) to infer."""

    def build_role_hypothesis(
        self,
        roles: list[RoleModel],
    ) -> RoleHypothesis:
        """A testable hypothesis about the role model:
        Admin can access /admin/*, viewer cannot.
        Manager can write, viewer can only read."""
```

### Integration Points

| Integration | Where | When |
|---|---|---|
| JWT decoder | DiscoveryStore read path | When roles are queried by AuthorizationScanner |
| Role hierarchy | AuthorizationScanner initialization | Provides level comparison for vertical testing |
| Permission hypothesis | BoundaryMapper | Feeds boundary inference |

---

## Part 5: Authorization Boundary Mapping

### Design

```python
class BoundaryMapper:
    """Automatically model access boundaries from discovered intelligence."""

    def map_boundaries(
        self,
        ownership_signals: list[OwnershipSignal],
        role_models: list[RoleModel],
        relationship_graph: RelationshipGraph,
        discovery_store: DiscoveryStore,
    ) -> list[AuthorizationBoundary]:
        """Produce candidate authorization boundaries."""
        boundaries = []
        boundaries.extend(self._from_ownership_patterns(ownership_signals))
        boundaries.extend(self._from_role_patterns(role_models))
        boundaries.extend(self._from_url_patterns(relationship_graph))
        boundaries.extend(self._from_gql_schema(discovery_store))
        boundaries.extend(self._from_openapi_schema(discovery_store))
        return boundaries

    def _from_url_patterns(self, graph) -> list[AuthorizationBoundary]:
        """For each URL pattern with ownership signals, infer boundary:
        /api/projects/{id} → user_isolation (owned by user_id field)
        /api/organizations/{id} → tenant_isolation (org-scoped)
        /api/admin/* → role_based (admin-only)"""

    def _from_gql_schema(self, store) -> list[AuthorizationBoundary]:
        """For each GQL type with ownership relationships:
        type Project { owner: User! } → user_isolation via owner field
        type Organization { members: [User!]! } → tenant_isolation"""

    def generate_candidates(
        self,
        boundaries: list[AuthorizationBoundary],
    ) -> list[BoundaryViolationCandidate]:
        """For each boundary, create testable candidates:
        - Try user A accessing user B's resource (same type)
        - Try role X accessing role Y's endpoint
        - Try tenant A accessing tenant B's data"""
```

### Violation Candidate Types

| Candidate Type | Boundary Trigger | Test Method |
|---|---|---|
| `horizontal_idor` | user_isolation boundary | User A's resource ID → User B's session |
| `vertical_privesc` | role_based boundary | Low-role session → high-role endpoint |
| `cross_tenant` | tenant_isolation boundary | Tenant A's org ID → Tenant B's session |
| `ownership_bypass` | ownership_based boundary | Non-owner session → modify resource |
| `field_level_exposure` | gql_role boundary | Low-role GQL query for restricted fields |

---

## Part 6: Differential Authorization Analysis

### Design

```python
@dataclass
class FieldLevelDifference:
    field_path: str              # "data.user.email"
    type: Literal["missing", "extra", "different_value", "null_vs_value"]
    original_value: Any
    target_value: Any
    sensitivity: Literal["pii", "financial", "credential", "internal", "none"]

class DifferentialAuthorizationEngine:
    """Compare responses across accounts at field level, not just HTTP status."""

    def compare(
        self,
        response_a: str | dict,
        response_b: str | dict,
        sensitivity_classifier: SemanticResponseAnalyzer | None = None,
    ) -> ComparisonResult:
        """Deep comparison of two responses."""
        # Parse both as JSON if possible
        # Recursively diff field by field
        # Classify differences by sensitivity
        # Flag differences that indicate authZ flaws

    def compare_http(
        self,
        req_a: requests.Response,
        req_b: requests.Response,
    ) -> AuthorizationComparison:
        """Full HTTP comparison with field-level analysis."""
        # Compare status codes
        # Compare headers (especially X-Role, X-Permissions)
        # Compare body at field level (JSON)
        # Compare body excerpt (non-JSON)
        # Classify: ownership_violation, field_leak, status_bypass

    def classify_violation(
        self,
        diff: FieldLevelDifference,
        context: AuthorizationBoundary,
    ) -> ViolationType:
        """Determine if a field difference represents an authZ violation."""
```

### Current Weakness in `AuthorizationEngine.test_endpoint()`

```python
# CURRENT: Only checks status + 200-char body excerpt
ownership_violation = (
    content_diff
    and same_status
    and target_status == 200
)

# NEEDED: Field-level comparison with sensitivity awareness
comparison = diff_engine.compare_http(resp_a, resp_b)
field_leaks = [
    d for d in comparison.field_diffs
    if d.type in ("extra", "different_value")
    and d.sensitivity in ("pii", "financial", "credential")
]
```

---

## Part 7: Multi-Account Expansion

### Current Weakness
`MultiAccountDiscoveryEngine` is fully implemented but **never called** — zero callers in the entire pipeline. Additionally, `AuthorizationScanner` and `MultiAccountDiscoveryEngine` duplicate functionality without sharing logic.

### Fix: Wire MultiAccountDiscoveryEngine into Pipeline

```python
# In orchestrator.py or main.py, after run_scans():
if container.multi_account_discovery:
    mae = container.multi_account_discovery
    candidates = mae.discover_candidates(recon_data, container.discovery_store)
    if candidates and len(role_sessions) >= 2:
        cross_account_findings = mae.run_cross_account_scan(
            recon_data, container.discovery_store, role_sessions
        )
        for f in cross_account_findings:
            all_findings.append(f)
```

### Expansion: Every Discovered Resource Becomes a Candidate

| Intelligence | Becomes Candidate For |
|---|---|
| `numeric_id` from DiscoveryStore | Cross-account replay on owner endpoints |
| `ownership_hint` from response | Cross-role verification on the same resource |
| `uuid` from DiscoveryStore | Cross-tenant IDOR testing |
| GQL mutation with ID arg | Cross-account mutation replay |
| Stateful create result | Cross-role access to created resource |
| SPA-discovered API route | Cross-session replay on new endpoints |

---

## Part 8: GraphQL Authorization Intelligence

### Current Weakness
Two separate GQL code paths exist (`GraphQLScanner` via ScannerBase, `ApiScanner` via ScannerModuleBase) with **zero intelligence sharing**. GQL types/fields/relationships are stored in DiscoveryStore but **never consumed** by any component.

### Design: GQL Authorization Discovery

```python
class GqlAuthorizationEngine:
    """Discover authorization model from GraphQL schemas."""

    def discover_auth_model(
        self,
        store: DiscoveryStore,
    ) -> GqlAuthModel:
        """Build authorization model from stored GQL intelligence."""
        types = store.get_by_category("gql_type")
        fields = store.get_by_category("gql_field")
        relationships = store.get_by_category("gql_relationship")

        # Find ownership-related fields: owner, user, creator, organization
        ownership_fields = self._find_ownership_fields(types, fields)

        # Find role-related fields: role, permission, access, group
        role_fields = self._find_role_fields(types, fields)

        # Find auth-directive patterns (if directives were fetched)
        auth_directives = self._find_auth_directives(types)

        return GqlAuthModel(
            ownership_fields=ownership_fields,
            role_fields=role_fields,
            auth_directives=auth_directives,
            relationships=relationships,
        )

    def generate_auth_tests(
        self,
        model: GqlAuthModel,
        endpoint: str,
        roles: dict[str, Session],
    ) -> list[GqlAuthTest]:
        """Generate targeted GQL auth tests using real field selectors."""
        tests = []
        for rel in model.relationships:
            # Test: Low-role queries a restricted relationship field
            # Test: Cross-role queries mutation with different IDs
            # Test: Ownership field returns different data across roles
            ...
        return tests
```

### Key Improvement: Use Real Field Selectors

```python
# CURRENT:
query = f"mutation {{ {mutation_name}({args}) {{ __typename }} }}"

# NEEDED: Use discovered type fields for meaningful comparison
# If Mutation.createProject returns type Project with fields {id, name, owner}:
query = f"""
mutation {{
  {mutation_name}({args}) {{
    id
    name
    owner {{ id email }}
  }}
}}
"""
```

---

## Part 9: Authorization Discovery Prioritization

### Design

```python
@dataclass
class AuthorizationScore:
    total: float
    signals: list[AuthorizationSignal]

@dataclass
class AuthorizationSignal:
    signal_type: str
    weight: float
    source: str
    description: str

class AuthorizationPriorityEngine:
    """Score targets by authorization potential."""

    SCORE_WEIGHTS = {
        "has_ownership_signal": 45,      # owner_id, created_by in responses
        "has_role_signal": 40,           # admin, manager in responses
        "has_tenant_signal": 40,         # org_id, tenant_id in responses
        "has_sensitive_data": 35,        # PII, financial data detected
        "is_graphql": 30,               # GQL endpoint with mutations
        "is_admin_endpoint": 25,         # /admin/, /manage/ in path
        "has_id_in_path": 20,           # Numeric ID in path segment
        "has_multiple_roles": 15,        # Response shows role differentiation
        "is_create_endpoint": 15,        # POST /api/resources
        "is_stateful": 10,              # Create→read→delete workflow
    }

    def score_endpoint(
        self,
        url: str,
        method: str,
        store: DiscoveryStore,
        graph: RelationshipGraph,
        recon_data: dict,
    ) -> AuthorizationScore:
        signals = []
        # Check DiscoveryStore for ownership hints on this URL
        # Check RelationshipGraph for auth candidates
        # Check recon_data for sensitive data classification
        # Check stored GQL types for this endpoint
        # Check OpenAPI models/properties
        return AuthorizationScore(
            total=sum(s.weight for s in signals),
            signals=signals,
        )
```

---

## Part 10: Authorization-Centric Investigation

### Current Weakness
The `InvestigationEngine` has `horizontal_idor` and `vertical_idor` strategies, but `_exec_idor()` sends a single-session GET. It does NOT:
- Use `AuthorizationEngine.test_endpoint()` for cross-account comparison
- Use `MultiAccountDiscoveryEngine` for cross-role testing
- Feed results back into `DiscoveryStore`

### Design: Authorization Investigation

```python
# New strategies for InvestigationEngine
STRATEGY_REGISTRY.extend([
    Strategy("cross_account_replay", "oob", cost=4, priority=90,
             description="Replay request across accounts via AuthorizationEngine"),
    Strategy("cross_tenant_replay", "none", cost=3, priority=85,
             description="Replay with different tenant context"),
    Strategy("ownership_bypass", "none", cost=3, priority=85,
             description="Test ownership bypass with modified IDs"),
    Strategy("role_escalation", "none", cost=3, priority=80,
             description="Test vertical privilege escalation"),
    Strategy("gql_auth_bypass", "none", cost=4, priority=85,
             description="Test GQL field-level auth across roles"),
])

# New executor methods
def _exec_cross_account_replay(self, finding, plan):
    """Use AuthorizationEngine to compare role A vs role B on the finding's URL."""
    engine = AuthorizationEngine(...)
    result = engine.test_endpoint(finding.url, role_a, role_b)

def _exec_cross_tenant_replay(self, finding, plan):
    """Modify tenant-scoping parameters (org_id, tenant_id) and replay."""

def _exec_ownership_bypass(self, finding, plan):
    """Modify ID parameters and check non-owner access."""

def _exec_role_escalation(self, finding, plan):
    """Send request with progressively higher-role sessions."""

def _exec_gql_auth_bypass(self, finding, plan):
    """Deep GQL auth test with real field selectors."""
```

### Feedback Loop: Investigation → DiscoveryStore

```python
def _apply_result(self, finding, plan, result):
    # ... existing code (confidence, stage, reasons) ...

    # NEW: Feed back into DiscoveryStore
    self._feed_discovery_store(finding, plan, result)

def _feed_discovery_store(self, finding, plan, result):
    """Store investigation discoveries back into the intelligence store."""
    if not self.container or not self.container.discovery_store:
        return
    store = self.container.discovery_store
    url = finding.url
    if plan.strategy in ("horizontal_idor", "cross_account_replay"):
        # The confirmed accessible URL/resource is new intelligence
        store.record("confirmed_authz_violation", url,
                     source_url=url,
                     extra={"vuln_type": finding.vuln_type,
                            "strategy": plan.strategy})
        # The accessed resource ID (if any) is a validated target
        for param_name in ["id", "user_id", "account_id", "resource_id"]:
            param_val = plan.params.get(param_name)
            if param_val:
                store.record("validated_target_id", str(param_val),
                             source_url=url,
                             extra={"param": param_name})
```

---

## Priority Map: All Known Bottlenecks

### Critical (Blocking Multiple Discovery Paths)

| # | Bottleneck | Impact | Fix |
|---|---|---|---|
| C1 | **MultiAccountDiscoveryEngine is dead code** | 0% of cross-account testing actually runs | Wire into pipeline after AuthorizationScanner |
| C2 | **GQL type/field/relationship intelligence is unused** | 100% of GQL schema intelligence wasted | Build GqlAuthorizationEngine consumer |
| C3 | **Object harvesting runs after AuthorizationScanner** | Current-scan IDs can't influence authZ testing | Move harvest before TARGET_LEVEL, or run authZ last |
| C4 | **Impact escalation results are invisible** | Computed per finding, never rendered | Surface in reports / submission packages |

### High (Major Discovery Opportunities Missed)

| # | Bottleneck | Impact | Fix |
|---|---|---|---|
| H1 | **Authorization comparison is too narrow** | Misses violations where status differs or fields leak | Field-level diff engine |
| H2 | **Roles harvested but never consumed** | Role intelligence stored, zero queries | RoleDiscoveryEngine + role hierarchy inference |
| H3 | **JWT tokens harvested but never decoded** | JWT claims (sub, roles, org) stored but unreadable | Decode on store or on query |
| H4 | **GQL auth test uses `__typename` only** | Can't detect field-level authZ differences | Use discovered type fields in query selector |
| H5 | **OwnershipValidator is passive-only** | Can't discover ownership without prior authZ evidence | OwnershipDiscoveryEngine |

### Medium (Valuable But Lower Impact)

| # | Bottleneck | Impact | Fix |
|---|---|---|---|
| M1 | **Sensitive data patterns unused** | PII/financial data classifications lost | Surface in authZ comparison evidence |
| M2 | **`get_related_urls()` is dead code** | ID cross-referencing capability unused | Consume in IDOR horizontal scanning |
| M3 | **AuthSessionManager not used by AuthorizationScanner** | Duplicate role-session building | Wire container singleton |
| M4 | **OpenAPI `api_property` records unused** | Parameter metadata (types, constraints) wasted | Feed to IDOR param fuzzing / body building |
| M5 | **Stateful IDOR scoped to first 10 targets** | Misses long-tail stateful workflows | Configurable limit, prioritize by score |

### Low (Nice-to-Have Improvements)

| # | Bottleneck | Impact | Fix |
|---|---|---|---|
| L1 | **`private_ip` and `api_key` categories unused** | Low-priority intelligence | Surface in reporting |
| L2 | **`graphql_response` category is just a signal** | No value stored, just a flag | Remove or enrich |
| L3 | **Asset graph always None** | Escalation analysis lacks context | Wire from recon or remove parameter |
| L4 | **`boolean_sqli` investigation is no-op** | `continue` on line 623 skips actual testing | Implement or remove |

---

## Implementation Roadmap

### Phase 1: Wire Dead Code (Critical — Estimated 2-3 days)

1. **Wire MultiAccountDiscoveryEngine into pipeline**
   - Add to container as singleton
   - Call from `main.py` after `run_scans()` when >= 2 role sessions exist
   - Deduplicate with AuthorizationScanner findings

2. **Build GqlAuthorizationEngine consumer**
   - Query DiscoveryStore for `gql_type`, `gql_field`, `gql_relationship`
   - Feed GQL ownership/role intelligence into RelationshipGraph
   - Use GQL relationships in boundary inference

3. **Surface impact escalation results**
   - Render `_escalation_result` and `_best_escalation_path` in all reporter formats
   - Add to HTML report finding cards
   - Add to JSON output

### Phase 2: Deep Authorization Intelligence (High — Estimated 4-5 days)

4. **Field-level differential comparison**
   - Build `DifferentialAuthorizationEngine`
   - Integrate into `AuthorizationEngine.test_endpoint()`
   - Add sensitivity classification via SemanticResponseAnalyzer
   - Detect field-level leaks (extra fields, missing fields, different values)

5. **OwnershipDiscoveryEngine**
   - Proactive ownership inference from response patterns, GQL schema, OpenAPI specs, JWT claims
   - Inject into pre-scan pipeline before AuthorizationScanner
   - Feed ownership hypotheses into boundary mapping

6. **RoleDiscoveryEngine + JWT decoder**
   - Decode stored JWT tokens, extract sub/roles/org_id claims
   - Infer role hierarchy from naming conventions + HTTP diff patterns
   - Feed role intelligence into authorization priority scoring

### Phase 3: GQL Authorization Testing (High — Estimated 3-4 days)

7. **GQL auth test with real field selectors**
   - `_build_gql_variables()` uses discovered type fields instead of `__typename`
   - Selection set includes ownership and role fields for comparison
   - Detect field-level differences across roles

8. **GQL directive parsing**
   - Extend introspection query to fetch directives
   - Parse `@auth`, `@hasRole`, `@isOwner`, `@requires` directives
   - Store directive info in DiscoveryStore as `gql_directive` records

9. **GQL mutation auth testing with discovered IDs**
   - Use all ID types (`numeric_id`, `uuid`, `email`) — not just numeric
   - Fallback with structurally valid ID patterns rather than `"test"`

### Phase 4: Authorization Priority & Investigation (Medium — Estimated 3-4 days)

10. **AuthorizationPriorityEngine**
    - 10 signal weights (ownership, role, tenant, sensitive data, GQL, admin, etc.)
    - Score all URLs pre-scan and pre-authorization
    - Re-sort URL queue when new intelligence arrives mid-scan

11. **Authorization investigation strategies**
    - Cross-account, cross-tenant, ownership bypass, role escalation
    - GQL auth bypass with real field selectors
    - Feedback loop: confirmed violations → DiscoveryStore

12. **Investigation → Discovery feedback**
    - Store confirmed violation URLs as `confirmed_authz_violation`
    - Store validated target IDs as `validated_target_id`
    - Feed back into RelationshipGraph for next-scan use

### Phase 5: Boundary Mapping & Ownership (Medium — Estimated 4-5 days)

13. **BoundaryMapper**
    - Consolidate ownership, role, tenant, and GQL signals into unified boundaries
    - Generate violation candidates from boundaries
    - Feed candidates to AuthorizationScanner and InvestigationEngine

14. **Move ObjectHarvesting before AuthorizationScanner**
    - Run harvest on recon responses before TARGET_LEVEL modules
    - Extract IDs from forms, JS responses, SPA state
    - Let AuthorizationScanner use current-scan IDs

15. **Expand stateful IDOR**
    - Use ownership hints to prioritize stateful targets
    - Add PUT/PATCH update workflow testing
    - Add multi-step workflows (create A → create B referencing A → cross-account)
    - Store exploited IDs back to DiscoveryStore

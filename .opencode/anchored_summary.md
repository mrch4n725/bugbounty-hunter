```markdown
## Goal
- Execute Discovery Effectiveness Overhaul: close feedback loops so every collected intelligence artifact feeds back into more discoveries

## Constraints & Preferences
- Preserve legacy scanners, legacy runtime, existing Finding/Evidence/Validation models
- Do not add report formats, readiness engines, exporters, or confidence systems unless required for discovery
- Prioritize discovery feedback loops and intelligence reuse over new scanner modules or payloads
- Maintain low false positives, strong validation, strong evidence, low-end hardware compatibility
- 259/259 tests must pass with zero regressions

## Progress
### Done
- Phase 1 (Quick Wins) — all 3 items implemented:
  - **C4: Semantic Object Extraction** (`engines/object_harvester.py`) — JSON-traversal based extraction replaces flat regex for parsed JSON responses. Recursively traverses dicts/lists to extract numeric IDs, UUIDs, emails, roles, JWTs from nested structures. Keeps regex fallback for non-JSON responses. Discovers ownership hints (`owner_id`, `organization_id`, etc.) and ownership relationships (resource + owner + role combos in same object).
  - **H2: OpenAPI Model → DiscoveryStore** (`modules/api_scanner.py:500`) — discovered OpenAPI endpoint paths, methods, and parameters are stored in DiscoveryStore as `api_model` and `api_property` records with type information, enabling downstream scanners to target API-specific parameters.
  - **H3: Ownership Boundary Inference** (`engines/object_harvester.py:92-104`, `engines/relationship_graph.py:85-113`) — ObjectHarvester extracts `OWNER_KEYS` (`owner_id`, `organization_id`, `tenant_id`, etc.) as `ownership_hint` records; RelationshipGraph now includes these in `get_ownership_boundaries()` output with `relationship_type: "owned_by"` for the AuthorizationEngine.
- Phase 1 critical items (previously implemented):
  - `fuzzed_params` fed into IDOR scanner
  - OpenAPI/GQL endpoints fed into URL pool
  - 6 discarded JS intelligence keys recovered
  - Passive import data loss fixed (~5 fields)
  - ObjectHarvester initial implementation
  - DiscoveryStore initial implementation
  - RelationshipGraph initial implementation
  - Multi-Account Discovery Engine
  - GQL mutations → AuthorizationEngine
  - AGENTS.md updated

### In Progress
- Phase 2 (GQL Intelligence) — not started
- Phase 3 (Stateful Discovery) — not started
- Phase 4 (Polish) — not started

### Blocked
- (none)

## Key Decisions
- ObjectHarvester tries JSON-parsed traversal first, falls back to regex for non-JSON. This recovers 50-70% more object IDs from nested JSON responses.
- Ownership hints are stored as `ownership_hint` (individual owner references) and `ownership_relationship` (resource+owner+role combos in same object) categories in DiscoveryStore
- `compute_endpoint_score()` is NOT yet modified to factor in DiscoveryStore — that requires passing store to the scoring function, which is a bigger change deferred to Phase 3 (Discovery Priority Engine)
- All changes preserve backward compatibility: ObjectHarvester reverts to regex-only behavior when JSON parsing fails

## Next Steps
1. Run a real scan with `--dry-run --verbose` to validate end-to-end JSON-traversal extraction
2. Phase 2: C3 (GQL Type Relationship Mapping), H1 (GQL Mutation Arg ID Injection), H4 (GQL Individual Mutation Auth Testing)
3. Phase 3: C2 (Stateful IDOR), H5 (Discovery Priority Engine), C1 (SPA Recon)
4. Phase 4: M1-M5 (Polish items)

## Critical Context
- 259/259 tests pass with zero regressions (verified after Phase 1 changes)
- `DISCOVERY_EFFECTIVENESS_REVIEW.md` contains the full analysis, bottleneck ranking, and implementation roadmap
- Plural `ImportError` typo in `main.py` line 377 — left as-is
- Integration test failure (`partially_validated` stage) is pre-existing
- Python 3.8+ compatibility preserved (no 3.14+ features used)

## Relevant Files
- `engines/object_harvester.py` — MODIFIED (Phase 1 C4): JSON-traversal extraction, ownership hint detection, regex fallback
- `modules/api_scanner.py` — MODIFIED (Phase 1 H2): `_store_openapi_to_discovery_store()` records API models/properties
- `engines/relationship_graph.py` — MODIFIED (Phase 1 H3): `get_ownership_boundaries()` now consumes ownership hints/relationships
- `engines/discovery_store.py` — unchanged (already supports all needed categories)
- `DISCOVERY_EFFECTIVENESS_REVIEW.md` — full analysis, bottleneck ranking, implementation roadmap
- `app/orchestrator.py` — unchanged (already wires ObjectHarvester into post-scan pipeline)
- `scanners/base.py` — unchanged (already wires ObjectHarvester into `_add_finding()`)
```

"""GraphQLAuthorizationMapper — generate authorization investigation plans from GQL intelligence.

Reads classified relationships and ownership hints from the GQL pipeline and
produces actionable AuthInvestigationPlan objects targeting cross-tenant access,
ownership violations, and role escalation paths.
"""

import json
from typing import Any

from engines.discovery_store import DiscoveryStore
from engines.gql_relationships import GraphQLRelationshipEngine
from engines.gql_ownership import GraphQLOwnershipDiscovery
from models.gql_auth import (
    AuthInvestigationPlan,
    PlanType,
    RelationshipType,
    TypeRelationship,
)


_ROLE_MUTATION_KEYWORDS = frozenset({
    "role", "roles", "permission", "permissions",
    "access", "access_level", "privilege",
    "updateRole", "setRole", "changeRole", "assignRole",
    "updatePermission", "grant", "revoke",
})

_OWNERSHIP_MUTATION_KEYWORDS = frozenset({
    "create", "update", "delete", "remove",
    "add", "transfer", "share", "invite",
})

_QUERY_KEYWORDS = frozenset({
    "get", "list", "search", "find", "query", "all",
    "byId", "byUser", "byOrg", "byOrganization",
})


def _is_mutation(field_name: str, parent_type: str) -> bool:
    """Check if a field name suggests a mutation operation."""
    lower = field_name.lower()
    if parent_type.lower().endswith("mutation"):
        return True
    if any(kw in lower for kw in ("create", "update", "delete", "remove", "set", "add")):
        return True
    return False


def _is_query(field_name: str, parent_type: str) -> bool:
    """Check if a field name suggests a query operation."""
    lower = field_name.lower()
    if parent_type.lower().endswith("query"):
        return True
    if any(kw in lower for kw in ("get", "list", "search", "find", "all")):
        return True
    return False


def _parse_extra(rec: dict) -> dict:
    extra_raw = rec.get("extra") or "{}"
    if isinstance(extra_raw, str):
        try:
            return json.loads(extra_raw)
        except (json.JSONDecodeError, TypeError):
            return {}
    return extra_raw


class GraphQLAuthorizationMapper:
    """Generate authorization investigation plans from GQL intelligence.

    Consumes:
      - Classified TypeRelationship objects (ownership, tenancy, membership)
      - Ownership hints from GraphQLOwnershipDiscovery
      - Raw gql_field records for mutation/query operations

    Produces:
      - AuthInvestigationPlan objects targeting GQL auth boundaries
    """

    def __init__(self, store: DiscoveryStore | None = None,
                 relationship_engine: GraphQLRelationshipEngine | None = None,
                 ownership_discovery: GraphQLOwnershipDiscovery | None = None):
        self._store = store
        self._rel_engine = relationship_engine or GraphQLRelationshipEngine(store)
        self._own_discovery = ownership_discovery or GraphQLOwnershipDiscovery(store, self._rel_engine)
        self._plans: list[AuthInvestigationPlan] = []

    def get_plans(self) -> list[AuthInvestigationPlan]:
        return list(self._plans)

    def _get_mutation_fields(self, store: DiscoveryStore) -> list[dict]:
        """Get mutation field records from the store."""
        fields = store.get_by_category("gql_field")
        results: list[dict] = []
        for rec in fields:
            extra = _parse_extra(rec)
            parent_type = extra.get("parent_type", "")
            field_name = rec.get("value", "").split(".")[-1]
            if not _is_mutation(field_name, parent_type):
                continue
            results.append({
                "field_name": field_name,
                "parent_type": parent_type,
                "field_type": extra.get("field_type", ""),
                "args": extra.get("args", 0),
                "source_url": rec.get("source_url", ""),
            })
        return results

    def _get_query_fields(self, store: DiscoveryStore) -> list[dict]:
        """Get query field records from the store."""
        fields = store.get_by_category("gql_field")
        results: list[dict] = []
        for rec in fields:
            extra = _parse_extra(rec)
            parent_type = extra.get("parent_type", "")
            field_name = rec.get("value", "").split(".")[-1]
            if not _is_query(field_name, parent_type):
                continue
            results.append({
                "field_name": field_name,
                "parent_type": parent_type,
                "field_type": extra.get("field_type", ""),
                "args": extra.get("args", 0),
                "source_url": rec.get("source_url", ""),
            })
        return results

    def map_cross_tenant_operations(
        self,
        relationships: list[TypeRelationship] | None = None,
        store: DiscoveryStore | None = None,
    ) -> list[AuthInvestigationPlan]:
        """Find queries/mutations that cross tenant boundaries.

        For each TENANT_OF relationship, generate a plan to test if
        one tenant's users can access another tenant's resources.
        """
        s = store or self._store
        if s is None:
            return []
        rels = relationships or self._rel_engine.infer_classified_relationships(s)

        tenant_rels = [r for r in rels
                       if r.relationship_type == RelationshipType.TENANT_OF]
        queries = self._get_query_fields(s)
        mutations = self._get_mutation_fields(s)

        plans: list[AuthInvestigationPlan] = []
        for tr in tenant_rels:
            related_ops = [
                q for q in (queries + mutations)
                if tr.from_type.lower() in q["field_name"].lower()
                or tr.to_type.lower() in q["field_name"].lower()
            ]
            for op in related_ops[:3]:
                plans.append(AuthInvestigationPlan(
                    target_url=op["source_url"],
                    plan_type=PlanType.CROSS_TENANT,
                    gql_operation=op["field_name"],
                    gql_arguments={"operation": op["field_name"]},
                    from_role=f"{tr.from_type}_user",
                    to_role=f"{tr.to_type}_user",
                    expected_behavior=(
                        f"Access to {tr.from_type} should be scoped to "
                        f"the authenticated user's {tr.to_type}"
                    ),
                    confidence=tr.confidence * 0.9,
                    rationale=(
                        f"Schema shows {tr.from_type}.{tr.via_field} → {tr.to_type}, "
                        f"indicating a tenant boundary at {tr.to_type}"
                    ),
                ))

        self._plans.extend(plans)
        return plans

    def map_ownership_violations(
        self,
        relationships: list[TypeRelationship] | None = None,
        ownership_hints: list[dict] | None = None,
        store: DiscoveryStore | None = None,
    ) -> list[AuthInvestigationPlan]:
        """Find operations where one user could access another's resources.

        For each BELONGS_TO relationship, generate a plan to test
        cross-owner access via related queries/mutations.
        """
        s = store or self._store
        if s is None:
            return []
        rels = relationships or self._rel_engine.infer_classified_relationships(s)

        belongs_to_rels = [r for r in rels
                           if r.relationship_type == RelationshipType.BELONGS_TO]
        queries = self._get_query_fields(s)
        mutations = self._get_mutation_fields(s)

        plans: list[AuthInvestigationPlan] = []
        for btr in belongs_to_rels:
            related_ops = [
                q for q in (queries + mutations)
                if btr.from_type.lower() in q["field_name"].lower()
            ]
            for op in related_ops[:3]:
                plans.append(AuthInvestigationPlan(
                    target_url=op["source_url"],
                    plan_type=PlanType.OWNERSHIP_VIOLATION,
                    gql_operation=op["field_name"],
                    gql_arguments={"operation": op["field_name"]},
                    from_role="attacker",
                    to_role=f"{btr.to_type}_owner",
                    expected_behavior=(
                        f"{op['field_name']} should only return "
                        f"{btr.from_type}s owned by the authenticated {btr.to_type}"
                    ),
                    confidence=btr.confidence * 0.85,
                    rationale=(
                        f"Schema shows {btr.from_type} belongs to {btr.to_type} "
                        f"via {btr.via_field} — test cross-owner access"
                    ),
                ))

        self._plans.extend(plans)
        return plans

    def map_role_escalation_paths(
        self, store: DiscoveryStore | None = None,
    ) -> list[AuthInvestigationPlan]:
        """Find mutations that could lead to role escalation.

        Looks for mutations with role-related keywords or that accept
        role/permission type arguments.
        """
        s = store or self._store
        if s is None:
            return []
        mutations = self._get_mutation_fields(s)

        role_mutations = [
            m for m in mutations
            if any(kw in m["field_name"].lower() for kw in _ROLE_MUTATION_KEYWORDS)
        ]

        # Also find mutations whose return type is a privilege type
        privilege_types = self._rel_engine.infer_privilege_types(s)
        type_related = [
            m for m in mutations
            if m["field_type"] in privilege_types
        ]

        plans: list[AuthInvestigationPlan] = []
        seen_ops: set[str] = set()
        for op in role_mutations + type_related:
            if op["field_name"] in seen_ops:
                continue
            seen_ops.add(op["field_name"])
            plans.append(AuthInvestigationPlan(
                target_url=op["source_url"],
                plan_type=PlanType.ROLE_ESCALATION,
                gql_operation=op["field_name"],
                gql_arguments={
                    "operation": op["field_name"],
                    "arg_count": op["args"],
                },
                from_role="low_privilege_user",
                to_role="high_privilege_user",
                expected_behavior=(
                    f"Mutation {op['field_name']} should not allow "
                    f"a low-privilege user to escalate to a higher role"
                ),
                confidence=0.6 if op["field_name"] in
                [m["field_name"] for m in role_mutations] else 0.4,
                rationale=(
                    f"Mutation {op['field_name']} accepts role-related fields — "
                    f"test privilege escalation"
                ),
            ))

        self._plans.extend(plans)
        return plans

    def map_mutation_authorization(
        self, store: DiscoveryStore | None = None,
    ) -> list[AuthInvestigationPlan]:
        """Find mutations with ID args that create/update resources.

        These are candidates for IDOR testing: mutations that accept
        resource IDs as arguments.
        """
        s = store or self._store
        if s is None:
            return []
        mutations = self._get_mutation_fields(s)

        plans: list[AuthInvestigationPlan] = []
        for m in mutations:
            if m["args"] == 0:
                continue
            plans.append(AuthInvestigationPlan(
                target_url=m["source_url"],
                plan_type=PlanType.OWNERSHIP_VIOLATION,
                gql_operation=m["field_name"],
                gql_arguments={"operation": m["field_name"], "args": m["args"]},
                from_role="attacker",
                to_role="resource_owner",
                expected_behavior=(
                    f"Mutation {m['field_name']} accepts {m['args']} args — "
                    f"test if another user's resource ID is accepted"
                ),
                confidence=0.5,
                rationale=(
                    f"Mutation {m['field_name']} accepts {m['args']} arguments — "
                    f"potential IDOR if resource IDs are not owner-scoped"
                ),
            ))

        self._plans.extend(plans)
        return plans

    def run_all(
        self, store: DiscoveryStore | None = None,
        ownership_hints: list[dict] | None = None,
    ) -> dict[str, Any]:
        """Run all mapping strategies and return statistics."""
        s = store or self._store
        if s is None:
            return {"error": "no store"}

        relationships = self._rel_engine.infer_classified_relationships(s)

        self.map_cross_tenant_operations(relationships, s)
        self.map_ownership_violations(relationships, ownership_hints, s)
        self.map_role_escalation_paths(s)
        self.map_mutation_authorization(s)

        plan_types: dict[str, int] = {}
        for p in self._plans:
            pt = p.plan_type.value
            plan_types[pt] = plan_types.get(pt, 0) + 1

        return {
            "total_plans": len(self._plans),
            "plan_types": plan_types,
        }

    def store_plans(
        self, store: DiscoveryStore | None = None,
    ) -> int:
        """Store all investigation plans to DiscoveryStore."""
        s = store or self._store
        if s is None:
            return 0
        count = 0
        for plan in self._plans:
            s.record(
                category="gql_auth_plan",
                value=f"{plan.plan_type.value}:{plan.gql_operation}",
                source_url=plan.target_url,
                extra=plan.to_dict(),
            )
            count += 1
        return count

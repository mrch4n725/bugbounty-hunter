"""GraphQLRelationshipEngine — infer domain relationships from GQL schemas.

Takes raw gql_type/gql_field/gql_relationship records from DiscoveryStore and
classifies them into domain-level relationships (ownership, tenancy, membership,
has-many). Also infers indirect ownership chains and privilege level types.
"""

import json
from typing import Any

from engines.discovery_store import DiscoveryStore
from models.gql_auth import RelationshipType, TypeRelationship


_OWNERSHIP_KEYWORDS = frozenset({
    "owner", "owner_id", "creator", "created_by", "creator_id",
    "author", "author_id",
    "assignee", "assignee_id", "assigned_to",
})

_BELONGS_TO_KEYWORDS = frozenset({
    "user", "user_id", "userId",
    "member", "member_id", "memberId",
    "belongs_to",
    "organisation", "organization",
    "organisation_id", "organization_id", "org_id", "orgId", "org",
    "account", "account_id", "accountId",
    "parent", "parent_id",
})

_TENANT_KEYWORDS = frozenset({
    "tenant", "tenant_id", "tenantId",
    "workspace", "workspace_id", "workspaceId",
    "team_id", "teamId",
})

_HAS_MANY_PLURAL_SUFFIXES = ("s", "es", "ies", "List", "list")

_PRIVILEGE_TYPE_KEYWORDS = frozenset({
    "admin", "administrator", "superadmin", "super_admin",
    "manager", "moderator", "editor",
    "member", "user", "viewer", "reader",
    "guest", "anonymous", "public",
})

_PRIVILEGE_SUFFIXES = ("role", "roles", "permission", "permissions",
                       "access_level", "privilege", "privileges")


def _is_plural(name: str) -> bool:
    lower = name.lower()
    return any(lower.endswith(s) for s in _HAS_MANY_PLURAL_SUFFIXES)


def _classify_field(field_name: str, field_type: str,
                    parent_type: str, is_relationship: bool = False) -> TypeRelationship | None:
    """Classify a single GQL field into a domain relationship type.

    Returns None if the field does not represent a domain relationship.
    """
    fn_lower = field_name.lower()
    ft_lower = field_type.lower()

    if fn_lower in _OWNERSHIP_KEYWORDS:
        return TypeRelationship(
            from_type=parent_type,
            to_type=field_type,
            via_field=field_name,
            relationship_type=RelationshipType.BELONGS_TO,
            confidence=0.8 if "id" in fn_lower else 0.7,
        )

    if fn_lower in _BELONGS_TO_KEYWORDS:
        return TypeRelationship(
            from_type=parent_type,
            to_type=field_type,
            via_field=field_name,
            relationship_type=RelationshipType.BELONGS_TO,
            confidence=0.6,
        )

    if fn_lower in _TENANT_KEYWORDS or "_tenant" in fn_lower or "_workspace" in fn_lower:
        return TypeRelationship(
            from_type=parent_type,
            to_type=field_type,
            via_field=field_name,
            relationship_type=RelationshipType.TENANT_OF,
            confidence=0.75,
        )

    if (is_relationship and _is_plural(field_name)
            and not fn_lower.endswith("_id")
            and not fn_lower.endswith("_ids")):
        return TypeRelationship(
            from_type=parent_type,
            to_type=field_type,
            via_field=field_name,
            relationship_type=RelationshipType.HAS_MANY,
            confidence=0.5,
        )

    if is_relationship:
        return TypeRelationship(
            from_type=parent_type,
            to_type=field_type,
            via_field=field_name,
            relationship_type=RelationshipType.GQL_ASSOCIATION,
            confidence=0.4,
        )

    return None


class GraphQLRelationshipEngine:
    """Infer domain-level relationships from GQL schema data.

    Consumes gql_type, gql_field, gql_relationship records from DiscoveryStore
    and produces classified TypeRelationship objects with confidence scores.
    """

    def __init__(self, store: DiscoveryStore | None = None):
        self._store = store
        self._relationships: list[TypeRelationship] = []
        self._type_names: set[str] = set()
        self._privilege_types: list[str] = []

    def get_type_names(self, store: DiscoveryStore | None = None) -> set[str]:
        """Return all discovered GQL type names."""
        s = store or self._store
        if s is None:
            return set()
        if self._type_names:
            return self._type_names
        types = s.get_by_category("gql_type")
        self._type_names = {rec.get("value", "") for rec in types}
        return self._type_names

    def _get_fields(self, store: DiscoveryStore) -> list[dict]:
        """Get all gql_field records with parsed extra."""
        fields = store.get_by_category("gql_field")
        results: list[dict] = []
        for rec in fields:
            val = rec.get("value", "")
            extra_raw = rec.get("extra") or "{}"
            if isinstance(extra_raw, str):
                try:
                    extra = json.loads(extra_raw)
                except (json.JSONDecodeError, TypeError):
                    extra = {}
            else:
                extra = extra_raw
            field_name = val.split(".")[-1] if "." in val else val
            results.append({
                "value": val,
                "field_name": field_name,
                "parent_type": extra.get("parent_type", ""),
                "field_type": extra.get("field_type", ""),
                "is_relationship": extra.get("is_relationship", False),
                "args": extra.get("args", 0),
                "source_url": rec.get("source_url", ""),
            })
        return results

    def _get_relationships(self, store: DiscoveryStore) -> list[dict]:
        """Get all gql_relationship records with parsed extra."""
        rels = store.get_by_category("gql_relationship")
        results: list[dict] = []
        for rec in rels:
            extra_raw = rec.get("extra") or "{}"
            if isinstance(extra_raw, str):
                try:
                    extra = json.loads(extra_raw)
                except (json.JSONDecodeError, TypeError):
                    extra = {}
            else:
                extra = extra_raw
            results.append({
                "from_type": extra.get("from_type", ""),
                "to_type": extra.get("to_type", ""),
                "via_field": extra.get("via_field", ""),
                "source_url": rec.get("source_url", ""),
            })
        return results

    def infer_classified_relationships(
        self, store: DiscoveryStore | None = None,
    ) -> list[TypeRelationship]:
        """Classify every gql_relationship into a domain relationship type.

        Returns TypeRelationship objects with confidence scores.
        """
        s = store or self._store
        if s is None:
            return []
        if self._relationships:
            return self._relationships

        type_names = self.get_type_names(s)
        fields = self._get_fields(s)

        classified: list[TypeRelationship] = []
        for f in fields:
            if not f["parent_type"] or not f["field_type"]:
                continue
            if f["field_type"] in ("String", "Int", "Float", "Boolean", "ID"):
                continue
            if f["parent_type"] not in type_names and f["field_type"] not in type_names:
                continue

            tr = _classify_field(
                field_name=f["field_name"],
                field_type=f["field_type"],
                parent_type=f["parent_type"],
                is_relationship=f["is_relationship"],
            )
            if tr is not None:
                tr.source_url = f["source_url"]
                classified.append(tr)

        self._relationships = classified
        return classified

    def infer_ownership_chains(
        self, relationships: list[TypeRelationship] | None = None,
    ) -> list[TypeRelationship]:
        """Follow BELONGS_TO chains to find indirect ownership paths.

        If A BELONGS_TO B and B BELONGS_TO C, then A OWNS_THROUGH C via B.
        Only follows chains of length 2 (three types).
        """
        rels = relationships or self._relationships
        if not rels:
            rels = self.infer_classified_relationships()

        parent_map: dict[str, list[TypeRelationship]] = {}
        for r in rels:
            if r.relationship_type in (RelationshipType.BELONGS_TO,):
                parent_map.setdefault(r.from_type, []).append(r)

        chains: list[TypeRelationship] = []
        for from_type, parents in parent_map.items():
            for direct in parents:
                grandparent_rels = parent_map.get(direct.to_type, [])
                for gp in grandparent_rels:
                    chains.append(TypeRelationship(
                        from_type=from_type,
                        to_type=gp.to_type,
                        via_field=f"{direct.via_field}→{gp.via_field}",
                        relationship_type=RelationshipType.OWNS_THROUGH,
                        confidence=direct.confidence * gp.confidence * 0.8,
                        source_url=direct.source_url,
                    ))

        self._relationships.extend(chains)
        return chains

    def infer_privilege_types(
        self, store: DiscoveryStore | None = None,
    ) -> list[str]:
        """Find GQL types that represent privilege/role levels."""
        s = store or self._store
        if s is None:
            return []
        if self._privilege_types:
            return self._privilege_types
        types = s.get_by_category("gql_type")
        results: list[str] = []
        for rec in types:
            name = rec.get("value", "")
            if name.lower() in _PRIVILEGE_TYPE_KEYWORDS:
                results.append(name)
            if any(name.lower().endswith(s) for s in _PRIVILEGE_SUFFIXES):
                results.append(name)
        self._privilege_types = results
        return results

    def infer_memberships(
        self, relationships: list[TypeRelationship] | None = None,
    ) -> list[TypeRelationship]:
        """Infer MEMBER_OF from HAS_MANY relationships.

        If Organization HAS_MANY User, then User MEMBER_OF Organization.
        """
        rels = relationships or self._relationships
        if not rels:
            rels = self.infer_classified_relationships()

        memberships: list[TypeRelationship] = []
        for r in rels:
            if r.relationship_type == RelationshipType.HAS_MANY:
                memberships.append(TypeRelationship(
                    from_type=r.to_type,
                    to_type=r.from_type,
                    via_field=r.via_field,
                    relationship_type=RelationshipType.MEMBER_OF,
                    confidence=r.confidence * 0.8,
                    source_url=r.source_url,
                ))

        self._relationships.extend(memberships)
        return memberships

    def run_all(self, store: DiscoveryStore | None = None) -> dict[str, Any]:
        """Run all inference methods and return statistics."""
        s = store or self._store
        if s is None:
            return {"error": "no store"}
        self.infer_classified_relationships(s)
        self.infer_ownership_chains()
        self.infer_memberships()
        self.infer_privilege_types(s)
        return {
            "classified_relationships": len(self._relationships),
            "privilege_types": len(self._privilege_types),
            "type_names": len(self._type_names),
        }

    def store_relationships(
        self, store: DiscoveryStore | None = None,
    ) -> int:
        """Store all inferred relationships back to DiscoveryStore.

        Categories:
          - gql_inferred_relationship: classified TypeRelationship records
          - gql_ownership_chain: indirect ownership chain records
          - role: privilege type records
        """
        s = store or self._store
        if s is None:
            return 0
        count = 0
        for r in self._relationships:
            category = "gql_inferred_relationship"
            if r.relationship_type == RelationshipType.OWNS_THROUGH:
                category = "gql_ownership_chain"
            s.record(
                category=category,
                value=f"{r.from_type}→{r.to_type}",
                source_url=r.source_url,
                extra=r.to_dict(),
            )
            count += 1
        for rt in self._privilege_types:
            s.record("role", rt, source_url="gql_schema")
            count += 1
        return count

"""GqlAuthorizationEngine — consume stored GraphQL type/field/relationship data.

The ApiScanner._store_gql_types() stores GQL schema data in DiscoveryStore
under categories gql_type, gql_field, gql_relationship. This engine reads
those records and feeds them into the authorization pipeline:

- Type-to-type relationships → RelationshipGraph (auth candidates)
- Ownership-related fields → ownership boundary inference
- Role-related fields → role discovery
- Mutation arguments → API scanner ID injection
"""

from typing import Any

from engines.discovery_store import DiscoveryStore


_OWNERSHIP_FIELD_NAMES = frozenset({
    "owner", "owner_id", "creator", "created_by", "creator_id",
    "user", "user_id", "userId", "author", "author_id",
    "assigned_to", "assignee", "assignee_id",
    "belongs_to", "organisation", "organization",
    "organisation_id", "organization_id", "org_id", "orgId",
    "tenant", "tenant_id", "tenantId",
    "account", "account_id", "accountId",
    "member", "member_id", "memberId",
})


_ROLE_FIELD_NAMES = frozenset({
    "role", "roles", "permission", "permissions",
    "access", "access_level", "privilege", "privileges",
    "group", "groups", "team", "teams",
    "scope", "scopes",
})


_PRIVILEGE_LEVEL_KEYWORDS = frozenset({
    "admin", "administrator", "superadmin", "super_admin",
    "manager", "moderator", "editor",
    "member", "user", "viewer", "reader",
    "guest", "anonymous", "public",
})


_GQL_OWNERSHIP_TYPES = frozenset({
    "User", "Profile", "Account", "Member",
    "Organization", "Organisation", "Tenant",
})


class GqlAuthorizationEngine:
    """Read stored GQL intelligence and feed it into the auth pipeline."""

    def __init__(self, store: DiscoveryStore | None = None):
        self._store = store

    def get_ownership_fields(self, store: DiscoveryStore | None = None) -> list[dict]:
        """Find GQL fields that suggest ownership relationships.

        Returns list of {type_name, field_name, target_type, source_url}.
        """
        s = store or self._store
        if s is None:
            return []
        fields = s.get_by_category("gql_field")
        results: list[dict] = []
        for rec in fields:
            val: str = rec.get("value", "")
            extra_raw = rec.get("extra") or "{}"
            if isinstance(extra_raw, str):
                import json
                try:
                    extra = json.loads(extra_raw)
                except (json.JSONDecodeError, TypeError):
                    extra = {}
            else:
                extra = extra_raw
            parent_type = extra.get("parent_type", "")
            field_type = extra.get("field_type", "")
            field_name = val.split(".")[-1] if "." in val else val
            if field_name.lower() in _OWNERSHIP_FIELD_NAMES:
                results.append({
                    "type_name": parent_type,
                    "field_name": field_name,
                    "target_type": field_type,
                    "source_url": rec.get("source_url", ""),
                    "confidence": 0.8 if field_name == "owner_id" else
                                  0.7 if field_name == "owner" else
                                  0.6,
                })
            if parent_type in _GQL_OWNERSHIP_TYPES and field_type in ("ID", "Int", "String"):
                results.append({
                    "type_name": parent_type,
                    "field_name": field_name,
                    "target_type": field_type,
                    "source_url": rec.get("source_url", ""),
                    "confidence": 0.5,
                })
        return results

    def get_role_fields(self, store: DiscoveryStore | None = None) -> list[dict]:
        """Find GQL fields that suggest role/permission boundaries."""
        s = store or self._store
        if s is None:
            return []
        fields = s.get_by_category("gql_field")
        results: list[dict] = []
        for rec in fields:
            val: str = rec.get("value", "")
            extra_raw = rec.get("extra") or "{}"
            if isinstance(extra_raw, str):
                import json
                try:
                    extra = json.loads(extra_raw)
                except (json.JSONDecodeError, TypeError):
                    extra = {}
            else:
                extra = extra_raw
            field_name = val.split(".")[-1] if "." in val else val
            parent_type = extra.get("parent_type", "")
            field_type = extra.get("field_type", "")
            if field_name.lower() in _ROLE_FIELD_NAMES:
                results.append({
                    "type_name": parent_type,
                    "field_name": field_name,
                    "target_type": field_type,
                    "source_url": rec.get("source_url", ""),
                })
        return results

    def get_relationships(self, store: DiscoveryStore | None = None) -> list[dict]:
        """Get GQL type-to-type relationships for boundary inference.

        Returns list of {from_type, to_type, via_field, source_url}.
        """
        s = store or self._store
        if s is None:
            return []
        rels = s.get_by_category("gql_relationship")
        results: list[dict] = []
        for rec in rels:
            extra_raw = rec.get("extra") or "{}"
            if isinstance(extra_raw, str):
                import json
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

    def get_privilege_level_types(self, store: DiscoveryStore | None = None) -> list[str]:
        """Find GQL types that represent privilege levels (admin, user, guest, etc.)."""
        s = store or self._store
        if s is None:
            return []
        types = s.get_by_category("gql_type")
        results: list[str] = []
        for rec in types:
            name: str = rec.get("value", "")
            if name.lower() in _PRIVILEGE_LEVEL_KEYWORDS:
                results.append(name)
            if name.lower().endswith("role") or name.lower().endswith("permission"):
                results.append(name)
        return results

    def get_mutations_with_id_args(self, store: DiscoveryStore | None = None) -> list[dict]:
        """Find mutation fields that accept ID-like arguments (auth test candidates)."""
        s = store or self._store
        if s is None:
            return []
        fields = s.get_by_category("gql_field")
        results: list[dict] = []
        for rec in fields:
            val: str = rec.get("value", "")
            extra_raw = rec.get("extra") or "{}"
            if isinstance(extra_raw, str):
                import json
                try:
                    extra = json.loads(extra_raw)
                except (json.JSONDecodeError, TypeError):
                    extra = {}
            else:
                extra = extra_raw
            if extra.get("args", 0) == 0:
                continue
            parent_type = extra.get("parent_type", "")
            field_name = val.split(".")[-1] if "." in val else val
            if not parent_type or not field_name:
                continue
            # Check if any arg name suggests an object ID
            results.append({
                "mutation_name": field_name,
                "type_name": parent_type,
                "arg_count": extra.get("args", 0),
                "source_url": rec.get("source_url", ""),
            })
        return results

    def build_ownership_hints(self, store: DiscoveryStore | None = None) -> list[dict]:
        """Build ownership hints from GQL schema for RelationshipGraph.

        Returns records compatible with DiscoveryStore ownership_hint format:
        {value, source_url, extra: {gql_type, field_name, target_type, confidence}}
        """
        ownership_fields = self.get_ownership_fields(store)
        hints: list[dict] = []
        for of in ownership_fields:
            hints.append({
                "value": f"gql:{of['type_name']}.{of['field_name']}",
                "source_url": of["source_url"],
                "category": "ownership_hint",
                "extra": {
                    "gql_type": of["type_name"],
                    "field_name": of["field_name"],
                    "target_type": of["target_type"],
                    "confidence": of["confidence"],
                    "discovery_method": "gql_schema",
                },
            })
        return hints

    def build_relationships(self, store: DiscoveryStore | None = None) -> list[dict]:
        """Build type-to-type relationship records for RelationshipGraph.

        Returns records compatible with DiscoveryStore ownership_relationship format:
        {value, source_url, extra: {from_type, to_type, via_field, relationship_type: "gql_association"}}
        """
        rels = self.get_relationships(store)
        results: list[dict] = []
        for r in rels:
            results.append({
                "value": f"{r['from_type']}→{r['to_type']}",
                "source_url": r["source_url"],
                "category": "ownership_relationship",
                "extra": {
                    "from_type": r["from_type"],
                    "to_type": r["to_type"],
                    "via_field": r["via_field"],
                    "relationship_type": "gql_association",
                },
            })
        return results

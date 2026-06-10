"""GraphQLOwnershipDiscovery — discover ownership boundaries from GQL intelligence.

Cross-references classified GQL relationships with recon data (URL patterns,
discovered IDs, JWT claims, response excerpts) to build concrete ownership
assertions. Stores results as ownership_hint and ownership_relationship records.
"""

import json
import re
from typing import Any

from engines.discovery_store import DiscoveryStore
from engines.gql_relationships import GraphQLRelationshipEngine
from models.gql_auth import RelationshipType, TypeRelationship


_ID_PATTERN = re.compile(r'/(\d{3,12})(?:/|$|\?)')
_UUID_PATTERN = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)',
    re.IGNORECASE,
)

_TYPE_TO_PATH_MAP: dict[str, list[str]] = {
    "User": ["user", "users", "profile", "profiles", "member", "members"],
    "Organization": ["org", "orgs", "organization", "organizations",
                      "organisation", "organisations", "company", "companies"],
    "Tenant": ["tenant", "tenants", "workspace", "workspaces"],
    "Account": ["account", "accounts"],
    "Project": ["project", "projects", "repo", "repos", "repository", "repositories"],
    "Team": ["team", "teams", "group", "groups"],
    "Invoice": ["invoice", "invoices", "billing", "bill", "payment", "payments"],
    "Order": ["order", "orders", "checkout", "purchase", "transaction", "transactions"],
    "Product": ["product", "products", "item", "items", "listing", "listings"],
    "Subscription": ["subscription", "subscriptions", "plan", "plans", "billing"],
    "ApiKey": ["api_key", "api_key", "token", "tokens", "key", "keys"],
    "Session": ["session", "sessions", "auth", "login"],
    "Notification": ["notification", "notifications", "alert", "alerts"],
    "Comment": ["comment", "comments", "post", "posts", "thread", "threads"],
    "File": ["file", "files", "upload", "uploads", "attachment", "attachments"],
    "Permission": ["permission", "permissions", "role", "roles", "access"],
    "Setting": ["setting", "settings", "config", "configuration", "preference", "preferences"],
}


def _url_to_type_hints(url: str, type_names: set[str]) -> list[tuple[str, float]]:
    """Match URL path segments to known GQL type names.

    Returns list of (type_name, confidence) tuples.
    """
    hints: list[tuple[str, float]] = []
    url_lower = url.lower()
    for type_name, path_keywords in _TYPE_TO_PATH_MAP.items():
        if type_name not in type_names:
            continue
        for kw in path_keywords:
            if f"/{kw}" in url_lower or f"/{kw}?" in url_lower:
                hints.append((type_name, 0.6))
                break
    for type_name in type_names:
        tn_lower = type_name.lower()
        if f"/{tn_lower}" in url_lower or f"/{tn_lower}s" in url_lower:
            hints.append((type_name, 0.5))
    return hints


def _extract_ids_from_url(url: str) -> list[tuple[str, str, float]]:
    """Extract numeric and UUID IDs from URL path.

    Returns list of (id_value, id_type, confidence).
    """
    ids: list[tuple[str, str, float]] = []
    for m in _UUID_PATTERN.finditer(url):
        ids.append((m.group(1), "uuid", 0.8))
    for m in _ID_PATTERN.finditer(url):
        val = m.group(1)
        if len(val) >= 3:
            ids.append((val, "numeric_id", 0.7))
    return ids


class GraphQLOwnershipDiscovery:
    """Discover ownership boundaries by cross-referencing GQL with recon data.

    Consumes classified relationships from GraphQLRelationshipEngine and
    cross-references them with URL patterns, discovered store IDs, and
    recon response data to build concrete ownership assertions.
    """

    def __init__(self, store: DiscoveryStore | None = None,
                 relationship_engine: GraphQLRelationshipEngine | None = None):
        self._store = store
        self._rel_engine = relationship_engine or GraphQLRelationshipEngine(store)
        self._ownership_hints: list[dict[str, Any]] = []

    def get_ownership_hints(self) -> list[dict[str, Any]]:
        return list(self._ownership_hints)

    def discover_from_url_patterns(
        self, urls: list[str],
        store: DiscoveryStore | None = None,
    ) -> list[dict[str, Any]]:
        """Match URL patterns to GQL types via path keywords and discovered IDs.

        For each URL, finds matching GQL types and extracted IDs, then
        builds ownership hints like "User owns Project at /projects/123".
        """
        s = store or self._store
        if s is None:
            return []
        type_names = self._rel_engine.get_type_names(s)

        hints: list[dict[str, Any]] = []
        for url in urls:
            type_hints = _url_to_type_hints(url, type_names)
            url_ids = _extract_ids_from_url(url)

            for type_name, _ in type_hints:
                for id_val, id_type, id_conf in url_ids:
                    hint = {
                        "value": f"gql_ownership:{type_name}:{id_val}",
                        "source_url": url,
                        "category": "ownership_hint",
                        "extra": {
                            "gql_type": type_name,
                            "discovery_method": "gql_url_pattern",
                            "confidence": id_conf * 0.9,
                            "id_value": id_val,
                            "id_type": id_type,
                            "relationship_type": "owned_by",
                        },
                    }
                    hints.append(hint)

        self._ownership_hints.extend(hints)
        return hints

    def discover_from_store_ids(
        self, store: DiscoveryStore | None = None,
    ) -> list[dict[str, Any]]:
        """Cross-reference discovered store IDs with GQL type names.

        Looks at numeric_id, uuid, email categories in DiscoveryStore and
        maps them to GQL types by matching ID patterns with type conventions.
        """
        s = store or self._store
        if s is None:
            return []
        type_names = self._rel_engine.get_type_names(s)

        hints: list[dict[str, Any]] = []
        id_categories = ["numeric_id", "uuid", "email", "jwt_sub"]

        for cat in id_categories:
            records = s.get_by_category(cat)
            for rec in records:
                id_val = rec.get("value", "")
                source_url = rec.get("source_url", "")
                if not id_val or not source_url:
                    continue

                url_hints = _url_to_type_hints(source_url, type_names)
                for type_name, url_conf in url_hints:
                    hint = {
                        "value": f"gql_ownership:{type_name}:{id_val}",
                        "source_url": source_url,
                        "category": "ownership_hint",
                        "extra": {
                            "gql_type": type_name,
                            "discovery_method": f"gql_store_crossref:{cat}",
                            "confidence": url_conf * 0.8,
                            "id_value": id_val,
                            "id_type": cat,
                            "relationship_type": "owned_by",
                        },
                    }
                    hints.append(hint)

        self._ownership_hints.extend(hints)
        return hints

    def discover_from_relationships(
        self,
        relationships: list[TypeRelationship] | None = None,
        store: DiscoveryStore | None = None,
    ) -> list[dict[str, Any]]:
        """Build ownership assertions from classified relationships.

        From BELONGS_TO relationships, creates ownership hints:
        "Project BELONGS_TO User" → "User OWNS Project"
        "Team BELONGS_TO Organization" → "Organization OWNS Team"
        """
        s = store or self._store
        if s is None:
            return []

        rels = relationships or self._rel_engine.infer_classified_relationships(s)
        hints: list[dict[str, Any]] = []

        for r in rels:
            if r.relationship_type == RelationshipType.BELONGS_TO:
                hint = {
                    "value": f"gql_ownership:{r.to_type}→{r.from_type}",
                    "source_url": r.source_url,
                    "category": "ownership_hint",
                    "extra": {
                        "owner_type": r.to_type,
                        "resource_type": r.from_type,
                        "via_field": r.via_field,
                        "discovery_method": "gql_relationship",
                        "confidence": r.confidence,
                        "relationship_type": "owned_by",
                    },
                }
                hints.append(hint)

                relationship_record = {
                    "value": f"{r.to_type}→{r.from_type}",
                    "source_url": r.source_url,
                    "category": "ownership_relationship",
                    "extra": {
                        "from_type": r.to_type,
                        "to_type": r.from_type,
                        "via_field": r.via_field,
                        "relationship_type": "ownership",
                    },
                }
                hints.append(relationship_record)

            elif r.relationship_type == RelationshipType.TENANT_OF:
                hint = {
                    "value": f"gql_tenant:{r.from_type}→{r.to_type}",
                    "source_url": r.source_url,
                    "category": "ownership_hint",
                    "extra": {
                        "tenant_type": r.to_type,
                        "resource_type": r.from_type,
                        "via_field": r.via_field,
                        "discovery_method": "gql_relationship",
                        "confidence": r.confidence,
                        "relationship_type": "tenant_of",
                    },
                }
                hints.append(hint)

            elif r.relationship_type == RelationshipType.HAS_MANY:
                relationship_record = {
                    "value": f"{r.from_type}→{r.to_type}",
                    "source_url": r.source_url,
                    "category": "ownership_relationship",
                    "extra": {
                        "from_type": r.from_type,
                        "to_type": r.to_type,
                        "via_field": r.via_field,
                        "relationship_type": "has_many",
                    },
                }
                hints.append(relationship_record)

        self._ownership_hints.extend(hints)
        return hints

    def discover_from_recon_responses(
        self, recon_data: dict[str, Any],
        store: DiscoveryStore | None = None,
    ) -> list[dict[str, Any]]:
        """Analyze recon response excerpts for ownership patterns.

        Scans response_excerpt fields from recon data for JSON field names
        matching GQL types (e.g., {"user_id": 123, "project_id": 456}).
        """
        s = store or self._store
        if s is None:
            return []
        type_names = self._rel_engine.get_type_names(s)

        hints: list[dict[str, Any]] = []
        owner_fields = {"user_id", "owner_id", "creator_id", "author_id",
                        "account_id", "organization_id", "org_id",
                        "tenant_id", "workspace_id"}

        excerpts: list[str] = []
        for url in recon_data.get("urls", []):
            excerpts.append(str(url))
        for form in recon_data.get("forms", []):
            excerpts.append(str(form))

        seen_combos: set[str] = set()
        for excerpt in excerpts:
            for match in re.finditer(r'"(user_id|owner_id|creator_id|author_id|account_id|organization_id|org_id|tenant_id|workspace_id)"\s*:\s*(\d+)', excerpt):
                field_name = match.group(1)
                id_val = match.group(2)
                for type_name in type_names:
                    tn_lower = type_name.lower()
                    if tn_lower in excerpt.lower():
                        combo = f"{type_name}:{field_name}:{id_val}"
                        if combo in seen_combos:
                            continue
                        seen_combos.add(combo)
                        hint = {
                            "value": f"gql_ownership:{type_name}:{id_val}",
                            "source_url": "",
                            "category": "ownership_hint",
                            "extra": {
                                "gql_type": type_name,
                                "field_name": field_name,
                                "id_value": id_val,
                                "discovery_method": "gql_response_pattern",
                                "confidence": 0.5,
                                "relationship_type": "owned_by",
                            },
                        }
                        hints.append(hint)

        self._ownership_hints.extend(hints)
        return hints

    def run_all(
        self, recon_data: dict[str, Any] | None = None,
        urls: list[str] | None = None,
        store: DiscoveryStore | None = None,
    ) -> dict[str, Any]:
        """Run all discovery methods and return statistics."""
        s = store or self._store
        if s is None:
            return {"error": "no store"}

        self._rel_engine.run_all(s)
        relationships = self._rel_engine.infer_classified_relationships(s)

        url_list = urls or recon_data.get("urls", []) if recon_data else []
        if url_list:
            self.discover_from_url_patterns(url_list, s)
        self.discover_from_store_ids(s)
        self.discover_from_relationships(relationships, s)
        if recon_data:
            self.discover_from_recon_responses(recon_data, s)

        return {
            "ownership_hints": len(self._ownership_hints),
            "relationships_classified": len(relationships),
            "sources": list({h.get("extra", {}).get("discovery_method", "unknown")
                             for h in self._ownership_hints}),
        }

    def store_hints(
        self, store: DiscoveryStore | None = None,
    ) -> int:
        """Store all ownership hints and relationships to DiscoveryStore."""
        s = store or self._store
        if s is None:
            return 0
        count = 0
        for hint in self._ownership_hints:
            category = hint.get("category", "ownership_hint")
            extra = hint.get("extra", {})
            s.record(
                category=category,
                value=hint.get("value", ""),
                source_url=hint.get("source_url", ""),
                extra=extra,
            )
            count += 1
        return count

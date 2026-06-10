"""OwnershipDiscoveryEngine — proactive ownership inference from multiple signals.

Rather than waiting for auth tests to confirm ownership violations, this
engine proactively discovers ownership relationships from:

- Response JSON structures (fields named owner_id, user_id, etc.)
- URL path patterns suggesting ownership hierarchies
- JWT claim cross-references (sub -> resources they own)
- GQL schema type-to-type relationships  
- OpenAPI model property analysis

These inferred relationships are stored in DiscoveryStore so that the
AuthorizationScanner, RelationshipGraph, and IDOR scanners find more
candidates without requiring explicit per-endpoint harvest.
"""

import json
import re
from typing import Any
from urllib.parse import urlparse

from engines.discovery_store import DiscoveryStore


_OWNER_KEYS = frozenset({
    "owner", "owner_id", "ownerId", "owner_uuid",
    "user_id", "userId", "userid",
    "creator", "creator_id", "creatorId", "created_by",
    "author", "author_id", "authorId",
    "assigned_to", "assignee", "assignee_id", "assigneeId",
    "belongs_to", "belongsTo",
    "organisation", "organisation_id", "organisationId",
    "organization", "organization_id", "organizationId",
    "org_id", "orgId",
    "tenant", "tenant_id", "tenantId",
    "account", "account_id", "accountId",
    "manager", "manager_id", "managerId",
    "member", "member_id", "memberId",
})

_RESOURCE_KEYS = frozenset({
    "id", "uuid", "uid", "guid", "resource_id", "resourceId",
    "item_id", "itemId", "object_id", "objectId", "entity_id", "entityId",
})


class OwnershipDiscoveryEngine:
    """Proactively discover ownership relationships from scan intelligence."""

    def __init__(self, store: DiscoveryStore | None = None):
        self._store = store

    def discover_from_response_patterns(self, url: str, response_text: str) -> list[dict]:
        """Infer ownership from JSON response structures.

        Looks for objects that contain both an ID and an owner reference
        (e.g., ``{"id": 123, "owner_id": 456}``), and for list endpoints
        where each item has a user_id scoping the data.
        """
        if not response_text:
            return []
        try:
            parsed = json.loads(response_text)
        except (json.JSONDecodeError, TypeError):
            return []

        discovered: list[dict] = []
        self._traverse_json(parsed, url, discovered, path="")
        return discovered

    def _traverse_json(
        self, obj: Any, url: str, discovered: list[dict], path: str
    ) -> None:
        if isinstance(obj, dict):
            self._check_ownership(obj, url, discovered, path)
            for key, val in obj.items():
                sub_path = f"{path}.{key}" if path else key
                self._traverse_json(val, url, discovered, sub_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                sub_path = f"{path}[{idx}]"
                self._traverse_json(item, url, discovered, sub_path)

    def _check_ownership(
        self, obj: dict, url: str, discovered: list[dict], path: str
    ) -> None:
        id_val: str | None = None
        owner_val: str | None = None
        owner_key: str | None = None

        for key, val in obj.items():
            key_lower = key.lower().strip()
            if key_lower in _RESOURCE_KEYS and isinstance(val, (int, str)):
                id_val = str(val)
            if key_lower in _OWNER_KEYS and isinstance(val, (int, str)):
                owner_val = str(val)
                owner_key = key_lower

        if id_val and owner_val and owner_val != id_val:
            extra = {
                "resource_id": id_val,
                "owner_id": owner_val,
                "owner_key": owner_key,
                "relationship": "owned_by",
                "json_path": path,
                "discovery_method": "response_pattern",
            }
            discovery_key = f"{id_val}@{url}"
            self._store_record(discovery_key, id_val, url, extra, discovered, "ownership_relationship")
            hint_key = f"pattern:{owner_key}={owner_val}@{url}"
            self._store_record(hint_key, owner_val, url, extra, discovered, "ownership_hint")

        if not id_val:
            for key, val in obj.items():
                key_lower = key.lower().strip()
                if key_lower in _OWNER_KEYS and isinstance(val, (int, str)):
                    owner_val = str(val)
                    owner_key = key_lower
                    hint_key = f"pattern:{owner_key}={owner_val}@{url}"
                    extra = {
                        "owner_id": owner_val,
                        "owner_key": owner_key,
                        "relationship": "scoped_by",
                        "json_path": path,
                        "discovery_method": "response_pattern",
                    }
                    self._store_record(hint_key, owner_val, url, extra, discovered, "ownership_hint")

    def discover_from_url_patterns(
        self, urls: list[str], known_ids: dict[str, list[str]]
    ) -> list[dict]:
        """Infer ownership from URL path patterns.

        Analyzes URL patterns like:
          - /users/123/resource  -> resource is scoped to user 123
          - /api/v1/orgs/456/teams -> team scoped to org 456
          - /accounts/{account_id}/users/{user_id}

        Uses known_ids (category -> list of IDs seen in the scan) to
        identify ID-like path segments and infer scoping.
        """
        discovered: list[dict] = []

        pattern_map: dict[str, dict[str, list[str]]] = {}
        for url in urls:
            parsed = urlparse(url)
            segments = [s for s in parsed.path.split("/") if s]
            for known_type, ids in known_ids.items():
                matched_segments = []
                for seg in segments:
                    if seg in ids:
                        matched_segments.append((seg, known_type))
                if len(matched_segments) >= 1:
                    for seg, kt in matched_segments:
                        pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        pattern_map.setdefault(pattern, {}).setdefault(kt, set())
                        pattern_map[pattern][kt].add(seg)

        for pattern, type_map in pattern_map.items():
            for known_type, segs in type_map.items():
                for seg in segs:
                    extra = {
                        "id_value": seg,
                        "id_type": known_type,
                        "url_pattern": pattern,
                        "relationship": "url_scoped",
                        "discovery_method": "url_pattern",
                    }
                    key = f"url:{seg}@{pattern}"
                    self._store_record(key, seg, pattern, extra, discovered, "ownership_hint")

        return discovered

    def discover_from_jwt_cross_reference(
        self, store: DiscoveryStore | None = None
    ) -> list[dict]:
        """Cross-reference JWT subjects with discovered resources.

        When a JWT ``sub`` claim (user ID) matches a resource owner_id
        in a different response, record the cross-reference as a strong
        ownership signal.
        """
        s = store or self._store
        if s is None:
            return []
        discovered: list[dict] = []

        subjects: list[dict] = []
        jwt_records = s.get_by_category("jwt")
        for jrec in jwt_records:
            extra_raw = jrec.get("extra") or "{}"
            if isinstance(extra_raw, str):
                try:
                    extra = json.loads(extra_raw)
                except (json.JSONDecodeError, TypeError):
                    extra = {}
            else:
                extra = extra_raw
            jwt_val = jrec.get("value", "")
            if extra.get("claim") == "sub":
                subjects.append({
                    "sub": jwt_val,
                    "source_url": jrec.get("source_url", ""),
                })

        for sub in subjects:
            sub_val = sub["sub"]
            # Look for this sub value in ownership_hints
            for hint in s.get_by_category("ownership_hint"):
                hint_val = hint.get("value", "")
                hint_key = (hint_val or "").split("=")[-1] if "=" in (hint_val or "") else hint_val
                if hint_key == sub_val:
                    extra_str = hint.get("extra") or "{}"
                    if isinstance(extra_str, str):
                        try:
                            hint_extra = json.loads(extra_str)
                        except (json.JSONDecodeError, TypeError):
                            hint_extra = {}
                    else:
                        hint_extra = extra_str
                    cross_extra = {
                        "jwt_sub": sub_val,
                        "jwt_url": sub["source_url"],
                        "matching_hint_value": hint_val,
                        "hint_path": hint_extra.get("json_path", ""),
                        "relationship": "jwt_verified_owner",
                        "discovery_method": "jwt_cross_reference",
                        "confidence": 0.9,
                    }
                    key = f"jwt_xref:{sub_val}@{hint_val}"
                    self._store_record(key, sub_val, hint.get("source_url", ""),
                                       cross_extra, discovered, "ownership_relationship")

        return discovered

    def discover_from_openapi_models(
        self, store: DiscoveryStore | None = None
    ) -> list[dict]:
        """Infer ownership from OpenAPI model properties stored in DiscoveryStore."""
        s = store or self._store
        if s is None:
            return []
        discovered: list[dict] = []

        api_models = s.get_by_category("api_model")
        api_properties = s.get_by_category("api_property")

        # Group properties by model name
        models: dict[str, dict[str, Any]] = {}
        for prop in api_properties:
            extra_raw = prop.get("extra") or "{}"
            if isinstance(extra_raw, str):
                try:
                    extra = json.loads(extra_raw)
                except (json.JSONDecodeError, TypeError):
                    extra = {}
            else:
                extra = extra_raw
            model_name = extra.get("schema_name", "") or extra.get("parent_model", "")
            if not model_name:
                continue
            models.setdefault(model_name, {})
            val = prop.get("value", "")
            prop_type = extra.get("type", "string")
            models[model_name][val] = prop_type

        for model_name, props in models.items():
            id_props = [k for k in props if k.lower() in _RESOURCE_KEYS]
            owner_props = [k for k in props if k.lower() in _OWNER_KEYS]
            for id_p in id_props:
                for owner_p in owner_props:
                    extra = {
                        "model_name": model_name,
                        "resource_field": id_p,
                        "owner_field": owner_p,
                        "relationship": "owned_by",
                        "discovery_method": "openapi_model",
                        "confidence": 0.7,
                    }
                    key = f"openapi:{model_name}.{id_p}"
                    # Use first available source URL
                    src_url = ""
                    for prop in api_properties:
                        if prop.get("value", "") == id_p:
                            src_url = prop.get("source_url", "")
                            break
                    self._store_record(key, f"{model_name}.{id_p}", src_url,
                                       extra, discovered, "ownership_relationship")

        return discovered

    def discover_from_schema_patterns(
        self, store: DiscoveryStore | None = None
    ) -> list[dict]:
        """Infer ownership from repeated data patterns in DiscoveryStore.

        For example, if many ownership_hints share the same owner_key
        (e.g., 'user_id'), that key is likely a cross-cutting ownership
        field for that source URL.
        """
        s = store or self._store
        if s is None:
            return []
        discovered: list[dict] = []

        hints = s.get_by_category("ownership_hint")
        key_counts: dict[str, dict[str, int]] = {}
        key_sources: dict[str, list[str]] = {}

        for hint in hints:
            extra_raw = hint.get("extra") or "{}"
            if isinstance(extra_raw, str):
                try:
                    extra = json.loads(extra_raw)
                except (json.JSONDecodeError, TypeError):
                    extra = {}
            else:
                extra = extra_raw
            owner_key = extra.get("owner_key", "unknown")
            source = hint.get("source_url", "")
            key_counts.setdefault(source, {})
            key_counts[source][owner_key] = key_counts[source].get(owner_key, 0) + 1
            if source:
                key_sources.setdefault(owner_key, []).append(source)

        for owner_key, sources in key_sources.items():
            if len(set(sources)) >= 2:
                extra = {
                    "owner_key": owner_key,
                    "appearances_in_urls": len(set(sources)),
                    "source_urls": list(set(sources))[:5],
                    "relationship": "cross_cutting_owner",
                    "discovery_method": "schema_pattern",
                    "confidence": 0.6,
                }
                key = f"schema:{owner_key}@{len(set(sources))}"
                self._store_record(key, owner_key, sources[0], extra,
                                   discovered, "ownership_hint")

        return discovered

    def discover_all(
        self,
        urls: list[str] | None = None,
        response_bodies: dict[str, str] | None = None,
        known_ids: dict[str, list[str]] | None = None,
        store: DiscoveryStore | None = None,
    ) -> list[dict]:
        """Run all discovery methods and return accumulated results."""
        discovered: list[dict] = []
        s = store or self._store

        if response_bodies:
            for url, body in response_bodies.items():
                results = self.discover_from_response_patterns(url, body)
                discovered.extend(results)

        if urls and known_ids:
            results = self.discover_from_url_patterns(urls, known_ids)
            discovered.extend(results)

        if s:
            results = self.discover_from_jwt_cross_reference(s)
            discovered.extend(results)
            results = self.discover_from_openapi_models(s)
            discovered.extend(results)
            results = self.discover_from_schema_patterns(s)
            discovered.extend(results)

        return discovered

    def _store_record(
        self,
        fingerprint_key: str,
        value: str,
        source_url: str,
        extra: dict[str, Any],
        collected: list[dict],
        category: str,
    ) -> None:
        if self._store:
            self._store.record(category, value, source_url=source_url, extra=extra)
        collected.append({
            "category": category,
            "value": value,
            "source_url": source_url,
            "extra": extra,
        })

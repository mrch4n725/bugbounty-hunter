"""RelationshipGraph — infers ownership boundaries from discovered objects.

Uses the DiscoveryStore to understand which URLs reference which object
IDs, building a map of ownership relationships that the AuthorizationEngine
can use for targeted IDOR testing.
"""

import re
from typing import Any

from engines.discovery_store import DiscoveryStore
from engines.object_harvester import UUID_PATTERN, NUMERIC_ID_PATTERN


class RelationshipGraph:
    """Infers object-ownership relationships from harvested intelligence.

    Maps URLs to the IDs they reference, building a graph that the
    AuthorizationEngine can query to find candidate endpoints for
    ownership violation testing.
    """

    def __init__(self, store: DiscoveryStore):
        self._store = store

    def get_ownership_boundaries(self) -> dict[str, list[dict]]:
        """Return a map of URL patterns to discovered object IDs.

        Returns:
            {url_pattern: [{id_value, id_type, source_url}, ...]}
        """
        boundaries: dict[str, list[dict]] = {}

        # Group numeric IDs by URL
        for rec in self._store.get_by_category("numeric_id"):
            source = rec.get("source_url", "")
            pattern = self._url_to_pattern(source)
            value = rec["value"]
            boundaries.setdefault(pattern, []).append({
                "id_value": value,
                "id_type": "numeric",
                "source_url": source,
            })

        # Group UUIDs by URL
        for rec in self._store.get_by_category("uuid"):
            source = rec.get("source_url", "")
            pattern = self._url_to_pattern(source)
            value = rec["value"]
            boundaries.setdefault(pattern, []).append({
                "id_value": value,
                "id_type": "uuid",
                "source_url": source,
            })

        # Group emails by URL
        for rec in self._store.get_by_category("email"):
            source = rec.get("source_url", "")
            pattern = self._url_to_pattern(source)
            value = rec["value"]
            boundaries.setdefault(pattern, []).append({
                "id_value": value,
                "id_type": "email",
                "source_url": source,
            })

        return boundaries

    def get_related_urls(self, id_value: str) -> list[str]:
        """Return all URLs that reference a specific ID value."""
        urls: list[str] = []
        for category in ("numeric_id", "uuid", "email", "jwt"):
            for rec in self._store.get_by_category(category):
                if rec["value"] == id_value and rec.get("source_url"):
                    urls.append(rec["source_url"])
        return urls

    def get_auth_candidates(self) -> list[dict]:
        """Return candidate endpoints for authorization testing.

        Cross-references harvested IDs with the URLs they appear in,
        identifying endpoints where changing an ID might access another
        user's data.
        """
        candidates: list[dict] = []
        boundaries = self.get_ownership_boundaries()
        seen: set[tuple[str, str]] = set()

        for pattern, refs in boundaries.items():
            if not refs:
                continue
            # If a pattern has multiple distinct ID values, each is a candidate
            unique_ids = set(r["id_value"] for r in refs)
            base_url = next((r["source_url"] for r in refs if r["source_url"]), "")
            if not base_url:
                continue

            # The URL pattern itself is an auth candidate
            for ref in refs:
                key = (base_url, ref["id_value"])
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    "url": base_url,
                    "id_value": ref["id_value"],
                    "id_type": ref["id_type"],
                    "url_pattern": pattern,
                    "related_ids": list(unique_ids),
                })

        return candidates

    @staticmethod
    def _url_to_pattern(url: str) -> str:
        """Convert a concrete URL to a pattern by replacing numeric IDs with {id}."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path
        # Replace numeric path segments with {id}
        pattern = re.sub(r'/\d+', '/{id}', path)
        # Replace UUIDs in path with {uuid}
        pattern = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}', pattern, flags=re.IGNORECASE)
        return f"{parsed.scheme}://{parsed.netloc}{pattern}"

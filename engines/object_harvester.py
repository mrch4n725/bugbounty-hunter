"""ObjectHarvester — inline extraction of interesting objects from HTTP responses.

Extracts UUIDs, numeric IDs, emails, JWT tokens, roles, and other objects
from response text and stores them in the DiscoveryStore for reuse across
scans (e.g., feeding discovered IDs into IDOR enumeration, roles into
authorization testing).
"""

import json
import re
from typing import Any

from engines.discovery_store import DiscoveryStore


UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)

NUMERIC_ID_PATTERN = re.compile(r'(?:"(?:id|userId|user_id|account|accountId|uid|org|orgId|role|team|project|group|item|customer|order|ticket|invoice|product|document|file|ref|asset)"\s*:\s*)(\d{2,12})', re.IGNORECASE)

EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

ROLE_PATTERN = re.compile(r'(?:"(?:role|group|permission|access_level|userRole|type)"\s*:\s*")([^"]+)', re.IGNORECASE)

PRIVATE_IP_PATTERN = re.compile(r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)')

API_KEY_PATTERN = re.compile(r'(?:"(?:api[_-]?key|apikey|secret|token|api_secret|access_token)"\s*:\s*")([A-Za-z0-9_\-]{16,})', re.IGNORECASE)


class ObjectHarvester:
    """Extract interesting objects from HTTP response text and persist them."""

    def __init__(self, store: DiscoveryStore | None = None):
        self._store = store or DiscoveryStore()

    @property
    def store(self) -> DiscoveryStore:
        return self._store

    def harvest(self, url: str, response_text: str,
                response_headers: dict[str, str] | None = None) -> list[dict]:
        """Scan response text for interesting objects and record them.

        Returns a list of harvested object dicts for immediate use.
        """
        if not response_text:
            return []

        harvested: list[dict] = []

        # UUIDs
        for match in UUID_PATTERN.finditer(response_text):
            val = match.group(0)
            self._store.record("uuid", val, source_url=url)
            harvested.append({"category": "uuid", "value": val, "source_url": url})

        # Numeric IDs in JSON
        for match in NUMERIC_ID_PATTERN.finditer(response_text):
            val = match.group(1)
            self._store.record("numeric_id", val, source_url=url)
            harvested.append({"category": "numeric_id", "value": val, "source_url": url})

        # Emails
        for match in EMAIL_PATTERN.finditer(response_text):
            val = match.group(0)
            self._store.record("email", val, source_url=url)
            harvested.append({"category": "email", "value": val, "source_url": url})

        # JWT tokens
        for match in JWT_PATTERN.finditer(response_text):
            val = match.group(0)
            self._store.record("jwt", val, source_url=url)
            harvested.append({"category": "jwt", "value": val, "source_url": url})

        # Roles
        for match in ROLE_PATTERN.finditer(response_text):
            val = match.group(1)
            self._store.record("role", val, source_url=url)
            harvested.append({"category": "role", "value": val, "source_url": url})

        # Private IPs
        for match in PRIVATE_IP_PATTERN.finditer(response_text):
            val = match.group(0)
            self._store.record("private_ip", val, source_url=url)
            harvested.append({"category": "private_ip", "value": val, "source_url": url})

        # API keys in JSON responses
        for match in API_KEY_PATTERN.finditer(response_text):
            val = match.group(1)
            self._store.record("api_key", val, source_url=url)
            harvested.append({"category": "api_key", "value": val, "source_url": url})

        # GraphQL-related patterns in response
        if "__typename" in response_text or '"data"' in response_text[:500]:
            self._store.record("graphql_response", url, source_url=url,
                               extra={"signal": "typename_or_data"})
            harvested.append({"category": "graphql_response", "value": url, "source_url": url})

        return harvested

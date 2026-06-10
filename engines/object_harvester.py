"""ObjectHarvester — inline extraction of interesting objects from HTTP responses.

Extracts UUIDs, numeric IDs, emails, JWT tokens, roles, and other objects
from response text and stores them in the DiscoveryStore for reuse across
scans (e.g., feeding discovered IDs into IDOR enumeration, roles into
authorization testing). Uses JSON-traversal when possible for nested
structures, falling back to regex for non-JSON responses.
"""

import base64
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

ID_KEYS = frozenset({
    "id", "userid", "user_id", "account", "accountid", "account_id",
    "uid", "org", "orgid", "org_id", "role", "team", "project",
    "group", "item", "customer", "order", "ticket", "invoice",
    "product", "document", "file", "ref", "asset",
})

OWNER_KEYS = frozenset({
    "owner_id", "ownerid", "user_id", "userid", "organization_id",
    "organizationid", "org_id", "orgid", "tenant_id", "tenantid",
    "workspace_id", "workspaceid", "account_id", "accountid",
    "team_id", "teamid", "group_id", "groupid", "company_id",
    "companyid", "customer_id", "customerid", "creator_id",
    "creatorid", "author_id", "authorid", "manager_id", "managerid",
})

ROLE_KEYS = frozenset({
    "role", "group", "permission", "access_level", "userrole",
    "type", "user_type", "member_type", "subscription_tier",
})


class ObjectHarvester:
    """Extract interesting objects from HTTP response text and persist them."""

    def __init__(self, store: DiscoveryStore | None = None):
        self._store = store or DiscoveryStore()

    def _harvest_jwt_claims(self, token: str, url: str, harvested: list[dict]) -> None:
        """Decode a JWT payload and store extracted claims as intelligence."""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            decoded = base64.urlsafe_b64decode(payload_b64)
            claims = json.loads(decoded)
        except Exception:
            return

        # Extract subject / user ID
        sub = claims.get("sub") or claims.get("user_id") or claims.get("userId") or claims.get("id")
        if sub and isinstance(sub, str) and len(sub) > 1:
            sub_cat = "uuid" if "-" in sub and len(sub) == 36 else "numeric_id" if sub.isdigit() else "email" if "@" in sub else "ownership_hint"
            self._store.record(sub_cat, sub, source_url=url, extra={"claim": "sub", "jwt_source": url[:100]})
            harvested.append({"category": sub_cat, "value": sub, "source_url": url, "extra": {"claim": "sub"}})

        # Extract roles
        for claim_name in ("roles", "role", "groups", "permissions", "scopes"):
            val = claims.get(claim_name)
            if val:
                if isinstance(val, list):
                    for v in val:
                        v_str = str(v)
                        self._store.record("role", v_str, source_url=url, extra={"claim": claim_name, "jwt_source": url[:100]})
                        harvested.append({"category": "role", "value": v_str, "source_url": url})
                elif isinstance(val, str):
                    self._store.record("role", val, source_url=url, extra={"claim": claim_name, "jwt_source": url[:100]})
                    harvested.append({"category": "role", "value": val, "source_url": url})

        # Extract organization / tenant
        for claim_name in ("org_id", "orgId", "organization_id", "tenant_id", "tenantId", "account_id", "accountId"):
            org_val = claims.get(claim_name)
            if org_val is not None:
                v_str = str(org_val)
                self._store.record("ownership_hint", f"jwt:{claim_name}={v_str}", source_url=url,
                                   extra={"claim": claim_name, "value": v_str, "jwt_source": url[:100]})
                harvested.append({"category": "ownership_hint", "value": v_str, "source_url": url})

    @property
    def store(self) -> DiscoveryStore:
        return self._store

    def harvest(self, url: str, response_text: str,
                response_headers: dict[str, str] | None = None) -> list[dict]:
        """Scan response text for interesting objects and record them.

        First attempts JSON-traversal for structured extraction, then
        applies regex patterns as a catch-all for non-JSON responses
        or unstructured text embedded in responses.

        Returns a list of harvested object dicts for immediate use.
        """
        if not response_text:
            return []

        harvested: list[dict] = []

        try:
            parsed = json.loads(response_text)
            if isinstance(parsed, (dict, list)):
                json_objects = self._harvest_json(url, parsed)
                harvested.extend(json_objects)
        except (json.JSONDecodeError, ValueError):
            pass

        harvested.extend(self._harvest_regex(url, response_text))

        if "__typename" in response_text or '"data"' in response_text[:500]:
            self._store.record("graphql_response", url, source_url=url,
                               extra={"signal": "typename_or_data"})
            harvested.append({"category": "graphql_response", "value": url, "source_url": url})

        return harvested

    def _harvest_json(self, url: str, obj: Any, _path: str = "") -> list[dict]:
        """Recursively traverse a parsed JSON structure, extracting objects.

        Handles nested dicts, lists, and mixed structures. Extracts:
          - Numeric values at ID-like keys
          - UUID strings at any key
          - Email strings at any key
          - Values at role/permission-like keys
          - Ownership hints (e.g. ``id`` + ``owner_id`` in same object)
        """
        harvested: list[dict] = []

        if isinstance(obj, dict):
            current_has_id = None
            current_has_owner = None
            current_role = None

            for key, value in obj.items():
                key_lower = key.lower()
                sub_path = f"{_path}.{key}" if _path else key

                if isinstance(value, (dict, list)):
                    nested = self._harvest_json(url, value, sub_path)
                    harvested.extend(nested)

                elif isinstance(value, (int, float)) and value >= 10 and value <= 10**12:
                    if key_lower in ID_KEYS:
                        val_str = str(int(value))
                        self._store.record("numeric_id", val_str, source_url=url,
                                           extra={"json_path": sub_path})
                        harvested.append({
                            "category": "numeric_id", "value": val_str,
                            "source_url": url, "json_path": sub_path,
                            "extracted_by": "json_traversal",
                        })
                        current_has_id = val_str

                    if key_lower in OWNER_KEYS:
                        val_str = str(int(value))
                        self._store.record("ownership_hint", val_str, source_url=url,
                                           extra={"json_path": sub_path,
                                                  "hint_type": "owner_reference",
                                                  "owner_key": key})
                        harvested.append({
                            "category": "ownership_hint", "value": val_str,
                            "source_url": url, "json_path": sub_path,
                            "hint_type": "owner_reference",
                        })
                        current_has_owner = val_str

                elif isinstance(value, str):
                    if key_lower in OWNER_KEYS:
                        match = _extract_id_from_str(value)
                        if match:
                            self._store.record("ownership_hint", match, source_url=url,
                                               extra={"json_path": sub_path,
                                                      "hint_type": "owner_reference",
                                                      "owner_key": key})
                            harvested.append({
                                "category": "ownership_hint", "value": match,
                                "source_url": url, "json_path": sub_path,
                                "hint_type": "owner_reference",
                            })
                            current_has_owner = match

                    if key_lower in ROLE_KEYS:
                        self._store.record("role", value, source_url=url,
                                           extra={"json_path": sub_path})
                        harvested.append({
                            "category": "role", "value": value,
                            "source_url": url, "json_path": sub_path,
                            "extracted_by": "json_traversal",
                        })
                        current_role = value

                    if UUID_PATTERN.fullmatch(value):
                        self._store.record("uuid", value, source_url=url,
                                           extra={"json_path": sub_path})
                        harvested.append({
                            "category": "uuid", "value": value,
                            "source_url": url, "json_path": sub_path,
                            "extracted_by": "json_traversal",
                        })

                    if "@" in value and "." in value and EMAIL_PATTERN.fullmatch(value):
                        self._store.record("email", value, source_url=url,
                                           extra={"json_path": sub_path})
                        harvested.append({
                            "category": "email", "value": value,
                            "source_url": url, "json_path": sub_path,
                            "extracted_by": "json_traversal",
                        })

                    if JWT_PATTERN.fullmatch(value):
                        self._store.record("jwt", value, source_url=url,
                                           extra={"json_path": sub_path})
                        harvested.append({
                            "category": "jwt", "value": value,
                            "source_url": url, "json_path": sub_path,
                            "extracted_by": "json_traversal",
                        })

            if current_has_id and (current_has_owner or current_role):
                extra: dict[str, Any] = {"resource_id": current_has_id}
                if current_has_owner:
                    extra["owner_id"] = current_has_owner
                    extra["relationship"] = "owned_by"
                if current_role:
                    extra["role"] = current_role
                    extra["relationship"] = extra.get("relationship", "has_role")
                self._store.record("ownership_relationship", f"{current_has_id}@{url}",
                                   source_url=url, extra=extra)
                harvested.append({
                    "category": "ownership_relationship",
                    "value": current_has_id,
                    "source_url": url,
                    "extra": extra,
                })

        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                sub_path = f"{_path}[{idx}]"
                nested = self._harvest_json(url, item, sub_path)
                harvested.extend(nested)

        return harvested

    def _harvest_regex(self, url: str, response_text: str) -> list[dict]:
        """Regex-based extraction for non-JSON responses or unstructured text."""
        harvested: list[dict] = []

        for match in UUID_PATTERN.finditer(response_text):
            val = match.group(0)
            self._store.record("uuid", val, source_url=url)
            harvested.append({"category": "uuid", "value": val, "source_url": url})

        for match in NUMERIC_ID_PATTERN.finditer(response_text):
            val = match.group(1)
            self._store.record("numeric_id", val, source_url=url)
            harvested.append({"category": "numeric_id", "value": val, "source_url": url})

        for match in EMAIL_PATTERN.finditer(response_text):
            val = match.group(0)
            self._store.record("email", val, source_url=url)
            harvested.append({"category": "email", "value": val, "source_url": url})

        for match in JWT_PATTERN.finditer(response_text):
            val = match.group(0)
            self._store.record("jwt", val, source_url=url)
            harvested.append({"category": "jwt", "value": val, "source_url": url})
            # Decode JWT payload to extract claims as structured intelligence
            self._harvest_jwt_claims(val, url, harvested)

        for match in ROLE_PATTERN.finditer(response_text):
            val = match.group(1)
            self._store.record("role", val, source_url=url)
            harvested.append({"category": "role", "value": val, "source_url": url})

        for match in PRIVATE_IP_PATTERN.finditer(response_text):
            val = match.group(0)
            self._store.record("private_ip", val, source_url=url)
            harvested.append({"category": "private_ip", "value": val, "source_url": url})

        for match in API_KEY_PATTERN.finditer(response_text):
            val = match.group(1)
            self._store.record("api_key", val, source_url=url)
            harvested.append({"category": "api_key", "value": val, "source_url": url})

        return harvested


def _extract_id_from_str(value: str) -> str | None:
    """Extract a numeric or UUID identifier from a string value.

    Handles string-encoded numbers (``"123"``), UUIDs, and values embedded
    in URL-like strings (``"/users/123"``). Returns None if no ID found.
    """
    if value.isdigit() and len(value) >= 2:
        return value
    if UUID_PATTERN.fullmatch(value):
        return value
    match = re.search(r'/(\d{2,12})(?:/|$)', value)
    if match:
        return match.group(1)
    match = re.search(r'(\d{2,12})', value)
    if match:
        return match.group(1)
    return None

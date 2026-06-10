"""
ApiScanner — REST API and GraphQL vulnerability checks.

Probes OpenAPI/Swagger specs, tests GraphQL introspection & injection,
checks REST endpoints for BOLA (verb tampering) and mass assignment.

Subclasses VulnScanner to reuse helpers (_add, _confirm_finding,
_append_finding, _record_confirmed, _deduplicate).
"""

import json
from typing import Any, Optional
from urllib.parse import urljoin

import yaml

from models.finding import Finding
from modules.scanner_base import ScannerModuleBase
from modules.utils import (
    make_session, safe_get, safe_post, finding, log, Colors, _build_curl,
    build_role_sessions, get_role_session,
    safe_cookies_dict,
)

# ── Constants ──────────────────────────────────────────────────────────────────

OPENAPI_PATHS = [
    "/api/docs", "/swagger.json", "/openapi.json",
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/api/swagger.json", "/api/openapi.json",
    "/api-docs", "/api/v1/openapi.json", "/api/v1/swagger.json",
    "/swagger/", "/api/swagger/", "/swagger/v1/swagger.json",
    "/api/v2/swagger.json", "/api/v3/swagger.json",
]

GQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/gql",
    "/api/v1/graphql", "/api/v2/graphql", "/api/v3/graphql",
    "/graphql/console", "/console/graphql",
    "/graphiql", "/api/graphiql", "/graphiql.html",
    "/graphql/graphiql", "/graphql/altair", "/altair",
    "/voyager", "/graphql/voyager",
    "/playground", "/graphql/playground",
    "/subscriptions", "/ws/graphql", "/graphqlws",
]

GQL_QUERY_PARAM_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/query", "/query",
]

GQL_WS_PATHS = [
    "/ws/graphql", "/graphql/ws", "/subscriptions",
    "/ws", "/socket", "/websocket",
]

BOLA_TAMPER_MAP = {
    "GET": ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    "POST": ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"],
    "PUT": ["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
    "DELETE": ["GET", "POST", "PUT", "PATCH", "OPTIONS"],
    "PATCH": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
}

MASS_ASSIGN_FIELDS = [
    "isAdmin", "role", "privileged", "admin",
    "userRole", "access_level", "permissions",
    "is_admin", "group", "groups", "superuser",
]

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name kind description
          fields {
            name
            type { name kind ofType { name kind } }
          }
        }
      }
    }
    """
}

XSS_PAYLOADS = [
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<script>alert(1)</script>',
]

BATCH_SIZE = 100

# ── Scanner class ──────────────────────────────────────────────────────────────

class ApiScanner(ScannerModuleBase):
    """Vulnerability scanner targeting REST and GraphQL APIs."""

    def __init__(self, config: dict, recon_data: dict, container=None):
        super().__init__(config, recon_data, container=container)
        self.role_sessions = build_role_sessions(config, base_session=self.session)
        self.current_role = config.get("role", None) or "default"

    # ── Orchestrator ──────────────────────────────────────────────────────

    def run_all(self) -> list[Finding]:
        """Run all API-specific scans and return combined findings."""
        findings: list[Finding] = []

        endpoints = self.discover_openapi()
        if endpoints:
            log(f"  [API] Discovered {len(endpoints)} endpoint(s) from OpenAPI specs", Colors.CYAN,
                verbose_only=True, verbose=self.verbose)
            # Feed OpenAPI endpoint URLs back into recon_data URL pool
            for ep in endpoints:
                ep_url = self.base_url + ep.get("path", "")
                if ep_url and self._in_scope(ep_url):
                    urls_list = self.recon.setdefault("urls", [])
                    if ep_url not in urls_list:
                        urls_list.append(ep_url)

        gql_endpoints = self._find_gql_endpoints()
        if gql_endpoints:
            log(f"  [API] Found {len(gql_endpoints)} GraphQL endpoint(s)", Colors.CYAN,
                verbose_only=True, verbose=self.verbose)
            # Feed GQL endpoints back into recon_data URL pool
            for gql_url in gql_endpoints:
                if gql_url and self._in_scope(gql_url):
                    urls_list = self.recon.setdefault("urls", [])
                    if gql_url not in urls_list:
                        urls_list.append(gql_url)

        findings.extend(self.scan_graphql_introspection(gql_endpoints))
        findings.extend(self.scan_graphql_injection(gql_endpoints))
        findings.extend(self.scan_graphql_auth_bypass(gql_endpoints))
        findings.extend(self._scan_gql_batched_auth_bypass(gql_endpoints))
        findings.extend(self.scan_graphql_query_depth(gql_endpoints))
        findings.extend(self.scan_bola(endpoints))
        findings.extend(self.scan_mass_assignment(endpoints))

        self._store_openapi_to_discovery_store(endpoints)

        # Final scope filter on all results
        in_scope = [f for f in findings if self._in_scope(f.url)]
        return self._deduplicate(in_scope)

    # ── OpenAPI / Swagger Discovery ────────────────────────────────────────

    def discover_openapi(self) -> list[dict]:
        """Probe common OpenAPI/Swagger paths, parse specs, extract endpoints."""
        endpoints: list[dict] = []
        seen_paths: set[str] = set()

        for path in OPENAPI_PATHS:
            url = self.base_url + path
            if not self._in_scope(url):
                continue
            if url in seen_paths:
                continue
            seen_paths.add(url)

            resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
            if not resp or resp.status_code not in (200, 301, 302):
                continue

            spec = self._try_parse_spec(resp)
            if not spec:
                continue

            parsed = self._parse_openapi(spec, url)
            if parsed:
                in_scope = [p for p in parsed if self._in_scope(p.get("url", ""))]
                log(f"  [API] Loaded spec → {url} ({len(in_scope)}/{len(parsed)} endpoints)", Colors.CYAN,
                    verbose_only=True, verbose=self.verbose)
                endpoints.extend(in_scope)

        return endpoints

    def _try_parse_spec(self, resp: Any) -> Optional[dict]:
        """Try to parse a response body as an OpenAPI/Swagger JSON or YAML spec."""
        try:
            return resp.json()
        except (json.JSONDecodeError, ValueError):
            pass
        try:
            parsed = yaml.safe_load(resp.text)
            if isinstance(parsed, dict):
                return parsed
        except yaml.YAMLError:
            pass
        return None

    def _parse_openapi(self, spec: dict, source_url: str) -> list[dict]:
        """Extract endpoint definitions from an OpenAPI 2.x / 3.x spec."""
        endpoints: list[dict] = []
        paths: dict = spec.get("paths", {}) or {}
        base_path = spec.get("basePath", "")

        for route, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            full_path = base_path + route

            for method in ("get", "post", "put", "delete", "patch", "options", "head"):
                operation = methods.get(method)
                if not isinstance(operation, dict):
                    continue

                ep: dict[str, Any] = {
                    "path": full_path,
                    "method": method.upper(),
                    "parameters": [],
                    "source_url": source_url,
                    "summary": operation.get("summary", ""),
                    "description": operation.get("description", ""),
                }

                params: list = operation.get("parameters", []) or []
                if not params:
                    params = methods.get("parameters", []) or []

                for p in params:
                    param_name = p.get("name", "")
                    if not param_name:
                        continue
                    param_info: dict[str, Any] = {
                        "name": param_name,
                        "in": p.get("in", "query"),
                        "required": p.get("required", False),
                        "type": p.get("type") or (p.get("schema") or {}).get("type", "string"),
                    }
                    ep["parameters"].append(param_info)

                request_body = operation.get("requestBody", {})
                if isinstance(request_body, dict):
                    content = request_body.get("content", {})
                    for media_type, media_obj in content.items():
                        schema = media_obj.get("schema", {}) or {}
                        props = schema.get("properties", {}) or {}
                        required_fields: list = schema.get("required", []) or []
                        for prop_name, prop_info in props.items():
                            if isinstance(prop_info, dict):
                                ep["parameters"].append({
                                    "name": prop_name,
                                    "in": "body",
                                    "required": prop_name in required_fields,
                                    "type": prop_info.get("type", "string"),
                                })
                endpoints.append(ep)

        return endpoints

    # ── GraphQL helpers ────────────────────────────────────────────────────

    def _get_discovery_store(self):
        """Return the DiscoveryStore instance if available, else None."""
        if self.container and hasattr(self.container, 'discovery_store'):
            return self.container.discovery_store
        return None

    def _get_numeric_ids_for_args(self, max_count: int = 10) -> list[str]:
        """Fetch numeric IDs from DiscoveryStore for injecting into GQL args."""
        store = self._get_discovery_store()
        if store is None:
            return []
        records = store.get_by_category("numeric_id")
        seen: set[str] = set()
        ids: list[str] = []
        for r in records:
            val = r["value"]
            if val not in seen:
                seen.add(val)
                ids.append(val)
                if len(ids) >= max_count:
                    break
        return ids

    def _store_gql_types(self, schema: dict, url: str) -> None:
        """Parse an introspection schema into DiscoveryStore type/field/relationship records.

        Stores:
          - ``gql_type``: each named type with kind and field count
          - ``gql_field``: each field with parent type and resolved type
          - ``gql_relationship``: type-to-type references (fields whose
            type is another object type, implying a relationship)
        """
        store = self._get_discovery_store()
        if store is None:
            return

        query_type_name = schema.get("queryType", {}).get("name", "Query")
        mutation_type_name = schema.get("mutationType", {}).get("name", "")

        store.record("gql_type", query_type_name, source_url=url,
                     extra={"kind": "OBJECT", "role": "query_root"})
        if mutation_type_name:
            store.record("gql_type", mutation_type_name, source_url=url,
                         extra={"kind": "OBJECT", "role": "mutation_root"})

        type_map: dict[str, dict] = {}
        for t in schema.get("types", []):
            name = t.get("name", "")
            if not name or name.startswith("__") or name in ("String", "Int", "Float", "Boolean", "ID"):
                continue
            type_map[name] = t

        seen_types: set[str] = set()
        for type_name, t in type_map.items():
            if type_name in seen_types:
                continue
            seen_types.add(type_name)
            kind = t.get("kind", "OBJECT")
            fields = t.get("fields") or []

            if kind not in ("OBJECT", "INPUT_OBJECT", "INTERFACE", "UNION"):
                continue

            store.record("gql_type", type_name, source_url=url,
                         extra={"kind": kind, "field_count": len(fields)})

            for field in fields:
                field_name = field.get("name", "")
                field_type = self._resolve_gql_type_name(field.get("type", {}))
                if not field_name:
                    continue

                is_relationship = field_type in type_map and field_type not in (
                    "String", "Int", "Float", "Boolean", "ID")
                store.record("gql_field", f"{type_name}.{field_name}", source_url=url,
                             extra={"parent_type": type_name,
                                    "field_type": field_type,
                                    "is_relationship": is_relationship,
                                    "args": len(field.get("args") or [])})

                if is_relationship:
                    store.record("gql_relationship",
                                 f"{type_name}→{field_type}", source_url=url,
                                 extra={"from_type": type_name,
                                        "to_type": field_type,
                                        "via_field": field_name})
                    log(f"  [GQL] Relationship: {type_name}.{field_name} → {field_type}",
                        Colors.CYAN, verbose_only=True, verbose=self.verbose)

    @staticmethod
    def _resolve_gql_type_name(type_ref: dict) -> str:
        """Resolve a GraphQL type reference to its base type name.

        Handles NON_NULL and LIST wrappers to find the underlying named type.
        """
        if not type_ref:
            return "Unknown"
        kind = type_ref.get("kind", "")
        if kind == "NON_NULL":
            return ApiScanner._resolve_gql_type_name(type_ref.get("ofType", {}) or {})
        if kind == "LIST":
            return ApiScanner._resolve_gql_type_name(type_ref.get("ofType", {}) or {})
        return type_ref.get("name", "Unknown")

    def _find_gql_endpoints(self) -> list[str]:
        """Probe common paths to discover live GraphQL endpoints.

        Probes:
          - Static GQL paths (graphql, graphiql, altair, voyager, playground, ws)
          - Query-parameter-based GQL (``/api?query=...``)
          - WebSocket GQL subscriptions
        """
        found: list[str] = []
        seen: set[str] = set()

        # 1. Static GQL paths
        for path in GQL_ENDPOINTS:
            url = self.base_url + path
            if not self._in_scope(url):
                continue
            if url in seen:
                continue
            seen.add(url)
            resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
            if not resp:
                continue
            if resp.status_code >= 500:
                continue
            if resp.status_code == 200:
                found.append(url)
                continue
            try:
                r = self.session.post(url, json={"query": "{ __typename }"}, timeout=self.timeout)
                if r.status_code == 200 and "__typename" in r.text:
                    found.append(url)
            except Exception:
                pass

        # 2. Query-parameter-based GQL endpoints
        for path in GQL_QUERY_PARAM_PATHS:
            url = self.base_url + path + "?query={__typename}"
            if not self._in_scope(url):
                continue
            if url in seen:
                continue
            seen.add(url)
            try:
                r = safe_get(self.session, url, self.timeout, raise_for_status=False)
                if r and r.status_code == 200 and "__typename" in (r.text or ""):
                    found.append(self.base_url + path)
            except Exception:
                pass

        # 3. WebSocket GQL subscriptions (probe via HTTP GET to WS endpoint as heuristic)
        for path in GQL_WS_PATHS:
            url = self.base_url + path
            if not self._in_scope(url):
                continue
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
                if resp and resp.status_code in (200, 426):
                    if "graphql" in (resp.text or "").lower() or "upgrade" in str(resp.headers).lower():
                        found.append(url)
            except Exception:
                pass

        return found

    # ── GraphQL Introspection ──────────────────────────────────────────────

    def scan_graphql_introspection(self, gql_endpoints: list[str]) -> list[dict]:
        """Detect GraphQL introspection and dump the full schema if enabled."""
        findings: list[dict] = []

        for url in gql_endpoints:
            try:
                resp = self.session.post(
                    url, json=INTROSPECTION_QUERY, timeout=self.timeout
                )
                if resp.status_code != 200:
                    continue
                data = resp.json()
                schema = data.get("data", {}).get("__schema", {})
                if not schema:
                    continue

                types = schema.get("types", [])
                query_count = sum(
                    1 for t in types if t.get("fields")
                )
                f = finding(
                    "GraphQL Introspection Enabled",
                    url,
                    "medium",
                    "GraphQL introspection is enabled and exposes the full schema.",
                    f"Schema exposes {query_count} types with fields",
                    verification_stage="validated",
                    request=_build_curl("POST", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=resp.text[:500],
                    steps_to_reproduce=[
                        f"Send POST request to {url} with GraphQL introspection query",
                        "Observe the schema response containing all types and fields",
                    ],
                )
                self._append_finding(findings, f)
                log(f"  [GQL] Introspection enabled → {url}", Colors.YELLOW,
                    verbose_only=True, verbose=self.verbose)

                if self.verbose:
                    self._print_schema_summary(schema)

                self._store_gql_types(schema, url)

            except Exception as e:
                log(f"  [GQL] Introspection error for {url}: {e}", Colors.WHITE,
                    verbose_only=True, verbose=self.verbose)

        return self._deduplicate(findings)

    def _print_schema_summary(self, schema: dict) -> None:
        """Log a human-readable summary of the GraphQL schema."""
        query_type = schema.get("queryType", {}).get("name", "Query")
        mutation_type = schema.get("mutationType", {}).get("name", "")
        lines = [f"  [GQL] Query root: {query_type}"]
        if mutation_type:
            lines.append(f"  [GQL] Mutation root: {mutation_type}")
        for t in schema.get("types", []):
            name = t.get("name", "")
            if name.startswith("__"):
                continue
            fields = t.get("fields", [])
            if fields:
                lines.append(f"  [GQL]   type {name} ({len(fields)} fields)")
        for line in lines:
            log(line, Colors.CYAN, verbose_only=True, verbose=self.verbose)

    def _discover_mutations(self, gql_endpoints: list[str]) -> list[dict]:
        """Return a list of mutation names and their argument fields."""
        mutations: list[dict] = []
        query = {"query": "{ __schema { mutationType { name fields { name args { name type { name kind } } } } } }"}
        seen_names: set[str] = set()

        for url in gql_endpoints:
            try:
                resp = self.session.post(url, json=query, timeout=self.timeout)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                mutation_type = data.get("data", {}).get("__schema", {}).get("mutationType")
                if not mutation_type:
                    continue
                for field in mutation_type.get("fields", []):
                    name = field.get("name", "")
                    if name and name not in seen_names:
                        seen_names.add(name)
                        args = [
                            {"name": a.get("name", ""), "type": a.get("type", {}).get("name", "String")}
                            for a in field.get("args", [])
                        ]
                        mutations.append({"name": name, "args": args, "url": url})
            except Exception:
                pass
        return mutations

    # ── GraphQL Injection ──────────────────────────────────────────────────

    def scan_graphql_injection(self, gql_endpoints: list[str]) -> list[dict]:
        """Test GraphQL mutations for SQLi, XSS, and batching attacks."""
        findings: list[dict] = []

        if not gql_endpoints:
            return findings

        mutations = self._discover_mutations(gql_endpoints)
        if not mutations:
            return findings

        sqli_payloads = self._load_payloads("sqli").get("error_based", ["' OR 1=1--"])

        for mut in mutations:
            url = mut["url"]
            mut_name = mut["name"]

            for payload in sqli_payloads[:2]:
                variables: dict[str, str] = {}
                for arg in mut["args"][:3]:
                    variables[arg["name"]] = payload

                if not variables:
                    variables["input"] = payload

                gql_query = f"mutation {{ {mut_name}({', '.join(f'{k}: ${k}' for k in variables)}) {{ __typename }} }}"
                op = {"query": gql_query, "variables": variables}

                try:
                    resp = self.session.post(url, json=op, timeout=self.timeout)
                    if resp.status_code not in (200,):
                        continue
                    body_text = resp.text.lower()
                    from modules.scanner import SQLI_ERRORS
                    matched = [e for e in SQLI_ERRORS if e in body_text]
                    if matched:
                        details = f"Mutation '{mut_name}' triggered SQL error with payload: {payload}"
                        self._record_confirmed(findings, "GraphQL SQL Injection", url, "critical",
                                               details, matched[0], "POST", op,
                                               response_excerpt=resp.text[:500],
                                               steps_to_reproduce=[
                                                   f"Send POST request to {url} with SQL injection payload in mutation '{mut_name}'",
                                                   "Observe database error messages in the response",
                                               ])
                        log(f"  [GQL Inj] SQLi in mutation {mut_name}", Colors.RED, verbose_only=True, verbose=self.verbose)
                        break
                except Exception:
                    pass

            for payload in XSS_PAYLOADS:
                variables: dict[str, str] = {}
                for arg in mut["args"][:3]:
                    variables[arg["name"]] = payload
                if not variables:
                    variables["input"] = payload

                gql_query = f"mutation {{ {mut_name}({', '.join(f'{k}: ${k}' for k in variables)}) {{ __typename }} }}"
                op = {"query": gql_query, "variables": variables}

                try:
                    resp = self.session.post(url, json=op, timeout=self.timeout)
                    if resp and payload in resp.text:
                        details = f"Mutation '{mut_name}' reflects XSS payload in response."
                        self._record_confirmed(findings, "GraphQL XSS", url, "high", details, payload, "POST", op,
                                               response_excerpt=resp.text[:500],
                                               steps_to_reproduce=[
                                                   f"Send POST request to {url} with XSS payload in mutation '{mut_name}'",
                                                   "Observe the XSS payload reflected in the response",
                                               ])
                        log(f"  [GQL Inj] XSS in mutation {mut_name}", Colors.RED, verbose_only=True, verbose=self.verbose)
                        break
                except Exception:
                    pass

        # ── Batching attack ────────────────────────────────────────────────
        if gql_endpoints:
            self._scan_graphql_batching(findings, gql_endpoints)

        return self._deduplicate(findings)

    def _store_openapi_to_discovery_store(self, endpoints: list[dict]) -> None:
        """Record OpenAPI endpoint model metadata into DiscoveryStore.

        Stores each endpoint path + method as an ``api_model`` record, and
        each parameter with its type as an ``api_property`` record linked to
        the parent endpoint. This intelligence feeds downstream scanners
        (IDOR, AuthZ) with parameter names and types.
        """
        store = None
        if self.container and hasattr(self.container, 'discovery_store'):
            store = self.container.discovery_store
        if store is None:
            return

        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "GET")
            ep_key = f"{method} {path}"

            store.record("api_model", ep_key, source_url=ep.get("source_url", ""),
                         extra={"path": path, "method": method,
                                "summary": ep.get("summary", "")})

            for param in ep.get("parameters", []):
                param_name = param.get("name", "")
                if not param_name:
                    continue
                store.record("api_property", param_name, source_url=ep.get("source_url", ""),
                             extra={"parent_endpoint": ep_key,
                                    "param_in": param.get("in", "query"),
                                    "param_type": param.get("type", "string"),
                                    "required": param.get("required", False)})

    def _scan_graphql_batching(self, findings: list[dict], gql_endpoints: list[str]) -> None:
        """Send a batch of identical queries and check for processing."""
        batch = [{"query": "{ __typename }"}] * BATCH_SIZE
        for url in gql_endpoints:
            try:
                resp = self.session.post(
                    url, json=batch, timeout=self.timeout + 5
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 1:
                            details = f"Server accepted a batch of {len(data)} queries in a single request."
                            self._record_confirmed(
                                findings, "GraphQL Batching Attack", url, "medium",
                                details, "__typename", "POST", batch,
                                response_excerpt=resp.text[:500],
                                steps_to_reproduce=[
                                    f"Send POST request to {url} with {len(batch)} batched queries",
                                    "Observe that the server processes all queries in a single request",
                                ],
                            )
                            log(f"  [GQL Batch] {url}", Colors.YELLOW,
                                verbose_only=True, verbose=self.verbose)
                    except (json.JSONDecodeError, ValueError):
                        pass
            except Exception as e:
                log(f"  [GQL Batch] Error: {e}", Colors.WHITE,
                    verbose_only=True, verbose=self.verbose)

    # ── REST BOLA (Verb Tampering) ─────────────────────────────────────────

    def scan_bola(self, endpoints: list[dict]) -> list[dict]:
        """Test discovered REST endpoints with HTTP verb tampering.

        For each endpoint, alternate methods are tried. A 200/201/204
        response on a method that was not originally declared suggests
        a BOLA / improper authorization risk.
        """
        findings: list[dict] = []

        if not endpoints:
            return findings

        bola_enabled = self._get_module_param("api", "bola", True)
        if not bola_enabled:
            return findings

        tested: set[tuple[str, str]] = set()
        for ep in endpoints:
            path = ep["path"]
            orig_method = ep["method"]
            tamper_methods = BOLA_TAMPER_MAP.get(orig_method, [])
            url = self.base_url + path

            for method in tamper_methods:
                key = (url, method)
                if key in tested:
                    continue
                tested.add(key)

                try:
                    resp = self.session.request(method, url, timeout=self.timeout)
                    if resp.status_code in (200, 201, 204):
                        details = (
                            f"Endpoint {path} returned HTTP {resp.status_code} "
                            f"on {method} (original: {orig_method}). "
                            "This may indicate missing authorization checks."
                        )
                        f = finding(
                            "Broken Object Level Authorization (BOLA)",
                            url, "high", details,
                            f"HTTP {resp.status_code} on {method}",
                            verification_stage="validated",
                            request=_build_curl(method, url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            response_excerpt=resp.text[:500],
                            steps_to_reproduce=[
                                f"Send {method.upper()} request to {url}",
                                "Observe that the endpoint returns accessible content without proper authorization",
                            ],
                        )
                        self._append_finding(findings, f)
                        log(f"  [BOLA] {method} {url} → {resp.status_code}", Colors.RED,
                            verbose_only=True, verbose=self.verbose)
                        break
                except Exception as e:
                    log(f"  [BOLA] Error {method} {url}: {e}", Colors.WHITE,
                        verbose_only=True, verbose=self.verbose)

        return self._deduplicate(findings)

    # ── Mass Assignment ────────────────────────────────────────────────────

    def scan_mass_assignment(self, endpoints: list[dict]) -> list[dict]:
        """For POST/PUT/PATCH endpoints, inject extra privilege-related
        fields (isAdmin, role, etc.) and check if they are reflected or
        accepted in the response.
        """
        findings: list[dict] = []

        if not endpoints:
            return findings

        mass_enabled = self._get_module_param("api", "mass_assignment", True)
        if not mass_enabled:
            return findings

        target_eps = [
            ep for ep in endpoints
            if ep.get("method") in ("POST", "PUT", "PATCH")
        ]

        for ep in target_eps:
            path = ep["path"]
            url = self.base_url + path
            method = ep["method"].lower()

            for field in MASS_ASSIGN_FIELDS:
                body = {field: True}

                try:
                    if method == "post":
                        resp = self.session.post(url, json=body, timeout=self.timeout)
                    elif method == "put":
                        resp = self.session.put(url, json=body, timeout=self.timeout)
                    elif method == "patch":
                        resp = self.session.patch(url, json=body, timeout=self.timeout)
                    else:
                        continue

                    if resp.status_code not in (200, 201):
                        continue

                    body_text = resp.text
                    if field in body_text or '"true"' in body_text or ":true" in body_text:
                        details = (
                            f"Endpoint {path} accepted extra field '{field}' "
                            f"and reflected it in the response. This may indicate "
                            f"a mass assignment vulnerability."
                        )
                        f = finding(
                            "Mass Assignment", url, "high",
                            details,
                            f"Field '{field}' reflected in response: {body_text[:120]}",
                            verification_stage="validated",
                            parameter=field,
                            request=_build_curl(method, url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            response_excerpt=resp.text[:500],
                            steps_to_reproduce=[
                                f"Send {method.upper()} request to {url} with extra field '{field}'",
                                "Observe that the field is accepted and reflected in the response",
                            ],
                        )
                        self._append_finding(findings, f)
                        log(f"  [MASS] {method.upper()} {url} field='{field}'", Colors.RED,
                            verbose_only=True, verbose=self.verbose)
                        break
                except Exception as e:
                    log(f"  [MASS] Error {method.upper()} {url}: {e}", Colors.WHITE,
                        verbose_only=True, verbose=self.verbose)

        return self._deduplicate(findings)

    # ── GraphQL Auth Bypass ────────────────────────────────────────────

    def scan_graphql_auth_bypass(self, gql_endpoints: list[str]) -> list[dict]:
        """Test GraphQL mutations with alternative role sessions to detect
        authorization bypass.

        Improvements over the previous implementation:
          - Tests ALL mutations (not just first 5)
          - Fills args with real IDs from DiscoveryStore when available
          - Adds response body content comparison (JSON diff) alongside
            status code comparison
          - Tests both mutations and queries
        """
        findings: list[dict] = []

        if len(gql_endpoints) < 1 or len(self.role_sessions) < 2:
            return findings

        mutations = self._discover_mutations(gql_endpoints)
        if not mutations:
            return findings

        roles = list(self.role_sessions.keys())
        default_role = self.current_role if self.current_role in self.role_sessions else roles[0]
        other_roles = [r for r in roles if r != default_role and r != "alt"]
        if not other_roles:
            return findings

        discovered_ids = self._get_numeric_ids_for_args(max_count=20)
        id_iter = iter(discovered_ids)

        for url in gql_endpoints:
            url_mutations = [m for m in mutations if m["url"] == url]
            findings.extend(self._test_mutation_auth(
                url, url_mutations, default_role, other_roles, discovered_ids))
            findings.extend(self._test_query_auth(
                url, default_role, other_roles))

        return self._deduplicate(findings)

    def _test_mutation_auth(self, url: str, mutations: list[dict],
                            default_role: str, other_roles: list[str],
                            discovered_ids: list[str]) -> list[dict]:
        """Test every mutation for auth bypass using role sessions.

        For each mutation, tries all roles as the 'alt' role to catch
        multi-role authorization violations. Uses real IDs from
        DiscoveryStore when arg names match ID patterns.
        """
        findings: list[dict] = []
        id_idx = 0

        default_sess = self.role_sessions[default_role]

        for mut in mutations:
            mut_name = mut["name"]
            args = mut.get("args", [])
            if not args:
                continue

            variables = self._build_gql_variables(args, discovered_ids, id_idx)
            id_idx += len(args)

            selection_set = self._build_gql_selection_set(mut_name)

            gql_query = (
                f"mutation {{ {mut_name}({', '.join(f'{k}: ${k}' for k in variables)})"
                f" {selection_set} }}"
            )
            body = {"query": gql_query, "variables": variables}

            resp_a = self._try_gql_request(default_sess, url, body)
            if resp_a is None:
                continue

            for alt_role in other_roles:
                alt_sess = self.role_sessions[alt_role]
                resp_b = self._try_gql_request(alt_sess, url, body)
                if resp_b is None:
                    continue

                bypass = self._compare_gql_responses(
                    mut_name, url, default_role, alt_role,
                    resp_a, resp_b, body, "mutation")
                if bypass:
                    findings.append(bypass)

        return findings

    def _test_query_auth(self, url: str, default_role: str,
                         other_roles: list[str]) -> list[dict]:
        """Test GraphQL queries for auth bypass across roles.

        Uses discovered type fields from the schema for meaningful
        comparison, plus basic introspection probes.
        """
        findings: list[dict] = []
        default_sess = self.role_sessions[default_role]

        # Build field-level queries from discovered types
        store = self._get_discovery_store()
        discovered_queries: list[tuple[str, str]] = []
        if store is not None:
            gql_types = store.get_by_category("gql_type")
            gql_fields = store.get_by_category("gql_field")
            query_root_name = "Query"
            for rec in gql_types:
                extra_raw = rec.get("extra") or "{}"
                try:
                    import json
                    extra = json.loads(extra_raw) if isinstance(extra_raw, str) else extra_raw
                except (json.JSONDecodeError, TypeError):
                    extra = {}
                if extra.get("role") == "query_root":
                    query_root_name = rec.get("value", "Query")
                    break

            # Find top-level query fields
            root_field_names: list[str] = []
            for rec in gql_fields:
                val: str = rec.get("value", "")
                extra_raw = rec.get("extra") or "{}"
                try:
                    extra = json.loads(extra_raw) if isinstance(extra_raw, str) else extra_raw
                except (json.JSONDecodeError, TypeError):
                    extra = {}
                if extra.get("parent_type") == query_root_name:
                    field_name = val.split(".")[-1]
                    field_type = extra.get("field_type", "")
                    if field_type and field_type not in ("String", "Int", "Float", "Boolean", "ID"):
                        root_field_names.append(f"{field_name} {{ id name }}")
                    elif field_name not in ("__typename",):
                        root_field_names.append(field_name)

            if root_field_names:
                deduped: list[str] = []
                seen: set[str] = set()
                for f in root_field_names[:5]:
                    base = f.split(" ")[0]
                    if base not in seen:
                        seen.add(base)
                        deduped.append(f)
                selection = "{ " + " ".join(deduped) + " }"
                discovered_queries.append(("type query", f"{{ {query_root_name} {selection} }}"))

        test_queries = discovered_queries + [
            ("__typename", "{ __typename }"),
            ("schema check", "{ __schema { queryType { name } } }"),
            ("introspection", "{ __schema { types { name } } }"),
        ]

        for qlabel, qtext in test_queries:
            body = {"query": qtext}
            resp_a = self._try_gql_request(default_sess, url, body)
            if resp_a is None:
                continue

            for alt_role in other_roles:
                alt_sess = self.role_sessions[alt_role]
                resp_b = self._try_gql_request(alt_sess, url, body)
                if resp_b is None:
                    continue

                bypass = self._compare_gql_responses(
                    qlabel, url, default_role, alt_role,
                    resp_a, resp_b, body, "query")
                if bypass:
                    findings.append(bypass)

        return findings

    def _build_gql_variables(self, args: list[dict], discovered_ids: list[str],
                             start_idx: int = 0) -> dict[str, str]:
        """Build GQL variables for a mutation, using real IDs when appropriate.

        Maps arg names to discovered IDs when the arg name suggests an
        identifier (``id``, ``userId``, ``accountId``, etc.), falling
        back to ``"test"`` for other args.
        """
        id_arg_keys = frozenset({
            "id", "userId", "user_id", "accountId", "account_id",
            "orgId", "org_id", "uid", "teamId", "team_id",
            "input", "data", "record",
        })
        variables: dict[str, str] = {}
        for i, arg in enumerate(args[:5]):
            arg_name = arg["name"]
            arg_lower = arg_name.lower()
            if arg_lower in id_arg_keys and discovered_ids:
                idx = (start_idx + i) % len(discovered_ids)
                variables[arg_name] = discovered_ids[idx]
            else:
                variables[arg_name] = "test"
        if not variables:
            variables["input"] = "test"
        return variables

    def _build_gql_selection_set(self, mutation_name: str) -> str:
        """Build a field selection set for a mutation's return type.

        Reads DiscoveryStore for gql_field records and constructs a
        meaningful selection set with real type fields instead of just
        ``{ __typename }``.

        Returns a string like ``{ id name email role { id name } }``.
        """
        store = self._get_discovery_store()
        if store is None:
            return "{ __typename }"

        gql_fields = store.get_by_category("gql_field")
        # Find mutation return fields: the mutation name typically maps
        # to a returned object type (e.g. createUser returns User)
        # Try to find fields belonging to the capitalized mutation name
        return_type_candidates = [
            mutation_name.replace("create", "").replace("update", "").replace("delete", ""),
            mutation_name.replace("add", "").replace("remove", ""),
            mutation_name.replace("set", ""),
        ]

        candidate_fields: list[str] = []
        for rec in gql_fields:
            val: str = rec.get("value", "")
            extra_raw = rec.get("extra") or "{}"
            try:
                import json
                extra = json.loads(extra_raw) if isinstance(extra_raw, str) else extra_raw
            except (json.JSONDecodeError, TypeError):
                extra = {}
            parent_type: str = extra.get("parent_type", "")
            # Check if this field belongs to any candidate return type
            for candidate in return_type_candidates:
                if candidate and parent_type.lower() == candidate.lower():
                    field_name = val.split(".")[-1]
                    is_rel = extra.get("is_relationship", False)
                    if is_rel:
                        field_type = extra.get("field_type", "")
                        candidate_fields.append(f"{field_name} {{ id name }}")
                    elif field_name not in ("__typename", "id"):
                        candidate_fields.append(field_name)
                    break

        if candidate_fields:
            # Deduplicate and limit to 10 fields max
            seen: set[str] = set()
            unique: list[str] = []
            for f in candidate_fields:
                base = f.split(" ")[0]
                if base not in seen:
                    seen.add(base)
                    unique.append(f)
                    if len(unique) >= 10:
                        break
            return "{ " + " ".join(unique) + " }"

        return "{ __typename }"

    @staticmethod
    def _try_gql_request(session: Any, url: str, body: dict,
                         timeout: int | None = None) -> Any | None:
        """Send a GQL POST request and return the response, or None on failure."""
        try:
            resp = session.post(url, json=body, timeout=timeout or 30)
            return resp
        except Exception:
            return None

    def _compare_gql_responses(self, name: str, url: str,
                               default_role: str, alt_role: str,
                               resp_a: Any, resp_b: Any,
                               body: dict, gql_type: str) -> dict | None:
        """Compare GQL responses between two roles and create a finding if bypass found.

        Detects bypass via:
          1. Status code disparity (default rejected, alt accepted)
          2. Body content disparity (default gets error, alt gets data)
        """
        findings_list: list[dict] = []

        status_bypass = (resp_a.status_code != 200 and resp_b.status_code == 200)
        if status_bypass:
            finding_obj = self._make_auth_finding(
                name, url, default_role, alt_role, gql_type,
                resp_a, resp_b, body, "HTTP status bypass")
            if finding_obj:
                findings_list.append(finding_obj)

        body_diff = self._detect_gql_body_diff(resp_a, resp_b)
        if body_diff and not status_bypass:
            finding_obj = self._make_auth_finding(
                name, url, default_role, alt_role, gql_type,
                resp_a, resp_b, body, "response body bypass")
            if finding_obj:
                findings_list.append(finding_obj)

        if findings_list:
            return findings_list[0]
        return None

    @staticmethod
    def _detect_gql_body_diff(resp_a: Any, resp_b: Any) -> bool:
        """Return True if the responses differ in a meaningful way.

        Checks:
          - One has ``data``, other has ``errors``
          - Different data content (field-level comparison, ignoring __typename)
          - Different error messages
        """
        try:
            data_a = resp_a.json() if hasattr(resp_a, 'json') else {}
            data_b = resp_b.json() if hasattr(resp_b, 'json') else {}
        except (json.JSONDecodeError, ValueError, AttributeError):
            return False

        if not isinstance(data_a, dict) or not isinstance(data_b, dict):
            return False

        has_data_a = "data" in data_a and data_a["data"] is not None
        has_data_b = "data" in data_b and data_b["data"] is not None
        if has_data_a and not has_data_b:
            return True
        if not has_data_a and has_data_b:
            return True

        has_errors_a = "errors" in data_a
        has_errors_b = "errors" in data_b
        if has_errors_a and not has_errors_b:
            return True
        if not has_errors_a and has_errors_b:
            return True

        # Field-level comparison when both have data
        if has_data_a and has_data_b:
            data_content_a = data_a.get("data", {})
            data_content_b = data_b.get("data", {})
            if data_content_a != data_content_b:
                return True

        return False

    def _make_auth_finding(self, name: str, url: str,
                           default_role: str, alt_role: str,
                           gql_type: str, resp_a: Any, resp_b: Any,
                           body: dict, bypass_signal: str) -> dict | None:
        """Create a finding for a detected GQL auth bypass."""
        from models.evidence import AuthorizationComparisonEvidence, HttpRequestEvidence, HttpResponseEvidence

        finding_obj = finding(
            "GraphQL Auth Bypass",
            url, "critical",
            f"{gql_type.capitalize()} '{name}' rejected for '{default_role}' "
            f"(HTTP {resp_a.status_code}) but accepted for '{alt_role}' "
            f"(HTTP {resp_b.status_code}) — {bypass_signal}.",
            f"Signal: {bypass_signal} | Role '{default_role}': "
            f"HTTP {resp_a.status_code} | "
            f"Role '{alt_role}': HTTP {resp_b.status_code}",
            verification_stage="validated",
            request=_build_curl("POST", url, dict(getattr(self, 'session', type('', (), {}))().headers
                                if not hasattr(self, 'session') else self.session.headers)),
            response_excerpt=resp_b.text[:500],
            steps_to_reproduce=[
                f"Authenticate as '{alt_role}'",
                f"Send {gql_type} '{name}' to {url}",
                f"Observe HTTP {resp_b.status_code} vs expected rejection (HTTP {resp_a.status_code})",
            ],
        )

        try:
            authz_ev = AuthorizationComparisonEvidence(
                original_role=default_role,
                original_status=resp_a.status_code,
                original_body=resp_a.text[:500] if hasattr(resp_a, 'text') else "",
                target_role=alt_role,
                target_status=resp_b.status_code,
                target_body=resp_b.text[:500] if hasattr(resp_b, 'text') else "",
                body_diff_detected=(bypass_signal == "response body bypass"),
            )
            existing = finding_obj.get("evidence", [])
            if isinstance(existing, str):
                existing = [existing] if existing else []
            existing.append(authz_ev)
            finding_obj["evidence"] = existing
        except Exception:
            pass

        log(f"  [GQL Auth] {name} ({gql_type}) — {alt_role} bypassed auth via {bypass_signal}",
            Colors.RED, verbose_only=True, verbose=self.verbose)
        return finding_obj

    # ── GraphQL Batched Auth Bypass ──────────────────────────────────────

    def _scan_gql_batched_auth_bypass(self, gql_endpoints: list[str]) -> list[dict]:
        """Send batched queries under different roles to detect auth bypass.

        Batched GQL can sometimes bypass auth checks because each request
        in the batch may be evaluated independently, and some roles may
        have access to data in the batch that they shouldn't.
        """
        findings: list[dict] = []

        if len(gql_endpoints) < 1 or len(self.role_sessions) < 2:
            return findings

        roles = list(self.role_sessions.keys())
        default_role = self.current_role if self.current_role in self.role_sessions else roles[0]
        other_roles = [r for r in roles if r != default_role and r != "alt"]
        if not other_roles:
            return findings

        batch_query = {"query": "{ __typename }"}
        batch = [batch_query] * 5 + [
            {"query": "{ __schema { queryType { name } } }"},
            {"query": "{ __schema { mutationType { name } } }"},
        ]

        default_sess = self.role_sessions[default_role]

        for url in gql_endpoints:
            resp_a = self._try_gql_request(default_sess, url, batch)
            if resp_a is None:
                continue

            for alt_role in other_roles:
                alt_sess = self.role_sessions[alt_role]
                resp_b = self._try_gql_request(alt_sess, url, batch)
                if resp_b is None:
                    continue

                bypass = self._compare_gql_responses(
                    "batched", url, default_role, alt_role,
                    resp_a, resp_b, {"batch": batch}, "batched query")
                if bypass:
                    findings.append(bypass)

        return findings

    # ── GraphQL Query Depth Attack (Phase 5) ──────────────────────────────

    def scan_graphql_query_depth(self, gql_endpoints: list[str]) -> list[dict]:
        """Test for deep/aliased/recursive queries that could cause DoS."""
        findings: list[dict] = []

        if not gql_endpoints:
            return findings

        deep_query = "{ __typename " + " ".join(f"a{i}: __typename" for i in range(50)) + " }"
        recursive_query = "query q { __typename ... { __typename ... { __typename ... { __typename } } } }"

        for url in gql_endpoints:
            for label, query in [("deep alias", deep_query), ("recursive", recursive_query)]:
                try:
                    resp = self.session.post(url, json={"query": query}, timeout=self.timeout)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if data and data.get("data"):
                                self._append_finding(findings, finding(
                                    "GraphQL Query Depth Attack",
                                    url, "medium",
                                    f"Server accepted a {label} query with high nesting — "
                                    f"potential for DoS via deep/aliased queries.",
                                    f"Query: {label} | Response: {resp.text[:200]}",
                                    verification_stage="validated",
                                    request=_build_curl("POST", url, dict(self.session.headers),
                                                        cookies=safe_cookies_dict(self.session.cookies)),
                                    response_excerpt=resp.text[:500],
                                    steps_to_reproduce=[
                                        f"Send POST request to {url} with a deeply aliased/recursive query",
                                        "Observe that the server processes and returns data without rejection",
                                    ],
                                ))
                                log(f"  [GQL Depth] {url} — {label} accepted",
                                    Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                        except (json.JSONDecodeError, ValueError):
                            pass
                except Exception as e:
                    log(f"  [GQL Depth] Error: {e}", Colors.WHITE,
                        verbose_only=True, verbose=self.verbose)

        return self._deduplicate(findings)

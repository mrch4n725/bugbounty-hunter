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
    "/api/v1/graphql", "/graphql/console",
    "/graphiql", "/api/graphiql", "/api/v2/graphql",
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

        gql_endpoints = self._find_gql_endpoints()
        if gql_endpoints:
            log(f"  [API] Found {len(gql_endpoints)} GraphQL endpoint(s)", Colors.CYAN,
                verbose_only=True, verbose=self.verbose)

        findings.extend(self.scan_graphql_introspection(gql_endpoints))
        findings.extend(self.scan_graphql_injection(gql_endpoints))
        findings.extend(self.scan_graphql_auth_bypass(gql_endpoints))
        findings.extend(self.scan_graphql_query_depth(gql_endpoints))
        findings.extend(self.scan_bola(endpoints))
        findings.extend(self.scan_mass_assignment(endpoints))

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

    def _find_gql_endpoints(self) -> list[str]:
        """Probe common paths to discover live GraphQL endpoints."""
        found: list[str] = []
        seen: set[str] = set()

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

    # ── GraphQL Auth Bypass (Phase 5) ─────────────────────────────────────

    def scan_graphql_auth_bypass(self, gql_endpoints: list[str]) -> list[dict]:
        """Test GraphQL mutations with alternative role sessions to detect
        authorization bypass. Sends the same operation with different roles
        and compares responses."""
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

        alt_role = other_roles[0]

        for mut in mutations[:5]:
            url = mut["url"]
            mut_name = mut["name"]
            args = mut.get("args", [])
            if not args:
                continue

            variables: dict[str, str] = {}
            for arg in args[:2]:
                variables[arg["name"]] = "test"
            if not variables:
                variables["input"] = "test"

            gql_query = f"mutation {{ {mut_name}({', '.join(f'{k}: ${k}' for k in variables)}) {{ __typename }} }}"
            body = {"query": gql_query, "variables": variables}

            default_sess = self.role_sessions[default_role]
            alt_sess = self.role_sessions[alt_role]

            try:
                resp_a = default_sess.post(url, json=body, timeout=self.timeout)
                resp_b = alt_sess.post(url, json=body, timeout=self.timeout)

                if resp_a.status_code != 200 and resp_b.status_code == 200:
                    self._append_finding(findings, finding(
                        "GraphQL Auth Bypass",
                        url, "critical",
                        f"Mutation '{mut_name}' rejected for '{default_role}' "
                        f"(HTTP {resp_a.status_code}) but accepted for '{alt_role}' "
                        f"(HTTP {resp_b.status_code}) — authorization bypass.",
                        f"Role '{default_role}': HTTP {resp_a.status_code} | "
                        f"Role '{alt_role}': HTTP {resp_b.status_code}",
                        verification_stage="validated",
                        request=_build_curl("POST", url, dict(default_sess.headers)),
                        response_excerpt=resp_b.text[:500],
                        steps_to_reproduce=[
                            f"Authenticate as '{alt_role}'",
                            f"Send mutation '{mut_name}' to {url}",
                            "Observe HTTP 200 vs the expected rejection",
                        ],
                    ))
                    log(f"  [GQL Auth] {mut_name} — {alt_role} bypassed auth",
                        Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [GQL Auth] Error: {e}", Colors.WHITE,
                    verbose_only=True, verbose=self.verbose)

        return self._deduplicate(findings)

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

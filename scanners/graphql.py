"""
GraphQLScanner — detects insecure GraphQL endpoint configurations.

Lifecycle:
  DETECTED:   Endpoint accessible, schema data found
  VALIDATED:  Schema introspection returns structured type/mutation info
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate + typed evidence + reproduction)
"""

from modules.utils import (
    finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
from models.evidence import GraphQLSchemaEvidence, EvidenceStatus


class GraphQLScanner(ScannerBase):
    SCANNER_NAME = "graphql"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = True
    SCANNER_ORDER = 10

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        return None

    def detect_endpoint(self, url: str, introspection_query: dict,
                        batch_payload: list, headers: dict) -> list[DetectionResult]:
        results: list[DetectionResult] = []

        # 1. Introspection
        try:
            r = self.session.post(url, json=introspection_query, headers=headers, timeout=self.timeout)
            if r.status_code == 200 and "__schema" in r.text:
                query_names: list[str] = []
                mutation_names: list[str] = []
                try:
                    data = r.json()
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    type_names = [t.get("name", "") for t in types if t.get("name") and not t["name"].startswith("__")]
                    deeper_q = {"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}
                    r2 = self.session.post(url, json=deeper_q, headers=headers, timeout=self.timeout)
                    if r2.status_code == 200:
                        d2 = r2.json()
                        s2 = d2.get("data", {}).get("__schema", {})
                        for t in s2.get("types", []):
                            if t.get("kind") == "OBJECT":
                                tname = t.get("name", "")
                                fields = t.get("fields", [])
                                fnames = [f.get("name", "") for f in fields if f.get("name")]
                                if tname == "Query" or tname.endswith("Query"):
                                    query_names.extend(fnames)
                                elif tname == "Mutation" or tname.endswith("Mutation"):
                                    mutation_names.extend(fnames)
                except Exception:
                    pass

                sev = "high" if mutation_names else "medium"
                details = f"Full schema is exposed via introspection. Types: {len(type_names)} found."
                if mutation_names:
                    details += f" Mutations ({len(mutation_names)}) present — potential for data modification."
                if query_names:
                    details += f" Queries ({len(query_names)}) exposed."

                results.append(DetectionResult(
                    url=url,
                    parameter="",
                    payload=f"schema_types={len(type_names)};mutations={len(mutation_names)};queries={len(query_names)}",
                    context="graphql_introspection",
                    evidence_signals=[details, str(type_names[:30])],
                ))
        except Exception:
            pass

        # 2. Query batching
        try:
            r = self.session.post(url, json=batch_payload, headers=headers, timeout=self.timeout)
            if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 1:
                results.append(DetectionResult(
                    url=url,
                    parameter="",
                    payload="50_batch",
                    context="graphql_batching",
                    evidence_signals=["Server accepts batched GraphQL arrays with no apparent limit (50 queries in one request)"],
                ))
        except Exception:
            pass

        # 3. Field suggestion leakage
        try:
            r = self.session.post(url, json={"query": "{ "}, headers=headers, timeout=self.timeout)
            if r.status_code == 400 and '"suggestions"' in r.text:
                suggestions_found = []
                try:
                    errs = r.json().get("errors", [])
                    for err in errs:
                        sug = err.get("extensions", {}).get("suggestions", [])
                        if sug:
                            suggestions_found.extend(sug[:5])
                except Exception:
                    pass
                evidence = "Error messages contain suggested field names, aiding attacker recon"
                if suggestions_found:
                    evidence += f" (suggestions: {', '.join(suggestions_found)})"
                results.append(DetectionResult(
                    url=url,
                    parameter="",
                    payload="suggestions",
                    context="graphql_suggestions",
                    evidence_signals=[evidence],
                ))
        except Exception:
            pass

        # 3b. Misspelled field probe for deeper suggestion leakage
        try:
            misspelled_queries = [
                "{ uesrs { name } }",
                "{ qurey { id } }",
                "{ mutaions { name } }",
            ]
            for mq in misspelled_queries[:2]:
                rm = self.session.post(url, json={"query": mq}, headers=headers, timeout=self.timeout)
                if rm.status_code == 400 and '"suggestions"' in rm.text:
                    sug_found = []
                    try:
                        errs = rm.json().get("errors", [])
                        for err in errs:
                            sug = err.get("extensions", {}).get("suggestions", [])
                            if sug:
                                sug_found.extend(sug[:3])
                    except Exception:
                        pass
                    evidence_sig = f"Misspelled field '{mq}' triggered suggestions"
                    if sug_found:
                        evidence_sig += f": {', '.join(sug_found)}"
                    results.append(DetectionResult(
                        url=url,
                        parameter="",
                        payload="misspelled_field",
                        context="graphql_suggestions",
                        evidence_signals=[evidence_sig],
                    ))
                    break
        except Exception:
            pass

        # 4. Alias-based resource exhaustion
        try:
            if self.config.get("allow_dos_tests", False):
                alias_qs = " ".join(f"a{i}: __typename" for i in range(200))
                r = self.session.post(url, json={"query": "{" + alias_qs + "}"},
                                      headers=headers, timeout=self.timeout)
                if r.status_code == 200:
                    results.append(DetectionResult(
                        url=url,
                        parameter="",
                        payload="200_aliases",
                        context="graphql_alias_dos",
                        evidence_signals=["Server accepts 200+ aliases in a single query, allowing resource exhaustion"],
                    ))
        except Exception:
            pass

        # 5. Depth limit testing — graduated approach
        try:
            # Test incremental depths to find the actual query depth limit
            depth_levels = [3, 5, 7, 10, 15]
            max_depth_allowed = 0
            for depth in depth_levels:
                # Build a deeply nested query of specified depth
                nested = "user"
                for _ in range(depth - 1):
                    nested += "{posts{comments{author{" + nested.split("{")[0] + "}}}"
                # Simpler approach: build depth incrementally
                inner = "name"
                for d in range(depth):
                    inner = f"user{{posts{{comments{{author{{{inner}}}}}}}}}"
                deep_q = "{" + inner + "}"
                # Limit query length to avoid false negatives
                if len(deep_q) > 2000:
                    break
                r = self.session.post(url, json={"query": deep_q}, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and "errors" not in r.text:
                    max_depth_allowed = depth
                else:
                    break
            if max_depth_allowed >= 7:
                results.append(DetectionResult(
                    url=url,
                    parameter="",
                    payload=f"{max_depth_allowed}_levels",
                    context="graphql_deep_query",
                    evidence_signals=[f"Server allows {max_depth_allowed}+ levels of nested queries (tested up to depth {max_depth_allowed}), enabling recursive DoS"],
                ))
            elif max_depth_allowed >= 5:
                results.append(DetectionResult(
                    url=url,
                    parameter="",
                    payload=f"{max_depth_allowed}_levels",
                    context="graphql_deep_query",
                    evidence_signals=[f"Server allows {max_depth_allowed} levels of nested queries — moderate depth limit may still permit resource exhaustion"],
                ))
        except Exception:
            pass

        # 6. Query cost analysis — wide query with many fields
        try:
            # Build a wide query that requests many fields to assess cost limiting
            from string import ascii_lowercase as _alc
            wide_fields = " ".join(f"a{i}: __typename" for i in range(50))
            wide_q = "{" + wide_fields + "}"
            r = self.session.post(url, json={"query": wide_q}, headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                # Measure response size as a proxy for query cost
                response_size = len(r.text)
                # Also send a more expensive query: multiple entities at varying depths
                cost_q = "{"
                for i in range(10):
                    cost_q += f"u{i}: user{{id name email posts{{title comments{{body}}}}}} "
                cost_q += "}"
                r2 = self.session.post(url, json={"query": cost_q}, headers=headers, timeout=self.timeout)
                if r2.status_code == 200:
                    cost_size = len(r2.text)
                    results.append(DetectionResult(
                        url=url,
                        parameter="",
                        payload=f"wide_fields=50+cost_size={cost_size}",
                        context="graphql_no_cost_limit",
                        evidence_signals=[
                            f"Server accepts wide queries with 50+ aliases and complex nested requests "
                            f"(response size: {cost_size} bytes), suggesting no query cost analysis is enforced"
                        ],
                    ))
        except Exception:
            pass

        return results

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        if detection.context == "graphql_introspection":
            return ValidationResult(confirmed=True, method="introspection_query",
                                    detail="GraphQL introspection enabled — schema data returned via standard query")
        if detection.context == "graphql_no_cost_limit":
            return ValidationResult(confirmed=True, method="query_cost_analysis",
                                    detail="Server accepts wide/nested queries without cost limiting or complexity analysis")
        return ValidationResult(confirmed=False, method="endpoint_behavior",
                                detail=f"GraphQL misconfiguration detected: {detection.context}")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        if detection.context == "graphql_introspection":
            return [
                GraphQLSchemaEvidence(
                    query_text="{ __schema { types { name } } }",
                    schema_preview=detection.evidence_signals[1] if len(detection.evidence_signals) > 1 else "",
                    mutation_count=int(detection.payload.split(";")[1].split("=")[1]) if "mutations=" in detection.payload else 0,
                    query_count=int(detection.payload.split(";")[2].split("=")[1]) if "queries=" in detection.payload else 0,
                    description=f"GraphQL introspection enabled at {detection.url}",
                    status=EvidenceStatus.VERIFIED,
                ),
            ]
        return []

    def generate_reproduction(self, detection: DetectionResult,
                              validation_result: ValidationResult | None = None) -> list[str]:
        ctx = detection.context
        if ctx == "graphql_introspection":
            return [
                f"curl -X POST '{detection.url}' -H 'Content-Type: application/json' -d '{{\"query\":\"query {{ __schema {{ types {{ name fields {{ name }} }} }} }}\"}}'",
                "Observe __schema in the JSON response — this confirms introspection is enabled",
                "An attacker can dump the entire schema: all queries, mutations, types, and fields for targeted attack construction",
            ]
        if ctx == "graphql_batching":
            return [
                f"curl -X POST '{detection.url}' -H 'Content-Type: application/json' -d '[{{\"query\":\"query {{ __typename }}\"}},...repeat 50 times]'",
                "Server returns an array of 50 responses (HTTP 200) — no batching limit enforced",
                "Unrestricted batching enables resource exhaustion DoS and efficient data harvesting at scale",
            ]
        if ctx == "graphql_suggestions":
            return [
                f"curl -X POST '{detection.url}' -H 'Content-Type: application/json' -d '{{\"query\":\"query {{ \"}}'",
                "Server responds with HTTP 400 and includes 'suggestions' in the error message containing valid field names",
                "This leaks the schema structure to unauthenticated attackers without needing full introspection, enabling targeted attack construction",
            ]
        if ctx == "graphql_alias_dos":
            return [
                f"curl -X POST '{detection.url}' -H 'Content-Type: application/json' -d '{{\"query\":\"query {{ a1:__typename a2:__typename ... a200:__typename }}\"}}'",
                "Server responds with HTTP 200 — all 200 aliases were resolved without throttling or rejection",
                "An attacker can cause DoS by sending many alias-heavy queries simultaneously, exhausting server CPU and database connections",
            ]
        if ctx == "graphql_auth_bypass":
            return [
                f"curl -X POST '{detection.url}' -H 'Content-Type: application/json' -d '{{\"query\":\"query {{ sensitiveQuery }}\"}}'",
                "Mutation returns data without authentication — the endpoint does not enforce access controls",
                "Any unauthenticated attacker can query, mutate, or delete data through publicly exposed GraphQL endpoints",
            ]
        if ctx == "graphql_depth_dos":
            return [
                f"curl -X POST '{detection.url}' -H 'Content-Type: application/json' -d '{{\"query\":\"query {{ user {{ posts {{ comments {{ author {{ posts {{ comments }} }} }} }} }} }}\"}}'",
                "Server responds with deeply nested object(s) without limiting query depth",
                "An attacker can craft deeply nested queries that cause database timeouts and CPU exhaustion, leading to denial of service",
            ]
        return [
            f"curl -X POST '{detection.url}' -H 'Content-Type: application/json' -d '{{\"query\":\"query {{ __typename }}\"}}'",
            "Inspect the response for GraphQL behavior",
            "GraphQL endpoint exposure can lead to data leakage and targeted attacks",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        endpoints = ["/graphql", "/api/graphql", "/nerdgraph/graphql", "/v1/graphql", "/query"]
        introspection_query = {"query": r"{ __schema { types { name } } }"}
        batch_payload = [{"query": "{ __typename }"}] * 50
        headers = {"Content-Type": "application/json"}

        for ep in endpoints:
            url = self.base_url + ep
            if not self._in_scope(url):
                continue

            detections = self.detect_endpoint(url, introspection_query, batch_payload, headers)
            for detection in detections:
                try:
                    validation_result = self.validate(detection)
                    evidence_list = self.collect_evidence(detection, validation_result)

                    for ev in evidence_list:
                        self.evidence_engine.store(ev)

                    vuln_type_map = {
                        "graphql_introspection": "GraphQL Introspection Enabled",
                        "graphql_batching": "GraphQL Query Batching Unrestricted",
                        "graphql_suggestions": "GraphQL Field Suggestion Leak",
                        "graphql_alias_dos": "GraphQL Alias-Based Query DoS",
                        "graphql_deep_query": "GraphQL Deeply Nested Query Allowed",
                        "graphql_no_cost_limit": "GraphQL No Query Cost Analysis",
                    }
                    sev_map = {
                        "graphql_introspection": "high" if "mutations=" in detection.payload and int(detection.payload.split(";")[1].split("=")[1]) > 0 else "medium",
                        "graphql_batching": "medium",
                        "graphql_suggestions": "low",
                        "graphql_alias_dos": "low",
                        "graphql_deep_query": "low",
                        "graphql_no_cost_limit": "medium",
                    }
                    stage_map = {
                        "graphql_introspection": VerificationStage.VALIDATED.value,
                        "graphql_batching": VerificationStage.VALIDATED.value,
                        "graphql_suggestions": VerificationStage.VALIDATED.value,
                        "graphql_alias_dos": VerificationStage.DETECTED.value,
                        "graphql_deep_query": VerificationStage.DETECTED.value,
                        "graphql_no_cost_limit": VerificationStage.DETECTED.value,
                    }

                    details = detection.evidence_signals[0] if detection.evidence_signals else "GraphQL misconfiguration detected"
                    f = finding(
                        vuln_type=vuln_type_map.get(detection.context, "GraphQL Misconfiguration"),
                        url=url,
                        severity=sev_map.get(detection.context, "medium"),
                        details=details,
                        evidence=detection.payload,
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=details[:500],
                        steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                        verification_stage=stage_map.get(detection.context, VerificationStage.DETECTED.value),
                    )
                    if f:
                        self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                        fingerprint = f.get("fingerprint", "")
                        if fingerprint:
                            for ev in evidence_list:
                                self.evidence_engine.link_to_finding(ev, fingerprint)
                        self._add_finding(f)
                except Exception:
                    pass

        return self._get_findings()

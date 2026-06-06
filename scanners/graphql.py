"""
GraphQLScanner — detects insecure GraphQL endpoint configurations.

Lifecycle:
  DETECTED:   Endpoint accessible, schema data found
  VALIDATED:  Schema introspection returns structured type/mutation info
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 2 (Detect + Validate)
"""

from modules.utils import (
    finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase
from models.evidence import GraphQLSchemaEvidence, EvidenceStatus


class GraphQLScanner(ScannerBase):
    SCANNER_NAME = "graphql"
    TARGET_LEVEL = True
    SCANNER_ORDER = 10

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        endpoints = ["/graphql", "/api/graphql", "/nerdgraph/graphql", "/v1/graphql", "/query"]
        introspection_query = {"query": r"{ __schema { types { name } } }"}
        batch_payload = [{"query": "{ __typename }"}] * 50
        headers = {"Content-Type": "application/json"}

        for ep in endpoints:
            url = self.base_url + ep
            if not self._in_scope(url):
                continue

            # ── 1. Introspection ──────────────────────────────────────
            try:
                r = self.session.post(url, json=introspection_query, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and "__schema" in r.text:
                    query_names: list[str] = []
                    mutation_names: list[str] = []
                    schema_preview = ""
                    try:
                        data = r.json()
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        type_names = [t.get("name", "") for t in types if t.get("name") and not t["name"].startswith("__")]
                        schema_preview = ", ".join(type_names[:30])
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
                    stage = VerificationStage.VALIDATED.value if query_names or mutation_names else VerificationStage.DETECTED.value
                    details = f"Full schema is exposed via introspection. Types: {len(type_names)} found."
                    if mutation_names:
                        details += f" Mutations ({len(mutation_names)}) present — potential for data modification."
                    if query_names:
                        details += f" Queries ({len(query_names)}) exposed."

                    schema_evidence = GraphQLSchemaEvidence(
                        query_text=str(introspection_query),
                        schema_preview=schema_preview or r.text[:500],
                        mutation_count=len(mutation_names),
                        query_count=len(query_names),
                        description=f"GraphQL introspection enabled at {url}",
                        status=EvidenceStatus.VERIFIED,
                    )
                    self.evidence_engine.store(schema_evidence)

                    f = finding(
                        vuln_type="GraphQL Introspection Enabled",
                        url=url,
                        severity=sev,
                        details=details,
                        evidence="__schema",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[
                            f"Send POST request to {url} with introspection query",
                            "Observe __schema in response confirming introspection is enabled",
                        ],
                        verification_stage=stage,
                    )
                    if f:
                        if mutation_names:
                            f["severity"] = "high"
                        self.evidence_engine.link_to_finding(schema_evidence, f.get("fingerprint", ""))
                        self._add_finding(f)
            except Exception:
                pass

            # ── 2. Query batching ─────────────────────────────────────
            try:
                r = self.session.post(url, json=batch_payload, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 1:
                    f = finding(
                        vuln_type="GraphQL Query Batching Unrestricted",
                        url=url,
                        severity="medium",
                        details="Server accepts batched GraphQL arrays with no apparent limit. (50 queries in one request)",
                        evidence="__typename",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[f"Send POST request to {url} with batch query", "Observe multiple results"],
                        verification_stage=VerificationStage.VALIDATED.value,
                    )
                    if f:
                        self._add_finding(f)
            except Exception:
                pass

            # ── 3. Field suggestion leakage ──────────────────────────
            try:
                r = self.session.post(url, json={"query": "{ "}, headers=headers, timeout=self.timeout)
                if r.status_code == 400 and '"suggestions"' in r.text:
                    f = finding(
                        vuln_type="GraphQL Field Suggestion Leak",
                        url=url,
                        severity="low",
                        details="Error messages contain suggested field names, aiding attacker recon.",
                        evidence="suggestions",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[f"Send POST request to {url} with malformed query", "Observe suggestions in error"],
                        verification_stage=VerificationStage.VALIDATED.value,
                    )
                    if f:
                        self._add_finding(f)
            except Exception:
                pass

            # ── 4. Alias-based resource exhaustion ───────────────────
            try:
                if self.config.get("allow_dos_tests", False):
                    alias_qs = " ".join(f"a{i}: __typename" for i in range(200))
                    r = self.session.post(url, json={"query": "{" + alias_qs + "}"},
                                          headers=headers, timeout=self.timeout)
                    if r.status_code == 200:
                        f = finding(
                            vuln_type="GraphQL Alias-Based Query DoS",
                            url=url,
                            severity="low",
                            details="Server accepts 200+ aliases in a single query, allowing resource exhaustion.",
                            evidence="200 aliases accepted",
                            request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                            response_excerpt=r.text[:500],
                            steps_to_reproduce=[f"Send POST request to {url} with 200 aliases", "Observe 200 OK response"],
                            verification_stage=VerificationStage.DETECTED.value,
                        )
                        if f:
                            self._add_finding(f)
            except Exception:
                pass

            # ── 5. Depth limit testing ───────────────────────────────
            try:
                deep_q = "{user{posts{comments{author{posts{comments{author{name}}}}}}}}"
                r = self.session.post(url, json={"query": deep_q}, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and "errors" not in r.text:
                    f = finding(
                        vuln_type="GraphQL Deeply Nested Query Allowed",
                        url=url,
                        severity="low",
                        details="Server allows 7+ levels of nested queries, enabling recursive DoS.",
                        evidence="7+ levels accepted without error",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[f"Send POST request to {url} with deeply nested query", "Observe 200 OK without errors"],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self._add_finding(f)
            except Exception:
                pass

        return self._get_findings()

import hashlib
from typing import Any

from models.finding import Finding
from models.chain import AttackNode, AttackEdge, AttackChain
from engines.root_cause import ROOT_CAUSE_MAP


CHAIN_RULES: list[tuple[str, str, str, str]] = [
    # (source_vuln_pattern, target_vuln_pattern, relationship, final_impact)
    ("open_redirect", "oauth", "enables", "account_takeover"),
    ("open redirect", "oauth", "enables", "account_takeover"),
    ("open_redirect", "token", "enables", "account_takeover"),
    ("xss", "csrf", "bypasses", "account_takeover"),
    ("xss", "csrf", "enables", "account_takeover"),
    ("csrf", "xss", "enables", "account_takeover"),
    ("csrf", "xss", "bypasses", "rce"),
    ("graphql", "idor", "exposes", "data_exposure"),
    ("graphql", "bola", "exposes", "data_exposure"),
    ("graphql", "mass assignment", "exposes", "privilege_escalation"),
    ("idor", "sensitive_data", "leads_to", "data_exposure"),
    ("idor", "sensitive data", "leads_to", "data_exposure"),
    ("bola", "sensitive_data", "leads_to", "data_exposure"),
    ("ssrf", "internal", "enables", "internal_pivot"),
    ("ssrf", "cloud_metadata", "enables", "cloud_compromise"),
    ("ssrf", "metadata", "enables", "cloud_compromise"),
    ("lfi", "log_poisoning", "enables", "rce"),
    ("lfi", "source_code", "leads_to", "information_disclosure"),
    ("ssti", "rce", "leads_to", "rce"),
    ("ssti", "file_read", "leads_to", "information_disclosure"),
    ("jwt", "auth_bypass", "enables", "account_takeover"),
    ("jwt", "authorization", "enables", "privilege_escalation"),
    ("authorization", "idor", "enables", "data_exposure"),
    ("authorization", "bola", "enables", "data_exposure"),
    ("rate_limiting", "brute_force", "enables", "account_takeover"),
    ("subdomain_takeover", "xss", "enables", "account_takeover"),
    ("cors", "sensitive_data", "enables", "data_exposure"),
    ("cors", "sensitive data", "enables", "data_exposure"),
    ("api", "mass assignment", "leads_to", "privilege_escalation"),
    ("api", "bola", "leads_to", "data_exposure"),
]

CHAIN_WEAKNESSES: dict[str, list[str]] = {
    "Improper Input Sanitization": ["xss", "sqli", "ssti", "lfi", "command injection", "cmd_injection"],
    "Missing Authorization Check": ["idor", "authorization", "bola", "graphql auth bypass"],
    "Server-Side Request Validation Missing": ["ssrf"],
    "Excessive GraphQL Schema Exposure": ["graphql"],
    "Sensitive Information Exposure": ["sensitive_data", "exposed js secret"],
}

IMPACT_SCORE = {
    "account_takeover": 100,
    "rce": 100,
    "cloud_compromise": 95,
    "data_exposure": 80,
    "privilege_escalation": 85,
    "internal_pivot": 70,
    "information_disclosure": 50,
}


class AttackChainEngine:
    """Correlates individual findings into attack paths.

    Uses two strategies:
    1. Rule-based matching (known attack patterns from CHAIN_RULES)
    2. Root-cause based (findings sharing the same root cause form clusters)
    3. Asset-graph based (findings on related assets)
    """

    def __init__(self):
        self.chains: list[AttackChain] = []

    def analyze(self, findings: list[Finding], rdc_noise: bool = False, asset_graph: Any = None) -> list[AttackChain]:
        self.chains = []
        if len(findings) < 2:
            return self.chains

        nodes = self._build_nodes(findings)
        edges = self._find_edges(nodes, findings, asset_graph=asset_graph)
        chains = self._build_chains(nodes, edges, findings, rdc_noise=rdc_noise)
        self.chains = chains
        return chains

    def _build_nodes(self, findings: list[Finding]) -> dict[str, AttackNode]:
        nodes: dict[str, AttackNode] = {}
        for f in findings:
            fp = f.fingerprint or ""
            if not fp:
                continue
            evidence_fps = []
            for ev in (f.evidence or []):
                if hasattr(ev, "to_dict"):
                    import hashlib, json
                    d = ev.to_dict()
                    d.pop("timestamp", None)
                    evidence_fps.append(hashlib.sha256(json.dumps(d, sort_keys=True, default=str).encode()).hexdigest()[:16])
            node = AttackNode(
                finding_fingerprint=fp,
                vuln_type=f.vuln_type,
                root_cause=f.root_cause,
                confidence=float(f.confidence_score or 0),
                evidence_fingerprints=evidence_fps,
                url=f.url,
            )
            nodes[fp] = node
        return nodes

    def _find_edges(
        self, nodes: dict[str, AttackNode], findings: list[Finding],
        asset_graph: Any = None,
    ) -> list[AttackEdge]:
        edges: list[AttackEdge] = []
        fingerprints = list(nodes.keys())

        # ── Build URL-to-asset lookup if asset graph is available ──────
        url_to_parents: dict[str, list[str]] = {}
        if asset_graph is not None and hasattr(asset_graph, "edges") and hasattr(asset_graph, "nodes"):
            node_list = asset_graph.nodes.values() if isinstance(asset_graph.nodes, dict) else asset_graph.nodes
            node_by_id = {n.asset_id: n for n in node_list}
            for edge in asset_graph.edges:
                if hasattr(edge, "source_id") and hasattr(edge, "target_id") and edge.relationship == "contains":
                    src_node = node_by_id.get(edge.source_id)
                    tgt_node = node_by_id.get(edge.target_id)
                    if src_node and tgt_node:
                        url_to_parents.setdefault(tgt_node.url, []).append(src_node.url)

        for i in range(len(fingerprints)):
            for j in range(len(fingerprints)):
                if i == j:
                    continue
                src_fp = fingerprints[i]
                tgt_fp = fingerprints[j]
                src_node = nodes[src_fp]
                tgt_node = nodes[tgt_fp]

                # Same endpoint findings
                if src_node.url == tgt_node.url and src_node.finding_fingerprint != tgt_node.finding_fingerprint:
                    edges.append(AttackEdge(
                        source=src_fp,
                        target=tgt_fp,
                        relationship="same_endpoint",
                        confidence=min(src_node.confidence, tgt_node.confidence),
                        prerequisite="",
                    ))

                # Related asset findings (share a parent in the asset graph)
                if url_to_parents and src_node.url != tgt_node.url:
                    def _find_parents(url: str) -> list[str]:
                        exact = url_to_parents.get(url, [])
                        if exact:
                            return exact
                        for asset_url, parents in url_to_parents.items():
                            if url.startswith(asset_url) or asset_url.startswith(url):
                                return parents
                        return []
                    src_parents = _find_parents(src_node.url)
                    tgt_parents = _find_parents(tgt_node.url)
                    if src_parents and tgt_parents and any(p in tgt_parents for p in src_parents):
                        edges.append(AttackEdge(
                            source=src_fp,
                            target=tgt_fp,
                            relationship="related_asset",
                            confidence=min(src_node.confidence, tgt_node.confidence) * 0.7,
                            prerequisite="Same asset group",
                        ))

                for src_keyword, tgt_keyword, rel, impact in CHAIN_RULES:
                    src_match = src_keyword in src_node.vuln_type.lower()
                    tgt_match = tgt_keyword in tgt_node.vuln_type.lower()
                    if src_match and tgt_match:
                        edges.append(AttackEdge(
                            source=src_fp,
                            target=tgt_fp,
                            relationship=rel,
                            confidence=min(src_node.confidence, tgt_node.confidence) * 0.8,
                            prerequisite=f"{src_node.vuln_type} must be exploitable first",
                        ))

        return self._deduplicate_edges(edges)

    def _deduplicate_edges(self, edges: list[AttackEdge]) -> list[AttackEdge]:
        seen: set[tuple[str, str, str]] = set()
        unique: list[AttackEdge] = []
        for e in edges:
            key = (e.source, e.target, e.relationship)
            if key not in seen:
                seen.add(key)
                unique.append(e)
        return unique

    def _same_root_cause_chain(self, chain_nodes: list[AttackNode]) -> bool:
        root_causes = {n.root_cause for n in chain_nodes if n.root_cause}
        return len(root_causes) <= 1

    def _build_chains(
        self,
        nodes: dict[str, AttackNode],
        edges: list[AttackEdge],
        findings: list[Finding],
        rdc_noise: bool = False,
    ) -> list[AttackChain]:
        if not edges:
            return []

        adjacency: dict[str, list[AttackEdge]] = {}
        for e in edges:
            adjacency.setdefault(e.source, []).append(e)

        chains: list[AttackChain] = []
        visited: set[str] = set()

        for start_fp in nodes:
            if start_fp in visited:
                continue
            if start_fp not in adjacency:
                continue

            chain_edges: list[AttackEdge] = []
            chain_fps: list[str] = [start_fp]
            current = start_fp

            while current in adjacency:
                next_edges = adjacency[current]
                best = max(next_edges, key=lambda e: e.confidence)
                if best.target in chain_fps:
                    break
                chain_edges.append(best)
                chain_fps.append(best.target)
                visited.add(best.target)
                current = best.target

                if len(chain_fps) > 10:
                    break

            if len(chain_edges) >= 1:
                chain_nodes = [nodes[fp] for fp in chain_fps if fp in nodes]
                if rdc_noise and self._same_root_cause_chain(chain_nodes):
                    continue
                final_impact = self._determine_final_impact(chain_edges)
                overall_conf = sum(e.confidence for e in chain_edges) / len(chain_edges) if chain_edges else 0
                chain_fp = hashlib.sha256(
                    "_".join(chain_fps).encode()
                ).hexdigest()[:16]

                chain = AttackChain(
                    nodes=chain_nodes,
                    edges=chain_edges,
                    entry_point=nodes[chain_fps[0]].vuln_type if chain_fps else "",
                    final_impact=final_impact,
                    overall_confidence=overall_conf,
                    chain_fingerprint=chain_fp,
                    description=self._build_description(chain_nodes, chain_edges, final_impact),
                )
                chains.append(chain)

        chains.sort(key=lambda c: c.overall_confidence, reverse=True)
        return chains[:5]

    def _determine_final_impact(self, edges: list[AttackEdge]) -> str:
        for e in reversed(edges):
            for src_keyword, tgt_keyword, rel, impact in CHAIN_RULES:
                if rel == e.relationship:
                    candidate_impact = impact
                    if candidate_impact in IMPACT_SCORE:
                        return candidate_impact
        return "information_disclosure"

    def _build_description(
        self, nodes: list[AttackNode], edges: list[AttackEdge], final_impact: str
    ) -> str:
        parts = []
        for i, edge in enumerate(edges):
            src_node = next((n for n in nodes if n.finding_fingerprint == edge.source), None)
            tgt_node = next((n for n in nodes if n.finding_fingerprint == edge.target), None)
            if src_node and tgt_node:
                parts.append(f"{src_node.vuln_type} → {tgt_node.vuln_type}")
        if final_impact:
            parts.append(f"= {final_impact.replace('_', ' ').title()}")
        return " → ".join(parts)

    @classmethod
    def annotate_findings(
        cls, findings: list[Finding], chains: list[AttackChain]
    ) -> list[Finding]:
        chain_by_fp: dict[str, list[AttackChain]] = {}
        for chain in chains:
            for node in chain.nodes:
                chain_by_fp.setdefault(node.finding_fingerprint, []).append(chain)

        for f in findings:
            fp = f.fingerprint
            if fp in chain_by_fp:
                related_chains = chain_by_fp[fp]
                chain_info = []
                for c in related_chains:
                    chain_info.append(c.to_dict())
                object.__setattr__(f, "chains", chain_info)
                object.__setattr__(f, "chain_impact", related_chains[0].final_impact if related_chains else "")
        return findings

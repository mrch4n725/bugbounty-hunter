"""Multi-Account Discovery Engine — cross-account replay and role hierarchy discovery.

Coordinates multiple account sessions to systematically test for authorization
violations by replaying requests across accounts and comparing responses.
"""

from typing import Any

from modules.utils import safe_get, log, Colors
from engines.authorization import AuthorizationEngine
from engines.relationship_graph import RelationshipGraph


class MultiAccountDiscoveryEngine:
    """Coordinate multiple account sessions for cross-account authorization testing.

    Discovers candidate endpoints from recon_data and RelationshipGraph, then
    replays each request across every pair of configured roles, rotating which
    role is the "owner" and which is the "attacker" to exhaustively find
    horizontal and vertical privilege escalation.
    """

    def __init__(self, config: dict, role_sessions: dict,
                 validation_engine=None, evidence_engine=None):
        self.config = config
        self.role_sessions = role_sessions
        self.validation = validation_engine
        self.evidence_engine = evidence_engine
        self.timeout = config.get("timeout", 10)
        self.verbose = config.get("verbose", False)

    def discover_candidates(self, recon_data: dict,
                            store=None) -> list[dict]:
        """Collect candidate URLs from recon_data and RelationshipGraph.

        Returns a deduplicated list of {url, source} dicts.
        """
        seen: set[str] = set()
        candidates: list[dict] = []

        # From recon URLs
        for url in recon_data.get("urls", []):
            if url not in seen:
                seen.add(url)
                candidates.append({"url": url, "source": "recon"})

        # From RelationshipGraph via DiscoveryStore
        if store is not None:
            try:
                graph = RelationshipGraph(store)
                auth_candidates = graph.get_auth_candidates()
                for c in auth_candidates:
                    c_url = c.get("url", "")
                    if c_url and c_url not in seen:
                        seen.add(c_url)
                        candidates.append({
                            "url": c_url,
                            "source": "relationship_graph",
                            "id_value": c.get("id_value", ""),
                            "id_type": c.get("id_type", ""),
                        })
            except Exception as e:
                log(f"  [MultiAcct] RelationshipGraph error: {e}", Colors.YELLOW,
                    verbose_only=True, verbose=self.verbose)

        return candidates

    def run_cross_account_scan(self, recon_data: dict,
                               store=None) -> list[dict]:
        """Run cross-account replays on all discovered candidates.

        For each candidate, tests every role pair (A, B) where A != B,
        comparing the responses. Discrepancies indicate authorization issues.
        """
        findings: list[dict] = []
        candidates = self.discover_candidates(recon_data, store)

        if len(self.role_sessions) < 2:
            log("[*] MultiAccountDiscovery needs >= 2 roles", Colors.YELLOW,
                verbose_only=True, verbose=self.verbose)
            return findings

        engine = AuthorizationEngine(
            config=self.config,
            role_sessions=self.role_sessions,
            validation_engine=self.validation,
            evidence_engine=self.evidence_engine,
        )

        # Horizontal: test all same-level role pairs
        for c in candidates:
            url = c["url"]
            role_names = list(self.role_sessions.keys())
            for i, role_a in enumerate(role_names):
                for role_b in role_names[i + 1:]:
                    try:
                        level_a = engine._role_level(role_a)
                        level_b = engine._role_level(role_b)
                        result = None
                        if level_a == level_b:
                            result = engine.test_endpoint(
                                url, role_a, role_b, method="GET",
                            )
                        if result:
                            f = engine._build_finding(
                                result, url, c.get("id_value", ""),
                                "GET", {},
                            )
                            if f:
                                findings.append(f)
                                log(f"  [MultiAcct] Horizontal: {role_a}→{role_b} @ {url[:60]}",
                                    Colors.RED, verbose_only=True, verbose=self.verbose)
                    except Exception as e:
                        log(f"  [MultiAcct] Error {url}: {e}", Colors.YELLOW,
                            verbose_only=True, verbose=self.verbose)

        # Vertical: test across different levels
        for c in candidates:
            url = c["url"]
            role_names = list(self.role_sessions.keys())
            for i, role_a in enumerate(role_names):
                for role_b in role_names[i + 1:]:
                    try:
                        level_a = engine._role_level(role_a)
                        level_b = engine._role_level(role_b)
                        if level_a != level_b:
                            # Test both directions
                            result = engine.test_endpoint(
                                url, role_a, role_b, method="GET",
                            )
                            if result:
                                f = engine._build_finding(
                                    result, url, c.get("id_value", ""),
                                    "GET", {},
                                )
                                if f:
                                    findings.append(f)
                    except Exception:
                        pass

        return findings

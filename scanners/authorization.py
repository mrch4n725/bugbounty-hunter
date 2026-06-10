"""
AuthorizationScanner — ScannerBase adapter for AuthorizationEngine.

Lifecycle:
  Wraps engines.authorization.AuthorizationEngine to prove
  authorization failures with evidence-driven role comparison.

Maturity: Level 4 (Verified — produces VERIFIED evidence via ownership comparison)
"""

from typing import Any

from models.finding import Finding
from scanners.base import ScannerBase
from engines.authorization import AuthorizationEngine
from engines.relationship_graph import RelationshipGraph
from modules.utils import log, Colors, build_role_sessions, safe_get


class AuthorizationScanner(ScannerBase):
    """Proves authorization failures via role-based access comparison.

    Tests discovered URLs against all configured role sessions,
    detecting horizontal (same-level) and vertical (cross-level)
    authorization failures with VERIFIED evidence.

    Integrates with RelationshipGraph (from DiscoveryStore) to identify
    ownership-boundary candidates, and tests GQL mutation endpoints
    discovered during recon.
    """

    SCANNER_NAME = "authorization"
    SCANNER_MATURITY = 4
    TARGET_LEVEL = True

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._engine = None

    def _collect_urls(self) -> list[str]:
        """Collect all URLs for authorization testing, including GQL endpoints."""
        urls = list(self.recon.get("urls", []))

        # Include GQL mutation endpoints from recon
        for url in urls:
            if "/graphql" in url or "/gql" in url.lower():
                if url not in urls:
                    urls.append(url)

        # Include auth candidates from RelationshipGraph via DiscoveryStore
        if self.container and hasattr(self.container, 'discovery_store'):
            try:
                graph = RelationshipGraph(self.container.discovery_store)
                candidates = graph.get_auth_candidates()
                for c in candidates:
                    c_url = c.get("url", "")
                    if c_url and c_url not in urls:
                        urls.append(c_url)
                        log(f"  [Authz::Graph] {c_url} (via {c.get('id_type', 'unknown')} {c.get('id_value', '')[:20]})",
                            Colors.CYAN, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [Authz] RelationshipGraph error: {e}", Colors.YELLOW,
                    verbose_only=True, verbose=self.verbose)

        # Probe minimal GQL mutation test on any graphql endpoint
        gql_urls = [u for u in urls if "/graphql" in u.lower() or u.endswith("/gql")]
        for gql_url in gql_urls:
            test_mutation = {"query": "mutation { __typename }"}
            try:
                resp = safe_get(self.session, gql_url, self.timeout, raise_for_status=False)
                if resp and resp.status_code == 200 and "__typename" in (resp.text or ""):
                    continue
                resp = self.session.post(gql_url, json=test_mutation, timeout=self.timeout)
                if resp.status_code == 200 and "__typename" in (resp.text or ""):
                    urls.append(gql_url)
            except Exception:
                pass

        return urls

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        """Run authorization scans across all discovered URLs and GQL endpoints.

        Discovers auth-relevant URLs from recon data and RelationshipGraph,
        then tests each with every pair of configured roles.
        """
        urls = self._collect_urls()
        if not urls:
            urls = [self.base_url] if self.base_url else []

        role_sessions = build_role_sessions(self.config, self.session)
        if len(role_sessions) < 2:
            if self.verbose:
                log("[*] AuthorizationScanner needs >= 2 roles (use --auth-header)",
                    Colors.YELLOW)
            return []

        self._engine = AuthorizationEngine(
            config=self.config,
            role_sessions=role_sessions,
            validation_engine=self.validation,
            evidence_engine=self.evidence_engine,
        )

        findings = self._engine.run_scans(urls)
        for f in findings:
            self._enrich_finding(f, 0, f.get("verification_stage", "detected"))
            self._add_finding(f)
        return self._get_findings()

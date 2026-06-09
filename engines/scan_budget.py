import re
from typing import Any
from urllib.parse import urlparse

from models.budget import TargetValueScore, ScanBudget


ADMIN_PATHS = re.compile(r'/admin|/dashboard|/manage|/console|/wp-admin', re.IGNORECASE)
API_PATHS = re.compile(r'/api/|/rest/|/v\d+/', re.IGNORECASE)
GRAPHQL_PATHS = re.compile(r'/graphql|/gql|/query', re.IGNORECASE)
AUTH_PATHS = re.compile(r'/auth|/login|/oauth|/token|/authorize', re.IGNORECASE)
SENSITIVE_PATHS = re.compile(r'/\.env|/\.git|/config|/backup|/dump', re.IGNORECASE)
UPLOAD_PATHS = re.compile(r'/upload|/import|/export|/download', re.IGNORECASE)


class ScanBudgetEngine:
    """Computes per-URL resource allocation based on target value.

    Allocates more requests/attention to high-value targets:
    - Authenticated endpoints
    - GraphQL endpoints
    - Admin panels
    - Sensitive APIs
    - URLs with historical findings
    - URLs with params (more attack surface)
    """

    BASE_BUDGET = 3
    MAX_BUDGET = 15
    MIN_BUDGET = 1

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.total_urls = 0
        self.scores: list[TargetValueScore] = []

    def compute_scores(
        self,
        urls: list[str],
        historical_data: dict[str, int] | None = None,
        capabilities: dict[str, bool] | None = None,
        asset_graph: Any = None,
    ) -> list[TargetValueScore]:
        self.total_urls = len(urls)
        scores = []
        for url in urls:
            score, factors = self._score_url(url, historical_data, capabilities=capabilities, asset_graph=asset_graph)
            budget = self._compute_budget(score)
            scores.append(TargetValueScore(
                url=url,
                score=score,
                factors=factors,
                allocated_budget=budget,
            ))
        scores.sort(key=lambda s: -s.score)
        self.scores = scores
        return scores

    def build_budget(
        self,
        urls: list[str],
        total_request_capacity: int = 5000,
        historical_data: dict[str, int] | None = None,
        capabilities: dict[str, bool] | None = None,
        asset_graph: Any = None,
    ) -> ScanBudget:
        scores = self.compute_scores(urls, historical_data, capabilities=capabilities, asset_graph=asset_graph)
        allocation: dict[str, int] = {}
        total_allocated = 0

        for s in scores:
            proportional = max(
                self.MIN_BUDGET,
                int(total_request_capacity * (s.score / max(sum(sc.score for sc in scores), 1))),
            )
            capped = min(self.MAX_BUDGET, proportional)
            allocation[s.url] = capped
            total_allocated += capped

        return ScanBudget(
            total_requests=total_allocated,
            remaining=total_allocated,
            allocation=allocation,
            system_load=self._estimate_load(),
        )

    def sorted_urls(self) -> list[str]:
        return [s.url for s in sorted(self.scores, key=lambda s: -s.allocated_budget)]

    def get_budget(self, url: str) -> int:
        for s in self.scores:
            if s.url == url:
                return s.allocated_budget
        return self.BASE_BUDGET

    def _score_url(
        self, url: str, historical_data: dict[str, int] | None = None,
        capabilities: dict[str, bool] | None = None,
        asset_graph: Any = None,
    ) -> tuple[int, dict[str, float]]:
        parsed = urlparse(url)
        path = parsed.path
        query = parsed.query
        factors: dict[str, float] = {}
        score = 0

        if query:
            n_params = len(query.split("&"))
            factors["has_params"] = min(1.0, n_params / 10)
            score += int(20 * factors["has_params"])

        if ADMIN_PATHS.search(path):
            factors["is_admin"] = 1.0
            score += 25

        if API_PATHS.search(path):
            factors["is_api"] = 1.0
            score += 20

        if GRAPHQL_PATHS.search(path):
            factors["is_graphql"] = 1.0
            score += 30

        if AUTH_PATHS.search(path):
            factors["is_auth"] = 1.0
            score += 20

        if SENSITIVE_PATHS.search(path):
            factors["is_sensitive"] = 1.0
            score += 15

        if UPLOAD_PATHS.search(path):
            factors["is_upload"] = 1.0
            score += 10

        # Asset graph boost — known high-value asset types
        if asset_graph is not None and hasattr(asset_graph, "nodes"):
            node_list = asset_graph.nodes.values() if isinstance(asset_graph.nodes, dict) else asset_graph.nodes
            for node in node_list:
                if hasattr(node, "url"):
                    if node.url == url or url.startswith(node.url):
                        if node.asset_type in ("graphql", "admin_panel", "auth_service"):
                            factors["asset_graph_high_value"] = 1.0
                            score += 25
                        elif node.asset_type in ("api_endpoint",):
                            factors["asset_graph_api"] = 1.0
                            score += 15
                        break

        # Capability awareness — adjust based on available testing capabilities
        if capabilities:
            if capabilities.get("oob", False):
                factors["oob_available"] = 1.0
                score += 10
            if capabilities.get("playwright", False) or capabilities.get("chromium", False):
                factors["browser_available"] = 1.0
                score += 5

        # Validation-success tracking (from historical data)
        if historical_data:
            prev = historical_data.get(url, 0)
            if prev > 0:
                factors["historical_findings"] = min(1.0, prev / 5)
                score += int(15 * factors["historical_findings"])

        path_depth = len([p for p in path.split("/") if p])
        factors["depth"] = min(1.0, path_depth / 5)
        score += int(10 * factors["depth"])

        score = min(100, max(0, score))
        return score, factors

    def _compute_budget(self, score: int) -> int:
        if score >= 80:
            return self.MAX_BUDGET
        if score >= 60:
            return 10
        if score >= 40:
            return 6
        if score >= 20:
            return 3
        return self.MIN_BUDGET

    def _estimate_load(self) -> float:
        import os
        factors = []
        try:
            import psutil
            factors.append(psutil.cpu_percent(interval=0.1) / 100.0)
            mem = psutil.virtual_memory()
            factors.append(mem.percent / 100.0)
            return min(1.0, sum(factors) / len(factors))
        except ImportError:
            try:
                load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0
                factors.append(min(1.0, load / (os.cpu_count() or 1)))
            except (AttributeError, OSError):
                factors.append(0.3)
            try:
                import subprocess
                result = subprocess.run(["free", "-m"], capture_output=True, text=True, timeout=2)
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 3:
                        total, used = int(parts[1]), int(parts[2])
                        if total > 0:
                            factors.append(min(1.0, used / total))
            except Exception:
                factors.append(0.3)
            return min(1.0, sum(factors) / len(factors))

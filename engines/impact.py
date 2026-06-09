from typing import Any
from models.finding import Finding
from models.evidence import EvidenceType
from models.impact import ImpactFactors, ImpactAssessment
from engines.evidence_quality import EvidenceQualityEngine
from engines.root_cause import ROOT_CAUSE_MAP
from modules.utils import classify_endpoint


SENSITIVITY_MAP: dict[str, str] = {
    "pii": "pii",
    "ssn": "pii",
    "credit": "financial",
    "card": "financial",
    "payment": "financial",
    "password": "credentials",
    "secret": "credentials",
    "key": "credentials",
    "token": "credentials",
    "auth": "credentials",
    "email": "pii",
    "address": "pii",
    "phone": "pii",
    "health": "pii",
    "medical": "pii",
}

BUSINESS_CONTEXT_MAP: dict[str, str] = {
    "auth": "authentication",
    "login": "authentication",
    "oauth": "authentication",
    "payment": "payment",
    "checkout": "payment",
    "admin": "admin_panel",
    "dashboard": "admin_panel",
    "api": "api_endpoint",
    "graphql": "graphql_endpoint",
    "storage": "storage",
    "upload": "storage",
    "download": "storage",
}

DATA_SENSITIVITY_ORDER = {"public": 0, "internal": 1, "pii": 2, "financial": 3, "credentials": 4}


class ImpactEngine:
    """Context-aware impact assessment engine.

    Estimates severity based on:
    - Data sensitivity (what the endpoint handles)
    - Authentication state (does the finding bypass auth)
    - Privilege level (anonymous vs user vs admin)
    - Asset importance (what kind of asset is affected)
    - Exploitability (how hard is it to exploit)
    - Validation quality (evidence strength)
    - Attack chain position (is this part of a larger chain)
    - Business context (payment, auth, admin, etc.)
    """

    @classmethod
    def assess(cls, finding: Finding, asset_graph: Any = None) -> ImpactAssessment:
        factors = cls._collect_factors(finding, asset_graph=asset_graph)
        score = cls._compute_score(factors)
        overall = cls._score_to_level(score)
        narrative = cls._build_narrative(finding, factors, overall)
        likelihood = cls._estimate_acceptance_likelihood(factors, overall)

        return ImpactAssessment(
            overall=overall,
            score=score,
            factors=factors,
            narrative=narrative,
            acceptance_likelihood=likelihood,
        )

    @classmethod
    def _collect_factors(cls, finding: Finding, asset_graph: Any = None) -> ImpactFactors:
        url_lower = (finding.url or "").lower()
        vuln_lower = (finding.vuln_type or "").lower()
        title_lower = (finding.title or "").lower()

        data_sensitivity = "public"
        for keyword, sensitivity in SENSITIVITY_MAP.items():
            if keyword in url_lower or keyword in vuln_lower or keyword in title_lower:
                data_sensitivity = sensitivity
                break

        business_context = ""
        for keyword, ctx in BUSINESS_CONTEXT_MAP.items():
            if keyword in url_lower or keyword in vuln_lower:
                business_context = ctx
                break

        auth_required = bool(finding.request or finding.validation_signals)

        privilege = "anonymous"
        if any(role in url_lower for role in ("admin", "dashboard", "manage", "administrator")):
            privilege = "admin"
        elif auth_required:
            privilege = "user"

        asset_importance = cls._assess_asset_importance(finding, url_lower, asset_graph=asset_graph)

        exploitability = cls._assess_exploitability(finding)

        evidence_scores = EvidenceQualityEngine.assess_finding_evidence(finding)
        validation_quality = EvidenceQualityEngine.aggregate_strength(evidence_scores)

        chain_pos = 0
        if hasattr(finding, "chains") and getattr(finding, "chains"):
            chain_pos = len(getattr(finding, "chains"))

        return ImpactFactors(
            data_sensitivity=data_sensitivity,
            authentication_required=auth_required,
            privilege_level=privilege,
            asset_importance=asset_importance,
            exploitability=exploitability,
            validation_quality=validation_quality,
            attack_chain_position=chain_pos,
            business_context=business_context,
        )

    @classmethod
    def _assess_asset_importance(cls, finding: Finding, url_lower: str, asset_graph: Any = None) -> str:
        if any(p in url_lower for p in ("/admin", "/dashboard", "/api/admin", "/graphql", "/payment")):
            return "critical"
        if any(p in url_lower for p in ("/api/", "/auth", "/oauth", "/token")):
            return "high"
        if any(p in url_lower for p in ("/v1/", "/v2/", "/rest/")):
            return "medium"
        if asset_graph is not None and hasattr(asset_graph, "nodes"):
            node_list = asset_graph.nodes.values() if isinstance(asset_graph.nodes, dict) else asset_graph.nodes
            for node in node_list:
                if hasattr(node, "url"):
                    if node.url == finding.url or (finding.url or "").startswith(node.url):
                        if node.asset_type in ("graphql", "admin_panel", "auth_service"):
                            return "critical"
                        if node.asset_type == "api_endpoint":
                            return "high"
        return "low"

    @classmethod
    def _assess_exploitability(cls, finding: Finding) -> str:
        score = finding.confidence_score or 0
        stage = (finding.verification_stage or "").lower()
        if stage in ("verified", "exploitable") and score >= 86:
            return "high"
        if stage in ("validated",) and score >= 61:
            return "medium"
        if stage in ("detected", "partially_validated"):
            return "low"
        return "none"

    @classmethod
    def _compute_score(cls, factors: ImpactFactors) -> int:
        score = 0

        sensitivity_score = DATA_SENSITIVITY_ORDER.get(factors.data_sensitivity, 0)
        score += sensitivity_score * 10

        importance_scores = {"low": 0, "medium": 5, "high": 10, "critical": 20}
        score += importance_scores.get(factors.asset_importance, 0)

        exploit_scores = {"none": 0, "low": 5, "medium": 10, "high": 20}
        score += exploit_scores.get(factors.exploitability, 0)

        quality_scores = {"weak": 0, "medium": 5, "strong": 10, "very_strong": 15}
        score += quality_scores.get(factors.validation_quality, 0)

        if factors.authentication_required:
            score += 5

        if factors.privilege_level == "admin":
            score += 10

        score += factors.attack_chain_position * 5

        return min(100, score)

    @classmethod
    def _score_to_level(cls, score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "informational"

    @classmethod
    def _build_narrative(cls, finding: Finding, factors: ImpactFactors, level: str) -> str:
        parts = []
        parts.append(f"Data sensitivity: {factors.data_sensitivity}")
        parts.append(f"Authentication: {'required' if factors.authentication_required else 'not required'}")
        parts.append(f"Privilege context: {factors.privilege_level}")
        parts.append(f"Asset importance: {factors.asset_importance}")
        parts.append(f"Exploitability: {factors.exploitability}")
        parts.append(f"Validation quality: {factors.validation_quality}")
        if factors.business_context:
            parts.append(f"Business context: {factors.business_context}")
        if factors.attack_chain_position > 0:
            parts.append(f"Chain position: {factors.attack_chain_position}")
        verdict = f"Impact: {level.upper()}"
        return f"{' | '.join(parts)} | {verdict}"

    @classmethod
    def _estimate_acceptance_likelihood(cls, factors: ImpactFactors, level: str) -> str:
        if level in ("critical", "high") and factors.validation_quality in ("strong", "very_strong"):
            return "high"
        if level == "critical" and factors.validation_quality == "weak":
            return "medium"
        if level in ("medium", "low"):
            return "low"
        return "medium"

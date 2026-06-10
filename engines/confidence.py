from typing import Any

from models.finding import Finding, ConfidenceLevel
from models.evidence import EvidenceBase, EvidenceStatus, EvidenceType
from models.confidence import (
    ConfidenceContribution, ConfidenceFactors, ConfidenceResult,
)
from engines.evidence_quality import EvidenceQualityEngine
from engines.consensus_engine import ConsensusResult


class ConfidenceEngine:
    """Unified, explainable confidence scoring engine.

    Aggregates all confidence signals into a single score:

    - Detection signal (base)
    - Evidence quality (typed evidence strength)
    - Ownership proof (authz comparison results)
    - Impact proof (exploitation demonstration)
    - Investigation depth (additional validation steps)
    - Consensus support (validator agreement)
    - Evidence penalties (missing required evidence)

    Every delta is explainable and recorded in confidence_reasons.
    """

    @classmethod
    def evaluate(cls, finding: Finding, consensus_result: ConsensusResult | None = None) -> ConfidenceResult:
        contributions: list[ConfidenceContribution] = []
        factors = ConfidenceFactors()

        current_score = finding.confidence_score if finding.confidence_score is not None else 25
        factors.base_score = current_score

        evidence = finding.evidence or []
        if isinstance(evidence, str):
            evidence = [evidence] if evidence else []

        quality_scores = EvidenceQualityEngine.assess_finding_evidence(finding)
        quality_contrib = EvidenceQualityEngine.confidence_contribution(quality_scores)
        if quality_contrib > 0:
            factors.evidence_quality = quality_contrib
            reasons = EvidenceQualityEngine.quality_reasons(quality_scores)
            contributions.append(ConfidenceContribution(
                source="evidence_quality",
                delta=quality_contrib,
                reason=reasons[0] if reasons else f"Evidence quality contribution: +{quality_contrib}",
            ))

        comprehensive = EvidenceQualityEngine.comprehensive_assessment(finding)
        object.__setattr__(finding, "_quality_assessment", comprehensive)
        if comprehensive.overall == "very_strong":
            contributions.append(ConfidenceContribution(
                source="comprehensive_quality",
                delta=5,
                reason="Comprehensive quality assessment: Very Strong across all dimensions",
            ))
            factors.evidence_quality = min(100, factors.evidence_quality + 5)

        ownership_boost = cls._compute_ownership_boost(finding, evidence)
        if ownership_boost > 0:
            factors.ownership_proof = ownership_boost
            contributions.append(ConfidenceContribution(
                source="ownership_proof",
                delta=ownership_boost,
                reason=f"Ownership proof adds +{ownership_boost}",
            ))

        impact_boost = cls._compute_impact_boost(finding, evidence)
        if impact_boost > 0:
            factors.impact_proof = impact_boost
            contributions.append(ConfidenceContribution(
                source="impact_proof",
                delta=impact_boost,
                reason=f"Impact demonstrated adds +{impact_boost}",
            ))

        investigation_boost = cls._compute_investigation_boost(finding)
        if investigation_boost > 0:
            factors.investigation_depth = investigation_boost
            contributions.append(ConfidenceContribution(
                source="investigation_depth",
                delta=investigation_boost,
                reason=f"Investigation validates with +{investigation_boost}",
            ))

        if consensus_result is not None:
            consensus_boost = cls._compute_consensus_boost(consensus_result)
            consensus_penalty = cls._compute_consensus_penalty(consensus_result)
            if consensus_boost > 0:
                factors.consensus_support = consensus_boost
                contributions.append(ConfidenceContribution(
                    source="consensus_support",
                    delta=consensus_boost,
                    reason=f"Validator consensus supports +{consensus_boost}",
                ))
            if consensus_penalty > 0:
                factors.consensus_penalty = consensus_penalty
                contributions.append(ConfidenceContribution(
                    source="consensus_penalty",
                    delta=-consensus_penalty,
                    reason=f"Validator consensus penalizes -{consensus_penalty}",
                ))

        evidence_penalty = cls._compute_evidence_penalty(finding)
        if evidence_penalty > 0:
            factors.evidence_penalty = evidence_penalty
            contributions.append(ConfidenceContribution(
                source="evidence_penalty",
                delta=-evidence_penalty,
                reason=f"Evidence incomplete penalty: -{evidence_penalty}",
            ))

        total_delta = sum(c.delta for c in contributions)
        final_score = max(0, min(100, current_score + total_delta))

        return ConfidenceResult(
            final_score=final_score,
            contributions=contributions,
            factors=factors,
        )

    @classmethod
    def apply(cls, finding: Finding, result: ConfidenceResult) -> Finding:
        object.__setattr__(finding, "confidence_score", result.final_score)
        object.__setattr__(finding, "confidence_label", ConfidenceLevel.from_score(result.final_score).value)

        from models.finding import evidence_strength_from_score, false_positive_risk_from_score
        object.__setattr__(finding, "evidence_strength", evidence_strength_from_score(result.final_score).value)
        object.__setattr__(finding, "false_positive_risk", false_positive_risk_from_score(result.final_score).value)

        current_reasons = list(getattr(finding, "confidence_reasons", []) or [])
        for c in result.contributions:
            reason = f"{c.delta:+d} via {c.source}: {c.reason}"
            if reason not in current_reasons:
                current_reasons.append(reason)

        object.__setattr__(finding, "confidence_reasons", current_reasons)
        object.__setattr__(finding, "_confidence_result", result)

        from models.finding import guard_confidence_invariants
        guard_confidence_invariants(finding)

        return finding

    @classmethod
    def evaluate_all(cls, findings: list[Finding],
                     consensus_results: dict[str, ConsensusResult] | None = None) -> list[Finding]:
        for f in findings:
            fp = f.fingerprint
            consensus = None
            if consensus_results and fp in consensus_results:
                consensus = consensus_results[fp]
            result = cls.evaluate(f, consensus_result=consensus)
            cls.apply(f, result)
        return findings

    @classmethod
    def _compute_ownership_boost(cls, finding: Finding, evidence: list) -> int:
        from engines.ownership_validator import OwnershipValidator
        return OwnershipValidator.calculate_confidence_boost(finding)

    @classmethod
    def _compute_impact_boost(cls, finding: Finding, evidence: list) -> int:
        from engines.impact_validator import ImpactValidator
        return ImpactValidator.calculate_confidence_boost(finding)

    @classmethod
    def _compute_investigation_boost(cls, finding: Finding) -> int:
        boost = 0
        reasons = getattr(finding, "confidence_reasons", []) or []
        for r in reasons:
            if "via investigation:" in r:
                try:
                    prefix = r.split(" ")[0]
                    delta = int(prefix)
                    if delta > 0:
                        boost += delta
                except (ValueError, IndexError):
                    pass
        return min(boost, 30)

    @classmethod
    def _compute_consensus_boost(cls, consensus: ConsensusResult) -> int:
        if consensus.consensus_level == "strong":
            return 10
        if consensus.consensus_level == "moderate":
            return 5
        return 0

    @classmethod
    def _compute_consensus_penalty(cls, consensus: ConsensusResult) -> int:
        if consensus.consensus_level == "weak":
            if consensus.final_score < 50:
                return 10
            return 5
        return 0

    @classmethod
    def _compute_evidence_penalty(cls, finding: Finding) -> int:
        from engines.evidence_validator import EvidenceCompletenessValidator as ECV
        penalty = getattr(finding, "_confidence_validator_penalty", 0)
        return penalty

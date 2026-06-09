from models.finding import Finding, FindingState, ConfidenceLevel, calculate_confidence
from engines.evidence_quality import EvidenceQualityEngine
from engines.evidence_validator import EvidenceCompletenessValidator


class FindingPromotionEngine:
    """Manages automatic finding promotion through the pipeline.

    Stages:
    SIGNAL → POTENTIAL → VALIDATED → VERIFIED → SUBMISSION_READY

    Promotion criteria:
    - SIGNAL: Initial detection (any signal)
    - POTENTIAL: Some evidence attached, confidence >= 25
    - VALIDATED: Evidence completeness checkpoint passes
    - VERIFIED: Multiple strong evidence items, confidence >= 61
    - SUBMISSION_READY: Impact assessed, all evidence collected, confidence >= 86
    """

    @classmethod
    def promote(cls, finding: Finding) -> Finding:
        current = FindingState(finding.finding_state or "signal")

        desired = cls._compute_desired_state(finding)

        if cls._should_promote(current, desired):
            object.__setattr__(finding, "finding_state", desired.value)
            object.__setattr__(finding, "verification_stage", cls._state_to_stage(desired))
            cls._add_promotion_reason(finding, current, desired)

        return finding

    @classmethod
    def promote_all(cls, findings: list[Finding]) -> list[Finding]:
        return [cls.promote(f) for f in findings]

    @classmethod
    def _compute_desired_state(cls, finding: Finding) -> FindingState:
        score = finding.confidence_score or 0
        stage = (finding.verification_stage or "").lower()

        if stage in ("verified", "exploitable") and score >= 86:
            return FindingState.SUBMISSION_READY

        if score >= 86:
            return FindingState.SUBMISSION_READY

        quality_scores = EvidenceQualityEngine.assess_finding_evidence(finding)
        agg_strength = EvidenceQualityEngine.aggregate_strength(quality_scores)
        n_evidence = len(quality_scores)

        if score >= 61 and agg_strength in ("strong", "very_strong") and n_evidence >= 2:
            return FindingState.VERIFIED

        try:
            validated = EvidenceCompletenessValidator.validate(finding)
            validated_ok = not any(
                "evidence incomplete" in r for r in (validated.confidence_reasons or [])
            )
        except Exception:
            validated_ok = False

        if validated_ok and score >= 31:
            return FindingState.VALIDATED

        if score >= 25 and n_evidence >= 1:
            return FindingState.POTENTIAL

        return FindingState.SIGNAL

    @classmethod
    def _should_promote(cls, current: FindingState, desired: FindingState) -> bool:
        order = ["signal", "potential", "validated", "verified", "submission_ready"]
        try:
            return order.index(desired.value) > order.index(current.value)
        except ValueError:
            return False

    @classmethod
    def _state_to_stage(cls, state: FindingState) -> str:
        mapping = {
            FindingState.SIGNAL: "detected",
            FindingState.POTENTIAL: "partially_validated",
            FindingState.VALIDATED: "validated",
            FindingState.VERIFIED: "exploitable",
            FindingState.SUBMISSION_READY: "verified",
        }
        return mapping.get(state, "detected")

    @classmethod
    def _add_promotion_reason(
        cls, finding: Finding, old: FindingState, new: FindingState
    ) -> None:
        reason = f"Promoted: {old.value} → {new.value}"
        if not hasattr(finding, "confidence_reasons") or not isinstance(finding.confidence_reasons, list):
            object.__setattr__(finding, "confidence_reasons", [])
        if reason not in finding.confidence_reasons:
            finding.confidence_reasons.append(reason)

    @classmethod
    def pipeline_stage_counts(cls, findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {
            "signal": 0, "potential": 0, "validated": 0,
            "verified": 0, "submission_ready": 0,
        }
        for f in findings:
            state = getattr(f, "finding_state", None) or "signal"
            if state in counts:
                counts[state] += 1
        return counts

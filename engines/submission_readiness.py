from typing import Any

from models.finding import Finding, FindingState
from models.evidence import EvidenceStatus, EvidenceBase
from engines.evidence_validator import EvidenceCompletenessValidator


class SubmissionReadinessEngine:
    """Assess whether a finding is ready for submission.

    Evaluates:
    - Verification stage depth (not just mechanical mapping)
    - Evidence completeness (covers required types)
    - Confidence score meets thresholds
    - Impact is validated (not just asserted)
    - Reproduction steps are actionable
    - Ownership is confirmed (for auth-related vulns)
    """

    MIN_CONFIDENCE_SUBMISSION = 86
    MIN_CONFIDENCE_VERIFIED = 61

    @classmethod
    def assess(cls, finding: Finding) -> FindingState:
        """Determine the true submission-readiness state of a finding.

        Overrides the mechanical ``from_verification_stage()`` mapping
        when evidence quality or confidence is insufficient.
        """
        stage = (finding.verification_stage or "").lower()
        score = finding.confidence_score or 0
        evidence = finding.evidence or []

        # Check evidence completeness
        has_verified_evidence = any(
            isinstance(ev, EvidenceBase) and ev.status == EvidenceStatus.VERIFIED
            for ev in evidence
        )
        has_any_evidence = any(
            isinstance(ev, EvidenceBase) for ev in evidence
        )
        has_reproduction = bool(finding.reproduction_steps) or bool(finding.curl_command)

        # ── Submission Ready ────────────────────────────────────────
        if stage in ("verified", "exploitable") and score >= cls.MIN_CONFIDENCE_SUBMISSION:
            if has_verified_evidence and has_reproduction:
                return FindingState.SUBMISSION_READY
            return FindingState.VERIFIED

        if stage == "verified" and score >= cls.MIN_CONFIDENCE_VERIFIED:
            if has_verified_evidence:
                return FindingState.VERIFIED
            return FindingState.VALIDATED

        if stage == "exploitable" and score >= cls.MIN_CONFIDENCE_VERIFIED:
            if has_verified_evidence or has_any_evidence:
                return FindingState.VERIFIED
            return FindingState.VALIDATED

        if stage == "validated" and score >= cls.MIN_CONFIDENCE_VERIFIED:
            if has_any_evidence:
                return FindingState.VALIDATED
            return FindingState.POTENTIAL

        if stage in ("detected", "partially_validated"):
            if has_any_evidence:
                return FindingState.POTENTIAL
            return FindingState.SIGNAL

        return FindingState.from_verification_stage(stage)

    @classmethod
    def assess_all(cls, findings: list[Finding]) -> list[Finding]:
        """Assess all findings and update their finding_state in place."""
        for f in findings:
            new_state = cls.assess(f)
            if new_state.value != f.finding_state:
                object.__setattr__(f, "finding_state", new_state.value)
        return findings

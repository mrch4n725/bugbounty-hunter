from dataclasses import dataclass, field
from typing import Any, Callable

from models.finding import Finding
from models.evidence import EvidenceStatus, EvidenceBase


@dataclass
class ValidatorVote:
    validator_name: str
    score: int
    reasoning: list[str] = field(default_factory=list)
    confidence_boost: int = 0
    confidence_penalty: int = 0


@dataclass
class ConsensusResult:
    final_score: int
    votes: list[ValidatorVote] = field(default_factory=list)
    consensus_level: str = "none"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "final_score": self.final_score,
            "consensus_level": self.consensus_level,
            "reasons": self.reasons,
            "validator_votes": [
                {"name": v.validator_name, "score": v.score,
                 "boost": v.confidence_boost, "penalty": v.confidence_penalty,
                 "reasoning": v.reasoning}
                for v in self.votes
            ],
        }


class ValidationConsensusEngine:
    """Aggregates multiple validator opinions into a consensus confidence score.

    Validators register with the engine and are run in defined priority order.
    The consensus score is computed as a weighted average, with each validator
    able to boost or penalize the final score.
    """

    def __init__(self):
        self._validators: list[tuple[str, Callable[[Finding], ValidatorVote], int]] = []

    def register(self, name: str, validator_fn: Callable[[Finding], ValidatorVote],
                 priority: int = 100) -> None:
        """Register a validator function.

        Args:
            name: Unique validator name.
            validator_fn: Callable that takes a Finding and returns a ValidatorVote.
            priority: Lower = runs first (default 100).
        """
        self._validators.append((name, validator_fn, priority))
        self._validators.sort(key=lambda x: x[2])

    def evaluate(self, finding: Finding) -> ConsensusResult:
        """Run all registered validators and produce a consensus score."""
        votes: list[ValidatorVote] = []
        for name, fn, _priority in self._validators:
            try:
                vote = fn(finding)
                votes.append(vote)
            except Exception:
                votes.append(ValidatorVote(
                    validator_name=name,
                    score=50,
                    reasoning=["Validator errored — neutral score"],
                ))

        if not votes:
            return ConsensusResult(
                final_score=finding.confidence_score or 25,
                consensus_level="none",
                reasons=["No validators registered"],
            )

        # Compute weighted score: simple average of validator scores
        avg_score = int(sum(v.score for v in votes) / len(votes))

        # Apply boosts and penalties
        total_boost = sum(v.confidence_boost for v in votes)
        total_penalty = sum(v.confidence_penalty for v in votes)
        final_score = max(0, min(100, avg_score + total_boost - total_penalty))

        # Assess consensus level
        scores = [v.score for v in votes]
        range_ = max(scores) - min(scores) if scores else 0
        if range_ <= 10:
            consensus_level = "strong"
        elif range_ <= 25:
            consensus_level = "moderate"
        else:
            consensus_level = "weak"

        # Aggregate reasons
        all_reasons: list[str] = []
        for v in votes:
            for r in v.reasoning:
                label = f"[{v.validator_name}] {r}"
                if label not in all_reasons:
                    all_reasons.append(label)

        return ConsensusResult(
            final_score=final_score,
            votes=votes,
            consensus_level=consensus_level,
            reasons=all_reasons[:10],
        )

    def evaluate_all(self, findings: list[Finding]) -> list[ConsensusResult]:
        return [self.evaluate(f) for f in findings]

    @classmethod
    def _evidence_completeness_vote(cls, finding: Finding) -> ValidatorVote:
        """Built-in validator: checks evidence completeness."""
        from engines.evidence_validator import EvidenceCompletenessValidator as ECV
        # Run validation (idempotent — skips if already penalised)
        ECV.validate(finding)

        # Check if penalty was applied
        penalty = getattr(finding, "_confidence_validator_penalty", 0)
        evidence = finding.evidence or []
        verified_count = sum(
            1 for ev in evidence
            if isinstance(ev, EvidenceBase) and ev.status == EvidenceStatus.VERIFIED
        )

        score = min(100, (verified_count * 20) + 10)
        reasoning: list[str] = []
        if penalty:
            reasoning.append(f"-{penalty} evidence incomplete penalty applied")
        if verified_count == 0:
            reasoning.append("No verified evidence")
        elif verified_count >= 2:
            reasoning.append(f"{verified_count} verified evidence items")
        return ValidatorVote(
            validator_name="evidence_completeness",
            score=score,
            reasoning=reasoning,
            confidence_penalty=penalty,
        )

    @classmethod
    def _verification_stage_vote(cls, finding: Finding) -> ValidatorVote:
        """Built-in validator: checks verification stage depth."""
        stage = (finding.verification_stage or "").lower()
        stage_scores = {
            "verified": 90, "exploitable": 85,
            "validated": 65, "partially_validated": 40,
            "detected": 25,
        }
        base_score = stage_scores.get(stage, 25)
        reasoning: list[str] = [f"Verification stage: {stage}"]
        return ValidatorVote(
            validator_name="verification_stage",
            score=base_score,
            reasoning=reasoning,
        )

    @classmethod
    def _reproduction_vote(cls, finding: Finding) -> ValidatorVote:
        """Built-in validator: checks reproduction step quality."""
        steps = finding.reproduction_steps or []
        curl = finding.curl_command or ""
        score = 25
        reasoning: list[str] = []

        if curl:
            score += 25
            reasoning.append("Curl command present")
        if len(steps) >= 3:
            score += 25
            reasoning.append(f"{len(steps)} reproduction steps")
        elif steps:
            score += 10
            reasoning.append(f"{len(steps)} reproduction steps (needs more)")

        # Check step quality (first step should be a curl or request)
        if steps and ("curl" in steps[0].lower() or "request" in steps[0].lower()):
            score += 10
            reasoning.append("First step is actionable request")

        return ValidatorVote(
            validator_name="reproduction_quality",
            score=min(100, score),
            reasoning=reasoning,
        )

    @classmethod
    def create_default(cls) -> "ValidationConsensusEngine":
        """Create an engine with the default set of validators."""
        engine = cls()
        engine.register("evidence_completeness", cls._evidence_completeness_vote, priority=10)
        engine.register("verification_stage", cls._verification_stage_vote, priority=20)
        engine.register("reproduction_quality", cls._reproduction_vote, priority=30)
        return engine

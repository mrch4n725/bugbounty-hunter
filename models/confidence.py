from dataclasses import dataclass, field
from typing import Any


@dataclass
class ConfidenceContribution:
    source: str
    delta: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "delta": self.delta,
            "reason": self.reason,
        }


@dataclass
class ConfidenceFactors:
    detection_signal: int = 0
    validation_proof: int = 0
    evidence_quality: int = 0
    ownership_proof: int = 0
    impact_proof: int = 0
    investigation_depth: int = 0
    consensus_support: int = 0
    consensus_penalty: int = 0
    evidence_penalty: int = 0
    base_score: int = 25

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_signal": self.detection_signal,
            "validation_proof": self.validation_proof,
            "evidence_quality": self.evidence_quality,
            "ownership_proof": self.ownership_proof,
            "impact_proof": self.impact_proof,
            "investigation_depth": self.investigation_depth,
            "consensus_support": self.consensus_support,
            "consensus_penalty": self.consensus_penalty,
            "evidence_penalty": self.evidence_penalty,
            "base_score": self.base_score,
        }


@dataclass
class ConfidenceResult:
    final_score: int
    contributions: list[ConfidenceContribution] = field(default_factory=list)
    factors: ConfidenceFactors = field(default_factory=ConfidenceFactors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "final_score": self.final_score,
            "contributions": [c.to_dict() for c in self.contributions],
            "factors": self.factors.to_dict(),
        }

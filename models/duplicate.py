from dataclasses import dataclass, field
from typing import Any


LIKELY_DUPLICATE = "likely_duplicate"
MODERATE_RISK = "moderate_risk"
POTENTIALLY_NOVEL = "potentially_novel"


@dataclass
class DuplicateRisk:
    likelihood: str = POTENTIALLY_NOVEL
    confidence: float = 0.0
    similar_findings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "likelihood": self.likelihood,
            "confidence": round(self.confidence, 1),
            "similar_findings": self.similar_findings[:5],
            "reasons": self.reasons[:3],
        }

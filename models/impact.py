from dataclasses import dataclass, field
from typing import Any


@dataclass
class ImpactFactors:
    data_sensitivity: str = "public"
    authentication_required: bool = False
    privilege_level: str = "anonymous"
    asset_importance: str = "low"
    exploitability: str = "none"
    validation_quality: str = "weak"
    attack_chain_position: int = 0
    business_context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "data_sensitivity": self.data_sensitivity,
            "authentication_required": self.authentication_required,
            "privilege_level": self.privilege_level,
            "asset_importance": self.asset_importance,
            "exploitability": self.exploitability,
            "validation_quality": self.validation_quality,
            "attack_chain_position": self.attack_chain_position,
            "business_context": self.business_context,
        }


@dataclass
class ImpactAssessment:
    overall: str = "informational"
    score: int = 0
    factors: ImpactFactors = field(default_factory=ImpactFactors)
    narrative: str = ""
    acceptance_likelihood: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall,
            "score": self.score,
            "factors": self.factors.to_dict(),
            "narrative": self.narrative,
            "acceptance_likelihood": self.acceptance_likelihood,
        }

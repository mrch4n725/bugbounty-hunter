from dataclasses import dataclass, field
from typing import Any


@dataclass
class PipelineMetrics:
    total_signals: int = 0
    promoted_to_potential: int = 0
    promoted_to_validated: int = 0
    promoted_to_verified: int = 0
    submission_ready: int = 0
    funnel: dict[str, float] = field(default_factory=dict)
    bottleneck: str = ""
    detection_coverage: dict[str, int] = field(default_factory=dict)
    validation_rate: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_signals": self.total_signals,
            "promoted_to_potential": self.promoted_to_potential,
            "promoted_to_validated": self.promoted_to_validated,
            "promoted_to_verified": self.promoted_to_verified,
            "submission_ready": self.submission_ready,
            "funnel": self.funnel,
            "bottleneck": self.bottleneck,
            "detection_coverage": self.detection_coverage,
            "validation_rate": self.validation_rate,
        }

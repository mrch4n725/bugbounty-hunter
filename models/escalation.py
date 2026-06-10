from dataclasses import dataclass, field
from typing import Any


@dataclass
class EscalationPath:
    path_type: str
    target: str
    description: str
    impact_if_confirmed: str
    requires_capability: str = ""
    estimated_effort: str = "low"
    confidence_gain: int = 0
    unsafe: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_type": self.path_type,
            "target": self.target,
            "description": self.description,
            "impact_if_confirmed": self.impact_if_confirmed,
            "requires_capability": self.requires_capability,
            "estimated_effort": self.estimated_effort,
            "confidence_gain": self.confidence_gain,
            "unsafe": self.unsafe,
        }


@dataclass
class EscalationResult:
    finding_fingerprint: str
    vuln_type: str
    current_impact: str
    escalation_paths: list[EscalationPath] = field(default_factory=list)
    worst_case_impact: str = ""
    has_safe_paths: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_fingerprint": self.finding_fingerprint,
            "vuln_type": self.vuln_type,
            "current_impact": self.current_impact,
            "escalation_paths": [p.to_dict() for p in self.escalation_paths],
            "worst_case_impact": self.worst_case_impact,
            "has_safe_paths": self.has_safe_paths,
        }

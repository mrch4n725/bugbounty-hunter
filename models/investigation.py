from dataclasses import dataclass, field
from typing import Any


@dataclass
class InvestigationTask:
    finding_fingerprint: str
    strategy: str = ""
    target_url: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    estimated_cost: int = 1
    priority: int = 0
    capability_required: str = ""
    completed: bool = False
    result_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_fingerprint": self.finding_fingerprint,
            "strategy": self.strategy,
            "target_url": self.target_url,
            "estimated_cost": self.estimated_cost,
            "priority": self.priority,
            "capability_required": self.capability_required,
            "completed": self.completed,
        }


@dataclass
class InvestigationPlan:
    finding_fingerprint: str
    tasks: list[InvestigationTask] = field(default_factory=list)
    current_confidence: int = 0
    target_confidence: int = 0
    budget_remaining: int = 0
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_fingerprint": self.finding_fingerprint,
            "tasks": [t.to_dict() for t in self.tasks],
            "current_confidence": self.current_confidence,
            "target_confidence": self.target_confidence,
            "budget_remaining": self.budget_remaining,
            "reason": self.reason,
        }


@dataclass
class InvestigationResult:
    task: InvestigationTask
    evidence_fingerprint: str = ""
    confidence_delta: int = 0
    success: bool = False
    next_strategy: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.task.strategy,
            "evidence_fingerprint": self.evidence_fingerprint,
            "confidence_delta": self.confidence_delta,
            "success": self.success,
            "next_strategy": self.next_strategy,
            "reason": self.reason,
        }

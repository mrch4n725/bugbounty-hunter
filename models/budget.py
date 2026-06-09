from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetValueScore:
    url: str
    score: int = 0
    factors: dict[str, float] = field(default_factory=dict)
    allocated_budget: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "score": self.score,
            "factors": self.factors,
            "allocated_budget": self.allocated_budget,
        }


@dataclass
class ScanBudget:
    total_requests: int = 0
    remaining: int = 0
    allocation: dict[str, int] = field(default_factory=dict)
    system_load: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "remaining": self.remaining,
            "system_load": round(self.system_load, 2),
            "allocation_count": len(self.allocation),
        }

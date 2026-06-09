from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ValidationSnapshot:
    request: str = ""
    response: str = ""
    response_body_hash: str = ""
    timestamp: str = ""
    validation_step: str = ""
    evidence_fingerprint: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request[:500],
            "response": self.response[:500],
            "response_body_hash": self.response_body_hash,
            "timestamp": self.timestamp,
            "validation_step": self.validation_step,
            "evidence_fingerprint": self.evidence_fingerprint,
        }


@dataclass
class ReplayBundle:
    finding_fingerprint: str = ""
    snapshots: list[ValidationSnapshot] = field(default_factory=list)
    validation_commands: list[str] = field(default_factory=list)
    expected_behavior: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_fingerprint": self.finding_fingerprint,
            "snapshots": [s.to_dict() for s in self.snapshots],
            "validation_commands": self.validation_commands,
            "expected_behavior": self.expected_behavior,
        }

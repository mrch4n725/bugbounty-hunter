import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any


class OutcomeRecord:
    """A single submission outcome record."""
    def __init__(
        self,
        finding_fingerprint: str,
        outcome: str,
        bounty: float = 0.0,
        notes: str = "",
        submitted_at: str = "",
    ):
        self.finding_fingerprint = finding_fingerprint
        self.outcome = outcome
        self.bounty = bounty
        self.notes = notes
        self.submitted_at = submitted_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_fingerprint": self.finding_fingerprint,
            "outcome": self.outcome,
            "bounty": self.bounty,
            "notes": self.notes,
            "submitted_at": self.submitted_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "OutcomeRecord":
        return cls(
            finding_fingerprint=d["finding_fingerprint"],
            outcome=d["outcome"],
            bounty=d.get("bounty", 0.0),
            notes=d.get("notes", ""),
            submitted_at=d.get("submitted_at", ""),
        )


class OutcomeFeedbackEngine:
    """Records and queries submission outcomes.

    Persists outcomes as JSON Lines to ``outcomes.jsonl`` in the output directory.
    Thread-safe for concurrent scanner access.
    """

    VALID_OUTCOMES = {"accepted", "rejected", "bounty_paid", "informative", "duplicate", "wont_fix"}

    def __init__(self, output_dir: str = ""):
        self.output_dir = output_dir
        self._lock = threading.Lock()
        self._records: dict[str, list[OutcomeRecord]] = {}
        self._outcomes_path = os.path.join(output_dir, "outcomes.jsonl") if output_dir else ""

        if self._outcomes_path and os.path.isfile(self._outcomes_path):
            self._load()

    def _load(self) -> None:
        try:
            with open(self._outcomes_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    rec = OutcomeRecord.from_dict(d)
                    self._records.setdefault(rec.finding_fingerprint, []).append(rec)
        except Exception:
            pass

    def _append(self, record: OutcomeRecord) -> None:
        if not self._outcomes_path:
            return
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            with open(self._outcomes_path, "a") as f:
                f.write(json.dumps(record.to_dict()) + "\n")
        except Exception:
            pass

    def record_outcome(
        self,
        finding_fingerprint: str,
        outcome: str = "",
        bounty: float = 0.0,
        notes: str = "",
    ) -> OutcomeRecord | None:
        if outcome and outcome not in self.VALID_OUTCOMES:
            return None
        record = OutcomeRecord(
            finding_fingerprint=finding_fingerprint,
            outcome=outcome,
            bounty=bounty,
            notes=notes,
        )
        with self._lock:
            self._records.setdefault(finding_fingerprint, []).append(record)
            self._append(record)
        return record

    def get_outcomes(self, finding_fingerprint: str) -> list[OutcomeRecord]:
        with self._lock:
            return list(self._records.get(finding_fingerprint, []))

    def get_all(self) -> dict[str, list[OutcomeRecord]]:
        with self._lock:
            return {k: list(v) for k, v in self._records.items()}

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            total = sum(len(v) for v in self._records.values())
            by_outcome: dict[str, int] = {}
            total_bounty = 0.0
            for recs in self._records.values():
                for r in recs:
                    by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
                    total_bounty += r.bounty
            return {
                "total_records": total,
                "unique_findings": len(self._records),
                "by_outcome": by_outcome,
                "total_bounty": total_bounty,
            }

    def has_positive_outcome(self, finding_fingerprint: str) -> bool:
        with self._lock:
            recs = self._records.get(finding_fingerprint, [])
            return any(r.outcome in ("accepted", "bounty_paid") for r in recs)

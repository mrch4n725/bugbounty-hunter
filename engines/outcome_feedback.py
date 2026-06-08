"""
outcome_feedback.py — Outcome Feedback Framework.

Tracks real-world bug bounty outcomes (Accepted, Duplicate, Informative,
Not Applicable, Won't Fix) and correlates them back to finding metadata
to enable data-driven validation and reporting improvements.

Data flow:
  Scanner findings  →  Report  →  Submitted to platform  →  Outcome received
       ↓                                                           ↓
  OutcomeEngine stores outcome + finding fingerprint        OutcomeEngine
       ↓                                                           ↓
  OutcomeAnalyzer computes: acceptance rate by type,               ↓
  confidence-score prediction accuracy, evidence-quality         OutcomeDB
  correlation                                                (JSON/SQLite)

Usage:
  from engines.outcome_feedback import OutcomeEngine, OutcomeAnalyzer
  engine = OutcomeEngine(config)
  engine.record_outcome(fingerprint="abc123", outcome="accepted",
                        vuln_type="XSS", confidence=85, ...)
  analyzer = OutcomeAnalyzer(engine)
  report = analyzer.generate_report()
"""

import json
import os
import time
from typing import Any
from collections import defaultdict

OUTCOME_FILE = "outcomes.jsonl"

OUTCOME_LABELS = {
    "accepted": "Accepted — report triaged as valid vulnerability",
    "duplicate": "Duplicate — previously reported by another researcher",
    "informative": "Informative — issue noted but not considered exploitable or in scope",
    "not_applicable": "Not Applicable — report does not describe a security vulnerability",
    "wont_fix": "Won't Fix — risk accepted or out of scope",
}


class OutcomeEngine:
    """Stores and retrieves outcome records, correlated to findings by fingerprint."""

    def __init__(self, config: dict):
        self.outcome_dir = os.path.join(
            config.get("output_dir", "reports"), "outcomes"
        )
        os.makedirs(self.outcome_dir, exist_ok=True)
        self._lock = False

    def _path(self) -> str:
        return os.path.join(self.outcome_dir, OUTCOME_FILE)

    def record_outcome(self, fingerprint: str, outcome: str,
                       vuln_type: str = "", severity: str = "",
                       confidence_score: float = 0.0,
                       verification_stage: str = "",
                       evidence_types: list[str] = None,
                       platform: str = "",
                       note: str = "") -> None:
        """Record a single outcome for a finding identified by fingerprint."""
        record = {
            "fingerprint": fingerprint,
            "outcome": outcome,
            "vuln_type": vuln_type,
            "severity": severity,
            "confidence_score": confidence_score,
            "verification_stage": verification_stage,
            "evidence_types": evidence_types or [],
            "platform": platform,
            "note": note,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with open(self._path(), "a") as f:
            f.write(json.dumps(record) + "\n")

    def load_outcomes(self) -> list[dict]:
        """Load all stored outcome records."""
        path = self._path()
        if not os.path.exists(path):
            return []
        records = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records


class OutcomeAnalyzer:
    """Analyzes outcomes and correlates with finding metadata."""

    def __init__(self, engine: OutcomeEngine):
        self.engine = engine

    def _load(self) -> list[dict]:
        return self.engine.load_outcomes()

    def by_outcome(self) -> dict[str, int]:
        records = self._load()
        counts: dict[str, int] = {}
        for r in records:
            o = r.get("outcome", "unknown")
            counts[o] = counts.get(o, 0) + 1
        return counts

    def by_vuln_type(self) -> dict[str, dict[str, int]]:
        records = self._load()
        result: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for r in records:
            vt = r.get("vuln_type", "unknown")
            o = r.get("outcome", "unknown")
            result[vt][o] += 1
        return dict(result)

    def acceptance_rate(self) -> dict[str, float]:
        """Acceptance rate per vuln_type (accepted / total)."""
        by_type = self.by_vuln_type()
        rates: dict[str, float] = {}
        for vt, outcomes in by_type.items():
            total = sum(outcomes.values())
            accepted = outcomes.get("accepted", 0)
            rates[vt] = round(accepted / total, 3) if total else 0.0
        return rates

    def confidence_prediction_accuracy(self) -> dict[str, Any]:
        """Determine whether confidence score predicts acceptance."""
        records = self._load()
        if not records:
            return {"error": "no outcomes recorded", "accuracy": 0.0}

        correct = 0
        total = 0
        for r in records:
            score = r.get("confidence_score", 0)
            outcome = r.get("outcome", "")
            if score >= 60 and outcome == "accepted":
                correct += 1
            elif score < 60 and outcome != "accepted":
                correct += 1
            total += 1
        accuracy = round(correct / total, 3) if total else 0.0

        high_confidence_accepted = sum(
            1 for r in records if r.get("confidence_score", 0) >= 60 and r.get("outcome") == "accepted"
        )
        high_confidence_total = sum(
            1 for r in records if r.get("confidence_score", 0) >= 60
        )
        low_confidence_rejected = sum(
            1 for r in records if r.get("confidence_score", 0) < 60 and r.get("outcome") not in ("accepted", "")
        )
        low_confidence_total = sum(
            1 for r in records if r.get("confidence_score", 0) < 60
        )

        return {
            "overall_accuracy": accuracy,
            "total_outcomes": total,
            "high_confidence_acceptance_rate": round(high_confidence_accepted / high_confidence_total, 3) if high_confidence_total else 0.0,
            "low_confidence_rejection_rate": round(low_confidence_rejected / low_confidence_total, 3) if low_confidence_total else 0.0,
            "high_confidence_count": high_confidence_total,
            "low_confidence_count": low_confidence_total,
        }

    def evidence_quality_correlation(self) -> dict[str, Any]:
        """Correlate evidence strength with acceptance rate."""
        records = self._load()
        if not records:
            return {"error": "no outcomes recorded"}

        by_evidence_count: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for r in records:
            ev_count = len(r.get("evidence_types", []))
            outcome = r.get("outcome", "unknown")
            by_evidence_count[ev_count][outcome] += 1

        result = {}
        for ev_count, outcomes in sorted(by_evidence_count.items()):
            total = sum(outcomes.values())
            accepted = outcomes.get("accepted", 0)
            result[str(ev_count)] = {
                "total": total,
                "accepted": accepted,
                "acceptance_rate": round(accepted / total, 3) if total else 0.0,
            }
        return result

    def by_verification_stage(self) -> dict[str, dict[str, int]]:
        """Acceptance breakdown by verification stage."""
        records = self._load()
        result: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for r in records:
            stage = r.get("verification_stage", "detected")
            o = r.get("outcome", "unknown")
            result[stage][o] += 1
        return dict(result)

    def generate_report(self) -> dict[str, Any]:
        """Full outcome analysis report."""
        return {
            "summary": {
                "total_outcomes": len(self._load()),
                "by_outcome": self.by_outcome(),
                "acceptance_rate_by_type": self.acceptance_rate(),
            },
            "confidence_accuracy": self.confidence_prediction_accuracy(),
            "evidence_quality": self.evidence_quality_correlation(),
            "by_verification_stage": self.by_verification_stage(),
            "recommendations": self._recommendations(),
        }

    def _recommendations(self) -> list[str]:
        records = self._load()
        recs = []
        if not records:
            return ["No outcomes recorded yet — submit findings to build feedback loop"]

        acc = self.confidence_prediction_accuracy()
        if acc.get("overall_accuracy", 0) < 0.5:
            recs.append("Confidence scoring does not predict acceptance — recalibrate thresholds")

        for vt, rate in self.acceptance_rate().items():
            if rate < 0.3:
                recs.append(f"Low acceptance rate for '{vt}' — improve validation or reduce severity")

        by_stage = self.by_verification_stage()
        for stage, outcomes in by_stage.items():
            total = sum(outcomes.values())
            accepted = outcomes.get("accepted", 0)
            if stage in ("detected", "validated") and total > 0 and accepted / total < 0.2:
                recs.append(f"'{stage}' findings have low acceptance — add stronger validation before reporting")

        return recs

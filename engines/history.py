"""
Historical Finding Correlation Engine.

Tracks vulnerabilities across scans using:

- Root-cause fingerprints  (vuln_type + root_cause)
- Evidence fingerprints    (SHA-256 of evidence content)
- Asset fingerprints       (host + port + protocol)

Classifies each finding as:

  Previously Seen   — same fingerprint in most recent scan
  New               — fingerprint never seen before
  Resolved          — existed in previous scan, absent in current
  Regressed         — was resolved/remediated, now reappeared
  Improved          — verification stage improved since last scan
  Degraded          — verification stage worsened since last scan
"""

import hashlib
import json
import os
import threading
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse


class FindingClassification(str, Enum):
    NEW = "new"
    PREVIOUSLY_SEEN = "previously_seen"
    REGRESSED = "regressed"
    RESOLVED = "resolved"
    IMPROVED = "improved"
    DEGRADED = "degraded"

    @classmethod
    def label(cls, value: str) -> str:
        labels = {
            "new": "New",
            "previously_seen": "Previously Seen",
            "regressed": "Regressed",
            "resolved": "Resolved",
            "improved": "Improved",
            "degraded": "Degraded",
        }
        return labels.get(value, value.replace("_", " ").title())


# ── Fingerprint helpers ───────────────────────────────────────────────


def compute_asset_fingerprint(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return hashlib.sha256(
        f"{host}:{port}:{parsed.scheme}".encode()
    ).hexdigest()


# ── History record ────────────────────────────────────────────────────


class FindingHistoryRecord:
    """Serialisable record of a finding from a past scan."""

    __slots__ = (
        "fingerprint", "vuln_type", "url", "parameter",
        "severity", "verification_stage", "confidence_score",
        "root_cause_fingerprint", "asset_fingerprint",
        "evidence_fingerprints",
    )

    def __init__(
        self,
        fingerprint: str,
        vuln_type: str,
        url: str,
        parameter: str = "",
        severity: str = "info",
        verification_stage: str = "detected",
        confidence_score: int = 25,
        root_cause_fingerprint: str = "",
        asset_fingerprint: str = "",
        evidence_fingerprints: list[str] | None = None,
    ):
        self.fingerprint = fingerprint
        self.vuln_type = vuln_type
        self.url = url
        self.parameter = parameter
        self.severity = severity
        self.verification_stage = verification_stage
        self.confidence_score = confidence_score
        self.root_cause_fingerprint = root_cause_fingerprint or ""
        self.asset_fingerprint = asset_fingerprint or compute_asset_fingerprint(url)
        self.evidence_fingerprints = evidence_fingerprints or []

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "vuln_type": self.vuln_type,
            "url": self.url,
            "parameter": self.parameter,
            "severity": self.severity,
            "verification_stage": self.verification_stage,
            "confidence_score": self.confidence_score,
            "root_cause_fingerprint": self.root_cause_fingerprint,
            "asset_fingerprint": self.asset_fingerprint,
            "evidence_fingerprints": self.evidence_fingerprints,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FindingHistoryRecord":
        return cls(
            fingerprint=d.get("fingerprint", ""),
            vuln_type=d.get("vuln_type", ""),
            url=d.get("url", ""),
            parameter=d.get("parameter", ""),
            severity=d.get("severity", "info"),
            verification_stage=d.get("verification_stage", "detected"),
            confidence_score=d.get("confidence_score", 25),
            root_cause_fingerprint=d.get("root_cause_fingerprint", ""),
            asset_fingerprint=d.get("asset_fingerprint", ""),
            evidence_fingerprints=d.get("evidence_fingerprints", []),
        )


# ── Scan snapshot ─────────────────────────────────────────────────────


class ScanSnapshot:
    """Snapshot of a single scan's findings."""

    def __init__(
        self,
        scan_id: str = "",
        timestamp: str = "",
        target: str = "",
        records: list[FindingHistoryRecord] | None = None,
    ):
        self.scan_id = scan_id
        self.timestamp = timestamp or datetime.utcnow().isoformat() + "Z"
        self.target = target
        self.records = records or []

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "target": self.target,
            "findings": [r.to_dict() for r in self.records],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanSnapshot":
        return cls(
            scan_id=d.get("scan_id", ""),
            timestamp=d.get("timestamp", ""),
            target=d.get("target", ""),
            records=[FindingHistoryRecord.from_dict(r) for r in d.get("findings", [])],
        )

    @property
    def fingerprint_set(self) -> set[str]:
        return {r.fingerprint for r in self.records}

    @property
    def records_by_fingerprint(self) -> dict[str, FindingHistoryRecord]:
        return {r.fingerprint: r for r in self.records}


# ── Correlation result ────────────────────────────────────────────────


class CorrelationResult:
    """Classification result for a single finding."""

    def __init__(
        self,
        classification: FindingClassification,
        previous_scan_id: str = "",
        previous_timestamp: str = "",
        previous_stage: str = "",
        previous_confidence: int = 0,
        previous_severity: str = "",
    ):
        self.classification = classification
        self.previous_scan_id = previous_scan_id
        self.previous_timestamp = previous_timestamp
        self.previous_stage = previous_stage
        self.previous_confidence = previous_confidence
        self.previous_severity = previous_severity

    def to_dict(self) -> dict:
        return {
            "classification": self.classification.value,
            "label": FindingClassification.label(self.classification.value),
            "previous_scan_id": self.previous_scan_id,
            "previous_timestamp": self.previous_timestamp,
            "previous_stage": self.previous_stage,
            "previous_confidence": self.previous_confidence,
            "previous_severity": self.previous_severity,
        }


# ── Scan History (persistent store) ───────────────────────────────────


class ScanHistory:
    """Persistent scan history stored as JSON alongside reports.

    Maintains an ordered list of ScanSnapshots, keyed by target.
    Only the most recent N scans per target are kept (default 10).
    """

    def __init__(self, history_path: str, max_scans_per_target: int = 10):
        self._path = history_path
        self._max = max_scans_per_target
        self._lock = threading.RLock()
        self._snapshots: list[ScanSnapshot] = []
        self._load()

    def _load(self) -> None:
        try:
            with open(self._path, "r") as f:
                data = json.load(f)
            self._snapshots = [
                ScanSnapshot.from_dict(s) for s in data.get("scans", [])
            ]
        except (FileNotFoundError, json.JSONDecodeError, Exception):
            self._snapshots = []

    def save(self) -> None:
        with self._lock:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with open(self._path, "w") as f:
                json.dump(
                    {"scans": [s.to_dict() for s in self._snapshots]},
                    f,
                    indent=2,
                    default=str,
                )

    def add_snapshot(self, snapshot: ScanSnapshot) -> None:
        with self._lock:
            target = snapshot.target
            self._snapshots.append(snapshot)
            target_scans = [s for s in self._snapshots if s.target == target]
            if len(target_scans) > self._max:
                excess = len(target_scans) - self._max
                for _ in range(excess):
                    idx = next(
                        i for i, s in enumerate(self._snapshots)
                        if s.target == target
                    )
                    self._snapshots.pop(idx)
            self.save()

    def get_scans_for_target(self, target: str) -> list[ScanSnapshot]:
        return [s for s in self._snapshots if s.target == target]

    def get_latest_scan(self, target: str) -> ScanSnapshot | None:
        scans = self.get_scans_for_target(target)
        return scans[-1] if scans else None

    def get_previous_scan(self, target: str) -> ScanSnapshot | None:
        scans = self.get_scans_for_target(target)
        return scans[-2] if len(scans) >= 2 else None

    def clear(self) -> None:
        with self._lock:
            self._snapshots.clear()
            self.save()

    def all_fingerprints_for_target(self, target: str) -> set[str]:
        fps: set[str] = set()
        for s in self.get_scans_for_target(target):
            fps.update(s.fingerprint_set)
        return fps


# ── Correlation Engine ────────────────────────────────────────────────


class HistoricalCorrelationEngine:
    """Correlates current findings against scan history.

    Provides:
      - classify_finding()   → CorrelationResult for one finding
      - classify_all()       → dict[fingerprint, CorrelationResult]
      - compute_delta()      → {new, previously_seen, resolved, regressed} lists
    """

    STAGE_ORDER = {
        "detected": 0,
        "partially_validated": 1,
        "validated": 2,
        "exploitable": 3,
        "verified": 4,
    }

    def __init__(self, history: ScanHistory):
        self._history = history

    def classify_finding(
        self,
        fingerprint: str,
        verification_stage: str,
        confidence_score: int,
        severity: str,
        vuln_type: str,
        url: str,
        parameter: str,
        root_cause_fingerprint: str = "",
        evidence_fingerprints: list[str] | None = None,
        target: str = "",
    ) -> CorrelationResult:
        latest = self._history.get_latest_scan(target)
        previous = self._history.get_previous_scan(target)
        all_fingerprints = self._history.all_fingerprints_for_target(target)

        in_latest = latest and fingerprint in latest.fingerprint_set
        in_previous = previous and fingerprint in previous.fingerprint_set
        in_any_older = fingerprint in all_fingerprints and not in_latest

        if not in_any_older and not in_latest:
            return CorrelationResult(FindingClassification.NEW)

        if in_latest:
            record = latest.records_by_fingerprint.get(fingerprint) if latest else None
            if record:
                current_order = self.STAGE_ORDER.get(verification_stage, 0)
                prev_order = self.STAGE_ORDER.get(record.verification_stage, 0)
                if current_order > prev_order:
                    return CorrelationResult(
                        FindingClassification.IMPROVED,
                        previous_scan_id=latest.scan_id,
                        previous_timestamp=latest.timestamp,
                        previous_stage=record.verification_stage,
                        previous_confidence=record.confidence_score,
                        previous_severity=record.severity,
                    )
                if current_order < prev_order:
                    return CorrelationResult(
                        FindingClassification.DEGRADED,
                        previous_scan_id=latest.scan_id,
                        previous_timestamp=latest.timestamp,
                        previous_stage=record.verification_stage,
                        previous_confidence=record.confidence_score,
                        previous_severity=record.severity,
                    )
            return CorrelationResult(
                FindingClassification.PREVIOUSLY_SEEN,
                previous_scan_id=latest.scan_id if latest else "",
                previous_timestamp=latest.timestamp if latest else "",
                previous_stage=record.verification_stage if record else "",
                previous_confidence=record.confidence_score if record else 0,
                previous_severity=record.severity if record else "",
            )

        if not in_latest and in_any_older:
            old_snapshot = None
            old_record = None
            for s in reversed(self._history.get_scans_for_target(target)):
                if fingerprint in s.fingerprint_set:
                    old_snapshot = s
                    old_record = s.records_by_fingerprint.get(fingerprint)
                    break
            return CorrelationResult(
                FindingClassification.REGRESSED,
                previous_scan_id=old_snapshot.scan_id if old_snapshot else "",
                previous_timestamp=old_snapshot.timestamp if old_snapshot else "",
                previous_stage=old_record.verification_stage if old_record else "",
                previous_confidence=old_record.confidence_score if old_record else 0,
                previous_severity=old_record.severity if old_record else "",
            )

        return CorrelationResult(FindingClassification.NEW)

    def classify_all(
        self,
        findings: list[dict | Any],
        target: str = "",
        evidence_engine=None,
    ) -> dict[str, CorrelationResult]:
        results: dict[str, CorrelationResult] = {}
        for f in findings:
            if isinstance(f, dict):
                fp = f.get("fingerprint", "")
                url = f.get("url", "")
                parameter = f.get("parameter", "")
            else:
                fp = getattr(f, "fingerprint", "")
                url = getattr(f, "url", "")
                parameter = getattr(f, "parameter", "")

            if not fp:
                continue

            evidence_fps: list[str] = []
            if evidence_engine and fp:
                evidence_list = evidence_engine.get_evidence(fp)
                for ev in evidence_list:
                    try:
                        from engines.evidence_engine import EvidenceEngine
                        ev_fp = EvidenceEngine._fingerprint(ev)
                        evidence_fps.append(ev_fp)
                    except Exception:
                        pass

            result = self.classify_finding(
                fingerprint=fp,
                verification_stage=f.get("verification_stage", "detected") if isinstance(f, dict) else getattr(f, "verification_stage", "detected"),
                confidence_score=f.get("confidence_score", 25) if isinstance(f, dict) else getattr(f, "confidence_score", 25),
                severity=f.get("severity", "info") if isinstance(f, dict) else getattr(f, "severity", "info"),
                vuln_type=f.get("vuln_type", f.get("type", "")) if isinstance(f, dict) else getattr(f, "vuln_type", ""),
                url=url,
                parameter=parameter,
                root_cause_fingerprint=f.get("root_cause_fingerprint", "") if isinstance(f, dict) else getattr(f, "root_cause_fingerprint", ""),
                evidence_fingerprints=evidence_fps,
                target=target,
            )
            results[fp] = result
        return results

    def compute_delta(
        self,
        findings: list[dict | Any],
        target: str = "",
        evidence_engine=None,
    ) -> dict[str, list]:
        correlations = self.classify_all(findings, target, evidence_engine)

        classified: dict[str, list] = {
            "new": [],
            "previously_seen": [],
            "resolved": [],
            "regressed": [],
            "improved": [],
            "degraded": [],
        }

        for f in findings:
            fp = f.get("fingerprint", "") if isinstance(f, dict) else getattr(f, "fingerprint", "")
            if not fp or fp not in correlations:
                classified["new"].append(f)
                continue
            result = correlations[fp]
            classified[result.classification.value].append(f)

        latest = self._history.get_latest_scan(target)
        if latest:
            current_fps = {
                f.get("fingerprint", "") if isinstance(f, dict) else getattr(f, "fingerprint", "")
                for f in findings
            }
            for record in latest.records:
                if record.fingerprint not in current_fps:
                    old = FindingHistoryRecord.from_dict(record.to_dict())
                    classified["resolved"].append(old)

        return classified

    def build_snapshot(
        self,
        findings: list[dict | Any],
        target: str = "",
        scan_id: str = "",
    ) -> ScanSnapshot:
        records: list[FindingHistoryRecord] = []
        for f in findings:
            if isinstance(f, dict):
                fp = f.get("fingerprint", "")
                vuln_type = f.get("vuln_type", f.get("type", ""))
                url = f.get("url", "")
                parameter = f.get("parameter", "")
                severity = f.get("severity", "info")
                stage = f.get("verification_stage", "detected")
                confidence = f.get("confidence_score", 25)
                rcf = f.get("root_cause_fingerprint", "")
            else:
                fp = getattr(f, "fingerprint", "")
                vuln_type = getattr(f, "vuln_type", "")
                url = getattr(f, "url", "")
                parameter = getattr(f, "parameter", "")
                severity = getattr(f, "severity", "info")
                stage = getattr(f, "verification_stage", "detected")
                confidence = getattr(f, "confidence_score", 25)
                rcf = getattr(f, "root_cause_fingerprint", "")

            if not fp:
                continue

            records.append(FindingHistoryRecord(
                fingerprint=fp,
                vuln_type=vuln_type,
                url=url,
                parameter=parameter,
                severity=severity,
                verification_stage=stage,
                confidence_score=confidence,
                root_cause_fingerprint=rcf,
            ))

        return ScanSnapshot(
            scan_id=scan_id,
            target=target,
            records=records,
        )


# ── Convenience function for main.py integration ─────────────────────


def correlate_findings(
    findings: list[dict | Any],
    config: dict,
    evidence_engine=None,
) -> list[dict]:
    """Correlate findings against scan history and attach classification metadata.

    Args:
        findings: List of finding dicts or Finding objects.
        config: Scan config dict with output_dir and target.
        evidence_engine: Optional EvidenceEngine for evidence-based correlation.

    Returns:
        Same findings list with 'historical' key attached to each dict
        (or Finding instance with historical attribute).
    """
    target = config.get("target", "")
    output_dir = config.get("output_dir", "reports")
    history_path = os.path.join(output_dir, "scan_history.json")

    history = ScanHistory(history_path)
    engine = HistoricalCorrelationEngine(history)

    correlations = engine.classify_all(findings, target, evidence_engine)

    for f in findings:
        fp = f.get("fingerprint", "") if isinstance(f, dict) else getattr(f, "fingerprint", "")
        if fp and fp in correlations:
            corr = correlations[fp]
            meta = corr.to_dict()
            if isinstance(f, dict):
                f["historical"] = meta
            else:
                object.__setattr__(f, "historical", meta)
        else:
            default = CorrelationResult(FindingClassification.NEW).to_dict()
            if isinstance(f, dict):
                f["historical"] = default
            else:
                object.__setattr__(f, "historical", default)

    snapshot = engine.build_snapshot(findings, target)
    history.add_snapshot(snapshot)

    return findings

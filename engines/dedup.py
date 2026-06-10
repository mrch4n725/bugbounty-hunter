"""Deduplication engine — groups duplicate findings by fingerprint."""

from threading import Lock
from typing import Any, Dict, List, Optional

from models.finding import Finding, FindingState


# Stage ordering for merge priority
_STAGE_ORDER = {
    "detected": 0,
    "partially_validated": 1,
    "validated": 2,
    "exploitable": 3,
    "verified": 4,
}


class DeduplicationEngine:
    """Deduplicate findings by fingerprint.
    Groups findings that share the same fingerprint across URLs.
    Stores Finding objects directly.
    """

    def __init__(self):
        self._lock = Lock()
        self._groups: Dict[str, Finding] = {}

    def add(self, finding: Finding) -> Optional[Finding]:
        fp = finding.fingerprint
        with self._lock:
            if fp in self._groups:
                existing = self._groups[fp]
                existing.grouped_urls.append(finding.url)
                # Merge _from_candidate tag from incoming finding
                if hasattr(finding, "_from_candidate") and not hasattr(existing, "_from_candidate"):
                    object.__setattr__(existing, "_from_candidate",
                                        getattr(finding, "_from_candidate"))
                # Prefer higher verification stage
                incoming_stage = getattr(finding, "verification_stage", "detected")
                existing_stage = getattr(existing, "verification_stage", "detected")
                if _STAGE_ORDER.get(incoming_stage, 0) > _STAGE_ORDER.get(existing_stage, 0):
                    existing.verification_stage = incoming_stage
                    existing.finding_state = FindingState.from_verification_stage(incoming_stage).value
                    if (finding.confidence_score or 0) > (existing.confidence_score or 0):
                        existing.confidence_score = finding.confidence_score
                        existing.confidence_label = getattr(finding, "confidence_label", "")
                return None
            self._groups[fp] = finding
            return finding

    def add_legacy(self, f: dict[str, Any] | Finding) -> dict[str, Any] | Finding | None:
        if isinstance(f, Finding):
            return f if self.add(f) else None
        finding_obj = Finding.from_dict(f)
        return f if self.add(finding_obj) else None

    def get_findings(self) -> List[Finding]:
        with self._lock:
            results = []
            for f in self._groups.values():
                if len(f.grouped_urls) >= 5:
                    f.details = f"{f.details} \u2014 Found on {len(f.grouped_urls)} URLs"
                results.append(f)
            return results

    def to_dict(self) -> dict[str, dict]:
        """Serialize dedup state to a dict of fingerprint → finding dicts."""
        with self._lock:
            return {fp: finding.to_dict() for fp, finding in self._groups.items()}

    @classmethod
    def from_dict(cls, data: dict[str, dict]) -> "DeduplicationEngine":
        """Restore dedup state from a dict of fingerprint → finding dicts."""
        engine = cls()
        for fp, d in data.items():
            finding = Finding.from_dict(d)
            if finding.fingerprint != fp:
                finding.fingerprint = fp
            engine._groups[fp] = finding
        return engine

    def clear(self) -> None:
        with self._lock:
            self._groups.clear()

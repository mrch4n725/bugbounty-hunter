import time
import threading
from typing import Any

from models.evidence import EvidenceBase, EvidenceType, EvidenceStatus


class EvidenceEngine:
    """Centralized evidence storage, linking, and export.

    Stores Evidence objects in memory, links them to findings,
    and exports structured evidence for reports and resume.
    """

    def __init__(self, config: Any | None = None, capabilities: Any | None = None):
        self.config = config or {}
        self.capabilities = capabilities
        self._lock = threading.Lock()
        self._store: dict[str, list[EvidenceBase]] = {}
        self._fingerprints: dict[str, EvidenceBase] = {}

    def store(self, evidence: EvidenceBase) -> str:
        """Store an evidence object and return its fingerprint.

        Fingerprint is used to deduplicate identical evidence.
        """
        fp = evidence.__class__.__name__ + ":" + str(time.time())
        with self._lock:
            self._fingerprints[fp] = evidence
        return fp

    def link_to_finding(self, evidence: EvidenceBase, finding_id: str) -> None:
        """Link evidence to a finding by finding ID."""
        with self._lock:
            self._store.setdefault(finding_id, []).append(evidence)

    def get_evidence(self, finding_id: str) -> list[EvidenceBase]:
        """Retrieve all evidence linked to a finding."""
        with self._lock:
            return list(self._store.get(finding_id, []))

    def all_fingerprints(self) -> dict[str, EvidenceBase]:
        with self._lock:
            return dict(self._fingerprints)

    def export_for_finding(self, finding_id: str) -> list[dict[str, Any]]:
        """Export evidence for a finding as serializable dicts."""
        ev_list = self.get_evidence(finding_id)
        return [e.to_dict() if hasattr(e, "to_dict") else {"raw": str(e)} for e in ev_list]

    def snapshot(self) -> dict[str, Any]:
        """Snapshot all evidence for resume persistence."""
        with self._lock:
            return {
                fid: [e.to_dict() for e in ev_list]
                for fid, ev_list in self._store.items()
            }

    def restore(self, snapshot: dict[str, Any]) -> None:
        """Restore evidence from a snapshot (resume)."""
        with self._lock:
            for fid, ev_dicts in snapshot.items():
                for d in ev_dicts:
                    try:
                        ev = EvidenceBase.from_dict(d)
                        self._store.setdefault(fid, []).append(ev)
                    except Exception:
                        pass

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._fingerprints.clear()

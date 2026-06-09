import hashlib
import json
import os
import sqlite3
import threading
from typing import Any

from models.evidence import EvidenceBase, EvidenceType, EvidenceStatus


class EvidenceEngine:
    """Centralized evidence storage, linking, and export.

    Stores Evidence objects in memory, links them to findings,
    and exports structured evidence for reports and resume.

    When config['evidence_db_path'] is set, persists all evidence to
    SQLite with WAL mode for concurrent read/write access.  Batch
    inserts are used within a transaction via batch_insert() context
    manager.
    """

    def __init__(self, config: Any | None = None, capabilities: Any | None = None):
        self.config = config or {}
        self.capabilities = capabilities
        self._lock = threading.Lock()
        self._store: dict[str, list[EvidenceBase]] = {}
        self._fingerprints: dict[str, EvidenceBase] = {}
        self._db_path = self.config.get("evidence_db_path", "")
        self._db_conn: sqlite3.Connection | None = None
        self._batch_depth = 0
        if self._db_path:
            self._init_db()

    def _init_db(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
            self._db_conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._db_conn.execute("PRAGMA journal_mode=WAL")
            self._db_conn.execute("PRAGMA synchronous=NORMAL")
            self._db_conn.execute("""CREATE TABLE IF NOT EXISTS evidence (
                fingerprint TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                data TEXT NOT NULL
            )""")
            self._db_conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence(finding_id)")
            self._db_conn.commit()
            self._load_from_db()
        except Exception:
            self._db_conn = None

    def _load_from_db(self) -> None:
        if not self._db_conn:
            return
        try:
            cursor = self._db_conn.execute(
                "SELECT fingerprint, finding_id, evidence_type, data FROM evidence"
            )
            for fp, fid, etype, data in cursor.fetchall():
                try:
                    d = json.loads(data)
                    ev = EvidenceBase.from_dict(d)
                    self._fingerprints[fp] = ev
                    self._store.setdefault(fid, []).append(ev)
                except Exception:
                    pass
        except Exception:
            pass

    def _db_insert(self, fp: str, finding_id: str, evidence: EvidenceBase) -> None:
        if not self._db_conn:
            return
        try:
            data = json.dumps(evidence.to_dict(), default=str)
            if self._batch_depth > 0:
                self._db_conn.execute(
                    "INSERT OR REPLACE INTO evidence (fingerprint, finding_id, evidence_type, data) VALUES (?, ?, ?, ?)",
                    (fp, finding_id, evidence.__class__.__name__, data),
                )
            else:
                self._db_conn.execute(
                    "INSERT OR REPLACE INTO evidence (fingerprint, finding_id, evidence_type, data) VALUES (?, ?, ?, ?)",
                    (fp, finding_id, evidence.__class__.__name__, data),
                )
                self._db_conn.commit()
        except Exception:
            pass

    def batch_insert(self) -> "EvidenceEngine":
        """Context manager for batched SQLite inserts (single transaction).

        Usage:
            with engine.batch_insert():
                engine.store(ev1)
                engine.link_to_finding(ev1, fid)
                engine.store(ev2)
                engine.link_to_finding(ev2, fid)
        """
        self._batch_depth += 1
        return self

    def __enter__(self) -> "EvidenceEngine":
        return self

    def __exit__(self, *args: Any) -> None:
        self._batch_depth -= 1
        if self._batch_depth == 0 and self._db_conn:
            try:
                self._db_conn.commit()
            except Exception:
                pass

    def store(self, evidence: EvidenceBase) -> str:
        """Store an evidence object and return its fingerprint.

        Fingerprint is a SHA-256 of the evidence's serialized content
        (minus timestamp), enabling deduplication of identical evidence.
        When SQLite is enabled, the evidence is also persisted.
        """
        fp = self._fingerprint(evidence)
        with self._lock:
            if fp not in self._fingerprints:
                self._fingerprints[fp] = evidence
        self._db_insert(fp, "", evidence)
        return fp

    def link_to_finding(self, evidence: EvidenceBase, finding_id: str) -> None:
        """Link evidence to a finding by finding ID.

        When SQLite is enabled, the finding_id is persisted alongside
        the evidence record.
        """
        with self._lock:
            self._store.setdefault(finding_id, []).append(evidence)
        fp = self._fingerprint(evidence)
        self._db_insert(fp, finding_id, evidence)

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
        return [e.to_dict() for e in ev_list]

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
                        # Populate fingerprints for dedup after restore
                        fp = self._fingerprint(ev)
                        if fp not in self._fingerprints:
                            self._fingerprints[fp] = ev
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).warning(
                            "EvidenceEngine.restore: skipped evidence %s: %s",
                            d.get("evidence_type", "?"), e)

    @staticmethod
    def _fingerprint(evidence: EvidenceBase) -> str:
        d = evidence.to_dict()
        d.pop("timestamp", None)
        d.pop("id", None)
        raw = evidence.__class__.__name__ + ":" + json.dumps(d, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get_orphaned_evidence(self) -> list[EvidenceBase]:
        """Return evidence items in _fingerprints that are NOT linked to any finding_id in _store."""
        with self._lock:
            linked: set[str] = set()
            for ev_list in self._store.values():
                for ev in ev_list:
                    linked.add(self._fingerprint(ev))
            return [ev for fp, ev in self._fingerprints.items() if fp not in linked]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._fingerprints.clear()

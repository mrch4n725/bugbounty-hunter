import json
import os
import sqlite3
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any

BBH_DIR = os.path.expanduser("~/.bbh")
SCAN_HISTORY_DB = os.path.join(BBH_DIR, "scan_history.db")


def _ensure_bbh_dir() -> str:
    try:
        os.makedirs(BBH_DIR, exist_ok=True)
        return BBH_DIR
    except OSError:
        fallback = tempfile.mkdtemp(prefix="bbh_")
        print(f"[!] Could not create ~/.bbh/, using {fallback}")
        return fallback


class ScanHistoryDB:
    def __init__(self, db_path: str | None = None):
        _ensure_bbh_dir()
        self._db_path = db_path or SCAN_HISTORY_DB
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self):
        with self._lock:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    programme_handle TEXT,
                    scanned_at TEXT,
                    findings_critical INTEGER DEFAULT 0,
                    findings_high INTEGER DEFAULT 0,
                    findings_medium INTEGER DEFAULT 0,
                    findings_low INTEGER DEFAULT 0,
                    submitted INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS my_findings (
                    fingerprint TEXT PRIMARY KEY,
                    programme_handle TEXT,
                    vuln_type TEXT,
                    url TEXT,
                    severity TEXT,
                    first_found TEXT,
                    submitted INTEGER DEFAULT 0,
                    outcome TEXT
                );
            """)
            self._conn.commit()

    def record_scan(self, target: str, programme_handle: str, findings: list,
                    severity_counts: dict[str, int] | None = None) -> int:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if severity_counts is None:
            sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                if isinstance(f, dict):
                    s = f.get("severity", "low").lower()
                else:
                    s = getattr(f, "severity", "low").lower()
                if s in sev:
                    sev[s] = sev.get(s, 0) + 1
            severity_counts = sev
        with self._lock:
            self._ensure_conn()
            cursor = self._conn.execute(
                """INSERT INTO scans
                    (target, programme_handle, scanned_at,
                     findings_critical, findings_high, findings_medium, findings_low)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (target, programme_handle, now,
                 severity_counts.get("critical", 0),
                 severity_counts.get("high", 0),
                 severity_counts.get("medium", 0),
                 severity_counts.get("low", 0)),
            )
            self._conn.commit()
            return cursor.lastrowid or 0

    def record_finding_outcome(self, fingerprint: str, programme_handle: str,
                                vuln_type: str, url: str, severity: str,
                                outcome: str = "pending"):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            self._ensure_conn()
            self._conn.execute(
                """INSERT OR REPLACE INTO my_findings
                    (fingerprint, programme_handle, vuln_type, url, severity,
                     first_found, submitted, outcome)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)""",
                (fingerprint, programme_handle, vuln_type, url, severity, now, outcome),
            )
            self._conn.commit()

    def get_previous_outcomes(self, programme_handle: str) -> dict[str, str]:
        with self._lock:
            self._ensure_conn()
            rows = self._conn.execute(
                "SELECT fingerprint, outcome FROM my_findings WHERE programme_handle = ?",
                (programme_handle,),
            ).fetchall()
            return {row["fingerprint"]: row["outcome"] for row in rows}

    def get_scan_count(self, programme_handle: str) -> int:
        with self._lock:
            self._ensure_conn()
            row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM scans WHERE programme_handle = ?",
                (programme_handle,),
            ).fetchone()
            return row["cnt"] if row else 0

    def _ensure_conn(self):
        if self._conn is None:
            self._init_db()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

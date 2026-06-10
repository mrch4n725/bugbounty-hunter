"""Scan audit logger — records every HTTP request sent during a scan."""

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any


class AuditLogger:
    BATCH_SIZE = 100

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self._lock = threading.Lock()
        self._buffer: list[tuple] = []
        self._closed = False
        self._filepath: str | None = None
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._filepath = os.path.join(self.output_dir, f"audit_scan_{ts}.db")
        os.makedirs(self.output_dir, exist_ok=True)
        self._conn = sqlite3.connect(self._filepath, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            method TEXT,
            url TEXT,
            status_code INTEGER,
            response_time_ms INTEGER,
            headers_json TEXT,
            body_preview TEXT,
            event_type TEXT
        )""")
        self._conn.execute("""CREATE INDEX IF NOT EXISTS idx_audit_url ON audit(url)""")
        self._conn.commit()

    def log_request(self, method: str, url: str, headers: dict,
                    status_code: int, response_time_ms: int,
                    body_preview: str = "") -> None:
        self._write((
            datetime.now(timezone.utc).isoformat(),
            method.upper(),
            url,
            status_code,
            response_time_ms,
            json.dumps(dict(headers), default=str, ensure_ascii=False)[:2000],
            body_preview[:500],
            "request",
        ))

    def log_finding(self, finding: dict) -> None:
        self._write((
            datetime.now(timezone.utc).isoformat(),
            "FINDING",
            finding.get("url", ""),
            None,
            None,
            "",
            json.dumps(finding, default=str, ensure_ascii=False)[:1000],
            "finding",
        ))

    def log_event(self, message: str, event_type: str = "info") -> None:
        self._write((
            datetime.now(timezone.utc).isoformat(),
            "",
            "",
            None,
            None,
            "",
            message[:500],
            event_type,
        ))

    def _write(self, row: tuple) -> None:
        with self._lock:
            if self._closed:
                return
            self._buffer.append(row)
            if len(self._buffer) >= self.BATCH_SIZE:
                self._flush()

    def _flush(self) -> None:
        if not self._buffer or self._conn is None:
            return
        try:
            self._conn.executemany(
                """INSERT INTO audit (timestamp, method, url, status_code,
                   response_time_ms, headers_json, body_preview, event_type)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                self._buffer,
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
        self._buffer.clear()

    def save(self) -> str:
        with self._lock:
            self._flush()
            return self._filepath or ""

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._flush()
            if self._conn is not None:
                try:
                    self._conn.execute("PRAGMA optimize")
                    self._conn.commit()
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None

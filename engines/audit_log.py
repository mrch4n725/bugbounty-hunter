"""Scan audit logger — records every HTTP request sent during a scan."""

import csv
import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any


class AuditLogger:
    BATCH_SIZE = 100
    HEADERS = ["timestamp", "method", "url", "status_code", "response_time_ms",
               "headers_json", "body_preview", "event_type"]

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self._lock = threading.Lock()
        self._buffer: list[list[Any]] = []
        self._closed = False
        self._filepath: str | None = None
        self._file_handle = None

    def log_request(self, method: str, url: str, headers: dict,
                    status_code: int, response_time_ms: int,
                    body_preview: str = "") -> None:
        self._write([
            datetime.now(timezone.utc).isoformat(),
            method.upper(),
            url,
            str(status_code),
            str(response_time_ms),
            json.dumps(dict(headers), default=str, ensure_ascii=False),
            body_preview[:500],
            "request",
        ])

    def log_finding(self, finding: dict) -> None:
        self._write([
            datetime.now(timezone.utc).isoformat(),
            "FINDING",
            finding.get("url", ""),
            "",
            "",
            "",
            json.dumps(finding, default=str, ensure_ascii=False)[:1000],
            "finding",
        ])

    def log_event(self, message: str, event_type: str = "info") -> None:
        self._write([
            datetime.now(timezone.utc).isoformat(),
            "",
            "",
            "",
            "",
            "",
            message[:500],
            event_type,
        ])

    def _write(self, row: list[Any]) -> None:
        with self._lock:
            if self._closed:
                return
            self._buffer.append(row)
            if len(self._buffer) >= self.BATCH_SIZE:
                self._flush()

    def _flush(self) -> None:
        if not self._buffer:
            return
        if self._file_handle is None:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            self._filepath = os.path.join(self.output_dir, f"audit_scan_{ts}.csv")
            os.makedirs(self.output_dir, exist_ok=True)
            self._file_handle = open(self._filepath, "w", newline="", encoding="utf-8")
            writer = csv.writer(self._file_handle)
            writer.writerow(self.HEADERS)
        writer = csv.writer(self._file_handle)
        for row in self._buffer:
            writer.writerow(row)
        self._file_handle.flush()
        self._buffer.clear()

    def save(self) -> str:
        with self._lock:
            self._flush()
            if self._file_handle is not None:
                self._file_handle.flush()
            return self._filepath or ""

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._flush()
            if self._file_handle is not None:
                self._file_handle.close()
                self._file_handle = None

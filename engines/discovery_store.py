"""DiscoveryStore — SQLite-backed persistent store for discovery intelligence.

Stores and retrieves discovered objects (IDs, endpoints, params) across
scans so intelligence accumulates rather than starting from zero each run.
"""

import hashlib
import json
import sqlite3
import threading
import time
from typing import Any


class DiscoveryStore:
    """Thread-safe SQLite-backed store for cross-scan discovery intelligence.

    Records are keyed by a SHA-256 fingerprint of the category+value to avoid
    duplicates. Each record carries a source URL, a category tag, and a
    human-readable value.

    Schema:
      discovered (
        fingerprint TEXT PRIMARY KEY,
        category    TEXT NOT NULL,
        value       TEXT NOT NULL,
        source_url  TEXT,
        extra       TEXT,
        first_seen  REAL NOT NULL,
        last_seen   REAL NOT NULL,
        hit_count   INTEGER DEFAULT 1
      )
    """

    def __init__(self, db_path: str = ""):
        self._db_path = db_path or ":memory:"
        self._lock = threading.Lock()
        self._connection: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(self._db_path, timeout=10)
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
        return self._connection

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS discovered (
                    fingerprint TEXT PRIMARY KEY,
                    category    TEXT NOT NULL,
                    value       TEXT NOT NULL,
                    source_url  TEXT,
                    extra       TEXT,
                    first_seen  REAL NOT NULL,
                    last_seen   REAL NOT NULL,
                    hit_count   INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_discovered_category
                ON discovered(category)
            """)
            conn.commit()

    @staticmethod
    def _make_fingerprint(category: str, value: str) -> str:
        return hashlib.sha256(f"{category}:{value}".encode()).hexdigest()

    def record(self, category: str, value: str, source_url: str = "",
               extra: dict | None = None) -> None:
        """Record a discovered object, deduplicating by (category, value)."""
        if not value or not category:
            return
        fingerprint = self._make_fingerprint(category, value)
        now = time.time()
        extra_json = json.dumps(extra or {})

        with self._lock:
            conn = self._get_conn()
            existing = conn.execute(
                "SELECT fingerprint FROM discovered WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()

            if existing:
                conn.execute("""
                    UPDATE discovered SET last_seen = ?, hit_count = hit_count + 1
                    WHERE fingerprint = ?
                """, (now, fingerprint))
            else:
                conn.execute("""
                    INSERT INTO discovered
                    (fingerprint, category, value, source_url, extra, first_seen, last_seen, hit_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """, (fingerprint, category, value, source_url, extra_json, now, now))
            conn.commit()

    def get_by_category(self, category: str) -> list[dict[str, Any]]:
        """Return all records matching a category, newest first."""
        with self._lock:
            rows = self._get_conn().execute("""
                SELECT category, value, source_url, extra, first_seen, last_seen, hit_count
                FROM discovered WHERE category = ?
                ORDER BY last_seen DESC
            """, (category,)).fetchall()
        result = []
        for row in rows:
            result.append({
                "category": row[0],
                "value": row[1],
                "source_url": row[2],
                "extra": json.loads(row[3]) if row[3] else {},
                "first_seen": row[4],
                "last_seen": row[5],
                "hit_count": row[6],
            })
        return result

    def get_all_categories(self) -> list[str]:
        with self._lock:
            rows = self._get_conn().execute(
                "SELECT DISTINCT category FROM discovered ORDER BY category"
            ).fetchall()
        return [r[0] for r in rows]

    def count(self, category: str | None = None) -> int:
        with self._lock:
            if category:
                row = self._get_conn().execute(
                    "SELECT COUNT(*) FROM discovered WHERE category = ?", (category,)
                ).fetchone()
            else:
                row = self._get_conn().execute("SELECT COUNT(*) FROM discovered").fetchone()
        return row[0] if row else 0

    def get_stats(self) -> dict[str, Any]:
        categories = self.get_all_categories()
        total = self.count()
        return {
            "total_records": total,
            "num_categories": len(categories),
            "categories": categories,
        }

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

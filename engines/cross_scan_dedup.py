import hashlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from models.finding import Finding, compute_fingerprint


class CrossScanDatabase:
    """Persist findings across scans using SQLite for cross-session dedup and regression detection."""

    def __init__(self, config: dict | None = None):
        self._config = config or {}
        db_path = self._config.get("cross_scan_db_path", "cross_scan.db")
        self._db_path = str(Path(db_path).resolve())
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    # ── Schema ──────────────────────────────────────────────────────────────

    def _init_db(self):
        with self._lock:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS findings (
                    fingerprint TEXT PRIMARY KEY,
                    vuln_type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    parameter TEXT DEFAULT '',
                    severity TEXT DEFAULT 'info',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_status TEXT DEFAULT 'present',
                    last_confidence INTEGER DEFAULT 0,
                    last_verification_stage TEXT DEFAULT 'detected',
                    scan_count INTEGER DEFAULT 1,
                    metadata TEXT DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_status ON findings(last_status);
                CREATE INDEX IF NOT EXISTS idx_type ON findings(vuln_type);

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    finding_count INTEGER DEFAULT 0,
                    config TEXT DEFAULT '{}',
                    ended INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS scan_findings (
                    scan_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    PRIMARY KEY (scan_id, fingerprint),
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
                    FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint)
                );
            """)
            self._conn.commit()

    def _ensure_connection(self):
        if self._conn is None:
            self._init_db()

    # ── Core methods ────────────────────────────────────────────────────────

    def record_findings(self, findings: list[Finding | dict], scan_id: str) -> list[dict]:
        """Upsert each finding by fingerprint. Returns regressed findings list."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        regressed = []

        with self._lock:
            self._ensure_connection()
            for item in findings:
                if isinstance(item, Finding):
                    fp = item.fingerprint or compute_fingerprint(item.vuln_type, item.url, item.parameter)
                    vuln_type = item.vuln_type
                    url = item.url
                    parameter = item.parameter
                    severity = item.severity
                    confidence = item.confidence_score
                    stage = item.verification_stage
                else:
                    fp = item.get("fingerprint", "")
                    if not fp:
                        fp = compute_fingerprint(
                            item.get("vuln_type", item.get("type", "")),
                            item.get("url", ""),
                            item.get("parameter", ""),
                        )
                    vuln_type = item.get("vuln_type", item.get("type", ""))
                    url = item.get("url", "")
                    parameter = item.get("parameter", "")
                    severity = item.get("severity", "info")
                    confidence = item.get("confidence_score", 0)
                    stage = item.get("verification_stage", "detected")

                row = self._conn.execute(
                    "SELECT last_status FROM findings WHERE fingerprint = ?", (fp,)
                ).fetchone()

                if row:
                    prev_status = row["last_status"]
                    self._conn.execute(
                        """UPDATE findings SET
                            last_seen = ?, severity = ?, last_confidence = ?,
                            last_verification_stage = ?, scan_count = scan_count + 1,
                            last_status = 'present'
                        WHERE fingerprint = ?""",
                        (now, severity, confidence, stage, fp),
                    )
                    if prev_status == "fixed":
                        regressed.append(dict(
                            fingerprint=fp,
                            vuln_type=vuln_type,
                            url=url,
                            parameter=parameter,
                            severity=severity,
                        ))
                else:
                    self._conn.execute(
                        """INSERT INTO findings
                            (fingerprint, vuln_type, url, parameter, severity,
                             first_seen, last_seen, last_status,
                             last_confidence, last_verification_stage, scan_count, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'present', ?, ?, 1, '{}')""",
                        (fp, vuln_type, url, parameter, severity,
                         now, now, confidence, stage),
                    )

                self._conn.execute(
                    "INSERT OR IGNORE INTO scan_findings (scan_id, fingerprint) VALUES (?, ?)",
                    (scan_id, fp),
                )

            # Mark regressed findings in the database
            for r in regressed:
                self._conn.execute(
                    "UPDATE findings SET last_status = 'regressed' WHERE fingerprint = ?",
                    (r["fingerprint"],),
                )

            self._conn.commit()

        return regressed

    def mark_fixed(self, fingerprints: set[str]):
        """Set last_status='fixed' for fingerprints not in current scan."""
        if not fingerprints:
            return
        with self._lock:
            self._ensure_connection()
            placeholders = ",".join("?" for _ in fingerprints)
            self._conn.execute(
                f"""UPDATE findings SET last_status = 'fixed'
                    WHERE fingerprint IN ({placeholders})
                      AND last_status IN ('present', 'regressed')""",
                list(fingerprints),
            )
            self._conn.commit()

    def get_status(self, fingerprint: str) -> str | None:
        """Return 'present', 'fixed', 'regressed', or None if unknown."""
        with self._lock:
            self._ensure_connection()
            row = self._conn.execute(
                "SELECT last_status FROM findings WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            return row["last_status"] if row else None

    def get_findings_by_status(self, status: str) -> list[dict]:
        """Get all findings with given status."""
        with self._lock:
            self._ensure_connection()
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE last_status = ? ORDER BY last_seen DESC",
                (status,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_regressions(self, since: str = None) -> list[dict]:
        """Findings where status changed from 'fixed' to 'present' (now 'regressed')."""
        with self._lock:
            self._ensure_connection()
            if since:
                rows = self._conn.execute(
                    "SELECT * FROM findings WHERE last_status = 'regressed' AND last_seen >= ? ORDER BY last_seen DESC",
                    (since,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM findings WHERE last_status = 'regressed' ORDER BY last_seen DESC",
                ).fetchall()
            return [dict(r) for r in rows]

    def get_summary(self) -> dict:
        """Counts by status."""
        with self._lock:
            self._ensure_connection()
            present = self._conn.execute(
                "SELECT COUNT(*) FROM findings WHERE last_status = 'present'"
            ).fetchone()[0]
            fixed = self._conn.execute(
                "SELECT COUNT(*) FROM findings WHERE last_status = 'fixed'"
            ).fetchone()[0]
            regressed = self._conn.execute(
                "SELECT COUNT(*) FROM findings WHERE last_status = 'regressed'"
            ).fetchone()[0]
            total = self._conn.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]
            return {
                "present": present,
                "fixed": fixed,
                "regressed": regressed,
                "total_unique": total,
            }

    def get_finding(self, fingerprint: str) -> dict | None:
        """Get a single finding by fingerprint."""
        with self._lock:
            self._ensure_connection()
            row = self._conn.execute(
                "SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            return dict(row) if row else None

    def get_scan_history(self, fingerprint: str) -> list[str]:
        """Scan IDs where this finding appeared."""
        with self._lock:
            self._ensure_connection()
            rows = self._conn.execute(
                "SELECT scan_id FROM scan_findings WHERE fingerprint = ? ORDER BY scan_id",
                (fingerprint,),
            ).fetchall()
            return [r["scan_id"] for r in rows]

    def list_scans(self) -> list[dict]:
        """All scans with finding counts."""
        with self._lock:
            self._ensure_connection()
            rows = self._conn.execute(
                """SELECT s.*, COALESCE(cnt.c, 0) AS finding_count
                   FROM scans s
                   LEFT JOIN (SELECT scan_id, COUNT(*) AS c FROM scan_findings GROUP BY scan_id) cnt
                     ON s.scan_id = cnt.scan_id
                   ORDER BY s.timestamp DESC""",
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Scan context ────────────────────────────────────────────────────────

    def start_scan(self, scan_id: str, target: str, config_snapshot: dict) -> bool:
        """Record scan start. Returns True if new, False if already exists."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            self._ensure_connection()
            existing = self._conn.execute(
                "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if existing:
                return False
            self._conn.execute(
                "INSERT INTO scans (scan_id, target, timestamp, finding_count, config) VALUES (?, ?, ?, 0, ?)",
                (scan_id, target, now, json.dumps(config_snapshot)),
            )
            self._conn.commit()
            return True

    def end_scan(self, scan_id: str, finding_count: int):
        """Record scan end with finding count."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            self._ensure_connection()
            self._conn.execute(
                "UPDATE scans SET finding_count = ?, ended = 1 WHERE scan_id = ?",
                (finding_count, scan_id),
            )
            self._conn.commit()

    def get_scan(self, scan_id: str) -> dict | None:
        """Get scan info by ID."""
        with self._lock:
            self._ensure_connection()
            row = self._conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            return dict(row) if row else None

    # ── Dedup helpers ───────────────────────────────────────────────────────

    def is_known(self, fingerprint: str) -> bool:
        """Check if finding was seen before."""
        with self._lock:
            self._ensure_connection()
            row = self._conn.execute(
                "SELECT 1 FROM findings WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            return row is not None

    def is_fixed(self, fingerprint: str) -> bool:
        """Check if finding was previously fixed."""
        return self.get_status(fingerprint) == "fixed"

    def note_seen(self, fingerprint: str, finding: dict):
        """Update seen status without full upsert — lightweight touch."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            self._ensure_connection()
            row = self._conn.execute(
                "SELECT last_status FROM findings WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if row:
                self._conn.execute(
                    "UPDATE findings SET last_seen = ?, scan_count = scan_count + 1 WHERE fingerprint = ?",
                    (now, fingerprint),
                )
            else:
                vuln_type = finding.get("vuln_type", finding.get("type", ""))
                url = finding.get("url", "")
                parameter = finding.get("parameter", "")
                severity = finding.get("severity", "info")
                confidence = finding.get("confidence_score", 0)
                stage = finding.get("verification_stage", "detected")
                self._conn.execute(
                    """INSERT INTO findings
                        (fingerprint, vuln_type, url, parameter, severity,
                         first_seen, last_seen, last_status,
                         last_confidence, last_verification_stage, scan_count, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'present', ?, ?, 1, '{}')""",
                    (fingerprint, vuln_type, url, parameter, severity,
                     now, now, confidence, stage),
                )
            self._conn.commit()

    # ── Cleanup ─────────────────────────────────────────────────────────────

    def close(self):
        """Close SQLite connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    def vacuum(self):
        """Reclaim space."""
        with self._lock:
            self._ensure_connection()
            self._conn.execute("VACUUM")
            self._conn.commit()

    def prune(self, days: int = 90):
        """Remove findings not seen in N days."""
        with self._lock:
            self._ensure_connection()
            cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
            cutoff_iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._conn.execute(
                "DELETE FROM findings WHERE last_seen < ?",
                (cutoff_iso,),
            )
            self._conn.execute(
                "DELETE FROM scan_findings WHERE fingerprint NOT IN (SELECT fingerprint FROM findings)"
            )
            self._conn.execute(
                "DELETE FROM scans WHERE scan_id NOT IN (SELECT DISTINCT scan_id FROM scan_findings)"
            )
            self._conn.commit()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


VULN_TYPE_TO_CWE: dict[str, str] = {
    "xss": "Cross-site Scripting",
    "xss reflected": "Cross-site Scripting",
    "xss stored": "Cross-site Scripting",
    "reflected xss": "Cross-site Scripting",
    "stored xss": "Cross-site Scripting",
    "dom xss": "Cross-site Scripting",
    "blind xss": "Cross-site Scripting",
    "sqli": "SQL Injection",
    "sql injection": "SQL Injection",
    "sql injection (error-based)": "SQL Injection",
    "sql injection (blind)": "SQL Injection",
    "sql injection (time-based)": "SQL Injection",
    "ssrf": "Server-Side Request Forgery",
    "server-side request forgery": "Server-Side Request Forgery",
    "xxe": "XML External Entity (XXE) Injection",
    "xml external entity": "XML External Entity (XXE) Injection",
    "ssti": "Server-Side Template Injection",
    "server-side template injection": "Server-Side Template Injection",
    "lfi": "Local File Inclusion",
    "local file inclusion": "Local File Inclusion",
    "path traversal": "Local File Inclusion",
    "command injection": "Command Injection",
    "cmd injection": "Command Injection",
    "cmdi": "Command Injection",
    "open redirect": "Open Redirect",
    "open_redirect": "Open Redirect",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "insecure direct object reference": "Insecure Direct Object Reference (IDOR)",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "cross-site request forgery": "Cross-Site Request Forgery (CSRF)",
    "jwt": "JSON Web Token (JWT)",
    "cors": "Cross-Origin Resource Sharing (CORS)",
    "api": "Broken Object Level Authorization",
    "bola": "Broken Object Level Authorization",
    "graphql": "GraphQL Injection",
    "clickjacking": "Clickjacking",
    "subdomain takeover": "Subdomain Takeover",
    "subdomain_takeover": "Subdomain Takeover",
    "rate limiting": "Rate Limiting",
    "rate_limiting": "Rate Limiting",
    "business logic": "Business Logic Error",
    "business_logic": "Business Logic Error",
    "auth bypass": "Authentication Bypass",
    "auth_bypass": "Authentication Bypass",
    "smuggling": "HTTP Request Smuggling",
    "information disclosure": "Information Disclosure",
    "sensitive data": "Sensitive Data Exposure",
    "exposed files": "Sensitive Data Exposure",
    "exposed_files": "Sensitive Data Exposure",
    "default credentials": "Use of Default Credentials",
    "default_credentials": "Use of Default Credentials",
}


def extract_domain(url: str) -> str:
    from urllib.parse import urlparse
    try:
        if "://" not in url:
            url = "//" + url
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def is_likely_duplicate(
    finding: dict | Any,
    intel: Any,
    days: int = 90,
) -> tuple[bool, str]:
    from datetime import datetime, timezone, timedelta
    if hasattr(intel, "disclosed_reports"):
        reports = intel.disclosed_reports
    else:
        reports = intel.get("disclosed_reports", [])
    if not reports:
        return False, ""
    vuln_type = ""
    if isinstance(finding, dict):
        vuln_type = (finding.get("vuln_type") or finding.get("type") or "").lower()
        finding_url = finding.get("url", "")
    else:
        vuln_type = (getattr(finding, "vuln_type", None) or "").lower()
        finding_url = getattr(finding, "url", "")
    domain = extract_domain(finding_url)
    if not domain:
        return False, ""
    cwe_name = None
    for key, val in VULN_TYPE_TO_CWE.items():
        if key in vuln_type or vuln_type in key or vuln_type == key:
            cwe_name = val
            break
    if not cwe_name:
        return False, ""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    for r in reports:
        if hasattr(r, "asset") and hasattr(r, "weakness"):
            report_domain = extract_domain(r.asset)
            report_weakness = r.weakness
            try:
                r_date = datetime.fromisoformat(r.disclosed_at.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                r_date = datetime.now(timezone.utc)
        else:
            report_domain = extract_domain(r.get("asset", ""))
            report_weakness = r.get("weakness", "")
            try:
                r_date = datetime.fromisoformat(r.get("disclosed_at", "").replace("Z", "+00:00"))
            except (ValueError, TypeError):
                r_date = datetime.now(timezone.utc)
        if r_date < cutoff:
            continue
        if not report_domain:
            continue
        same_domain = (domain == report_domain) or domain.endswith("." + report_domain) or report_domain.endswith("." + domain)
        if same_domain and report_weakness and cwe_name.lower() in report_weakness.lower():
            days_ago = (datetime.now(timezone.utc) - r_date).days
            report_id = getattr(r, "id", "") or ""
            id_suffix = f" (H1 report #{report_id})" if report_id else ""
            reason = f"{report_weakness} on {report_domain} was disclosed {days_ago} days ago{id_suffix}"
            return True, reason
    return False, ""

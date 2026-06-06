"""
ExposedFilesScanner — discovers publicly accessible sensitive files.

Lifecycle:
  DETECTED:   (not applicable)
  VALIDATED:  File returns HTTP 200 with valid content
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 2 (Detect + Validate)
"""

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence

EXPOSED_FILES = [
    ".env", ".env.local", ".env.backup", "/.git/config", "/.gitignore",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/phpinfo.php",
    "/wp-config.php", "/wp-config.php.bak", "/.DS_Store", "/web.config",
    "/web.config.bak", "/config.php", "/config.xml", "/.htaccess",
    "/.htpasswd", "/web.xml", "/pom.xml", "/.aws/credentials",
    "/.ssh/id_rsa", "/Dockerfile", "/.dockerignore", "/docker-compose.yml",
    "/secrets.txt", "/passwords.txt", "/.env.example",
]


class ExposedFilesScanner(ScannerBase):
    SCANNER_NAME = "exposed_files"
    TARGET_LEVEL = True
    SCANNER_ORDER = 20

    @staticmethod
    def _file_metadata(path: str) -> tuple[str, str]:
        lower = path.lower()
        if ".env" in path or "config" in lower:
            return "critical", "Configuration file containing potential secrets is accessible"
        if "backup" in lower:
            return "high", "Backup archive is publicly accessible"
        if ".git" in path or ".DS_Store" in path:
            return "high", "Version control metadata is exposed"
        if "phpinfo" in path:
            return "high", "PHP information disclosure via phpinfo()"
        if ".ssh" in path or ".aws" in path:
            return "critical", "Credentials file is publicly accessible"
        return "critical", "Sensitive file is publicly accessible"

    @staticmethod
    def _validate_content(path: str, body: str, raw: bytes) -> bool:
        ext = path.lower()
        if ".env" in ext:
            return "=" in body
        if "/.git/config" in ext:
            return "[core]" in body
        if "phpinfo" in ext:
            return "PHP Version" in body
        if ext.endswith(".zip"):
            return raw[:2] == b"PK"
        if ext.endswith(".gz") or ext.endswith(".tar.gz"):
            return raw[:2] == b"\x1f\x8b"
        if ext.endswith(".sql"):
            return any(body.lstrip().startswith(w) for w in ("-- ", "CREATE", "INSERT", "DROP", "ALTER", "SELECT"))
        return True

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        target_base = self.base_url
        for exposed_path in EXPOSED_FILES:
            try:
                file_url = target_base + exposed_path
                if not self._in_scope(file_url):
                    continue
                resp = safe_get(self.session, file_url, self.timeout, raise_for_status=False)
                if not (resp and resp.status_code == 200):
                    continue
                body = resp.text
                raw = resp.content
                severity, details = self._file_metadata(exposed_path)
                content_ok = self._validate_content(exposed_path, body, raw)
                if not content_ok:
                    severity = "info"
                    details += " (content check failed — may be a generic 200 response)"

                req_ev = HttpRequestEvidence(
                    method="GET",
                    url=file_url,
                    curl_command=_build_curl("GET", file_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                )
                resp_ev = ResponseExcerptEvidence(
                    excerpt=body[:500],
                    length=len(body),
                    context="exposed_file",
                )
                req_fp = self.evidence_engine.store(req_ev)
                resp_fp = self.evidence_engine.store(resp_ev)

                f = finding(
                    vuln_type="Exposed Sensitive File",
                    url=file_url,
                    severity=severity,
                    details=details,
                    evidence=f"HTTP {resp.status_code} — {len(body)} bytes",
                    request=_build_curl("GET", file_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                    response_excerpt=body[:500],
                    steps_to_reproduce=[f"Send request to {file_url}", f"Observe: {details[:100]}"],
                    verification_stage=VerificationStage.VALIDATED.value,
                )
                if f:
                    self.evidence_engine.link_to_finding(req_ev, f.get("fingerprint", ""))
                    self.evidence_engine.link_to_finding(resp_ev, f.get("fingerprint", ""))
                    self._add_finding(f)
                log(f"  [EXPOSED] {file_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

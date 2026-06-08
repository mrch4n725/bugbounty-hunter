"""
ExposedFilesScanner — discovers publicly accessible sensitive files.

Lifecycle:
  DETECTED:   (not applicable)
  VALIDATED:  File returns HTTP 200 with valid content
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate + typed evidence + reproduction)
"""

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
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
    SCANNER_MATURITY = 3
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

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
        if not (resp and resp.status_code == 200):
            return None
        return DetectionResult(
            url=url,
            parameter="",
            payload="200",
            context="exposed_file",
            raw_response=resp,
            evidence_signals=[f"HTTP 200 — {len(resp.text)} bytes"],
        )

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        resp = detection.raw_response
        if not resp:
            return ValidationResult(confirmed=False, method="content_validation", detail="No response body to validate")
        path = detection.url.split(self.base_url)[-1] if self.base_url in detection.url else ""
        body = resp.text
        raw = resp.content
        content_ok = self._validate_content(path, body, raw)
        if content_ok:
            return ValidationResult(confirmed=True, method="content_validation",
                                    detail=f"Content validation passed for {path}")
        return ValidationResult(confirmed=False, method="content_validation",
                                detail=f"Content validation failed for {path} — may be a generic 200 response")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        resp = detection.raw_response
        if not resp:
            return []
        return [
            HttpRequestEvidence(
                method="GET",
                url=detection.url,
                curl_command=_build_curl("GET", detection.url, dict(self.session.headers), cookies=dict(self.session.cookies)),
            ),
            ResponseExcerptEvidence(
                excerpt=resp.text[:500],
                length=len(resp.text),
                context="exposed_file",
            ),
        ]

    def generate_reproduction(self, detection: DetectionResult,
                              validation_result: ValidationResult | None = None) -> list[str]:
        url = detection.url
        if validation_result and validation_result.confirmed:
            return [
                f"Send GET request to {url}",
                f"Observe: Sensitive file is publicly accessible (HTTP 200, content validated)",
                "Sensitive files should not be publicly accessible",
            ]
        return [
            f"Send GET request to {url}",
            "Inspect the HTTP 200 response for exposed sensitive content",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        self._prepare_scan()
        target_base = self.base_url
        for exposed_path in EXPOSED_FILES:
            try:
                file_url = target_base + exposed_path
                if not self._in_scope(file_url):
                    continue

                detection = self.detect(file_url)
                if detection is None:
                    continue

                validation_result = self.validate(detection)
                evidence_list = self.collect_evidence(detection, validation_result)
                resp = detection.raw_response

                for ev in evidence_list:
                    self.evidence_engine.store(ev)

                severity, details = self._file_metadata(exposed_path)
                if not validation_result or not validation_result.confirmed:
                    severity = "info"
                    details += " (content check failed — may be a generic 200 response)"

                f = finding(
                    vuln_type="Exposed Sensitive File",
                    url=file_url,
                    severity=severity,
                    details=details,
                    evidence=f"HTTP {resp.status_code} — {len(resp.text)} bytes" if resp else "",
                    request=_build_curl("GET", file_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                    response_excerpt=resp.text[:500] if resp else "",
                    steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                    verification_stage=VerificationStage.VALIDATED.value if (validation_result and validation_result.confirmed) else VerificationStage.DETECTED.value,
                )
                if f:
                    fingerprint = f.get("fingerprint", "")
                    if fingerprint:
                        for ev in evidence_list:
                            self.evidence_engine.link_to_finding(ev, fingerprint)
                    self._add_finding(f)
                log(f"  [EXPOSED] {file_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

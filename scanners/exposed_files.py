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
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
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
        # Config / dotenv files
        if ".env" in ext:
            return "=" in body
        if "/.git/config" in ext:
            return "[core]" in body

        # PHP files
        if "wp-config.php" in ext or "wp-config.php.bak" in ext:
            return "<?php" in body or "DB_NAME" in body or "wp-config" in body
        if "config.php" in ext:
            return "<?php" in body
        if "phpinfo" in ext:
            return "PHP Version" in body

        # Apache configuration
        if ".htpasswd" in ext:
            return ":" in body  # user:password format
        if ".htaccess" in ext:
            return any(d in body for d in ("RewriteRule", "RewriteEngine", "Deny from", "Allow from",
                                           "Order allow", "Order deny", "ErrorDocument", "Redirect",
                                           "AuthType", "AuthName", "Require"))

        # Docker / container files
        if "dockerfile" in ext:
            return any(d in body for d in ("FROM ", "RUN ", "CMD ", "COPY ", "WORKDIR", "EXPOSE ", "ENV "))
        if "docker-compose" in ext and ".yml" in ext:
            return any(d in body for d in ("version:", "services:", "image:", "volumes:", "networks:"))
        if ".dockerignore" in ext:
            return len(body.strip()) > 3

        # XML-based config files
        if ext.endswith(".xml"):
            return body.lstrip().startswith("<?xml") or body.lstrip().startswith("<")
        if "web.config" in ext:
            return "<configuration>" in body or "<?xml" in body
        if "pom.xml" in ext:
            return "<project" in body or "<?xml" in body

        # Cloud credentials
        if ".aws/credentials" in ext:
            return "[default]" in body or "aws_access_key_id" in body
        if ".aws/config" in ext:
            return "[" in body and "=" in body

        # SSH private keys
        if ".ssh/id_rsa" in ext:
            return body.startswith("-----BEGIN") or "PRIVATE KEY" in body or "OPENSSH" in body

        # Generic secret / password files
        if "secrets" in ext or "password" in ext:
            return "=" in body or ":" in body

        # Binary archives
        if ext.endswith(".zip"):
            return raw[:2] == b"PK"
        if ext.endswith(".gz") or ext.endswith(".tar.gz"):
            return raw[:2] == b"\x1f\x8b"

        # SQL backups
        if ext.endswith(".sql"):
            return any(body.lstrip().startswith(w) for w in ("-- ", "CREATE", "INSERT", "DROP", "ALTER", "SELECT"))

        # Catch-all: for paths without a specific validator, still check that
        # the body has meaningful content (not just whitespace/empty)
        return bool(body.strip())

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
                curl_command=_build_curl("GET", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
            ),
            ResponseExcerptEvidence(
                excerpt=resp.text[:500],
                length=len(resp.text),
                context="exposed_file",
            ),
        ]

    def generate_reproduction(self, f: dict) -> list[str]:
        url = f["url"]
        stage = f.get("verification_stage", "detected")
        if stage == "validated":
            return [
                f"curl -X GET '{url}'",
                f"Observe: Sensitive file is publicly accessible (HTTP 200, content validated) — contains potentially sensitive information",
                "Sensitive files should not be publicly accessible; they can leak credentials, source code, API keys, or business logic",
            ]
        return [
            f"curl -X GET '{url}'",
            "Inspect the HTTP 200 response for exposed sensitive content",
            "Publicly accessible sensitive files can leak credentials, source code, or business logic to attackers",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
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
                    request=_build_curl("GET", file_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=resp.text[:500] if resp else "",
                    verification_stage=VerificationStage.VALIDATED.value if (validation_result and validation_result.confirmed) else VerificationStage.DETECTED.value,
                )
                if f:
                    f["steps_to_reproduce"] = self.generate_reproduction(f)
                    self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                    fingerprint = f.get("fingerprint", "")
                    if fingerprint:
                        for ev in evidence_list:
                            self.evidence_engine.link_to_finding(ev, fingerprint)
                    self._add_finding(f)
                log(f"  [EXPOSED] {file_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

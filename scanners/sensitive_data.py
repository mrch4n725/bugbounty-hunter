"""
SensitiveDataScanner — detects secrets and sensitive data in page content.

Lifecycle:
  DETECTED:   Pattern matched but validation skipped/failed
  VALIDATED:  SecretValidator confirms token is live/valid
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate with live secret validation)
"""

import re
from urllib.parse import urlparse

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage, SecretValidator,
)
from scanners.base import ScannerBase
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence, SecretValidationEvidence

SENSITIVE_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}")),
    ("GitHub Token", re.compile(r"(?:ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}")),
    ("Slack Token", re.compile(r"(?:xox[baprs]-|xapp-)[0-9A-Za-z-]{10,}")),
    ("Private RSA Key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    ("Private EC Key", re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
]

STATIC_EXTENSIONS = {".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".pdf"}


class SensitiveDataScanner(ScannerBase):
    SCANNER_NAME = "sensitive"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = False

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in urls:
            if not self._in_scope(url):
                continue
            parsed_path = urlparse(url).path.lower()
            if any(parsed_path.endswith(ext) for ext in STATIC_EXTENSIONS):
                continue
            try:
                resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
                if not resp or not resp.text:
                    continue
                body = resp.text
                for label, pattern in SENSITIVE_PATTERNS:
                    match = pattern.search(body)
                    if match:
                        value = match.group(0)[:120]

                        secret_type_map = {
                            "AWS Access Key": "aws_access_key",
                            "AWS Secret Key": "aws_secret_key",
                            "GitHub Token": "github_token",
                            "Slack Token": "slack_token",
                        }
                        secret_type = secret_type_map.get(label)
                        validation_result = None
                        secret_ev = None
                        if secret_type:
                            validation_result = SecretValidator.validate(secret_type, value)
                            secret_ev = SecretValidationEvidence(
                                secret_type=secret_type,
                                validation_method="pattern_validation",
                                is_valid=bool(validation_result and validation_result.get("valid")),
                                api_response=validation_result.get("details", "") if validation_result else "",
                                description=f"Secret validation ({label}): {'valid' if validation_result and validation_result.get('valid') else 'invalid or unknown'}",
                            )
                            self.evidence_engine.store(secret_ev)

                        if validation_result and validation_result.get("valid") is True:
                            severity = "critical"
                            stage = VerificationStage.VALIDATED.value
                        elif validation_result and validation_result.get("valid") is False:
                            severity = "info"
                            stage = VerificationStage.DETECTED.value
                        else:
                            severity = "high" if "key" in label.lower() else "medium"
                            stage = VerificationStage.DETECTED.value

                        evidence_parts = [f"Matched: {value}"]
                        if validation_result:
                            result_label = {
                                True: "Valid",
                                False: "Invalid",
                                None: "Unknown",
                            }.get(validation_result.get("valid"))
                            evidence_parts.append(f"Validation: {result_label}")

                        req_ev = HttpRequestEvidence(
                            method="GET",
                            url=url,
                            curl_command=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        )
                        resp_ev = ResponseExcerptEvidence(
                            excerpt=body[:500],
                            length=len(body),
                            context="sensitive_data_scan",
                        )
                        req_fp = self.evidence_engine.store(req_ev)
                        resp_fp = self.evidence_engine.store(resp_ev)

                        f = finding(
                            vuln_type=f"Sensitive Data Exposure ({label})",
                            url=url,
                            severity=severity,
                            details=f"Potential sensitive value detected in page content: {label}",
                            evidence=" | ".join(evidence_parts),
                            request=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                            response_excerpt=body[:500],
                            steps_to_reproduce=[f"Send request to {url}", f"Observe {label} in response"],
                            verification_stage=stage,
                        )
                        if f:
                            self.evidence_engine.link_to_finding(req_ev, f.get("fingerprint", ""))
                            self.evidence_engine.link_to_finding(resp_ev, f.get("fingerprint", ""))
                            if secret_ev:
                                self.evidence_engine.link_to_finding(secret_ev, f.get("fingerprint", ""))
                            self._add_finding(f)
                        log(f"  [SENSITIVE] {url} - {label}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

"""
SensitiveDataScanner — detects secrets and sensitive data in page content.

Lifecycle:
  DETECTED:   Pattern matched but validation skipped/failed
  VALIDATED:  SecretValidator confirms token is live/valid
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 4 (Full lifecycle — typed evidence, secret validation, confidence, skip legacy)
"""

import re
from urllib.parse import urlparse

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage, SecretValidator,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
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
    SCANNER_MATURITY = 4
    TARGET_LEVEL = False

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        parsed_path = urlparse(url).path.lower()
        if any(parsed_path.endswith(ext) for ext in STATIC_EXTENSIONS):
            return None
        resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
        if not resp or not resp.text:
            return None
        body = resp.text
        for label, pattern in SENSITIVE_PATTERNS:
            match = pattern.search(body)
            if match:
                value = match.group(0)[:120]
                return DetectionResult(
                    url=url,
                    parameter="",
                    payload=value,
                    context=label,
                    raw_response=resp,
                    evidence_signals=[f"Matched: {label}: {value}"],
                )
        return None

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        label = detection.context
        value = detection.payload
        secret_type_map = {
            "AWS Access Key": "aws_access_key",
            "AWS Secret Key": "aws_secret_key",
            "GitHub Token": "github_token",
            "Slack Token": "slack_token",
        }
        secret_type = secret_type_map.get(label)
        if not secret_type:
            return ValidationResult(confirmed=False, method="no_validation",
                                    detail=f"No automated validation available for {label}")
        validation_result = SecretValidator.validate(secret_type, value)
        if validation_result and validation_result.get("valid") is True:
            return ValidationResult(confirmed=True, method="secret_validator",
                                    detail=f"Secret validation passed for {label}")
        return ValidationResult(confirmed=False, method="secret_validator",
                                detail=f"Secret validation failed or inconclusive for {label}")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        resp = detection.raw_response
        body = resp.text if resp else ""
        ev_list = [
            HttpRequestEvidence(
                method="GET",
                url=detection.url,
                curl_command=_build_curl("GET", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
            ),
            ResponseExcerptEvidence(
                excerpt=body[:500],
                length=len(body),
                context="sensitive_data_scan",
            ),
        ]
        label = detection.context
        value = detection.payload
        secret_type_map = {
            "AWS Access Key": "aws_access_key",
            "AWS Secret Key": "aws_secret_key",
            "GitHub Token": "github_token",
            "Slack Token": "slack_token",
        }
        secret_type = secret_type_map.get(label)
        if secret_type:
            valid = validation_result and validation_result.confirmed
            secret_ev = SecretValidationEvidence(
                secret_type=secret_type,
                validation_method="pattern_validation",
                is_valid=bool(valid),
                api_response=validation_result.detail if validation_result else "",
                description=f"Secret validation ({label}): {'valid' if valid else 'invalid or unknown'}",
            )
            ev_list.append(secret_ev)
        return ev_list

    def generate_reproduction(self, detection: DetectionResult,
                              validation_result: ValidationResult | None = None) -> list[str]:
        label = detection.context
        url = detection.url
        pattern_str = str(SENSITIVE_PATTERNS[0][1].pattern)
        for pat_label, pat in SENSITIVE_PATTERNS:
            if pat_label == label:
                pattern_str = str(pat.pattern)
                break
        return [
            f"Send GET request to {url}",
            f"Search response body for {label} matching: {pattern_str}",
            f"Rotate exposed credentials immediately — they can be used for lateral attacks",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in urls:
            if not self._in_scope(url):
                continue

            try:
                detection = self.detect(url)
                if detection is None:
                    continue

                validation_result = self.validate(detection)
                evidence_list = self.collect_evidence(detection, validation_result)

                for ev in evidence_list:
                    self.evidence_engine.store(ev)

                label = detection.context
                value = detection.payload

                if validation_result and validation_result.confirmed:
                    severity = "critical"
                    stage = VerificationStage.VALIDATED.value
                else:
                    severity = "high" if "key" in label.lower() else "medium"
                    stage = VerificationStage.DETECTED.value

                evidence_parts = [f"Matched: {value}"]
                validation_states = {
                    True: "Valid",
                    False: "Invalid",
                }
                if validation_result:
                    evidence_parts.append(f"Validation: {validation_states.get(validation_result.confirmed, 'Unknown')}")

                f = finding(
                    vuln_type=f"Sensitive Data Exposure ({label})",
                    url=url,
                    severity=severity,
                    details=f"Potential sensitive value detected in page content: {label}",
                    evidence=" | ".join(evidence_parts),
                    request=_build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=detection.raw_response.text[:500] if detection.raw_response else "",
                    steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                    verification_stage=stage,
                )
                if f:
                    self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                    fingerprint = f.get("fingerprint", "")
                    if fingerprint:
                        for ev in evidence_list:
                            self.evidence_engine.link_to_finding(ev, fingerprint)
                    self._add_finding(f)
                log(f"  [SENSITIVE] {url} - {label}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

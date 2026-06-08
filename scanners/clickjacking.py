"""
ClickjackingScanner — checks for missing frame-busting headers.

Lifecycle:
  DETECTED:   X-Frame-Options missing and CSP frame-ancestors absent
  VALIDATED:  (not applicable)
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 1 (Detection only)
"""

from modules.utils import (
    safe_get, finding, VerificationStage, log, Colors, _build_curl,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence


class ClickjackingScanner(ScannerBase):
    SCANNER_NAME = "clickjacking"
    SCANNER_MATURITY = 1
    TARGET_LEVEL = True
    SCANNER_ORDER = 10

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
        if not resp:
            return None
        x_frame = resp.headers.get("X-Frame-Options", "").lower()
        csp = resp.headers.get("Content-Security-Policy", "").lower()
        safe_directives = [
            "frame-ancestors 'none'", "frame-ancestors 'self'",
            "frame-ancestors https:",
        ]
        csp_protected = any(d in csp for d in safe_directives)
        x_frame_protected = bool(x_frame)
        missing_protection = not x_frame_protected and not csp_protected
        if not missing_protection:
            return None
        return DetectionResult(
            url=url,
            parameter="",
            payload="",
            context="missing_frame_protection",
            raw_response=resp,
            evidence_signals=[f"X-Frame-Options: {x_frame or 'missing'}, CSP: {csp or 'missing'}"],
        )

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        return ValidationResult(confirmed=False, method="header_analysis", detail="Clickjacking detection based on response header analysis")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence
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
                context="clickjacking_check",
            ),
        ]

    def generate_reproduction(self, detection: DetectionResult,
                              validation_result: ValidationResult | None = None) -> list[str]:
        return [
            f"Send GET request to {detection.url} and inspect response headers",
            "Verify X-Frame-Options header is missing (should be DENY or SAMEORIGIN)",
            "Verify Content-Security-Policy lacks frame-ancestors directive",
            f"Create an HTML page with <iframe src='{detection.url}'> — the page loads inside the iframe",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        target = self.base_url
        if not target or not self._in_scope(target):
            return self._get_findings()
        try:
            detection = self.detect(target)
            if detection is None:
                return self._get_findings()

            validation_result = self.validate(detection)
            evidence_list = self.collect_evidence(detection, validation_result)
            resp = detection.raw_response
            x_frame = resp.headers.get("X-Frame-Options", "").lower() if resp else ""
            csp = resp.headers.get("Content-Security-Policy", "").lower() if resp else ""

            for ev in evidence_list:
                self.evidence_engine.store(ev)

            f = finding(
                vuln_type="Clickjacking Exposure",
                url=target,
                severity="medium",
                details=f"The application does not enforce frame protection headers (X-Frame-Options: {x_frame or 'missing'}, CSP: {csp or 'missing'})",
                evidence=f"X-Frame-Options: {x_frame or 'missing'}, CSP: {csp or 'missing'}",
                request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                response_excerpt=resp.text[:500] if resp else "",
                steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                verification_stage=VerificationStage.DETECTED.value,
            )
            if f:
                fingerprint = f.get("fingerprint", "")
                if fingerprint:
                    for ev in evidence_list:
                        self.evidence_engine.link_to_finding(ev, fingerprint)
                self._add_finding(f)
                log(f"  [CLICKJACKING] {target}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        except Exception:
            pass
        return self._get_findings()

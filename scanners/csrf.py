"""
CSRFScanner — detects POST forms missing anti-CSRF tokens.

Lifecycle:
  DETECTED:   POST form lacks known CSRF token field
  VALIDATED:  (not applicable)
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 1 (Detection only)
"""

from urllib.parse import urlparse

from models.evidence import ResponseExcerptEvidence
from modules.utils import (
    finding, VerificationStage, log, Colors, _build_curl,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

CSRF_TOKEN_NAMES = {
    "csrf_token", "csrfmiddlewaretoken", "authenticity_token",
    "token", "csrf", "xsrf-token", "xsrf_token",
    "anti_csrf_token", "_csrf", "_token",
}


class CSRFScanner(ScannerBase):
    SCANNER_NAME = "csrf"
    SCANNER_MATURITY = 1
    TARGET_LEVEL = False

    def detect(self, form: dict) -> DetectionResult | None:
        form_action = form.get("action", form.get("url", ""))
        if not form_action:
            return None
        if form.get("method", "GET").upper() != "POST":
            return None
        token_found = any(
            fld.get("name", "").lower() in CSRF_TOKEN_NAMES
            for fld in form.get("fields", [])
        )
        if token_found:
            return None
        return DetectionResult(
            url=form_action,
            parameter="",
            payload="",
            context="missing_csrf_token",
            raw_response=None,
            evidence_signals=[f"Missing CSRF token in POST form at {form_action}"],
        )

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        return ValidationResult(confirmed=False, method="form_analysis", detail="CSRF detection is based on form structure analysis — no secondary validation available")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        from models.evidence import ResponseExcerptEvidence
        return [ResponseExcerptEvidence(
            excerpt=f"Form action: {detection.url} | Method: POST | No CSRF token found",
            length=0,
            context="csrf_form_analysis",
            description=f"CSRF analysis of form at {detection.url}",
        )]

    def generate_reproduction(self, detection: DetectionResult,
                              validation_result: ValidationResult | None = None) -> list[str]:
        return [
            f"Navigate to the page containing the form at {detection.url}",
            "Using a proxy or curl, submit the same POST request without any anti-CSRF token (remove csrf_token / authenticity_token fields)",
            "Observe that the server accepts the request with HTTP 200 — no token validation enforced",
            "Compare with legitimate request that includes a token — both succeed, confirming missing CSRF protection",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        forms = self.recon.get("forms", [])
        if target_urls is not None:
            origins = {urlparse(u).scheme + "://" + urlparse(u).netloc for u in target_urls}
            forms = [
                f for f in forms
                if any(
                    urlparse(f.get("action", f.get("url", ""))).scheme + "://"
                    + urlparse(f.get("action", f.get("url", ""))).netloc == o
                    for o in origins
                )
            ]
        for form in forms:
            try:
                detection = self.detect(form)
                if detection is None:
                    continue
                if not self._in_scope(detection.url):
                    continue

                validation_result = self.validate(detection)
                evidence_list = self.collect_evidence(detection, validation_result)

                f = finding(
                    vuln_type="Missing CSRF Protection",
                    url=detection.url,
                    severity="medium",
                    details="POST form does not contain a known anti-CSRF token field",
                    evidence=f"Form fields: {[fld.get('name') for fld in form.get('fields', [])]}",
                    request=_build_curl("POST", detection.url, {}, data={
                        fld.get("name", "field"): fld.get("value", "test")
                        for fld in form.get("fields", [])[:5]
                    }),
                    response_excerpt="(no request made — detected from form structure)",
                    steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                    verification_stage=VerificationStage.DETECTED.value,
                )
                if f:
                    for ev in evidence_list:
                        self.evidence_engine.store(ev)
                        self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                    self._add_finding(f)
                    log(f"  [CSRF] {detection.url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

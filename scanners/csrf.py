"""
CSRFScanner — detects POST forms missing anti-CSRF tokens.

Lifecycle:
  DETECTED:   POST form lacks known CSRF token field
  VALIDATED:  Token replay test confirms server accepts requests without token
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 2 (Detect + Validate)
"""

from urllib.parse import urlparse
from urllib.parse import urljoin

from models.finding import Finding
from models.evidence import ResponseExcerptEvidence, HttpRequestEvidence
from modules.utils import (
    finding, VerificationStage, log, Colors, _build_curl, safe_post, safe_get,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

CSRF_TOKEN_NAMES = {
    "csrf_token", "csrfmiddlewaretoken", "authenticity_token",
    "token", "csrf", "xsrf-token", "xsrf_token",
    "anti_csrf_token", "_csrf", "_token",
}


class CSRFScanner(ScannerBase):
    SCANNER_NAME = "csrf"
    SCANNER_MATURITY = 2
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
        form_action = detection.url
        if not form_action or self.config.get("passive"):
            return ValidationResult(confirmed=False, method="form_analysis",
                                    detail="CSRF detection based on form structure analysis")

        try:
            form_data = {"test": "test"}
            resp = safe_post(self.session, form_action, form_data, self.timeout, raise_for_status=False)
            if resp and resp.status_code in (200, 201, 202, 204, 301, 302):
                return ValidationResult(
                    confirmed=True,
                    signals=[f"POST to {form_action} returned HTTP {resp.status_code} without token"],
                    method="token_replay",
                    detail=f"Server accepted POST request without anti-CSRF token (HTTP {resp.status_code})",
                )
            if resp and resp.status_code in (400, 403, 422):
                return ValidationResult(
                    confirmed=False,
                    signals=[f"POST rejected with HTTP {resp.status_code}"],
                    method="token_replay",
                    detail=f"Server rejected POST without token (HTTP {resp.status_code}) — CSRF protection likely present",
                )
            return ValidationResult(
                confirmed=False,
                method="token_replay",
                detail=f"Server returned HTTP {resp.status_code if resp else 'N/A'} — inconclusive",
            )
        except Exception as e:
            return ValidationResult(
                confirmed=False,
                method="token_replay_error",
                detail=f"Token replay test failed: {e}",
            )

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        from models.evidence import ResponseExcerptEvidence
        return [ResponseExcerptEvidence(
            excerpt=f"Form action: {detection.url} | Method: POST | No CSRF token found",
            length=0,
            context="csrf_form_analysis",
            description=f"CSRF analysis of form at {detection.url}",
        )]

    def generate_reproduction(self, f: dict) -> list[str]:
        return [
            f"Navigate to the page containing the form at {f['url']}",
            "Using a proxy or curl, submit the same POST request without any anti-CSRF token (remove csrf_token / authenticity_token fields)",
            "Observe that the server accepts the request with HTTP 200 — no token validation enforced",
            "Compare with legitimate request that includes a token — both succeed, confirming missing CSRF protection",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
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

                stage = VerificationStage.VALIDATED.value if (validation_result and validation_result.confirmed) else VerificationStage.DETECTED.value

                curl_cmd = _build_curl("POST", detection.url, {}, data={
                    fld.get("name", "field"): fld.get("value", "test")
                    for fld in form.get("fields", [])[:5]
                })

                f = finding(
                    vuln_type="Missing CSRF Protection",
                    url=detection.url,
                    severity="medium",
                    details="POST form does not contain a known anti-CSRF token field",
                    evidence=f"Form fields: {[fld.get('name') for fld in form.get('fields', [])]}",
                    request=curl_cmd,
                    response_excerpt="(no request made — detected from form structure)" if stage == VerificationStage.DETECTED.value else validation_result.detail,
                    steps_to_reproduce=self.generate_reproduction(f),
                    verification_stage=stage,
                )
                if f:
                    self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                    for ev in evidence_list:
                        self.evidence_engine.store(ev)
                        self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                    if stage == VerificationStage.VALIDATED.value and f.get("fingerprint", ""):
                        req_ev = HttpRequestEvidence(
                            method="POST",
                            url=detection.url,
                            curl_command=curl_cmd,
                        )
                        self.evidence_engine.store(req_ev)
                        self.evidence_engine.link_to_finding(req_ev, f.get("fingerprint", ""))
                    self._add_finding(f)
                    log(f"  [CSRF] {detection.url} [{stage}]", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

"""
InsecureFormsScanner — detects insecure form actions and cross-origin password submission.

Lifecycle:
  DETECTED:   Form action uses HTTP, or password form submits cross-origin
  VALIDATED:  HTTP form submission confirmed reachable over cleartext
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 2 (Detect + Validate)
"""

from urllib.parse import urlparse, urljoin

from models.finding import Finding
from models.evidence import ResponseExcerptEvidence, HttpRequestEvidence
from modules.utils import (
    finding, VerificationStage, log, Colors, _build_curl, safe_post, safe_get,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult


class InsecureFormsScanner(ScannerBase):
    SCANNER_NAME = "insecure_forms"
    SCANNER_MATURITY = 2
    TARGET_LEVEL = False

    def _same_origin(self, action_url: str) -> bool:
        target = urlparse(self.base_url)
        action = urlparse(action_url)
        return action.netloc == "" or action.netloc == target.netloc

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        return None

    def detect_form(self, form: dict) -> DetectionResult | None:
        method = form.get("method", "get").lower()
        action = form.get("action", "")
        if not action or method != "post":
            return None
        parsed = urlparse(action)
        if parsed.scheme == "http":
            return DetectionResult(
                url=action,
                parameter="",
                payload="http_scheme",
                context="insecure_form_action",
                evidence_signals=[f"Form action uses http:// scheme; fields: {[f.get('name', '?') for f in form.get('fields', [])]}"],
            )
        if any(field.get("type") == "password" for field in form.get("fields", [])):
            if parsed.netloc and not self._same_origin(action):
                return DetectionResult(
                    url=action,
                    parameter="",
                    payload="cross_origin_password",
                    context="password_cross_origin_submission",
                    evidence_signals=[f"Password form submits to different origin: {parsed.netloc}; Action: {action}"],
                )
        return None

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        action = detection.url
        context = detection.context

        if self.config.get("passive"):
            return ValidationResult(confirmed=False, method="form_structure_analysis",
                                    detail="Insecure form detection based on static form structure analysis")

        if context == "insecure_form_action":
            try:
                test_data = {"test": "test"}
                resp = safe_post(self.session, action, test_data, self.timeout, raise_for_status=False)
                if resp is not None:
                    return ValidationResult(
                        confirmed=True,
                        signals=[f"HTTP POST to {action} returned HTTP {resp.status_code}"],
                        method="http_submission_probe",
                        detail=f"Form action over HTTP confirmed reachable — data submitted in cleartext (HTTP {resp.status_code})",
                    )
            except Exception as e:
                return ValidationResult(
                    confirmed=False,
                    method="http_submission_error",
                    detail=f"HTTP submission test failed: {e}",
                )
            return ValidationResult(
                confirmed=False,
                method="http_submission_unreachable",
                detail="Form action uses HTTP but endpoint appears unreachable",
            )

        if context == "password_cross_origin_submission":
            return ValidationResult(
                confirmed=False,
                method="origin_analysis",
                detail="Cross-origin password submission detected via form structure analysis — confirm manually by inspecting the form action",
            )

        return ValidationResult(confirmed=False, method="form_structure_analysis",
                                detail="Insecure form detection based on static form structure analysis")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        action = detection.url
        excerpt = detection.evidence_signals[0] if detection.evidence_signals else ""
        ctx = detection.context
        return [
            ResponseExcerptEvidence(
                excerpt=excerpt,
                length=0,
                context=ctx,
                description=f"Insecure form detection at {action}",
            ),
        ]

    def generate_reproduction(self, f: dict) -> list[str]:
        url = f["url"]
        vuln_type = f.get("vuln_type", "")
        if vuln_type == "Insecure Form Action":
            return [
                f"Navigate to page containing form that submits to {url}",
                "Open browser DevTools or a proxy (Burp/ZAP) to inspect the request",
                "Submit the form and observe that POST data is sent over HTTP (cleartext) — no TLS encryption",
                "Any network eavesdropper can read form data including passwords, tokens, and personal information",
            ]
        return [
            f"Navigate to the page containing the password form",
            f"Inspect the form action URL: {url} — note it points to a different origin",
            "Submit the form with a test password",
            "Observe that credentials are sent to a third-party origin — the password may be harvested by an external service",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        forms = self.recon.get("forms", [])
        if target_urls is not None:
            origins = {urlparse(u).scheme + "://" + urlparse(u).netloc for u in target_urls}
            forms = [
                f for f in forms
                if any(
                    urlparse(
                        urljoin(url, f.get("action", ""))
                    ).scheme + "://" + urlparse(
                        urljoin(url, f.get("action", ""))
                    ).netloc == o
                    for o in origins
                    for url in target_urls
                )
            ]
        for form in forms:
            try:
                detection = self.detect_form(form)
                if detection is None:
                    continue

                validation_result = self.validate(detection)
                evidence_list = self.collect_evidence(detection, validation_result)
                action = detection.url

                for ev in evidence_list:
                    self.evidence_engine.store(ev)

                vuln_type = "Insecure Form Action" if detection.context == "insecure_form_action" else "Password Form Cross-Origin Submission"
                stage = VerificationStage.VALIDATED.value if (validation_result and validation_result.confirmed) else VerificationStage.DETECTED.value

                curl_cmd = _build_curl("POST", action, {}, data={
                    field.get("name", "field"): field.get("value", "test")
                    for field in form.get("fields", [])[:5]
                })

                f = finding(
                    vuln_type=vuln_type,
                    url=action,
                    severity="high",
                    details=detection.evidence_signals[0] if detection.evidence_signals else "Insecure form detected",
                    evidence=detection.evidence_signals[0] if detection.evidence_signals else "",
                    request=curl_cmd,
                    response_excerpt="(no request made — vulnerability detected from form structure)" if stage == VerificationStage.DETECTED.value else validation_result.detail,
                    steps_to_reproduce=self.generate_reproduction(f),
                    verification_stage=stage,
                )
                if f:
                    self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                    fingerprint = f.get("fingerprint", "")
                    if fingerprint:
                        for ev in evidence_list:
                            self.evidence_engine.link_to_finding(ev, fingerprint)
                    if stage == VerificationStage.VALIDATED.value and fingerprint:
                        req_ev = HttpRequestEvidence(
                            method="POST",
                            url=action,
                            curl_command=curl_cmd,
                        )
                        self.evidence_engine.store(req_ev)
                        self.evidence_engine.link_to_finding(req_ev, fingerprint)
                    self._add_finding(f)
                    log(f"  [FORM] {action} [{stage}]", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

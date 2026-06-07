"""
InsecureFormsScanner — detects insecure form actions and cross-origin password submission.

Lifecycle:
  DETECTED:   Form action uses HTTP, or password form submits cross-origin
  VALIDATED:  (not applicable)
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 1 (Detection only)
"""

from urllib.parse import urlparse

from modules.utils import (
    finding, VerificationStage, log, Colors, _build_curl,
)
from scanners.base import ScannerBase


class InsecureFormsScanner(ScannerBase):
    SCANNER_NAME = "insecure_forms"
    SCANNER_MATURITY = 1
    TARGET_LEVEL = False

    def _same_origin(self, action_url: str) -> bool:
        target = urlparse(self.base_url)
        action = urlparse(action_url)
        return action.netloc == "" or action.netloc == target.netloc

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        forms = self.recon.get("forms", [])
        if target_urls is not None:
            origins = {urlparse(u).scheme + "://" + urlparse(u).netloc for u in target_urls}
            forms = [
                f for f in forms
                if any(
                    urlparse(f.get("action", "")).scheme + "://"
                    + urlparse(f.get("action", "")).netloc == o
                    for o in origins
                )
            ]
        for form in forms:
            try:
                method = form.get("method", "get").lower()
                action = form.get("action", "")
                if not action or method != "post":
                    continue
                parsed = urlparse(action)

                if parsed.scheme == "http":
                    f = finding(
                        vuln_type="Insecure Form Action",
                        url=action,
                        severity="high",
                        details="A POST form submits data over an insecure HTTP connection",
                        evidence="Form action uses http:// scheme",
                        request=_build_curl("POST", action, {}, data={
                            field.get("name", "field"): field.get("value", "test")
                            for field in form.get("fields", [])[:5]
                        }),
                        response_excerpt="(no request made — vulnerability detected from form structure)",
                        steps_to_reproduce=[
                            f"Navigate to page with form action {action}",
                            "Submit the form over HTTP",
                            "Observe credentials submitted in cleartext",
                        ],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self._add_finding(f)
                    log(f"  [FORM] {action}", Colors.RED, verbose_only=True, verbose=self.verbose)
                    continue

                if any(field.get("type") == "password" for field in form.get("fields", [])):
                    if parsed.netloc and not self._same_origin(action):
                        f = finding(
                            vuln_type="Password Form Cross-Origin Submission",
                            url=action,
                            severity="high",
                            details="A password field submits to a different origin",
                            evidence=f"Action host: {parsed.netloc}",
                            request=_build_curl("POST", action, {}, data={
                                field.get("name", "field"): field.get("value", "test")
                                for field in form.get("fields", [])[:5]
                            }),
                            response_excerpt="(no request made — vulnerability detected from form structure)",
                            steps_to_reproduce=[
                                f"Navigate to page with form action {action}",
                                "Submit the form to cross-origin endpoint",
                                "Observe credentials submitted cross-origin",
                            ],
                            verification_stage=VerificationStage.DETECTED.value,
                        )
                        if f:
                            self._add_finding(f)
                        log(f"  [FORM] {action}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

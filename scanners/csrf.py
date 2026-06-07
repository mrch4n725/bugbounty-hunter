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

from modules.utils import (
    finding, VerificationStage, log, Colors, _build_curl,
)
from scanners.base import ScannerBase

CSRF_TOKEN_NAMES = {
    "csrf_token", "csrfmiddlewaretoken", "authenticity_token",
    "token", "csrf", "xsrf-token", "xsrf_token",
    "anti_csrf_token", "_csrf", "_token",
}


class CSRFScanner(ScannerBase):
    SCANNER_NAME = "csrf"
    SCANNER_MATURITY = 1
    TARGET_LEVEL = False

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
                form_action = form.get("action", form.get("url", ""))
                if form_action and not self._in_scope(form_action):
                    continue
                if form.get("method", "GET").upper() != "POST":
                    continue
                token_found = any(
                    fld.get("name", "").lower() in CSRF_TOKEN_NAMES
                    for fld in form.get("fields", [])
                )
                if not token_found:
                    f = finding(
                        vuln_type="Missing CSRF Protection",
                        url=form_action,
                        severity="medium",
                        details="POST form does not contain a known anti-CSRF token field",
                        evidence=f"Form fields: {[fld.get('name') for fld in form.get('fields', [])]}",
                        request=_build_curl("POST", form_action, {}, data={
                            fld.get("name", "field"): fld.get("value", "test")
                            for fld in form.get("fields", [])[:5]
                        }),
                        response_excerpt="(no request made — detected from form structure)",
                        steps_to_reproduce=[
                            f"Navigate to the page containing the form at {form_action}",
                            "Submit the POST form without a CSRF token",
                            "Observe that the server accepts the request without token validation",
                        ],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self._add_finding(f)
                    log(f"  [CSRF] {form_action}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

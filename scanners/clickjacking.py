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
)
from scanners.base import ScannerBase
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence


class ClickjackingScanner(ScannerBase):
    SCANNER_NAME = "clickjacking"
    SCANNER_MATURITY = 1
    TARGET_LEVEL = True
    SCANNER_ORDER = 10

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        target = self.base_url
        if not target or not self._in_scope(target):
            return self._get_findings()
        try:
            resp = safe_get(self.session, target, self.timeout, raise_for_status=False)
            if not resp:
                return self._get_findings()

            x_frame = resp.headers.get("X-Frame-Options", "").lower()
            csp = resp.headers.get("Content-Security-Policy", "").lower()

            safe_directives = [
                "frame-ancestors 'none'", "frame-ancestors 'self'",
                "frame-ancestors https:",
            ]
            csp_protected = any(d in csp for d in safe_directives)
            x_frame_protected = bool(x_frame)
            missing_protection = not x_frame_protected and not csp_protected

            req_ev = HttpRequestEvidence(
                method="GET",
                url=target,
                curl_command=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
            )
            resp_ev = ResponseExcerptEvidence(
                excerpt=resp.text[:500],
                length=len(resp.text),
                context="clickjacking_check",
            )
            req_fp = self.evidence_engine.store(req_ev)
            resp_fp = self.evidence_engine.store(resp_ev)

            if missing_protection:
                f = finding(
                    vuln_type="Clickjacking Exposure",
                    url=target,
                    severity="medium",
                    details=f"The application does not enforce frame protection headers (X-Frame-Options: {x_frame or 'missing'}, CSP: {csp or 'missing'})",
                    evidence=f"X-Frame-Options: {x_frame or 'missing'}, CSP: {csp or 'missing'}",
                    request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                    response_excerpt=resp.text[:500],
                    steps_to_reproduce=[
                        f"Send GET request to {target}",
                        "Observe missing X-Frame-Options header",
                        "Observe missing frame-ancestors CSP directive",
                        "Application can be embedded in an iframe by an attacker",
                    ],
                    verification_stage=VerificationStage.DETECTED.value,
                )
                if f:
                    self.evidence_engine.link_to_finding(req_ev, f.get("fingerprint", ""))
                    self.evidence_engine.link_to_finding(resp_ev, f.get("fingerprint", ""))
                    self._add_finding(f)
                    log(f"  [CLICKJACKING] {target}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        except Exception:
            pass
        return self._get_findings()

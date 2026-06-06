"""
OpenRedirectScanner — detects URL parameters that redirect to external domains.

Lifecycle:
  DETECTED:   (not applicable — requires validation)
  VALIDATED:  Location header contains external domain
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 2 (Detect + Validate)
"""

from urllib.parse import urlparse, parse_qs

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase, DetectionResult

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "return", "return_to",
    "returnUrl", "next", "url", "goto", "dest", "destination",
    "continue", "forward", "target", "redir", "r", "u",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com",
    "https://evil.com%2F%2F", "/\\evil.com",
    "https%3A%2F%2Fevil.com", "javascript:alert(1)",
]


class OpenRedirectScanner(ScannerBase):
    SCANNER_NAME = "open_redirect"
    SCANNER_MATURITY = 2
    TARGET_LEVEL = False

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def detect(self, url: str, parameter: str) -> DetectionResult | None:
        for payload in OPEN_REDIRECT_PAYLOADS:
            try:
                test_url = self._inject_param(url, parameter, payload)
                resp = safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                if not resp:
                    continue
                loc = resp.headers.get("Location", "")
                if "evil.com" in loc:
                    return DetectionResult(
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        context=f"Redirect to {loc[:80]}",
                        raw_response=resp,
                        evidence_signals=[f"Location: {loc[:100]}"],
                    )
            except Exception:
                continue
        return None

    def generate_reproduction(self, detection: DetectionResult) -> list[str]:
        return [
            f"Send GET to {detection.url}",
            f"Observe redirect to external domain: {detection.context}",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                params = list(parse_qs(urlparse(url).query).keys())
                redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
                if not redirect_params:
                    continue
                for param in redirect_params:
                    detection = self.detect(url, param)
                    if detection is None:
                        continue
                    resp = detection.raw_response
                    f = finding(
                        vuln_type="Open Redirect",
                        url=detection.url,
                        severity="medium",
                        details=f"Parameter '{param}' redirects to external domain",
                        evidence=f"Location: {resp.headers.get('Location', '')[:100] if resp else ''}",
                        request=_build_curl("GET", detection.url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500] if resp else "",
                        parameter=param,
                        steps_to_reproduce=self.generate_reproduction(detection),
                        verification_stage=VerificationStage.VALIDATED.value,
                    )
                    if f:
                        self._add_finding(f)
                    log(f"  [REDIRECT] {detection.url[:80]}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                    break
            except Exception:
                continue
        return self._get_findings()

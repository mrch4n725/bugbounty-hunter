"""
OpenRedirectScanner — detects URL parameters that redirect to external domains.

Lifecycle:
  DETECTED:   (not applicable — requires validation)
  VALIDATED:  Location header contains external domain
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate + typed evidence + reproduction)
"""

from urllib.parse import urlparse, parse_qs

from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence
from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

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
    SCANNER_MATURITY = 3
    TARGET_LEVEL = False

    @staticmethod
    def _is_evil_redirect(loc: str) -> bool:
        """Check if a Location header points to an external/open redirect target."""
        if not loc:
            return False
        if loc.lower().startswith("javascript:"):
            return True
        parsed = urlparse(loc)
        if not parsed.netloc:
            return False
        return parsed.netloc == "evil.com" or parsed.netloc.endswith(".evil.com")

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
                resp = safe_get(self.session, test_url, self.timeout, raise_for_status=False, allow_redirects=False)
                if not resp:
                    continue
                loc = resp.headers.get("Location", "")
                if self._is_evil_redirect(loc):
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

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        resp = detection.raw_response
        if not resp:
            return None
        loc = resp.headers.get("Location", "")
        if not loc:
            return None
        if loc.lower().startswith("javascript:"):
            return ValidationResult(
                confirmed=True,
                signals=["javascript_url"],
                method="javascript_confirm",
                detail="JavaScript URL in Location header confirmed",
            )
        followed = safe_get(self.session, loc, self.timeout, raise_for_status=False, allow_redirects=True)
        if followed:
            final_url = followed.url or loc
            parsed = urlparse(final_url)
            if parsed.netloc and parsed.netloc != urlparse(detection.url).netloc:
                return ValidationResult(
                    confirmed=True,
                    signals=[f"redirected_to:{final_url[:80]}"],
                    method="redirect_follow",
                    detail=f"Redirect followed to external domain: {final_url}",
                )
        return ValidationResult(
            confirmed=False,
            method="redirect_not_followed",
            detail=f"Location header present but redirect not confirmed to external domain",
        )

    def generate_reproduction(self, detection: DetectionResult) -> list[str]:
        return [
            f"Send GET to {detection.url}",
            f"Observe redirect to external domain: {detection.context}",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
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
                        request=_build_curl("GET", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=resp.text[:500] if resp else "",
                        parameter=param,
                        steps_to_reproduce=self.generate_reproduction(detection),
                        verification_stage=VerificationStage.VALIDATED.value,
                    )
                    if f:
                        validation_result = self.validate(detection)
                        if validation_result and validation_result.confirmed:
                            f["verification_stage"] = VerificationStage.EXPLOITABLE.value
                        else:
                            f["verification_stage"] = VerificationStage.VALIDATED.value
                        fp = f.get("fingerprint", "")
                        if fp and self.evidence_engine is not None:
                            req_ev = HttpRequestEvidence(
                                method="GET",
                                url=detection.url,
                                curl_command=_build_curl("GET", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            )
                            self.evidence_engine.store(req_ev)
                            self.evidence_engine.link_to_finding(req_ev, fp)
                        self._enrich_finding(f, 0, f["verification_stage"])
                        self._add_finding(f)
                        if fp and self.evidence_engine is not None and resp is not None:
                            resp_ev = ResponseExcerptEvidence(
                                excerpt=resp.text[:500],
                                length=len(resp.text),
                                context="open_redirect",
                                description=f"Open redirect probe response at {detection.url}",
                            )
                            self.evidence_engine.store(resp_ev)
                            self.evidence_engine.link_to_finding(resp_ev, fp)
                    log(f"  [REDIRECT] {detection.url[:80]}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                    break
            except Exception:
                continue
        return self._get_findings()

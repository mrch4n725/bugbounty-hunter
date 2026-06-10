"""
SSTIScanner — 4-stage Server-Side Template Injection detection.

Lifecycle:
  DETECTED:   Template syntax reflected in response (arithmetic)
  VALIDATED:  Engine fingerprinted with engine-specific payloads
  EXPLOITABLE: Read-proof payload produced meaningful output
  VERIFIED:   (not applicable)

Maturity: Level 4 (Full lifecycle — typed evidence, reproduction, confidence)
"""

import re
from typing import Any
from urllib.parse import urlparse, parse_qs

from models.finding import Finding
from models.evidence import (
    HttpRequestEvidence,
    ResponseExcerptEvidence,
)
from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

POLYGLOT_PROBES = ["{{7*'7'}}${7*7}#{7*7}*{7*7}"]
BYPASS_PAYLOADS = [
    '{%raw%}{{7*7}}{%endraw%}',
    '{{ [].class.base.subclasses() }}',
    '｛｛7*7｝｝',
]

SSTI_PAYLOADS = {
    "arithmetic": [
        "{{7*7}}", "{{7+7}}", "{{7-7}}",
        "${7*7}", "${7+7}",
        "<%=7*7%>", "<%=7+7%>",
        "#{7*7}", "#{7+7}",
    ],
    "engine_fingerprint": [
        ("twig", "{{7*'7'}}", "49"),
        ("jinja2", "{{7*'7'}}", "7777777"),
        ("freemarker", "${7*7}", "49"),
        ("velocity", "#set($x=7*7)$x", "49"),
        ("razor", "@(7*7)", "49"),
        ("smarty", "{$smarty.now}", ""),
        ("mustache", "{{7*7}}", "49"),
    ],
    "read_proof": [
        "{{config}}", "{{self._TemplateReference__context}}",
        "${7*7}", "#{7*7}",
    ],
}

SSTI_ENGINE_PATTERNS = {
    "jinja2": [
        re.compile(r"\{\{7\*'7'\}\}.*?7777777"),
        re.compile(r"\{\{config\}\}"),
        re.compile(r"cycler|joiner|namespace|lipsum|dict|url_for|get_flashed_messages"),
    ],
    "twig": [
        re.compile(r"\{\{7\*'7'\}\}.*?49"),
        re.compile(r"\{\{7\*7\}\}"),
        re.compile(r"self\._TemplateReference__context"),
    ],
    "freemarker": [
        re.compile(r"\$\{7\*7\}"),
    ],
    "smarty": [
        re.compile(r"\{\$smarty"),
    ],
}


class SSTIScanner(ScannerBase):
    SCANNER_NAME = "ssti"
    SCANNER_MATURITY = 4
    TARGET_LEVEL = False

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _has_pre_existing_result(self, url: str, parameter: str) -> bool:
        """Fetch page without payload — skip if result values already present in baseline."""
        baseline = safe_get(self.session, url, self.timeout)
        if not baseline:
            return False
        body = baseline.text
        for val in ("49", "14", "0"):
            if val in body:
                return True
        for tpl in ("{{", "${", "<%=", "#{"):
            if tpl in body:
                return True
        return False

    def _error_fingerprint(self, url: str, parameter: str) -> str | None:
        test_url = self._inject_param(url, parameter, "{{")
        resp = safe_get(self.session, test_url, self.timeout)
        if not resp:
            return None
        body = resp.text
        if "jinja2.exceptions" in body:
            return "jinja2"
        if "freemarker.core" in body:
            return "freemarker"
        if "org.thymeleaf" in body:
            return "thymeleaf"
        if "velocity.app" in body:
            return "velocity"
        return None

    def detect(self, url: str, parameter: str) -> DetectionResult | None:
        if self._has_pre_existing_result(url, parameter):
            return None
        engine_from_error = self._error_fingerprint(url, parameter)
        if engine_from_error:
            self._detected_engine = engine_from_error
        test_value = "__SSTI_REFLECT_TEST__"
        reflect_url = self._inject_param(url, parameter, test_value)
        reflect_resp = safe_get(self.session, reflect_url, self.timeout)
        reflects_content = reflect_resp and test_value in reflect_resp.text
        if reflects_content:
            for payload in POLYGLOT_PROBES:
                test_url = self._inject_param(url, parameter, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if resp:
                    body = resp.text
                    if "7777777" in body or "49" in body:
                        second = "{{7*'7'}}${7*7}"
                        second_url = self._inject_param(url, parameter, second)
                        second_resp = safe_get(self.session, second_url, self.timeout)
                        second_confirmed = second_resp and ("7777777" in second_resp.text or "49" in second_resp.text)
                        signals = ["Polyglot detection"]
                        if second_confirmed:
                            signals.append("Dual arithmetic confirmed")
                            return DetectionResult(url=test_url, parameter=parameter, payload=payload, context="polyglot_dual", raw_response=resp, evidence_signals=signals)
                        return DetectionResult(url=test_url, parameter=parameter, payload=payload, context="polyglot", raw_response=resp, evidence_signals=signals)
        payloads = SSTI_PAYLOADS
        standard_sent_no_eval = False
        for payload in payloads.get("arithmetic", []):
            test_url = self._inject_param(url, parameter, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            body = resp.text
            arithmetic_possible = any(e in body for e in ["49", "14"])
            raw_payload_absent = payload not in body
            if payload == "{{7*7}}" and not arithmetic_possible:
                standard_sent_no_eval = True
            if arithmetic_possible and raw_payload_absent:
                second_payload = "{{7-7}}" if "7*7" in payload else "{{7+7}}"
                if payload.count("*") > 0:
                    second_payload = "{{7-7}}"
                elif payload.count("+") > 0:
                    second_payload = "{{7*7}}"
                elif payload.count("-") > 0:
                    second_payload = "{{7*7}}"
                else:
                    second_payload = "{{7-7}}"
                second_url = self._inject_param(url, parameter, second_payload)
                second_resp = safe_get(self.session, second_url, self.timeout)
                second_confirmed = False
                if second_resp:
                    second_body = second_resp.text
                    if "{{7-7}}" in second_payload and "0" in second_body and "{{7-7}}" not in second_body:
                        second_confirmed = True
                    elif "{{7+7}}" in second_payload and "14" in second_body and "{{7+7}}" not in second_body:
                        second_confirmed = True
                    elif "{{7*7}}" in second_payload and "49" in second_body and "{{7*7}}" not in second_body:
                        second_confirmed = True
                signals = ["Arithmetic evaluation detected"]
                if second_confirmed:
                    signals.append("Dual arithmetic confirmed")
                    context = "arithmetic"
                else:
                    context = "arithmetic_single"
                return DetectionResult(
                    url=test_url,
                    parameter=parameter,
                    payload=payload,
                    context=context,
                    raw_response=resp,
                    evidence_signals=signals,
                )
            if payload in body:
                return DetectionResult(
                    url=test_url,
                    parameter=parameter,
                    payload=payload,
                    context="reflection",
                    raw_response=resp,
                    evidence_signals=["Template syntax reflected"],
                )
        if standard_sent_no_eval:
            for payload in BYPASS_PAYLOADS:
                test_url = self._inject_param(url, parameter, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if resp and "49" in resp.text:
                    second = "{{7-7}}"
                    second_url = self._inject_param(url, parameter, second)
                    second_resp = safe_get(self.session, second_url, self.timeout)
                    second_confirmed = second_resp and "0" in second_resp.text and "{{7-7}}" not in second_resp.text
                    signals = ["Filter bypass SSTI"]
                    if second_confirmed:
                        signals.append("Dual arithmetic confirmed")
                    return DetectionResult(
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        context="bypass",
                        raw_response=resp,
                        evidence_signals=signals,
                    )
        if engine_from_error:
            return DetectionResult(
                url=url,
                parameter=parameter,
                payload="{{",
                context="error_fingerprint",
                raw_response=None,
                evidence_signals=[f"Engine identified from error: {engine_from_error}"],
            )
        return None

    def validate(self, detection: DetectionResult) -> dict | None:
        payloads = SSTI_PAYLOADS
        engine_sigs = []
        for engine, payload, expected in payloads.get("engine_fingerprint", []):
            test_url = self._inject_param(detection.url, detection.parameter, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if resp and expected and expected in resp.text:
                engine_sigs.append(engine)
            elif resp and payload in resp.text:
                engine_sigs.append(f"reflected_{engine}")
        verified_engine = None
        engine_bodies = []
        for engine_name, fp_payload, expected in payloads.get("engine_fingerprint", []):
            test_url = self._inject_param(detection.url, detection.parameter, fp_payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if resp:
                engine_bodies.append((engine_name, resp.text))
        for engine, pattern_list in SSTI_ENGINE_PATTERNS.items():
            for pattern in pattern_list:
                for eng_name, body in engine_bodies:
                    if pattern.search(body):
                        verified_engine = engine
                        break
                if verified_engine:
                    break
            if verified_engine:
                break
        if verified_engine:
            return {"confirmed": True, "engine": verified_engine, "method": "engine_fingerprint"}
        if engine_sigs:
            return {"confirmed": False, "engine": engine_sigs[0] if engine_sigs else None, "method": "reflection"}
        return {"confirmed": False, "engine": None, "method": "none"}

    def exploit(self, detection: DetectionResult, validation: dict | None = None) -> dict:
        payloads = SSTI_PAYLOADS
        for payload in payloads.get("read_proof", []):
            test_url = self._inject_param(detection.url, detection.parameter, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if resp and len(resp.text) > 500 and payload not in resp.text:
                return {"confirmed": True, "proof": f"Read-proof payload '{payload}' produced {len(resp.text)} chars of output", "response": resp}
        return {"confirmed": False, "proof": ""}

    def generate_reproduction(self, detection: DetectionResult, stage: str = "detected",
                              engine: str | None = None, proof: str = "") -> list[str]:
        if stage == "detected":
            return [
                f"curl -X GET '{detection.url}?{detection.parameter}={detection.payload}'",
                "Observe template syntax reflected in the response — unsanitized template expression confirms injection point",
                "An attacker can execute arbitrary code on the server via template engine RCE, leading to full server compromise",
            ]
        elif stage == "validated":
            return [
                f"curl -X GET '{detection.url}?{detection.parameter}={detection.payload}'",
                f"Observe arithmetic evaluation in response—template engine evaluates expressions{(', engine fingerprinted as ' + engine) if engine else ''}",
                "Confirmed template injection allows code execution: read files, access environment variables, and potentially execute OS commands",
            ]
        elif stage == "exploitable":
            return [
                f"curl -X GET '{detection.url}?{detection.parameter}={detection.payload}'",
                "Observe read-proof output indicating full server-side execution — engine evaluation produces arbitrary output",
                "Full server-side template execution achieved: read /etc/passwd, access environment variables, execute OS commands via template engine RCE vectors",
            ]
        return [
            f"curl -X GET '{detection.url}?{detection.parameter}={detection.payload}'",
            "Observe template syntax in response",
            "An attacker can execute arbitrary code on the server via template engine RCE",
        ]

    def collect_evidence(self, detection: DetectionResult,
                         validation: dict | None = None,
                         exploitation: dict | None = None) -> list:
        ev_list = []
        resp = detection.raw_response
        if resp:
            ev_list.append(HttpRequestEvidence(
                method="GET",
                url=detection.url,
                curl_command=_build_curl("GET", detection.url, dict(self.session.headers),
                                         cookies=safe_cookies_dict(self.session.cookies)),
                description=f"SSTI detection probe: {detection.payload}",
            ))
            ev_list.append(ResponseExcerptEvidence(
                excerpt=resp.text[:500],
                length=len(resp.text),
                context=detection.context,
                description=f"SSTI detection response ({detection.context})",
            ))
        if validation and validation.get("confirmed"):
            ev_list.append(ResponseExcerptEvidence(
                excerpt=f"Engine fingerprinted: {validation.get('engine', 'unknown')} | Method: {validation.get('method', '')}",
                length=0,
                context="engine_fingerprint",
                description=f"SSTI validation: {validation.get('engine', 'unknown')} engine",
            ))
        if exploitation and exploitation.get("confirmed"):
            proof = exploitation.get("proof", "")[:200]
            ev_list.append(ResponseExcerptEvidence(
                excerpt=proof,
                length=len(proof),
                context="read_proof",
                description=f"SSTI exploitation proof: {proof[:80]}",
            ))
        return ev_list

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        template_params = {"template", "name", "message", "content", "body", "title", "subject", "text", "input", "value", "data", "html", "page", "view"}
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                params.sort(key=lambda p: 0 if p.lower() in template_params else 1)
                for param in params:
                    detection = self.detect(url, param)
                    if detection is None:
                        continue
                    validation = self.validate(detection)
                    exploitation = self.exploit(detection, validation)

                    has_arithmetic = detection.context in ("arithmetic", "polyglot_dual", "bypass")
                    confirmed_engine = validation and validation.get("confirmed")
                    read_proof = exploitation.get("confirmed")

                    if read_proof:
                        title = "Confirmed SSTI"
                        severity = "critical"
                        stage = VerificationStage.EXPLOITABLE.value
                        engine = validation.get("engine") if validation else None
                    elif confirmed_engine or has_arithmetic:
                        title = "Likely SSTI"
                        severity = "high"
                        stage = VerificationStage.VALIDATED.value
                    else:
                        title = "Potential SSTI"
                        severity = "medium"
                        stage = VerificationStage.DETECTED.value

                    evidence = self.collect_evidence(detection, validation, exploitation)
                    resp = detection.raw_response
                    engine_str = validation.get("engine", "") if validation else ""
                    f = finding(
                        vuln_type=title,
                        url=detection.url,
                        severity=severity,
                        details=f"Parameter '{param}': {title.lower()} detected" + (f" (engine: {engine_str})" if engine_str else ""),
                        evidence=f"Context: {detection.context}" + (f", Engine: {engine_str}" if engine_str else "") + (f", Proof: {exploitation.get('proof', '')[:100]}" if read_proof else ""),
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=resp.text[:500] if resp else "",
                        parameter=param,
                        steps_to_reproduce=self.generate_reproduction(detection, stage, engine_str, exploitation.get("proof", "")),
                        verification_stage=stage,
                    )
                    if f:
                        for ev in evidence:
                            self.evidence_engine.store(ev)
                            self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                        self._enrich_finding(f, len(evidence), f["verification_stage"])
                        self._add_finding(f)
            except Exception as e:
                log(f"  [SSTI] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        return self._get_findings()

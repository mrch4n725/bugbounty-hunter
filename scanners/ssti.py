"""
SSTIScanner — 4-stage Server-Side Template Injection detection.

Lifecycle:
  DETECTED:   Template syntax reflected in response (arithmetic)
  VALIDATED:  Engine fingerprinted with engine-specific payloads
  EXPLOITABLE: Read-proof payload produced meaningful output
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate + Exploit safe proof)
"""

import re
from typing import Any
from urllib.parse import urlparse, parse_qs

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase, DetectionResult

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
    SCANNER_MATURITY = 3
    TARGET_LEVEL = False

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def detect(self, url: str, parameter: str) -> DetectionResult | None:
        payloads = SSTI_PAYLOADS
        for payload in payloads.get("arithmetic", []):
            test_url = self._inject_param(url, parameter, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            body = resp.text
            arithmetic_possible = any(e in body for e in ["49", "14", "0"])
            raw_payload_absent = payload not in body
            if arithmetic_possible and raw_payload_absent:
                return DetectionResult(
                    url=test_url,
                    parameter=parameter,
                    payload=payload,
                    context="arithmetic",
                    raw_response=resp,
                    evidence_signals=["Arithmetic evaluation detected"],
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
        steps = [f"Send request to {detection.url} with payload '{detection.payload}' in parameter '{detection.parameter}'"]
        if stage == "detected":
            steps.append("Observe template syntax in response")
        elif stage == "validated":
            steps.append("Observe arithmetic evaluation in response")
            if engine:
                steps.append(f"Engine fingerprinted as {engine}")
        elif stage == "exploitable":
            steps.append("Observe read-proof output indicating full server-side execution")
        return steps

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    detection = self.detect(url, param)
                    if detection is None:
                        continue
                    validation = self.validate(detection)
                    exploitation = self.exploit(detection, validation)

                    has_arithmetic = detection.context == "arithmetic"
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

                    resp = detection.raw_response
                    engine_str = validation.get("engine", "") if validation else ""
                    f = finding(
                        vuln_type=title,
                        url=detection.url,
                        severity=severity,
                        details=f"Parameter '{param}': {title.lower()} detected" + (f" (engine: {engine_str})" if engine_str else ""),
                        evidence=f"Context: {detection.context}" + (f", Engine: {engine_str}" if engine_str else "") + (f", Proof: {exploitation.get('proof', '')[:100]}" if read_proof else ""),
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500] if resp else "",
                        parameter=param,
                        steps_to_reproduce=self.generate_reproduction(detection, stage, engine_str, exploitation.get("proof", "")),
                        verification_stage=stage,
                    )
                    if f:
                        self._add_finding(f)
            except Exception as e:
                log(f"  [SSTI] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        return self._get_findings()

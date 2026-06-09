"""
HttpMethodsScanner — discovers dangerous HTTP methods (TRACE, PUT, DELETE, etc.).

Lifecycle:
  DETECTED:   OPTIONS response reveals dangerous HTTP methods
  VALIDATED:  Per-method probe confirms method is actually enabled
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 2 (Detect + Validate)
"""

import json

from modules.utils import (
    safe_get, finding, VerificationStage, log, Colors, _build_curl,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence


class HttpMethodsScanner(ScannerBase):
    SCANNER_NAME = "http_methods"
    SCANNER_MATURITY = 2
    TARGET_LEVEL = True
    SCANNER_ORDER = 10

    DANGEROUS_METHODS = {"TRACE", "PUT", "DELETE", "PATCH", "PROPFIND"}

    def _normalize_list(self, value):
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return value
        return [value]

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        try:
            resp = self.session.options(url, timeout=self.timeout)
            if not resp:
                return None
            allow_header = resp.headers.get("Allow", "")
            cors_methods = resp.headers.get("Access-Control-Allow-Methods", "")
            methods = set(self._normalize_list(allow_header) + self._normalize_list(cors_methods))
            exposed = [m for m in methods if m.upper() in self.DANGEROUS_METHODS]
            if not exposed:
                return None
            return DetectionResult(
                url=url,
                parameter="",
                payload=", ".join(exposed),
                context="dangerous_methods",
                raw_response=resp,
                evidence_signals=[f"Enabled: {', '.join(exposed)}"],
            )
        except Exception:
            return None

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        url = detection.url
        methods = [m.strip() for m in detection.payload.split(",")]
        confirmed_methods: list[str] = []

        for method in methods:
            try:
                if method.upper() == "TRACE":
                    resp = self.session.request("TRACE", url, timeout=self.timeout)
                    if resp and resp.status_code in (200, 201, 202):
                        confirmed_methods.append(method)
                elif method.upper() == "PUT":
                    resp = self.session.put(url, data="test", timeout=self.timeout)
                    if resp and resp.status_code not in (405, 501, 403):
                        confirmed_methods.append(method)
                elif method.upper() == "DELETE":
                    resp = self.session.delete(url, timeout=self.timeout)
                    if resp and resp.status_code not in (405, 501, 403):
                        confirmed_methods.append(method)
                elif method.upper() == "PATCH":
                    resp = self.session.patch(url, data="test", timeout=self.timeout)
                    if resp and resp.status_code not in (405, 501, 403):
                        confirmed_methods.append(method)
                elif method.upper() == "PROPFIND":
                    resp = self.session.request("PROPFIND", url, timeout=self.timeout)
                    if resp and resp.status_code not in (405, 501, 403):
                        confirmed_methods.append(method)
            except Exception:
                continue

        if confirmed_methods:
            return ValidationResult(
                confirmed=True,
                signals=confirmed_methods,
                method="per_method_probe",
                detail=f"Dangerous HTTP methods confirmed enabled: {', '.join(confirmed_methods)}",
            )
        return ValidationResult(
            confirmed=False,
            method="per_method_probe",
            detail="Methods advertised in OPTIONS but not confirmed via per-method probes",
        )

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence
        resp = detection.raw_response
        if not resp:
            return []
        return [
            HttpRequestEvidence(
                method="OPTIONS",
                url=detection.url,
                curl_command=_build_curl("OPTIONS", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
            ),
            ResponseExcerptEvidence(
                excerpt=resp.text[:500],
                length=len(resp.text),
                context="http_methods_check",
            ),
        ]

    def generate_reproduction(self, f: dict) -> list[str]:
        return [
            f"Send OPTIONS request to {f['url']} and inspect the Allow header",
            f"Server advertises dangerous methods: {f.get('evidence', '')}",
            f"Test each method (e.g., curl -X PUT {f['url']}) to verify it is actually enabled, not just advertised",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        targets = target_urls if target_urls else [self.base_url]
        for target in targets:
            if not target or not self._in_scope(target):
                continue
            try:
                detection = self.detect(target)
                if detection is None:
                    continue

                validation_result = self.validate(detection)
                evidence_list = self.collect_evidence(detection, validation_result)

                for ev in evidence_list:
                    self.evidence_engine.store(ev)

                stage = VerificationStage.VALIDATED.value if (validation_result and validation_result.confirmed) else VerificationStage.DETECTED.value

                f = finding(
                    vuln_type="Dangerous HTTP Methods Enabled",
                    url=target,
                    severity="medium",
                    details=f"The server supports non-safe HTTP methods: {detection.payload}",
                    evidence=f"Allowed methods: {detection.payload}",
                    request=_build_curl("OPTIONS", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=detection.raw_response.text[:500] if detection.raw_response else "",
                    steps_to_reproduce=self.generate_reproduction(f),
                    verification_stage=stage,
                )
                if f:
                    self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                    fingerprint = f.get("fingerprint", "")
                    if fingerprint:
                        for ev in evidence_list:
                            self.evidence_engine.link_to_finding(ev, fingerprint)
                    self._add_finding(f)
                    log(f"  [HTTP METHODS] {target} -> {detection.payload}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

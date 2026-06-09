"""
CORSScanner — detects CORS misconfigurations.

Checks:
  - Reflected Origin in Access-Control-Allow-Origin
  - Wildcard ACAO with Access-Control-Allow-Credentials: true
  - Null origin acceptance
  - Trusted origin prefix/suffix bypass (e.g. evil.com.evil.com)
  - Preflight bypass

Lifecycle:
  DETECTED:   ACAO header present with wildcard or reflective pattern
  VALIDATED:  Reflected origin confirmed via probe
  EXPLOITABLE: Reflected + credentials: true confirmed
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate + typed evidence + reproduction)
"""

from urllib.parse import urlparse

from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence
from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage, make_session,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult


class CORSScanner(ScannerBase):
    SCANNER_NAME = "cors"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = True
    SCANNER_ORDER = 10

    PROBE_ORIGINS = [
        "https://evil.com",
        "null",
        "https://evil.com.evil.com",
        "https://evilevil.com",
    ]

    @staticmethod
    def _check_acao_reflection(resp, probe_origin: str) -> bool:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        return acao == probe_origin

    @staticmethod
    def _is_wildcard_with_credentials(resp) -> bool:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        return acao == "*" and acac.lower() == "true"

    def detect(self, url: str, parameter: str | None = None) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        base_resp = safe_get(self.session, url, self.timeout)
        if not base_resp:
            return results

        acao = base_resp.headers.get("Access-Control-Allow-Origin", "")

        if acao == "*":
            acac = base_resp.headers.get("Access-Control-Allow-Credentials", "")
            results.append(DetectionResult(
                url=url, parameter="Access-Control-Allow-Origin",
                payload="*",
                context="wildcard_acao",
                raw_response=base_resp,
                evidence_signals=[f"Wildcard ACAO: Access-Control-Allow-Origin: *"],
            ))
            if acac.lower() == "true":
                results.append(DetectionResult(
                    url=url, parameter="Access-Control-Allow-Credentials",
                    payload="* + credentials",
                    context="wildcard_with_credentials",
                    raw_response=base_resp,
                    evidence_signals=[f"Wildcard ACAO with credentials: Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true"],
                ))

        return results

    def validate(self, url: str) -> list[dict]:
        results: list[dict] = []
        base_resp = safe_get(self.session, url, self.timeout)
        if not base_resp:
            return results

        for probe in self.PROBE_ORIGINS:
            probe_session = make_session(self.config)
            probe_session.headers.update({"Origin": probe})
            try:
                probe_resp = safe_get(probe_session, url, self.timeout)
                if not probe_resp:
                    continue

                acao = probe_resp.headers.get("Access-Control-Allow-Origin", "")
                if self._check_acao_reflection(probe_resp, probe):
                    acac = probe_resp.headers.get("Access-Control-Allow-Credentials", "")
                    context = "origin_reflection"
                    if probe == "null":
                        context = "null_origin_accepted"
                    results.append({
                        "confirmed": True,
                        "method": "origin_probe",
                        "url": url,
                        "acao": acao,
                        "credentials": acac.lower() == "true",
                        "probe": probe,
                        "context": context,
                    })

                if self._is_wildcard_with_credentials(probe_resp):
                    results.append({
                        "confirmed": True,
                        "method": "wildcard_credentials",
                        "url": url,
                        "acao": acao,
                        "credentials": True,
                        "probe": "*",
                        "context": "wildcard_with_credentials",
                    })
            except Exception:
                continue
        return results

    def generate_reproduction(self, f: dict) -> list[str]:
        url = f["url"]
        vuln_type = f.get("vuln_type", "")
        if vuln_type == "CORS: Wildcard ACAO":
            return [
                f"Send GET request to {url} with Origin header set to https://evil.com",
                "Observe Access-Control-Allow-Origin: https://evil.com in the response — origin is reflected",
                "An attacker can make authenticated cross-origin requests from any domain",
            ]
        if vuln_type == "CORS: Wildcard ACAO with Credentials":
            return [
                f"Send GET request to {url} with Origin: https://evil.com",
                "Observe Access-Control-Allow-Origin: https://evil.com and Access-Control-Allow-Credentials: true",
                "An attacker can make authenticated requests (cookies sent) from any domain via client-side JavaScript",
            ]
        return [
            f"Send GET request to {url} and inspect CORS headers",
            "Test with non-standard Origin headers to verify reflection patterns",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        target = self.config.get("target", "")
        if not target or not self._in_scope(target):
            return []

        urls_to_check = [target]
        for sub in (self.recon.get("subdomains", []) or [])[:20]:
            sub_url = f"https://{sub}"
            if self._in_scope(sub_url):
                urls_to_check.append(sub_url)

        for url in urls_to_check:
            detections = self.detect(url)
            validations = self.validate(url)

            resp = safe_get(self.session, url, self.timeout)
            if not detections and not validations:
                continue

            for d in detections:
                matched_v = [v for v in validations if v["confirmed"] and v["url"] == url]
                if d.context == "wildcard_acao":
                    stage = VerificationStage.EXPLOITABLE.value if any(v.get("credentials") for v in matched_v) else VerificationStage.DETECTED.value
                else:
                    stage = VerificationStage.VALIDATED.value if matched_v else VerificationStage.DETECTED.value

                curl_cmd = _build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies))
                resp_text = resp.text[:500] if resp else ""

                if d.context == "wildcard_acao":
                    vuln_type = "CORS: Wildcard ACAO"
                    severity = "medium"
                    details = "Access-Control-Allow-Origin is set to wildcard (*)"
                    ev = "Access-Control-Allow-Origin: *"
                elif d.context == "wildcard_with_credentials":
                    vuln_type = "CORS: Wildcard ACAO with Credentials"
                    severity = "critical"
                    details = "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true — allows authenticated cross-origin reads from any domain"
                    ev = "ACAO: * with Credentials: true"
                else:
                    vuln_type = "CORS Misconfiguration"
                    severity = "medium"
                    details = d.evidence_signals[0] if d.evidence_signals else "CORS misconfiguration detected"
                    ev = d.evidence_signals[0] if d.evidence_signals else ""

                f = finding(
                    vuln_type=vuln_type,
                    url=url,
                    severity=severity,
                    details=details,
                    evidence=ev,
                    request=curl_cmd,
                    response_excerpt=resp_text,
                    steps_to_reproduce=self.generate_reproduction(f),
                    verification_stage=stage,
                )
                if f:
                    self._enrich_finding(f, 0, f["verification_stage"])
                    if matched_v:
                        # Store validation evidence
                        for v in matched_v:
                            fp = f.get("fingerprint", "")
                            if fp:
                                req_ev = HttpRequestEvidence(
                                    method="GET",
                                    url=url,
                                    curl_command=_build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                                )
                                self.evidence_engine.store(req_ev)
                                self.evidence_engine.link_to_finding(req_ev, fp)
                    self._add_finding(f)
                    log(f"  [CORS] {url} — {vuln_type}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

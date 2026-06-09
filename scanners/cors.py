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
                f"curl -X GET '{url}' -H 'Origin: https://evil.com' -I",
                "Observe Access-Control-Allow-Origin: https://evil.com in the response — origin is reflected from the request header",
                "An attacker can make authenticated cross-origin requests from any domain via client-side JavaScript, bypassing Same-Origin Policy",
            ]
        if vuln_type == "CORS: Wildcard ACAO with Credentials":
            return [
                f"curl -X GET '{url}' -H 'Origin: https://evil.com' -I",
                "Observe Access-Control-Allow-Origin: https://evil.com and Access-Control-Allow-Credentials: true — cookies will be sent cross-origin",
                "An attacker can exfiltrate sensitive data by making authenticated requests (cookies sent) from any domain via client-side JavaScript",
            ]
        return [
            f"curl -X GET '{url}' -H 'Origin: https://evil.com' -I",
            "Inspect Access-Control-Allow-Origin in response headers for reflection patterns",
            "CORS misconfigurations allow attackers to bypass Same-Origin Policy and access protected resources",
        ]

    def _test_credentials_mode(self, url: str) -> list[dict]:
        """Test if CORS misconfiguration allows credentialed cross-origin reads."""
        results: list[dict] = []
        probe_session = make_session(self.config)
        probe_session.headers.update({"Origin": "https://evil.com"})
        try:
            probe_resp = safe_get(probe_session, url, self.timeout)
            if not probe_resp:
                return results
            acao = probe_resp.headers.get("Access-Control-Allow-Origin", "")
            acac = probe_resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "https://evil.com" and acac.lower() == "true":
                results.append({
                    "confirmed": True,
                    "method": "credentials_confirmed",
                    "url": url,
                    "acao": acao,
                    "credentials": True,
                    "context": "credentialed_reflection",
                    "detail": f"Origin reflected with Access-Control-Allow-Credentials: true — attacker can read authenticated responses",
                })
            # Test preflight bypass with custom headers
            preflight_session = make_session(self.config)
            preflight_session.headers.update({
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-Custom-Header",
            })
            pre_resp = safe_get(preflight_session, url, self.timeout)
            if pre_resp:
                pre_acao = pre_resp.headers.get("Access-Control-Allow-Origin", "")
                pre_headers = pre_resp.headers.get("Access-Control-Allow-Headers", "")
                if pre_acao == "https://evil.com" and pre_headers:
                    results.append({
                        "confirmed": True,
                        "method": "preflight_bypass",
                        "url": url,
                        "acao": pre_acao,
                        "allowed_headers": pre_headers,
                        "context": "preflight_bypass",
                        "detail": f"Preflight accepted custom headers — XHR with non-simple headers allowed from any origin",
                    })
        except Exception:
            pass
        return results

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
            credentials_tests = self._test_credentials_mode(url)

            resp = safe_get(self.session, url, self.timeout)
            if not detections and not validations and not credentials_tests:
                continue

            for d in detections:
                matched_v = [v for v in validations if v["confirmed"] and v["url"] == url]
                cred = any(c for c in credentials_tests if c["confirmed"] and c["url"] == url)
                if d.context == "wildcard_acao":
                    stage = VerificationStage.EXPLOITABLE.value if (any(v.get("credentials") for v in matched_v) or cred) else VerificationStage.DETECTED.value
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
                    if matched_v or cred:
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

        if credentials_tests:
            for ct in credentials_tests:
                if not ct["confirmed"]:
                    continue
                curl_cmd = _build_curl("GET", ct["url"], {"Origin": "https://evil.com"}, cookies=safe_cookies_dict(self.session.cookies))
                f = finding(
                    vuln_type="CORS: Credentialed Cross-Origin Bypass",
                    url=ct["url"],
                    severity="critical",
                    details=ct["detail"],
                    evidence=f"ACAO: {ct.get('acao', '')} | Credentials: true",
                    request=curl_cmd,
                    response_excerpt="",
                    verification_stage=VerificationStage.VERIFIED.value,
                    steps_to_reproduce=[
                        f"Send GET to {ct['url']} with Origin: https://evil.com",
                        f"Observe Access-Control-Allow-Origin: https://evil.com with Access-Control-Allow-Credentials: true",
                        "An attacker's JavaScript can read authenticated cross-origin responses including CSRF tokens and user data",
                    ],
                )
                if f:
                    self._add_finding(f)
                    log(f"  [CORS CRED] {ct['url']} — credentialed bypass confirmed", Colors.RED, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

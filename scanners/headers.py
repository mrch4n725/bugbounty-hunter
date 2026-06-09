"""
HeadersScanner — security header analysis.

Lifecycle:
  DETECTED:   Required header is missing, or information is disclosed
  VALIDATED:  CORS origin reflection confirmed
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 4 (Full lifecycle — typed evidence, reproduction, confidence, skip legacy)
"""

from typing import Any

from models.finding import Finding
from models.evidence import ResponseExcerptEvidence, HttpRequestEvidence
from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

SECURITY_HEADERS = {
    "Strict-Transport-Security": "high",
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "medium",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
    "X-XSS-Protection": "low",
}


class HeadersScanner(ScannerBase):
    SCANNER_NAME = "headers"
    TARGET_LEVEL = True
    SCANNER_MATURITY = 4

    # ── Detection phase ─────────────────────────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        resp = safe_get(self.session, url, self.timeout)
        if not resp:
            return results

        # Missing security headers
        for header, severity in SECURITY_HEADERS.items():
            if header not in resp.headers:
                results.append(DetectionResult(
                    url=url,
                    parameter=header,
                    payload="",
                    context="missing_header",
                    raw_response=resp,
                    evidence_signals=[f"Missing {header}"],
                ))

        # Information disclosure (Server, X-Powered-By)
        disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for h in disclosure_headers:
            val = resp.headers.get(h, "")
            if val and not self._is_safe_disclosure(val):
                results.append(DetectionResult(
                    url=url,
                    parameter=h,
                    payload=val,
                    context="information_disclosure",
                    raw_response=resp,
                    evidence_signals=[f"Disclosure: {h}={val}"],
                ))

        # Weak CSP
        csp = resp.headers.get("Content-Security-Policy", "")
        if csp:
            csp_lower = csp.lower()
            directives = dict(p.split(None, 1) if ' ' in p else (p, '') for p in csp_lower.split(';'))
            weak_directives = []
            for directive, value in directives.items():
                directive = directive.strip()
                value = value.strip()
                if directive in ("default-src", "script-src", "object-src", "frame-src", "base-uri"):
                    if "unsafe-inline" in value or "unsafe-eval" in value or value == "*" or value.startswith("* "):
                        weak_directives.append(directive)
            if weak_directives:
                evidence = "; ".join(f"{d} has {'unsafe-inline/unsafe-eval/wildcard' if d in weak_directives else 'weak value'}" for d in weak_directives)
                results.append(DetectionResult(
                    url=url,
                    parameter="Content-Security-Policy",
                    payload=csp[:120],
                    context="weak_csp",
                    raw_response=resp,
                    evidence_signals=[f"Weak CSP directive(s): {', '.join(weak_directives)}"],
                ))

        # Cookie analysis
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            if "Secure" not in set_cookie or "HttpOnly" not in set_cookie:
                results.append(DetectionResult(
                    url=url,
                    parameter="Set-Cookie",
                    payload=set_cookie[:120],
                    context="insecure_cookie",
                    raw_response=resp,
                    evidence_signals=["Insecure cookie flag"],
                ))

        # CORS (requires probe — mark as detection)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or not acao:
            pass  # CORS reflection needs a validated probe
        return results

    def _is_safe_disclosure(self, val: str) -> bool:
        safe_servers = ["cloudflare", "nginx", "apache", "amazons3", "cloudfront", "github.com"]
        return any(s in val.lower() for s in safe_servers)

    # ── Validation phase (CORS origin reflection) ───────────────────────

    def validate(self, url: str, resp) -> list[dict]:
        results: list[dict] = []
        # CORS origin reflection: send a probe Origin header
        from modules.utils import make_session
        probe_session = make_session(self.config)
        probe_session.headers.update({"Origin": "https://evil.com"})
        try:
            probe_resp = safe_get(probe_session, url, self.timeout)
            if probe_resp:
                reflected = probe_resp.headers.get("Access-Control-Allow-Origin", "")
                if reflected == "https://evil.com":
                    acac = probe_resp.headers.get("Access-Control-Allow-Credentials", "")
                    results.append({
                        "confirmed": True,
                        "method": "cors_origin_reflection",
                        "url": url,
                        "acao": reflected,
                        "credentials": "true" in acac.lower() if acac else False,
                    })
        except Exception:
            pass
        return results

    # ── Scan entry point ────────────────────────────────────────────────

    def generate_reproduction(self, detection: DetectionResult | None = None) -> list[str]:
        if detection:
            url = detection.url
            header = detection.parameter
            context = detection.context
            if context == "missing_header":
                return [
                    f"Send GET request to {url}",
                    f"Observe missing security header: {header}",
                ]
            elif context == "information_disclosure":
                return [
                    f"Send GET request to {url}",
                    f"Observe information disclosure header: {header}={detection.payload}",
                ]
            elif context == "weak_csp":
                return [
                    f"Send GET request to {url}",
                    f"Observe weak Content-Security-Policy: {detection.payload[:80]}",
                ]
            elif context == "insecure_cookie":
                return [
                    f"Send GET request to {url}",
                    f"Observe insecure cookie flags: {detection.payload[:80]}",
                ]
        return [
            "Send GET request to the target URL",
            "Inspect response headers for security misconfigurations",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        target = self.config.get("target", "")
        if not target or not self._in_scope(target):
            return []

        findings: list[dict] = []
        urls_to_check = [target]
        for sub in (self.recon.get("subdomains", []) or [])[:20]:
            sub_url = f"https://{sub}"
            if self._in_scope(sub_url):
                urls_to_check.append(sub_url)

        for url in urls_to_check:
            detections = self.detect(url)
            cors_validations = []

            resp = safe_get(self.session, url, self.timeout)
            if resp:
                cors_validations = self.validate(url, resp)

            for d in detections:
                is_cors = any(
                    v["confirmed"] and v["url"] == url
                    for v in cors_validations
                    if d.parameter == "Access-Control-Allow-Origin"
                )
                stage = VerificationStage.VALIDATED.value if is_cors else VerificationStage.DETECTED.value

                curl_cmd = _build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies))
                resp_text = resp.text[:500] if resp else ""
                f = finding(
                    vuln_type=f"Missing Security Header: {d.parameter}" if d.context == "missing_header"
                    else f"Information Disclosure: {d.parameter}" if d.context == "information_disclosure"
                    else f"Weak Content Security Policy" if d.context == "weak_csp"
                    else f"Insecure Cookie" if d.context == "insecure_cookie"
                    else d.parameter,
                    url=url,
                    severity="low" if d.context in ("insecure_cookie", "information_disclosure") else "medium",
                    details=f"{d.context.replace('_', ' ').title()}: {d.payload[:100]}",
                    evidence=d.payload,
                    request=curl_cmd,
                    response_excerpt=resp_text,
                    steps_to_reproduce=[
                        f"Send GET request to {url} and inspect response headers (curl -I or browser DevTools > Network tab)",
                        "Recommended security headers for web applications: Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security, X-Frame-Options, Referrer-Policy, Permissions-Policy",
                    ] if d.context == "missing_header" else ([
                        f"Send GET request to {url} and inspect response headers",
                        f"Observe {d.context.replace('_', ' ')}: {d.payload[:80]}",
                    ] if d.context != "weak_csp" else [
                        f"Send GET request to {url} and inspect Content-Security-Policy header",
                        f"Weak directive(s) found — inspect the full CSP value: {d.payload[:120]}",
                        "A strict CSP should avoid unsafe-inline, unsafe-eval, and wildcard (*) sources",
                    ]),
                    verification_stage=stage,
                )
                if f:
                    self._enrich_finding(f, 1, f["verification_stage"])
                    self._add_finding(f)
                    findings.append(f)
                    fp = f.get("fingerprint", "")
                    if fp and self.evidence_engine is not None and resp is not None:
                        req_ev = HttpRequestEvidence(
                            method="GET",
                            url=url,
                            curl_command=curl_cmd,
                            description=f"Header check request at {url}",
                        )
                        self.evidence_engine.store(req_ev)
                        self.evidence_engine.link_to_finding(req_ev, fp)
                        resp_ev = ResponseExcerptEvidence(
                            excerpt=resp.text[:500],
                            length=len(resp.text),
                            context=d.context,
                            description=f"Response for header check at {url}",
                        )
                        self.evidence_engine.store(resp_ev)
                        self.evidence_engine.link_to_finding(resp_ev, fp)

        return self._get_findings()

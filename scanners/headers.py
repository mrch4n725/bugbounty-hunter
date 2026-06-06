"""
HeadersScanner — security header analysis.

Lifecycle:
  DETECTED:   Required header is missing, or information is disclosed
  VALIDATED:  CORS origin reflection confirmed
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 2 (Detect + limited Validate)
"""

from typing import Any

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase, DetectionResult

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
    SCANNER_MATURITY = 2

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
            if "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp:
                results.append(DetectionResult(
                    url=url,
                    parameter="Content-Security-Policy",
                    payload=csp[:120],
                    context="weak_csp",
                    raw_response=resp,
                    evidence_signals=["Weak CSP: " + ("unsafe-inline" if "unsafe-inline" in csp else "unsafe-eval" if "unsafe-eval" in csp else "wildcard")],
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

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
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
                    verification_stage=stage,
                    response_excerpt="",
                )
                if f:
                    self._add_finding(f)
                    findings.append(f)

        return self._get_findings()

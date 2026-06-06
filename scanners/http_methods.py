"""
HttpMethodsScanner — discovers dangerous HTTP methods (TRACE, PUT, DELETE, etc.).

Lifecycle:
  DETECTED:   OPTIONS response reveals dangerous HTTP methods
  VALIDATED:  (not applicable)
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 1 (Detection only)
"""

from modules.utils import (
    safe_get, finding, VerificationStage, log, Colors, _build_curl,
)
from scanners.base import ScannerBase
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence


class HttpMethodsScanner(ScannerBase):
    SCANNER_NAME = "http_methods"
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

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        targets = target_urls if target_urls else [self.base_url]
        for target in targets:
            if not target or not self._in_scope(target):
                continue
            try:
                resp = self.session.options(target, timeout=self.timeout)
                if not resp:
                    continue
                allow_header = resp.headers.get("Allow", "")
                cors_methods = resp.headers.get("Access-Control-Allow-Methods", "")
                methods = set(self._normalize_list(allow_header) + self._normalize_list(cors_methods))
                exposed = [m for m in methods if m.upper() in self.DANGEROUS_METHODS]
                if exposed:
                    req_ev = HttpRequestEvidence(
                        method="OPTIONS",
                        url=target,
                        curl_command=_build_curl("OPTIONS", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                    )
                    resp_ev = ResponseExcerptEvidence(
                        excerpt=resp.text[:500],
                        length=len(resp.text),
                        context="http_methods_check",
                    )
                    req_fp = self.evidence_engine.store(req_ev)
                    resp_fp = self.evidence_engine.store(resp_ev)

                    f = finding(
                        vuln_type="Dangerous HTTP Methods Enabled",
                        url=target,
                        severity="medium",
                        details=f"The server supports non-safe HTTP methods: {', '.join(exposed)}",
                        evidence=f"Allowed methods: {', '.join(sorted(methods))}",
                        request=_build_curl("OPTIONS", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[
                            f"Send OPTIONS request to {target}",
                            f"Observe dangerous methods: {', '.join(exposed)}",
                        ],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self.evidence_engine.link_to_finding(req_ev, f.get("fingerprint", ""))
                        self.evidence_engine.link_to_finding(resp_ev, f.get("fingerprint", ""))
                        self._add_finding(f)
                    log(f"  [HTTP METHODS] {target} -> {', '.join(exposed)}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

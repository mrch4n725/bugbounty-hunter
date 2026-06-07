"""
SubdomainTakeoverScanner — detects vulnerable subdomains pointing to defunct services.

Lifecycle:
  DETECTED:   Known takeover signature found in subdomain response
  VALIDATED:  (not applicable)
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 1 (Detection only)
"""

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase

TAKEOVER_SIGNATURES = [
    "NoSuchBucket", "There isn't a GitHub Pages site here.",
    "Fastly error: unknown domain", "No such app",
    "The requested URL was not found on this server.",
    "A DNS leak or misconfiguration", "NoSuchDomain", "No such host",
]


class SubdomainTakeoverScanner(ScannerBase):
    SCANNER_NAME = "subdomain_takeover"
    SCANNER_MATURITY = 1
    TARGET_LEVEL = True
    SCANNER_ORDER = 20

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        for subdomain in self.recon.get("subdomains", []):
            try:
                for scheme in ("http://", "https://"):
                    target_url = f"{scheme}{subdomain}"
                    if not self._in_scope(target_url):
                        continue
                    resp = safe_get(self.session, target_url, self.timeout, raise_for_status=False)
                    if not resp or not resp.text:
                        continue
                    body = resp.text
                    for signature in TAKEOVER_SIGNATURES:
                        if signature.lower() in body.lower():
                            f = finding(
                                vuln_type="Subdomain Takeover",
                                url=target_url,
                                severity="high",
                                details=f"A known takeover fingerprint ({signature!r}) was detected on the subdomain",
                                evidence=f"Signature: {signature}",
                                request=_build_curl("GET", target_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                                response_excerpt=resp.text[:500],
                                steps_to_reproduce=[
                                    f"Send GET request to {target_url}",
                                    f"Observe takeover signature: {signature}",
                                ],
                                verification_stage=VerificationStage.DETECTED.value,
                            )
                            if f:
                                self._add_finding(f)
                            log(f"  [TAKEOVER] {target_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                            break
                    else:
                        continue
                    break
            except Exception:
                continue
        return self._get_findings()

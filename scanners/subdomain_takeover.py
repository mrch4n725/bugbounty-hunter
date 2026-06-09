"""
SubdomainTakeoverScanner — detects vulnerable subdomains pointing to defunct services.

Uses DNS resolution and HTTP response fingerprinting for validation.

Lifecycle:
  DETECTED:   Known takeover signature found in subdomain response
  VALIDATED:  DNS resolves + service-specific fingerprint confirmed
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate + typed evidence + reproduction)
"""

import socket

from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence
from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

# Service-specific takeover fingerprints
TAKEOVER_SIGNATURES: dict[str, list[str]] = {
    "AWS S3": [
        "NoSuchBucket", "The specified bucket does not exist",
        "AllAccessDisabled",
    ],
    "GitHub Pages": [
        "There isn't a GitHub Pages site here.",
    ],
    "Fastly": [
        "Fastly error: unknown domain",
    ],
    "Heroku": [
        "No such app", "There's nothing here, yet.",
    ],
    "Azure": [
        "There is no site configured at this address",
        "The web you are trying to access is not available",
        "the hostname you are trying to reach is not configured",
        "did not find a resource associated with this hostname",
    ],
    "Cloudfront": [
        "NoSuchCloudFrontDistribution",
        "The request could not be satisfied",
        "BadRequest: 400",
    ],
    "Shopify": [
        "Sorry, this shop is currently unavailable.",
    ],
    "Cargo Collective": [
        "404 Not Found",
        "The site you were looking for doesn't exist.",
    ],
    "Tumblr": [
        "There's nothing here.",
        "Whatever you were looking for doesn't currently exist at this address.",
    ],
    "WordPress": [
        "Domain mapping upgrade for this domain not found",
        "The site you were trying to access does not exist on this server.",
    ],
    "UserVoice": [
        "This UserVoice subdomain is currently available!",
    ],
    "Surge.sh": [
        "project not found",
    ],
    "Bitbucket": [
        "Repository not found",
    ],
    "Campaign Monitor": [
        "Trying to access your account?",
    ],
    "Unbounce": [
        "The page you requested was not found",
    ],
    "Fly.io": [
        "Page not found",
        "404 Not Found - Fly",
    ],
    "Render": [
        "Render",
        "Redirecting to 404",
    ],
    "Railway": [
        "There is nothing here, yet.",
        "404 - Nothing here",
    ],
    "Vercel": [
        "The page could not be found",
        "404: NOT_FOUND",
        "Vercel",
    ],
    "Pantheon": [
        "The gods are angry",
        "pantheon",
        "This site is not configured",
    ],
}

FLAT_SIGNATURES: list[str] = []
for sigs in TAKEOVER_SIGNATURES.values():
    FLAT_SIGNATURES.extend(sigs)

SERVICE_CNAME_PATTERNS: dict[str, list[str]] = {
    "AWS S3": [".s3.amazonaws.com", ".s3-website", "s3-"],
    "GitHub Pages": [".github.io"],
    "Fastly": [".fastly.net"],
    "Heroku": [".herokuapp.com", ".herokudns.com"],
    "Azure": [".azurewebsites.net", ".trafficmanager.net", ".cloudapp.net"],
    "Cloudfront": [".cloudfront.net"],
    "Shopify": [".myshopify.com"],
    "Cargo Collective": [".cargocollective.com"],
    "Tumblr": [".tumblr.com"],
    "WordPress": [".wordpress.com"],
    "UserVoice": [".uservoice.com"],
    "Surge.sh": [".surge.sh"],
    "Bitbucket": [".bitbucket.io"],
    "Campaign Monitor": [".createsend.com"],
    "Unbounce": [".unbouncepages.com"],
    "Fly.io": [".fly.dev", ".fly.io"],
    "Render": [".onrender.com"],
    "Railway": [".railway.app"],
    "Vercel": [".vercel.app", "cname.vercel-dns.com"],
    "Pantheon": [".pantheonsite.io", ".pantheon.io"],
}


class SubdomainTakeoverScanner(ScannerBase):
    SCANNER_NAME = "subdomain_takeover"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = True
    SCANNER_ORDER = 20

    def _resolve_dns(self, hostname: str) -> dict:
        """Resolve DNS and return {'ips': [...], 'cname': str or None, 'resolves': bool}."""
        result = {"ips": [], "cname": None, "resolves": False}
        try:
            _, aliases, ips = socket.gethostbyname_ex(hostname)
            result["ips"] = ips
            result["resolves"] = bool(ips)
            # First alias often is the CNAME target
            if aliases:
                result["cname"] = aliases[0]
            try:
                canon = socket.getaddrinfo(hostname, 0, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_CANONNAME)
                if canon and canon[0][3]:
                    cname = canon[0][3]
                    if cname != hostname:
                        result["cname"] = cname
            except Exception:
                pass
        except socket.gaierror:
            result["resolves"] = False
        except Exception:
            result["resolves"] = False
        return result

    def _match_cname_service(self, cname: str | None) -> str | None:
        """Match a CNAME target to a known cloud service."""
        if not cname:
            return None
        cname_lower = cname.lower()
        for service, patterns in SERVICE_CNAME_PATTERNS.items():
            for pat in patterns:
                if pat in cname_lower:
                    return service
        return None

    def _match_body_service(self, body: str) -> tuple[str | None, str | None]:
        """Match response body against known takeover fingerprints.
        Returns (service_name, matched_signature) or (None, None)."""
        for service, sigs in TAKEOVER_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in body.lower():
                    return service, sig
        for sig in FLAT_SIGNATURES:
            if sig.lower() in body.lower():
                return "Unknown", sig
        return None, None

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
        if not resp or not resp.text:
            return None
        body = resp.text
        service, sig = self._match_body_service(body)
        if service is None:
            return None
        return DetectionResult(
            url=url,
            parameter="",
            payload=sig,
            context=service,
            raw_response=resp,
            evidence_signals=[f"Takeover fingerprint ({service}): {sig}"],
        )

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        resp = detection.raw_response
        body = resp.text if resp else ""
        hostname = detection.url.split("://")[-1].split("/")[0]

        dns_info = self._resolve_dns(hostname)
        service_from_cname = self._match_cname_service(dns_info.get("cname"))
        service_from_body, _ = self._match_body_service(body)

        signals: list[str] = []
        confirmations = 0

        if dns_info["resolves"]:
            signals.append(f"dns_resolves:{','.join(dns_info['ips'][:3])}")
        else:
            signals.append("dns_no_resolution")

        if dns_info["cname"]:
            signals.append(f"cname:{dns_info['cname']}")
            if service_from_cname:
                signals.append(f"service_from_cname:{service_from_cname}")
                confirmations += 1

        if service_from_body:
            signals.append(f"service_from_body:{service_from_body}")
            confirmations += 1

        if service_from_cname and service_from_body:
            if service_from_cname == service_from_body:
                confirmations += 2  # Strong match

        detail_parts = []
        if service_from_cname:
            detail_parts.append(f"CNAME points to {service_from_cname}")
        if service_from_body:
            detail_parts.append(f"body matches {service_from_body}")

        # Confirmed if:
        # - CNAME matches a known service AND body matches a takeover signature, OR
        # - Body matches a known service signature AND DNS resolves (CNAME or not)
        confirmed = False
        if service_from_cname and service_from_body:
            confirmed = True
        elif service_from_body and dns_info.get("cname"):
            confirmed = True
        elif service_from_body and not dns_info["resolves"]:
            confirmed = True
        elif confirmations >= 2:
            confirmed = True

        if confirmed:
            return ValidationResult(
                confirmed=True,
                signals=signals,
                method="dns_http_multi_signal",
                detail="; ".join(detail_parts) if detail_parts else "Takeover confirmed via DNS + HTTP fingerprinting",
            )
        return ValidationResult(
            confirmed=False,
            signals=signals,
            method="dns_http_check",
            detail="; ".join(detail_parts) if detail_parts else "Takeover detected but not validated — DNS or secondary signals missing",
        )

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

    def generate_reproduction(self, f: dict) -> list[str]:
        host = f['url'].split("/")[2]
        return [
            f"curl -X GET '{f['url']}' -H 'Host: {host}'",
            f"Response contains takeover fingerprint: '{f.get('evidence', '')}' — the DNS CNAME points to an unclaimed external service",
            "An attacker who registers the unclaimed external resource can serve arbitrary content under the victim's subdomain, enabling phishing, session hijacking, and complete loss of subdomain integrity",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
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

                    stage = VerificationStage.VALIDATED.value if (validation_result and validation_result.confirmed) else VerificationStage.DETECTED.value

                    f = finding(
                        vuln_type="Subdomain Takeover",
                        url=target_url,
                        severity="high",
                        details=f"A known takeover fingerprint ({detection.payload!r}) was detected on the subdomain (service: {detection.context})",
                        evidence=f"Signature: {detection.payload}",
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=detection.raw_response.text[:500] if detection.raw_response else "",
                        verification_stage=stage,
                    )
                    if f:
                        f["steps_to_reproduce"] = self.generate_reproduction(f)
                        self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                        fingerprint = f.get("fingerprint", "")
                        if fingerprint:
                            for ev in evidence_list:
                                self.evidence_engine.link_to_finding(ev, fingerprint)
                        self._add_finding(f)
                        log(f"  [TAKEOVER] {target_url} [{stage}]", Colors.RED, verbose_only=True, verbose=self.verbose)
                    break
            except Exception:
                continue
        return self._get_findings()

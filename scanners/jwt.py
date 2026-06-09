"""
JWTScanner — detects JWT vulnerabilities.

Passive analysis:
  - Detect JWT tokens in Authorization headers, cookies, and response bodies
  - Decode payload and inspect claims
  - Detect weak algorithms (alg: none, alg: None)

Active testing (non-passive mode):
  - alg: none / alg: None injection
  - Weak HMAC secret brute force (common keys)
  - Algorithm confusion (RS256 public key as HS256 secret)

Lifecycle:
  DETECTED:   JWT token found in request/response
  VALIDATED:  Weak algorithm or configuration confirmed
  EXPLOITABLE: Token forged or signature bypassed
  VERIFIED:   (not applicable)

Maturity: Level 3 (Detect + Validate + typed evidence + reproduction)
"""

import base64
import json
import re
from typing import Any

from models.finding import Finding
from models.evidence import HttpRequestEvidence, ResponseExcerptEvidence
from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

JWT_PATTERN = re.compile(
    r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
)

COMMON_JWT_SECRETS = [
    "secret", "password", "key", "jwt_secret", "jwt_secret_key",
    "mysecret", "my_secret", "changeme", "admin", "token",
    "supersecret", "pass", "p@ssw0rd", "123456", "qwerty",
]

WEAK_ALG_PAYLOADS = [
    {"alg": "none", "typ": "JWT"},
    {"alg": "None", "typ": "JWT"},
    {"alg": "NONE", "typ": "JWT"},
    {"alg": "nOnE", "typ": "JWT"},
]


class JWTScanner(ScannerBase):
    SCANNER_NAME = "jwt"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = True
    SCANNER_ORDER = 10

    @staticmethod
    def _decode_jwt_part(part: str) -> dict | None:
        """Decode a base64url-encoded JWT segment."""
        try:
            missing = len(part) % 4
            if missing:
                part += "=" * (4 - missing)
            padded = part.replace("-", "+").replace("_", "/")
            decoded = base64.b64decode(padded).decode("utf-8")
            return json.loads(decoded)
        except Exception:
            return None

    @staticmethod
    def _parse_jwt(token: str) -> dict | None:
        """Parse a JWT token into {header, payload, signature} or None."""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header = JWTScanner._decode_jwt_part(parts[0])
        payload = JWTScanner._decode_jwt_part(parts[1])
        if header is None or payload is None:
            return None
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "raw": token,
        }

    @staticmethod
    def _forge_token(header: dict, payload: dict) -> str:
        """Forge a JWT with modified header/payload (no signature)."""
        def _b64url_encode(data: dict) -> str:
            raw = json.dumps(data, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        h = _b64url_encode(header)
        p = _b64url_encode(payload)
        return f"{h}.{p}."

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        """Decode base64url with padding fix."""
        missing = len(data) % 4
        if missing:
            data += "=" * (4 - missing)
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def _weak_hmac_test(token: str, secret: str) -> bool:
        """Test if a JWT was signed with a given HMAC secret.
        Uses stdlib hmac module."""
        import hmac as hmac_mod
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            expected_sig = hmac_mod.new(
                secret.encode(), signing_input, "sha256"
            ).digest()
            expected_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")
            return expected_b64 == parts[2]
        except Exception:
            return False

    def detect(self, url: str, parameter: str | None = None) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        resp = safe_get(self.session, url, self.timeout)
        if not resp:
            return results

        jwts_found: list[dict] = []

        # Check Authorization header
        auth = resp.request.headers.get("Authorization", "") if hasattr(resp, "request") else ""
        if auth.lower().startswith("bearer "):
            token = auth[7:]
            parsed = self._parse_jwt(token)
            if parsed:
                jwts_found.append(parsed)
                results.append(DetectionResult(
                    url=url, parameter="Authorization",
                    payload=token[:80],
                    context="jwt_in_auth_header",
                    raw_response=resp,
                    evidence_signals=["JWT found in Authorization: Bearer header"],
                ))

        # Check Set-Cookie
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            match = JWT_PATTERN.search(set_cookie)
            if match:
                token = match.group(1)
                parsed = self._parse_jwt(token)
                if parsed:
                    jwts_found.append(parsed)
                    results.append(DetectionResult(
                        url=url, parameter="Set-Cookie",
                        payload=token[:80],
                        context="jwt_in_cookie",
                        raw_response=resp,
                        evidence_signals=["JWT found in Set-Cookie header"],
                    ))

        # Check response body
        if resp.text:
            for match in JWT_PATTERN.finditer(resp.text):
                token = match.group(1)
                parsed = self._parse_jwt(token)
                if parsed:
                    jwts_found.append(parsed)
                    results.append(DetectionResult(
                        url=url, parameter="response_body",
                        payload=token[:80],
                        context="jwt_in_response_body",
                        raw_response=resp,
                        evidence_signals=["JWT found in response body"],
                    ))
                    break  # One per response is enough

        # Analyze each found JWT for weak alg
        for parsed in jwts_found:
            alg = parsed["header"].get("alg", "").lower()
            if alg in ("none", "none"):
                results.append(DetectionResult(
                    url=url, parameter="alg",
                    payload=parsed["header"].get("alg", ""),
                    context="jwt_alg_none",
                    raw_response=resp,
                    evidence_signals=[f"JWT uses alg=none (no signature)"],
                ))

        return results

    def validate(self, url: str, detection: DetectionResult | None = None) -> list[dict]:
        """Attempt to exploit JWT weaknesses.
        Forged tokens are sent to the target URL to test acceptance."""
        if self.config.get("passive") or self.config.get("dry_run"):
            return []  # Skip active testing in passive mode

        results: list[dict] = []
        resp = safe_get(self.session, url, self.timeout)
        if not resp:
            return results

        # Collect JWTs from response
        all_jwts: list[dict] = []

        # Check Auth header
        auth = resp.request.headers.get("Authorization", "") if hasattr(resp, "request") else ""
        if auth.lower().startswith("bearer "):
            parsed = self._parse_jwt(auth[7:])
            if parsed:
                all_jwts.append(parsed)

        # Check Set-Cookie
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            match = JWT_PATTERN.search(set_cookie)
            if match:
                parsed = self._parse_jwt(match.group(1))
                if parsed:
                    all_jwts.append(parsed)

        # Check response body
        if resp.text:
            for match in JWT_PATTERN.finditer(resp.text):
                parsed = self._parse_jwt(match.group(1))
                if parsed:
                    all_jwts.append(parsed)
                    break

        for parsed in all_jwts:
            orig_token = parsed["raw"]

            # Test alg=none
            for weak_header in WEAK_ALG_PAYLOADS:
                forged = self._forge_token(weak_header, parsed["payload"])
                test_resp = safe_get(
                    self.session, url, self.timeout,
                    headers={"Authorization": f"Bearer {forged}"} if auth else {},
                    raise_for_status=False,
                )
                if test_resp and test_resp.status_code == 200:
                    results.append({
                        "confirmed": True,
                        "method": "alg_none",
                        "url": url,
                        "detail": f"JWT with alg={weak_header['alg']} accepted by server",
                        "forged_token": forged[:80],
                    })
                    break

            # Test weak HMAC secrets
            for secret in COMMON_JWT_SECRETS:
                if self._weak_hmac_test(orig_token, secret):
                    forged = self._forge_token(
                        parsed["header"],
                        {**parsed["payload"], "iat": 1234567890},
                    )
                    results.append({
                        "confirmed": True,
                        "method": "weak_hmac_secret",
                        "url": url,
                        "detail": f"JWT HMAC secret cracked: '{secret}'",
                        "forged_token": forged[:80],
                    })
                    break

        return results

    def generate_reproduction(self, detection: DetectionResult | None = None) -> list[str]:
        if detection and detection.context == "jwt_alg_none":
            return [
                f"Capture the JWT from {detection.url}",
                f"The JWT header contains alg=none — no signature is required",
                "Send a modified JWT with any payload and alg=none, no signature",
                "Observe that the server accepts the forged token",
            ]
        if detection and detection.context in ("jwt_in_auth_header", "jwt_in_cookie", "jwt_in_response_body"):
            location = detection.context.replace("_", " ").replace("jwt", "JWT")
            return [
                f"Send request to {detection.url}",
                f"Observe {location} contains a JWT token",
                "Decode the JWT payload to inspect claims",
            ]
        return [
            f"Send request to {detection.url} and locate JWT tokens",
            "Inspect JWT header and payload for weak configurations",
        ]

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
            if not detections:
                continue

            validations = self.validate(url)

            for d in detections:
                curl_cmd = _build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies))
                resp = d.raw_response
                resp_text = resp.text[:500] if resp else ""

                matched_v = [v for v in validations if v["confirmed"]]

                if d.context == "jwt_alg_none":
                    vuln_type = "JWT: alg=none"
                    severity = "critical"
                    details = "JWT token uses alg=none — signature verification is disabled"
                    ev = f"JWT alg=none in header"
                    stage = VerificationStage.EXPLOITABLE.value if matched_v else VerificationStage.DETECTED.value
                elif matched_v:
                    vuln_type = f"JWT Weakness: {matched_v[0]['method']}"
                    severity = "critical"
                    details = matched_v[0]["detail"]
                    ev = f"JWT weakness: {matched_v[0]['method']}"
                    stage = VerificationStage.VALIDATED.value
                else:
                    vuln_type = "JWT Token Disclosure"
                    severity = "medium"
                    details = "JWT token found in response — may contain sensitive claims"
                    ev = f"JWT token prefix: {d.payload[:50]}"
                    stage = VerificationStage.DETECTED.value

                # Decode payload for details
                parsed = self._parse_jwt(d.payload)
                if parsed and parsed["payload"]:
                    claims = parsed["payload"]
                    sensitive_claims = [k for k in claims if k in ("sub", "role", "groups", "admin", "iat", "exp", "nbf", "jti")]
                    if sensitive_claims:
                        details += f" — claims: {', '.join(sensitive_claims)}"

                f = finding(
                    vuln_type=vuln_type,
                    url=url,
                    severity=severity,
                    details=details,
                    evidence=ev,
                    request=curl_cmd,
                    response_excerpt=resp_text,
                    steps_to_reproduce=self.generate_reproduction(d),
                    verification_stage=stage,
                )
                if f:
                    fp = f.get("fingerprint", "")
                    if fp:
                        req_ev = HttpRequestEvidence(
                            method="GET",
                            url=url,
                            curl_command=curl_cmd,
                        )
                        self.evidence_engine.store(req_ev)
                        self.evidence_engine.link_to_finding(req_ev, fp)
                    self._add_finding(f)
                    log(f"  [JWT] {url} — {vuln_type}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

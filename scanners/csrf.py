"""
CSRFScanner — detects POST forms missing anti-CSRF tokens.

Lifecycle:
  DETECTED:   POST form lacks known CSRF token field
  VALIDATED:  Token replay test confirms server accepts requests without token
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 2 (Detect + Validate)
"""

import re
from urllib.parse import urlparse
from urllib.parse import urljoin

from models.finding import Finding
from models.evidence import ResponseExcerptEvidence, HttpRequestEvidence
from modules.utils import (
    finding, VerificationStage, log, Colors, _build_curl, safe_post, safe_get,
    safe_cookies_dict, make_session,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

CSRF_TOKEN_NAMES = {
    "csrf_token", "csrfmiddlewaretoken", "authenticity_token",
    "token", "csrf", "xsrf-token", "xsrf_token",
    "anti_csrf_token", "_csrf", "_token",
}


CSRF_TOKEN_RE = re.compile(
    r'<input[^>]*?name=["\'](' + '|'.join(CSRF_TOKEN_NAMES) + r')["\'][^>]*?>',
    re.IGNORECASE,
)
CSRF_VALUE_RE = re.compile(r'value=["\']([^"\']+)["\']', re.IGNORECASE)


class CSRFScanner(ScannerBase):
    SCANNER_NAME = "csrf"
    SCANNER_MATURITY = 2
    TARGET_LEVEL = False

    def detect(self, form: dict) -> DetectionResult | None:
        form_action = form.get("action", form.get("url", ""))
        if not form_action:
            return None
        if form.get("method", "GET").upper() != "POST":
            return None
        token_found = any(
            fld.get("name", "").lower() in CSRF_TOKEN_NAMES
            for fld in form.get("fields", [])
        )
        if token_found:
            return None
        # Also flag if SameSite cookie attribute is missing/none
        cookies = form.get("cookies", form.get("set_cookie", ""))
        samesite_weak = False
        if isinstance(cookies, str):
            samesite_weak = "samesite" not in cookies.lower() or "samesite=none" in cookies.lower()
        elif isinstance(cookies, dict):
            sc = cookies.get("SameSite", "")
            samesite_weak = not sc or sc.lower() == "none"
        context = "missing_csrf_token"
        signals = [f"Missing CSRF token in POST form at {form_action}"]
        if samesite_weak:
            context = "missing_csrf_token_no_samesite"
            signals.append("SameSite cookie attribute missing or set to None")
        return DetectionResult(
            url=form_action,
            parameter="",
            payload="",
            context=context,
            raw_response=None,
            evidence_signals=signals,
        )

    @staticmethod
    def _extract_csrf_token(html: str) -> str | None:
        """Extract the first CSRF token value from an HTML form."""
        match = CSRF_TOKEN_RE.search(html)
        if not match:
            return None
        value_match = CSRF_VALUE_RE.search(match.group(0))
        return value_match.group(1) if value_match else None

    def validate(self, detection: DetectionResult,
                 form: dict | None = None) -> ValidationResult | None:
        form_action = detection.url
        if not form_action or self.config.get("passive"):
            return ValidationResult(confirmed=False, method="form_analysis",
                                    detail="CSRF detection based on form structure analysis")

        try:
            # ── Step 1: fetch the form page and try to extract a CSRF token ──
            csrf_token = None
            page_resp = safe_get(self.session, form_action, self.timeout)
            if page_resp and page_resp.text:
                csrf_token = self._extract_csrf_token(page_resp.text)

            # ── Step 2: build form data with/without token ───────────────────
            base_data: dict[str, str] = {}
            if form:
                for fld in form.get("fields", []):
                    name = (fld.get("name", "") or "").strip()
                    val = (fld.get("value", "") or "").strip()
                    if name:
                        base_data[name] = val

            # Baseline: submit WITH a valid token if we extracted one
            if csrf_token:
                token_name = next(
                    (n for n in CSRF_TOKEN_NAMES
                     if CSRF_TOKEN_RE.search(f'name="{n}"')),
                    "csrf_token",
                )
                baseline_data = {**base_data, token_name: csrf_token}
                baseline = safe_post(self.session, form_action, baseline_data,
                                     self.timeout, raise_for_status=False)
                if baseline and baseline.status_code in (200, 201, 202, 204, 301, 302):
                    pass  # Baseline succeeded — proceed with replay test
                else:
                    # Could not get a baseline success — likely needs a real session
                    return ValidationResult(
                        confirmed=False, method="token_replay",
                        detail="Could not establish baseline with extracted CSRF token",
                    )

            # Replay: submit WITHOUT any token
            replay_data = {k: v for k, v in base_data.items()
                           if k.lower() not in CSRF_TOKEN_NAMES}
            resp = safe_post(self.session, form_action, replay_data or {"test": "test"},
                             self.timeout, raise_for_status=False)

            if resp and resp.status_code in (200, 201, 202, 204, 301, 302):
                return ValidationResult(
                    confirmed=True,
                    signals=[f"POST to {form_action} returned HTTP {resp.status_code} without token"],
                    method="token_replay",
                    detail=f"Server accepted POST request without anti-CSRF token (HTTP {resp.status_code})",
                )
            if resp and resp.status_code in (400, 403, 422):
                return ValidationResult(
                    confirmed=False,
                    signals=[f"POST rejected with HTTP {resp.status_code}"],
                    method="token_replay",
                    detail=f"Server rejected POST without token (HTTP {resp.status_code}) — CSRF protection likely present",
                )
            return ValidationResult(
                confirmed=False,
                method="token_replay",
                detail=f"Server returned HTTP {resp.status_code if resp else 'N/A'} — inconclusive",
            )
        except Exception as e:
            return ValidationResult(
                confirmed=False,
                method="token_replay_error",
                detail=f"Token replay test failed: {e}",
            )

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        from models.evidence import ResponseExcerptEvidence
        return [ResponseExcerptEvidence(
            excerpt=f"Form action: {detection.url} | Method: POST | No CSRF token found",
            length=0,
            context="csrf_form_analysis",
            description=f"CSRF analysis of form at {detection.url}",
        )]

    def generate_reproduction(self, f: dict) -> list[str]:
        return [
            f"curl -X POST '{f['url']}' -d 'action=transfer&amount=1000&recipient=attacker'",
            "Observe that the server accepts the request with HTTP 200 — no anti-CSRF token validation enforced; compare with legitimate request that includes a token — both succeed",
            "An attacker can forge cross-origin requests to perform state-changing actions (password change, fund transfer, privilege escalation) on behalf of authenticated victims",
        ]

    def _check_json_content_type_confusion(self, urls: list[str]) -> list[Finding]:
        """Check if JSON endpoints accept text/plain content-type (CSRF bypass)."""
        json_findings: list[Finding] = []
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                resp = safe_get(self.session, url, self.timeout)
                if not resp or "application/json" not in resp.headers.get("Content-Type", ""):
                    continue
                test_data = '{"test":"csrf_probe"}'
                plain_resp = safe_post(
                    self.session, url, data=test_data,
                    headers={"Content-Type": "text/plain"},
                    timeout=self.timeout, raise_for_status=False,
                )
                if plain_resp and plain_resp.status_code in (200, 201, 202, 204):
                    json_resp = safe_post(
                        self.session, url, data=test_data,
                        headers={"Content-Type": "application/json"},
                        timeout=self.timeout, raise_for_status=False,
                    )
                    if json_resp and json_resp.status_code in (200, 201, 202, 204):
                        f = finding(
                            vuln_type="CSRF JSON Content-Type Confusion",
                            url=url,
                            severity="medium",
                            details="JSON endpoint accepts text/plain content-type — browser can send cross-origin POST without preflight",
                            evidence=f"text/plain POST returned HTTP {plain_resp.status_code}, same as application/json ({json_resp.status_code})",
                            request=_build_curl("POST", url, {"Content-Type": "text/plain"}, data=test_data),
                            response_excerpt=plain_resp.text[:200],
                            verification_stage=VerificationStage.VALIDATED.value,
                            steps_to_reproduce=[
                                f"Send POST to {url} with Content-Type: text/plain and body: {test_data}",
                                "Observe that the server returns HTTP 200 — same as with application/json",
                                "An attacker can craft a self-submitting form with enctype=text/plain to bypass CSRF protection",
                            ],
                        )
                        if f:
                            self._add_finding(f)
                            json_findings.append(f)
                            log(f"  [CSRF JSON] {url} — text/plain accepted", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return json_findings

    def _test_origin_referer_bypass(self, form: dict, base_data: dict) -> ValidationResult | None:
        """Validate CSRF by testing Origin/Referer header bypass."""
        form_action = form.get("action", form.get("url", ""))
        if not form_action:
            return None
        try:
            for origin in ("null", "https://evil.com", "https://attacker.com"):
                bypass_session = make_session(self.config)
                bypass_session.headers.update({"Origin": origin})
                resp = safe_post(bypass_session, form_action, base_data or {"test": "test"},
                                self.timeout, raise_for_status=False)
                if resp and resp.status_code in (200, 201, 202, 204, 301, 302):
                    return ValidationResult(
                        confirmed=True,
                        signals=[f"Origin bypass: Origin={origin} returned HTTP {resp.status_code}"],
                        method="origin_bypass",
                        detail=f"Server accepted POST with malicious Origin header ({origin}) — no CSRF protection via Origin check",
                    )
            for referer in ("https://evil.com/", "https://attacker.com/page"):
                bypass_session = make_session(self.config)
                bypass_session.headers.update({"Referer": referer})
                resp = safe_post(bypass_session, form_action, base_data or {"test": "test"},
                                self.timeout, raise_for_status=False)
                if resp and resp.status_code in (200, 201, 202, 204, 301, 302):
                    return ValidationResult(
                        confirmed=True,
                        signals=[f"Referer bypass: Referer={referer} returned HTTP {resp.status_code}"],
                        method="referer_bypass",
                        detail=f"Server accepted POST with spoofed Referer header ({referer}) — no CSRF protection via Referer check",
                    )
        except Exception:
            return None
        return None

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        forms = self.recon.get("forms", [])
        if target_urls is not None:
            origins = {urlparse(u).scheme + "://" + urlparse(u).netloc for u in target_urls}
            forms = [
                f for f in forms
                if any(
                    urlparse(f.get("action", f.get("url", ""))).scheme + "://"
                    + urlparse(f.get("action", f.get("url", ""))).netloc == o
                    for o in origins
                )
            ]
        for form in forms:
            try:
                detection = self.detect(form)
                if detection is None:
                    continue
                if not self._in_scope(detection.url):
                    continue

                validation_result = self.validate(detection, form)
                evidence_list = self.collect_evidence(detection, validation_result)
                base_data = {
                    fld.get("name", "field"): fld.get("value", "test")
                    for fld in form.get("fields", [])[:5]
                }

                stage = VerificationStage.VALIDATED.value if (validation_result and validation_result.confirmed) else VerificationStage.DETECTED.value

                if stage == VerificationStage.DETECTED.value and not self.config.get("passive"):
                    bypass_result = self._test_origin_referer_bypass(form, base_data)
                    if bypass_result and bypass_result.confirmed:
                        validation_result = bypass_result
                        stage = VerificationStage.VALIDATED.value

                curl_cmd = _build_curl("POST", detection.url, {}, data=base_data)

                f = finding(
                    vuln_type="Missing CSRF Protection",
                    url=detection.url,
                    severity="medium",
                    details="POST form does not contain a known anti-CSRF token field",
                    evidence=f"Form fields: {[fld.get('name') for fld in form.get('fields', [])]}",
                    request=curl_cmd,
                    response_excerpt="(no request made — detected from form structure)" if stage == VerificationStage.DETECTED.value else validation_result.detail,
                    steps_to_reproduce=self.generate_reproduction(f),
                    verification_stage=stage,
                )
                if f:
                    self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                    for ev in evidence_list:
                        self.evidence_engine.store(ev)
                        self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                    if stage == VerificationStage.VALIDATED.value and f.get("fingerprint", ""):
                        req_ev = HttpRequestEvidence(
                            method="POST",
                            url=detection.url,
                            curl_command=curl_cmd,
                        )
                        self.evidence_engine.store(req_ev)
                        self.evidence_engine.link_to_finding(req_ev, f.get("fingerprint", ""))
                    self._add_finding(f)
                    log(f"  [CSRF] {detection.url} [{stage}]", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue

        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        self._check_json_content_type_confusion(urls)

        return self._get_findings()

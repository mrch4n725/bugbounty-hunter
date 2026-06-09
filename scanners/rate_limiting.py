"""
RateLimitingScanner — tests auth-related endpoints for missing rate limiting.

Lifecycle:
  DETECTED:   No 429 returned across 50 rapid POST requests
  VALIDATED:  (not applicable)
  EXPLOITABLE: (not applicable)
  VERIFIED:   (not applicable)

Maturity: Level 1 (Detection only)
"""

import random
import time
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from modules.utils import (
    finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
from models.evidence import TimingEvidence

HARDCODED_PATHS = [
    "/login", "/auth/login", "/api/login", "/api/auth/login",
    "/register", "/auth/register", "/api/register",
    "/reset-password", "/auth/reset-password", "/api/reset-password",
    "/forgot-password", "/auth/forgot-password",
    "/api/v1/login", "/api/v1/register",
    "/oauth/token", "/api/token",
]

PROBE_COUNT = 50


class RateLimitingScanner(ScannerBase):
    SCANNER_NAME = "rate_limiting"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = True

    def _build_candidates(self, target_urls: list[str] | None = None) -> list[dict]:
        candidates: list[dict] = []
        seen_urls: set = set()

        def _add(url: str, sev: str, form_fields: list = None):
            if url in seen_urls:
                return
            seen_urls.add(url)
            candidates.append({"url": url, "severity": sev, "form_fields": form_fields or []})

        base = self.base_url
        if target_urls:
            parsed = urlparse(target_urls[0])
            base = f"{parsed.scheme}://{parsed.netloc}"

        for path in HARDCODED_PATHS:
            full = urljoin(base, path)
            sev = "high" if any(k in path for k in ("login", "auth", "signin", "reset", "password", "token")) else "medium"
            _add(full, sev)

        forms = self.recon.get("forms", [])
        if target_urls is not None:
            target_origins = {urlparse(u).scheme + "://" + urlparse(u).netloc for u in target_urls}
            forms = [
                f for f in forms
                if any(urlparse(f.get("action", "")).scheme + "://" + urlparse(f.get("action", "")).netloc == o for o in target_origins)
            ]
        for form in forms:
            method = form.get("method", "GET").upper()
            if method != "POST":
                continue
            fields = form.get("fields", [])
            field_names = [f.get("name", "").lower() for f in fields if f.get("name")]
            pw_fields = [n for n in field_names if n in ("password", "passwd", "pass", "secret", "pin", "otp", "code", "token")]
            if not pw_fields:
                continue
            action = form.get("action", "")
            if not action:
                continue
            _add(action, "high", fields)

        return candidates

    def _build_probe_data(self, form_fields: list) -> dict:
        if form_fields:
            probe_data = {}
            for f in form_fields:
                name = f.get("name", "")
                ftype = f.get("type", "").lower()
                if name.lower() in ("password", "passwd", "pass", "secret", "pin", "otp"):
                    probe_data[name] = "Wr0ng_P4ss_probe!"
                elif name.lower() in ("email", "username", "login"):
                    probe_data[name] = "probe@ratelimit.test"
                elif name.lower() in ("code", "token"):
                    probe_data[name] = "000000"
                else:
                    probe_data[name] = f.get("value", "test")
            return probe_data
        return {
            "username": "ratelimit_probe_user",
            "password": "Wr0ng_P4ss_probe!",
            "email": "probe@ratelimit.test",
        }

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        return None

    def detect_candidate(self, test_url: str, probe_data: dict) -> DetectionResult | None:
        try:
            base_resp = self.session.post(test_url, timeout=self.timeout, data={"baseline": "1"})
            if base_resp.status_code in (404, 410):
                return None
        except Exception:
            return None

        _probe_cookies = safe_cookies_dict(self.session.cookies)
        _probe_headers = dict(self.session.headers)

        def _probe(_idx: int, _url=test_url, _data=probe_data, _timeout=self.timeout,
                   _cookies=_probe_cookies, _headers=_probe_headers) -> tuple[int, str]:
            try:
                import requests as _requests
                delay = random.uniform(0.5, 1.5) if self.config.get("stealth") else max(0.05, self.config.get("delay", 0.0))
                if delay:
                    time.sleep(delay)
                r = _requests.post(_url, data=_data, timeout=_timeout,
                                   cookies=_cookies, headers=_headers, verify=False)
                return (r.status_code, r.text[:500])
            except Exception:
                return (0, "")

        results: list[tuple[int, str]] = []
        start = time.time()

        with ThreadPoolExecutor(max_workers=5) as pool:
            for status_code, body_snippet in pool.map(_probe, range(PROBE_COUNT)):
                results.append((status_code, body_snippet))

        elapsed = time.time() - start
        statuses = [s for s, _ in results]
        unique_statuses = set(statuses)
        has_429 = 429 in unique_statuses
        has_5xx = any(s >= 500 for s in unique_statuses)
        first_body = results[0][1] if results else ""
        body_changed = any(b != first_body for b in [b for _, b in results[1:]])

        throttled = has_429 or (body_changed and not has_5xx)
        if throttled:
            return None

        return DetectionResult(
            url=test_url,
            parameter="",
            payload=f"{PROBE_COUNT}_probes",
            context="missing_rate_limiting",
            evidence_signals=[
                f"Sent {PROBE_COUNT} POST requests in {elapsed:.1f}s. Statuses: {sorted(unique_statuses)}. No 429 received. Body changed: {body_changed}.",
                f"elapsed_ms={elapsed * 1000:.0f}",
            ],
        )

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        elapsed_ms = 0.0
        statuses_seen = set()
        main_sig = ""
        for sig in detection.evidence_signals:
            if sig.startswith("elapsed_ms="):
                try:
                    elapsed_ms = float(sig.split("=")[1])
                except (ValueError, IndexError):
                    pass
            elif not main_sig:
                main_sig = sig
        if main_sig:
            import re
            m = re.search(r"Statuses: \{([^}]+)\}", main_sig)
            if m:
                try:
                    statuses_seen = {int(s.strip()) for s in m.group(1).split(",") if s.strip().isdigit()}
                except ValueError:
                    pass
        all_200 = statuses_seen == {200}
        fast_burst = elapsed_ms < 30_000
        no_throttling = 429 not in statuses_seen and not any(s >= 500 for s in statuses_seen)
        if all_200 and fast_burst:
            return ValidationResult(
                confirmed=True,
                signals=[f"all_200", f"burst_{elapsed_ms:.0f}ms"],
                method="burst_analysis",
                detail=f"Rate limiting absent: {PROBE_COUNT} POSTs in {elapsed_ms / 1000:.1f}s, all returned 200",
            )
        if no_throttling and fast_burst:
            return ValidationResult(
                confirmed=False,
                signals=[f"burst_{elapsed_ms:.0f}ms"],
                method="burst_analysis",
                detail=f"No rate limit triggered: statuses {sorted(statuses_seen)}, {elapsed_ms / 1000:.1f}s",
            )
        return ValidationResult(confirmed=False, method="burst_analysis",
                                detail=f"No rate limiting detected across {PROBE_COUNT} rapid requests")

    def collect_evidence(self, detection: DetectionResult,
                         validation_result: ValidationResult | None = None) -> list:
        elapsed_ms = 0.0
        for sig in detection.evidence_signals:
            if sig.startswith("elapsed_ms="):
                try:
                    elapsed_ms = float(sig.split("=")[1])
                except (ValueError, IndexError):
                    pass
        return [
            TimingEvidence(
                baseline_time_ms=0.0,
                triggered_time_ms=elapsed_ms,
                delay_threshold_ms=0.0,
                total_attempts=PROBE_COUNT,
                description=f"Rate limit burst: {PROBE_COUNT} POSTs in {elapsed_ms / 1000:.2f}s",
            ),
        ]

    def generate_reproduction(self, f: dict) -> list[str]:
        return [
            f"Send {PROBE_COUNT} rapid POST requests to {f['url']} in quick succession (with minimal delay between requests)",
            f"None of the {PROBE_COUNT} requests returned HTTP 429 (rate limited) or showed throttling behavior",
            "Without rate limiting, an attacker can perform brute-force password guessing, credential stuffing, or OTP enumeration at full speed",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        candidates = self._build_candidates(target_urls)
        for candidate in candidates:
            test_url = candidate["url"]
            if not self._in_scope(test_url):
                continue
            form_fields = candidate["form_fields"]
            severity = candidate["severity"]
            probe_data = self._build_probe_data(form_fields)

            try:
                detection = self.detect_candidate(test_url, probe_data)
                if detection is None:
                    continue

                validation_result = self.validate(detection)
                evidence_list = self.collect_evidence(detection, validation_result)

                for ev in evidence_list:
                    self.evidence_engine.store(ev)

                response_excerpt = ""
                for sig in detection.evidence_signals:
                    if not sig.startswith("elapsed_ms="):
                        response_excerpt = sig[:300]
                        break

                f = finding(
                    vuln_type="Missing Rate Limiting",
                    url=test_url,
                    severity=severity,
                    details=f"Endpoint accepted {PROBE_COUNT} POST requests without rate limiting",
                    evidence=detection.evidence_signals[0] if detection.evidence_signals else "",
                    request=_build_curl("POST", test_url, dict(self.session.headers), data=probe_data),
                    response_excerpt=response_excerpt,
                    verification_stage=VerificationStage.VALIDATED.value if (validation_result and validation_result.confirmed) else VerificationStage.DETECTED.value,
                )
                if f:
                    f["steps_to_reproduce"] = self.generate_reproduction(f)
                    self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                    fingerprint = f.get("fingerprint", "")
                    if fingerprint:
                        for ev in evidence_list:
                            self.evidence_engine.link_to_finding(ev, fingerprint)
                    self._add_finding(f)
                log(f"  [RATE LIMITING] {test_url} — no 429",
                    Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

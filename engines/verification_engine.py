"""VerificationEngine — post-scan verification pipeline.

Takes low-confidence findings (DETECTED, score < 60) and systematically
promotes them to the highest achievable stage using every available tool:
response diffing, timing analysis, OOB callbacks, browser execution.

Design principle: each finding must *earn* its confidence score.
We promote findings, not guess them.
"""

import hashlib
import threading
import time
from typing import Any

from modules.utils import (
    log, Colors, VerificationStage, EvidenceStrength, FalsePositiveRisk,
    safe_get, make_session,
)
from models.finding import calculate_confidence


class VerificationEngine:
    """Systematic finding verifier.

    Parameters
    ----------
    config : dict
        Scan configuration.
    container : ApplicationContainer or None
        Dependency injection container with OOB, browser, evidence.
    capabilities : dict-like or None
        Set of available capabilities (browser_validation, oob_validation, etc.).
    """

    def __init__(self, config: dict, container=None, capabilities=None):
        self.config = config
        self.container = container
        self.capabilities = capabilities or {}
        self._session = make_session(config)

        if container:
            self.oob = container.oob_framework
            self.browser = container.browser_validator
            self.oob_available = bool(self.oob and self.oob.oob_host)
        else:
            self.oob = None
            self.browser = None
            self.oob_available = bool(config.get("oob_host"))

        self.browser_available = bool(self.browser)

    def verify_all(self, findings: list[dict]) -> list[dict]:
        """Run verification on all findings below 60 confidence."""
        for f in findings:
            if f.get("confidence_score", 0) >= 60:
                continue
            if f.get("verification_stage", "") in ("verified", "exploitable"):
                continue
            try:
                self.verify(f)
            except Exception as e:
                log(f"  [Verify] Error: {e}", Colors.WHITE,
                    verbose_only=True, verbose=self.config.get("verbose", False))
        return findings

    def verify(self, finding: dict) -> dict:
        """Run appropriate verification checks for this finding type."""
        vuln_type = (finding.get("vuln_type") or finding.get("type", "")).lower()
        if "sqli" in vuln_type:
            self._verify_sqli(finding)
        elif "xss" in vuln_type:
            self._verify_xss(finding)
        elif "ssrf" in vuln_type:
            self._try_oob(finding, "ssrf")
        elif "xxe" in vuln_type:
            self._try_oob(finding, "xxe")
        elif "cmdi" in vuln_type or "command" in vuln_type:
            self._verify_cmdi(finding)
        elif "ssti" in vuln_type:
            self._verify_ssti(finding)
        elif "lfi" in vuln_type or "path traversal" in vuln_type:
            self._verify_lfi(finding)
        elif "open redirect" in vuln_type:
            self._verify_open_redirect(finding)
        return finding

    def _promote(self, f: dict, stage: str, evidence_parts: list[str] | None = None) -> None:
        stage = stage.lower()
        f["verification_stage"] = stage
        f["confidence_score"] = calculate_confidence(
            detection=True,
            validation=stage in ("validated", "exploitable", "verified"),
            exploitation=stage in ("exploitable", "verified"),
        )
        f["evidence_strength"] = EvidenceStrength.from_score(f["confidence_score"]).value
        f["false_positive_risk"] = FalsePositiveRisk.from_score(f["confidence_score"]).value
        if evidence_parts:
            existing = f.get("evidence", "")
            f["evidence"] = (existing + " | " + " | ".join(evidence_parts)
                             if existing else " | ".join(evidence_parts))
        log(f"  [Verify] {f.get('vuln_type', '')} @ {f.get('url', '')} promoted to {stage.upper()} (score={f['confidence_score']})",
            Colors.GREEN)

    def _verify_sqli(self, f: dict) -> None:
        if f.get("verification_stage") in ("verified", "exploitable"):
            return
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        if self.oob_available:
            self._try_oob(f, "sqli")
            if f.get("verification_stage") == "verified":
                return

        current_steps = f.get("validation_steps", [])
        has_time = any("time" in s.lower() or "delay" in s.lower() for s in current_steps)
        has_boolean = any("boolean" in s.lower() or "1=1" in s for s in current_steps)

        if not has_time:
            time_payloads = [
                "' OR SLEEP(5)--", "\" OR SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "1' OR SLEEP(5)--",
            ]
            for payload in time_payloads:
                test_url = self._inject_param(url, param, payload)
                delays = []
                for _ in range(2):
                    start = time.time()
                    safe_get(self._session, test_url, 15, raise_for_status=False)
                    delays.append(time.time() - start)
                if min(delays) > 4.0:
                    self._promote(f, "validated", [f"time:delay={min(delays):.2f}s"])
                    has_time = True
                    break

        if not has_boolean and not has_time:
            pairs = [
                ("AND 1=1", "AND 1=2"),
            ]
            baseline = safe_get(self._session, url, 10)
            if baseline:
                base_hash = hashlib.md5(baseline.text.encode()).hexdigest()
                for true_s, false_s in pairs:
                    true_url = self._inject_param(url, param, f"1 {true_s}")
                    false_url = self._inject_param(url, param, f"1 {false_s}")
                    t_resp = safe_get(self._session, true_url, 10)
                    f_resp = safe_get(self._session, false_url, 10)
                    if t_resp and f_resp:
                        t_hash = hashlib.md5(t_resp.text.encode()).hexdigest()
                        f_hash = hashlib.md5(f_resp.text.encode()).hexdigest()
                        if base_hash == t_hash and base_hash != f_hash:
                            self._promote(f, "validated", ["boolean:AND 1=1 vs AND 1=2"])
                            break

    def _verify_xss(self, f: dict) -> None:
        if not self.browser_available:
            return
        if f.get("verification_stage") in ("verified", "exploitable"):
            return
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        simple_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for payload in simple_payloads:
            test_url = self._inject_param(url, param, payload)
            exec_result = self.browser.check_xss_execution(test_url, payload) if self.browser else None
            if exec_result and (exec_result.get("alert_fired") or exec_result.get("dom_mutation")):
                self._promote(f, "verified", [f"browser:alert_fired"])
                return

    def _verify_cmdi(self, f: dict) -> None:
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        current_steps = f.get("validation_steps", [])
        has_time = any("time" in s.lower() or "delay" in s.lower() for s in current_steps)
        if not has_time:
            for payload in ["; sleep 5", "| sleep 5", "& ping -n 5 127.0.0.1 &"]:
                test_url = self._inject_param(url, param, payload)
                start = time.time()
                safe_get(self._session, test_url, 15, raise_for_status=False)
                elapsed = time.time() - start
                if elapsed > 4.5:
                    self._promote(f, "validated", [f"time:delay={elapsed:.2f}s"])
                    break

        if self.oob_available and f.get("confidence_score", 0) < 100:
            self._try_oob(f, "cmdi")

    def _verify_ssti(self, f: dict) -> None:
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        current_steps = f.get("validation_steps", [])
        has_math = any("7*7" in s or "49" in s for s in current_steps)
        if not has_math:
            for probe in ["{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"]:
                test_url = self._inject_param(url, param, probe)
                resp = safe_get(self._session, test_url, 10, raise_for_status=False)
                if resp and "49" in resp.text:
                    self._promote(f, "validated", [f"ssti:math_eval"])
                    break

        if self.oob_available and f.get("confidence_score", 0) < 100:
            self._try_oob(f, "ssti")

    def _verify_lfi(self, f: dict) -> None:
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        for path, marker in [
            ("/etc/passwd", "root:"),
            ("/etc/hostname", ""),
            ("/proc/self/environ", "HOME="),
        ]:
            test_url = self._inject_param(url, param, path)
            resp = safe_get(self._session, test_url, 10, raise_for_status=False)
            if resp:
                if marker and marker in resp.text:
                    self._promote(f, "exploitable", [f"lfi:file_read {path}"])
                    return
                if len(resp.text) > 500:
                    self._promote(f, "validated", [f"lfi:large_response {path}"])

    def _verify_open_redirect(self, f: dict) -> None:
        url = f.get("url", "")
        if not url:
            return
        resp = safe_get(self._session, url, 10, allow_redirects=True, raise_for_status=False)
        if resp:
            final_url = resp.url
            target = self.config.get("target", "")
            if final_url != url and not final_url.startswith(target.rstrip("/")):
                self._promote(f, "validated", [f"redirect:{final_url}"])

    def _try_oob(self, f: dict, vuln_type: str) -> None:
        if not self.oob_available or not self.oob:
            return
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return
        oob_payload = self.oob.generate_payload()
        test_url = self._inject_param(url, param, oob_payload)
        safe_get(self._session, test_url, 10, raise_for_status=False)
        self.oob.register_interaction(vuln_type, oob_payload, url)

        confirmed = self.oob.poll()
        if confirmed:
            self._promote(f, "verified", [f"oob:callback"])

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

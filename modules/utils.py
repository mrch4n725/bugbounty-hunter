"""
BugBounty Hunter Utility Module

Provides helper functions for HTTP requests, logging, URL handling,
and standardized data structures used throughout the application.
"""

import hashlib
import re
import threading
import time
import warnings
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from rich.console import Console
    from rich.live import Live
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
    )
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

_rich_console: Optional["Console"] = None
_use_rich: bool = True
_log_lock = threading.Lock()
_seen_findings = set()
_seen_findings_lock = threading.Lock()


def set_rich_enabled(enabled: bool) -> None:
    """Enable or disable Rich terminal output (e.g. --no-rich)."""
    global _use_rich
    _use_rich = enabled and RICH_AVAILABLE


def _get_console() -> Optional["Console"]:
    global _rich_console
    if not _use_rich or not RICH_AVAILABLE:
        return None
    if _rich_console is None:
        _rich_console = Console()
    return _rich_console


class Colors:
    """ANSI color codes for terminal output (legacy / --no-rich fallback)."""

    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    END = "\033[0m"


# CVSS v3 metadata keyed by vuln type strings used in scanner.py
VULN_METADATA: Dict[str, Dict[str, Any]] = {
    "Reflected XSS": {
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "what_is_it": "User-supplied input is echoed in the HTTP response without proper output encoding.",
        "impact": "An attacker can run JavaScript in the victim's browser to steal session cookies, perform actions as the user, or deface the page.",
        "remediation": "Apply context-aware output encoding (HTML, attribute, JS, URL). Enable a strict Content-Security-Policy and use frameworks with auto-escaping templates.",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
        "confidence": "probable",
    },
    "Reflected XSS (Form)": {
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "what_is_it": "A form submission causes user input to be reflected in the response without escaping.",
        "impact": "Attackers can submit crafted form data that executes JavaScript when another user views the result.",
        "remediation": "Encode all form output by context; validate input server-side; add CSRF tokens and CSP to limit script execution.",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/cross-site-scripting",
        ],
        "confidence": "probable",
    },
    "SQL Injection": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "what_is_it": "Untrusted input is concatenated into SQL queries instead of using bound parameters.",
        "impact": "Attackers can read, modify, or delete database rows and may escalate to OS command execution on misconfigured stacks.",
        "remediation": "Use parameterized queries or ORM bindings exclusively; denylist is insufficient. Apply least-privilege DB accounts and disable verbose SQL errors in production.",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        ],
        "confidence": "confirmed",
    },
    "Blind SQL Injection (Time-based)": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "what_is_it": "SQL injection inferred when database delay payloads cause measurably slower HTTP responses.",
        "impact": "Attackers can extract data bit-by-bit from the database using timing side channels.",
        "remediation": "Parameterized queries only; set DB statement timeouts; rate-limit and monitor anomalous query latency per session.",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection/blind/time-based",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
        "confidence": "probable",
    },
    "Local File Inclusion": {
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "what_is_it": "User-controlled paths are passed to file read/include functions without validation.",
        "impact": "Attackers can read sensitive files such as /etc/passwd, application config, or source code from the server.",
        "remediation": "Use allowlists for include targets; map IDs to files internally; never pass raw user input to open(), include, or file APIs.",
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html",
            "https://portswigger.net/web-security/file-path-traversal",
        ],
        "confidence": "confirmed",
    },
    "Server-Side Request Forgery (SSRF)": {
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "what_is_it": "The server fetches a URL supplied by the user, including internal or cloud metadata endpoints.",
        "impact": "Attackers can reach internal services, steal cloud credentials from metadata APIs, or port-scan the internal network.",
        "remediation": "Block private/link-local IP ranges; disable redirects on outbound fetches; use URL allowlists and a dedicated egress proxy.",
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/ssrf",
        ],
        "confidence": "probable",
    },
    "Open Redirect": {
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "what_is_it": "The application redirects the browser to an attacker-controlled destination based on user input.",
        "impact": "Enables phishing that inherits trust from your domain and can chain into OAuth token theft.",
        "remediation": "Allow redirects only to relative paths or a fixed allowlist of hosts; reject protocol-relative and external URLs in redirect parameters.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
            "https://portswigger.net/web-security/dom-based/open-redirection",
        ],
        "confidence": "probable",
    },
    "Missing Security Header": {
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "what_is_it": "Responses omit HTTP security headers that browsers rely on to block common attacks.",
        "impact": "Increases risk of clickjacking, MIME sniffing, cleartext downgrade, and XSS when other controls fail.",
        "remediation": "Set HSTS, CSP, X-Frame-Options or frame-ancestors, X-Content-Type-Options, and Referrer-Policy on all HTML responses.",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
            "https://securityheaders.com/",
        ],
        "confidence": "confirmed",
    },
    "Information Disclosure (Server)": {
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "what_is_it": "The Server response header reveals software name and version information.",
        "impact": "Attackers can map your stack to known CVEs and tailor exploits before probing further.",
        "remediation": "Strip or genericize the Server header at the reverse proxy; keep server software patched and disable version tokens.",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server",
            "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html",
        ],
        "confidence": "confirmed",
    },
    "Information Disclosure (X-Powered-By)": {
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "what_is_it": "The X-Powered-By header exposes the application framework or runtime.",
        "impact": "Reveals technology choices that shrink the attacker's search space for framework-specific bugs.",
        "remediation": "Remove X-Powered-By in application and web server config (e.g. expose_php Off, removeServerHeader in Express).",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Powered-By",
            "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html",
        ],
        "confidence": "confirmed",
    },
    "Missing CSRF Protection": {
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "what_is_it": "State-changing POST forms lack unpredictable anti-CSRF tokens tied to the user session.",
        "impact": "A malicious site can submit authenticated requests that change passwords, settings, or perform transactions.",
        "remediation": "Issue per-session CSRF tokens on all mutating forms; validate Origin/Referer; set SameSite=Lax or Strict on session cookies.",
        "references": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/csrf",
        ],
        "confidence": "confirmed",
    },
    "Exposed Sensitive File": {
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "what_is_it": "Backup, config, or VCS files are reachable over HTTP without authentication.",
        "impact": "Attackers may obtain credentials, API keys, source code, or .env secrets leading to full compromise.",
        "remediation": "Deny web access to dotfiles and backups; deploy outside web root; block /.git and env paths at the WAF or reverse proxy.",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html",
        ],
        "confidence": "confirmed",
    },
    "Subdomain Takeover": {
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "what_is_it": "DNS for a subdomain points to a third-party host that no longer serves your content.",
        "impact": "Anyone who claims that external hostname can serve phishing or malware on your subdomain.",
        "remediation": "Delete stale DNS records; verify CNAME targets before publishing; monitor subdomains for dangling CNAMEs to SaaS platforms.",
        "references": [
            "https://owasp.org/www-community/attacks/DNS_Spoofing",
            "https://cheatsheetseries.owasp.org/cheatsheets/DNS_Security_Cheat_Sheet.html",
            "https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-heroku-github-pages-bitbucket-and-more/",
        ],
        "confidence": "probable",
    },
    "IDOR": {
        "cvss_score": 7.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "what_is_it": "Object identifiers in URLs or APIs are used without verifying the requester owns that resource.",
        "impact": "Attackers can read or modify other users' records by incrementing or guessing object IDs.",
        "remediation": "Authorize every object access against the authenticated user; use opaque UUIDs; log and alert on cross-tenant access attempts.",
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "https://portswigger.net/web-security/access-control/idor",
        ],
        "confidence": "probable",
    },
    "JWT Vulnerability": {
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "what_is_it": "JSON Web Tokens are accepted without proper signature verification or with weak algorithms.",
        "impact": "Attackers can forge tokens with arbitrary claims and impersonate any user including administrators.",
        "remediation": "Verify signatures with a strong secret or asymmetric key; reject alg=none; pin allowed algorithms; use short expirations and rotation.",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/JSON_Web_Token_(JWT)_Vulnerabilities",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
        ],
        "confidence": "probable",
    },
}

# Aliases for legacy scanner type strings until scanner.py is aligned (task 4)
_VULN_ALIASES: Dict[str, str] = {
    "Time-based Blind SQL Injection": "Blind SQL Injection (Time-based)",
    "Boolean-based SQL Injection": "SQL Injection",
    "Information Disclosure (Server Banner)": "Information Disclosure (Server)",
    "Potential Subdomain Takeover": "Subdomain Takeover",
    "Insecure Direct Object Reference (IDOR)": "IDOR",
}


def url_in_scope(url: str, config: dict) -> bool:
    """
    Return True if url is allowed by exclude_patterns and include_paths in config.
    Used by the scanner and recon crawler.
    """
    parsed = urlparse(url)
    path = parsed.path + ("?" + parsed.query if parsed.query else "")

    for pattern in config.get("exclude_patterns", []) or []:
        try:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        except re.error:
            continue

    include_paths = config.get("include_paths", []) or []
    if include_paths:
        for pattern in include_paths:
            try:
                if re.search(pattern, path, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False

    return True


def _resolve_vuln_type(vuln_type: str) -> str:
    return _VULN_ALIASES.get(vuln_type, vuln_type)


def banner() -> None:
    """Print the BugBounty Hunter ASCII art banner."""
    art = """
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║              🔍 BugBounty Hunter 🔍                      ║
║                                                          ║
║    Automated Security Reconnaissance & Vulnerability    ║
║                  Scanning Framework                      ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""
    console = _get_console()
    if console is not None:
        console.print(art, style="bold cyan")
    else:
        print(f"{Colors.CYAN}{Colors.BOLD}{art}{Colors.END}")


def log(
    message: str,
    color: str = Colors.WHITE,
    verbose_only: bool = False,
    verbose: bool = False,
) -> None:
    """
    Print a colored log line (Rich when enabled, else ANSI).

    Signature preserved for all call sites: log(msg, color, verbose_only, verbose).
    """
    if verbose_only and not verbose:
        return

    color_map = {
        Colors.CYAN: "cyan",
        Colors.YELLOW: "yellow",
        Colors.RED: "red",
        Colors.GREEN: "green",
        Colors.WHITE: "white",
        Colors.BOLD: "bold white",
    }
    style = color_map.get(color, "white")

    with _log_lock:
        console = _get_console()
        if console is not None:
            if color == Colors.BOLD:
                console.print(message, style=style)
            else:
                console.print(message, style=style)
        else:
            print(f"{color}{message}{Colors.END}", flush=True)


def finding(
    vuln_type: str,
    url: str,
    severity: str,
    details: str,
    evidence: str = "",
    confidence: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Build a standardized finding dict with CVSS metadata, fingerprint, and timestamp.
    """
    dedupe_key = (vuln_type, url)
    with _seen_findings_lock:
        if dedupe_key in _seen_findings:
            return None
        _seen_findings.add(dedupe_key)

    canonical_type = _resolve_vuln_type(vuln_type)
    meta = VULN_METADATA.get(canonical_type, {})

    if confidence is None:
        confidence = meta.get("confidence", "probable")

    evidence_str = evidence if isinstance(evidence, str) else str(evidence)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fingerprint = hashlib.sha256(
        f"{vuln_type}:{url}:{evidence_str}".encode()
    ).hexdigest()

    result: Dict[str, Any] = {
        "title": vuln_type,
        "type": vuln_type,
        "url": url,
        "severity": severity,
        "details": details,
        "evidence": evidence_str,
        "confidence": confidence,
        "fingerprint": fingerprint,
        "timestamp": timestamp,
    }

    for key in (
        "cvss_score",
        "cvss_vector",
        "what_is_it",
        "impact",
        "remediation",
        "references",
    ):
        if key in meta:
            result[key] = meta[key]

    return result


def parse_auth(auth_string: str):
    """Parse username:password basic auth string."""
    if not auth_string or ":" not in auth_string:
        return None
    username, password = auth_string.split(":", 1)
    return username.strip(), password.strip()


def _install_request_delay(session: requests.Session, delay: float) -> None:
    """Wrap session.request with a thread-safe delay between requests."""
    if delay <= 0:
        return
    original_request = session.request
    delay_lock = threading.Lock()
    last_request = {"at": 0.0}

    def delayed_request(method, url, **kwargs):
        with delay_lock:
            elapsed = time.time() - last_request["at"]
            if elapsed < delay:
                time.sleep(delay - elapsed)
            last_request["at"] = time.time()
        return original_request(method, url, **kwargs)

    session.request = delayed_request


def make_session(config: Dict[str, Any]) -> requests.Session:
    """Create a configured requests.Session from scan config."""
    session = requests.Session()

    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })

    if "headers" in config:
        session.headers.update(config["headers"])

    if config.get("cookies"):
        session.cookies.update(config["cookies"])

    proxy = config.get("proxy")
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    auth_info = parse_auth(config.get("auth", ""))
    if auth_info:
        session.auth = auth_info

    retries = config.get("retries", 3)
    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.verify = config.get("verify_ssl", True)
    if not session.verify:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    _install_request_delay(session, float(config.get("delay", 0.0) or 0.0))
    return session


def safe_get(
    session: requests.Session,
    url: str,
    timeout: int = 10,
    allow_redirects: bool = True,
    raise_for_status: bool = True,
    **kwargs,
) -> Optional[requests.Response]:
    """HTTP GET with logging on failure."""
    try:
        response = session.get(
            url, timeout=timeout, allow_redirects=allow_redirects, **kwargs
        )
        if raise_for_status:
            response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        log(f"[!] Timeout accessing {url}", Colors.YELLOW)
        return None
    except requests.exceptions.ConnectionError:
        log(f"[!] Connection error accessing {url}", Colors.YELLOW)
        return None
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        log(f"[!] HTTP error accessing {url}: {status}", Colors.YELLOW)
        return None
    except requests.exceptions.RequestException as e:
        log(f"[!] Request error accessing {url}: {e}", Colors.YELLOW)
        return None
    except Exception as e:
        log(f"[!] Unexpected error accessing {url}: {e}", Colors.RED)
        return None


def safe_post(
    session: requests.Session,
    url: str,
    data: Dict[str, Any],
    timeout: int = 10,
    allow_redirects: bool = True,
    raise_for_status: bool = True,
    **kwargs,
) -> Optional[requests.Response]:
    """HTTP POST with logging on failure."""
    try:
        response = session.post(
            url, data=data, timeout=timeout, allow_redirects=allow_redirects, **kwargs
        )
        if raise_for_status:
            response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        log(f"[!] Timeout posting to {url}", Colors.YELLOW)
        return None
    except requests.exceptions.ConnectionError:
        log(f"[!] Connection error posting to {url}", Colors.YELLOW)
        return None
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        log(f"[!] HTTP error posting to {url}: {status}", Colors.YELLOW)
        return None
    except requests.exceptions.RequestException as e:
        log(f"[!] Request error posting to {url}: {e}", Colors.YELLOW)
        return None
    except Exception as e:
        log(f"[!] Unexpected error posting to {url}: {e}", Colors.RED)
        return None


def normalize_url(base_url: str, relative: str) -> str:
    """Convert a relative URL to absolute using base_url."""
    try:
        if relative.startswith(("http://", "https://", "//")):
            if relative.startswith("//"):
                parsed_base = urlparse(base_url)
                return f"{parsed_base.scheme}:{relative}"
            return relative
        return urljoin(base_url, relative)
    except Exception:
        return relative


def same_domain(target_url: str, url_to_check: str) -> bool:
    """Return True if both URLs share the same host."""
    try:
        target_host = urlparse(target_url).netloc.lower().split(":")[0]
        check_host = urlparse(url_to_check).netloc.lower().split(":")[0]
        return target_host == check_host
    except Exception:
        return False


class _DummyProgress:
    """Minimal Progress stand-in when Rich is disabled or unavailable."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def add_task(self, description: str, total: int = 0):
        return 0

    def update(self, task_id, advance: int = 0, **kwargs):
        pass


def progress_bar(total: int, description: str = "Processing"):
    """
    Return a Rich Progress instance (context manager) or a no-op dummy.

    Usage:
        with progress_bar(100, "Scanning") as progress:
            task = progress.add_task(description, total=total)
            progress.update(task, advance=1)
    """
    if _use_rich and RICH_AVAILABLE:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=_get_console(),
        )
    return _DummyProgress()


def _severity_style(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }.get(severity.lower(), "white")


def _build_findings_table(rows: List[Dict[str, Any]]) -> "Table":
    table = Table(title="Live Findings", expand=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", width=28)
    table.add_column("URL", overflow="fold")
    table.add_column("Confidence", width=12)
    table.add_column("CVSS", width=6, justify="right")

    for row in rows:
        sev = str(row.get("severity", "info"))
        cvss = row.get("cvss_score")
        cvss_txt = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "-"
        table.add_row(
            sev.upper(),
            str(row.get("type", ""))[:28],
            str(row.get("url", ""))[:80],
            str(row.get("confidence", "")),
            cvss_txt,
            style=_severity_style(sev),
        )
    return table


@contextmanager
def live_table():
    """
    Context manager showing a live-updating table of findings as they are added.

    Yields an object with add_finding(finding_dict) method.

    Usage:
        with live_table() as lt:
            lt.add_finding(finding_dict)
    """
    rows: List[Dict[str, Any]] = []
    live_ref: Dict[str, Any] = {"live": None}

    class LiveFindingsHandle:
        def add_finding(self, item: Dict[str, Any]) -> None:
            rows.append(item)
            live = live_ref["live"]
            if live is not None:
                live.update(_build_findings_table(rows))

    handle = LiveFindingsHandle()
    console = _get_console()

    if console is not None and RICH_AVAILABLE:
        table = _build_findings_table(rows)
        with Live(table, console=console, refresh_per_second=4) as live:
            live_ref["live"] = live
            yield handle
    else:
        yield handle


def get_rich_table(title: str, columns: List[str]) -> Optional["Table"]:
    """Create a Rich Table when Rich is enabled."""
    if not _use_rich or not RICH_AVAILABLE:
        return None
    table = Table(title=title)
    for col in columns:
        table.add_column(col)
    return table

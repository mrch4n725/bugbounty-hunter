"""
BugBounty Hunter Utility Module

Provides helper functions for HTTP requests, logging, URL handling,
and standardized data structures used throughout the application.
"""

import sys
import threading
import warnings
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin, urlparse
from contextlib import contextmanager

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Global rich console instance
_rich_console = None

def _get_console():
    """Get or create the rich console instance."""
    global _rich_console
    if _rich_console is None and RICH_AVAILABLE:
        _rich_console = Console()
    return _rich_console

class Colors:
    """ANSI color codes for terminal output (legacy support)."""
    
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


# Vulnerability metadata: CVSS scores, descriptions, impact, remediation, references
VULN_METADATA = {
    "Reflected XSS": {
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "what_is_it": "User input is reflected in the response without proper HTML escaping, allowing arbitrary JavaScript execution.",
        "impact": "An attacker can inject malicious JavaScript that steals cookies, sessions, or credentials from other users visiting a crafted link.",
        "remediation": "Use context-aware output encoding (HTML encode, JavaScript encode, or URL encode as appropriate). Implement Content Security Policy (CSP) headers. Use secure templating engines with auto-escaping enabled.",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://developer.mozilla.org/en-US/docs/Glossary/Cross-site_scripting_XSS",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ],
        "confidence": "probable"
    },
    
    "Reflected XSS (Form)": {
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "what_is_it": "A form field echoes user input back in the response without escaping, allowing XSS attacks.",
        "impact": "Attackers can craft malicious form submissions that execute JavaScript in the context of the application.",
        "remediation": "Sanitize and encode all form input before displaying. Use parameterized templates with auto-escaping. Implement strict CSP headers.",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/cross-site-scripting"
        ],
        "confidence": "probable"
    },
    
    "SQL Injection": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "what_is_it": "User input is concatenated directly into SQL queries without parameterization, allowing arbitrary SQL execution.",
        "impact": "An attacker can extract, modify, or delete database records, potentially compromising the entire application and all user data.",
        "remediation": "Use parameterized queries (prepared statements) exclusively. Never concatenate user input into SQL strings. Implement least-privilege database accounts.",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/sql-injection"
        ],
        "confidence": "confirmed"
    },
    
    "Boolean-based SQL Injection": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "what_is_it": "SQL injection vulnerability exploitable through boolean logic differences in response content or size.",
        "impact": "Attackers can extract sensitive data bit-by-bit by observing differences in application responses.",
        "remediation": "Use parameterized queries and prepared statements. Implement rate limiting and intrusion detection for suspicious query patterns.",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/sql-injection/blind"
        ],
        "confidence": "probable"
    },
    
    "Time-based Blind SQL Injection": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "what_is_it": "SQL injection vulnerability exploitable by observing timing differences in query execution.",
        "impact": "An attacker can extract database content byte-by-byte based on response times, achieving full database compromise.",
        "remediation": "Use parameterized queries exclusively. Implement query timeouts and rate limiting. Monitor for suspicious timing patterns.",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection/blind/time-based",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ],
        "confidence": "probable"
    },
    
    "Local File Inclusion": {
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "what_is_it": "User input is used in file include statements without proper validation, allowing arbitrary local file access.",
        "impact": "Attackers can read sensitive files like /etc/passwd, configuration files with credentials, or source code.",
        "remediation": "Never pass user input directly to file inclusion functions. Use an allowlist of permitted files. Store includes outside web root.",
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html",
            "https://portswigger.net/web-security/file-path-traversal"
        ],
        "confidence": "confirmed"
    },
    
    "Server-Side Request Forgery (SSRF)": {
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "what_is_it": "Application accepts user-controlled URLs and makes requests to them, allowing access to internal services.",
        "impact": "Attackers can access internal services (metadata endpoints, internal APIs), bypass firewalls, and compromise internal infrastructure.",
        "remediation": "Validate and whitelist all user-supplied URLs. Disable HTTP redirects to internal IPs. Use network segmentation and firewall rules.",
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/ssrf"
        ],
        "confidence": "probable"
    },
    
    "Open Redirect": {
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "what_is_it": "Application redirects users to attacker-controlled URLs based on user input without validation.",
        "impact": "Attackers can redirect users to phishing sites to steal credentials or perform social engineering attacks.",
        "remediation": "Validate redirect URLs against a whitelist of safe destinations. Display a confirmation page before redirecting to external sites.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/Open_Redirect",
            "https://portswigger.net/web-security/authentication/other-mechanisms/open-redirect"
        ],
        "confidence": "probable"
    },
    
    "Missing Security Header": {
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "what_is_it": "HTTP response is missing critical security headers that protect against various attacks.",
        "impact": "Applications are vulnerable to clickjacking, man-in-the-middle attacks, MIME-sniffing attacks, and XSS.",
        "remediation": "Implement security headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
            "https://securityheaders.com/"
        ],
        "confidence": "confirmed"
    },
    
    "Information Disclosure (Server Banner)": {
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "what_is_it": "Server reveals its software name and version number in HTTP response headers.",
        "impact": "Attackers can identify known vulnerabilities in specific versions and target them with automated exploits.",
        "remediation": "Remove or obfuscate Server header. Use a reverse proxy to hide backend technology. Disable version disclosure.",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server"
        ],
        "confidence": "confirmed"
    },
    
    "Information Disclosure (X-Powered-By)": {
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "what_is_it": "X-Powered-By header reveals the web framework or technology stack in use.",
        "impact": "Attackers can identify framework versions and exploit known vulnerabilities specific to that framework.",
        "remediation": "Remove X-Powered-By header entirely. Configure web server to not emit this header.",
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Powered-By",
            "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html"
        ],
        "confidence": "confirmed"
    },
    
    "Missing CSRF Protection": {
        "cvss_score": 6.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "what_is_it": "POST forms lack anti-CSRF tokens, allowing cross-site request forgery attacks.",
        "impact": "Attackers can trick authenticated users into performing unintended actions (password changes, fund transfers, etc.).",
        "remediation": "Implement CSRF tokens on all state-changing forms. Use SameSite cookie attribute. Verify Origin/Referer headers.",
        "references": [
            "https://owasp.org/www-community/attacks/csrf",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/csrf"
        ],
        "confidence": "confirmed"
    },
    
    "Exposed Sensitive File": {
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "what_is_it": "Sensitive configuration or backup files are accessible through the web root.",
        "impact": "Attackers can read environment variables, database credentials, source code, or private keys.",
        "remediation": "Remove sensitive files from web root. Use .gitignore and .dockerignore. Implement proper access controls and authentication.",
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html",
            "https://owasp.org/www-project-secrets-management/"
        ],
        "confidence": "confirmed"
    },
    
    "Subdomain Takeover": {
        "cvss_score": 4.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "what_is_it": "A subdomain's DNS entry points to a service (S3, GitHub Pages, Heroku) that is no longer provisioned.",
        "impact": "Attackers can register the service and respond to requests for the subdomain, hosting malicious content.",
        "remediation": "Remove unused DNS entries. Provision all subdomains or use CNAME validation. Monitor DNS regularly.",
        "references": [
            "https://owasp.org/www-community/attacks/DNS_Spoofing",
            "https://cheatsheetseries.owasp.org/cheatsheets/DNS_Spoofing_Prevention_Cheat_Sheet.html",
            "https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-heroku-github-firebase-and-other-platforms/"
        ],
        "confidence": "probable"
    },
    
    "Insecure Direct Object Reference (IDOR)": {
        "cvss_score": 7.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
        "what_is_it": "Application uses predictable IDs to access resources without proper authorization checks.",
        "impact": "Attackers can access, modify, or delete other users' data by manipulating object IDs in URLs or requests.",
        "remediation": "Implement access control checks on every resource access. Use non-sequential IDs (UUIDs). Log access attempts.",
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "https://portswigger.net/web-security/access-control"
        ],
        "confidence": "probable"
    },
    
    "JWT Vulnerability": {
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "what_is_it": "JWT tokens are improperly validated, allowing signature bypass or algorithm confusion attacks.",
        "impact": "Attackers can forge valid JWT tokens, impersonating any user without authentication.",
        "remediation": "Always validate JWT signatures. Disallow 'none' algorithm. Use strong signing secrets. Implement token expiration and refresh.",
        "references": [
            "https://owasp.org/www-community/attacks/JWT_Vulnerabilities",
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
        ],
        "confidence": "probable"
    },
}



# Thread lock for thread-safe logging
_log_lock = threading.Lock()


def banner() -> None:
    """
    Print the BugBounty Hunter ASCII art banner and introduction.
    """
    banner_text = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║              🔍 BugBounty Hunter 🔍                      ║
║                                                          ║
║    Automated Security Reconnaissance & Vulnerability    ║
║                  Scanning Framework                      ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
{Colors.END}
    """
    print(banner_text)


def log(message: str, color: str = Colors.WHITE, verbose_only: bool = False, verbose: bool = False) -> None:
    """
    Print a colored logging message with thread-safe output.
    Supports both rich and plain ANSI output.
    
    Args:
        message: The message to log
        color: Color code from Colors class (for ANSI fallback)
        verbose_only: If True, only print when verbose is True
        verbose: Whether verbose mode is enabled
    """
    if verbose_only and not verbose:
        return
    
    with _log_lock:
        console = _get_console()
        if console is not None and RICH_AVAILABLE:
            # Map ANSI colors to rich colors
            color_map = {
                Colors.CYAN: "cyan",
                Colors.YELLOW: "yellow",
                Colors.RED: "red",
                Colors.GREEN: "green",
                Colors.WHITE: "white",
                Colors.BOLD: "bold white",
            }
            rich_color = color_map.get(color, "white")
            console.print(message, style=rich_color)
        else:
            # Fallback to ANSI
            output = f"{color}{message}{Colors.END}"
            print(output, flush=True)


def finding(
    vuln_type: str,
    url: str,
    severity: str,
    details: str,
    evidence: Any = "",
    confidence: Optional[str] = None,
    **extras
) -> Dict[str, Any]:
    """
    Create a standardized finding dictionary with enriched metadata.
    
    Args:
        vuln_type: Type of vulnerability (must match VULN_METADATA keys)
        url: URL where the finding was discovered
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        details: Detailed description of the finding
        evidence: Evidence or proof of the vulnerability
        confidence: Confidence level (confirmed/probable/tentative)
        **extras: Additional metadata fields
    
    Returns:
        Dictionary with standardized finding structure including metadata
    """
    # Timestamp in ISO 8601 format
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Generate fingerprint: SHA256 of vuln_type:url:evidence
    fingerprint_str = f"{vuln_type}:{url}:{evidence}"
    fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    # Extract evidence for default confidence if not provided
    if confidence is None:
        confidence = VULN_METADATA.get(vuln_type, {}).get("confidence", "probable")
    
    # Build finding from metadata
    metadata = VULN_METADATA.get(vuln_type, {})
    finding_data = {
        'type': vuln_type,
        'url': url,
        'severity': severity,
        'details': details,
        'evidence': evidence,
        'confidence': confidence,
        'fingerprint': fingerprint,
        'timestamp': timestamp,
        'cvss_score': metadata.get('cvss_score'),
        'cvss_vector': metadata.get('cvss_vector'),
        'what_is_it': metadata.get('what_is_it'),
        'impact': metadata.get('impact'),
        'remediation': metadata.get('remediation'),
        'references': metadata.get('references', []),
    }
    finding_data.update(extras)
    return finding_data


def parse_auth(auth_string: str):
    """
    Parse a basic auth credential string into a tuple.

    Args:
        auth_string: A string formatted as username:password

    Returns:
        Tuple[str, str] or None
    """
    if not auth_string or ':' not in auth_string:
        return None
    username, password = auth_string.split(':', 1)
    return username.strip(), password.strip()


def make_session(config: Dict[str, Any]) -> requests.Session:
    """
    Create a requests Session with custom configuration.
    
    Configures the session with:
    - Custom headers (User-Agent, Accept, etc. to prevent 406 errors)
    - Cookie jar if provided
    - Retry strategy for resilience
    - SSL verification settings
    - Optional proxy support and basic auth
    
    Args:
        config: Configuration dictionary containing:
            - 'headers': dict of HTTP headers
            - 'cookies': dict of cookies (optional)
            - 'verify_ssl': bool for SSL verification (default: True)
            - 'retries': int number of retries (default: 3)
            - 'proxy': proxy URL (optional)
            - 'auth': Basic auth credentials string username:password
    
    Returns:
        Configured requests.Session object
    """
    session = requests.Session()
    
    # Expanded headers to satisfy the target server's content negotiation rules
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    })
    
    # Set headers (This will overwrite the default if you pass custom headers)
    if 'headers' in config:
        session.headers.update(config['headers'])
    
    # Set cookies if provided
    if 'cookies' in config and config['cookies']:
        session.cookies.update(config['cookies'])
    
    # Configure proxy support
    proxy = config.get('proxy')
    if proxy:
        session.proxies.update({
            'http': proxy,
            'https': proxy
        })
    
    # Set basic auth if provided
    auth_info = parse_auth(config.get('auth', ''))
    if auth_info:
        session.auth = auth_info
    
    # Configure retry strategy
    retries = config.get('retries', 3)
    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Handle SSL verification
    verify_ssl = config.get('verify_ssl', True)
    session.verify = verify_ssl
    
    if not verify_ssl:
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    return session
def safe_get(
    session: requests.Session,
    url: str,
    timeout: int = 10,
    allow_redirects: bool = True,
    raise_for_status: bool = True,
    **kwargs
) -> Optional[requests.Response]:
    """
    Safely make an HTTP GET request with error handling.
    
    Args:
        session: requests.Session object
        url: URL to request
        timeout: Request timeout in seconds
        allow_redirects: Follow redirects if True
        raise_for_status: Raise an exception for non-success status codes
        **kwargs: Additional request kwargs to pass to session.get
    
    Returns:
        requests.Response object or None if error occurred
    """
    try:
        response = session.get(url, timeout=timeout, allow_redirects=allow_redirects, **kwargs)
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
        log(f"[!] HTTP error accessing {url}: {e.response.status_code}", Colors.YELLOW)
        return None
    except requests.exceptions.RequestException as e:
        log(f"[!] Request error accessing {url}: {str(e)}", Colors.YELLOW)
        return None
    except Exception as e:
        log(f"[!] Unexpected error accessing {url}: {str(e)}", Colors.RED)
        return None


def safe_post(
    session: requests.Session,
    url: str,
    data: Dict[str, Any],
    timeout: int = 10,
    allow_redirects: bool = True,
    raise_for_status: bool = True,
    **kwargs
) -> Optional[requests.Response]:
    """
    Safely make an HTTP POST request with error handling.
    
    Args:
        session: requests.Session object
        url: URL to request
        data: POST data dictionary
        timeout: Request timeout in seconds
        allow_redirects: Follow redirects if True
        raise_for_status: Raise an exception for non-success status codes
        **kwargs: Additional request kwargs to pass to session.post
    
    Returns:
        requests.Response object or None if error occurred
    """
    try:
        response = session.post(url, data=data, timeout=timeout, allow_redirects=allow_redirects, **kwargs)
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
        log(f"[!] HTTP error posting to {url}: {e.response.status_code}", Colors.YELLOW)
        return None
    except requests.exceptions.RequestException as e:
        log(f"[!] Request error posting to {url}: {str(e)}", Colors.YELLOW)
        return None
    except Exception as e:
        log(f"[!] Unexpected error posting to {url}: {str(e)}", Colors.RED)
        return None


def normalize_url(base_url: str, relative: str) -> str:
    """
    Convert a relative URL to an absolute URL.
    
    Args:
        base_url: Base URL to use as reference
        relative: Relative or absolute URL to normalize
    
    Returns:
        Absolute URL string
    """
    try:
        # If already absolute, return as-is
        if relative.startswith(('http://', 'https://', '//')):
            if relative.startswith('//'):
                # Protocol-relative URL
                parsed_base = urlparse(base_url)
                return f"{parsed_base.scheme}:{relative}"
            return relative
        
        # Join relative URL with base
        normalized = urljoin(base_url, relative)
        return normalized
    except Exception:
        return relative


def same_domain(target_url: str, url_to_check: str) -> bool:
    """
    Check if two URLs belong to the same domain.
    
    Args:
        target_url: Target URL
        url_to_check: URL to check against target
    
    Returns:
        True if both URLs are on the same domain, False otherwise
    """
    try:
        target_parsed = urlparse(target_url)
        check_parsed = urlparse(url_to_check)
        
        # Extract domain (netloc includes host:port)
        target_domain = target_parsed.netloc.lower()
        check_domain = check_parsed.netloc.lower()
        
        # Remove port if present for comparison
        target_host = target_domain.split(':')[0]
        check_host = check_domain.split(':')[0]
        
        return target_host == check_host
    except Exception:
        return False


def get_rich_table(title: str, columns: List[str]) -> Optional[Table]:
    """
    Create a Rich Table if available, otherwise return None.
    
    Args:
        title: Title of the table
        columns: List of column names
    
    Returns:
        Rich Table instance or None if Rich is not available
    """
    if not RICH_AVAILABLE:
        return None
    
    table = Table(title=title)
    for col in columns:
        table.add_column(col)
    return table


@contextmanager
def progress_bar(total: int, description: str = "Processing"):
    """
    Context manager for a rich progress bar.
    
    Args:
        total: Total number of items to process
        description: Description of the task
    
    Yields:
        Tuple of (Progress instance, task_id) or (None, None) if Rich is not available
    """
    if RICH_AVAILABLE:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
        )
        with progress:
            task_id = progress.add_task(description, total=total)
            yield progress, task_id
    else:
        # Fallback: dummy object that does nothing
        class DummyProgress:
            def update(self, task_id, advance=1):
                pass
        yield DummyProgress(), None


@contextmanager
def live_table(table: Optional[Table], refresh_per_second: int = 4):
    """
    Context manager for a live-updating rich table.
    
    Args:
        table: Rich Table instance
        refresh_per_second: Update frequency
    
    Yields:
        Live instance or None if Rich is not available
    """
    if RICH_AVAILABLE and table is not None:
        live = Live(table, refresh_per_second=refresh_per_second)
        with live:
            yield live
    else:
        # Fallback: dummy context
        class DummyLive:
            def update(self, table):
                pass
        yield DummyLive()

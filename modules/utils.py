"""
BugBounty Hunter Utility Module

Provides helper functions for HTTP requests, logging, URL handling,
and standardized data structures used throughout the application.
"""

import sys
import threading
import warnings
from typing import Optional, Dict, Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class Colors:
    """ANSI color codes for terminal output."""
    
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


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


def log(message: str, color: str, verbose_only: bool = False, verbose: bool = False) -> None:
    """
    Print a colored logging message with thread-safe output.
    
    Args:
        message: The message to log
        color: Color code from Colors class
        verbose_only: If True, only print when verbose is True
        verbose: Whether verbose mode is enabled
    """
    if verbose_only and not verbose:
        return
    
    with _log_lock:
        output = f"{color}{message}{Colors.END}"
        print(output, flush=True)


def finding(
    title: str,
    url: str,
    severity: str,
    details: str,
    evidence: Any,
    impact: str = "",
    recommendation: str = "",
    **extras
) -> Dict[str, Any]:
    """
    Create a standardized finding dictionary.
    
    Args:
        title: Title/name of the finding
        url: URL where the finding was discovered
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        details: Detailed description of the finding
        evidence: Evidence or proof of the vulnerability
        impact: Optional impact summary of the finding
        recommendation: Optional remediation guidance
        **extras: Additional metadata fields
    
    Returns:
        Dictionary with standardized finding structure
    """
    finding_data = {
        'title': title,
        'url': url,
        'severity': severity,
        'details': details,
        'evidence': evidence,
        'impact': impact,
        'recommendation': recommendation,
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

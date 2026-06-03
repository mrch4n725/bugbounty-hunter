"""Shared utilities: logging, colors, HTTP helpers."""

import requests
import sys
from urllib.parse import urlparse, urljoin


class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def log(msg: str, color: str = Colors.WHITE, verbose_only: bool = False, verbose: bool = True):
    if verbose_only and not verbose:
        return
    print(f"{color}{msg}{Colors.RESET}")


def banner():
    art = r"""
  ____              ____                   _          
 | __ ) _   _  __ _| __ )  ___  _   _ _ __| |_ _   _ 
 |  _ \| | | |/ _` |  _ \ / _ \| | | | '_ \ __| | | |
 | |_) | |_| | (_| | |_) | (_) | |_| | | | | |_| |_| |
 |____/ \__,_|\__, |____/ \___/ \__,_|_| |_|\__|\__, |
              |___/  Hunter                      |___/ 
    """
    print(f"{Colors.CYAN}{Colors.BOLD}{art}{Colors.RESET}")
    print(f"{Colors.YELLOW}  Automated Bug Bounty Scanner | Use responsibly & ethically{Colors.RESET}\n")


def make_session(config: dict) -> requests.Session:
    """Create a pre-configured requests session."""
    session = requests.Session()
    session.verify = False  # many bug bounty targets use self-signed certs
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (BugBountyHunter/1.0; +https://github.com/youruser/bugbounty-hunter)",
        "Accept": "*/*",
    })
    if config.get("headers"):
        session.headers.update(config["headers"])
    if config.get("cookies"):
        session.cookies.update(config["cookies"])
    return session


def safe_get(session: requests.Session, url: str, timeout: int = 10, **kwargs) -> requests.Response | None:
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, **kwargs)
        return resp
    except Exception:
        return None


def safe_post(session: requests.Session, url: str, data: dict, timeout: int = 10, **kwargs) -> requests.Response | None:
    try:
        resp = session.post(url, data=data, timeout=timeout, allow_redirects=True, **kwargs)
        return resp
    except Exception:
        return None


def normalize_url(base: str, href: str) -> str | None:
    try:
        full = urljoin(base, href)
        parsed = urlparse(full)
        if parsed.scheme in ("http", "https"):
            return full
    except Exception:
        pass
    return None


def same_domain(url1: str, url2: str) -> bool:
    try:
        return urlparse(url1).netloc == urlparse(url2).netloc
    except Exception:
        return False


def finding(vuln_type: str, url: str, severity: str, details: str, evidence: str = "") -> dict:
    """Standardised finding dict."""
    return {
        "type":     vuln_type,
        "url":      url,
        "severity": severity,   # critical | high | medium | low | info
        "details":  details,
        "evidence": evidence,
    }

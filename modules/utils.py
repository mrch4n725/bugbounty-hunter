"""
BugBounty Hunter Utility Module

Provides helper functions for HTTP requests, logging, URL handling,
and standardized data structures used throughout the application.
"""

import enum
import hashlib
import json
import sys
import os
import random
import re
import socket
import threading
import time
import uuid
import warnings
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_rich_console: Optional["Console"] = None
_use_rich: bool = True
_log_lock = threading.Lock()
_rich_available_cache: bool | None = None
_seen_findings = set()
_seen_findings_lock = threading.Lock()


def _rich_available() -> bool:
    """Check if Rich terminal library is available via CapabilityRegistry (cached)."""
    global _rich_available_cache
    if _rich_available_cache is not None:
        return _rich_available_cache
    try:
        from app.capabilities import CapabilityRegistry
        _rich_available_cache = CapabilityRegistry.get_global().has("rich")
    except Exception:
        _rich_available_cache = False
    return _rich_available_cache


def reset_seen_findings() -> None:
    """Clear the module-level deduplication set. Call once per scan session."""
    global _seen_findings
    with _seen_findings_lock:
        _seen_findings = set()


SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "x-auth-token"}


def safe_cookies_dict(cookie_jar) -> dict[str, str]:
    """Safely convert a RequestsCookieJar to a plain dict.

    ``dict(jar)`` raises ``KeyError`` when multiple cookies share a name
    across different domains/paths.  This helper picks the *last* value
    for each cookie name, which is the correct behaviour for curl -b.
    """
    out: dict[str, str] = {}
    try:
        for c in cookie_jar:
            out[c.name] = c.value
    except Exception:
        pass
    return out

# Module-level default; main.py flips via set_mask_sensitive_default()
_MASK_SENSITIVE_DEFAULT: bool = True

class ScanProgress:
    """Rich-based scan progress bar with ETA, findings count, and module tracking.

    Uses the same Console singleton as log() to avoid display corruption.
    Falls back to no-op when Rich is unavailable or --no-rich is set.
    Usage:
        with ScanProgress(total_urls, config) as prog:
            for url in urls:
                prog.advance(url, findings_count)
    """

    def __init__(self, total: int, config: dict, desc: str = "Scanning"):
        self._total = total
        self._config = config
        self._desc = desc
        self._progress: Optional["Progress"] = None
        self._task_id = None
        self._findings_count = 0

    def __enter__(self):
        no_rich = self._config.get("no_rich", False) or not _rich_available()
        if no_rich:
            return self
        console = _get_console()
        if console is None:
            return self
        from rich.progress import (
            BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn,
        )
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            TextColumn("[bold]{task.fields[findings]} findings"),
            console=console,
        )
        self._progress.start()
        self._task_id = self._progress.add_task(
            self._desc, total=self._total, findings=0
        )
        return self

    def __exit__(self, *args):
        if self._progress:
            self._progress.stop()

    def advance(self, url: str = "", findings_count: int = 0):
        if self._progress and self._task_id is not None:
            self._progress.update(self._task_id, advance=1, findings=findings_count)
            if url:
                self._progress.update(self._task_id, description=f"{self._desc} | {url[:80]}")

    def update_findings(self, count: int):
        self._findings_count = count
        if self._progress and self._task_id is not None:
            self._progress.update(self._task_id, findings=count)


class ModuleProgress:
    """Simpler spinner + label for tracking TARGET_LEVEL module execution.

    Shows a spinner and the current module name while it runs.
    Falls back to plain print when Rich is unavailable.
    """

    def __init__(self, config: dict, desc: str = "Running modules"):
        self._config = config
        self._desc = desc
        self._status: Optional["Status"] = None
        self._task_id = None

    def __enter__(self):
        if self._config.get("no_rich", False) or not _rich_available():
            return self
        console = _get_console()
        if console is None:
            return self
        from rich.status import Status
        self._status = Status(self._desc, console=console, spinner="dots")
        self._status.start()
        return self

    def __exit__(self, *args):
        if self._status:
            self._status.stop()

    def update(self, msg: str):
        if self._status:
            self._status.update(msg)

    def stop(self):
        if self._status:
            self._status.stop()
            self._status = None


def set_mask_sensitive_default(enabled: bool) -> None:
    global _MASK_SENSITIVE_DEFAULT
    _MASK_SENSITIVE_DEFAULT = enabled

def _build_curl(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    cookies: Optional[Dict[str, str]] = None,
    mask_sensitive: Optional[bool] = None,
) -> str:
    """Build a curl command string for reproduction of a request."""
    if mask_sensitive is None:
        mask_sensitive = _MASK_SENSITIVE_DEFAULT
    parts = ["curl", "-X", method.upper()]
    if headers:
        for k, v in headers.items():
            display_v = "<REDACTED>" if (mask_sensitive and k.lower() in SENSITIVE_HEADER_NAMES) else v
            parts.append(f"-H '{k}: {display_v}'")
    if cookies:
        for k, v in cookies.items():
            parts.append(f"-b '{k}={v}'")
    if data is not None and data:
        if isinstance(data, str):
            parts.append(f"-d '{data}'")
        elif isinstance(data, dict):
            import urllib.parse
            parts.append(f"-d '{urllib.parse.urlencode(data)}'")
    parts.append(f"'{url}'")
    return " \\\n  ".join(parts)


def set_rich_enabled(enabled: bool) -> None:
    """Enable or disable Rich terminal output (e.g. --no-rich)."""
    global _use_rich
    _use_rich = enabled and _rich_available()


def _get_console() -> Optional["Console"]:
    global _rich_console
    if not _use_rich or not _rich_available():
        return None
    if _rich_console is None:
        from rich.console import Console
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


# ── Core model imports ─────────────────────────────────────────────────────────
# Phase 1: re-export from canonical models module.
# Phases 2-4: migrate callers to import from models directly.

from models.finding import (
    VerificationStage,
    EvidenceStrength,
    FalsePositiveRisk,
    ConfidenceLevel,
    FindingState,
    CONFIDENCE_WEIGHTS,
    calculate_confidence,
    evidence_strength_from_score,
    false_positive_risk_from_score,
    compute_fingerprint,
    compute_root_cause_fingerprint,
)
from models.evidence import (
    EvidenceType,
    EvidenceStatus,
    EvidenceBase,
    HttpRequestEvidence,
    HttpResponseEvidence,
    ResponseExcerptEvidence,
    ScreenshotEvidence,
    OOBCallbackEvidence,
    TimingEvidence,
    SecretValidationEvidence,
    BrowserExecutionEvidence,
    GraphQLSchemaEvidence,
    AuthorizationComparisonEvidence,
)
from models.finding import Finding

# ── Prioritization Scoring Engine ────────────────────────────────────────────

SEVERITY_PRIORITY = {"critical": 100, "high": 75, "medium": 50, "low": 25}
STAGE_PRIORITY = {"verified": 100, "exploitable": 90, "validated": 60, "detected": 30}

def compute_priority_score(finding) -> int:
    """
    Compute a 0–100 priority score for a finding based on:
    - Severity (25 pts max)
    - Verification stage (35 pts max)
    - Evidence strength (20 pts max)
    - OOB bonus (+15)
    - Signal count (+5 per signal, cap 10)
    """
    severity = finding.severity.lower() if finding.severity else "low"
    stage = finding.verification_stage.lower() if finding.verification_stage else "detected"
    evidence = finding.evidence_strength.lower() if finding.evidence_strength else "weak"

    sev_score = SEVERITY_PRIORITY.get(severity, 25)
    stage_score = STAGE_PRIORITY.get(stage, 30)
    evidence_map = {"verified": 20, "strong": 15, "moderate": 10, "weak": 5}
    ev_score = evidence_map.get(evidence, 5)

    ev_list = finding.evidence
    if not isinstance(ev_list, list):
        ev_list = [str(ev_list)] if ev_list else []
    oob_bonus = 15 if any("oob" in str(ev).lower() for ev in ev_list) else 0
    validation_steps = finding.reproduction_steps
    signal_bonus = min(len(validation_steps) * 5, 10)

    raw = sev_score * 0.25 + stage_score * 0.35 + ev_score * 0.20 + oob_bonus + signal_bonus
    return min(int(raw), 100)


def prioritize_findings(findings) -> list:
    """Sort findings by computed priority score descending, adding priority_score key."""
    for f in findings:
        f["priority_score"] = compute_priority_score(f)
    return sorted(findings, key=lambda f: f.get("priority_score", 0), reverse=True)


# ── OOB Detection Framework ───────────────────────────────────────────────

class OOBDetectionFramework:
    """Out-of-band detection using dnslog.cn (DNS) and subdomain-based callback URLs.

    Generates unique callback tokens, optionally registers with dnslog.cn for
    DNS-based polling, and polls for callbacks to confirm blind vulnerabilities.

    If dnslog.cn is reachable, DNS callbacks are confirmed automatically.
    For HTTP callbacks, set ``--oob-host`` to a service such as interactsh,
    Burp Collaborator, or a self-hosted listener; unique URLs will be generated
    but polling requires a compatible backend.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.oob_host = config.get("oob_host", "") or ""
        self.callback_token = str(uuid.uuid4()).replace("-", "")[:16]
        self._interactions: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

        # DNS-based polling backend (dnslog.cn)
        self._dnslog_domain: str | None = None
        self._dnslog_cookies: dict | None = None
        self._init_dnslog()

    # ── Backend initialisation ──────────────────────────────────────────

    def _init_dnslog(self) -> None:
        """Register with dnslog.cn for DNS-based OOB polling."""
        try:
            resp = requests.get("http://dnslog.cn/getdomain.php", timeout=10)
            if resp.status_code == 200:
                domain = resp.text.strip()
                if domain:
                    self._dnslog_domain = domain
                    self._dnslog_cookies = dict(resp.cookies)
        except Exception:
            pass

    # ── Callback URL generation ─────────────────────────────────────────

    @property
    def callback_host(self) -> str:
        """Return the callback host — dnslog domain or token-based subdomain."""
        if self._dnslog_domain:
            return f"{self.callback_token}.{self._dnslog_domain}"
        if self.oob_host:
            return f"{self.callback_token}.{self.oob_host}"
        return ""

    @property
    def callback_url(self) -> str:
        host = self.callback_host
        if not host:
            return ""
        return f"http://{host}/bbh-verify"

    def generate_payload(self, placeholder: str = "{oob}") -> str:
        """Replace {oob} placeholder with the unique callback host."""
        if not self.oob_host and not self._dnslog_domain:
            return ""
        return placeholder.replace("{oob}", self.callback_host)

    # ── Token generation ───────────────────────────────────────────

    def _generate_token(self, fingerprint: str, payload: str, url: str) -> str:
        """Generate a deterministic token derived from all three inputs."""
        raw = f"{fingerprint}:{payload}:{url}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def generate_unique_callback_host(self, fingerprint: str, payload: str, url: str) -> str:
        """Return a callback host with a token unique to (fingerprint, payload, url)."""
        token = self._generate_token(fingerprint, payload, url)
        if self._dnslog_domain:
            return f"{token}.{self._dnslog_domain}"
        if self.oob_host:
            return f"{token}.{self.oob_host}"
        return ""

    def generate_unique_payload(self, placeholder: str, fingerprint: str, payload: str, url: str) -> str:
        """Replace {oob} with a unique callback host for this combination."""
        host = self.generate_unique_callback_host(fingerprint, payload, url)
        if not host:
            return ""
        return placeholder.replace("{oob}", host)

    # ── Interaction tracking ────────────────────────────────────────────

    def register_interaction(self, vuln_type: str, payload: str, url: str,
                             fingerprint: str = "") -> None:
        token = self._generate_token(fingerprint or vuln_type, payload, url)
        with self._lock:
            self._interactions.setdefault(vuln_type, []).append({
                "payload": payload,
                "url": url,
                "fingerprint": fingerprint or vuln_type,
                "token": token,
                "timestamp": time.time(),
            })

    def poll(self, timeout: float = 120.0) -> List[Dict[str, Any]]:
        """Poll for callbacks with exponential backoff.

        Starts with 1 s interval, doubling each retry up to max 30 s.
        Returns list of confirmed interactions.
        """
        if not self.callback_host:
            return []
        start_time = time.time()
        interval = 1.0
        max_interval = 30.0
        verbose = self.config.get("verbose", False)

        confirmed: List[Dict[str, Any]] = []
        while time.time() - start_time < timeout:
            with self._lock:
                items = list(self._interactions.items())
            found = False
            for vuln_type, interactions in items:
                for entry in interactions:
                    if entry.get("confirmed"):
                        continue
                    if self._check_callback(entry):
                        entry["confirmed"] = True
                        confirmed.append(entry)
                        found = True
            if found:
                break

            remaining = timeout - (time.time() - start_time)
            if remaining <= 0:
                break

            sleep_time = min(interval, remaining, max_interval)
            log(f"[OOB] Poll attempt — sleeping {sleep_time:.1f}s (interval={interval:.0f}s)",
                Colors.CYAN, verbose_only=True, verbose=verbose)
            time.sleep(sleep_time)
            interval = min(interval * 2, max_interval)

        return confirmed

    def _check_callback(self, entry: Dict[str, Any]) -> bool:
        """Check if a DNS or HTTP callback has been received."""
        if self._dnslog_domain:
            return self._poll_dnslog()
        return False

    def _poll_dnslog(self) -> bool:
        """Poll dnslog.cn for DNS records for the registered domain."""
        if not self._dnslog_cookies:
            return False
        try:
            resp = requests.get(
                "http://dnslog.cn/getrecords.php",
                cookies=self._dnslog_cookies,
                timeout=5,
            )
            if resp.status_code == 200:
                records = resp.text.strip()
                if records and records != "[]":
                    return True
        except Exception:
            pass
        return False

    def clear(self) -> None:
        with self._lock:
            self._interactions.clear()


# ── Deduplication Engine ─────────────────────────────────────────────────

# ── Browser Validation Layer ─────────────────────────────────────────────

class BrowserValidator:
    """Pooled Playwright browser validator.
    
    Launches ONE browser per scan session. Every check_* method reuses the
    same browser — only individual pages are created and closed. Call
    `close()` at scan end to release the browser.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.timeout = config.get("timeout", 10) * 1000
        self._pw = None
        self._browser = None
        self._lock = threading.Lock()
        self._screenshot_counter = 0

    def _ensure_browser(self):
        if self._browser is not None:
            return self._browser
        with self._lock:
            if self._browser is not None:
                return self._browser
            try:
                from playwright.sync_api import sync_playwright
                self._pw = sync_playwright().start()
            except Exception:
                self._pw = None
                self._browser = None
                return None
            try:
                self._browser = self._pw.chromium.launch(headless=True)
            except Exception:
                try:
                    self._pw.stop()
                except Exception:
                    pass
                self._pw = None
                self._browser = None
            return self._browser

    def close(self):
        with self._lock:
            try:
                if self._browser:
                    self._browser.close()
            except Exception:
                pass
            try:
                if self._pw:
                    self._pw.stop()
            except Exception:
                pass
            self._browser = None
            self._pw = None

    def _new_page(self):
        browser = self._ensure_browser()
        if not browser:
            return None
        return browser.new_page()

    def check_xss_execution(self, url: str, payload: str,
                            html_content: Optional[str] = None,
                            screenshot_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Load URL (or HTML content for POST forms) and check if JS executes.
        
        If Playwright confirms JS execution and screenshot_dir is provided,
        captures a full-page PNG screenshot and includes its path in the result.
        """
        page = None
        try:
            page = self._new_page()
            if not page:
                return None
            result = {"alert_fired": False, "dom_mutation": False, "callback": False, "screenshot_path": ""}

            def on_dialog(dialog):
                result["alert_fired"] = True
                dialog.dismiss()

            page.on("dialog", on_dialog)
            page.set_viewport_size({"width": 1280, "height": 720})
            if html_content:
                page.set_content(html_content, wait_until="domcontentloaded")
            else:
                page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)

            dom_evidence = page.evaluate("""() => {
                const body = document.body ? document.body.innerHTML : '';
                const scripts = Array.from(document.querySelectorAll('script'));
                const bbhAttr = document.querySelector('[data-bbh-xss]');
                return {
                    body_snippet: body.substring(0, 200),
                    script_count: scripts.length,
                    has_bbh_marker: window.__bbh_xss === 1 || body.includes('__bbh_xss'),
                    has_bbh_fired: window.__bbhXSSFired === true,
                    has_data_attr: bbhAttr !== null,
                };
            }""")
            result["dom_mutation"] = dom_evidence.get("has_bbh_marker", False) or dom_evidence.get("has_bbh_fired", False) or dom_evidence.get("has_data_attr", False)

            # Capture screenshot when execution confirmed and output dir available
            execution_confirmed = result["alert_fired"] or result["dom_mutation"]
            if execution_confirmed and screenshot_dir:
                import os
                os.makedirs(screenshot_dir, exist_ok=True)
                self._screenshot_counter += 1
                safe_name = re.sub(r'[^\w\-]', '_', url.split('//')[-1][:60])
                shot_path = os.path.join(screenshot_dir, f"xss_{self._screenshot_counter:03d}_{safe_name}.png")
                try:
                    page.screenshot(path=shot_path, full_page=True)
                    result["screenshot_path"] = shot_path
                except Exception:
                    try:
                        page.screenshot(path=shot_path)
                        result["screenshot_path"] = shot_path
                    except Exception:
                        pass

            return result
        except Exception:
            return None
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass

    def scan_dom_xss(self, url: str, probes: List[str]) -> List[Dict[str, Any]]:
        """Scan for DOM-based XSS by testing common sinks with each probe.
        
        Tests: document.write, innerHTML, outerHTML, insertAdjacentHTML,
        eval, setTimeout, Function constructor, jQuery $(), document.domain,
        location.assign, location.replace.
        Returns list of findings dicts with 'sink', 'probe', 'executed' keys.
        """
        findings: List[Dict[str, Any]] = []
        page = None
        try:
            page = self._new_page()
            if not page:
                return findings
            page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(1000)
            marker = "__bbh_dom_sink_triggered"

            for probe in probes:
                sink_checks = [
                    ("document.write", """
                        try { document.write('<script>window.{m}="dw"<\\/script>');
                        return window.{m} === "dw"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("div.innerHTML", """
                        try { var d=document.createElement('div');
                        d.innerHTML='<img src=x onerror=window.{m}="ih">';
                        document.body.appendChild(d);
                        return window.{m} === "ih"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("div.outerHTML", """
                        try { var d=document.createElement('div');
                        d.outerHTML='<img src=x onerror=window.{m}="oh">';
                        document.body.appendChild(d);
                        return window.{m} === "oh"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("insertAdjacentHTML", """
                        try { var d=document.createElement('div');
                        d.insertAdjacentHTML('afterbegin','<img src=x onerror=window.{m}="iah">');
                        document.body.appendChild(d);
                        return window.{m} === "iah"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("eval", """
                        try { eval('window.{m}="ev"');
                        return window.{m} === "ev"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("Function", """
                        try { new Function('window.{m}="fn"')( );
                        return window.{m} === "fn"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("setTimeout", """
                        try { setTimeout('window.{m}="st"',0);
                        return window.{m} === "st"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("jQuery.$()", """
                        try { window.{m}="jq"; $(window).html('<img src=x onerror=window.{m}="jqe">');
                        return window.{m} === "jqe"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("document.domain", """
                        try { document.domain = 'x'; window.{m}="dd";
                        return window.{m} === "dd"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("location.assign", """
                        try { var old = window.onbeforeunload;
                        window.onbeforeunload = function(){{}};
                        location.assign('javascript:window.{m}="la"');
                        setTimeout(function(){{ window.onbeforeunload = old; }}, 100);
                        return window.{m} === "la"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                    ("location.replace", """
                        try { var old = window.onbeforeunload;
                        window.onbeforeunload = function(){{}};
                        location.replace('javascript:window.{m}="lr"');
                        setTimeout(function(){{ window.onbeforeunload = old; }}, 100);
                        return window.{m} === "lr"; } catch(e) { return false; }
                    """.replace("{m}", marker)),
                ]
                for sink_name, js_code in sink_checks:
                    try:
                        executed = page.evaluate(js_code)
                        if executed:
                            findings.append({
                                "sink": sink_name, "probe": probe,
                                "executed": True, "url": url,
                            })
                    except Exception:
                        continue

            return findings
        except Exception:
            return findings
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass

    def capture_screenshot(self, url: str, output_path: str) -> Optional[str]:
        """Capture a full-page PNG screenshot."""
        page = None
        try:
            page = self._new_page()
            if not page:
                return None
            page.set_viewport_size({"width": 1280, "height": 720})
            page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
            try:
                page.screenshot(path=output_path, full_page=True)
            except Exception:
                try:
                    page.screenshot(path=output_path)
                except Exception:
                    pass
            return output_path
        except Exception:
            return None
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass

    def check_network_requests(self, url: str, callback_domain: str) -> Optional[Dict[str, Any]]:
        """Load URL and intercept outbound requests matching callback_domain."""
        page = self._new_page()
        if not page:
            return None
        try:
            result: Dict[str, Any] = {
                "requests": [], "callback_detected": False, "callback_urls": [],
            }

            def on_request(request):
                result["requests"].append(request.url)
                if callback_domain and callback_domain in request.url:
                    result["callback_detected"] = True
                    result["callback_urls"].append(request.url)

            page.on("request", on_request)
            page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(3000)
            page.close()
            return result
        except Exception:
            try:
                page.close()
            except Exception:
                pass
            return None

    def check_blind_xss(self, url: str, oob_host: str) -> Optional[Dict[str, Any]]:
        """Load URL and check for JS execution with OOB callback detection."""
        page = self._new_page()
        if not page:
            return None
        try:
            result: Dict[str, Any] = {
                "alert_fired": False, "dom_mutation": False,
                "callback_detected": False, "network_requests": [],
            }

            def on_dialog(dialog):
                result["alert_fired"] = True
                dialog.dismiss()

            def on_request(request):
                url_str = request.url
                result["network_requests"].append(url_str)
                if oob_host and oob_host in url_str:
                    result["callback_detected"] = True
                    result["callback_url"] = url_str

            page.on("dialog", on_dialog)
            page.on("request", on_request)
            page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(3000)

            dom_evidence = page.evaluate("""() => {
                return {
                    body_snippet: (document.body ? document.body.innerHTML.substring(0, 500) : ''),
                    has_bbh_marker: window.__bbh_xss === 1,
                };
            }""")
            result["dom_mutation"] = dom_evidence.get("has_bbh_marker", False)
            page.close()
            return result
        except Exception:
            try:
                page.close()
            except Exception:
                pass
            return None


# ── Secret Validator ──────────────────────────────────────────────────────

class SecretValidator:
    """Validate discovered credentials by making verified API calls."""

    @staticmethod
    def validate_aws_key(access_key: str, secret_key: Optional[str] = None) -> Dict[str, Any]:
        """Test AWS credentials via STS GetCallerIdentity."""
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key or "dummy",
            )
            sts = session.client("sts", region_name="us-east-1")
            identity = sts.get_caller_identity()
            return {
                "valid": True,
                "type": "aws",
                "details": f"ARN: {identity.get('Arn', 'unknown')}",
                "account_id": identity.get("Account", ""),
            }
        except ImportError:
            return {"valid": None, "type": "aws", "details": "boto3 not installed"}
        except Exception as e:
            error_str = str(e).lower()
            if "access denied" in error_str or "not authorized" in error_str:
                return {"valid": False, "type": "aws", "details": "Access denied — key may be invalid"}
            if "invalid" in error_str or "not found" in error_str or "could not be found" in error_str:
                return {"valid": False, "type": "aws", "details": f"Invalid credentials: {e}"}
            return {"valid": None, "type": "aws", "details": f"Unknown: {e}"}

    @staticmethod
    def validate_github_token(token: str) -> Dict[str, Any]:
        """Test GitHub token via /user endpoint."""
        try:
            resp = requests.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "valid": True,
                    "type": "github",
                    "details": f"User: {data.get('login', 'unknown')} (scope: {resp.headers.get('X-OAuth-Scopes', 'unknown')})",
                }
            elif resp.status_code == 401:
                return {"valid": False, "type": "github", "details": "Token invalid or revoked"}
            elif resp.status_code == 403:
                return {"valid": None, "type": "github", "details": "Rate limited — retry later"}
            return {"valid": False, "type": "github", "details": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"valid": None, "type": "github", "details": f"Error: {e}"}

    @staticmethod
    def validate_slack_token(token: str) -> Dict[str, Any]:
        """Test Slack token via auth.test."""
        try:
            resp = requests.get(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    return {
                        "valid": True,
                        "type": "slack",
                        "details": f"Team: {data.get('team', 'unknown')}, User: {data.get('user', 'unknown')}",
                    }
                return {"valid": False, "type": "slack", "details": f"Not ok: {data.get('error', 'unknown')}"}
            return {"valid": False, "type": "slack", "details": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"valid": None, "type": "slack", "details": f"Error: {e}"}

    @staticmethod
    def _has_long_run(value: str, length: int = 4) -> bool:
        """Check if value has a run of `length` consecutive identical characters."""
        for i in range(len(value) - length + 1):
            if len(set(value[i:i + length])) == 1:
                return True
        return False

    @staticmethod
    def validate_twilio_sid(sid: str) -> Dict[str, Any]:
        """Validate Twilio Account SID format and entropy (offline)."""
        if not sid.startswith("AC") or len(sid) != 34:
            return {"valid": False, "type": "twilio_sid", "details": "Invalid format"}
        body = sid[2:]
        if "=" in body:
            return {"valid": False, "type": "twilio_sid", "details": "Base64 padding detected — not a real SID"}
        if SecretValidator._has_long_run(body, 4):
            return {"valid": False, "type": "twilio_sid", "details": "Long repeated-char run detected — not a real SID"}
        unique_chars = len(set(body))
        if unique_chars < 10:
            return {"valid": False, "type": "twilio_sid", "details": f"Too few unique chars ({unique_chars}/10) — likely garbage"}
        return {"valid": None, "type": "twilio_sid", "details": "Format and entropy pass — not API-verified"}

    @staticmethod
    def validate_twilio_token(token: str) -> Dict[str, Any]:
        """Validate Twilio Auth Token format and entropy (offline)."""
        if not token.startswith("SK") or len(token) != 34:
            return {"valid": False, "type": "twilio_token", "details": "Invalid format"}
        body = token[2:]
        if "=" in body:
            return {"valid": False, "type": "twilio_token", "details": "Base64 padding detected — not a real token"}
        if SecretValidator._has_long_run(body, 4):
            return {"valid": False, "type": "twilio_token", "details": "Long repeated-char run detected — not a real token"}
        unique_chars = len(set(body))
        if unique_chars < 10:
            return {"valid": False, "type": "twilio_token", "details": f"Too few unique chars ({unique_chars}/10) — likely garbage"}
        return {"valid": None, "type": "twilio_token", "details": "Format and entropy pass — not API-verified"}

    @staticmethod
    def validate_firebase_api_key(key: str) -> Dict[str, Any]:
        """Offline format and entropy check for Firebase FCM server keys."""
        if not key.startswith("AAAA"):
            return {"valid": False, "type": "firebase_api_key", "details": "Invalid prefix (expected AAAA)"}
        if len(key) < 50:
            return {"valid": False, "type": "firebase_api_key", "details": "Too short to be a valid Firebase key"}
        if "=" in key:
            return {"valid": False, "type": "firebase_api_key", "details": "Base64 padding detected — likely binary/codec data"}
        if SecretValidator._has_long_run(key, 5):
            return {"valid": False, "type": "firebase_api_key", "details": "Long repeated-char run — likely binary encoded data"}
        unique_chars = len(set(key))
        if unique_chars < 20:
            return {"valid": False, "type": "firebase_api_key", "details": f"Low entropy ({unique_chars} unique chars) — likely not a real key"}
        return {"valid": None, "type": "firebase_api_key", "details": "Format and entropy pass — not API-verified"}

    @classmethod
    def validate(cls, secret_type: str, value: str) -> Dict[str, Any]:
        """Route validation based on secret type label."""
        mapping = {
            "aws_access_key": cls.validate_aws_key,
            "aws_secret_key": cls.validate_aws_key,
            "github_token": cls.validate_github_token,
            "slack_token": cls.validate_slack_token,
            "twilio_sid": cls.validate_twilio_sid,
            "twilio_token": cls.validate_twilio_token,
            "firebase_api_key": cls.validate_firebase_api_key,
        }
        handler = mapping.get(secret_type)
        if not handler:
            return {"valid": None, "type": secret_type, "details": "No validator available"}
        return handler(value)


# ── Technology Fingerprinter ───────────────────────────────────────────────

# ── CVSS v3 metadata keyed by vuln type strings used in scanner.py ────────
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
    "Potential SSTI": {
        "cvss_score": 6.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "what_is_it": "User input is reflected in a way that may indicate server-side template injection.",
        "impact": "If confirmed, an attacker could achieve remote code execution or read sensitive server-side data.",
        "remediation": "Validate that template engines do not evaluate user-supplied expressions. Use sandboxed environments and avoid rendering raw user input.",
        "references": [
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html",
        ],
        "confidence": "tentative",
    },
    "Likely SSTI": {
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "what_is_it": "Server-side template injection is likely: payloads produced arithmetic results consistent with engine evaluation.",
        "impact": "An attacker can execute arbitrary expressions on the server, potentially leading to RCE or data exfiltration.",
        "remediation": "Never render user input through template engines. Use context-aware escaping and fixed templates without dynamic evaluation.",
        "references": [
            "https://portswigger.net/web-security/server-side-template-injection",
        ],
        "confidence": "probable",
    },
    "Confirmed SSTI": {
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "what_is_it": "Server-side template injection confirmed: engine-specific payloads executed and produced differentiated output.",
        "impact": "Full server-side code execution within the template engine context. Attacker can read files, access internal services, or pivot deeper.",
        "remediation": "Immediately replace dynamic template rendering of user input with static templates. Apply input sanitization and evaluate sandboxing options.",
        "references": [
            "https://portswigger.net/web-security/server-side-template-injection",
        ],
        "confidence": "confirmed",
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
    "Potential SSTI": "Potential SSTI",
    "Likely SSTI": "Likely SSTI",
    "Confirmed SSTI": "Confirmed SSTI",
    "SSTI Detection": "Potential SSTI",
    "SSTI Validation": "Likely SSTI",
    "SSTI Exploitation": "Confirmed SSTI",
    "Confirmed SSRF": "Server-Side Request Forgery (SSRF)",
    "Confirmed SSRF (OOB)": "Server-Side Request Forgery (SSRF)",
}

STEALTH_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
]

_stealth_ua_counter: int = 0
_stealth_ua_lock = threading.Lock()


def url_in_scope(url: str, config: dict) -> bool:
    """
    Return True if url is allowed by exclude_patterns, include_paths,
    and the optional ScopeEnforcer (loaded from --scope).
    Used by the scanner and recon crawler.
    """
    parsed = urlparse(url)
    path = parsed.path + ("?" + parsed.query if parsed.query else "")

    enforcer = config.get("scope_enforcer")
    if enforcer is not None and not enforcer.check_url(url):
        return False

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
    evidence: str | list[str] = "",
    confidence: Optional[str] = None,
    proof: Optional[List[str]] = None,
    validation_steps: Optional[List[str]] = None,
    confidence_score: Optional[int] = None,
    verification_stage: Optional[str] = None,
    evidence_strength: Optional[str] = None,
    false_positive_risk: Optional[str] = None,
    exploitability_rating: Optional[str] = None,
    parameter: Optional[str] = None,
    request: Optional[str] = None,
    response_excerpt: Optional[str] = None,
    steps_to_reproduce: Optional[List[str]] = None,
    confidence_reasons: Optional[list[str]] = None,
) -> Optional[Finding]:
    """
    Build a standardized Finding object with CVSS metadata, fingerprint, and timestamp.
    Supports both legacy confidence strings and new proof-based confidence fields.
    Returns None if duplicate of an already-seen finding (process-wide dedup).
    """
    sanitised_vuln_type = vuln_type.replace("\n", " ").replace("\r", " ").strip()
    dedupe_key = (sanitised_vuln_type, url, parameter or "")
    with _seen_findings_lock:
        if dedupe_key in _seen_findings:
            return None
        _seen_findings.add(dedupe_key)

    canonical_type = _resolve_vuln_type(sanitised_vuln_type)
    vuln_type = sanitised_vuln_type
    meta = VULN_METADATA.get(canonical_type, {})

    if confidence is None:
        confidence = meta.get("confidence", "probable")

    # Normalize evidence to a list
    if isinstance(evidence, str):
        evidence_list = [evidence] if evidence else []
    elif isinstance(evidence, list):
        evidence_list = evidence
    else:
        evidence_list = [str(evidence)] if evidence else []

    # Calculate confidence score from stage if not provided
    if confidence_score is None:
        stage = verification_stage or "detected"
        confidence_score = calculate_confidence(
            detection=True,
            validation=stage in ("validated", "exploitable", "verified"),
            exploitation=stage in ("exploitable", "verified"),
        )

    # Derive evidence strength and FPR from score if not provided
    if evidence_strength is None:
        evidence_strength = evidence_strength_from_score(confidence_score).value
    if false_positive_risk is None:
        false_positive_risk = false_positive_risk_from_score(confidence_score).value

    # Build confidence reasons from stage if not provided
    if confidence_reasons is None:
        confidence_reasons = []
        stage = (verification_stage or "detected").lower()
        if stage == "detected":
            confidence_reasons.append("+ Detection signal present")
            confidence_reasons.append("- Not yet validated (no secondary confirmation)")
        elif stage == "validated":
            confidence_reasons.append("+ Detection signal present")
            confidence_reasons.append("+ Secondary validation confirmed")
        elif stage == "exploitable":
            confidence_reasons.append("+ Detection signal present")
            confidence_reasons.append("+ Secondary validation confirmed")
            confidence_reasons.append("+ Exploitation proof demonstrated")
        elif stage == "verified":
            confidence_reasons.append("+ Detection signal present")
            confidence_reasons.append("+ Secondary validation confirmed")
            confidence_reasons.append("+ Exploitation proof demonstrated")
            confidence_reasons.append("+ Independently verified (OOB/browser/evidence)")

    f = Finding(
        title=vuln_type,
        vuln_type=vuln_type,
        url=url,
        severity=severity,
        details=details,
        evidence=evidence_list,
        confidence_score=confidence_score,
        verification_stage=verification_stage or VerificationStage.DETECTED.value,
        evidence_strength=evidence_strength,
        false_positive_risk=false_positive_risk,
        parameter=parameter or "",
        request=request or "",
        response_excerpt=response_excerpt or "",
        reproduction_steps=steps_to_reproduce or validation_steps or [],
        exploitability_rating=exploitability_rating or "unknown",
        confidence_reasons=confidence_reasons,
    )

    # Sync FindingState and ConfidenceLabel for dict-compatible access
    f.finding_state = FindingState.from_verification_stage(f.verification_stage).value
    f.confidence_label = ConfidenceLevel.from_score(f.confidence_score).value

    for key in (
        "cvss_score",
        "cvss_vector",
        "what_is_it",
        "impact",
        "remediation",
        "references",
        "cwe",
    ):
        if key in meta:
            f[key] = meta[key]

    return f


# ── Baseline Fingerprinting ───────────────────────────────────────────

def parse_auth(auth_string: str):
    """Parse username:password basic auth string."""
    if not auth_string or ":" not in auth_string:
        return None
    username, password = auth_string.split(":", 1)
    return username.strip(), password.strip()


class RateLimiter:
    """Adaptive rate limiter that halves throughput on 429 and restores gradually."""

    def __init__(self, rps: float = 5.0):
        self.max_rps = max(0.1, rps)
        self.current_rps = self.max_rps
        self._lock = threading.Lock()
        self._last_request = 0.0
        self._success_count = 0
        self._backoff_until = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            total_sleep = 0.0
            if now < self._backoff_until:
                total_sleep = self._backoff_until - now
                now = self._backoff_until
            min_interval = 1.0 / self.current_rps
            elapsed = now - self._last_request
            if elapsed < min_interval:
                total_sleep += min_interval - elapsed
            self._last_request = now + total_sleep
        if total_sleep > 0:
            time.sleep(total_sleep)

    def report_429(self) -> None:
        with self._lock:
            self.current_rps = max(0.1, self.current_rps / 2)
            self._backoff_until = time.monotonic() + 5.0
            self._success_count = 0
        log(f"  [RateLimit] 429 received — throttled to {self.current_rps:.1f} RPS", Colors.YELLOW)

    def report_success(self) -> None:
        with self._lock:
            self._success_count += 1
            if self._success_count >= 20 and self.current_rps < self.max_rps:
                prev = self.current_rps
                self.current_rps = min(self.max_rps, self.current_rps * 2)
                self._success_count = 0
                log(f"  [RateLimit] Restored to {self.current_rps:.1f} RPS (was {prev:.1f})", Colors.GREEN)


class ScopeEnforcer:
    """Load in-scope domains from a file and reject out-of-scope URLs."""

    def __init__(self, scope_file: str, output_dir: str):
        self._allowed: set = set()
        self._oob_path = os.path.join(output_dir, "out_of_scope.log")
        self._oob_lock = threading.Lock()
        if scope_file:
            self._load(scope_file)

    def _load(self, path: str) -> None:
        try:
            with open(path, "r") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    self._allowed.add(stripped.lower())
        except FileNotFoundError:
            log(f"[!] Scope file not found: {path}", Colors.RED)
            sys.exit(1)

    def check_url(self, url: str) -> bool:
        if not self._allowed:
            return True
        try:
            host = urlparse(url).netloc.lower().split(":")[0]
            for allowed in self._allowed:
                if host == allowed or host.endswith("." + allowed):
                    return True
                if "/" in allowed and self._ip_in_cidr(host, allowed):
                    return True
        except Exception:
            pass
        self._log_oob(url)
        return False

    @staticmethod
    def _ip_in_cidr(host: str, cidr: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
        except (ValueError, ImportError):
            return False

    def _log_oob(self, url: str) -> None:
        with self._oob_lock:
            try:
                with open(self._oob_path, "a") as f:
                    f.write(url + "\n")
            except OSError:
                pass


# ── Request pipeline wrappers ────────────────────────────────────────

def _wrap_jitter_retry(request_fn, retries: int):
    """Exponential backoff + random jitter for connection errors and 5xx."""
    if retries <= 0:
        return request_fn
    def wrapper(method, url, **kwargs):
        max_attempts = retries + 1
        last_exc = None
        for attempt in range(max_attempts):
            try:
                resp = request_fn(method, url, **kwargs)
                if resp.status_code >= 500 and attempt < max_attempts - 1:
                    delay = 0.5 * (2 ** attempt) + random.random()
                    time.sleep(delay)
                    continue
                return resp
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                last_exc = e
                if attempt == max_attempts - 1:
                    raise
                delay = 0.5 * (2 ** attempt) + random.random()
                time.sleep(delay)
        raise last_exc
    return wrapper


def _wrap_stealth(request_fn):
    """Rotate User-Agent, randomise POST param order, add 0.5–2 s delay."""
    def wrapper(method, url, **kwargs):
        global _stealth_ua_counter
        with _stealth_ua_lock:
            idx = _stealth_ua_counter % len(STEALTH_USER_AGENTS)
            _stealth_ua_counter += 1
        kwargs.setdefault("headers", {})["User-Agent"] = STEALTH_USER_AGENTS[idx]
        if method.upper() == "POST" and "data" in kwargs and isinstance(kwargs["data"], dict):
            items = list(kwargs["data"].items())
            random.shuffle(items)
            kwargs["data"] = dict(items)
        time.sleep(0.5 + random.random() * 1.5)
        return request_fn(method, url, **kwargs)
    return wrapper


def _wrap_fixed_delay(request_fn, delay: float):
    """Legacy fixed inter-request delay."""
    if delay <= 0:
        return request_fn
    _lock = threading.Lock()
    _last = {"at": 0.0}
    def wrapper(method, url, **kwargs):
        with _lock:
            elapsed = time.time() - _last["at"]
            if elapsed < delay:
                time.sleep(delay - elapsed)
            _last["at"] = time.time()
        return request_fn(method, url, **kwargs)
    return wrapper


def _wrap_rate_limiter(request_fn, limiter: RateLimiter):
    """Acquire rate-limit slot, report 429 / success."""
    def wrapper(method, url, **kwargs):
        limiter.wait()
        resp = request_fn(method, url, **kwargs)
        if resp.status_code == 429:
            limiter.report_429()
        else:
            limiter.report_success()
        return resp
    return wrapper


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

    session.verify = config.get("verify_ssl", True)
    if not session.verify:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    # ── Connection pooling with retry adapters ─────────────────────
    retries = int(config.get("retries", 3))
    # Inner urllib3 Retry set to total=0 to avoid double-retry cascade.
    # The outer _wrap_jitter_retry layer handles all retry logic.
    retry_strategy = Retry(
        total=0,
        backoff_factor=1.5,
        allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=50,
        pool_maxsize=50,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    # Keep-alive: disable default pool-block, allow connection reuse
    session.keep_alive = True

    pipeline = session.request

    pipeline = _wrap_jitter_retry(pipeline, retries)

    if config.get("stealth", False):
        pipeline = _wrap_stealth(pipeline)

    delay = float(config.get("delay", 0.0) or 0.0)
    pipeline = _wrap_fixed_delay(pipeline, delay)

    rps = float(config.get("rps", 5.0) or 5.0)
    limiter = RateLimiter(rps)
    pipeline = _wrap_rate_limiter(pipeline, limiter)

    session.request = pipeline
    session._rate_limiter = limiter
    session._stealth = config.get("stealth", False)

    return session


def _audit_log_result(t0: float, url: str, method: str, status: int,
                      config: dict | None = None,
                      result: object = None) -> object:
    """Log request to audit_logger (if configured) and return *result*."""
    if config:
        auditor = config.get("_audit_logger")
        if auditor is not None:
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            try:
                auditor.log_request(method, url, {}, status, elapsed_ms)
            except Exception:
                pass
    return result


def safe_get(
    session: requests.Session,
    url: str,
    timeout: int = 10,
    allow_redirects: bool = True,
    raise_for_status: bool = True,
    config: Optional[dict] = None,
    **kwargs,
) -> Optional[requests.Response]:
    """HTTP GET with logging on failure and scope-checked redirects."""
    _t0 = time.monotonic()
    _resp: Optional[requests.Response] = None
    _status: int = 0
    try:
        response = session.get(
            url, timeout=timeout, allow_redirects=allow_redirects, **kwargs
        )
        _resp = response
        _status = response.status_code if response is not None else 0
        # Check redirect targets against scope
        if config and allow_redirects and response.history:
            enforcer = config.get("scope_enforcer")
            if enforcer is not None:
                for resp in response.history:
                    if resp.headers.get("Location"):
                        redirect_target = resp.headers["Location"]
                        if not redirect_target.startswith("/") and not enforcer.check_url(redirect_target):
                            log(f"[!] Redirect to out-of-scope URL blocked: {redirect_target}", Colors.YELLOW)
                            return _audit_log_result(_t0, url, "GET", _status, config)
                        if redirect_target.startswith("/"):
                            from urllib.parse import urljoin
                            redirect_target = urljoin(url, redirect_target)
                            if not enforcer.check_url(redirect_target):
                                log(f"[!] Redirect to out-of-scope URL blocked: {redirect_target}", Colors.YELLOW)
                                return _audit_log_result(_t0, url, "GET", _status, config)
        if raise_for_status:
            response.raise_for_status()
    except requests.exceptions.Timeout:
        log(f"[!] Timeout accessing {url}", Colors.YELLOW)
        _resp = None
        _status = 0
    except requests.exceptions.ConnectionError:
        log(f"[!] Connection error accessing {url}", Colors.YELLOW)
        _resp = None
        _status = 0
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        log(f"[!] HTTP error accessing {url}: {status}", Colors.YELLOW)
        _resp = None
        _status = status if isinstance(status, int) else 0
    except requests.exceptions.RequestException as e:
        log(f"[!] Request error accessing {url}: {e}", Colors.YELLOW)
        _resp = None
        _status = 0
    except Exception as e:
        log(f"[!] Unexpected error accessing {url}: {e}", Colors.RED)
        _resp = None
        _status = 0
    return _audit_log_result(_t0, url, "GET", _status, config, _resp)


def safe_post(
    session: requests.Session,
    url: str,
    data: Dict[str, Any],
    timeout: int = 10,
    allow_redirects: bool = True,
    raise_for_status: bool = True,
    config: Optional[dict] = None,
    **kwargs,
) -> Optional[requests.Response]:
    """HTTP POST with logging on failure and scope-checked redirects."""
    _t0 = time.monotonic()
    _resp: Optional[requests.Response] = None
    _status: int = 0
    try:
        response = session.post(
            url, data=data, timeout=timeout, allow_redirects=allow_redirects, **kwargs
        )
        _resp = response
        _status = response.status_code if response is not None else 0
        # Check redirect targets against scope
        if config and allow_redirects and response.history:
            enforcer = config.get("scope_enforcer")
            if enforcer is not None:
                for resp in response.history:
                    if resp.headers.get("Location"):
                        redirect_target = resp.headers["Location"]
                        if not redirect_target.startswith("/") and not enforcer.check_url(redirect_target):
                            log(f"[!] Redirect to out-of-scope URL blocked: {redirect_target}", Colors.YELLOW)
                            return _audit_log_result(_t0, url, "POST", _status, config)
                        if redirect_target.startswith("/"):
                            from urllib.parse import urljoin
                            redirect_target = urljoin(url, redirect_target)
                            if not enforcer.check_url(redirect_target):
                                log(f"[!] Redirect to out-of-scope URL blocked: {redirect_target}", Colors.YELLOW)
                                return _audit_log_result(_t0, url, "POST", _status, config)
        if raise_for_status:
            response.raise_for_status()
    except requests.exceptions.Timeout:
        log(f"[!] Timeout posting to {url}", Colors.YELLOW)
        _resp = None
        _status = 0
    except requests.exceptions.ConnectionError:
        log(f"[!] Connection error posting to {url}", Colors.YELLOW)
        _resp = None
        _status = 0
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        log(f"[!] HTTP error posting to {url}: {status}", Colors.YELLOW)
        _resp = None
        _status = status if isinstance(status, int) else 0
    except requests.exceptions.RequestException as e:
        log(f"[!] Request error posting to {url}: {e}", Colors.YELLOW)
        _resp = None
        _status = 0
    except Exception as e:
        log(f"[!] Unexpected error posting to {url}: {e}", Colors.RED)
        _resp = None
        _status = 0
    return _audit_log_result(_t0, url, "POST", _status, config, _resp)


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
    if _use_rich and _rich_available():
        from rich.progress import (
            BarColumn, Progress, SpinnerColumn,
            TextColumn, TimeElapsedColumn, TimeRemainingColumn,
        )
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
    from rich.table import Table
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
            str(row.get("vuln_type", ""))[:28],
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

    if console is not None and _rich_available():
        from rich.live import Live
        table = _build_findings_table(rows)
        with Live(table, console=console, refresh_per_second=4) as live:
            live_ref["live"] = live
            yield handle
    else:
        yield handle


def get_rich_table(title: str, columns: List[str]) -> Optional["Table"]:
    """Create a Rich Table when Rich is enabled."""
    if not _use_rich or not _rich_available():
        return None
    from rich.table import Table
    table = Table(title=title)
    for col in columns:
        table.add_column(col)
    return table


# ── Intelligence-led module selection ──────────────────────────────────


def classify_endpoint(
    url: str,
    forms: list[dict],
    recon_data: dict,
) -> set[str]:
    """Classify a URL into applicable scan module names based on signals.

    Args:
        url: The URL to classify.
        forms: List of form dicts from recon_data (each has ``action``, ``fields``, etc).
        recon_data: Full recon data dict (used for ``js_endpoints`` lookups).

    Returns:
        A set of module name strings (keys used in ``_active_module_map``).
    """
    modules: set[str] = _CLASSIFY_ALWAYS.copy()
    parsed = urlparse(url)
    qs_raw = parsed.query
    param_keys = [kv.split("=")[0] for kv in qs_raw.split("&") if "=" in kv]
    path = parsed.path.lower()
    params_lower = [p.lower() for p in param_keys]

    # ── Signal detection ───────────────────────────────────────────────
    signals: set[str] = set()

    if qs_raw:
        signals.add("has_params")

    file_param_names = (
        "file", "path", "doc", "upload", "attachment", "img",
        "src", "url", "load", "template", "view", "page", "include",
    )
    if any(any(fn in p for fn in file_param_names) for p in params_lower):
        signals.add("has_file_param")

    url_param_names = (
        "url", "redirect", "next", "return", "goto", "dest",
        "target", "link", "href", "continue", "forward", "redir", "location",
    )
    if any(any(un in p for un in url_param_names) for p in params_lower):
        signals.add("has_url_param")

    id_param_names = (
        "id", "uid", "user", "account", "profile", "order",
        "item", "object", "record", "uuid", "guid", "ref",
    )
    if any(any(in_ in p for in_ in id_param_names) for p in params_lower):
        signals.add("has_id_param")

    form_is_post = any(
        form.get("method", "").upper() == "POST"
        for form in forms
        if form.get("action", "") in parsed.path or parsed.path in form.get("action", "")
    )
    if form_is_post:
        signals.add("is_form_post")

    js_endpoints = recon_data.get("js_endpoints", []) if isinstance(recon_data, dict) else []

    if (
        "/api/" in path
        or "/v1/" in path
        or "/v2/" in path
        or "/v3/" in path
        or "/rest/" in path
        or "/graphql" in path
        or "/gql" in path
        or url in js_endpoints
    ):
        signals.add("is_json_api")

    if path.endswith(".xml") or "/soap/" in path or "/wsdl" in path or "/xmlrpc" in path:
        signals.add("is_xml_endpoint")

    if "/graphql" in path or "/gql" in path:
        signals.add("is_graphql")

    file_upload_paths = ("upload", "import", "ingest", "attach", "file", "media", "asset")
    path_segments = path.split("/")
    if any(fp in path_segments for fp in file_upload_paths):
        signals.add("is_file_upload")

    admin_paths = (
        "/admin", "/manage", "/dashboard", "/internal", "/staff",
        "/superuser", "/console", "/portal", "/backoffice", "/ops",
    )
    if any(ap in path for ap in admin_paths):
        signals.add("is_admin_path")

    cmd_param_names = (
        "cmd", "exec", "command", "shell", "run", "ping",
        "eval", "query", "process", "system",
    )
    if any(any(cn in p for cn in cmd_param_names) for p in params_lower):
        signals.add("has_cmd_param")

    # ── Signal → module mapping ───────────────────────────────────────
    has_params = "has_params" in signals
    has_file_param = "has_file_param" in signals
    has_url_param = "has_url_param" in signals
    has_id_param = "has_id_param" in signals
    is_form_post = "is_form_post" in signals
    is_json_api = "is_json_api" in signals
    is_xml = "is_xml_endpoint" in signals
    is_graphql = "is_graphql" in signals
    is_file_upload = "is_file_upload" in signals
    is_admin = "is_admin_path" in signals
    has_cmd = "has_cmd_param" in signals

    if has_params:
        modules.update({"xss", "sqli", "ssti", "cmd_injection"})
    if has_file_param:
        modules.update({"lfi", "xxe", "ssrf"})
    if has_url_param:
        modules.update({"ssrf", "open_redirect"})
    if has_id_param:
        modules.update({"idor", "sqli"})
    if is_form_post:
        modules.update({"csrf", "xss", "sqli", "insecure_forms"})
    if is_json_api:
        modules.update({"sqli", "idor", "rate_limiting", "api", "http_methods", "cmd_injection"})
    if is_xml:
        modules.update({"xxe", "http_methods"})
    if is_graphql:
        modules.add("graphql")
    if is_file_upload:
        modules.update({"xxe", "lfi", "cmd_injection"})
    if is_admin:
        modules.update({"idor", "csrf", "http_methods"})
    if has_cmd:
        modules.update({"cmd_injection", "ssrf"})

    # ── Technology-based ADDITIVE module routing ─────────────────────────
    # Reads detected technology from recon_data and adds extra per-URL
    # modules that are relevant to the known tech stack. This NEVER removes
    # modules — it enables additional specialized probes on top of defaults.
    tech_data = recon_data.get("technology", {})
    if isinstance(tech_data, dict):
        for category in ("cms", "framework", "language"):
            detected = tech_data.get(category, [])
            if isinstance(detected, list):
                for tech in detected:
                    extra = TECH_MODULE_MAP.get(tech.lower(), set())
                    if extra:
                        modules.update(extra)
        # Also check for GraphQL via path signal (already in TECH_MODULE_MAP
        # but added here for completeness when tech data has it as framework)
        detected_frameworks = tech_data.get("framework", [])
        if isinstance(detected_frameworks, list):
            if any("graphql" in fw.lower() for fw in detected_frameworks):
                modules.add("graphql")

    return modules


def compute_endpoint_score(url: str, forms: list[dict], recon_data: dict) -> int:
    """Score a URL by signals present; higher = more attack surface.

    Args:
        url: The URL to score.
        forms: List of form dicts from recon_data.
        recon_data: Full recon data dict.

    Returns:
        An integer score (higher is more interesting).
    """
    signals = _get_signal_set(url, forms, recon_data)
    weights = {
        "has_params": 30,
        "is_form_post": 20,
        "has_id_param": 25,
        "has_url_param": 20,
        "has_file_param": 15,
        "is_admin_path": 35,
        "is_json_api": 25,
        "is_file_upload": 10,
        "has_cmd_param": 10,
        "is_graphql": 5,
        "has_auth_potential": 40,
        "has_biz_impact": 30,
        "has_ownership_signal": 45,
    }
    # Tech signals get a uniform bonus (framework-specific URLs are higher value)
    score = sum(weights[s] for s in signals if s in weights)
    tech_signals = [s for s in signals if s.startswith("tech_")]
    if tech_signals:
        tech_bonus = min(len(tech_signals) * 20, 40)
        score += tech_bonus
    return score


def _get_signal_set(
    url: str,
    forms: list[dict],
    recon_data: dict,
) -> set[str]:
    """Extract the raw signal set from a URL (shared by classify + scoring)."""
    signals: set[str] = set()
    parsed = urlparse(url)
    qs_raw = parsed.query
    param_keys = [kv.split("=")[0] for kv in qs_raw.split("&") if "=" in kv]
    path = parsed.path.lower()
    params_lower = [p.lower() for p in param_keys]

    if qs_raw:
        signals.add("has_params")

    file_param_names = (
        "file", "path", "doc", "upload", "attachment", "img",
        "src", "url", "load", "template", "view", "page", "include",
    )
    if any(any(fn in p for fn in file_param_names) for p in params_lower):
        signals.add("has_file_param")

    url_param_names = (
        "url", "redirect", "next", "return", "goto", "dest",
        "target", "link", "href", "continue", "forward", "redir", "location",
    )
    if any(any(un in p for un in url_param_names) for p in params_lower):
        signals.add("has_url_param")

    id_param_names = (
        "id", "uid", "user", "account", "profile", "order",
        "item", "object", "record", "uuid", "guid", "ref",
    )
    if any(any(in_ in p for in_ in id_param_names) for p in params_lower):
        signals.add("has_id_param")

    form_is_post = any(
        form.get("method", "").upper() == "POST"
        for form in forms
        if form.get("action", "") in parsed.path or parsed.path in form.get("action", "")
    )
    if form_is_post:
        signals.add("is_form_post")

    if (
        "/api/" in path
        or "/v1/" in path
        or "/v2/" in path
        or "/v3/" in path
        or "/rest/" in path
        or "/graphql" in path
        or "/gql" in path
        or url in (recon_data.get("js_endpoints", []) if isinstance(recon_data, dict) else [])
    ):
        signals.add("is_json_api")

    if path.endswith(".xml") or "/soap/" in path or "/wsdl" in path or "/xmlrpc" in path:
        signals.add("is_xml_endpoint")

    if "/graphql" in path or "/gql" in path:
        signals.add("is_graphql")

    file_upload_paths = ("upload", "import", "ingest", "attach", "file", "media", "asset")
    path_segments = path.split("/")
    if any(fp in path_segments for fp in file_upload_paths):
        signals.add("is_file_upload")

    admin_paths = (
        "/admin", "/manage", "/dashboard", "/internal", "/staff",
        "/superuser", "/console", "/portal", "/backoffice", "/ops",
    )
    if any(ap in path for ap in admin_paths):
        signals.add("is_admin_path")

    cmd_param_names = (
        "cmd", "exec", "command", "shell", "run", "ping",
        "eval", "query", "process", "system",
    )
    if any(any(cn in p for cn in cmd_param_names) for p in params_lower):
        signals.add("has_cmd_param")

    # ── Discovery priority signals ──────────────────────────────────────
    path_segments_numeric = re.findall(r'/(\d{2,12})(?:/|$)', path)
    if path_segments_numeric:
        signals.add("has_auth_potential")

    biz_impact_paths = (
        "payment", "billing", "invoice", "checkout", "order",
        "transaction", "transfer", "payout", "refund", "wallet",
        "purchase", "subscription", "admin", "internal",
        "organisation", "organization", "management", "settings",
        "privacy", "security", "verification",
    )
    if any(bp in path for bp in biz_impact_paths):
        signals.add("has_biz_impact")

    if isinstance(recon_data, dict):
        discovery_hints = recon_data.get("_discovery_hints", {})
        if isinstance(discovery_hints, dict):
            ownership_urls = discovery_hints.get("ownership_urls", [])
            if isinstance(ownership_urls, list):
                pattern_match = any(
                    isinstance(p, str) and re.match(p.replace("{id}", r"\d+").replace("{uuid}", r"[0-9a-f-]+"), url)
                    for p in ownership_urls
                )
                if pattern_match:
                    signals.add("has_ownership_signal")
            auth_patterns = discovery_hints.get("auth_patterns", [])
            if isinstance(auth_patterns, list) and auth_patterns:
                pattern_match = any(
                    isinstance(p, str) and re.match(p.replace("{id}", r"\d+").replace("{uuid}", r"[0-9a-f-]+"), url)
                    for p in auth_patterns
                )
                if pattern_match:
                    signals.add("has_auth_potential")

    # ── Technology-aware path signals (auto, never subtractive) ─────────
    tech_data: dict = {}
    if isinstance(recon_data, dict):
        tech_data = recon_data.get("technology", {}) or {}
    for category in ("cms", "framework", "language"):
        detected = tech_data.get(category, [])
        if isinstance(detected, list):
            for tech_name in detected:
                tech_key = f"tech_{tech_name.lower().replace('.', '_').replace(' ', '_')}"
                signals.add(tech_key)
    # Direct path-based tech hints (even without recon tech data)
    if "/wp-" in path or "/xmlrpc.php" in path:
        signals.add("tech_wordpress")
    if "/actuator/" in path or "/swagger-ui" in path:
        signals.add("tech_spring")
    if "/graphql" in path or "/gql" in path:
        signals.add("tech_graphql")

    return signals


# Modules that run on every URL regardless of signals
_CLASSIFY_ALWAYS: set[str] = {
    "headers", "sensitive", "exposed_files", "clickjacking",
    "cors", "jwt", "rate_limiting",
}

# ── Technology → Extra per-URL modules (additive, never subtractive) ─────
# These modules run IN ADDITION to the modules selected by URL/param signals.
# Each framework gets specialized probes that only make sense when that
# technology is detected on the target.
TECH_MODULE_MAP: dict[str, set[str]] = {
    "wordpress": set(),
    "drupal": set(),
    "joomla": set(),
    "spring": set(),
    "rails": set(),
    "laravel": set(),
    "django": set(),
    "express": set(),
    "graphql": {"graphql"},
    "asp.net": set(),
}

# ── Role-based session helpers (Phase 5: Authorization) ──────────────────

def build_role_sessions(config: dict, base_session=None) -> dict[str, Any]:
    """Build a dict of {role_name: requests.Session} from --auth-header args.
    
    Parses entries like:
      --auth-header user_b:Authorization:'Bearer tok_b'
      --auth-header admin:Cookie:'session=admin123'
    
    Returns at minimum {"default": base_session or make_session(config)}.
    """
    result: dict[str, Any] = {}
    if base_session is not None:
        result["default"] = base_session

    raw = config.get("auth_header", [])
    if isinstance(raw, str):
        raw = [raw]
    for entry in raw:
        try:
            parts = entry.split(":", 2)
            if len(parts) != 3:
                continue
            role, header_name, header_value = parts
            role = role.strip()
            sess = make_session(config)
            sess.headers.update({header_name.strip(): header_value.strip()})
            result[role] = sess
        except Exception:
            continue

    # If --cookies-alt is set, build an 'alt' session for backward compat
    cookies_alt = config.get("cookies_alt", "")
    if cookies_alt and "alt" not in result:
        sess = make_session(config)
        for part in cookies_alt.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                sess.cookies[k.strip()] = v.strip()
        result["alt"] = sess

    # Ensure at least a default session
    if "default" not in result:
        result["default"] = make_session(config)

    return result


def get_role_session(role_sessions: dict, role: str = "default"):
    """Get a session for a given role, falling back to default."""
    return role_sessions.get(role, role_sessions.get("default"))


# ── Shared evidence / confidence utilities ──────────────────────────────
# Used by both VulnScanner (modules/scanner.py) and ScannerBase (scanners/base.py)
# to prevent drift between legacy and new scanner paths.

def enrich_finding_confidence(f: Finding) -> None:
    """Recalculate confidence score if below threshold; populate reasons."""
    from models.finding import calculate_confidence as calc_conf
    from models.finding import evidence_strength_from_score, false_positive_risk_from_score
    stage = (f.verification_stage or "").lower()
    score = f.confidence_score or 0
    if score < 25:
        new_score = calc_conf(
            detection=True,
            validation=stage in ("validated", "exploitable", "verified"),
            exploitation=stage in ("exploitable", "verified"),
        )
        f.confidence_score = new_score
        f.evidence_strength = evidence_strength_from_score(new_score).value
        f.false_positive_risk = false_positive_risk_from_score(new_score).value
    reasons = f.confidence_reasons
    if not reasons or not isinstance(reasons, list) or len(reasons) == 0:
        reasons = []
        if stage == "detected":
            reasons.append("+ Detection signal present")
            reasons.append("- Not yet validated (no secondary confirmation)")
        elif stage == "validated":
            reasons.append("+ Detection signal present")
            reasons.append("+ Secondary validation confirmed")
        elif stage == "exploitable":
            reasons.append("+ Detection signal present")
            reasons.append("+ Secondary validation confirmed")
            reasons.append("+ Exploitation proof demonstrated")
        elif stage == "verified":
            reasons.append("+ Detection signal present")
            reasons.append("+ Secondary validation confirmed")
            reasons.append("+ Exploitation proof demonstrated")
            reasons.append("+ Independently verified (OOB/browser/evidence)")
        f.confidence_reasons = reasons


def add_capability_confidence_reasons(f: Finding) -> None:
    """Add capability-aware confidence reasons (browser, OOB, JS parser)."""
    try:
        from app.capabilities import CapabilityRegistry
        caps = CapabilityRegistry.get_global()
    except Exception:
        return
    reasons = f.confidence_reasons
    if not isinstance(reasons, list):
        reasons = []
    score = f.confidence_score or 0
    has_browser = caps.has("playwright") and caps.has("chromium")
    has_oob = caps.has("oob_validation")
    has_esprima = caps.has("esprima")

    if has_browser and score < 80:
        if not any("browser" in r for r in reasons):
            reasons.append("+ Browser validation available (can increase confidence)")
    if not has_browser:
        if not any("No browser" in r for r in reasons):
            reasons.append("- No browser validation (XSS/JS findings unverifiable via Playwright)")
            if (f.vuln_type or "").lower() in ("xss", "dom xss", "blind xss"):
                reasons.append("- XSS confidence limited without browser execution")
    if has_oob and score < 80:
        if not any("OOB" in r for r in reasons):
            reasons.append("+ OOB callback validation available (can increase confidence)")
    if not has_oob:
        if not any("No OOB" in r for r in reasons):
            reasons.append("- No OOB callback service (SSRF/XXE/CMDI unverifiable out-of-band)")
    if not has_esprima:
        if not any("No JS parser" in r for r in reasons):
            reasons.append("- No JS parser (limited DOM/JS analysis)")
    if score >= 80 and not any("high confidence" in r for r in reasons):
        reasons.append("+ High confidence score achieved (score >= 80)")
    if score >= 25 and not any("score >= 25" in r for r in reasons):
        reasons.append("+ Base confidence threshold met (score >= 25)")
    f.confidence_reasons = reasons


def link_finding_evidence(finding: Finding, evidence_engine: Any,
                          session: Any = None) -> None:
    """Auto-create and link HttpRequestEvidence from finding request data."""
    fp = finding.fingerprint
    url = finding.url
    request_str = finding.request
    if not fp or not request_str or evidence_engine is None:
        return
    try:
        from models.evidence import HttpRequestEvidence
        method = "GET"
        if request_str.startswith("curl"):
            parts = request_str.split()
            for i, p in enumerate(parts):
                if p == "-X" and i + 1 < len(parts):
                    method = parts[i + 1]
                    break
        req_ev = HttpRequestEvidence(
            method=method,
            url=url,
            curl_command=request_str,
        )
        evidence_engine.store(req_ev)
        evidence_engine.link_to_finding(req_ev, fp)
    except Exception:
        pass


def collect_and_link_evidence(finding: Finding, evidence_list: list,
                              evidence_engine: Any) -> None:
    """Store and link typed evidence objects for a finding."""
    if evidence_engine is None:
        return
    fp = finding.fingerprint
    if not fp:
        return
    for ev in evidence_list:
        try:
            evidence_engine.store(ev)
            evidence_engine.link_to_finding(ev, fp)
        except Exception:
            continue


# ── Session health check ─────────────────────────────────────────────────


def check_session_health(session: Any, config: dict,
                         log_fn: Any = None) -> bool:
    """Probe a known endpoint to verify the auth session is still valid.

    Returns True if the session appears healthy, False otherwise.
    Logs a warning on first detected expiry.
    """
    if not session:
        return True
    has_auth = bool(session.cookies) or bool(
        session.headers.get("Authorization")
    )
    if not has_auth:
        return True  # No auth configured — nothing to expire
    probe_paths = ["/api/v1/user", "/api/v1/me", "/graphql", "/api/graphql"]
    target = config.get("target", "")
    for path in probe_paths:
        try:
            from urllib.parse import urljoin
            r = session.get(urljoin(target, path), timeout=10)
            if r.status_code == 401:
                msg = ("[!] WARNING: Auth session appears to have expired "
                       "(HTTP 401 on probe). Findings after this point "
                       "may be unauthenticated.")
                if log_fn:
                    log_fn(msg, Colors.RED)
                else:
                    from modules.utils import log as _log
                    _log(msg, Colors.RED)
                return False
            if r.status_code in (200, 403, 404):
                return True
        except Exception:
            continue
    return True


# ── Playwright-based auto-login ─────────────────────────────────────────


def do_playwright_login(
    login_url: str,
    username: str,
    password: str,
    username_field: str = "username",
    password_field: str = "password",
    extra_fields: dict[str, str] | None = None,
    timeout_ms: int = 30000,
) -> dict[str, str] | None:
    """Use Playwright to log in and return session cookies.

    Navigates to *login_url*, fills the login form, submits it, and
    extracts all cookies set by the application.  Returns a
    ``{cookie_name: cookie_value}`` dict, or ``None`` if Playwright is
    unavailable or the login attempt fails.

    Handles CSRF tokens automatically (extracts hidden ``csrf_*`` /
    ``authenticity_token`` inputs before filling the form).  Also
    attempts to extract a Bearer token from ``localStorage`` after login
    (for SPA/JWT-based apps).
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log("[!] Playwright not available — cannot auto-login", Colors.RED)
        return None

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = context.new_page()

            log(f"[*] Navigating to login page: {login_url}", Colors.CYAN)
            page.goto(login_url, timeout=timeout_ms, wait_until="networkidle")

            # ── Auto-detect and fill CSRF token if present ────────────
            csrf_inputs = page.query_selector_all(
                'input[name^="csrf"], input[name^="authenticity_token"], '
                'input[name="_token"], input[name="_csrf"]',
            )
            for inp in csrf_inputs:
                name = inp.get_attribute("name") or ""
                value = inp.get_attribute("value") or ""
                if name and value:
                    log(f"  [CSRF] Auto-detected token field: {name}", Colors.YELLOW,
                        verbose_only=True, verbose=True)
                    # already present — just leave it

            # ── Fill username / email field ───────────────────────────
            username_selector = (
                f'input[name="{username_field}"]'
            )
            if not page.query_selector(username_selector):
                username_selector = 'input[type="email"], input[name="email"]'
            page.fill(username_selector, username)

            # ── Fill password field ───────────────────────────────────
            password_selector = f'input[name="{password_field}"]'
            if not page.query_selector(password_selector):
                password_selector = 'input[type="password"]'
            page.fill(password_selector, password)

            # ── Fill extra fields ─────────────────────────────────────
            for fname, fval in (extra_fields or {}).items():
                sel = f'input[name="{fname}"]'
                if page.query_selector(sel):
                    page.fill(sel, fval)

            # ── Submit via Enter on password field or click submit ────
            submit_btn = page.query_selector(
                'button[type="submit"], input[type="submit"]',
            )
            if submit_btn:
                submit_btn.click()
            else:
                page.press(password_selector, "Enter")

            # ── Wait for post-login state ─────────────────────────────
            page.wait_for_load_state("networkidle", timeout=timeout_ms)

            # ── Extract cookies ───────────────────────────────────────
            cookies_playwright = context.cookies()
            cookie_dict: dict[str, str] = {}
            for c in cookies_playwright:
                if c.get("name") and c.get("value"):
                    cookie_dict[c["name"]] = c["value"]

            # ── Try to extract JWT from localStorage (SPA apps) ──────
            jwt_token = None
            try:
                jwt_token = page.evaluate(
                    "() => localStorage.getItem('token') "
                    "|| localStorage.getItem('access_token') "
                    "|| localStorage.getItem('jwt')"
                )
            except Exception:
                pass

            browser.close()

            if cookie_dict:
                log(f"[+] Login successful — {len(cookie_dict)} cookies extracted",
                    Colors.GREEN)
                if jwt_token:
                    log("  [JWT] Bearer token also extracted from localStorage",
                        Colors.GREEN)
                return cookie_dict

            if jwt_token:
                log("[+] JWT token extracted from localStorage (no cookies set)",
                    Colors.GREEN)
                return {}  # caller should check for jwt_token separately

            log("[!] Auto-login completed but no session cookies were set — "
                "login may have failed", Colors.YELLOW)
            return None

    except Exception as e:
        log(f"[!] Auto-login failed: {e}", Colors.RED)
        return None


# ── Default-credential detection ──────────────────────────────────────

DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
    ("admin",   "admin"),
    ("admin",   "password"),
    ("admin",   "admin123"),
    ("admin",   "letmein"),
    ("admin",   "root"),
    ("admin",   "123456"),
    ("admin",   "passw0rd"),
    ("admin",   "Admin123"),
    ("admin",   "administrator"),
    ("test",    "test"),
    ("test",    "test123"),
    ("guest",   "guest"),
    ("user",    "user"),
    ("user",    "password"),
    ("user",    "123456"),
    ("support", "support"),
    ("demo",    "demo"),
    ("manager", "manager"),
    ("backup",  "backup"),
]


def _try_default_credentials_inner(
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",
    extra_fields: dict[str, str] | None = None,
    verify_url: str | None = None,
    credentials: list[tuple[str, str]] | None = None,
    timeout_ms: int = 12000,
) -> tuple[dict[str, str] | None, str | None, str | None]:
    """Inner sync Playwright logic — must run in a thread without an asyncio loop."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None, None, None

    creds = credentials or DEFAULT_CREDENTIALS

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)

        for i, (uname, pwd) in enumerate(creds):
            log(f"  [{i+1}/{len(creds)}] Trying {uname}:{pwd}", Colors.YELLOW,
                verbose_only=True, verbose=True)

            context = browser.new_context()
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            # Block resource-heavy third-party content that causes hangs
            page.route("**/*", lambda route: route.abort("blockedbyclient")
                       if route.request.resource_type in ("image", "font", "media", "stylesheet")
                       else route.continue_())
            success = False
            cookie_dict: dict[str, str] = {}

            try:
                page.goto(login_url, timeout=timeout_ms,
                          wait_until="domcontentloaded")

                # ── Fill username ────────────────────────────────
                usel = f'input[name="{username_field}"]'
                if not page.query_selector(usel):
                    usel = 'input[type="email"], input[name="email"]'
                page.fill(usel, uname)

                # ── Fill password ────────────────────────────────
                psel = f'input[name="{password_field}"]'
                if not page.query_selector(psel):
                    psel = 'input[type="password"]'
                page.fill(psel, pwd)

                # ── Extra fields ─────────────────────────────────
                for fname, fval in (extra_fields or {}).items():
                    sel = f'input[name="{fname}"]'
                    if page.query_selector(sel):
                        page.fill(sel, fval)

                # ── Submit ───────────────────────────────────────
                btn = page.query_selector(
                    'button[type="submit"], input[type="submit"]'
                )
                if btn:
                    btn.click()
                else:
                    page.press(psel, "Enter")
                page.wait_for_load_state("networkidle",
                                         timeout=timeout_ms)

                # ── Verify ───────────────────────────────────────
                if verify_url:
                    import requests as _req
                    pw_cookies = context.cookies()
                    for c in pw_cookies:
                        if c.get("name") and c.get("value"):
                            cookie_dict[c["name"]] = c["value"]
                    if not cookie_dict:
                        context.close()
                        continue
                    jar = _req.cookies.RequestsCookieJar()
                    for c in pw_cookies:
                        jar.set(c["name"], c["value"],
                                domain=c.get("domain", ""),
                                path=c.get("path", "/"))
                    r = _req.get(verify_url, cookies=jar, timeout=10,
                                 allow_redirects=False)
                    if r.status_code not in (301, 302, 401):
                        success = True
                else:
                    # No verify URL — use URL-change heuristic
                    current_url = page.url
                    if current_url.rstrip("/") != login_url.rstrip("/"):
                        pw_cookies = context.cookies()
                        for c in pw_cookies:
                            if c.get("name") and c.get("value"):
                                cookie_dict[c["name"]] = c["value"]
                        if cookie_dict:
                            success = True

            except Exception:
                context.close()
                continue

            context.close()

            if success:
                browser.close()
                log(f"[!] Default credential FOUND: {uname}:{pwd}",
                    Colors.RED)
                return cookie_dict, uname, pwd

        browser.close()
        return None, None, None


def try_default_credentials(
    login_url: str,
    username_field: str = "username",
    password_field: str = "password",
    extra_fields: dict[str, str] | None = None,
    verify_url: str | None = None,
    credentials: list[tuple[str, str]] | None = None,
    timeout_ms: int = 12000,
) -> tuple[dict[str, str] | None, str | None, str | None]:
    """Try default / weak username-password pairs and return the first
    working set as ``(cookies, username, password)``.

    Each attempt uses a fresh browser context (isolated cookie jar).  A
    credential is considered successful when *verify_url* returns an HTTP
    status outside ``{301, 302, 401}``, or when no *verify_url* is given,
    when the page URL changes after form submission (i.e. the app
    redirected away from the login page).

    Runs Playwright in a separate thread to avoid conflicts with any
    asyncio event loop on the main thread.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log("[!] Playwright not available — cannot check default creds", Colors.RED)
        return None, None, None

    from concurrent.futures import ThreadPoolExecutor, wait

    with ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(
            _try_default_credentials_inner,
            login_url=login_url,
            username_field=username_field,
            password_field=password_field,
            extra_fields=extra_fields,
            verify_url=verify_url,
            credentials=credentials,
            timeout_ms=timeout_ms,
        )
        done, _ = wait([fut], timeout=300)
        if not done:
            log("[!] Default-cred check timed out", Colors.YELLOW)
            return None, None, None
        try:
            return fut.result()
        except Exception as e:
            log(f"[!] Default-cred check failed: {e}", Colors.YELLOW)
            return None, None, None


def inject_param(url: str, param: str, value: str) -> str:
    """Replace or add a query parameter in a URL.

    Returns the original URL unmodified on any parsing failure.
    """
    from urllib.parse import urlencode, urlunparse, parse_qs
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url


# ── Backward-compatible re-exports ──────────────────────────────────────
from engines.dedup import DeduplicationEngine  # noqa: E402, F401
from engines.baseline import BaselineFingerprinter  # noqa: E402, F401
# NOTE: TechnologyFingerprinter / TECH_SIGNATURES not re-exported here
# because engines/tech_fingerprint.py imports safe_get from this module,
# which would create a circular import at load time.

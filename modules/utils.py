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
from dataclasses import dataclass, field
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


def reset_seen_findings() -> None:
    """Clear the module-level deduplication set. Call once per scan session."""
    global _seen_findings
    with _seen_findings_lock:
        _seen_findings = set()


SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "x-api-key", "x-auth-token"}

# Module-level default; main.py flips via set_mask_sensitive_default()
_MASK_SENSITIVE_DEFAULT: bool = True

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
    if mask_sensitive is None:
        mask_sensitive = _MASK_SENSITIVE_DEFAULT
    """Build a curl command string for reproduction of a request."""
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


# ── Enums ──────────────────────────────────────────────────────────────────────

class VerificationStage(str, enum.Enum):
    DETECTED = "detected"
    VALIDATED = "validated"
    EXPLOITABLE = "exploitable"
    VERIFIED = "verified"

class EvidenceStrength(str, enum.Enum):
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    VERIFIED = "verified"

class FalsePositiveRisk(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class ConfidenceLevel(str, enum.Enum):
    UNVERIFIED = "Unverified"
    LIKELY = "Likely"
    HIGH_CONFIDENCE = "High Confidence"
    CONFIRMED = "Confirmed"

    @staticmethod
    def from_score(score: int) -> "ConfidenceLevel":
        if score >= 86:
            return ConfidenceLevel.CONFIRMED
        if score >= 61:
            return ConfidenceLevel.HIGH_CONFIDENCE
        if score >= 31:
            return ConfidenceLevel.LIKELY
        return ConfidenceLevel.UNVERIFIED

# ── Confidence Scoring ─────────────────────────────────────────────────────

CONFIDENCE_WEIGHTS = {
    "detection_signal": 25,
    "validation_signal": 35,
    "exploitation_proof": 40,
}

def calculate_confidence(
    detection: bool = False,
    validation: bool = False,
    exploitation: bool = False,
    extra_points: int = 0,
) -> int:
    score = 0
    if detection:
        score += CONFIDENCE_WEIGHTS["detection_signal"]
    if validation:
        score += CONFIDENCE_WEIGHTS["validation_signal"]
    if exploitation:
        score += CONFIDENCE_WEIGHTS["exploitation_proof"]
    score = min(100, score + extra_points)
    return score

def evidence_strength_from_score(score: int) -> EvidenceStrength:
    if score >= 86:
        return EvidenceStrength.VERIFIED
    if score >= 61:
        return EvidenceStrength.STRONG
    if score >= 31:
        return EvidenceStrength.MODERATE
    return EvidenceStrength.WEAK

def false_positive_risk_from_score(score: int) -> FalsePositiveRisk:
    if score >= 86:
        return FalsePositiveRisk.LOW
    if score >= 61:
        return FalsePositiveRisk.MEDIUM
    return FalsePositiveRisk.HIGH

# ── Prioritization Scoring Engine ────────────────────────────────────────────

SEVERITY_PRIORITY = {"critical": 100, "high": 75, "medium": 50, "low": 25}
STAGE_PRIORITY = {"verified": 100, "exploitable": 90, "validated": 60, "detected": 30}

def compute_priority_score(finding: dict) -> int:
    """
    Compute a 0–100 priority score for a finding based on:
    - Severity (25 pts max)
    - Verification stage (35 pts max)
    - Evidence strength (20 pts max)
    - OOB bonus (+15)
    - Signal count (+5 per signal, cap 10)
    """
    severity = finding.get("severity", "low").lower()
    stage = finding.get("verification_stage", "detected").lower()
    evidence = finding.get("evidence_strength", "weak").lower()

    sev_score = SEVERITY_PRIORITY.get(severity, 25)
    stage_score = STAGE_PRIORITY.get(stage, 30)
    evidence_map = {"verified": 20, "strong": 15, "moderate": 10, "weak": 5}
    ev_score = evidence_map.get(evidence, 5)

    oob_bonus = 15 if "oob" in finding.get("evidence", "").lower() else 0
    validation_steps = finding.get("validation_steps", [])
    signal_bonus = min(len(validation_steps) * 5, 10)

    raw = sev_score * 0.25 + stage_score * 0.35 + ev_score * 0.20 + oob_bonus + signal_bonus
    return min(int(raw), 100)


def prioritize_findings(findings: list[dict]) -> list[dict]:
    """Sort findings by computed priority score descending, adding priority_score key."""
    for f in findings:
        f["priority_score"] = compute_priority_score(f)
    return sorted(findings, key=lambda f: f.get("priority_score", 0), reverse=True)


# ── Vulnerability Finding Model ─────────────────────────────────────────────

@dataclass
class VulnerabilityFinding:
    title: str
    vuln_type: str
    url: str
    severity: str
    details: str
    evidence: str = ""
    confidence_score: int = 0
    confidence_label: str = "Unverified"
    verification_stage: str = "detected"
    evidence_strength: str = "weak"
    false_positive_risk: str = "high"
    proof: List[str] = field(default_factory=list)
    fingerprint: str = ""
    grouped_urls: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    what_is_it: str = ""
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: str = ""
    validation_steps: List[str] = field(default_factory=list)
    exploitability_rating: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "title": self.title,
            "type": self.vuln_type,
            "url": self.url,
            "severity": self.severity,
            "details": self.details,
            "evidence": self.evidence,
            "confidence": self.confidence_label,
            "confidence_score": self.confidence_score,
            "evidence_strength": self.evidence_strength,
            "verification_stage": self.verification_stage,
            "false_positive_risk": self.false_positive_risk,
            "proof": self.proof,
            "fingerprint": self.fingerprint,
            "timestamp": self.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "validation_steps": self.validation_steps,
            "exploitability_rating": self.exploitability_rating,
        }
        if self.grouped_urls:
            result["grouped_urls"] = self.grouped_urls
        if self.cvss_score is not None:
            result["cvss_score"] = self.cvss_score
        if self.cvss_vector is not None:
            result["cvss_vector"] = self.cvss_vector
        if self.what_is_it:
            result["what_is_it"] = self.what_is_it
        if self.impact:
            result["impact"] = self.impact
        if self.remediation:
            result["remediation"] = self.remediation
        if self.references:
            result["references"] = self.references
        return result

    def _compute_fingerprint(self) -> str:
        return hashlib.sha256(
            f"{self.vuln_type}:{self._extract_param_name()}:{self._extract_root_cause()}".encode()
        ).hexdigest()

    def _extract_param_name(self) -> str:
        for text in (self.details, self.evidence):
            if "Parameter '" in text:
                return text.split("Parameter '")[1].split("'")[0]
            if "Form field '" in text:
                return text.split("Form field '")[1].split("'")[0]
        if "?" in self.url:
            from urllib.parse import parse_qs, urlparse
            params = parse_qs(urlparse(self.url).query)
            if params:
                return next(iter(params.keys()))
        return ""

    def _extract_root_cause(self) -> str:
        return self.details[:80] if self.details else self.evidence[:80]

    @staticmethod
    def from_legacy(f: Dict[str, Any]) -> "VulnerabilityFinding":
        score = calculate_confidence(
            detection=True,
            validation=f.get("confirmed", False),
            exploitation=False,
        )
        vf = VulnerabilityFinding(
            title=f.get("title", f.get("type", "Unknown")),
            vuln_type=f.get("type", "Unknown"),
            url=f.get("url", ""),
            severity=f.get("severity", "info"),
            details=f.get("details", ""),
            evidence=f.get("evidence", ""),
            confidence_score=score,
            confidence_label=ConfidenceLevel.from_score(score).value,
            verification_stage=VerificationStage.VALIDATED.value if f.get("confirmed") else VerificationStage.DETECTED.value,
            evidence_strength=evidence_strength_from_score(score).value,
            false_positive_risk=false_positive_risk_from_score(score).value,
            fingerprint=f.get("fingerprint", ""),
            timestamp=f.get("timestamp", ""),
            cvss_score=f.get("cvss_score"),
            cvss_vector=f.get("cvss_vector"),
            what_is_it=f.get("what_is_it", ""),
            impact=f.get("impact", ""),
            remediation=f.get("remediation", ""),
            references=f.get("references", []),
            grouped_urls=f.get("grouped_urls", []),
        )
        if not vf.fingerprint:
            vf.fingerprint = vf._compute_fingerprint()
        return vf


# ── OOB Detection Framework ───────────────────────────────────────────────

class OOBDetectionFramework:
    """Out-of-band detection using Interactsh, Burp Collaborator, or custom webhooks.

    Generates unique callback tokens, registers expected interactions,
    and polls for DNS/HTTP callbacks to confirm blind vulnerabilities.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.oob_host = config.get("oob_host", "")
        self.callback_token = str(uuid.uuid4()).replace("-", "")[:16]
        self._interactions: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    @property
    def callback_host(self) -> str:
        """Return the callback host with a unique token subdomain."""
        if not self.oob_host:
            return ""
        return f"{self.callback_token}.{self.oob_host}"

    @property
    def callback_url(self) -> str:
        host = self.callback_host
        if not host:
            return ""
        return f"http://{host}/bbh-verify"

    def generate_payload(self, placeholder: str = "{oob}") -> str:
        """Replace {oob} placeholder with the unique callback URL."""
        if not self.oob_host:
            return ""
        return placeholder.replace("{oob}", self.callback_host)

    def register_interaction(self, vuln_type: str, payload: str, url: str) -> None:
        with self._lock:
            self._interactions.setdefault(vuln_type, []).append({
                "payload": payload,
                "url": url,
                "timestamp": time.time(),
            })

    def poll(self, timeout: float = 5.0) -> List[Dict[str, Any]]:
        """Poll for callbacks. Returns list of confirmed interactions."""
        if not self.oob_host:
            return []
        confirmed: List[Dict[str, Any]] = []
        for vuln_type, interactions in list(self._interactions.items()):
            for entry in interactions:
                if entry.get("confirmed"):
                    continue
                if self._check_callback(entry):
                    entry["confirmed"] = True
                    confirmed.append(entry)
        return confirmed

    def _check_callback(self, entry: Dict[str, Any]) -> bool:
        """Check if a callback has been received for this entry."""
        try:
            import urllib.request
            poll_url = f"http://{self.oob_host}/poll?id={self.callback_token}"
            req = urllib.request.Request(poll_url, method="GET")
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status == 200:
                data = json.loads(resp.read().decode())
                return len(data.get("interactions", [])) > 0
        except Exception:
            pass
        return False

    def clear(self) -> None:
        with self._lock:
            self._interactions.clear()


# ── Deduplication Engine ─────────────────────────────────────────────────

class DeduplicationEngine:
    """Deduplicate findings by (vuln_type + parameter + root_cause) fingerprint.
    Groups findings that share the same root cause across URLs.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._groups: Dict[str, Dict[str, Any]] = {}

    def _make_key(self, f: VulnerabilityFinding) -> str:
        return hashlib.sha256(
            f"{f.vuln_type}:{f._extract_param_name()}:{f._extract_root_cause()}".encode()
        ).hexdigest()

    def add(self, finding: VulnerabilityFinding) -> Optional[VulnerabilityFinding]:
        key = finding._compute_fingerprint()
        with self._lock:
            if key in self._groups:
                existing = self._groups[key]
                existing.grouped_urls.append(finding.url)
                return None
            self._groups[key] = finding
            return finding

    def add_legacy(self, f: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        vf = VulnerabilityFinding.from_legacy(f)
        added = self.add(vf)
        if added is None:
            return None
        return added.to_dict()

    def get_findings(self) -> List[Dict[str, Any]]:
        with self._lock:
            results = []
            for f in self._groups.values():
                d = f.to_dict()
                if len(f.grouped_urls) >= 5:
                    d["grouped_urls"] = f.grouped_urls
                    d["details"] = (
                        f"{f.details} — Found on {len(f.grouped_urls)} URLs"
                    )
                results.append(d)
            return results

    def clear(self) -> None:
        with self._lock:
            self._groups.clear()


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
                self._browser = self._pw.chromium.launch(headless=True)
            except Exception:
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
        page = self._new_page()
        if not page:
            return None
        try:
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
                return {
                    body_snippet: body.substring(0, 200),
                    script_count: scripts.length,
                    has_bbh_marker: window.__bbh_xss === 1 || body.includes('__bbh_xss'),
                };
            }""")
            result["dom_mutation"] = dom_evidence.get("has_bbh_marker", False)

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
                    pass

            page.close()
            return result
        except Exception:
            try:
                page.close()
            except Exception:
                pass
            return None

    def scan_dom_xss(self, url: str, probes: List[str]) -> List[Dict[str, Any]]:
        """Scan for DOM-based XSS by testing common sinks with each probe.
        
        Tests: document.write, innerHTML, outerHTML, insertAdjacentHTML,
        eval, setTimeout, Function constructor, jQuery $().
        Returns list of findings dicts with 'sink', 'probe', 'executed' keys.
        """
        findings: List[Dict[str, Any]] = []
        page = self._new_page()
        if not page:
            return findings
        try:
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

            page.close()
            return findings
        except Exception:
            try:
                page.close()
            except Exception:
                pass
            return findings

    def capture_screenshot(self, url: str, output_path: str) -> Optional[str]:
        """Capture a full-page PNG screenshot."""
        page = self._new_page()
        if not page:
            return None
        try:
            page.set_viewport_size({"width": 1280, "height": 720})
            page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
            page.screenshot(path=output_path, full_page=True)
            page.close()
            return output_path
        except Exception:
            try:
                page.close()
            except Exception:
                pass
            return None

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
        if unique_chars < 24:
            return {"valid": False, "type": "twilio_sid", "details": f"Too few unique chars ({unique_chars}/24) — likely garbage"}
        return {"valid": True, "type": "twilio_sid", "details": "Format and entropy pass"}

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
        if unique_chars < 24:
            return {"valid": False, "type": "twilio_token", "details": f"Too few unique chars ({unique_chars}/24) — likely garbage"}
        return {"valid": True, "type": "twilio_token", "details": "Format and entropy pass"}

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
        }
        handler = mapping.get(secret_type)
        if not handler:
            return {"valid": None, "type": secret_type, "details": "No validator available"}
        return handler(value)


# ── Technology Fingerprinter ───────────────────────────────────────────────

TECH_SIGNATURES: Dict[str, List[Dict[str, Any]]] = {
    "framework": [
        {"name": "Django", "headers": {"x-frame-options": "DENY"}, "body": re.compile(r"django\.wsgi|csrfmiddlewaretoken|__admin_media_prefix__")},
        {"name": "Laravel", "headers": {"x-powered-by": "Laravel"}, "body": re.compile(r"laravel_session|csrf_token|Livewire|__livewire")},
        {"name": "Rails", "headers": {"x-powered-by": "Phusion|Passenger"}, "body": re.compile(r"csrf-token|rails-ujs|data-remote|data-method")},
        {"name": "Spring", "headers": {"x-application-context": ""}, "body": re.compile(r"spring|_csrf|XSRF-TOKEN")},
        {"name": "ASP.NET", "headers": {"x-aspnet-version": "", "x-powered-by": "ASP.NET"}, "body": re.compile(r"__viewstate|__eventvalidation|aspnetForm")},
        {"name": "Express", "headers": {"x-powered-by": "Express"}, "body": re.compile(r"express|connect\.sid")},
        {"name": "Flask", "headers": {}, "body": re.compile(r"flask|__debug__|secret_key")},
        {"name": "FastAPI", "headers": {}, "body": re.compile(r"fastapi|openapi\.json|docs|redoc")},
        {"name": "Next.js", "headers": {"x-powered-by": "Next.js"}, "body": re.compile(r"__NEXT_DATA__|/_next/static")},
        {"name": "Nuxt.js", "headers": {}, "body": re.compile(r"nuxt\.config|__NUXT__")},
        {"name": "Gatsby", "headers": {}, "body": re.compile(r"gatsby|___gatsby")},
    ],
    "cms": [
        {"name": "WordPress", "headers": {}, "body": re.compile(r"/wp-content/|/wp-includes/|wp-json|wordpress_[a-f0-9]{32}")},
        {"name": "Drupal", "headers": {}, "body": re.compile(r"drupal\.js|sites/default|/drupal|Drupal\.settings")},
        {"name": "Joomla", "headers": {}, "body": re.compile(r"joomla|/components/|/modules/|/templates/")},
        {"name": "Shopify", "headers": {"x-shopid": ""}, "body": re.compile(r"shopify|myshopify\.com|Shopify\.sdk")},
        {"name": "Magento", "headers": {}, "body": re.compile(r"mage\.|Magento|/static/version")},
    ],
    "language": [
        {"name": "PHP", "headers": {"x-powered-by": "PHP"}, "body": re.compile(r"php")},
        {"name": "Python", "headers": {}, "body": re.compile(r"django|flask|python|bottle|tornado")},
        {"name": "Ruby", "headers": {"x-powered-by": "Phusion|Passenger"}, "body": re.compile(r"ruby|\.erb")},
        {"name": "Java", "headers": {}, "body": re.compile(r"servlet|jsp|java|spring|tomcat")},
        {"name": "Node.js", "headers": {"x-powered-by": "Express"}, "body": re.compile(r"node|express|next\.js")},
        {"name": "Go", "headers": {}, "body": re.compile(r"go\.(min\.)?js|gorilla")},
    ],
    "proxy": [
        {"name": "Cloudflare", "headers": {"server": "cloudflare", "cf-ray": ""}, "body": re.compile(r"cloudflare|__cfduid")},
        {"name": "Akamai", "headers": {}, "body": re.compile(r"akamai|akamaized")},
        {"name": "Fastly", "headers": {"x-served-by": "", "x-cache": ""}, "body": re.compile(r"fastly")},
        {"name": "CloudFront", "headers": {"x-amz-cf-id": "", "x-amz-cf-pop": ""}, "body": re.compile(r"cloudfront")},
        {"name": "Varnish", "headers": {"x-varnish": "", "via": "varnish"}, "body": re.compile(r"varnish")},
        {"name": "Nginx", "headers": {"server": "nginx"}, "body": re.compile(r"nginx")},
        {"name": "Apache", "headers": {"server": "apache"}, "body": re.compile(r"apache")},
        {"name": "IIS", "headers": {"server": "iis", "x-powered-by": "ASP.NET"}, "body": re.compile(r"iis")},
    ],
    "waf": [
        {"name": "Cloudflare (WAF)", "headers": {"server": "cloudflare"}, "body": re.compile(r"cloudflare-nginx|attention: required|ray id:")},
        {"name": "AWS WAF", "headers": {}, "body": re.compile(r"Request blocked|waf|AWS WAF")},
        {"name": "ModSecurity", "headers": {}, "body": re.compile(r"ModSecurity|This error was generated by Mod_Security")},
        {"name": "Akamai WAF", "headers": {}, "body": re.compile(r"akamai|reference number|#ref_")},
        {"name": "F5 BIG-IP", "headers": {}, "body": re.compile(r"big-ip|F5|TS[0-9a-f]+")},
        {"name": "Sucuri", "headers": {"x-sucuri-id": ""}, "body": re.compile(r"sucuri|cloudproxy")},
    ],
    "template_engine": [
        {"name": "Jinja2", "body": re.compile(r"\{\{.*\}\}|jinja2")},
        {"name": "Twig", "body": re.compile(r"twig|\.twig")},
        {"name": "Smarty", "body": re.compile(r"smarty|\{\$.*\}")},
        {"name": "FreeMarker", "body": re.compile(r"\$\{.*\}")},
        {"name": "Velocity", "body": re.compile(r"velocity|#set\(|#if\(")},
        {"name": "Mustache", "body": re.compile(r"mustache|\{\{.*\}\}")},
        {"name": "Handlebars", "body": re.compile(r"handlebars|Handlebars\.")},
        {"name": "EJS", "body": re.compile(r"<%|%=|ejs")},
        {"name": "Pug/Jade", "body": re.compile(r"pug|jade")},
    ],
}


class TechnologyFingerprinter:
    """Identify web technologies (frameworks, CMS, languages, proxies, WAFs) from HTTP responses."""

    def __init__(self, session: Any, timeout: int):
        self.session = session
        self.timeout = timeout
        self.results: Dict[str, List[str]] = {}

    def fingerprint(self, url: str) -> Dict[str, List[str]]:
        """Fingerprint a URL by analyzing response headers and body."""
        try:
            resp = safe_get(self.session, url, self.timeout)
            if not resp:
                return {}
        except Exception:
            return {}

        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body = resp.text.lower()

        for category, signatures in TECH_SIGNATURES.items():
            if category not in self.results:
                self.results[category] = []
            for sig in signatures:
                detected = self._match_signature(sig, headers, body)
                if detected and sig["name"] not in self.results[category]:
                    self.results[category].append(sig["name"])

        return self.results

    def _match_signature(self, sig: Dict[str, Any], headers: Dict[str, str], body: str) -> bool:
        header_match = all(
            key in headers and (not val or val in headers[key])
            for key, val in sig.get("headers", {}).items()
        )
        body_pattern = sig.get("body")
        body_match = body_pattern.search(body) if body_pattern else False
        return header_match or bool(body_match)

    def get(self, category: str, default: Optional[List[str]] = None) -> List[str]:
        return self.results.get(category, default or [])

    def all(self) -> Dict[str, List[str]]:
        return self.results

    def summary(self) -> str:
        parts = []
        for category, items in self.results.items():
            if items:
                parts.append(f"{category}: {', '.join(items)}")
        return " | ".join(parts) if parts else "Unknown"


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
    evidence: str = "",
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
) -> Optional[Dict[str, Any]]:
    """
    Build a standardized finding dict with CVSS metadata, fingerprint, and timestamp.
    Supports both legacy confidence strings and new proof-based confidence fields.
    """
    dedupe_key = (vuln_type, url, parameter or "")
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
        "confidence_score": confidence_score,
        "verification_stage": verification_stage or VerificationStage.DETECTED.value,
        "evidence_strength": evidence_strength,
        "false_positive_risk": false_positive_risk,
        "proof": proof or [],
        "validation_steps": validation_steps or [],
        "exploitability_rating": exploitability_rating or "unknown",
        "parameter": parameter or "",
        "request": request or "",
        "response_excerpt": response_excerpt or "",
        "steps_to_reproduce": steps_to_reproduce or [],
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


def finding_v2(
    title: str,
    vuln_type: str,
    url: str,
    severity: str,
    details: str,
    evidence: str = "",
    detection: bool = True,
    validation: bool = False,
    exploitation: bool = False,
    extra_confidence_points: int = 0,
    proof: Optional[List[str]] = None,
    validation_steps: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """New-style finding with explicit stage-based confidence scoring."""
    score = calculate_confidence(
        detection=detection,
        validation=validation,
        exploitation=exploitation,
        extra_points=extra_confidence_points,
    )
    if exploitation:
        stage = VerificationStage.EXPLOITABLE.value
    elif validation:
        stage = VerificationStage.VALIDATED.value
    else:
        stage = VerificationStage.DETECTED.value

    return finding(
        vuln_type=vuln_type,
        url=url,
        severity=severity,
        details=details,
        evidence=evidence,
        confidence=ConfidenceLevel.from_score(score).value,
        proof=proof,
        validation_steps=validation_steps,
        confidence_score=score,
        verification_stage=stage,
        evidence_strength=evidence_strength_from_score(score).value,
        false_positive_risk=false_positive_risk_from_score(score).value,
    )


# ── Baseline Fingerprinting ───────────────────────────────────────────

class BaselineFingerprinter:
    """Record a known-safe response baseline per (method, base_url) and
    flag deviations >15% length, different status code, or error patterns."""

    def __init__(self, session: requests.Session, timeout: int = 10):
        self.session = session
        self.timeout = timeout
        self._baselines: dict[tuple[str, str], dict] = {}
        self._lock = threading.Lock()

    def _base_key(self, url: str, method: str = "GET") -> tuple[str, str]:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
        return (method, base)

    def fingerprint(self, url: str, method: str = "GET") -> dict:
        """Fetch a URL and store its baseline.  Returns the baseline dict."""
        key = self._base_key(url, method)
        with self._lock:
            if key in self._baselines:
                return self._baselines[key]
        try:
            r = self.session.get(url, timeout=self.timeout) if method == "GET" else self.session.post(url, timeout=self.timeout)
        except Exception:
            r = None
        baseline = {
            "status": r.status_code if r else 0,
            "length": len(r.text) if r else 0,
            "hash": hashlib.md5(r.text.encode()).hexdigest() if r else "",
        }
        with self._lock:
            self._baselines[key] = baseline
        return baseline

    def is_anomalous(self, url: str, response, method: str = "GET") -> bool:
        """Return True if the response meaningfully deviates from the baseline."""
        key = self._base_key(url, method)
        bl = self._baselines.get(key)
        if bl is None:
            return True
        if response is None:
            return False
        length = len(response.text)
        length_diff = abs(length - bl["length"])
        if bl["length"] > 0 and length_diff / max(bl["length"], 1) > 0.15:
            return True
        if response.status_code != bl["status"] and response.status_code not in (0,):
            return True
        return False


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
            now = time.time()
            if now < self._backoff_until:
                time.sleep(self._backoff_until - now)
                now = time.time()
            min_interval = 1.0 / self.current_rps
            elapsed = now - self._last_request
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self._last_request = time.time()

    def report_429(self) -> None:
        with self._lock:
            self.current_rps = max(0.1, self.current_rps / 2)
            self._backoff_until = time.time() + 5.0
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
    retry_strategy = Retry(
        total=retries,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
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

    pipeline = _wrap_jitter_retry(pipeline, int(config.get("retries", 3)))

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
    try:
        response = session.get(
            url, timeout=timeout, allow_redirects=allow_redirects, **kwargs
        )
        # Check redirect targets against scope
        if config and allow_redirects and response.history:
            enforcer = config.get("scope_enforcer")
            if enforcer is not None:
                for resp in response.history:
                    if resp.headers.get("Location"):
                        redirect_target = resp.headers["Location"]
                        if not redirect_target.startswith("/") and not enforcer.check_url(redirect_target):
                            log(f"[!] Redirect to out-of-scope URL blocked: {redirect_target}", Colors.YELLOW)
                            return None
                        if redirect_target.startswith("/"):
                            from urllib.parse import urljoin
                            redirect_target = urljoin(url, redirect_target)
                            if not enforcer.check_url(redirect_target):
                                log(f"[!] Redirect to out-of-scope URL blocked: {redirect_target}", Colors.YELLOW)
                                return None
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
    config: Optional[dict] = None,
    **kwargs,
) -> Optional[requests.Response]:
    """HTTP POST with logging on failure and scope-checked redirects."""
    try:
        response = session.post(
            url, data=data, timeout=timeout, allow_redirects=allow_redirects, **kwargs
        )
        # Check redirect targets against scope
        if config and allow_redirects and response.history:
            enforcer = config.get("scope_enforcer")
            if enforcer is not None:
                for resp in response.history:
                    if resp.headers.get("Location"):
                        redirect_target = resp.headers["Location"]
                        if not redirect_target.startswith("/") and not enforcer.check_url(redirect_target):
                            log(f"[!] Redirect to out-of-scope URL blocked: {redirect_target}", Colors.YELLOW)
                            return None
                        if redirect_target.startswith("/"):
                            from urllib.parse import urljoin
                            redirect_target = urljoin(url, redirect_target)
                            if not enforcer.check_url(redirect_target):
                                log(f"[!] Redirect to out-of-scope URL blocked: {redirect_target}", Colors.YELLOW)
                                return None
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
        modules.update({"xss", "sqli", "ssti"})
    if has_file_param:
        modules.update({"lfi", "xxe", "ssrf"})
    if has_url_param:
        modules.update({"ssrf", "open_redirect"})
    if has_id_param:
        modules.update({"idor", "sqli"})
    if is_form_post:
        modules.update({"csrf", "xss", "sqli", "insecure_forms"})
    if is_json_api:
        modules.update({"sqli", "idor", "rate_limiting", "api", "http_methods"})
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
    }
    return sum(weights[s] for s in signals if s in weights)


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

    return signals


# Modules that run on every URL regardless of signals
_CLASSIFY_ALWAYS: set[str] = {
    "headers", "sensitive", "exposed_files", "clickjacking",
}

"""
ScannerBase — shared kernel for all vulnerability scanners.

Provides:
- Config, session, recon access
- Scope enforcement (_in_scope)
- Deduplication (dedup)
- Validation engine (OOB, browser, timing, secret)
- Evidence engine
- Threaded execution
- Payload loading
- WAF detection, baseline fingerprinting, tech fingerprinting
- Standard lifecycle interface: detect → validate → collect_evidence → generate_reproduction → calculate_confidence
"""

import json
import os
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from queue import Queue

from modules.utils import (
    make_session, safe_get, safe_post, finding, log, Colors, url_in_scope,
    BaselineFingerprinter, DeduplicationEngine, TechnologyFingerprinter,
    _build_curl, reset_seen_findings,
)
from engines import ValidationEngine, EvidenceEngine


class DetectionResult:
    """Result from the detect() phase."""
    def __init__(self, url: str, parameter: str = "",
                 payload: str = "", context: str = "",
                 raw_response: Any = None,
                 evidence_signals: list[str] | None = None):
        self.url = url
        self.parameter = parameter
        self.payload = payload
        self.context = context
        self.raw_response = raw_response
        self.evidence_signals = evidence_signals or []


class ValidationResult:
    """Result from the validate() phase."""
    def __init__(self, confirmed: bool = False,
                 signals: list[str] | None = None,
                 method: str = "",
                 detail: str = ""):
        self.confirmed = confirmed
        self.signals = signals or []
        self.method = method
        self.detail = detail


class ScannerBase:
    """Base class for vulnerability scanners with the 5-phase lifecycle."""

    # Scanner metadata — override in subclasses
    SCANNER_NAME = "base"
    SCANNER_MATURITY = 1  # 1-5: Detection only → Verified
    SCANNER_ORDER = 100   # Lower = runs earlier (target-level: 10, per-url: 100)
    TARGET_LEVEL = False  # True = runs once per target, not per URL

    def __init__(self, config: dict, recon: dict, container=None):
        self.config = config
        self.recon = recon
        self.container = container
        self.timeout = config.get("timeout", 10)
        self.threads = config.get("threads", 10)
        self.verbose = config.get("verbose", False)
        self.session = make_session(config)
        self.base_url = config.get("target", "").rstrip("/")

        self._lock = threading.Lock()
        self.dedup = DeduplicationEngine()
        if container:
            self.validation = container.validation_engine
            self.evidence_engine = container.evidence_engine
        else:
            self.validation = ValidationEngine(config)
            self.evidence_engine = EvidenceEngine()

        self.waf_detected = False
        self._prepared = False
        self._findings_store: list[dict] = []

    # ── Lifecycle (override in subclasses) ───────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        raise NotImplementedError

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        raise NotImplementedError

    def collect_evidence(self, result) -> list:
        return []

    def generate_reproduction(self, result) -> list[str]:
        return []

    def calculate_confidence(self, detection: bool, validation: bool,
                             exploitation: bool, extra: int = 0) -> int:
        from models.finding import calculate_confidence
        return calculate_confidence(
            detection=detection,
            validation=validation,
            exploitation=exploitation,
            extra_points=extra,
        )

    def scan(self, target_urls: list[str] | None = None) -> list[dict]:
        """Main scan entry point. Override to implement scanning logic."""
        raise NotImplementedError

    # ── Shared utilities ─────────────────────────────────────────────────

    def _in_scope(self, url: str) -> bool:
        return url_in_scope(url, self.config)

    def _prepare_scan(self) -> None:
        if self._prepared:
            return
        self._prepared = True
        self._detect_waf()
        self._fingerprint_baselines()
        self._fingerprint_tech()

    def _detect_waf(self) -> None:
        target = self.config.get("target", "")
        if not target:
            return
        if self.config.get("stealth"):
            log("[*] WAF detection skipped in stealth mode", Colors.YELLOW, verbose_only=True, verbose=self.verbose)
            self.waf_detected = True
            return
        safe_url = target.rstrip("/") + "/"
        blocked = 0
        for probe in ("' OR 1=1--", "<script>alert(1)</script>"):
            try:
                r = safe_get(self.session, safe_url + "?" + urlencode({"q": probe}),
                             self.timeout, raise_for_status=False)
                if r and r.status_code in (403, 406, 429):
                    blocked += 1
            except Exception:
                continue
        if blocked >= 2:
            self.waf_detected = True
            log("[!] WAF detected", Colors.YELLOW, verbose_only=True, verbose=self.verbose)

    def _fingerprint_baselines(self) -> None:
        bf = BaselineFingerprinter(self.session, self.timeout)
        for url in self.recon.get("urls", []):
            try:
                bf.fingerprint(url)
            except Exception:
                continue

    def _fingerprint_tech(self) -> None:
        tf = TechnologyFingerprinter(self.session, self.timeout)
        for url in self.recon.get("urls", []):
            try:
                tf.fingerprint(url)
            except Exception:
                continue
        self.config["technology"] = tf.all()

    def _load_payloads(self, payload_type: str) -> Any:
        import yaml
        yaml_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "payloads", f"{payload_type}.yaml"
        )
        list_types = {"lfi", "ssrf"}
        try:
            with open(yaml_path, "r") as f:
                loaded = yaml.safe_load(f)
            if loaded and "payloads" in loaded:
                raw = loaded["payloads"]
                if isinstance(raw, dict) and payload_type in list_types:
                    flat = []
                    for cat in raw.values():
                        if isinstance(cat, list):
                            flat.extend(cat)
                    if flat:
                        return flat
                if isinstance(raw, (dict, list)):
                    return raw
        except (FileNotFoundError, yaml.YAMLError):
            pass
        fallbacks = {
            "sqli": None,
            "xss": None,
            "lfi": None,
            "ssrf": None,
            "xxe": None,
            "ssti": None,
            "cmdi": None,
        }
        fb = fallbacks.get(payload_type, [])
        if self.verbose:
            log(f"[*] Payload YAML for '{payload_type}' not found — using scanner defaults",
                Colors.YELLOW, verbose_only=True, verbose=self.verbose)
        return fb

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

    def _add_finding(self, f: dict | None) -> bool:
        if not f:
            return False
        with self._lock:
            if not self.dedup.add_legacy(f):
                return False
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Finding")[:60]
            url = f.get("url", "")[:60]
            stage = f.get("verification_stage", "detected").title()
            score = f.get("confidence_score", 0)
            log(f"  [FOUND] [{sev}] {title} @ {url} [{stage}, {score:.0f}/100]",
                Colors.RED if sev in ("CRITICAL", "HIGH") else Colors.YELLOW)
            return True

    def _get_findings(self) -> list[dict]:
        from modules.utils import prioritize_findings
        raw = self.dedup.get_findings()
        return prioritize_findings(raw)

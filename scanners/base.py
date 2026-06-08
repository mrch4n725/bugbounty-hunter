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

    def generate_reproduction(self, result=None) -> list[str]:
        url = getattr(result, "url", "") if result else ""
        ctx = getattr(result, "context", "") if result else ""
        if url and ctx:
            return [
                f"Send request to {url}",
                f"Observe: {ctx}",
                "Verify by inspecting the response for the expected vulnerability signal",
            ]
        if url:
            return [
                f"Send request to {url}",
                "Inspect the response for anomalies or unexpected behavior",
            ]
        return [
            "Identify the target endpoint that may be vulnerable",
            "Send a crafted request with a test payload",
            "Inspect the response for the expected vulnerability signal",
        ]

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
        """Main scan entry point. Override to implement scanning logic.

        TARGET_LEVEL = True means scan() ignores the target_urls argument
        and always operates on self.base_url or self.recon directly.
        SCANNER_ORDER = 10 for target-level scanners that run before
        per-URL passes. The _dispatch_to_scanner() caller in
        modules/scanner.py always passes target_urls; target-level scanners
        must simply ignore it.
        """
        raise NotImplementedError

    def finalize(self) -> list[dict]:
        """Post-scan hook called after scan() returns.
        Override in OOB-based scanners to poll for callbacks.
        Returns additional findings confirmed by OOB."""
        return []

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
        try:
            import yaml
        except ImportError:
            return self._payload_fallback(payload_type)
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
        return self._payload_fallback(payload_type)

    def _payload_fallback(self, payload_type: str) -> Any:
        fallbacks = {
            "sqli": {},
            "xss": {},
            "lfi": [],
            "ssrf": [],
            "xxe": {},
            "ssti": {},
            "cmdi": {},
        }
        fb = fallbacks.get(payload_type, {})
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

    def _enrich_confidence(self, f) -> None:
        from models.finding import calculate_confidence as calc_conf
        from models.finding import evidence_strength_from_score, false_positive_risk_from_score
        stage = f.get("verification_stage", "").lower()
        score = f.get("confidence_score", 0)
        if score < 25:
            new_score = calc_conf(
                detection=True,
                validation=stage in ("validated", "exploitable", "verified"),
                exploitation=stage in ("exploitable", "verified"),
            )
            f["confidence_score"] = new_score
            f["evidence_strength"] = evidence_strength_from_score(new_score).value
            f["false_positive_risk"] = false_positive_risk_from_score(new_score).value
        # Always populate confidence reasons
        reasons = f.get("confidence_reasons")
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
            f["confidence_reasons"] = reasons

    def _add_capability_confidence_reasons(self, f) -> None:
        """Add or adjust confidence reasons based on available capabilities."""
        try:
            from app.capabilities import CapabilityRegistry
            caps = CapabilityRegistry.get_global()
        except Exception:
            return
        reasons = f.get("confidence_reasons")
        if not isinstance(reasons, list):
            reasons = []
        score = f.get("confidence_score", 0)
        has_browser = caps.has("playwright") and caps.has("chromium")
        has_oob = caps.has("oob_validation")
        has_esprima = caps.has("esprima")

        if has_browser and score < 80:
            if not any("browser" in r for r in reasons):
                reasons.append("+ Browser validation available (can increase confidence)")
        if not has_browser:
            if not any("No browser" in r for r in reasons):
                reasons.append("- No browser validation (XSS/JS findings unverifiable via Playwright)")
                if f.get("vuln_type", "").lower() in ("xss", "dom xss", "blind xss"):
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
        f["confidence_reasons"] = reasons

    def _add_finding(self, f) -> bool:
        if not f:
            return False
        with self._lock:
            if not self.dedup.add_legacy(f):
                return False
            self._enrich_confidence(f)
            self._add_capability_confidence_reasons(f)
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Finding")[:60]
            url = f.get("url", "")[:60]
            stage = f.get("verification_stage", "detected").replace("_", " ").title()
            score = f.get("confidence_score", 0)
            log(f"  [FOUND] [{sev}] {title} @ {url} [{stage}, {score:.0f}/100]",
                Colors.RED if sev in ("CRITICAL", "HIGH") else Colors.YELLOW)

            # Auto-create and link HttpRequestEvidence for every finding
            fp = f.get("fingerprint", "")
            request_str = f.get("request", "")
            if fp and request_str and self.evidence_engine is not None:
                try:
                    from models.evidence import HttpRequestEvidence
                    req_str = f.get("request", "")
                    method = "GET"
                    if req_str.startswith("curl"):
                        parts = req_str.split()
                        for i, p in enumerate(parts):
                            if p == "-X" and i + 1 < len(parts):
                                method = parts[i + 1]
                                break
                    req_ev = HttpRequestEvidence(
                        method=method,
                        url=url,
                        curl_command=request_str,
                    )
                    self.evidence_engine.store(req_ev)
                    self.evidence_engine.link_to_finding(req_ev, fp)
                except Exception as e:
                    log(f"  [evidence] Failed to auto-create HttpRequestEvidence: {e}",
                        Colors.WHITE, verbose_only=True, verbose=self.verbose)
            return True

    def _get_findings(self) -> list:
        from modules.utils import prioritize_findings
        raw = self.dedup.get_findings()
        return prioritize_findings(raw)

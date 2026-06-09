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

from models.finding import Finding
from modules.utils import (
    make_session, safe_get, safe_post, finding, log, Colors, url_in_scope,
    _build_curl, reset_seen_findings,
    enrich_finding_confidence, add_capability_confidence_reasons,
    link_finding_evidence,
)
from engines import ValidationEngine, EvidenceEngine, DeduplicationEngine
from engines.baseline import BaselineFingerprinter
from engines.tech_fingerprint import TechnologyFingerprinter


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

    def calculate_confidence(self, signals: int, stage: "VerificationStage",
                             evidence_count: int, false_positive_risk: str) -> int:
        from models.finding import VerificationStage

        if signals >= 3:
            base = 60
        elif signals == 2:
            base = 40
        else:
            base = 25

        stage_mult = {
            VerificationStage.DETECTED: 1.0,
            VerificationStage.VALIDATED: 1.5,
            VerificationStage.EXPLOITABLE: 2.0,
            VerificationStage.VERIFIED: 2.0,
        }
        score = int(base * stage_mult.get(stage, 1.0))
        score = min(score, 100)

        evidence_bonus = min(evidence_count * 5, 20)
        score += evidence_bonus

        fp_penalty = {"HIGH": -15, "MEDIUM": -5, "LOW": 0}
        score += fp_penalty.get(false_positive_risk, 0)

        return max(10, min(score, 100))

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        """Main scan entry point. Override to implement scanning logic.

        TARGET_LEVEL = True means scan() ignores the target_urls argument
        and always operates on self.base_url or self.recon directly.
        SCANNER_ORDER = 10 for target-level scanners that run before
        per-URL passes. The _dispatch_to_scanner() caller in
        modules/scanner.py always passes target_urls; target-level scanners
        must simply ignore it.
        """
        raise NotImplementedError

    def finalize(self) -> list[Finding]:
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
        if not (self.config.get("passive") or self.config.get("dry_run")):
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

    def _enrich_confidence(self, f: Finding) -> None:
        enrich_finding_confidence(f)

    def _add_capability_confidence_reasons(self, f: Finding) -> None:
        add_capability_confidence_reasons(f)

    def _enrich_finding(self, f, evidence_count: int, verification_stage_value: str) -> None:
        from models.finding import VerificationStage, EvidenceStrength
        stage_enum = VerificationStage(verification_stage_value)
        signal_map = {
            VerificationStage.DETECTED: 1,
            VerificationStage.VALIDATED: 2,
            VerificationStage.EXPLOITABLE: 3,
            VerificationStage.VERIFIED: 3,
        }
        signals = signal_map.get(stage_enum, 1)
        if self.SCANNER_MATURITY >= 4:
            fp_risk = "LOW"
        elif self.SCANNER_MATURITY == 3:
            fp_risk = "MEDIUM"
        else:
            fp_risk = "HIGH"
        strength_map = {
            VerificationStage.DETECTED: EvidenceStrength.WEAK,
            VerificationStage.VALIDATED: EvidenceStrength.MODERATE,
            VerificationStage.EXPLOITABLE: EvidenceStrength.STRONG,
            VerificationStage.VERIFIED: EvidenceStrength.VERIFIED,
        }
        evidence_strength = strength_map.get(stage_enum, EvidenceStrength.WEAK)
        score = self.calculate_confidence(signals, stage_enum, evidence_count, fp_risk)
        if f.get("confidence_score", 0) == 0:
            f["confidence_score"] = score
        f["evidence_strength"] = evidence_strength.value
        f["false_positive_risk"] = fp_risk

    def _add_finding(self, f: Finding) -> bool:
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

            link_finding_evidence(f, self.evidence_engine)
            return True

    def _get_findings(self) -> list[Finding]:
        from modules.utils import prioritize_findings
        raw = self.dedup.get_findings()
        return prioritize_findings(raw)

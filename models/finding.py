import enum
import hashlib
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar


# ── UUIDv7 generation (Python < 3.14 compat) ──────────────────────────────

def _uuid7() -> str:
    """Generate a UUIDv7-like string (time-ordered, 8-4-4-4-12 format)."""
    timestamp_ms = int(time.time() * 1000)
    rand = os.urandom(10)
    ts_high = (timestamp_ms >> 16) & 0xFFFFFFFF
    ts_low = timestamp_ms & 0xFFFF
    time_hi_and_version = (0x7000 | ((rand[0] << 4) | (rand[1] >> 4))) & 0xFFFF
    clock_seq = 0x80 | (rand[1] & 0x0f)
    node = (rand[2] << 40) | (rand[3] << 32) | (rand[4] << 24) | (rand[5] << 16) | (rand[6] << 8) | rand[7]
    return f"{ts_high:08x}-{ts_low:04x}-{time_hi_and_version:04x}-{clock_seq:02x}{node >> 40:02x}-{node & 0xFFFFFFFFFF:010x}"


# ── Enums ──────────────────────────────────────────────────────────────────

class VerificationStage(str, enum.Enum):
    DETECTED = "detected"
    PARTIALLY_VALIDATED = "partially_validated"
    VALIDATED = "validated"
    EXPLOITABLE = "exploitable"
    VERIFIED = "verified"


class FindingState(str, enum.Enum):
    SIGNAL = "signal"
    POTENTIAL = "potential"
    VALIDATED = "validated"
    VERIFIED = "verified"
    SUBMISSION_READY = "submission_ready"

    @classmethod
    def from_verification_stage(cls, stage: str) -> "FindingState":
        mapping = {
            "detected": FindingState.SIGNAL,
            "partially_validated": FindingState.POTENTIAL,
            "validated": FindingState.VALIDATED,
            "exploitable": FindingState.VERIFIED,
            "verified": FindingState.SUBMISSION_READY,
        }
        return mapping.get(stage.lower(), FindingState.SIGNAL)


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
    return min(100, score + extra_points)


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


# ── Fingerprints ───────────────────────────────────────────────────────────

def compute_fingerprint(vuln_type: str, url: str, parameter: str = "") -> str:
    return hashlib.sha256(
        f"{vuln_type}:{url}:{parameter}".encode()
    ).hexdigest()


def compute_root_cause_fingerprint(vuln_type: str, root_cause: str) -> str:
    return hashlib.sha256(
        f"{vuln_type}:{root_cause}".encode()
    ).hexdigest()


# ── Finding Model ──────────────────────────────────────────────────────────

@dataclass
class Finding:
    id: str = ""
    title: str = ""
    vuln_type: str = ""
    severity: str = "info"
    confidence_score: int = 25
    confidence_label: str = "Unverified"
    verification_stage: str = "detected"
    evidence_strength: str = "weak"
    false_positive_risk: str = "high"
    finding_state: str = "signal"
    fingerprint: str = ""
    root_cause_fingerprint: str = ""
    evidence_fingerprint: str = ""

    # ── Dict-compatible access ─────────────────────────────────────────
    # Makes Finding instances look like dicts to reporters and utilities.
    # Supports f.get("key"), f["key"], f.setdefault("key", val), etc.

    # Dict keys that map to different Finding field names
    _DICT_ATTR_MAP: ClassVar[dict[str, str]] = {
        "type": "vuln_type",
        "steps_to_reproduce": "reproduction_steps",
        "validation_steps": "reproduction_steps",
        "recommendation": "remediation",
        "what_is_it": "details",
        "proof": "evidence",
    }
    # Legacy dict keys that don't have a Finding field but are preserved dynamically
    _DICT_LEGACY_KEYS: ClassVar[set[str]] = {
        "screenshot_path", "confirmed", "priority_score", "component",
        "what_is_it", "request_response", "demonstrated_impact",
        "chains", "self_halted",
    }

    def __getitem__(self, key: str) -> Any:
        if key in self._DICT_ATTR_MAP:
            key = self._DICT_ATTR_MAP[key]
        try:
            val = getattr(self, key)
        except AttributeError:
            if key in self._DICT_LEGACY_KEYS:
                return ""
            raise KeyError(key)
        if key == "evidence" and isinstance(val, list):
            return val
        return val

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self._DICT_ATTR_MAP:
            key = self._DICT_ATTR_MAP[key]
        if key in self.__dataclass_fields__:
            object.__setattr__(self, key, value)
        else:
            # Allow dynamic attributes (e.g. impact_assessment, grouped_urls)
            object.__setattr__(self, key, value)

    def __contains__(self, key: str) -> bool:
        if key in self._DICT_ATTR_MAP:
            key = self._DICT_ATTR_MAP[key]
        return key in self.__dataclass_fields__ or hasattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            val = self[key]
            if val is None or val == "":
                return default
            return val
        except (AttributeError, KeyError, TypeError):
            return default

    def setdefault(self, key: str, default: Any = None) -> Any:
        try:
            if key not in self:
                self[key] = default
            return self[key]
        except (AttributeError, KeyError, TypeError):
            return default

    def keys(self) -> list[str]:
        return list(self.__dataclass_fields__.keys())

    def values(self) -> list[Any]:
        return [self[k] for k in self.keys()]

    def items(self) -> list[tuple[str, Any]]:
        return [(k, self[k]) for k in self.keys()]

    target: str = ""
    url: str = ""
    parameter: str = ""

    details: str = ""
    impact: str = ""
    business_impact: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    exploitability_rating: str = "unknown"

    root_cause: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    grouped_urls: list[str] = field(default_factory=list)
    validation_signals: list[str] = field(default_factory=list)

    evidence: list[Any] = field(default_factory=list)
    reproduction_steps: list[str] = field(default_factory=list)
    curl_command: str = ""

    request: str = ""
    response_excerpt: str = ""

    timestamp: str = ""
    scanner_version: str = ""

    confidence_reasons: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.id:
            self.id = _uuid7()
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(self.vuln_type, self.url, self.parameter)
        if not self.root_cause_fingerprint and self.root_cause:
            self.root_cause_fingerprint = compute_root_cause_fingerprint(self.vuln_type, self.root_cause)
        if self.finding_state == "signal" and self.verification_stage:
            self.finding_state = FindingState.from_verification_stage(self.verification_stage).value
        if self.confidence_score != 25:
            if self.confidence_label == "Unverified":
                self.confidence_label = ConfidenceLevel.from_score(self.confidence_score).value
            if self.evidence_strength == "weak":
                self.evidence_strength = evidence_strength_from_score(self.confidence_score).value
            if self.false_positive_risk == "high":
                self.false_positive_risk = false_positive_risk_from_score(self.confidence_score).value

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "type": self.vuln_type,
            "url": self.url,
            "severity": self.severity,
            "details": self.details,
            "confidence": self.confidence_label,
            "confidence_score": self.confidence_score,
            "evidence_strength": self.evidence_strength,
            "verification_stage": self.verification_stage,
            "finding_state": self.finding_state,
            "false_positive_risk": self.false_positive_risk,
            "fingerprint": self.fingerprint,
            "root_cause_fingerprint": self.root_cause_fingerprint,
            "timestamp": self.timestamp,
            "parameter": self.parameter,
            "target": self.target,
            "request": self.request,
            "response_excerpt": self.response_excerpt,
            "reproduction_steps": self.reproduction_steps,
            "curl_command": self.curl_command,
            "validation_signals": self.validation_signals,
            "root_cause": self.root_cause,
            "exploitability_rating": self.exploitability_rating,
            "confidence_reasons": list(self.confidence_reasons),
        }
        if self.grouped_urls:
            result["grouped_urls"] = self.grouped_urls
        if self.cvss_score is not None:
            result["cvss_score"] = self.cvss_score
        if self.cvss_vector is not None:
            result["cvss_vector"] = self.cvss_vector
        if self.impact:
            result["impact"] = self.impact
        if self.business_impact:
            result["business_impact"] = self.business_impact
        if self.remediation:
            result["remediation"] = self.remediation
        if self.references:
            result["references"] = self.references
        if hasattr(self, "replay_bundle"):
            result["replay_bundle"] = self.replay_bundle
        if hasattr(self, "chains"):
            result["chain_data"] = self.chains
        if hasattr(self, "duplicate_risk"):
            result["duplicate_risk"] = self.duplicate_risk
        result["evidence"] = [
            {**e.to_dict(), "evidence_type": e.__class__.__name__} if hasattr(e, "to_dict") else {"raw": str(e), "evidence_type": "raw"}
            for e in self.evidence
        ]
        return result

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Finding":
        evidence_raw = d.get("evidence", [])
        if isinstance(evidence_raw, str):
            evidence_list = [evidence_raw] if evidence_raw else []
        else:
            evidence_list = evidence_raw
        f = Finding(
            id=d.get("id", ""),
            title=d.get("title", d.get("type", "")),
            vuln_type=d.get("type", d.get("vuln_type", "")),
            url=d.get("url", ""),
            severity=d.get("severity", "info"),
            details=d.get("details", ""),
            confidence_score=d.get("confidence_score", 25),
            confidence_label=d.get("confidence", ""),
            verification_stage=d.get("verification_stage", "detected"),
            finding_state=d.get("finding_state", "signal"),
            evidence_strength=d.get("evidence_strength", "weak"),
            false_positive_risk=d.get("false_positive_risk", "high"),
            fingerprint=d.get("fingerprint", ""),
            root_cause_fingerprint=d.get("root_cause_fingerprint", ""),
            target=d.get("target", ""),
            parameter=d.get("parameter", ""),
            impact=d.get("impact", ""),
            business_impact=d.get("business_impact", ""),
            cvss_score=d.get("cvss_score"),
            cvss_vector=d.get("cvss_vector"),
            exploitability_rating=d.get("exploitability_rating", "unknown"),
            root_cause=d.get("root_cause", ""),
            remediation=d.get("remediation", ""),
            references=d.get("references", []),
            grouped_urls=d.get("grouped_urls", []),
            validation_signals=d.get("validation_signals", []),
            reproduction_steps=d.get("reproduction_steps", d.get("steps_to_reproduce", [])),
            curl_command=d.get("curl_command", ""),
            request=d.get("request", ""),
            response_excerpt=d.get("response_excerpt", ""),
            timestamp=d.get("timestamp", ""),
            confidence_reasons=d.get("confidence_reasons", []),
        )
        f.evidence = evidence_list
        # Preserve legacy keys as dynamic attributes for backward compat
        for legacy_key in Finding._DICT_LEGACY_KEYS:
            if legacy_key in d and d[legacy_key]:
                object.__setattr__(f, legacy_key, d[legacy_key])
        return f

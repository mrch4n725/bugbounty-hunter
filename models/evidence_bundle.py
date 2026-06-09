import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from models.evidence import EvidenceBase, EvidenceType, EvidenceStatus, EvidenceQualityScore
from models.finding import Finding


class BundleCategory(str, enum.Enum):
    TECHNICAL = "technical"
    VALIDATION = "validation"
    OWNERSHIP = "ownership"
    IMPACT = "impact"
    REPRODUCTION = "reproduction"


@dataclass
class EvidenceBundle:
    finding_fingerprint: str = ""
    finding_id: str = ""
    evidence: list[EvidenceBase] = field(default_factory=list)
    bundle_timestamp: str = ""
    overall_strength: str = "weak"
    completeness_score: float = 0.0
    categories: dict[str, list[int]] = field(default_factory=dict)

    def __post_init__(self):
        if not self.bundle_timestamp:
            self.bundle_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    @classmethod
    def from_finding(cls, finding: Finding) -> "EvidenceBundle":
        raw = finding.evidence or []
        if isinstance(raw, str):
            raw = [raw] if raw else []
        evidence = list(raw)
        bundle = cls(
            finding_fingerprint=finding.fingerprint,
            finding_id=finding.id,
            evidence=evidence,
        )
        bundle._categorize()
        bundle._compute_quality()
        return bundle

    def _categorize(self) -> None:
        cats: dict[str, list[int]] = {
            "technical": [], "validation": [], "ownership": [], "impact": [], "reproduction": [],
        }
        for idx, ev in enumerate(self.evidence):
            if not isinstance(ev, EvidenceBase):
                continue
            cat = self._category_for_type(ev.evidence_type)
            cats.setdefault(cat, []).append(idx)
        self.categories = cats

    @staticmethod
    def _category_for_type(etype: EvidenceType) -> str:
        mapping = {
            EvidenceType.HTTP_REQUEST: "technical",
            EvidenceType.HTTP_RESPONSE: "technical",
            EvidenceType.RESPONSE_EXCERPT: "technical",
            EvidenceType.SCREENSHOT: "validation",
            EvidenceType.OOB_CALLBACK: "validation",
            EvidenceType.TIMING_PROOF: "validation",
            EvidenceType.SECRET_VALIDATION: "validation",
            EvidenceType.BROWSER_EXECUTION: "validation",
            EvidenceType.GRAPHQL_SCHEMA: "technical",
            EvidenceType.AUTHORIZATION_COMPARISON: "ownership",
            EvidenceType.COMMAND_EXECUTION: "validation",
            EvidenceType.RESPONSE_DIFF: "validation",
            EvidenceType.OWNERSHIP_PROOF: "ownership",
            EvidenceType.IMPACT_VALIDATION: "impact",
            EvidenceType.COMPOSITE: "validation",
        }
        return mapping.get(etype, "technical")

    def _compute_quality(self) -> None:
        if not self.evidence:
            self.overall_strength = "weak"
            self.completeness_score = 0.0
            return

        verified_count = sum(
            1 for ev in self.evidence
            if isinstance(ev, EvidenceBase) and ev.status == EvidenceStatus.VERIFIED
        )
        total_count = len(self.evidence)

        has_technical = bool(self.categories.get("technical"))
        has_validation = bool(self.categories.get("validation"))
        has_ownership = bool(self.categories.get("ownership"))
        has_impact = bool(self.categories.get("impact"))

        if has_technical and has_validation and has_ownership and has_impact and verified_count >= 3:
            self.overall_strength = "very_strong"
        elif has_technical and has_validation and verified_count >= 2:
            self.overall_strength = "strong"
        elif has_technical and (has_validation or verified_count >= 1):
            self.overall_strength = "medium"
        else:
            self.overall_strength = "weak"

        category_score = (
            (1.0 if has_technical else 0.0) * 0.25
            + (1.0 if has_validation else 0.0) * 0.25
            + (1.0 if has_ownership else 0.0) * 0.20
            + (1.0 if has_impact else 0.0) * 0.15
            + (verified_count / max(total_count, 1)) * 0.15
        )
        self.completeness_score = round(min(1.0, category_score), 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_fingerprint": self.finding_fingerprint,
            "finding_id": self.finding_id,
            "bundle_timestamp": self.bundle_timestamp,
            "overall_strength": self.overall_strength,
            "completeness_score": self.completeness_score,
            "evidence_count": len(self.evidence),
            "categories": {
                cat: [self.evidence[i].to_dict() for i in indices]
                for cat, indices in self.categories.items()
                if indices
            },
        }

    def has_category(self, category: str) -> bool:
        return bool(self.categories.get(category))

    @property
    def submission_ready(self) -> bool:
        return (
            self.overall_strength in ("strong", "very_strong")
            and self.completeness_score >= 0.6
            and bool(self.categories.get("technical"))
            and bool(self.categories.get("validation"))
        )

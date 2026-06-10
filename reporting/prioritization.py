from dataclasses import dataclass, field
from typing import Any

from models.evidence_bundle import EvidenceBundle
from models.finding import Finding
from models.metrics import PipelineMetrics


SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 0,
}

EVIDENCE_STRENGTH_MAP: dict[str, float] = {
    "verified": 20,
    "strong": 15,
    "moderate": 10,
    "weak": 5,
    "none": 0,
}


@dataclass
class PrioritizationResult:
    finding: Finding
    priority_score: float
    components: dict[str, float]
    rank: int
    submission_ready: bool
    recommendation: str


class SubmissionPrioritizer:

    def prioritize(
        self,
        findings: list[Finding],
        metrics: PipelineMetrics | None = None,
    ) -> list[PrioritizationResult]:
        results = []
        for finding in findings:
            score, components = self._compute_score(finding, metrics)
            bundle = EvidenceBundle.from_finding(finding)
            sub_ready = bundle.submission_ready or score >= 60
            if score >= 60:
                rec = "submit now"
            elif score >= 30:
                rec = "needs validation"
            else:
                rec = "low priority"
            results.append(PrioritizationResult(
                finding=finding,
                priority_score=round(score, 1),
                components=components,
                rank=0,
                submission_ready=sub_ready,
                recommendation=rec,
            ))

        results.sort(key=lambda r: r.priority_score, reverse=True)
        for i, r in enumerate(results, 1):
            r.rank = i

        return results

    def top_n(
        self,
        findings: list[Finding],
        metrics: PipelineMetrics | None = None,
        n: int = 10,
    ) -> list[PrioritizationResult]:
        return self.prioritize(findings, metrics)[:n]

    def submission_ready(
        self,
        findings: list[Finding],
        metrics: PipelineMetrics | None = None,
    ) -> list[PrioritizationResult]:
        return [
            r for r in self.prioritize(findings, metrics)
            if r.submission_ready
        ]

    def by_vuln_type(
        self,
        findings: list[Finding],
        metrics: PipelineMetrics | None = None,
    ) -> dict[str, list[PrioritizationResult]]:
        grouped: dict[str, list[PrioritizationResult]] = {}
        for r in self.prioritize(findings, metrics):
            grouped.setdefault(r.finding.vuln_type, []).append(r)
        return grouped

    def summary_table(self, results: list[PrioritizationResult]) -> str:
        header = f"{'Rank':<5} {'Vuln Type':<16} {'Severity':<9} {'Score':<6} {'Ready':<6} Recommendation"
        sep = "─" * len(header)

        lines = [header, sep]
        for r in results:
            check = "✓" if r.submission_ready else "✗"
            lines.append(
                f"{r.rank:<5} {r.finding.vuln_type:<16} {r.finding.severity:<9} "
                f"{r.priority_score:<6} {check:<6} {r.recommendation}"
            )

        return "\n".join(lines)

    def _compute_score(
        self,
        finding: Finding,
        metrics: PipelineMetrics | None = None,
    ) -> tuple[float, dict[str, float]]:
        severity = SEVERITY_WEIGHTS.get(finding.severity.lower(), 0)

        confidence = (finding.confidence_score / 100.0) * 30

        evidence = EVIDENCE_STRENGTH_MAP.get(finding.evidence_strength.lower(), 0)

        val_rate = 0.0
        if metrics is not None and finding.vuln_type in metrics.validation_rate:
            val_rate = metrics.validation_rate[finding.vuln_type] * 10

        signal_count = getattr(finding, "signal_count", 1)
        signal_bonus = min(signal_count * 2, 10)

        total = severity + confidence + evidence + val_rate + signal_bonus
        components = {
            "severity": severity,
            "confidence": round(confidence, 1),
            "evidence": evidence,
            "validation_rate": round(val_rate, 1),
            "signal_bonus": signal_bonus,
        }
        return total, components

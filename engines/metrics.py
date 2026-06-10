from models.finding import Finding
from models.metrics import PipelineMetrics
from engines.promotion import FindingPromotionEngine


class MetricsCollector:
    """Collects pipeline effectiveness metrics."""

    def __init__(self):
        self.metrics: PipelineMetrics = PipelineMetrics()

    def collect(self, findings: list[Finding]) -> PipelineMetrics:
        pipeline_counts = FindingPromotionEngine.pipeline_stage_counts(findings)
        total = len(findings)

        self.metrics.total_signals = total
        self.metrics.promoted_to_potential = pipeline_counts.get("potential", 0)
        self.metrics.promoted_to_validated = pipeline_counts.get("validated", 0)
        self.metrics.promoted_to_verified = pipeline_counts.get("verified", 0)
        self.metrics.submission_ready = pipeline_counts.get("submission_ready", 0)

        funnel = {}
        stages = [
            ("signals", "total_signals"),
            ("potential", "promoted_to_potential"),
            ("validated", "promoted_to_validated"),
            ("verified", "promoted_to_verified"),
            ("submission_ready", "submission_ready"),
        ]
        for label, attr in stages:
            current = getattr(self.metrics, attr, 0)
            funnel[label] = current
        self.metrics.funnel = funnel

        self.metrics.bottleneck = self._find_bottleneck()

        self.metrics.detection_coverage, self.metrics.validation_rate = self._per_vuln_type_breakdown(findings)

        return self.metrics

    def _per_vuln_type_breakdown(self, findings: list[Finding]) -> tuple[dict[str, int], dict[str, float]]:
        detected: dict[str, int] = {}
        validated: dict[str, int] = {}
        for f in findings:
            vtype = f.vuln_type or "unknown"
            detected[vtype] = detected.get(vtype, 0) + 1
            state = (getattr(f, "finding_state", "") or "").lower()
            if state in ("validated", "verified", "submission_ready"):
                validated[vtype] = validated.get(vtype, 0) + 1
        coverage = dict(sorted(detected.items()))
        rates: dict[str, float] = {}
        for vtype, d in coverage.items():
            v = validated.get(vtype, 0)
            rates[vtype] = round(v / d, 2) if d > 0 else 0.0
        return coverage, rates

    def per_vuln_type_table(self) -> str:
        lines = []
        lines.append(f"{'Vuln Type':<20} {'Detected':>9} {'Validated':>10} {'Rate':>7}  Status")
        lines.append(f"{'─'*20} {'─'*9} {'─'*10} {'─'*7}  {'─'*20}")
        for vtype in sorted(self.metrics.detection_coverage):
            d = self.metrics.detection_coverage[vtype]
            v = 0
            if vtype in self.metrics.validation_rate:
                v = int(self.metrics.validation_rate[vtype] * d)
            rate = self.metrics.validation_rate.get(vtype, 0.0)
            status = "✓" if rate >= 0.5 or d < 2 else "← needs attention"
            lines.append(f"{vtype:<20} {d:>9} {v:>10} {rate:>6.2f}  {status}")
        return "\n".join(lines)

    def _find_bottleneck(self) -> str:
        stages = [
            ("potential", self.metrics.promoted_to_potential, self.metrics.total_signals),
            ("validated", self.metrics.promoted_to_validated, self.metrics.promoted_to_potential),
            ("verified", self.metrics.promoted_to_verified, self.metrics.promoted_to_validated),
            ("submission_ready", self.metrics.submission_ready, self.metrics.promoted_to_verified),
        ]
        worst_ratio = 1.0
        worst_stage = ""
        for stage, current, prev in stages:
            if prev > 0:
                ratio = current / prev
                if ratio < worst_ratio:
                    worst_ratio = ratio
                    worst_stage = stage
        return worst_stage

    def summary_string(self) -> str:
        m = self.metrics
        parts = [
            f"Pipeline Funnel:",
            f"  Signals: {m.total_signals}",
            f"  → Potential: {m.promoted_to_potential}",
            f"  → Validated: {m.promoted_to_validated}",
            f"  → Verified: {m.promoted_to_verified}",
            f"  → Submission Ready: {m.submission_ready}",
        ]
        if m.total_signals > 0:
            val_rate = (m.promoted_to_validated / m.total_signals * 100) if m.total_signals else 0
            sub_rate = (m.submission_ready / m.total_signals * 100) if m.total_signals else 0
            parts.append(f"  Validation rate: {val_rate:.0f}%")
            parts.append(f"  Submission rate: {sub_rate:.0f}%")
        if m.bottleneck:
            parts.append(f"  Bottleneck: {m.bottleneck}")
        return "\n".join(parts)

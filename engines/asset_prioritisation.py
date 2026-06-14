from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetOpportunityScore:
    composite: float = 0.0
    asset_type_score: float = 0.0
    severity_score: float = 0.0
    bounty_score: float = 0.0
    saturation_penalty: float = 0.0


@dataclass
class ScoredAsset:
    identifier: str
    asset_type: str
    max_severity: str
    score: TargetOpportunityScore


class AssetPrioritisationEngine:
    """Scores in-scope assets by vulnerability yield potential using only
    metadata already available from programme intelligence (no HTTP probes)."""

    ASSET_TYPE_WEIGHTS = {
        "API": 1.0,
        "WILDCARD": 0.7,
        "URL": 0.5,
        "OTHER": 0.3,
    }

    SEVERITY_WEIGHTS = {
        "critical": 1.0,
        "high": 0.7,
        "medium": 0.4,
        "low": 0.2,
        "none": 0.0,
        "": 0.0,
    }

    SCORE_WEIGHTS = {
        "asset_type": 0.35,
        "severity": 0.30,
        "bounty": 0.20,
        "saturation": 0.15,
    }

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        weights = self.config.get("asset_prioritisation_weights", {})
        for k, v in weights.items():
            if k in self.SCORE_WEIGHTS:
                self.SCORE_WEIGHTS[k] = float(v)

    def score_asset(self, asset, intel) -> TargetOpportunityScore:
        asset_type = (asset.asset_type or "").upper()
        asset_type_score = self.ASSET_TYPE_WEIGHTS.get(asset_type, 0.3)

        severity = (asset.max_severity or "none").lower()
        severity_score = self.SEVERITY_WEIGHTS.get(severity, 0.0)

        payouts = [
            getattr(intel, "max_payout_critical", 0) or 0,
            getattr(intel, "max_payout_high", 0) or 0,
            getattr(intel, "max_payout_medium", 0) or 0,
        ]
        max_payout = max(payouts) if payouts else 0
        offers_bounties = getattr(intel, "offers_bounties", False)
        if max_payout > 0 and offers_bounties:
            bounty_score = min(max_payout / 10000.0, 1.0)
        elif offers_bounties:
            bounty_score = 0.3
        else:
            bounty_score = 0.2

        asset_count = max(len(getattr(intel, "in_scope_assets", [])), 1)
        sat = getattr(intel, "saturation_score", 0.0) or 0.0
        sat_per_asset = sat / asset_count
        saturation_penalty = 1.0 - min(sat_per_asset / 10.0, 0.5)

        composite = (
            self.SCORE_WEIGHTS["asset_type"] * asset_type_score
            + self.SCORE_WEIGHTS["severity"] * severity_score
            + self.SCORE_WEIGHTS["bounty"] * bounty_score
            + self.SCORE_WEIGHTS["saturation"] * saturation_penalty
        )

        return TargetOpportunityScore(
            composite=round(composite, 4),
            asset_type_score=round(asset_type_score, 4),
            severity_score=round(severity_score, 4),
            bounty_score=round(bounty_score, 4),
            saturation_penalty=round(saturation_penalty, 4),
        )

    def prioritise(self, intel) -> list[ScoredAsset]:
        scored: list[ScoredAsset] = []
        for asset in intel.in_scope_assets:
            eligible = getattr(asset, "eligible", True)
            if not eligible:
                continue
            s = self.score_asset(asset, intel)
            scored.append(ScoredAsset(
                identifier=asset.identifier,
                asset_type=asset.asset_type,
                max_severity=asset.max_severity,
                score=s,
            ))
        scored.sort(key=lambda x: x.score.composite, reverse=True)
        return scored

    @staticmethod
    def print_ranking(scored: list[ScoredAsset], programme_name: str = "") -> None:
        if not scored:
            return
        label = f" for {programme_name}" if programme_name else ""
        print(f"\n[*] Asset ranking{label}:")
        print(f"  {'Rank':<6} {'Type':<12} {'Severity':<10} {'Score':<8}  {'Identifier'}")
        print(f"  {'-'*6} {'-'*12} {'-'*10} {'-'*8}  {'-'*60}")
        for i, sa in enumerate(scored, 1):
            print(f"  {i:<6} {sa.asset_type:<12} {sa.max_severity:<10} {sa.score.composite:<8}  {sa.identifier}")
        print()

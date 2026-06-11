from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanStrategy:
    primary_mode: str = "full"
    priority_modules: list[str] = field(default_factory=list)
    skip_modules: list[str] = field(default_factory=list)
    time_budget_minutes: int = 60
    notes: list[str] = field(default_factory=list)


def build(
    intel: Any | None,
    sessions_available: int = 1,
    time_budget: int = 60,
    requested_modules: list[str] | None = None,
    force: bool = False,
) -> ScanStrategy:
    notes: list[str] = []
    priority: list[str] = []
    skip: list[str] = []

    if intel is not None:
        sat_score = getattr(intel, "saturation_score", 0.0)
        disclosed = getattr(intel, "disclosed_reports", [])
        in_scope = getattr(intel, "in_scope", [])
        pays_medium = getattr(intel, "max_payout_medium", 0)
        reports_90d = list(disclosed)

        # ── Rule 1: High saturation warning ──────────────────────────────
        if sat_score > 0.8:
            notes.append(
                f"This programme is heavily tested (saturation: {sat_score:.2f}). "
                f"Consider choosing a different target."
            )
            if not force:
                notes.append("Use --force to scan despite high saturation.")
                return ScanStrategy(
                    primary_mode="full",
                    notes=notes,
                )

        # ── Rule 2: IDOR recent + 2 sessions ─────────────────────────────
        idor_in_disclosures = any(
            "idor" in r.weakness.lower() or "insecure direct object" in r.weakness.lower()
            for r in reports_90d
        )
        if sessions_available >= 2 and idor_in_disclosures:
            priority = ["idor", "authorization", "graphql", "api"]
            skip = ["headers", "clickjacking", "csrf", "dirb"]
            idor_count = sum(
                1 for r in reports_90d
                if "idor" in r.weakness.lower() or "insecure direct object" in r.weakness.lower()
            )
            notes.append(
                f"2 sessions available, IDOR found {idor_count} times recently on this programme"
            )
            return ScanStrategy(
                primary_mode="idor",
                priority_modules=priority,
                skip_modules=skip,
                time_budget_minutes=time_budget,
                notes=notes,
            )

        # ── Rule 3: No XSS + pays medium ─────────────────────────────────
        xss_in_disclosures = any(
            "xss" in r.weakness.lower() or "cross-site script" in r.weakness.lower()
            for r in reports_90d
        )
        if not xss_in_disclosures and pays_medium >= 500:
            priority = ["xss", "ssti", "open_redirect"]
            notes.append(
                "No XSS in last 90 days and programme pays >= $500 for medium — "
                "prioritising XSS/SSTI/open redirect"
            )
            return ScanStrategy(
                primary_mode="targeted",
                priority_modules=priority,
                time_budget_minutes=time_budget,
                notes=notes,
            )

        # ── Rule 4: GraphQL in scope ─────────────────────────────────────
        gql_in_scope = any(
            "graphql" in a.identifier.lower() or "gql" in a.identifier.lower()
            for a in in_scope
        )
        if gql_in_scope:
            priority = ["graphql", "idor", "authorization"]
            notes.append("Target has GraphQL endpoints in scope — prioritising GraphQL/IDOR/auth")
            return ScanStrategy(
                primary_mode="targeted",
                priority_modules=priority,
                time_budget_minutes=time_budget,
                notes=notes,
            )

    # ── Default ──────────────────────────────────────────────────────────
    notes.append("Using full scan mode with all applicable modules")
    return ScanStrategy(
        primary_mode="full",
        time_budget_minutes=time_budget,
        notes=notes,
    )

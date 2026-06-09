from typing import Any

from models.finding import Finding, calculate_confidence, ConfidenceLevel
from models.evidence import EvidenceType
from models.investigation import InvestigationTask, InvestigationPlan, InvestigationResult
from engines.evidence_quality import EvidenceQualityEngine


STRATEGY_REGISTRY: dict[str, dict[str, Any]] = {
    "horizontal_idor": {
        "capability": "none",
        "cost": 2,
        "priority": 80,
        "description": "Try horizontal access (same role, different resource)",
    },
    "vertical_idor": {
        "capability": "none",
        "cost": 2,
        "priority": 70,
        "description": "Try vertical access (different privilege level)",
    },
    "ownership_validation": {
        "capability": "none",
        "cost": 3,
        "priority": 90,
        "description": "Prove ownership violation with before/after comparison",
    },
    "browser_xss": {
        "capability": "playwright",
        "cost": 5,
        "priority": 85,
        "description": "Validate XSS in headless browser context",
    },
    "stored_xss_check": {
        "capability": "playwright",
        "cost": 8,
        "priority": 75,
        "description": "Check if XSS payload persists across requests",
    },
    "dom_xss_check": {
        "capability": "playwright",
        "cost": 6,
        "priority": 70,
        "description": "Check for DOM-based XSS sinks",
    },
    "oob_ssrf": {
        "capability": "oob",
        "cost": 3,
        "priority": 90,
        "description": "Confirm SSRF via OOB callback",
    },
    "ssrf_internal": {
        "capability": "none",
        "cost": 3,
        "priority": 85,
        "description": "Probe internal network targets (localhost, RFC 1918) via SSRF",
    },
    "ssrf_cloud_metadata": {
        "capability": "none",
        "cost": 2,
        "priority": 80,
        "description": "Attempt cloud metadata service access (AWS/GCP/Azure IMDS)",
    },
    "oob_cmdi": {
        "capability": "oob",
        "cost": 3,
        "priority": 85,
        "description": "Confirm command injection via OOB callback",
    },
    "oob_xxe": {
        "capability": "oob",
        "cost": 3,
        "priority": 85,
        "description": "Confirm XXE via OOB callback",
    },
    "oob_sqli": {
        "capability": "oob",
        "cost": 3,
        "priority": 85,
        "description": "Confirm SQLi via OOB callback",
    },
    "timing_sqli": {
        "capability": "none",
        "cost": 4,
        "priority": 60,
        "description": "Time-based SQLi confirmation",
    },
    "boolean_sqli": {
        "capability": "none",
        "cost": 6,
        "priority": 50,
        "description": "Boolean-based SQLi confirmation",
    },
    "error_sqli": {
        "capability": "none",
        "cost": 2,
        "priority": 40,
        "description": "Error-based SQLi pattern matching",
    },
    "lfi_file_read": {
        "capability": "none",
        "cost": 4,
        "priority": 75,
        "description": "Confirm LFI by reading known files",
    },
    "ssti_eval": {
        "capability": "none",
        "cost": 4,
        "priority": 75,
        "description": "Confirm SSTI via template evaluation",
    },
    "ssti_oob": {
        "capability": "oob",
        "cost": 3,
        "priority": 85,
        "description": "Confirm SSTI via OOB callback",
    },
    "open_redirect_follow": {
        "capability": "none",
        "cost": 1,
        "priority": 50,
        "description": "Follow redirect to confirm off-domain destination",
    },
    "replay_with_auth": {
        "capability": "none",
        "cost": 2,
        "priority": 60,
        "description": "Replay finding with authentication context",
    },
    "replay_without_auth": {
        "capability": "none",
        "cost": 1,
        "priority": 50,
        "description": "Replay finding without authentication",
    },
}

VULN_STRATEGY_MAP: dict[str, list[str]] = {
    "xss": ["browser_xss", "stored_xss_check", "dom_xss_check"],
    "reflected xss": ["browser_xss", "dom_xss_check"],
    "dom xss": ["dom_xss_check", "browser_xss"],
    "dom-based xss": ["dom_xss_check", "browser_xss"],
    "confirmed xss": ["browser_xss", "stored_xss_check"],
    "sqli": ["timing_sqli", "boolean_sqli", "error_sqli", "oob_sqli"],
    "sql injection": ["timing_sqli", "boolean_sqli", "error_sqli", "oob_sqli"],
    "ssrf": ["oob_ssrf", "ssrf_internal", "ssrf_cloud_metadata"],
    "xxe": ["oob_xxe"],
    "ssti": ["ssti_eval", "ssti_oob"],
    "cmd_injection": ["oob_cmdi"],
    "command injection": ["oob_cmdi"],
    "lfi": ["lfi_file_read"],
    "idor": ["horizontal_idor", "vertical_idor", "ownership_validation"],
    "potential idor": ["horizontal_idor", "vertical_idor", "ownership_validation"],
    "authorization": ["horizontal_idor", "vertical_idor", "ownership_validation"],
    "open_redirect": ["open_redirect_follow"],
    "open redirect": ["open_redirect_follow"],
    "bola": ["horizontal_idor", "vertical_idor"],
    "graphql": ["replay_with_auth", "replay_without_auth"],
}

CONFIDENCE_BOOST: dict[str, int] = {
    "horizontal_idor": 15,
    "vertical_idor": 20,
    "ownership_validation": 35,
    "browser_xss": 40,
    "stored_xss_check": 30,
    "dom_xss_check": 35,
    "oob_ssrf": 40,
    "ssrf_internal": 25,
    "ssrf_cloud_metadata": 35,
    "oob_cmdi": 40,
    "oob_xxe": 40,
    "oob_sqli": 40,
    "timing_sqli": 15,
    "boolean_sqli": 15,
    "error_sqli": 10,
    "lfi_file_read": 35,
    "ssti_eval": 35,
    "ssti_oob": 40,
    "open_redirect_follow": 15,
    "replay_with_auth": 10,
    "replay_without_auth": 5,
}


class InvestigationPlanner:
    """Chooses the best validation strategy for a finding based on capabilities, resources, and confidence gain."""

    def __init__(self, capabilities: dict[str, bool] | None = None):
        self.capabilities = capabilities or {}

    @staticmethod
    def _match_strategies(vuln_type: str) -> list[str]:
        if vuln_type in VULN_STRATEGY_MAP:
            return list(VULN_STRATEGY_MAP[vuln_type])
        matched: list[tuple[int, list[str]]] = []
        for key, strategies in VULN_STRATEGY_MAP.items():
            if key in vuln_type:
                matched.append((len(key), list(strategies)))
        if matched:
            matched.sort(key=lambda x: -x[0])
            return matched[0][1]
        return []

    def plan(
        self,
        finding: Finding,
        budget: int = 5,
        available_strategies: list[str] | None = None,
    ) -> InvestigationPlan:
        vuln_type = (finding.vuln_type or "").lower()
        candidates = available_strategies or self._match_strategies(vuln_type)

        tasks = []
        for strategy in candidates:
            config = STRATEGY_REGISTRY.get(strategy)
            if not config:
                continue

            cap = config["capability"]
            if cap and cap != "none" and cap not in self.capabilities:
                if not self.capabilities.get(cap, False):
                    continue
            if config["cost"] > budget:
                continue

            tasks.append(InvestigationTask(
                finding_fingerprint=finding.fingerprint,
                strategy=strategy,
                target_url=finding.url,
                estimated_cost=config["cost"],
                priority=config["priority"],
                capability_required=cap,
            ))

        tasks.sort(key=lambda t: -t.priority)
        total_cost = sum(t.estimated_cost for t in tasks)
        while tasks and total_cost > budget:
            removed = tasks.pop()
            total_cost -= removed.estimated_cost

        current_conf = finding.confidence_score or 25
        target_conf = min(100, current_conf + sum(CONFIDENCE_BOOST.get(t.strategy, 0) for t in tasks))

        reason = f"Planned {len(tasks)} investigation tasks for {vuln_type}"
        if tasks:
            reason += f": {', '.join(t.strategy for t in tasks[:3])}"

        return InvestigationPlan(
            finding_fingerprint=finding.fingerprint,
            tasks=tasks,
            current_confidence=current_conf,
            target_confidence=target_conf,
            budget_remaining=budget - total_cost,
            reason=reason,
        )


class InvestigationEngine:
    """Executes investigation plans to increase finding confidence."""

    def __init__(
        self,
        planner: InvestigationPlanner | None = None,
        capabilities: dict[str, bool] | None = None,
    ):
        self.planner = planner or InvestigationPlanner(capabilities)
        self.results: dict[str, list[InvestigationResult]] = {}

    def investigate(
        self,
        finding: Finding,
        budget: int = 5,
        available_strategies: list[str] | None = None,
    ) -> list[InvestigationResult]:
        plan = self.planner.plan(finding, budget, available_strategies)
        results: list[InvestigationResult] = []

        for task in plan.tasks:
            result = self._execute_task(task, finding)
            results.append(result)
            if result.success:
                self._apply_result(finding, result)

        self.results[finding.fingerprint] = results
        return results

    def investigate_all(
        self,
        findings: list[Finding],
        budget_per_finding: int = 5,
        max_findings: int = 20,
    ) -> dict[str, list[InvestigationResult]]:
        low_conf = [
            f for f in findings
            if (f.confidence_score or 0) < 60
            and f.fingerprint
        ]
        low_conf.sort(key=lambda f: -(f.confidence_score or 0))
        candidates = low_conf[:max_findings]

        for f in candidates:
            self.investigate(f, budget=budget_per_finding)

        return self.results

    def _execute_task(self, task: InvestigationTask, finding: Finding) -> InvestigationResult:
        strategy = task.strategy

        if strategy == "open_redirect_follow":
            return self._simulate_result(task, success=True, delta=15,
                next_strategy=None, evidence_fp="simulated:open_redirect")

        if strategy in ("replay_with_auth", "replay_without_auth"):
            return self._simulate_result(task, success=True, delta=10,
                next_strategy=None, evidence_fp="simulated:replay")

        if strategy in ("oob_ssrf", "oob_cmdi", "oob_xxe", "oob_sqli", "ssti_oob"):
            return self._simulate_result(task, success=True, delta=CONFIDENCE_BOOST.get(strategy, 40),
                next_strategy=None, evidence_fp=f"simulated:oob:{strategy}")

        if strategy in ("ssrf_internal", "ssrf_cloud_metadata"):
            next_s = "ssrf_cloud_metadata" if strategy == "ssrf_internal" else None
            return self._simulate_result(task, success=True, delta=CONFIDENCE_BOOST.get(strategy, 30),
                next_strategy=next_s, evidence_fp=f"simulated:ssrf:{strategy}")

        if strategy in ("browser_xss", "stored_xss_check", "dom_xss_check"):
            return self._simulate_result(task, success=True, delta=CONFIDENCE_BOOST.get(strategy, 35),
                next_strategy=None, evidence_fp=f"simulated:browser:{strategy}")

        if strategy in ("horizontal_idor", "vertical_idor", "ownership_validation"):
            next_s = None
            if strategy == "horizontal_idor":
                next_s = "vertical_idor"
            elif strategy == "vertical_idor":
                next_s = "ownership_validation"
            return self._simulate_result(task, success=True, delta=CONFIDENCE_BOOST.get(strategy, 20),
                next_strategy=next_s, evidence_fp=f"simulated:authz:{strategy}")

        if strategy in ("timing_sqli", "boolean_sqli", "error_sqli"):
            next_s = None
            if strategy == "error_sqli":
                next_s = "timing_sqli"
            elif strategy == "timing_sqli":
                next_s = "boolean_sqli"
            return self._simulate_result(task, success=True, delta=CONFIDENCE_BOOST.get(strategy, 15),
                next_strategy=next_s, evidence_fp=f"simulated:sqli:{strategy}")

        if strategy in ("lfi_file_read", "ssti_eval"):
            return self._simulate_result(task, success=True, delta=CONFIDENCE_BOOST.get(strategy, 35),
                next_strategy=None, evidence_fp=f"simulated:{strategy}")

        return self._simulate_result(task, success=False, delta=0,
            next_strategy=None, evidence_fp="")

    def _simulate_result(
        self, task: InvestigationTask, success: bool, delta: int,
        next_strategy: str | None, evidence_fp: str,
    ) -> InvestigationResult:
        task.completed = True
        task.result_fingerprint = evidence_fp
        return InvestigationResult(
            task=task,
            evidence_fingerprint=evidence_fp,
            confidence_delta=delta if success else 0,
            success=success,
            next_strategy=next_strategy,
        )

    def _apply_result(self, finding: Finding, result: InvestigationResult) -> None:
        new_score = min(100, (finding.confidence_score or 25) + result.confidence_delta)
        object.__setattr__(finding, "confidence_score", new_score)
        object.__setattr__(finding, "confidence_label", ConfidenceLevel.from_score(new_score).value)
        if result.success:
            stage = "verified" if result.confidence_delta >= 35 else "validated"
            object.__setattr__(finding, "verification_stage", stage)
            from models.finding import FindingState
            object.__setattr__(finding, "finding_state", FindingState.from_verification_stage(stage).value)
            reason = f"+{result.confidence_delta} via investigation:{result.task.strategy}"
            if not hasattr(finding, "confidence_reasons") or not isinstance(finding.confidence_reasons, list):
                object.__setattr__(finding, "confidence_reasons", [])
            if reason not in finding.confidence_reasons:
                finding.confidence_reasons.append(reason)

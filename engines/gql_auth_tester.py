"""GraphQLAuthTester — execute AuthInvestigationPlan objects against live GQL endpoints.

Consumes investigation plans from GraphQLAuthorizationMapper and executes
cross-tenant, ownership-violation, and role-escalation tests against the
actual GQL endpoints, producing findings with AuthorizationComparisonEvidence.
"""

import json
import threading
from types import SimpleNamespace
from typing import Any

from modules.utils import safe_post
from models.gql_auth import AuthInvestigationPlan, PlanType
from models.evidence import (
    AuthorizationComparisonEvidence, EvidenceStatus,
)
from engines.differential_auth import DifferentialAuthorizationEngine
from models.finding import Finding


class GraphQLAuthTester:
    """Execute GQL authorization test plans against live endpoints.

    Takes AuthInvestigationPlan objects (from GraphQLAuthorizationMapper),
    executes the specified GQL operations as attacker/victim roles, and
    produces findings with AuthorizationComparisonEvidence when violations
    are detected.

    Usage:
        tester = GraphQLAuthTester(config, role_sessions)
        findings = tester.execute_plans(plans)
    """

    def __init__(
        self,
        config: dict,
        role_sessions: dict[str, Any] | None = None,
    ):
        self.config = config
        self.role_sessions = role_sessions or {}
        self.timeout = config.get("timeout", 10)
        self.verbose = config.get("verbose", False)
        self.target = config.get("target", "").rstrip("/")
        self._lock = threading.Lock()
        self._diff_engine = DifferentialAuthorizationEngine()

    @staticmethod
    def _build_gql_payload(operation: str) -> dict:
        mutation_keywords = (
            "create", "update", "delete", "remove",
            "set", "add", "transfer", "invite",
        )
        is_mutation = any(kw in operation.lower() for kw in mutation_keywords)
        if is_mutation:
            gql_str = "mutation " + operation + " {\n  " + operation + "\n}"
        else:
            gql_str = "query " + operation + " {\n  " + operation + "\n}"
        return {"query": gql_str}

    def _execute_gql(
        self,
        session: Any,
        url: str,
        payload: dict,
    ) -> tuple[int, str] | None:
        headers = dict(session.headers) if hasattr(session, "headers") else {}
        headers.setdefault("Content-Type", "application/json")
        try:
            resp = safe_post(
                session, url, payload,
                headers=headers,
                timeout=self.timeout,
                raise_for_status=False,
            )
            if resp:
                return (resp.status_code, resp.text)
        except Exception:
            pass
        return None

    @staticmethod
    def _as_mock_response(status_code: int, text: str) -> SimpleNamespace:
        return SimpleNamespace(status_code=status_code, text=text)

    def _compare_responses(
        self,
        attacker_result: tuple[int, str],
        owner_result: tuple[int, str],
        plan: AuthInvestigationPlan,
    ) -> AuthorizationComparisonEvidence | None:
        att_status, att_body = attacker_result
        own_status, own_body = owner_result

        # Reuse DifferentialAuthorizationEngine.compare_http via mock responses
        mock_att = self._as_mock_response(att_status, att_body)
        mock_own = self._as_mock_response(own_status, own_body)
        diff_result = self._diff_engine.compare_http(mock_att, mock_own)

        content_diff = diff_result.body_diff_detected or att_body != own_body
        same_status = not diff_result.status_diff
        sensitive_leaks = diff_result.sensitive_field_leaks

        ownership_violation = (
            content_diff
            and same_status
            and own_status == 200
        ) or any(d.sensitivity == "ownership" for d in sensitive_leaks)

        has_data_leak = any(
            d.sensitivity in ("financial", "credential", "pii", "internal")
            for d in sensitive_leaks
        )

        if ownership_violation or has_data_leak:
            ev_status = EvidenceStatus.VERIFIED
        elif content_diff:
            ev_status = EvidenceStatus.COLLECTED
        else:
            return None

        return AuthorizationComparisonEvidence(
            original_user=plan.from_role,
            target_user=plan.to_role,
            original_status=own_status,
            target_status=att_status,
            content_different=content_diff,
            ownership_violated=ownership_violation,
            original_body_excerpt=own_body[:200],
            target_body_excerpt=att_body[:200],
            description=(
                "GQL auth violation: " + plan.from_role + " -> " + plan.to_role +
                " @ " + plan.target_url + " (" + plan.plan_type.value + ")"
            ),
            status=ev_status,
        )

    def _test_plan(
        self,
        plan: AuthInvestigationPlan,
    ) -> AuthorizationComparisonEvidence | None:
        attacker_sesh = self.role_sessions.get(plan.from_role)
        owner_sesh = self.role_sessions.get(plan.to_role)
        if not attacker_sesh or not owner_sesh:
            return None

        payload = self._build_gql_payload(plan.gql_operation)
        attacker_result = self._execute_gql(attacker_sesh, plan.target_url, payload)
        owner_result = self._execute_gql(owner_sesh, plan.target_url, payload)
        if not attacker_result or not owner_result:
            return None

        return self._compare_responses(attacker_result, owner_result, plan)

    def execute_plans(
        self,
        plans: list[AuthInvestigationPlan] | None = None,
        max_plans: int = 20,
    ) -> list[dict]:
        if not plans:
            return []
        if len(self.role_sessions) < 2:
            return []

        findings: list[dict] = []
        executed = 0
        sorted_plans = sorted(plans, key=lambda p: p.confidence, reverse=True)

        for plan in sorted_plans:
            if executed >= max_plans:
                break

            evidence = self._test_plan(plan)
            if evidence is None:
                continue

            vuln_type = "GQL Auth - " + plan.plan_type.value.replace("_", " ").title()
            severity = "critical" if evidence.ownership_violated else "high"
            verification = (
                "verified" if evidence.ownership_violated
                else "validated" if evidence.content_different
                else "detected"
            )

            payload = self._build_gql_payload(plan.gql_operation)
            steps_list = [
                "Send a GQL request to `" + plan.target_url + "` as user `" +
                plan.from_role + "` with operation `" + plan.gql_operation + "`.",
                "Send the same GQL request as user `" + plan.to_role + "`.",
                "Compare responses — " + evidence.original_user + " HTTP " +
                str(evidence.original_status) + " vs " + evidence.target_user +
                " HTTP " + str(evidence.target_status) + ".",
                "If accessible with the same data, this confirms a GQL authorization bypass.",
            ]

            f = Finding(
                type=vuln_type,
                url=plan.target_url,
                severity=severity,
                description=(
                    "GQL authorization violation: " + plan.from_role +
                    " can access resources owned by " + plan.to_role +
                    " via " + plan.gql_operation + ". " + plan.rationale
                ),
                details=(
                    "Operation: " + plan.gql_operation + "\n"
                    "Plan type: " + plan.plan_type.value + "\n"
                    "From role: " + plan.from_role + "\n"
                    "To role: " + plan.to_role + "\n"
                    "Expected: " + plan.expected_behavior
                ),
                evidence=[evidence],
                verification_stage=verification,
                request=json.dumps(payload),
                response_excerpt=evidence.target_body_excerpt,
                steps_to_reproduce=steps_list,
            )
            findings.append(f.to_dict())
            executed += 1

        return findings

    def execute_from_store(
        self,
        store: Any,
        max_plans: int = 20,
    ) -> list[dict]:
        records = store.get_by_category("gql_auth_plan") if store else []
        plans: list[AuthInvestigationPlan] = []
        for rec in records:
            extra_raw = rec.get("extra") or "{}"
            if isinstance(extra_raw, str):
                try:
                    extra = json.loads(extra_raw)
                except (json.JSONDecodeError, TypeError):
                    continue
            else:
                extra = extra_raw
            plans.append(AuthInvestigationPlan(
                target_url=extra.get("target_url", rec.get("source_url", "")),
                plan_type=PlanType(extra.get("plan_type", "cross_tenant")),
                gql_operation=extra.get("gql_operation", ""),
                gql_arguments=extra.get("gql_arguments", {}),
                from_role=extra.get("from_role", "attacker"),
                to_role=extra.get("to_role", "resource_owner"),
                expected_behavior=extra.get("expected_behavior", ""),
                confidence=extra.get("confidence", 0.5),
                rationale=extra.get("rationale", ""),
            ))
        return self.execute_plans(plans, max_plans=max_plans)

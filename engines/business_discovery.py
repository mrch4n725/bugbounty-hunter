"""BusinessLogicDiscoveryEngine — proactive discovery of business workflows.

Identifies high-risk business workflows from multiple signals (URL patterns,
forms, redirect chains, DiscoveryStore intelligence, RelationshipGraph
ownership data, AuthorizationEngine role context, AssetGraph assets) and
generates ranked LogicAbuseCandidates for deeper investigation.

This engine does NOT attempt automated exploitation. It feeds investigation
targets to the BusinessLogicScanner, InvestigationEngine, and manual review.
"""

import json
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse, urljoin

from models.business_flow import (
    BusinessWorkflow, WorkflowStep, WorkflowCategory, WorkflowRiskModel,
    LogicAbuseCandidate, AbusePattern,
)
from engines.discovery_store import DiscoveryStore


# ── URL patterns for business workflow discovery ─────────────────────────

_WORKFLOW_PATTERNS: dict[WorkflowCategory, list[re.Pattern]] = {
    WorkflowCategory.INVITE: [
        re.compile(r'/invite', re.IGNORECASE),
        re.compile(r'/refer', re.IGNORECASE),
        re.compile(r'/referral', re.IGNORECASE),
        re.compile(r'/join/', re.IGNORECASE),
        re.compile(r'/accept-invite', re.IGNORECASE),
    ],
    WorkflowCategory.SHARING: [
        re.compile(r'/share', re.IGNORECASE),
        re.compile(r'/collaborat', re.IGNORECASE),
        re.compile(r'/team/.*/member', re.IGNORECASE),
        re.compile(r'/grant', re.IGNORECASE),
        re.compile(r'/permission', re.IGNORECASE),
        re.compile(r'/access/.*/grant', re.IGNORECASE),
    ],
    WorkflowCategory.APPROVAL: [
        re.compile(r'/approve', re.IGNORECASE),
        re.compile(r'/review', re.IGNORECASE),
        re.compile(r'/authorize', re.IGNORECASE),
        re.compile(r'/publish', re.IGNORECASE),
        re.compile(r'/reject', re.IGNORECASE),
        re.compile(r'/confirm', re.IGNORECASE),
    ],
    WorkflowCategory.TRANSFER_OWNERSHIP: [
        re.compile(r'/transfer', re.IGNORECASE),
        re.compile(r'/change-owner', re.IGNORECASE),
        re.compile(r'/reassign', re.IGNORECASE),
        re.compile(r'/delegate', re.IGNORECASE),
        re.compile(r'/relinquish', re.IGNORECASE),
    ],
    WorkflowCategory.BILLING: [
        re.compile(r'/billing', re.IGNORECASE),
        re.compile(r'/payment', re.IGNORECASE),
        re.compile(r'/invoice', re.IGNORECASE),
        re.compile(r'/subscription', re.IGNORECASE),
        re.compile(r'/upgrade', re.IGNORECASE),
        re.compile(r'/downgrade', re.IGNORECASE),
        re.compile(r'/cancel.*subscription', re.IGNORECASE),
        re.compile(r'/refund', re.IGNORECASE),
    ],
    WorkflowCategory.COUPON: [
        re.compile(r'/coupon', re.IGNORECASE),
        re.compile(r'/promo', re.IGNORECASE),
        re.compile(r'/discount', re.IGNORECASE),
        re.compile(r'/voucher', re.IGNORECASE),
        re.compile(r'/gift-card', re.IGNORECASE),
        re.compile(r'/referral.*code', re.IGNORECASE),
    ],
    WorkflowCategory.CREDIT: [
        re.compile(r'/credit', re.IGNORECASE),
        re.compile(r'/points', re.IGNORECASE),
        re.compile(r'/reward', re.IGNORECASE),
        re.compile(r'/balance', re.IGNORECASE),
        re.compile(r'/wallet', re.IGNORECASE),
        re.compile(r'/coin', re.IGNORECASE),
        re.compile(r'/token', re.IGNORECASE),
        re.compile(r'/loyalty', re.IGNORECASE),
    ],
    WorkflowCategory.ROLE_ASSIGNMENT: [
        re.compile(r'/role', re.IGNORECASE),
        re.compile(r'/permission', re.IGNORECASE),
        re.compile(r'/privilege', re.IGNORECASE),
        re.compile(r'/make-admin', re.IGNORECASE),
        re.compile(r'/set-role', re.IGNORECASE),
        re.compile(r'/access-level', re.IGNORECASE),
    ],
    WorkflowCategory.TEAM_MANAGEMENT: [
        re.compile(r'/team', re.IGNORECASE),
        re.compile(r'/org', re.IGNORECASE),
        re.compile(r'/organization', re.IGNORECASE),
        re.compile(r'/workspace', re.IGNORECASE),
        re.compile(r'/group', re.IGNORECASE),
    ],
    WorkflowCategory.REGISTRATION: [
        re.compile(r'/register', re.IGNORECASE),
        re.compile(r'/signup', re.IGNORECASE),
        re.compile(r'/create-account', re.IGNORECASE),
    ],
    WorkflowCategory.PASSWORD_RESET: [
        re.compile(r'/reset-password', re.IGNORECASE),
        re.compile(r'/forgot-password', re.IGNORECASE),
        re.compile(r'/password-reset', re.IGNORECASE),
        re.compile(r'/change-password', re.IGNORECASE),
    ],
    WorkflowCategory.ACCOUNT_DEletion: [
        re.compile(r'/delete-account', re.IGNORECASE),
        re.compile(r'/deactivate', re.IGNORECASE),
        re.compile(r'/close-account', re.IGNORECASE),
    ],
    WorkflowCategory.DATA_EXPORT: [
        re.compile(r'/export', re.IGNORECASE),
        re.compile(r'/download.*data', re.IGNORECASE),
        re.compile(r'/privacy.*export', re.IGNORECASE),
        re.compile(r'/data.*download', re.IGNORECASE),
    ],
}

# ── Param name patterns → risk signals ───────────────────────────────────

_PARAM_RISK_SIGNALS: dict[str, str] = {
    # Ownership / IDOR
    "owner_id": "ownership", "owner": "ownership", "created_by": "ownership",
    "user_id": "ownership", "userId": "ownership", "account_id": "ownership",
    "resource_id": "ownership", "team_id": "ownership", "organisation_id": "ownership",
    # Role / privilege
    "role": "role", "permission": "role", "access_level": "role",
    "user_type": "role", "member_type": "role", "group": "role",
    "privilege": "role", "scope": "role",
    # Price / financial
    "price": "price", "amount": "price", "total": "price",
    "discount": "price", "cost": "price", "fee": "price",
    "tax": "price", "subtotal": "price", "grand_total": "price",
    # Coupon / promo
    "coupon": "coupon", "promo_code": "coupon", "discount_code": "coupon",
    "voucher": "coupon", "referral_code": "coupon",
    # Quantity
    "quantity": "quantity", "qty": "quantity", "count": "quantity",
    # Approval
    "approved": "approval", "approve": "approval", "status": "approval",
    "state": "approval", "action": "approval",
    # Tenant / org
    "tenant_id": "tenant", "org_id": "tenant", "organization_id": "tenant",
    "workspace_id": "tenant",
}

# ── Bounty yield weights by category ─────────────────────────────────────

_YIELD_WEIGHTS: dict[WorkflowCategory, float] = {
    WorkflowCategory.APPROVAL: 0.95,
    WorkflowCategory.TRANSFER_OWNERSHIP: 0.92,
    WorkflowCategory.ROLE_ASSIGNMENT: 0.90,
    WorkflowCategory.BILLING: 0.88,
    WorkflowCategory.CREDIT: 0.85,
    WorkflowCategory.INVITE: 0.82,
    WorkflowCategory.SHARING: 0.80,
    WorkflowCategory.COUPON: 0.78,
    WorkflowCategory.TEAM_MANAGEMENT: 0.75,
    WorkflowCategory.DATA_EXPORT: 0.65,
    WorkflowCategory.PASSWORD_RESET: 0.60,
    WorkflowCategory.REGISTRATION: 0.45,
    WorkflowCategory.ACCOUNT_DEletion: 0.40,
}

# ── Workflow step ordering keywords (for flow sequencing) ────────────────

_FLOW_SEQUENCE: dict[WorkflowCategory, list[str]] = {
    WorkflowCategory.INVITE: [
        "/invite", "/join", "/accept", "/confirm",
    ],
    WorkflowCategory.CHECKOUT: [
        "/cart", "/checkout", "/payment", "/confirm", "/receipt",
    ],
    WorkflowCategory.APPROVAL: [
        "/submit", "/review", "/approve", "/publish",
    ],
    WorkflowCategory.TRANSFER_OWNERSHIP: [
        "/transfer", "/confirm", "/complete",
    ],
    WorkflowCategory.REGISTRATION: [
        "/register", "/verify", "/welcome",
    ],
    WorkflowCategory.PASSWORD_RESET: [
        "/forgot", "/reset", "/confirm",
    ],
    WorkflowCategory.BILLING: [
        "/billing", "/payment", "/invoice", "/receipt",
    ],
}


class BusinessLogicDiscoveryEngine:
    """Proactive discovery of business workflows from scan intelligence.

    Integrates signals from:
      - URL patterns (workflow-specific keywords)
      - Form analysis (price, coupon, role, quantity fields)
      - Redirect chains (multi-step flows)
      - DiscoveryStore (ownership hints on workflow URLs)
      - RelationshipGraph (IDOR candidates overlapping workflows)
      - AuthorizationEngine (role access patterns on workflows)
      - AssetGraph (API, GQL, admin assets within flows)

    Generates ranked LogicAbuseCandidates for downstream investigation.
    """

    def __init__(
        self,
        discovery_store: DiscoveryStore | None = None,
        relationship_graph: Any | None = None,
        authorization_engine: Any | None = None,
        asset_graph: Any | None = None,
    ):
        self._store = discovery_store
        self._graph = relationship_graph
        self._authz = authorization_engine
        self._assets = asset_graph

    # ── Primary discovery entry point ──────────────────────────────────

    def discover_workflows(
        self,
        urls: list[str],
        forms: list[dict],
        role_sessions: dict[str, Any] | None = None,
        recon_data: dict[str, Any] | None = None,
    ) -> list[BusinessWorkflow]:
        """Discover business workflows from all available signals.

        Args:
            urls: All discovered URLs from the scan.
            forms: All extracted form definitions.
            role_sessions: Role → Session mapping (optional, for auth context).
            recon_data: Full recon data (for redirect chains, JS endpoints, etc.).

        Returns:
            List of discovered BusinessWorkflow objects.
        """
        workflows: list[BusinessWorkflow] = []

        # Phase 1: URL pattern matching — identify workflow endpoints
        url_workflows = self._discover_from_urls(urls, forms)
        workflows.extend(url_workflows)

        # Phase 2: Form analysis — find forms with risk-signal fields
        form_workflows = self._discover_from_forms(urls, forms)
        # Merge with existing workflows
        for fw in form_workflows:
            existing = self._find_workflow(workflows, fw.name)
            if existing:
                self._merge_workflow(existing, fw)
            else:
                workflows.append(fw)

        # Phase 3: DiscoveryStore cross-reference — ownership hints on workflow URLs
        if self._store:
            store_workflows = self._discover_from_store(urls)
            for sw in store_workflows:
                existing = self._find_workflow(workflows, sw.name)
                if existing:
                    self._merge_workflow(existing, sw)
                else:
                    workflows.append(sw)

        # Phase 4: Redirect chain analysis — build multi-step sequences
        redirects = (recon_data or {}).get("redirect_chains", [])
        if redirects:
            chain_workflows = self._discover_from_redirects(redirects, forms)
            for cw in chain_workflows:
                existing = self._find_workflow(workflows, cw.name)
                if existing:
                    self._merge_workflow(existing, cw)
                else:
                    workflows.append(cw)

        # Phase 5: Authorization cross-reference — role-sensitive workflows
        if role_sessions and len(role_sessions) >= 2:
            self._annotate_auth_context(workflows, role_sessions)

        return workflows

    def risk_assess(
        self,
        workflows: list[BusinessWorkflow],
        role_sessions: dict[str, Any] | None = None,
    ) -> list[WorkflowRiskModel]:
        """Assess risk for each discovered workflow.

        Combines technical signals (auth, role, ownership) with business
        signals (monetary value, privilege escalation, data exposure) to
        produce a risk model per workflow.
        """
        risk_models: list[WorkflowRiskModel] = []

        for wf in workflows:
            risk = self._assess_single_workflow(wf, role_sessions)
            risk_models.append(risk)

        risk_models.sort(key=lambda r: -r.overall_risk)
        return risk_models

    def prioritize_candidates(
        self,
        workflows: list[BusinessWorkflow],
        risk_models: list[WorkflowRiskModel],
    ) -> list[LogicAbuseCandidate]:
        """Generate ranked LogicAbuseCandidates from workflows and risk models.

        Each candidate identifies the highest-signal abuse point within a
        workflow and suggests investigation strategies.
        """
        candidates: list[LogicAbuseCandidate] = []

        risk_map: dict[str, WorkflowRiskModel] = {}
        for rm in risk_models:
            risk_map[rm.workflow.name] = rm

        for wf in workflows:
            rm = risk_map.get(wf.name)
            if not rm or rm.overall_risk < 0.3:
                continue

            candidates_from_wf = self._generate_candidates(wf, rm)
            candidates.extend(candidates_from_wf)

        candidates.sort(key=lambda c: -c.yield_rank)
        return candidates

    def run(
        self,
        urls: list[str],
        forms: list[dict],
        role_sessions: dict[str, Any] | None = None,
        recon_data: dict[str, Any] | None = None,
    ) -> list[LogicAbuseCandidate]:
        """Convenience: discover → assess → prioritize in one call.

        Returns ranked LogicAbuseCandidates ready for investigation routing.
        """
        workflows = self.discover_workflows(urls, forms, role_sessions, recon_data)
        risk_models = self.risk_assess(workflows, role_sessions)
        candidates = self.prioritize_candidates(workflows, risk_models)

        # Persist to DiscoveryStore
        if self._store:
            for c in candidates:
                self._store.record(
                    category="business_workflow",
                    value=c.workflow.name,
                    source_url=c.abuse_url or (c.workflow.source_urls or [""])[0],
                    extra={
                        "category": c.workflow.category.value,
                        "risk_score": round(c.risk_model.overall_risk, 3),
                        "yield_rank": round(c.yield_rank, 3),
                        "abuse_url": c.abuse_url,
                        "suggested_strategies": c.suggested_strategies,
                        "suggested_scanner": c.suggested_scanner,
                        "patterns": [p.value for p in c.risk_model.likely_patterns],
                    },
                )

        return candidates

    # ── Phase 1: URL pattern discovery ─────────────────────────────────

    def _discover_from_urls(
        self,
        urls: list[str],
        forms: list[dict],
    ) -> list[BusinessWorkflow]:
        """Discover workflows by matching URL patterns against known categories."""
        category_urls: dict[WorkflowCategory, list[str]] = defaultdict(list)
        category_params: dict[str, set[str]] = defaultdict(set)

        for url in urls:
            parsed = urlparse(url)
            for category, patterns in _WORKFLOW_PATTERNS.items():
                if any(p.search(parsed.path) for p in patterns):
                    category_urls[category].append(url)
                    # Extract query params
                    if parsed.query:
                        for pair in parsed.query.split("&"):
                            if "=" in pair:
                                key = pair.split("=")[0].lower()
                                category_params[f"{category.value}:{url}"].add(key)

        workflows: list[BusinessWorkflow] = []
        for category, matched_urls in category_urls.items():
            if not matched_urls:
                continue

            wf = BusinessWorkflow(
                name=f"{category.value}: {len(matched_urls)} endpoints",
                category=category,
                source_urls=matched_urls[:20],
                discovered_by="url_pattern",
                confidence=min(0.8, 0.4 + len(matched_urls) * 0.05),
            )

            for url in matched_urls[:10]:
                step = self._url_to_step(url, forms=forms)
                wf.steps.append(step)

            wf = self._classify_workflow_params(wf, category_params)
            workflows.append(wf)

        return workflows

    # ── Phase 2: Form-based discovery ──────────────────────────────────

    def _discover_from_forms(
        self,
        urls: list[str],
        forms: list[dict],
    ) -> list[BusinessWorkflow]:
        """Discover workflows from forms with high-risk field names."""
        if not forms:
            return []

        base_url = urls[0] if urls else ""
        workflows: list[BusinessWorkflow] = []
        seen_forms: set[str] = set()

        for form in forms:
            action = form.get("action", "")
            if not action:
                continue
            resolved = urljoin(base_url, action) if not action.startswith("http") else action
            if resolved in seen_forms:
                continue
            seen_forms.add(resolved)

            fields = form.get("fields", [])
            field_names = [f.get("name", "").lower() for f in fields if f.get("name")]

            if not field_names:
                continue

            risk_signals: dict[str, bool] = {}
            for fname in field_names:
                signal = _PARAM_RISK_SIGNALS.get(fname)
                if signal:
                    risk_signals[signal] = True

            if not risk_signals:
                continue

            # Determine category from risk signals
            category = self._infer_category_from_signals(risk_signals, resolved)

            wf = BusinessWorkflow(
                name=f"{category.value}: form at {resolved}",
                category=category,
                source_urls=[resolved],
                discovered_by="form_analysis",
                confidence=0.6 if len(risk_signals) >= 2 else 0.4,
            )

            step = WorkflowStep(
                url=resolved,
                method=form.get("method", "POST").upper(),
                parameter_names=field_names,
                has_form=True,
                form_fields=fields,
                page_type=category.value,
                discovered_by="form_analysis",
            )
            wf.steps.append(step)

            wf = self._classify_workflow_params(wf, {f"{category.value}:{resolved}": set(field_names)})
            workflows.append(wf)

        return workflows

    # ── Phase 3: DiscoveryStore cross-reference ────────────────────────

    def _discover_from_store(self, urls: list[str]) -> list[BusinessWorkflow]:
        """Cross-reference DiscoveryStore intelligence with workflow URLs."""
        workflows: list[BusinessWorkflow] = []
        if not self._store:
            return workflows

        store_records = defaultdict(list)
        for cat in ("ownership_hint", "ownership_relationship", "confirmed_endpoint", "validated_resource"):
            for rec in self._store.get_by_category(cat):
                src = rec.get("source_url", "")
                if src:
                    store_records[src].append(rec)

        if not store_records:
            return workflows

        # Find workflow URLs that have store intelligence
        for url in urls:
            records = store_records.get(url, [])
            if not records:
                continue

            parsed = urlparse(url)
            matched_category = WorkflowCategory.GENERIC

            for category, patterns in _WORKFLOW_PATTERNS.items():
                if any(p.search(parsed.path) for p in patterns):
                    matched_category = category
                    break

            wf = BusinessWorkflow(
                name=f"{matched_category.value}: store-backed {url[:60]}",
                category=matched_category,
                source_urls=[url],
                discovered_by="discovery_store",
                confidence=0.7,
            )

            for rec in records:
                extra_raw = rec.get("extra") or "{}"
                if isinstance(extra_raw, str):
                    try:
                        extra = json.loads(extra_raw)
                    except (json.JSONDecodeError, TypeError):
                        extra = {}
                else:
                    extra = extra_raw

                rid = extra.get("resource_id") or rec.get("value", "")
                if rid:
                    wf.owned_resource_ids.append(str(rid))
                oid = extra.get("owner_id") or extra.get("owner_key", "")
                if oid:
                    wf.owner_id_references.append(str(oid))

            step = self._url_to_step(url)
            wf.steps.append(step)
            wf.has_ownership_param = bool(wf.owner_id_references)
            workflows.append(wf)

        return workflows

    # ── Phase 4: Redirect chain discovery ──────────────────────────────

    def _discover_from_redirects(
        self,
        redirect_chains: list[list[str]],
        forms: list[dict],
    ) -> list[BusinessWorkflow]:
        """Build multi-step workflows from redirect chains."""
        workflows: list[BusinessWorkflow] = []

        for chain in redirect_chains:
            if len(chain) < 2:
                continue

            categories_observed = set()
            for url in chain:
                parsed = urlparse(url)
                for category, patterns in _WORKFLOW_PATTERNS.items():
                    if any(p.search(parsed.path) for p in patterns):
                        categories_observed.add(category)

            if not categories_observed:
                continue

            # Use the most specific category
            category = max(categories_observed,
                           key=lambda c: _YIELD_WEIGHTS.get(c, 0.5))

            wf = BusinessWorkflow(
                name=f"{category.value}: {len(chain)}-step redirect chain",
                category=category,
                source_urls=chain,
                discovered_by="redirect_chain",
                confidence=min(0.9, 0.5 + len(chain) * 0.1),
            )

            for url in chain:
                step = self._url_to_step(url, forms=forms)
                wf.steps.append(step)

            workflows.append(wf)

        return workflows

    # ── Phase 5: Authorization context annotation ──────────────────────

    def _annotate_auth_context(
        self,
        workflows: list[BusinessWorkflow],
        role_sessions: dict[str, Any],
    ) -> None:
        """Annotate workflows with role/authorization context."""
        roles = list(role_sessions.keys())
        if not roles:
            return

        for wf in workflows:
            wf.roles_observed = list(roles)
            wf.requires_auth = len(roles) >= 1

            # Check if any step URL is IDOR-relevant by querying RelationshipGraph
            if self._graph:
                for step in wf.steps:
                    candidates = self._graph.get_auth_candidates()
                    for c in candidates:
                        if c.get("url") == step.url:
                            wf.has_user_id_param = True
                            if c.get("id_value"):
                                wf.owner_id_references.append(c["id_value"])
                            break

    # ── Risk assessment ────────────────────────────────────────────────

    def _assess_single_workflow(
        self,
        wf: BusinessWorkflow,
        role_sessions: dict[str, Any] | None = None,
    ) -> WorkflowRiskModel:
        """Assess risk for a single workflow based on all available signals."""
        likely_patterns: list[AbusePattern] = []

        # ── Technical severity ──────────────────────────────────
        tech_sev = 0.0

        has_multi_step = wf.step_count >= 2
        has_auth = wf.requires_auth or False
        has_multi_role = len(wf.roles_observed) >= 2

        if has_multi_step:
            tech_sev += 0.15
            likely_patterns.append(AbusePattern.STEP_SKIP)
            likely_patterns.append(AbusePattern.STEP_REORDER)
        if wf.has_role_param:
            tech_sev += 0.12
            likely_patterns.append(AbusePattern.ROLE_SELF_UPGRADE)
        if wf.has_ownership_param or wf.owner_id_references:
            tech_sev += 0.10
            likely_patterns.append(AbusePattern.TRANSFER_TO_SELF)
        if wf.has_approval_param:
            tech_sev += 0.10
            likely_patterns.append(AbusePattern.APPROVAL_BYPASS)
        if wf.has_tenant_id_param:
            tech_sev += 0.08
        if wf.owner_id_references:
            tech_sev += 0.08
        if wf.involves_graphql:
            tech_sev += 0.05
        if has_multi_role:
            tech_sev += 0.05

        tech_sev = min(1.0, tech_sev)

        # ── Business impact ─────────────────────────────────────
        biz_impact = 0.0

        if wf.category == WorkflowCategory.APPROVAL:
            biz_impact += 0.35
        elif wf.category == WorkflowCategory.TRANSFER_OWNERSHIP:
            biz_impact += 0.33
        elif wf.category in (WorkflowCategory.BILLING, WorkflowCategory.CREDIT):
            biz_impact += 0.30
        elif wf.category == WorkflowCategory.ROLE_ASSIGNMENT:
            biz_impact += 0.28
        elif wf.category == WorkflowCategory.INVITE:
            biz_impact += 0.25
        elif wf.category == WorkflowCategory.SHARING:
            biz_impact += 0.22

        if wf.involves_payment:
            biz_impact += 0.10
        if wf.has_price_param:
            biz_impact += 0.08
        if wf.has_coupon_param:
            biz_impact += 0.07
        if wf.involves_admin:
            biz_impact += 0.06

        biz_impact = min(1.0, biz_impact)

        # ── Exploitability ─────────────────────────────────────
        exploit = 0.0

        if wf.step_count >= 2:
            exploit += 0.20
        if any(s.has_form for s in wf.steps):
            exploit += 0.15
        if wf.has_user_id_param or wf.has_ownership_param:
            exploit += 0.15
        if wf.has_coupon_param or wf.has_price_param:
            exploit += 0.10
        if wf.involves_api:
            exploit += 0.10
        if has_multi_role:
            exploit += 0.05

        exploit = min(1.0, exploit)

        # ── Detection difficulty ───────────────────────────────
        detect_diff = 0.0

        if wf.step_count >= 3:
            detect_diff += 0.25
        if wf.involves_graphql:
            detect_diff += 0.20
        if has_multi_role:
            detect_diff += 0.15
        if wf.owner_id_references:
            detect_diff += 0.10
        if wf.confidence < 0.6:
            detect_diff += 0.10

        detect_diff = min(1.0, detect_diff)

        # ── Build risk model ───────────────────────────────────
        auth_bypass = wf.has_user_id_param or (
            wf.category in (WorkflowCategory.APPROVAL, WorkflowCategory.TRANSFER_OWNERSHIP)
            and has_multi_step
        )
        role_esc = wf.has_role_param or wf.category in (
            WorkflowCategory.ROLE_ASSIGNMENT, WorkflowCategory.TEAM_MANAGEMENT,
        )
        ownership_violation = bool(wf.owner_id_references) or wf.has_ownership_param
        race_cond = wf.has_quantity_param or wf.has_coupon_param
        param_inj = wf.has_price_param or wf.has_coupon_param

        involves_money = wf.involves_payment or wf.has_price_param or wf.has_coupon_param or wf.has_quantity_param
        involves_priv_esc = role_esc or wf.category in (
            WorkflowCategory.ROLE_ASSIGNMENT, WorkflowCategory.INVITE,
        )
        involves_data = wf.category == WorkflowCategory.DATA_EXPORT
        involves_identity = wf.has_user_id_param or wf.has_ownership_param
        involves_exhaustion = wf.has_quantity_param or wf.has_coupon_param

        return WorkflowRiskModel(
            workflow=wf,
            auth_bypass_possible=auth_bypass,
            role_escalation_possible=role_esc,
            ownership_violation_possible=ownership_violation,
            race_condition_possible=race_cond,
            parameter_injection_possible=param_inj,
            involves_monetary_value=involves_money,
            involves_access_control=True,
            involves_privilege_escalation=involves_priv_esc,
            involves_data_exposure=involves_data,
            involves_identity_assumption=involves_identity,
            involves_resource_exhaustion=involves_exhaustion,
            likely_patterns=likely_patterns,
            discovery_urls=wf.source_urls,
            technical_severity=tech_sev,
            business_impact=biz_impact,
            exploitability=exploit,
            detection_difficulty=detect_diff,
        )

    # ── Candidate generation ──────────────────────────────────────────

    def _generate_candidates(
        self,
        wf: BusinessWorkflow,
        rm: WorkflowRiskModel,
    ) -> list[LogicAbuseCandidate]:
        """Generate investigation candidates from a workflow and risk model."""
        candidates: list[LogicAbuseCandidate] = []

        # Strategy: one candidate per abuse pattern per workflow
        pattern_priority = {
            AbusePattern.SELF_APPROVAL: 0.95,
            AbusePattern.APPROVAL_BYPASS: 0.93,
            AbusePattern.ROLE_SELF_UPGRADE: 0.90,
            AbusePattern.TRANSFER_TO_SELF: 0.88,
            AbusePattern.TRANSFER_TO_UNAUTHORIZED: 0.86,
            AbusePattern.PRICE_OVERRIDE: 0.85,
            AbusePattern.CREDIT_INFLATION: 0.83,
            AbusePattern.CREDIT_TRANSFER_ABUSE: 0.82,
            AbusePattern.INVITE_TO_PRIVILEGED: 0.80,
            AbusePattern.MASS_INVITE: 0.78,
            AbusePattern.SHARE_BEYOND_BOUNDARY: 0.78,
            AbusePattern.STEP_SKIP: 0.75,
            AbusePattern.STEP_REORDER: 0.73,
            AbusePattern.RACE_CONDITION: 0.70,
            AbusePattern.COUPON_STACKING: 0.68,
            AbusePattern.NEGATIVE_QUANTITY: 0.65,
            AbusePattern.BILLING_PARAMETER_INJECTION: 0.63,
            AbusePattern.DATA_EXPORT_ABUSE: 0.60,
            AbusePattern.UNLIMITED_USE: 0.58,
            AbusePattern.COUPON_CODE_PREDICTION: 0.55,
            AbusePattern.REWARD_INFLATION: 0.53,
            AbusePattern.ACCOUNT_TAKEOVER_VIA_WORKFLOW: 0.50,
            AbusePattern.STEP_REPEAT: 0.45,
            AbusePattern.RATE_LIMIT_BYPASS: 0.40,
        }

        for pattern in rm.likely_patterns:
            base_priority = pattern_priority.get(pattern, 0.3)
            abuse_step_idx, abuse_url, abuse_param = self._find_abuse_point(wf, pattern)
            suggested_strategies = self._suggest_strategies(pattern)

            priority = (
                base_priority * 0.4
                + rm.overall_risk * 0.3
                + wf.confidence * 0.2
                + (0.1 if wf.step_count >= 2 else 0.0)
            )

            candidate = LogicAbuseCandidate(
                workflow=wf,
                risk_model=rm,
                abuse_step_index=abuse_step_idx,
                abuse_url=abuse_url,
                abuse_parameter=abuse_param,
                suggested_strategies=suggested_strategies,
                suggested_scanner="business_logic",
                priority_score=priority,
                supporting_evidence=[],
                related_finding_fingerprints=[],
            )
            candidates.append(candidate)

        if not candidates and rm.overall_risk >= 0.4:
            abuse_step_idx, abuse_url, abuse_param = self._find_abuse_point(wf, None)
            candidate = LogicAbuseCandidate(
                workflow=wf,
                risk_model=rm,
                abuse_step_index=abuse_step_idx,
                abuse_url=abuse_url,
                abuse_parameter=abuse_param,
                suggested_strategies=["cross_account_idor", "differential_auth"],
                suggested_scanner="authorization",
                priority_score=rm.overall_risk * 0.6,
            )
            candidates.append(candidate)

        return candidates

    # ── Internal helpers ──────────────────────────────────────────────

    def _url_to_step(
        self,
        url: str,
        forms: list[dict] | None = None,
    ) -> WorkflowStep:
        """Convert a URL to a WorkflowStep with form matching."""
        parsed = urlparse(url)
        params = []
        if parsed.query:
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    params.append(pair.split("=")[0])

        matched_form = None
        if forms:
            for form in forms:
                action = form.get("action", "")
                if action and (action in url or url.endswith(action)):
                    matched_form = form
                    break

        return WorkflowStep(
            url=url,
            parameter_names=params,
            has_form=matched_form is not None,
            form_fields=matched_form.get("fields", []) if matched_form else [],
            discovered_by="url_pattern",
        )

    def _classify_workflow_params(
        self,
        wf: BusinessWorkflow,
        category_params: dict[str, set[str]],
    ) -> BusinessWorkflow:
        """Classify workflow parameters into risk signals."""
        for key, param_set in category_params.items():
            if wf.name.startswith(key.split(":")[0]):
                pass
            for p in param_set:
                signal = _PARAM_RISK_SIGNALS.get(p)
                if signal == "ownership":
                    wf.has_ownership_param = True
                elif signal == "role":
                    wf.has_role_param = True
                elif signal == "price":
                    wf.has_price_param = True
                elif signal == "coupon":
                    wf.has_coupon_param = True
                elif signal == "quantity":
                    wf.has_quantity_param = True
                elif signal == "approval":
                    wf.has_approval_param = True
                elif signal == "tenant":
                    wf.has_tenant_id_param = True
        return wf

    def _infer_category_from_signals(
        self,
        signals: dict[str, bool],
        url: str,
    ) -> WorkflowCategory:
        """Infer workflow category from form risk signals and URL."""
        if signals.get("role"):
            return WorkflowCategory.ROLE_ASSIGNMENT
        if signals.get("price") or signals.get("quantity"):
            return WorkflowCategory.BILLING
        if signals.get("coupon"):
            return WorkflowCategory.COUPON
        if signals.get("approval"):
            return WorkflowCategory.APPROVAL
        if signals.get("ownership"):
            return WorkflowCategory.TRANSFER_OWNERSHIP
        if signals.get("tenant"):
            return WorkflowCategory.TEAM_MANAGEMENT

        # Fallback: URL pattern
        parsed = urlparse(url)
        for category, patterns in _WORKFLOW_PATTERNS.items():
            if any(p.search(parsed.path) for p in patterns):
                return category

        return WorkflowCategory.GENERIC

    def _find_workflow(
        self,
        workflows: list[BusinessWorkflow],
        name: str,
    ) -> BusinessWorkflow | None:
        """Find existing workflow by name."""
        for wf in workflows:
            if wf.name == name:
                return wf
        return None

    def _merge_workflow(
        self,
        target: BusinessWorkflow,
        source: BusinessWorkflow,
    ) -> None:
        """Merge source workflow into target, preserving both signals."""
        for step in source.steps:
            if step.url not in {s.url for s in target.steps}:
                target.steps.append(step)

        for url in source.source_urls:
            if url not in target.source_urls:
                target.source_urls.append(url)

        target.confidence = max(target.confidence, source.confidence)
        target.owned_resource_ids.extend(
            rid for rid in source.owned_resource_ids
            if rid not in target.owned_resource_ids
        )
        target.owner_id_references.extend(
            ref for ref in source.owner_id_references
            if ref not in target.owner_id_references
        )

        for attr in (
            "has_ownership_param", "has_role_param", "has_price_param",
            "has_coupon_param", "has_quantity_param", "has_approval_param",
            "has_tenant_id_param", "has_user_id_param",
            "involves_api", "involves_graphql", "involves_admin",
            "involves_payment", "involves_form",
        ):
            if getattr(source, attr, False):
                setattr(target, attr, True)

    def _find_abuse_point(
        self,
        wf: BusinessWorkflow,
        pattern: AbusePattern | None,
    ) -> tuple[int, str, str]:
        """Identify the most likely abuse point within a workflow.

        Returns (step_index, url, parameter_name).
        """
        if not wf.steps:
            return (0, "", "")

        if pattern == AbusePattern.STEP_SKIP and len(wf.steps) >= 3:
            return (len(wf.steps) // 2, wf.steps[len(wf.steps) // 2].url, "")

        if pattern == AbusePattern.STEP_REORDER and len(wf.steps) >= 2:
            return (len(wf.steps) - 1, wf.steps[-1].url, "")

        if pattern == AbusePattern.ROLE_SELF_UPGRADE:
            for i, s in enumerate(wf.steps):
                for p in s.parameter_names:
                    if p.lower() in ("role", "permission", "access_level", "user_type"):
                        return (i, s.url, p)
            return (0, wf.steps[0].url, "role")

        if pattern in (
            AbusePattern.PRICE_OVERRIDE, AbusePattern.NEGATIVE_QUANTITY,
            AbusePattern.COUPON_STACKING,
        ):
            for i, s in enumerate(wf.steps):
                for p in s.parameter_names:
                    if p.lower() in ("price", "amount", "total", "discount", "coupon", "quantity"):
                        return (i, s.url, p)
            return (0, wf.steps[0].url, "price")

        if pattern in (AbusePattern.TRANSFER_TO_SELF, AbusePattern.TRANSFER_TO_UNAUTHORIZED):
            for i, s in enumerate(wf.steps):
                for p in s.parameter_names:
                    if p.lower() in ("owner_id", "user_id", "transfer_to", "new_owner"):
                        return (i, s.url, p)
            return (0, wf.steps[0].url, "owner_id")

        if pattern == AbusePattern.APPROVAL_BYPASS:
            for i, s in enumerate(wf.steps):
                if any(k in s.url.lower() for k in ("approve", "review", "publish")):
                    return (i, s.url, "status")
            return (len(wf.steps) - 1, wf.steps[-1].url, "status")

        if pattern == AbusePattern.RACE_CONDITION:
            for i, s in enumerate(wf.steps):
                if s.method == "POST":
                    return (i, s.url, s.parameter_names[0] if s.parameter_names else "")
            return (0, wf.steps[0].url, "")

        # Default: first step with form data
        for i, s in enumerate(wf.steps):
            if s.has_form and s.parameter_names:
                return (i, s.url, s.parameter_names[0])
        return (0, wf.steps[0].url, "")

    def _suggest_strategies(self, pattern: AbusePattern) -> list[str]:
        """Map abuse patterns to investigation strategies."""
        mapping = {
            AbusePattern.STEP_SKIP: ["replay_with_auth", "cross_account_idor"],
            AbusePattern.STEP_REORDER: ["replay_with_auth", "cross_account_idor"],
            AbusePattern.STEP_REPEAT: ["replay_with_auth"],
            AbusePattern.RACE_CONDITION: ["replay_with_auth"],
            AbusePattern.PRICE_OVERRIDE: ["replay_with_auth", "differential_auth"],
            AbusePattern.COUPON_STACKING: ["replay_with_auth"],
            AbusePattern.NEGATIVE_QUANTITY: ["replay_with_auth"],
            AbusePattern.SELF_APPROVAL: ["cross_account_idor", "differential_auth", "ownership_validation"],
            AbusePattern.APPROVAL_BYPASS: ["cross_account_idor", "ownership_validation"],
            AbusePattern.INVITE_TO_PRIVILEGED: ["cross_account_idor", "differential_auth"],
            AbusePattern.MASS_INVITE: ["replay_without_auth"],
            AbusePattern.SHARE_BEYOND_BOUNDARY: ["cross_account_idor", "ownership_validation"],
            AbusePattern.TRANSFER_TO_SELF: ["cross_account_idor", "ownership_validation"],
            AbusePattern.TRANSFER_TO_UNAUTHORIZED: ["cross_account_idor", "ownership_validation"],
            AbusePattern.ROLE_SELF_UPGRADE: ["cross_account_idor", "differential_auth", "horizontal_idor"],
            AbusePattern.CREDIT_INFLATION: ["replay_with_auth", "differential_auth"],
            AbusePattern.CREDIT_TRANSFER_ABUSE: ["cross_account_idor", "horizontal_idor"],
            AbusePattern.BILLING_PARAMETER_INJECTION: ["differential_auth", "replay_with_auth"],
            AbusePattern.INVOICE_MANIPULATION: ["differential_auth", "replay_with_auth"],
            AbusePattern.DATA_EXPORT_ABUSE: ["cross_account_idor", "horizontal_idor"],
            AbusePattern.ACCOUNT_TAKEOVER_VIA_WORKFLOW: ["cross_account_idor", "ownership_validation"],
            AbusePattern.COUPON_CODE_PREDICTION: ["replay_with_auth"],
            AbusePattern.RATE_LIMIT_BYPASS: ["replay_with_auth"],
            AbusePattern.REWARD_INFLATION: ["differential_auth", "replay_with_auth"],
            AbusePattern.UNLIMITED_USE: ["replay_with_auth"],
        }
        return mapping.get(pattern, ["cross_account_idor"])

"""Business workflow data models for business logic discovery.

These models represent discovered business workflows and abuse candidates.
They are NOT exploitation tools — they identify high-signal workflow segments
that deserve deeper investigation by the BusinessLogicScanner or manual review.

Each model carries the signals needed to rank candidates by expected yield.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class WorkflowCategory(str, Enum):
    INVITE = "invite"
    SHARING = "sharing"
    APPROVAL = "approval"
    TRANSFER_OWNERSHIP = "transfer_ownership"
    BILLING = "billing"
    COUPON = "coupon"
    CREDIT = "credit"
    ROLE_ASSIGNMENT = "role_assignment"
    TEAM_MANAGEMENT = "team_management"
    REGISTRATION = "registration"
    CHECKOUT = "checkout"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_DEletion = "account_deletion"
    DATA_EXPORT = "data_export"
    GENERIC = "generic"


class AbusePattern(str, Enum):
    """High-signal patterns that suggest business logic abuse."""

    STEP_SKIP = "step_skip"
    STEP_REORDER = "step_reorder"
    STEP_REPEAT = "step_repeat"
    RACE_CONDITION = "race_condition"
    PRICE_OVERRIDE = "price_override"
    COUPON_STACKING = "coupon_stacking"
    NEGATIVE_QUANTITY = "negative_quantity"
    SELF_APPROVAL = "self_approval"
    APPROVAL_BYPASS = "approval_bypass"
    INVITE_TO_PRIVILEGED = "invite_to_privileged"
    MASS_INVITE = "mass_invite"
    SHARE_BEYOND_BOUNDARY = "share_beyond_boundary"
    TRANSFER_TO_SELF = "transfer_to_self"
    TRANSFER_TO_UNAUTHORIZED = "transfer_to_unauthorized"
    ROLE_SELF_UPGRADE = "role_self_upgrade"
    ROLE_CREATE = "role_create"
    CREDIT_INFLATION = "credit_inflation"
    CREDIT_TRANSFER_ABUSE = "credit_transfer_abuse"
    BILLING_PARAMETER_INJECTION = "billing_parameter_injection"
    INVOICE_MANIPULATION = "invoice_manipulation"
    DATA_EXPORT_ABUSE = "data_export_abuse"
    ACCOUNT_TAKEOVER_VIA_WORKFLOW = "account_takeover_via_workflow"
    COUPON_CODE_PREDICTION = "coupon_code_prediction"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    REWARD_INFLATION = "reward_inflation"
    UNLIMITED_USE = "unlimited_use"


@dataclass
class WorkflowStep:
    """A single step in a discovered business workflow."""

    url: str
    method: str = "GET"
    parameter_names: list[str] = field(default_factory=list)
    page_type: str = ""
    requires_auth: bool | None = None
    requires_role: str | None = None
    has_form: bool = False
    form_fields: list[dict] = field(default_factory=list)
    discovered_by: str = "recon"


@dataclass
class BusinessWorkflow:
    """A discovered business workflow with multiple steps.

    Represents a complete or partial workflow identified from recon data,
    URL patterns, form analysis, and cross-scan intelligence.
    """

    name: str
    category: WorkflowCategory = WorkflowCategory.GENERIC
    steps: list[WorkflowStep] = field(default_factory=list)
    source_urls: list[str] = field(default_factory=list)

    # Authentication & authorization context
    requires_auth: bool | None = None
    min_role_required: str | None = None
    roles_observed: list[str] = field(default_factory=list)

    # Ownership context (from RelationshipGraph / DiscoveryStore)
    owned_resource_ids: list[str] = field(default_factory=list)
    owner_id_references: list[str] = field(default_factory=list)

    # Asset context (from AssetGraph)
    involves_api: bool = False
    involves_graphql: bool = False
    involves_admin: bool = False
    involves_auth_service: bool = False
    involves_form: bool = False
    involves_file_upload: bool = False
    involves_payment: bool = False

    # Multi-tenancy signals
    has_tenant_id_param: bool = False
    has_org_id_param: bool = False
    has_user_id_param: bool = False
    has_role_param: bool = False
    has_price_param: bool = False
    has_quantity_param: bool = False
    has_coupon_param: bool = False
    has_approval_param: bool = False
    has_ownership_param: bool = False

    # Discovery metadata
    confidence: float = 0.5
    discovered_by: str = "url_pattern"
    first_seen: str = ""

    @property
    def step_count(self) -> int:
        return len(self.steps)

    @property
    def risk_score(self) -> float:
        """Pre-computed risk score based on workflow characteristics."""
        score = 0.0
        base = min(1.0, self.step_count / 5.0) * 0.2
        score += base

        if self.involves_payment:
            score += 0.15
        if self.involves_admin:
            score += 0.1
        if self.has_role_param:
            score += 0.1
        if self.has_approval_param:
            score += 0.1
        if self.has_price_param:
            score += 0.08
        if self.has_coupon_param:
            score += 0.07
        if self.has_ownership_param:
            score += 0.07
        if self.has_quantity_param:
            score += 0.05
        if self.has_tenant_id_param:
            score += 0.05
        if self.owner_id_references:
            score += 0.05

        return min(1.0, score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "steps": [s.__dict__ for s in self.steps],
            "source_urls": self.source_urls,
            "requires_auth": self.requires_auth,
            "min_role_required": self.min_role_required,
            "roles_observed": self.roles_observed,
            "owned_resource_ids": self.owned_resource_ids,
            "owner_id_references": self.owner_id_references,
            "involves_api": self.involves_api,
            "involves_graphql": self.involves_graphql,
            "involves_admin": self.involves_admin,
            "involves_payment": self.involves_payment,
            "has_role_param": self.has_role_param,
            "has_price_param": self.has_price_param,
            "has_coupon_param": self.has_coupon_param,
            "has_approval_param": self.has_approval_param,
            "has_ownership_param": self.has_ownership_param,
            "has_tenant_id_param": self.has_tenant_id_param,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "discovered_by": self.discovered_by,
        }


@dataclass
class WorkflowRiskModel:
    """Risk assessment for a business workflow.

    Combines technical signals (auth required, role level, asset sensitivity)
    with business signals (involves money, involves ownership transfer,
    involves approval) to produce a risk score and yield estimate.
    """

    workflow: BusinessWorkflow

    # Technical risk factors
    auth_bypass_possible: bool = False
    role_escalation_possible: bool = False
    ownership_violation_possible: bool = False
    race_condition_possible: bool = False
    parameter_injection_possible: bool = False

    # Business risk factors
    involves_monetary_value: bool = False
    involves_access_control: bool = False
    involves_privilege_escalation: bool = False
    involves_data_exposure: bool = False
    involves_identity_assumption: bool = False
    involves_resource_exhaustion: bool = False

    # Abuse pattern indicators
    likely_patterns: list[AbusePattern] = field(default_factory=list)
    discovery_urls: list[str] = field(default_factory=list)

    # Score
    technical_severity: float = 0.0
    business_impact: float = 0.0
    exploitability: float = 0.0
    detection_difficulty: float = 0.0

    @property
    def overall_risk(self) -> float:
        """Weighted combination of all risk dimensions, 0-1."""
        return (
            self.technical_severity * 0.25
            + self.business_impact * 0.35
            + self.exploitability * 0.25
            + self.detection_difficulty * 0.15
        )

    @property
    def estimated_bounty_yield(self) -> str:
        """Qualitative yield estimate based on risk dimensions."""
        risk = self.overall_risk
        if risk >= 0.8:
            return "critical"
        if risk >= 0.6:
            return "high"
        if risk >= 0.4:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_name": self.workflow.name,
            "workflow_category": self.workflow.category.value,
            "overall_risk": round(self.overall_risk, 3),
            "estimated_bounty_yield": self.estimated_bounty_yield,
            "technical_severity": round(self.technical_severity, 3),
            "business_impact": round(self.business_impact, 3),
            "exploitability": round(self.exploitability, 3),
            "detection_difficulty": round(self.detection_difficulty, 3),
            "auth_bypass_possible": self.auth_bypass_possible,
            "role_escalation_possible": self.role_escalation_possible,
            "ownership_violation_possible": self.ownership_violation_possible,
            "race_condition_possible": self.race_condition_possible,
            "parameter_injection_possible": self.parameter_injection_possible,
            "involves_monetary_value": self.involves_monetary_value,
            "involves_privilege_escalation": self.involves_privilege_escalation,
            "likely_patterns": [p.value for p in self.likely_patterns],
            "discovery_urls": self.discovery_urls,
        }


@dataclass
class LogicAbuseCandidate:
    """A high-signal workflow segment that deserves deeper investigation.

    This is NOT a finding — it is an investigation target. Each candidate
    carries the signals needed to route it to the appropriate scanner or
    investigation strategy.
    """

    workflow: BusinessWorkflow
    risk_model: WorkflowRiskModel

    # Which step(s) are the likely abuse point
    abuse_step_index: int = 0
    abuse_url: str = ""
    abuse_parameter: str = ""

    # Suggested investigation strategy
    suggested_strategies: list[str] = field(default_factory=list)
    suggested_scanner: str = "business_logic"

    # Priority for investigation ordering
    priority_score: float = 0.0

    # Discovery context
    supporting_evidence: list[dict] = field(default_factory=list)
    related_finding_fingerprints: list[str] = field(default_factory=list)

    @property
    def yield_rank(self) -> float:
        """Estimated bug bounty yield based on risk + priority."""
        return self.risk_model.overall_risk * 0.7 + self.priority_score * 0.3

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow": self.workflow.to_dict(),
            "risk_model": self.risk_model.to_dict(),
            "abuse_step_index": self.abuse_step_index,
            "abuse_url": self.abuse_url,
            "abuse_parameter": self.abuse_parameter,
            "suggested_strategies": self.suggested_strategies,
            "suggested_scanner": self.suggested_scanner,
            "priority_score": round(self.priority_score, 3),
            "yield_rank": round(self.yield_rank, 3),
            "supporting_evidence_count": len(self.supporting_evidence),
            "related_findings": len(self.related_finding_fingerprints),
        }

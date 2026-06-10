"""Data models for GraphQL Authorization Intelligence.

Defines the relationship types, relationship records, and investigation
plans used by the GQL authorization discovery pipeline.
"""

import enum
from dataclasses import dataclass, field
from typing import Any


class RelationshipType(str, enum.Enum):
    OWNS = "owns"
    BELONGS_TO = "belongs_to"
    HAS_MANY = "has_many"
    MEMBER_OF = "member_of"
    OWNS_THROUGH = "owns_through"
    TENANT_OF = "tenant_of"
    GQL_ASSOCIATION = "gql_association"


_INFERRED_TYPE_LABELS: dict[str, str] = {
    "owns": "direct ownership",
    "belongs_to": "belongs to",
    "has_many": "has many",
    "member_of": "member of",
    "owns_through": "indirect ownership via chain",
    "tenant_of": "tenant boundary",
    "gql_association": "schema association",
}


class PlanType(str, enum.Enum):
    CROSS_TENANT = "cross_tenant"
    CROSS_OWNER = "cross_owner"
    ROLE_ESCALATION = "role_escalation"
    OWNERSHIP_VIOLATION = "ownership_violation"


@dataclass
class TypeRelationship:
    from_type: str
    to_type: str
    via_field: str
    relationship_type: RelationshipType
    confidence: float = 0.5
    source_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_type": self.from_type,
            "to_type": self.to_type,
            "via_field": self.via_field,
            "relationship_type": self.relationship_type.value,
            "confidence": self.confidence,
            "source_url": self.source_url,
        }


@dataclass
class AuthInvestigationPlan:
    target_url: str
    plan_type: PlanType
    gql_operation: str
    gql_arguments: dict[str, Any] = field(default_factory=dict)
    from_role: str = ""
    to_role: str = ""
    expected_behavior: str = ""
    confidence: float = 0.5
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "plan_type": self.plan_type.value,
            "gql_operation": self.gql_operation,
            "gql_arguments": self.gql_arguments,
            "from_role": self.from_role,
            "to_role": self.to_role,
            "expected_behavior": self.expected_behavior,
            "confidence": self.confidence,
            "rationale": self.rationale,
        }

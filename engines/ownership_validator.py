from typing import Any

from models.finding import Finding
from models.evidence import (
    EvidenceBase, EvidenceStatus, EvidenceType,
    OwnershipEvidence, AuthorizationComparisonEvidence,
)


class OwnershipValidator:
    """Validates ownership claims on findings.

    Examines existing evidence for authorization comparison results,
    and produces OwnershipEvidence that captures whether:
    - The finding proves cross-user data access
    - The ownership violation is confirmed via response comparison
    - The evidence supports submission-quality ownership proof
    """

    REQUIRED_OWNERSHIP_TYPES = {
        EvidenceType.AUTHORIZATION_COMPARISON,
        EvidenceType.OWNERSHIP_PROOF,
    }

    @classmethod
    def validate(cls, finding: Finding) -> OwnershipEvidence | None:
        """Validate ownership for a finding, returning evidence or None.

        Looks for existing AuthorizationComparisonEvidence in the finding's
        evidence list. If found, promotes it to OwnershipEvidence.
        If no authz evidence exists but the vuln_type suggests ownership
        relevance, produces a weak OwnershipEvidence flagging the gap.
        """
        evidence = finding.evidence or []
        vuln_type = (finding.vuln_type or "").lower()
        title = (finding.title or "").lower()

        # Gather existing authz comparison evidence
        authz_evidence: list[AuthorizationComparisonEvidence] = [
            ev for ev in evidence
            if isinstance(ev, AuthorizationComparisonEvidence)
        ]

        is_ownership_relevant = any(
            keyword in vuln_type or keyword in title
            for keyword in ("authorization", "idor", "bola", "ownership",
                            "privilege escalation", "horizontal", "vertical",
                            "acl", "access control", "forbidden", "unauthorized")
        )

        if authz_evidence:
            # Found authz comparison — promote to ownership evidence
            best = authz_evidence[-1]  # Take most recent
            return OwnershipEvidence(
                ownership_violated=best.ownership_violated,
                original_owner=best.original_user,
                claiming_identity=best.target_user,
                proof_type="authorization_comparison",
                resource_identifier=finding.url,
                access_granted=(
                    best.target_status == 200
                    and best.content_different
                ),
                description=f"Ownership validated: {best.original_user} → {best.target_user} "
                           f"@ {finding.url} "
                           f"({'violated' if best.ownership_violated else 'not violated'})",
                status=EvidenceStatus.VERIFIED if best.ownership_violated else EvidenceStatus.COLLECTED,
            )

        # No authz evidence — flag gap for ownership-relevant findings
        if is_ownership_relevant:
            return OwnershipEvidence(
                ownership_violated=False,
                proof_type="missing",
                description=f"Ownership not validated: no authorization comparison "
                           f"evidence for {vuln_type} @ {finding.url}",
                status=EvidenceStatus.PENDING,
                resource_identifier=finding.url,
            )

        return None

    @classmethod
    def calculate_confidence_boost(cls, finding: Finding) -> int:
        """Calculate confidence boost based on ownership validation.

        Returns 0–20 points to add to confidence score.
        """
        evidence = finding.evidence or []
        ownership_evs = [
            ev for ev in evidence
            if isinstance(ev, (OwnershipEvidence, AuthorizationComparisonEvidence))
        ]
        if not ownership_evs:
            return 0

        boost = 0
        for ev in ownership_evs:
            if isinstance(ev, OwnershipEvidence) and ev.ownership_violated:
                boost += 15
            elif isinstance(ev, AuthorizationComparisonEvidence) and ev.ownership_violated:
                boost += 10
            elif ev.status == EvidenceStatus.VERIFIED:
                boost += 5

        return min(20, boost)

from typing import Any

from models.finding import Finding
from models.evidence import (
    EvidenceBase, EvidenceStatus, EvidenceType,
    ImpactEvidence, BrowserExecutionEvidence,
    OOBCallbackEvidence, CommandExecutionEvidence,
    SecretValidationEvidence,
)


class ImpactValidator:
    """Validates the impact claim of a finding.

    Distinguishes between theoretical impact (asserted but not proven)
    and demonstrated impact (proven via evidence). Produces ImpactEvidence
    that captures what was actually achieved.
    """

    # Evidence types that demonstrate actual exploitation
    EXPLOITATION_PROOF_TYPES = {
        EvidenceType.BROWSER_EXECUTION,
        EvidenceType.OOB_CALLBACK,
        EvidenceType.COMMAND_EXECUTION,
        EvidenceType.SECRET_VALIDATION,
    }

    @classmethod
    def validate(cls, finding: Finding) -> ImpactEvidence:
        """Validate the impact of a finding, returning ImpactEvidence.

        Examines evidence for exploitation proof and assesses whether
        the claimed severity / business impact is confirmed.
        """
        evidence = finding.evidence or []
        vuln_type = (finding.vuln_type or "").lower()
        title = (finding.title or "").lower()
        stage = (finding.verification_stage or "").lower()
        score = finding.confidence_score or 0

        # Check for exploitation-proof evidence
        exploitation_evidence = [
            ev for ev in evidence
            if isinstance(ev, EvidenceBase)
            and ev.evidence_type in cls.EXPLOITATION_PROOF_TYPES
            and ev.status == EvidenceStatus.VERIFIED
        ]

        # Check for browser execution specifically
        browser_evs = [
            ev for ev in exploitation_evidence
            if isinstance(ev, BrowserExecutionEvidence)
        ]

        oob_evs = [
            ev for ev in exploitation_evidence
            if isinstance(ev, OOBCallbackEvidence)
        ]

        cmd_evs = [
            ev for ev in exploitation_evidence
            if isinstance(ev, CommandExecutionEvidence)
        ]

        # Determine if impact is demonstrated
        demonstrated = bool(exploitation_evidence)
        if not demonstrated:
            # Check stage as proxy
            demonstrated = stage in ("verified", "exploitable") and score >= 86

        # Build exploitation proof description
        proof_parts: list[str] = []
        if browser_evs:
            fired = any(b.alert_fired for b in browser_evs)
            mutated = any(b.dom_mutation for b in browser_evs)
            proof_parts.append(f"XSS {'executed' if fired else 'DOM mutated' if mutated else 'tested'}")
        if oob_evs:
            types = set(ev.callback_type for ev in oob_evs)
            proof_parts.append(f"OOB callback{'s' if len(oob_evs) > 1 else ''}: {', '.join(types)}")
        if cmd_evs:
            codes = [ev.exit_code_observed for ev in cmd_evs if ev.exit_code_observed >= 0]
            proof_parts.append(f"Command execution (exit codes: {codes})")
        exploitation_proof = "; ".join(proof_parts) if proof_parts else (
            "Theoretical — exploitation not confirmed" if not demonstrated
            else "Confirmed via verification stage"
        )

        # Confirm severity
        high_severity = finding.severity in ("critical", "high")
        severity_confirmed = demonstrated and high_severity

        # Build attack scenario
        attack_scenario = cls._build_attack_scenario(finding, evidence, vuln_type)

        return ImpactEvidence(
            impact_type=vuln_type,
            severity_confirmed=severity_confirmed,
            business_impact=finding.get("business_impact", "") or "",
            evidence_of_exploitation=exploitation_proof,
            exploitation_proof=exploitation_proof,
            attack_scenario=attack_scenario,
            demonstrated=demonstrated,
            description=f"Impact {'demonstrated' if demonstrated else 'theoretical'}: "
                       f"{vuln_type} @ {finding.url}",
            status=EvidenceStatus.VERIFIED if demonstrated else EvidenceStatus.COLLECTED,
        )

    @classmethod
    def _build_attack_scenario(cls, finding: Finding, evidence: list,
                                vuln_type: str) -> str:
        """Construct a concise attack scenario from available evidence."""
        url = finding.url
        param = finding.parameter or ""

        # Try to build scenario from evidence
        browser_evs = [
            ev for ev in evidence
            if isinstance(ev, BrowserExecutionEvidence) and ev.alert_fired
        ]
        oob_evs = [
            ev for ev in evidence
            if isinstance(ev, OOBCallbackEvidence)
        ]
        secret_evs = [
            ev for ev in evidence
            if isinstance(ev, SecretValidationEvidence) and ev.is_valid
        ]

        if browser_evs:
            return f"Attacker delivers payload to victim's browser at {url}; alert() executed, confirming XSS"
        if oob_evs:
            host = oob_evs[0].callback_host or "external"
            return f"Server-side request reaches attacker-controlled {host}; confirms SSRF/XXE/CMD injection"
        if secret_evs:
            return f"Live {secret_evs[0].secret_type} credential validated against its API — enables lateral access"

        # Fallback: generic scenario from vuln type
        scenarios = {
            "xss": f"Attacker injects script at {url}{' via ' + param if param else ''}",
            "sqli": f"Query structure altered at {url} — database state inferred",
            "lfi": f"File path traversal at {url} — server files read",
            "ssrf": f"Server-side request forced to attacker-chosen destination from {url}",
            "ssti": f"Server-side template logic hijacked at {url}",
            "command injection": f"OS command execution triggered via {url}",
            "cmd_injection": f"OS command execution triggered via {url}",
            "idor": f"Resource identifier enumerated at {url} — cross-user data accessed",
            "authorization": f"Privilege boundary crossed at {url}",
            "open_redirect": f"Victim redirected from {url} to attacker-controlled origin",
        }
        for key, scenario in scenarios.items():
            if key in vuln_type:
                return scenario
        return f"Exploitation of {vuln_type} at {url}"

    @classmethod
    def calculate_confidence_boost(cls, finding: Finding) -> int:
        """Calculate confidence boost based on impact validation.

        Returns 0–15 points to add to confidence score.
        """
        evidence = finding.evidence or []
        impact_evs = [
            ev for ev in evidence
            if isinstance(ev, ImpactEvidence)
        ]

        if not impact_evs:
            return 0

        boost = 0
        for ev in impact_evs:
            if ev.demonstrated and ev.severity_confirmed:
                boost += 15
            elif ev.demonstrated:
                boost += 10
            elif ev.severity_confirmed:
                boost += 5

        return min(15, boost)

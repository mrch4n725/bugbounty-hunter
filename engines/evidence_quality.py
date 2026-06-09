from models.evidence import (
    EvidenceBase, EvidenceType, EvidenceStatus, EvidenceQualityScore,
)
from models.finding import Finding


class EvidenceQualityEngine:
    """Assesses quality of evidence attached to findings.

    Each evidence type has its own quality criteria:
    - HttpRequest + HttpResponse: weakest (no execution proof)
    - TimingEvidence: medium (indirect signal)
    - OOBCallback: strong (out-of-band confirmation)
    - BrowserExecution: strong (direct execution proof)
    - AuthorizationComparison + ownership_violated: very strong
    - Composite with multiple strong children: very strong
    """

    STRENGTH_WEIGHTS = {
        "weak": 0,
        "medium": 1,
        "strong": 2,
        "very_strong": 3,
    }

    @classmethod
    def assess_evidence(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        etype = evidence.evidence_type

        if etype == EvidenceType.HTTP_REQUEST:
            return cls._score_http_request(evidence)
        elif etype == EvidenceType.HTTP_RESPONSE:
            return cls._score_http_response(evidence)
        elif etype == EvidenceType.RESPONSE_EXCERPT:
            return cls._score_response_excerpt(evidence)
        elif etype == EvidenceType.OOB_CALLBACK:
            return cls._score_oob_callback(evidence)
        elif etype == EvidenceType.TIMING_PROOF:
            return cls._score_timing(evidence)
        elif etype == EvidenceType.BROWSER_EXECUTION:
            return cls._score_browser(evidence)
        elif etype == EvidenceType.AUTHORIZATION_COMPARISON:
            return cls._score_authz(evidence)
        elif etype == EvidenceType.COMMAND_EXECUTION:
            return cls._score_cmd(evidence)
        elif etype == EvidenceType.SECRET_VALIDATION:
            return cls._score_secret(evidence)
        elif etype == EvidenceType.SCREENSHOT:
            return cls._score_screenshot(evidence)
        elif etype == EvidenceType.GRAPHQL_SCHEMA:
            return cls._score_graphql(evidence)
        elif etype == EvidenceType.RESPONSE_DIFF:
            return cls._score_response_diff(evidence)
        elif etype == EvidenceType.COMPOSITE:
            return cls._score_composite(evidence)
        return EvidenceQualityScore(
            evidence_type=etype,
            strength="weak",
            completeness=0.3,
            reproducibility="single_request",
            independence=False,
            reasons=["Unknown evidence type"],
        )

    @classmethod
    def assess_finding_evidence(cls, finding: Finding) -> list[EvidenceQualityScore]:
        scores = []
        for ev in (finding.evidence or []):
            if isinstance(ev, str):
                continue
            if hasattr(ev, "evidence_type"):
                scores.append(cls.assess_evidence(ev))
        if finding.request:
            scores.append(EvidenceQualityScore(
                evidence_type=EvidenceType.HTTP_REQUEST,
                strength="weak",
                completeness=0.4,
                reproducibility="single_request",
                independence=False,
                reasons=["Request string present on finding"],
            ))
        if finding.response_excerpt:
            scores.append(EvidenceQualityScore(
                evidence_type=EvidenceType.RESPONSE_EXCERPT,
                strength="weak",
                completeness=0.3,
                reproducibility="single_request",
                independence=False,
                reasons=["Response excerpt present on finding"],
            ))
        return scores

    @classmethod
    def best_quality(cls, scores: list[EvidenceQualityScore]) -> EvidenceQualityScore | None:
        if not scores:
            return None
        return max(scores, key=lambda s: cls.STRENGTH_WEIGHTS.get(s.strength, 0))

    @classmethod
    def aggregate_strength(cls, scores: list[EvidenceQualityScore]) -> str:
        if not scores:
            return "weak"
        best = cls.best_quality(scores)
        if not best:
            return "weak"
        n_strong = sum(1 for s in scores if cls.STRENGTH_WEIGHTS.get(s.strength, 0) >= 2)
        if n_strong >= 2:
            return "very_strong"
        return best.strength

    @classmethod
    def confidence_contribution(cls, scores: list[EvidenceQualityScore]) -> int:
        strength = cls.aggregate_strength(scores)
        contributions = {"weak": 5, "medium": 15, "strong": 30, "very_strong": 45}
        return contributions.get(strength, 0)

    @classmethod
    def quality_reasons(cls, scores: list[EvidenceQualityScore]) -> list[str]:
        reasons = []
        if not scores:
            reasons.append("No typed evidence attached")
            return reasons
        best = cls.best_quality(scores)
        if best:
            reasons.append(f"Best evidence: {best.strength} ({best.evidence_type.value})")
        n_independent = sum(1 for s in scores if s.independence)
        if n_independent >= 2:
            reasons.append(f"Multiple independent validation methods ({n_independent})")
        if cls.aggregate_strength(scores) == "very_strong":
            reasons.append("Multiple strong evidence items corroborate finding")
        worst = min(scores, key=lambda s: cls.STRENGTH_WEIGHTS.get(s.strength, 0))
        if worst and cls.STRENGTH_WEIGHTS.get(worst.strength, 0) == 0:
            reasons.append(f"Weakest evidence: {worst.evidence_type.value} ({worst.strength})")
        return reasons

    @classmethod
    def _score_http_request(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        return EvidenceQualityScore(
            evidence_type=EvidenceType.HTTP_REQUEST,
            strength="weak",
            completeness=0.5,
            reproducibility="single_request",
            independence=False,
            reasons=["HTTP request alone does not prove vulnerability"],
        )

    @classmethod
    def _score_http_response(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        return EvidenceQualityScore(
            evidence_type=EvidenceType.HTTP_RESPONSE,
            strength="weak",
            completeness=0.4,
            reproducibility="single_request",
            independence=False,
            reasons=["Response alone does not prove exploitation"],
        )

    @classmethod
    def _score_response_excerpt(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        return EvidenceQualityScore(
            evidence_type=EvidenceType.RESPONSE_EXCERPT,
            strength="weak",
            completeness=0.3,
            reproducibility="single_request",
            independence=False,
            reasons=["Response excerpt is minimal evidence"],
        )

    @classmethod
    def _score_oob_callback(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        if evidence.status == EvidenceStatus.VERIFIED:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.OOB_CALLBACK,
                strength="strong",
                completeness=0.9,
                reproducibility="multi_step",
                independence=True,
                reasons=["OOB callback independently confirms outbound interaction"],
            )
        return EvidenceQualityScore(
            evidence_type=EvidenceType.OOB_CALLBACK,
            strength="medium",
            completeness=0.5,
            reproducibility="multi_step",
            independence=False,
            reasons=["OOB callback registered but not confirmed"],
        )

    @classmethod
    def _score_timing(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        delay = getattr(evidence, "triggered_time_ms", 0) - getattr(evidence, "baseline_time_ms", 0)
        if delay > 5000:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.TIMING_PROOF,
                strength="medium",
                completeness=0.6,
                reproducibility="multi_step",
                independence=False,
                reasons=[f"Timing delay of {delay:.0f}ms is significant"],
            )
        return EvidenceQualityScore(
            evidence_type=EvidenceType.TIMING_PROOF,
            strength="weak",
            completeness=0.4,
            reproducibility="single_request",
            independence=False,
            reasons=[f"Timing delay of {delay:.0f}ms may be network variance"],
        )

    @classmethod
    def _score_browser(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        alert = getattr(evidence, "alert_fired", False)
        dom = getattr(evidence, "dom_mutation", False)
        if alert or dom:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.BROWSER_EXECUTION,
                strength="strong",
                completeness=0.95,
                reproducibility="multi_step",
                independence=True,
                reasons=["JavaScript execution confirmed in browser context"],
            )
        return EvidenceQualityScore(
            evidence_type=EvidenceType.BROWSER_EXECUTION,
            strength="weak",
            completeness=0.3,
            reproducibility="single_request",
            independence=False,
            reasons=["Browser execution attempted but no alert/mutation detected"],
        )

    @classmethod
    def _score_authz(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        violated = getattr(evidence, "ownership_violated", False)
        if violated:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.AUTHORIZATION_COMPARISON,
                strength="very_strong",
                completeness=0.95,
                reproducibility="multi_step",
                independence=True,
                reasons=["Ownership violation proven with before/after comparison"],
            )
        diff = getattr(evidence, "content_different", False)
        if diff:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.AUTHORIZATION_COMPARISON,
                strength="medium",
                completeness=0.6,
                reproducibility="multi_step",
                independence=False,
                reasons=["Content differs between roles but ownership not confirmed"],
            )
        return EvidenceQualityScore(
            evidence_type=EvidenceType.AUTHORIZATION_COMPARISON,
            strength="weak",
            completeness=0.3,
            reproducibility="single_request",
            independence=False,
            reasons=["No access violation detected"],
        )

    @classmethod
    def _score_cmd(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        exit_code = getattr(evidence, "exit_code_observed", -1)
        if exit_code >= 0:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.COMMAND_EXECUTION,
                strength="strong",
                completeness=0.85,
                reproducibility="multi_step",
                independence=True,
                reasons=[f"Command execution confirmed with exit code {exit_code}"],
            )
        delay = getattr(evidence, "timing_delay_ms", 0)
        if delay > 3000:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.COMMAND_EXECUTION,
                strength="medium",
                completeness=0.5,
                reproducibility="multi_step",
                independence=False,
                reasons=[f"Timing-based command injection signal ({delay:.0f}ms delay)"],
            )
        return EvidenceQualityScore(
            evidence_type=EvidenceType.COMMAND_EXECUTION,
            strength="weak",
            completeness=0.3,
            reproducibility="single_request",
            independence=False,
            reasons=["Command injection detected syntactically only"],
        )

    @classmethod
    def _score_secret(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        is_valid = getattr(evidence, "is_valid", False)
        if is_valid:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.SECRET_VALIDATION,
                strength="very_strong",
                completeness=1.0,
                reproducibility="multi_step",
                independence=True,
                reasons=["Secret validated against live API"],
            )
        return EvidenceQualityScore(
            evidence_type=EvidenceType.SECRET_VALIDATION,
            strength="medium",
            completeness=0.5,
            reproducibility="single_request",
            independence=False,
            reasons=["Secret pattern detected but not validated against live API"],
        )

    @classmethod
    def _score_screenshot(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        return EvidenceQualityScore(
            evidence_type=EvidenceType.SCREENSHOT,
            strength="medium",
            completeness=0.7,
            reproducibility="single_request",
            independence=False,
            reasons=["Screenshot provides visual confirmation"],
        )

    @classmethod
    def _score_graphql(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        return EvidenceQualityScore(
            evidence_type=EvidenceType.GRAPHQL_SCHEMA,
            strength="medium",
            completeness=0.6,
            reproducibility="single_request",
            independence=False,
            reasons=["GraphQL schema introspection confirms exposure"],
        )

    @classmethod
    def _score_response_diff(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        diff = getattr(evidence, "content_length_diff", 0)
        if abs(diff) > 500:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.RESPONSE_DIFF,
                strength="medium",
                completeness=0.6,
                reproducibility="multi_step",
                independence=False,
                reasons=[f"Response diff of {diff:+d} bytes indicates behavior change"],
            )
        return EvidenceQualityScore(
            evidence_type=EvidenceType.RESPONSE_DIFF,
            strength="weak",
            completeness=0.3,
            reproducibility="single_request",
            independence=False,
            reasons=["Response diff is minimal or absent"],
        )

    @classmethod
    def _score_composite(cls, evidence: EvidenceBase) -> EvidenceQualityScore:
        count = getattr(evidence, "evidence_count", 0)
        if count >= 3:
            return EvidenceQualityScore(
                evidence_type=EvidenceType.COMPOSITE,
                strength="very_strong",
                completeness=min(1.0, 0.5 + count * 0.1),
                reproducibility="multi_step",
                independence=True,
                reasons=[f"Composite evidence from {count} sources provides corroboration"],
            )
        return EvidenceQualityScore(
            evidence_type=EvidenceType.COMPOSITE,
            strength="medium",
            completeness=0.5,
            reproducibility="multi_step",
            independence=False,
            reasons=["Composite evidence from limited sources"],
        )

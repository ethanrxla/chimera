from __future__ import annotations

from chimera_core.shannon.schemas import CandidateFinding, ValidatorDecision


def apply_validator_decision(
    *,
    candidate: CandidateFinding,
    verification_results,
    evidence_refs,
    prior_findings,
) -> ValidatorDecision:
    passed = [result for result in verification_results if getattr(result, "outcome", None) == "passed"]
    if not passed:
        return ValidatorDecision(
            status="rejected",
            final_claim_type=candidate.claim_type,
            severity=candidate.severity_claimed,
            rationale="No deterministic verifier passed.",
            duplicate_of=None,
            evidence_refs=[],
        )
    primary = passed[0]
    if candidate.claim_type == "broken_authentication" and primary.claim_type == "exposed_docs":
        return ValidatorDecision(
            status="downgraded",
            final_claim_type="exposed_docs",
            severity="medium",
            rationale="Evidence supports exposed docs/info disclosure, not broken authentication.",
            duplicate_of=None,
            evidence_refs=list(evidence_refs),
        )
    return ValidatorDecision(
        status="verified",
        final_claim_type=primary.claim_type,
        severity=candidate.severity_claimed,
        rationale="Deterministic verifier passed and evidence refs are present.",
        duplicate_of=None,
        evidence_refs=list(evidence_refs),
    )

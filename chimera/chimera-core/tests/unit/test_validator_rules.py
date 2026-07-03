from chimera_core.shannon.schemas import CandidateFinding
from chimera_core.shannon.validator import apply_validator_decision
from chimera_core.verifiers.base import VerificationResult


def test_validator_downgrades_exposed_docs_claim_not_auth_bypass() -> None:
    candidate = CandidateFinding(
        candidate_id="cand-1",
        source="strix",
        title="Broken Authentication - Insecure API Endpoint Exposure",
        claim_type="broken_authentication",
        severity_claimed="high",
        endpoint="/docs/api",
        target="https://example.com/docs/api",
        narrative="Public docs endpoint reachable without auth.",
    )
    verifier_result = VerificationResult(
        verification_id="ver-1",
        check_id="check-1",
        claim_type="exposed_docs",
        outcome="passed",
        rationale="Endpoint reachable and contains API docs markers.",
        evidence_refs=["artifacts/run-1/hexstrike/ver-1/check-1/response.json"],
    )

    decision = apply_validator_decision(
        candidate=candidate,
        verification_results=[verifier_result],
        evidence_refs=verifier_result.evidence_refs,
        prior_findings=[],
    )

    assert decision.status == "downgraded"
    assert decision.final_claim_type == "exposed_docs"
    assert "broken authentication" in decision.rationale.lower()

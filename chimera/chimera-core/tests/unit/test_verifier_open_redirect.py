from chimera_core.shannon.schemas import (
    CandidateFinding,
    ProbeInput,
    SuccessCondition,
    VerificationCheck,
    VerificationPlan,
)
from chimera_core.hexstrike.schemas import HexStrikeResult, HttpResponseSummary
from chimera_core.verifiers.open_redirect import OpenRedirectVerifier


def _plan() -> VerificationPlan:
    return VerificationPlan(
        verification_id="ver-1",
        candidate_id="cand-1",
        target="https://example.com",
        claim_type="open_redirect",
        checks=[
            VerificationCheck(
                check_id="check-1",
                probe_type="http_redirect_check",
                description="verify redirect parameter reflection",
                probe_input=ProbeInput(
                    method="GET",
                    url="https://example.com/login",
                    headers={},
                    query={"redirect": "https://attacker.example"},
                    body=None,
                    follow_redirects=False,
                    timeout_s=30,
                ),
                success_condition=SuccessCondition(
                    type="open_redirect",
                    rules={
                        "expected_redirect_statuses": [301, 302, 303, 307, 308],
                        "location_equals": "https://attacker.example",
                    },
                ),
            )
        ],
        required_artifact_kinds=["http_request", "http_response", "http_normalized"],
        planner_notes="Need external Location header reflection.",
    )


def test_open_redirect_verifier_passes_with_exact_location_match() -> None:
    verifier = OpenRedirectVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-1",
            ok=True,
            error=None,
            observed_targets=["https://example.com/login"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-1/check-1/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-1/check-1/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-1/check-1/normalized.json",
            summary=HttpResponseSummary(
                status_code=302,
                headers={"Location": "https://attacker.example"},
                body_excerpt="",
                body_sha256="abc123",
            ),
        ),
    )

    assert result.outcome == "passed"
    assert result.evidence_refs == [
        "artifacts/run-1/hexstrike/ver-1/check-1/request.json",
        "artifacts/run-1/hexstrike/ver-1/check-1/response.json",
        "artifacts/run-1/hexstrike/ver-1/check-1/normalized.json",
    ]


def test_open_redirect_verifier_fails_without_matching_location() -> None:
    verifier = OpenRedirectVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-1",
            ok=True,
            error=None,
            observed_targets=["https://example.com/login"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-1/check-1/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-1/check-1/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-1/check-1/normalized.json",
            summary=HttpResponseSummary(
                status_code=200,
                headers={"Location": "/dashboard"},
                body_excerpt="ok",
                body_sha256="abc123",
            ),
        ),
    )

    assert result.outcome == "failed"
    assert result.evidence_refs == []

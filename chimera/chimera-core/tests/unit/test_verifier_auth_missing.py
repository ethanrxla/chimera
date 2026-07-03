from chimera_core.hexstrike.schemas import HexStrikeResult, HttpResponseSummary
from chimera_core.shannon.schemas import ProbeInput, SuccessCondition, VerificationCheck, VerificationPlan
from chimera_core.verifiers.auth_missing import AuthMissingVerifier


def _plan() -> VerificationPlan:
    return VerificationPlan(
        verification_id="ver-auth",
        candidate_id="cand-auth",
        target="https://example.com/rest/user/whoami",
        claim_type="auth_missing",
        checks=[
            VerificationCheck(
                check_id="check-auth",
                probe_type="http_auth_missing_check",
                description="verify identity endpoint without auth",
                probe_input=ProbeInput(
                    method="GET",
                    url="https://example.com/rest/user/whoami",
                    headers={},
                    query={},
                    body=None,
                    follow_redirects=True,
                    timeout_s=30,
                ),
                success_condition=SuccessCondition(
                    type="auth_missing",
                    rules={
                        "status_in": [200],
                        "body_contains_any": ["user", "email", "id"],
                        "allow_non_error_200": True,
                    },
                ),
            )
        ],
        required_artifact_kinds=["http_request", "http_response", "http_normalized"],
        planner_notes="Need anonymous identity leakage.",
    )


def test_auth_missing_verifier_passes_on_identity_data() -> None:
    verifier = AuthMissingVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-auth",
            ok=True,
            error=None,
            observed_targets=["https://example.com/rest/user/whoami"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-auth/check-auth/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-auth/check-auth/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-auth/check-auth/normalized.json",
            summary=HttpResponseSummary(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body_excerpt='{"id":1,"email":"user@example.com"}',
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "passed"


def test_auth_missing_verifier_fails_on_unauthorized_body() -> None:
    verifier = AuthMissingVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-auth",
            ok=True,
            error=None,
            observed_targets=["https://example.com/rest/user/whoami"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-auth/check-auth/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-auth/check-auth/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-auth/check-auth/normalized.json",
            summary=HttpResponseSummary(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body_excerpt='{"message":"Unauthorized"}',
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "failed"

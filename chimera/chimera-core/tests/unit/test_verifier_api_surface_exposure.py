from chimera_core.hexstrike.schemas import HexStrikeResult, HttpResponseSummary
from chimera_core.shannon.schemas import ProbeInput, SuccessCondition, VerificationCheck, VerificationPlan
from chimera_core.verifiers.api_surface_exposure import ApiSurfaceExposureVerifier


def _plan() -> VerificationPlan:
    return VerificationPlan(
        verification_id="ver-api",
        candidate_id="cand-api",
        target="https://example.com/openapi.json",
        claim_type="api_surface_exposure",
        checks=[
            VerificationCheck(
                check_id="check-api",
                probe_type="http_api_surface_check",
                description="verify api surface exposure",
                probe_input=ProbeInput(
                    method="GET",
                    url="https://example.com/openapi.json",
                    headers={},
                    query={},
                    body=None,
                    follow_redirects=True,
                    timeout_s=30,
                ),
                success_condition=SuccessCondition(
                    type="api_surface_exposure",
                    rules={
                        "status_in": [200, 400],
                        "endpoint_contains_any": ["/openapi.json", "/graphql"],
                        "body_contains_any": ["openapi", "\"paths\"", "graphql"],
                        "allow_endpoint_match": True,
                    },
                ),
            )
        ],
        required_artifact_kinds=["http_request", "http_response", "http_normalized"],
        planner_notes="Need API schema exposure markers.",
    )


def test_api_surface_verifier_passes_on_exposed_endpoint() -> None:
    verifier = ApiSurfaceExposureVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-api",
            ok=True,
            error=None,
            observed_targets=["https://example.com/openapi.json"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-api/check-api/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-api/check-api/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-api/check-api/normalized.json",
            summary=HttpResponseSummary(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body_excerpt='{"title":"app"}',
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "passed"


def test_api_surface_verifier_fails_when_endpoint_is_not_api_like() -> None:
    verifier = ApiSurfaceExposureVerifier()
    plan = _plan()
    check = plan.checks[0]
    mutated = VerificationPlan(
        verification_id=plan.verification_id,
        candidate_id=plan.candidate_id,
        target="https://example.com/home",
        claim_type=plan.claim_type,
        checks=[
            VerificationCheck(
                check_id=check.check_id,
                probe_type=check.probe_type,
                description=check.description,
                probe_input=ProbeInput(
                    method=check.probe_input.method,
                    url="https://example.com/home",
                    headers=check.probe_input.headers,
                    query=check.probe_input.query,
                    body=check.probe_input.body,
                    follow_redirects=check.probe_input.follow_redirects,
                    timeout_s=check.probe_input.timeout_s,
                ),
                success_condition=check.success_condition,
            )
        ],
        required_artifact_kinds=plan.required_artifact_kinds,
        planner_notes=plan.planner_notes,
    )
    result = verifier.verify(
        run_id="run-1",
        plan=mutated,
        hexstrike_result=HexStrikeResult(
            call_id="call-api",
            ok=True,
            error=None,
            observed_targets=["https://example.com/home"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-api/check-api/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-api/check-api/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-api/check-api/normalized.json",
            summary=HttpResponseSummary(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body_excerpt="<html>home</html>",
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "failed"

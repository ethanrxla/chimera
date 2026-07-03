from chimera_core.hexstrike.schemas import HexStrikeResult, HttpResponseSummary
from chimera_core.shannon.schemas import ProbeInput, SuccessCondition, VerificationCheck, VerificationPlan
from chimera_core.verifiers.admin_exposure import AdminExposureVerifier


def _plan() -> VerificationPlan:
    return VerificationPlan(
        verification_id="ver-admin",
        candidate_id="cand-admin",
        target="https://example.com/admin",
        claim_type="admin_exposure",
        checks=[
            VerificationCheck(
                check_id="check-admin",
                probe_type="http_admin_access_check",
                description="verify anonymous admin access",
                probe_input=ProbeInput(
                    method="GET",
                    url="https://example.com/admin",
                    headers={},
                    query={},
                    body=None,
                    follow_redirects=True,
                    timeout_s=30,
                ),
                success_condition=SuccessCondition(
                    type="admin_exposure",
                    rules={
                        "status_in": [200],
                        "endpoint_contains_any": ["/admin", "/rest/admin"],
                        "body_contains_any": ["admin", "dashboard"],
                        "allow_path_only_match": True,
                    },
                ),
            )
        ],
        required_artifact_kinds=["http_request", "http_response", "http_normalized"],
        planner_notes="Need anonymous success on admin endpoint.",
    )


def test_admin_exposure_verifier_passes_on_admin_like_endpoint() -> None:
    verifier = AdminExposureVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-admin",
            ok=True,
            error=None,
            observed_targets=["https://example.com/admin"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-admin/check-admin/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-admin/check-admin/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-admin/check-admin/normalized.json",
            summary=HttpResponseSummary(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body_excerpt="<html>single page app shell</html>",
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "passed"
    assert len(result.evidence_refs) == 3


def test_admin_exposure_verifier_fails_on_forbidden() -> None:
    verifier = AdminExposureVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-admin",
            ok=True,
            error=None,
            observed_targets=["https://example.com/admin"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-admin/check-admin/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-admin/check-admin/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-admin/check-admin/normalized.json",
            summary=HttpResponseSummary(
                status_code=403,
                headers={"Content-Type": "text/html"},
                body_excerpt="forbidden",
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "failed"

from chimera_core.hexstrike.schemas import HexStrikeResult, HttpResponseSummary
from chimera_core.shannon.schemas import ProbeInput, SuccessCondition, VerificationCheck, VerificationPlan
from chimera_core.verifiers.idor import IDORVerifier


def _plan() -> VerificationPlan:
    return VerificationPlan(
        verification_id="ver-idor",
        candidate_id="cand-idor",
        target="https://example.com/rest/basket/2",
        claim_type="idor",
        checks=[
            VerificationCheck(
                check_id="check-idor",
                probe_type="http_idor_check",
                description="verify alternate object id access",
                probe_input=ProbeInput(
                    method="GET",
                    url="https://example.com/rest/basket/2",
                    headers={},
                    query={},
                    body=None,
                    follow_redirects=True,
                    timeout_s=30,
                ),
                success_condition=SuccessCondition(
                    type="idor",
                    rules={"status_in": [200], "require_numeric_object_id": True},
                ),
            )
        ],
        required_artifact_kinds=["http_request", "http_response", "http_normalized"],
        planner_notes="Need alternate object id to stay accessible.",
    )


def test_idor_verifier_passes_on_accessible_alternate_object() -> None:
    verifier = IDORVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-idor",
            ok=True,
            error=None,
            observed_targets=["https://example.com/rest/basket/2"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-idor/check-idor/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-idor/check-idor/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-idor/check-idor/normalized.json",
            summary=HttpResponseSummary(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body_excerpt='{"data":{"Products":[]}}',
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "passed"


def test_idor_verifier_fails_on_access_denied() -> None:
    verifier = IDORVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-idor",
            ok=True,
            error=None,
            observed_targets=["https://example.com/rest/basket/2"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-idor/check-idor/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-idor/check-idor/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-idor/check-idor/normalized.json",
            summary=HttpResponseSummary(
                status_code=403,
                headers={"Content-Type": "application/json"},
                body_excerpt='{"message":"Forbidden"}',
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "failed"

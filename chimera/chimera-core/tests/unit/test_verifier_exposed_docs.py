from chimera_core.hexstrike.schemas import HexStrikeResult, HttpResponseSummary
from chimera_core.shannon.schemas import ProbeInput, SuccessCondition, VerificationCheck, VerificationPlan
from chimera_core.verifiers.exposed_docs import ExposedDocsVerifier


def _plan() -> VerificationPlan:
    return VerificationPlan(
        verification_id="ver-docs",
        candidate_id="cand-docs",
        target="https://example.com/docs/api",
        claim_type="exposed_docs",
        checks=[
            VerificationCheck(
                check_id="check-docs",
                probe_type="http_exposed_docs_check",
                description="verify public docs endpoint",
                probe_input=ProbeInput(
                    method="GET",
                    url="https://example.com/docs/api",
                    headers={},
                    query={},
                    body=None,
                    follow_redirects=True,
                    timeout_s=30,
                ),
                success_condition=SuccessCondition(
                    type="exposed_docs",
                    rules={"status_in": [200], "body_contains_any": ["openapi", "swagger", "\"paths\""]},
                ),
            )
        ],
        required_artifact_kinds=["http_request", "http_response", "http_normalized"],
        planner_notes="Need docs markers in response body.",
    )


def test_exposed_docs_verifier_passes_with_docs_markers() -> None:
    verifier = ExposedDocsVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-docs",
            ok=True,
            error=None,
            observed_targets=["https://example.com/docs/api"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-docs/check-docs/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-docs/check-docs/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-docs/check-docs/normalized.json",
            summary=HttpResponseSummary(
                status_code=200,
                headers={"Content-Type": "application/json"},
                body_excerpt='{"openapi":"3.1.0","paths":{}}',
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "passed"
    assert result.claim_type == "exposed_docs"
    assert len(result.evidence_refs) == 3


def test_exposed_docs_verifier_fails_without_docs_markers() -> None:
    verifier = ExposedDocsVerifier()
    result = verifier.verify(
        run_id="run-1",
        plan=_plan(),
        hexstrike_result=HexStrikeResult(
            call_id="call-docs",
            ok=True,
            error=None,
            observed_targets=["https://example.com/docs/api"],
            request_artifact_ref="artifacts/run-1/hexstrike/ver-docs/check-docs/request.json",
            response_artifact_ref="artifacts/run-1/hexstrike/ver-docs/check-docs/response.json",
            normalized_artifact_ref="artifacts/run-1/hexstrike/ver-docs/check-docs/normalized.json",
            summary=HttpResponseSummary(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body_excerpt="<html>home</html>",
                body_sha256="abc",
            ),
        ),
    )

    assert result.outcome == "failed"

from chimera_core.shannon.schemas import CandidateFinding, ProbeInput, SuccessCondition, VerificationCheck, VerificationPlan


def test_verification_plan_round_trip_dict() -> None:
    plan = VerificationPlan(
        verification_id="ver-1",
        candidate_id="cand-1",
        target="https://example.com",
        claim_type="open_redirect",
        checks=[
            VerificationCheck(
                check_id="check-1",
                probe_type="http_redirect_check",
                description="verify redirect parameter",
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
                    rules={"location_equals": "https://attacker.example"},
                ),
            )
        ],
        required_artifact_kinds=["http_request", "http_response"],
        planner_notes="exact match required",
    )

    payload = plan.to_dict()
    assert payload["verification_id"] == "ver-1"
    assert payload["checks"][0]["success_condition"]["type"] == "open_redirect"

    candidate = CandidateFinding(
        candidate_id="cand-1",
        source="strix",
        title="Open Redirect",
        claim_type="open_redirect",
        severity_claimed="medium",
        endpoint="/login",
        target="https://example.com/login",
    )
    assert candidate.to_dict()["claim_type"] == "open_redirect"

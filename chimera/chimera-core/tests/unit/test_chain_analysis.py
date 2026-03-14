from chimera_core.chain_analysis import synthesize_chains
from chimera_core.findings import Finding


def _finding(finding_id: str, finding_type: str, title: str, validation_status: str = "confirmed") -> Finding:
    return Finding(
        finding_id=finding_id,
        severity="high",
        title=title,
        description=title,
        affected_target="https://api.example.com/users/7",
        tool_source="test",
        tool_version="1.0",
        run_id="run-1",
        scope_hash="scope",
        finding_type=finding_type,
        validation_status=validation_status,
        confidence=0.9,
    )


def test_synthesize_chains_uses_explicit_rules() -> None:
    records = synthesize_chains(
        [
            _finding("f-idor", "IDOR", "IDOR on profile endpoint"),
            _finding("f-jwt", "JWT", "JWT alg none accepted", validation_status="confirmed"),
        ],
        run_id="run-1",
        scope_hash="scope",
        target="https://api.example.com/users/7",
    )

    assert len(records) == 1
    assert records[0].rule_id == "idor_jwt_takeover"
    assert records[0].finding.finding_type == "EXPLOIT_CHAIN"
    assert records[0].finding.severity == "critical"


def test_synthesize_chains_requires_rule_inputs() -> None:
    records = synthesize_chains(
        [_finding("f-auth", "AUTH_EXPOSURE", "Unauthenticated API exposure")],
        run_id="run-1",
        scope_hash="scope",
        target="https://api.example.com/users/7",
    )

    assert records == []

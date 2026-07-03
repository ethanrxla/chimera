from pathlib import Path

from chimera_core.artifacts import ArtifactWriter
from chimera_core.event_store import EventStore
from chimera_core.findings_gate import promote_validated_finding
from chimera_core.shannon.schemas import CandidateFinding, ValidatorDecision
from chimera_core.verifiers.base import VerificationResult


def test_findings_gate_rejects_verified_claim_without_evidence_refs(tmp_path: Path) -> None:
    events_path = tmp_path / "artifacts" / "run-1" / "events.jsonl"
    events_path.parent.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(events_path)
    artifact_writer = ArtifactWriter(tmp_path / "artifacts", event_store=event_store)

    decision = promote_validated_finding(
        run_id="run-1",
        candidate=CandidateFinding(
            candidate_id="cand-1",
            source="strix",
            title="Open Redirect",
            claim_type="open_redirect",
            severity_claimed="medium",
            endpoint="/login",
            target="https://example.com/login",
        ),
        validator_decision=ValidatorDecision(
            status="verified",
            final_claim_type="open_redirect",
            severity="medium",
            rationale="looks good",
            duplicate_of=None,
            evidence_refs=[],
        ),
        verification_results=[
            VerificationResult(
                verification_id="ver-1",
                check_id="check-1",
                claim_type="open_redirect",
                outcome="passed",
                rationale="redirect matched",
                evidence_refs=[],
            )
        ],
        artifact_writer=artifact_writer,
        event_store=event_store,
    )

    assert decision.accepted is False
    assert decision.status == "rejected"
    assert "evidence_refs" in decision.reason


def test_findings_gate_promotes_verified_claim_with_existing_evidence(tmp_path: Path) -> None:
    events_path = tmp_path / "artifacts" / "run-1" / "events.jsonl"
    events_path.parent.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(events_path)
    artifact_writer = ArtifactWriter(tmp_path / "artifacts", event_store=event_store)

    request_ref = artifact_writer.write_json(
        run_id="run-1",
        relpath="hexstrike/ver-1/check-1/request.json",
        kind="http_request",
        obj={"url": "https://example.com/login?redirect=https://attacker.example"},
        source="hexstrike",
        task_id="check-1",
    )
    response_ref = artifact_writer.write_json(
        run_id="run-1",
        relpath="hexstrike/ver-1/check-1/response.json",
        kind="http_response",
        obj={"status_code": 302, "headers": {"Location": "https://attacker.example"}},
        source="hexstrike",
        task_id="check-1",
    )

    decision = promote_validated_finding(
        run_id="run-1",
        candidate=CandidateFinding(
            candidate_id="cand-1",
            source="strix",
            title="Open Redirect",
            claim_type="open_redirect",
            severity_claimed="medium",
            endpoint="/login",
            target="https://example.com/login",
        ),
        validator_decision=ValidatorDecision(
            status="verified",
            final_claim_type="open_redirect",
            severity="medium",
            rationale="verified by redirect evidence",
            duplicate_of=None,
            evidence_refs=[request_ref.relpath, response_ref.relpath],
        ),
        verification_results=[
            VerificationResult(
                verification_id="ver-1",
                check_id="check-1",
                claim_type="open_redirect",
                outcome="passed",
                rationale="redirect matched",
                evidence_refs=[request_ref.relpath, response_ref.relpath],
            )
        ],
        artifact_writer=artifact_writer,
        event_store=event_store,
    )

    assert decision.accepted is True
    assert decision.status == "verified"
    assert decision.finding is not None
    assert decision.finding["evidence_refs"] == [request_ref.relpath, response_ref.relpath]

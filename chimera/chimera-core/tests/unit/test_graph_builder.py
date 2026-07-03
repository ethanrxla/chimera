import json
from pathlib import Path

from chimera_core.graph.builder import build_evidence_graph


def test_graph_builder_creates_event_artifact_and_finding_edges(tmp_path: Path) -> None:
    artifacts_root = tmp_path / "artifacts"
    run_root = artifacts_root / "run-1"
    command_root = run_root / "commands" / "task-1"
    command_root.mkdir(parents=True, exist_ok=True)
    stdout_path = command_root / "stdout.txt"
    stdout_path.write_text("ok", encoding="utf-8")

    events = [
        {
            "event_id": "e1",
            "run_id": "run-1",
            "seq": 1,
            "event_type": "cmd_started",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "source": "runtime",
            "payload": {"task_id": "task-1", "command": ["curl", "https://example.com"]},
        },
        {
            "event_id": "e2",
            "run_id": "run-1",
            "seq": 2,
            "event_type": "artifact_saved",
            "timestamp": "2026-01-01T00:00:01+00:00",
            "source": "runtime",
            "payload": {"task_id": "task-1", "path": str(stdout_path), "artifact_type": "stdout"},
        },
    ]

    findings_path = run_root / "findings.json"
    findings_path.write_text(
        json.dumps(
            [
                {
                    "finding_id": "finding-1",
                    "severity": "medium",
                    "title": "XSS",
                    "affected_target": "https://example.com/search",
                    "evidence_refs": [str(stdout_path)],
                }
            ]
        ),
        encoding="utf-8",
    )

    graph = build_evidence_graph(events=events, artifacts_root=artifacts_root, findings_path=findings_path)
    edge_labels = {(edge.src, edge.label, edge.dst) for edge in graph.edges}

    assert ("run:run-1", "HAS_EVENT", "event:e1") in edge_labels
    assert ("event:e1", "NEXT", "event:e2") in edge_labels
    assert any(edge.label == "EMITS_ARTIFACT" for edge in graph.edges)
    assert any(edge.label == "TASK_PRODUCED" for edge in graph.edges)
    assert any(edge.label == "EVIDENCE_FOR" for edge in graph.edges)
    assert any(edge.label == "TARGETS" and edge.src == "finding:finding-1" for edge in graph.edges)


def test_graph_builder_links_promoted_findings_and_verification_evidence(tmp_path: Path) -> None:
    artifacts_root = tmp_path / "artifacts"
    run_root = artifacts_root / "run-2"
    verify_root = run_root / "hexstrike" / "ver-1" / "check-1"
    verify_root.mkdir(parents=True, exist_ok=True)
    response_path = verify_root / "response.json"
    response_path.write_text('{"status_code":302}', encoding="utf-8")

    events = [
        {
            "event_id": "e1",
            "run_id": "run-2",
            "seq": 1,
            "event_type": "artifact_saved",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "source": "hexstrike",
            "payload": {"task_id": "t1", "path": str(response_path), "artifact_type": "http_response"},
        },
        {
            "event_id": "e2",
            "run_id": "run-2",
            "seq": 2,
            "event_type": "verification_passed",
            "timestamp": "2026-01-01T00:00:01+00:00",
            "source": "chimera",
            "payload": {
                "verification_id": "ver-1",
                "check_id": "check-1",
                "claim_type": "open_redirect",
                "evidence_refs": [str(response_path)],
            },
        },
        {
            "event_id": "e3",
            "run_id": "run-2",
            "seq": 3,
            "event_type": "finding_promoted",
            "timestamp": "2026-01-01T00:00:02+00:00",
            "source": "chimera",
            "payload": {
                "candidate_id": "cand-1",
                "finding_id": "finding-2",
                "claim_type": "open_redirect",
                "severity": "medium",
                "evidence_refs": [str(response_path)],
            },
        },
    ]

    graph = build_evidence_graph(events=events, artifacts_root=artifacts_root, findings_path=None)
    edge_labels = {(edge.src, edge.label, edge.dst) for edge in graph.edges}
    assert any(edge.label == "EVIDENCE_FOR" and edge.dst == "finding:finding-2" for edge in graph.edges)


def test_graph_builder_links_agent_events_and_handoffs(tmp_path: Path) -> None:
    artifacts_root = tmp_path / "artifacts"
    events = [
        {
            "event_id": "e1",
            "run_id": "run-3",
            "seq": 1,
            "event_type": "agent_started",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "source": "shannon",
            "payload": {"task_id": "shannon-1", "mode": "investigate", "agent_role": "analysis"},
        },
        {
            "event_id": "e2",
            "run_id": "run-3",
            "seq": 2,
            "event_type": "agent_tool_called",
            "timestamp": "2026-01-01T00:00:01+00:00",
            "source": "shannon",
            "payload": {
                "task_id": "shannon-1",
                "call_id": "call-1",
                "tool_name": "browser_navigate",
                "target_refs": ["https://example.com/login"],
            },
        },
        {
            "event_id": "e3",
            "run_id": "run-3",
            "seq": 3,
            "event_type": "agent_handoff_created",
            "timestamp": "2026-01-01T00:00:02+00:00",
            "source": "shannon",
            "payload": {
                "task_id": "shannon-1",
                "candidate_id": "cand-1",
                "claim_type": "open_redirect",
            },
        },
    ]

    graph = build_evidence_graph(events=events, artifacts_root=artifacts_root, findings_path=None)
    edge_labels = {(edge.src, edge.label, edge.dst) for edge in graph.edges}

    assert ("run:run-3", "HAS_TASK", "agent:shannon-1") in edge_labels
    assert ("agent:shannon-1", "TASK_PRODUCED", "agent_call:call-1") in edge_labels
    assert ("agent_call:call-1", "TARGETS", "asset:https://example.com/login") in edge_labels
    assert ("agent:shannon-1", "TASK_PRODUCED", "candidate:cand-1") in edge_labels

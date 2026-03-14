from pathlib import Path

import pytest
from unittest.mock import Mock

from chimera_core.adapters.autoswagger_adapter import AutoswaggerAdapter
from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def load_fixture(name: str) -> str:
    base = Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger"
    return (base / name).read_text(encoding="utf-8")


def make_runtime(tmp_path: Path):
    scope_manifest = {"allowlist": ["api.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-123"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(run_dir / "events.jsonl")
    runtime = Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
    )
    return runtime


def make_adapter(tmp_path, options=None, rate_limits=None, scope_hash="scope-123"):
    runtime = make_runtime(tmp_path)
    return AutoswaggerAdapter(
        runtime=runtime,
        options=options,
        rate_limits=rate_limits,
        run_id="run-123",
        task_id="T1",
        scope_hash=scope_hash,
    )


def test_autoswagger_build_command_includes_rate_and_flags(tmp_path):
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={"json": True, "risk": True, "verbose": True},
        rate_limits={"requests_per_second": 7},
    )
    command = adapter.build_command(["https://api.example.com"])
    assert str(adapter.tool_path) in command
    assert "-json" in command
    assert "-risk" in command
    assert "-v" in command
    assert "-rate" in command
    assert "7" in command


def test_autoswagger_enforces_scope(tmp_path):
    adapter = make_adapter(tmp_path=tmp_path)
    with pytest.raises(ValueError):
        adapter.build_command(["https://evil.com"])


def test_autoswagger_normalizes_fixture_output(tmp_path):
    adapter = make_adapter(tmp_path=tmp_path)
    raw_output = load_fixture("output.json")
    findings = adapter.normalize(raw_output)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.to_dict() == {
        "finding_id": "autoswagger:GET:https://api.example.com/users:200",
        "severity": "low",
        "title": "Unauthenticated API data exposure",
        "description": "GET https://api.example.com/users returned 200 with PII.",
        "affected_target": "https://api.example.com/users",
        "evidence_refs": [],
        "tool_source": "autoswagger",
        "tool_version": "0.1.0",
        "repro_guidance": None,
        "timestamps": finding.timestamps.isoformat(),
        "run_id": "run-123",
        "scope_hash": "scope-123",
        "status": "new",
        "finding_type": "AUTH_EXPOSURE",
        "asset": {
            "host": "api.example.com",
            "endpoint": "/users",
            "method": "GET",
            "parameter": None,
        },
        "confidence": 0.55,
    }


def test_autoswagger_run_uses_runtime_command(tmp_path):
    raw_output = load_fixture("output.json")
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={"live": True, "json": True},
        rate_limits={"requests_per_second": 5},
    )
    adapter.runtime.run_cmd = Mock(
        return_value=Mock(stdout=raw_output, stderr="", returncode=0)
    )

    adapter.run(["https://api.example.com"])

    assert adapter.runtime.run_cmd.called
    command = adapter.runtime.run_cmd.call_args.args[0]
    assert command[0].endswith("python") or command[0].endswith("python3") or command[0].endswith("python3.13")
    assert str(adapter.tool_path) in command
    assert "-json" in command
    assert "-rate" in command
    assert "5" in command
    assert "https://api.example.com" in command


def test_autoswagger_writes_artifact(tmp_path):
    raw_output = load_fixture("output.json")
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={"raw_output_override": raw_output},
    )
    result = adapter.run(["https://api.example.com"])
    artifacts = result["artifacts"]
    raw_paths = [Path(artifact["path"]) for artifact in artifacts if artifact["artifact_type"] == "raw_output"]
    findings_paths = [Path(artifact["path"]) for artifact in artifacts if artifact["artifact_type"] == "findings"]
    assert len(raw_paths) == 1
    assert len(findings_paths) == 1
    assert raw_paths[0].exists()
    assert raw_paths[0].read_text(encoding="utf-8") == raw_output

    events = list(adapter.runtime.event_store.replay())
    event_types = [event["event_type"] for event in events]
    expected = ["task_started", "cmd_started", "artifact_saved", "cmd_finished", "task_finished"]
    cursor = 0
    for name in expected:
        while cursor < len(event_types) and event_types[cursor] != name:
            cursor += 1
        assert cursor < len(event_types), f"Missing event: {name}"
        cursor += 1

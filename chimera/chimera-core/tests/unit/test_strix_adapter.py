from pathlib import Path
from unittest.mock import Mock

import pytest

from chimera_core.adapters.strix_adapter import StrixAdapter
from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy

def load_fixture(name: str) -> str:
    base = Path(__file__).resolve().parents[1] / "fixtures" / "strix"
    return (base / name).read_text(encoding="utf-8")

def make_runtime(tmp_path: Path):
    scope_manifest = {"allowlist": ["www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-456"
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

def make_adapter(tmp_path, options=None, rate_limits=None, scope_hash="scope-456"):
    runtime = make_runtime(tmp_path)
    return StrixAdapter(
        runtime=runtime,
        options=options,
        rate_limits=rate_limits,
        run_id="run-456",
        task_id="T2",
        scope_hash=scope_hash,
    )

def test_strix_build_command_includes_rate_and_flags(tmp_path):
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={"scan_mode": "full", "aggressive": True},
        rate_limits={"requests_per_second": 5},
    )
    command = adapter.build_command(["https://www.example.com"])
    assert "python" in command[0]
    assert str(adapter.tool_path) in command
    assert "--mode" in command and "full" in command
    assert "--aggressive" in command
    assert "--rate" in command and "5" in command
    assert "https://www.example.com" in command

def test_strix_enforces_scope(tmp_path):
    adapter = make_adapter(tmp_path=tmp_path)
    with pytest.raises(ValueError):
        adapter.build_command(["https://evil.com"])

def test_strix_normalizes_fixture_output(tmp_path):
    adapter = make_adapter(tmp_path=tmp_path)
    raw_output = load_fixture("output.json")
    findings = adapter.normalize(raw_output)
    assert len(findings) == 3

    # Check specific finding 1 (XSS)
    xss_finding = next((f for f in findings if "XSS" in f.title), None)
    assert xss_finding is not None
    assert xss_finding.severity == "high"
    assert "www.example.com/search" in xss_finding.affected_target
    assert "Reflected XSS" in xss_finding.description

    # Check specific finding 2 (CORS)
    cors_finding = next((f for f in findings if "CORS" in f.title), None)
    assert cors_finding is not None
    assert cors_finding.severity == "medium"
    assert "www.example.com" in cors_finding.affected_target

    # Check specific finding 3 (Open Redirect)
    redirect_finding = next((f for f in findings if "Open Redirect" in f.title), None)
    assert redirect_finding is not None
    assert redirect_finding.severity == "medium"
    assert "www.example.com/redirect" in redirect_finding.affected_target

    # Verify common fields
    for f in findings:
        assert f.tool_source == "strix"
        assert f.tool_version == "strix-1.0.0"
        assert f.run_id == "run-456"
        assert f.scope_hash == "scope-456"
        assert f.status == "new"
        assert f.timestamps is not None

def test_strix_run_uses_runtime_command(tmp_path: Path):
    raw_output = load_fixture("output.json")
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={"live": True, "scan_mode": "full"},
        rate_limits={"requests_per_second": 3},
    )
    adapter.runtime.run_cmd = Mock(
        return_value=Mock(stdout=raw_output, stderr="", returncode=0)
    )

    adapter.run(["https://www.example.com"])

    assert adapter.runtime.run_cmd.called
    command = adapter.runtime.run_cmd.call_args.args[0]
    assert str(adapter.tool_path) in command
    assert "--mode" in command and "full" in command
    assert "--rate" in command and "3" in command
    assert "https://www.example.com" in command


def test_strix_writes_artifact(tmp_path: Path):
    raw_output = load_fixture("output.json")
    adapter = make_adapter(tmp_path=tmp_path, options={"raw_output_override": raw_output})
    result = adapter.run(["https://www.example.com"])
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

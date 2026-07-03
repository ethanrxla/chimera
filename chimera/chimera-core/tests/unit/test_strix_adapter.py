from pathlib import Path
from unittest.mock import Mock, patch

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
        options={"scan_mode": "full"},
        rate_limits={"requests_per_second": 5},
    )
    command = adapter.build_command(["https://www.example.com"])
    assert command[0].endswith("strix")
    assert "-n" in command
    assert "--scan-mode" in command and "full" in command
    assert "https://www.example.com" in command
    # rate is embedded in the instruction string
    assert any("5 rps" in arg for arg in command)


def test_strix_build_command_normalizes_multiline_instruction(tmp_path):
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "instruction": (
                "Perform pre-reconnaissance static architectural analysis first.\n\n"
                "Map entry points and auth systems."
            )
        },
        rate_limits={"requests_per_second": 3},
    )
    command = adapter.build_command(["https://www.example.com"])
    instruction = command[command.index("--instruction") + 1]
    assert "\n" not in instruction
    assert "Perform pre-reconnaissance static architectural analysis first." in instruction
    assert "Map entry points and auth systems." in instruction
    assert "Respect rate limit: 3 rps." in instruction

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
    assert command[0].endswith("strix")
    assert "--scan-mode" in command and "full" in command
    assert any("3 rps" in arg for arg in command)
    assert "https://www.example.com" in command


def test_strix_error_prefers_stdout_fatal_over_stderr_noise(tmp_path: Path):
    """When strix exits non-zero with a transient sandbox error, it retries up to 3 times,
    then raises the stdout fatal message (not stderr Python warnings)."""
    adapter = make_adapter(tmp_path=tmp_path, options={"live": True})
    fatal_stdout = "Tool server failed to start\nContainer initialization timed out. Please try again."
    noisy_stderr = (
        "DeprecationWarning: 'imghdr' is deprecated\n"
        "UserWarning: Some non-fatal warning\n"
    )
    mock_result = Mock(stdout=fatal_stdout, stderr=noisy_stderr, returncode=1, exit_code=1)
    adapter.tool_runner.run = Mock(return_value=mock_result)
    adapter._existing_strix_run_dirs = Mock(return_value=set())
    adapter._cleanup_sandbox_container = Mock()

    with patch("chimera_core.adapters.strix_adapter.time.sleep") as mock_sleep:
        with pytest.raises(RuntimeError) as exc_info:
            adapter.run(["https://www.example.com"])

    # All 3 attempts exhausted, sleep called between each retry
    assert adapter.tool_runner.run.call_count == 3
    assert mock_sleep.call_count == 2

    error_text = str(exc_info.value)
    assert "Tool server failed to start" in error_text, (
        f"Expected stdout fatal message in error, got: {error_text!r}"
    )
    assert "DeprecationWarning" not in error_text, (
        f"Stderr noise must not appear in error message, got: {error_text!r}"
    )


def test_strix_error_falls_back_to_stderr_when_stdout_empty(tmp_path: Path):
    """If stdout is empty but stderr has content, use stderr as the error message."""
    adapter = make_adapter(tmp_path=tmp_path, options={"live": True})
    mock_result = Mock(stdout="", stderr="docker: permission denied", returncode=1, exit_code=1)
    adapter.tool_runner.run = Mock(return_value=mock_result)
    adapter._existing_strix_run_dirs = Mock(return_value=set())
    adapter._cleanup_sandbox_container = Mock()

    with pytest.raises(RuntimeError) as exc_info:
        adapter.run(["https://www.example.com"])

    assert "docker: permission denied" in str(exc_info.value)


def test_strix_error_fallback_message_when_both_streams_empty(tmp_path: Path):
    """If both streams are empty, report a generic exit-code message."""
    adapter = make_adapter(tmp_path=tmp_path, options={"live": True})
    mock_result = Mock(stdout="", stderr="", returncode=2, exit_code=2)
    adapter.tool_runner.run = Mock(return_value=mock_result)
    adapter._existing_strix_run_dirs = Mock(return_value=set())
    adapter._cleanup_sandbox_container = Mock()

    with pytest.raises(RuntimeError) as exc_info:
        adapter.run(["https://www.example.com"])

    assert "exited with code 2" in str(exc_info.value)


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
    expected = ["task_started", "llm_started", "cmd_started", "artifact_saved", "llm_finished", "cmd_finished", "task_finished"]
    cursor = 0
    for name in expected:
        while cursor < len(event_types) and event_types[cursor] != name:
            cursor += 1
        assert cursor < len(event_types), f"Missing event: {name}"
        cursor += 1

import sys
from pathlib import Path

from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def test_runtime_executes_mock_command_and_emits_events(tmp_path: Path):
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)

    artifacts_root = tmp_path / "artifacts"
    run_id = "run-mock"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    events_file = run_dir / "events.jsonl"
    event_store = EventStore(events_file)

    runtime = Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
    )

    event_store.emit({"event_type": "run_created", "payload": {"run_id": run_id}})
    event_store.emit({"event_type": "task_started", "payload": {"run_id": run_id, "task_id": "mock-task"}})

    command = [sys.executable, "-c", "print('hello')", "https://example.com"]
    runtime.run_cmd(command, task_id="mock-task")

    event_store.emit({"event_type": "task_finished", "payload": {"run_id": run_id, "task_id": "mock-task"}})

    assert run_dir.exists()
    assert events_file.exists()

    events = list(event_store.replay())
    event_types = [event["event_type"] for event in events]

    expected_order = [
        "run_created",
        "task_started",
        "cmd_started",
        "artifact_saved",
        "cmd_finished",
        "task_finished",
    ]
    cursor = 0
    for expected in expected_order:
        while cursor < len(event_types) and event_types[cursor] != expected:
            cursor += 1
        assert cursor < len(event_types), f"Missing event: {expected}"
        cursor += 1

    stdout_path = run_dir / "commands" / "mock-task" / "stdout.txt"
    stderr_path = run_dir / "commands" / "mock-task" / "stderr.txt"
    assert stdout_path.exists()
    assert stderr_path.exists()

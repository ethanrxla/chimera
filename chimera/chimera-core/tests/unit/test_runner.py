import pytest
from unittest.mock import Mock
from pathlib import Path

from chimera_core.planner import ExecutionPlan, Task
from chimera_core.context import RunContext
from chimera_core.runner import Runner
from chimera_core.adapters.net_utils_adapter import NetUtilsAdapter
from chimera_core.scope import ScopeGraph, ScopePolicy # Added imports


@pytest.mark.skip(reason="NetUtilsAdapter references a path from the old dev environment; covered by PlanRunner tests")
def test_runner_emits_events_in_correct_order(tmp_path: Path):
    """
    Tests that the runner emits task_started and task_finished events
    in the correct order for a single task.
    """
    plan = ExecutionPlan()
    
    # Use a dummy task that doesn't actually run external tools, but still triggers event emission.
    # For simplicity here, we'll create a task that uses the NetUtilsAdapter.
    # The key is to provide a writable artifacts_root.
    task = Task(task_id="T1", tool="net-utils", target="example.com", options={})
    plan.add_task(task)

    context = RunContext("test_job")
    
    # Mock the event sink (e.g., a Supabase client)
    event_sink = Mock()
    
    # Pass the mock to the runner and ensure artifacts_root is tmp_path
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    
    runner = Runner(
        plan=plan,
        context=context,
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_sink=event_sink,
        adapters={
            "net-utils": NetUtilsAdapter(scope_graph=scope_graph, scope_policy=scope_policy, options={}, rate_limits={}, run_id="test_job", task_id="T1", artifacts_root=tmp_path)
        },
        artifacts_root=tmp_path
    )
    runner.execute()

    # Check that the event sink was called with the correct events
    calls = event_sink.emit.call_args_list
    assert len(calls) == 6, "Expected six events to be emitted (start, 3 findings, 1 artifact, finish)"
    
    # Check the event types in order
    assert calls[0].args[0]["event_type"] == "task_started", "First event should be task_started"
    assert calls[0].args[0]["payload"]["task_id"] == "T1", "task_id should be in started event"

    # Check for finding_emitted events (3 of them)
    for i in range(1, 4): # calls[1], calls[2], calls[3]
        assert calls[i].args[0]["event_type"] == "finding_emitted", f"Event {i} should be finding_emitted"
        assert "finding" in calls[i].args[0]["payload"], f"Finding payload missing in event {i}"
        assert calls[i].args[0]["payload"]["job_id"] == "test_job", f"job_id missing in finding_emitted event {i}"

    # Check for artifact_saved event
    assert calls[4].args[0]["event_type"] == "artifact_saved", "Fifth event should be artifact_saved"
    assert calls[4].args[0]["payload"]["artifact_type"] == "raw_output", "Artifact type should be raw_output"
    assert "path" in calls[4].args[0]["payload"], "Artifact path missing"

    # Check the task_finished event
    assert calls[5].args[0]["event_type"] == "task_finished", "Last event should be task_finished"
    assert calls[5].args[0]["payload"]["task_id"] == "T1", "task_id should be in finished event"

import pytest
from pathlib import Path
from unittest.mock import Mock

from chimera_core.plan import ExecutionPlan, Task
from chimera_core.runtime import Runtime, RuntimeCancelledError
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.event_store import EventStore
from chimera_core.runner import PlanRunner


def _make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    event_store = EventStore(tmp_path / "events.jsonl")
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=tmp_path / "artifacts",
    )


def test_plan_runner_respects_cancel_before_start(tmp_path: Path):
    runtime = _make_runtime(tmp_path)
    runtime.cancel_event.set()

    plan = ExecutionPlan()
    plan.add_task(Task(task_id="t1", tool="strix", target="example.com", options={}))

    runner = PlanRunner(runtime=runtime)
    with pytest.raises(RuntimeCancelledError):
        runner.execute(plan)


def test_plan_runner_stops_after_cancel(tmp_path: Path):
    runtime = _make_runtime(tmp_path)
    plan = ExecutionPlan()
    plan.add_task(Task(task_id="t1", tool="strix", target="example.com", options={}))
    plan.add_task(Task(task_id="t2", tool="strix", target="example.com", options={}))
    plan.add_dependency("t1", "t2")

    runner = PlanRunner(runtime=runtime)

    class DummyAdapter:
        def __init__(self, cancel=False):
            self.cancel = cancel
        def run(self, targets):
            if self.cancel:
                runtime.cancel_event.set()
            return {"findings": []}

    def fake_adapter(task):
        return DummyAdapter(cancel=task.task_id == "t1")

    runner._adapter_for_task = Mock(side_effect=fake_adapter)

    with pytest.raises(RuntimeCancelledError):
        runner.execute(plan)

"""
TDD tests for PlanRunner dependency gating and stop_on_fail semantics.

RED → GREEN targets:
- DAG A->B->C: when A fails, B and C must not execute.
- stop_on_fail=True prevents any new task from being scheduled after first failure.
- task_blocked events are emitted for tasks that are never executed due to upstream failure.
- TaskResult stats distinguish failed vs blocked.
"""
import json
from pathlib import Path

import pytest

from chimera_core.event_store import EventStore
from chimera_core.plan import ExecutionPlan, Task
from chimera_core.runner import PlanRunner
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_runtime(tmp_path: Path, mode: str = "fixture") -> Runtime:
    scope_manifest = {"allowlist": ["http://example.com"], "denylist": []}
    run_dir = tmp_path / "artifacts" / "run-dep-test"
    run_dir.mkdir(parents=True, exist_ok=True)
    return Runtime(
        scope_graph=ScopeGraph(scope_manifest),
        scope_policy=ScopePolicy(scope_manifest),
        event_store=EventStore(run_dir / "events.jsonl"),
        artifacts_root=tmp_path / "artifacts",
        run_id="run-dep-test",
        mode=mode,
    )


def _autoswagger_fixture(tmp_path: Path) -> str:
    """Return path to a minimal autoswagger fixture."""
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir(exist_ok=True)
    fixture = fixture_dir / "swagger.json"
    fixture.write_text(json.dumps({"endpoints": []}), encoding="utf-8")
    return str(fixture)


def _events(tmp_path: Path) -> list[dict]:
    events_path = tmp_path / "artifacts" / "run-dep-test" / "events.jsonl"
    if not events_path.exists():
        return []
    lines = events_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(l) for l in lines if l.strip()]


def _event_types(tmp_path: Path) -> list[str]:
    return [e["event_type"] for e in _events(tmp_path)]


def _executed_task_ids(tmp_path: Path) -> list[str]:
    """Return task_ids that actually started executing (task_executing events)."""
    return [
        e["payload"]["task_id"]
        for e in _events(tmp_path)
        if e["event_type"] == "task_executing"
    ]


def _blocked_task_ids(tmp_path: Path) -> list[str]:
    return [
        e["payload"]["task_id"]
        for e in _events(tmp_path)
        if e["event_type"] == "task_blocked"
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_failed_task_does_not_unlock_downstream(tmp_path: Path):
    """
    DAG: A -> B -> C
    A fails (out-of-scope target). B and C must never execute.
    """
    fixture = _autoswagger_fixture(tmp_path)
    plan = ExecutionPlan()
    # A uses an out-of-scope URL to trigger a failure
    plan.add_task(Task("A", "autoswagger", "http://evil.notallowed.com/api", {"live": False}))
    plan.add_task(Task("B", "autoswagger", "http://example.com/api", {"live": False}))
    plan.add_task(Task("C", "autoswagger", "http://example.com/api", {"live": False}))
    plan.add_dependency("A", "B")
    plan.add_dependency("B", "C")

    runtime = _make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True,
                        fixture_registry={"autoswagger": fixture})
    results = runner.execute(plan)

    executed = _executed_task_ids(tmp_path)
    assert "B" not in executed, "B must not execute when A failed"
    assert "C" not in executed, "C must not execute when A failed"

    statuses = {r.task_id: r.status for r in results}
    assert statuses["A"] == "failed"
    # B and C should appear as blocked (not silently missing)
    assert statuses.get("B") == "blocked", f"Expected B blocked, got {statuses.get('B')}"
    assert statuses.get("C") == "blocked", f"Expected C blocked, got {statuses.get('C')}"


def test_task_blocked_events_emitted_for_unreachable_tasks(tmp_path: Path):
    """
    When A fails in DAG A->B->C, task_blocked events must be emitted for B and C.
    """
    fixture = _autoswagger_fixture(tmp_path)
    plan = ExecutionPlan()
    plan.add_task(Task("A", "autoswagger", "http://evil.notallowed.com/api", {"live": False}))
    plan.add_task(Task("B", "autoswagger", "http://example.com/api", {"live": False}))
    plan.add_task(Task("C", "autoswagger", "http://example.com/api", {"live": False}))
    plan.add_dependency("A", "B")
    plan.add_dependency("B", "C")

    runtime = _make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True,
                        fixture_registry={"autoswagger": fixture})
    runner.execute(plan)

    blocked = _blocked_task_ids(tmp_path)
    assert "B" in blocked, f"Expected task_blocked for B; got blocked={blocked}"
    assert "C" in blocked, f"Expected task_blocked for C; got blocked={blocked}"


def test_stop_on_fail_only_blocks_dependent_chain(tmp_path: Path):
    """
    When stop_on_fail=True, a failure in one chain must block only that chain's
    dependents — independent chains with no shared dependencies must continue.

    Plan: A and D are both initially ready (no deps between them). A fails.
    D is independent and must still complete.
    """
    fixture = _autoswagger_fixture(tmp_path)
    plan = ExecutionPlan()
    plan.add_task(Task("A", "autoswagger", "http://evil.notallowed.com/api", {"live": False}))
    plan.add_task(Task("D", "autoswagger", "http://example.com/api", {"live": False}))
    # No dependency between A and D — both are initially ready

    runtime = _make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True,
                        fixture_registry={"autoswagger": fixture})
    results = runner.execute(plan)

    statuses = {r.task_id: r.status for r in results}
    assert statuses["A"] == "failed"
    # D has no dependency on A — it must complete regardless of A's failure
    assert statuses.get("D") == "completed", (
        f"Independent task D should complete even when A fails; got {statuses}"
    )


def test_stop_on_fail_false_allows_independent_tasks(tmp_path: Path):
    """
    With stop_on_fail=False, independent tasks should still run even if A fails.
    B depends on A and must still be blocked; D is independent and must run.
    """
    fixture = _autoswagger_fixture(tmp_path)
    plan = ExecutionPlan()
    plan.add_task(Task("A", "autoswagger", "http://evil.notallowed.com/api", {"live": False}))
    plan.add_task(Task("B", "autoswagger", "http://example.com/api", {"live": False}))
    plan.add_task(Task("D", "autoswagger", "http://example.com/api", {"live": False}))
    plan.add_dependency("A", "B")  # B depends on A

    runtime = _make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=2, stop_on_fail=False,
                        fixture_registry={"autoswagger": fixture})
    results = runner.execute(plan)

    statuses = {r.task_id: r.status for r in results}
    assert statuses["A"] == "failed"
    assert statuses.get("B") == "blocked", "B must be blocked (depends on failed A)"
    assert statuses.get("D") == "completed", "D must complete (independent of A)"


def test_blocked_tasks_in_result_list(tmp_path: Path):
    """
    Blocked tasks must appear in execute() return value with status='blocked'.
    """
    fixture = _autoswagger_fixture(tmp_path)
    plan = ExecutionPlan()
    plan.add_task(Task("A", "autoswagger", "http://evil.notallowed.com/api", {"live": False}))
    plan.add_task(Task("B", "autoswagger", "http://example.com/api", {"live": False}))
    plan.add_dependency("A", "B")

    runtime = _make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True,
                        fixture_registry={"autoswagger": fixture})
    results = runner.execute(plan)

    result_map = {r.task_id: r for r in results}
    assert "B" in result_map, "B must appear in results"
    assert result_map["B"].status == "blocked"
    assert result_map["B"].findings == []

from pathlib import Path

from chimera_core.event_store import EventStore
from chimera_core.plan import ExecutionPlan, Task
from chimera_core.runner import PlanRunner
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def make_runtime(tmp_path: Path):
    scope_manifest = {"allowlist": ["api.example.com", "www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-plan"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(run_dir / "events.jsonl")
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
    )


def test_plan_runner_topological_order(tmp_path: Path):
    plan = ExecutionPlan()
    task_a = Task("A", "autoswagger", "https://api.example.com/api", {"live": False})
    task_b = Task("B", "autoswagger", "https://api.example.com/api", {"live": False})
    task_c = Task("C", "autoswagger", "https://api.example.com/api", {"live": False})
    for task in (task_a, task_b, task_c):
        plan.add_task(task)
    plan.add_dependency("A", "B")
    plan.add_dependency("A", "C")

    runtime = make_runtime(tmp_path)
    fixtures = {"autoswagger": str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")}
    runner = PlanRunner(runtime=runtime, max_workers=2, stop_on_fail=True, fixture_registry=fixtures)
    results = runner.execute(plan)

    order = [result.task_id for result in results]
    assert order.index("A") < order.index("B")
    assert order.index("A") < order.index("C")


def test_plan_runner_concurrency_cap(tmp_path: Path):
    plan = ExecutionPlan()
    for i in range(4):
        plan.add_task(Task(f"T{i}", "autoswagger", "https://api.example.com/api", {"live": False}))

    runtime = make_runtime(tmp_path)
    fixtures = {"autoswagger": str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")}
    runner = PlanRunner(runtime=runtime, max_workers=2, stop_on_fail=True, fixture_registry=fixtures)
    runner.execute(plan)

    assert runner.peak_concurrency <= 2


def test_plan_runner_stop_on_fail(tmp_path: Path):
    plan = ExecutionPlan()
    plan.add_task(Task("A", "autoswagger", "https://evil.com", {"live": False}))
    plan.add_task(Task("B", "autoswagger", "https://api.example.com/api", {"live": False}))
    plan.add_dependency("A", "B")

    runtime = make_runtime(tmp_path)
    fixtures = {"autoswagger": str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")}
    runner = PlanRunner(runtime=runtime, max_workers=2, stop_on_fail=True, fixture_registry=fixtures)
    results = runner.execute(plan)

    assert len(results) == 1
    assert results[0].status == "failed"

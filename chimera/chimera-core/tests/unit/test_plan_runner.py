from pathlib import Path

import httpx

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


def test_plan_runner_executes_routed_recon_tool(tmp_path: Path):
    plan = ExecutionPlan()
    fixture = tmp_path / "zypheron.txt"
    fixture.write_text(
        "[ASSET] host: www.example.com\n[SERVICE] host: www.example.com, port: 443, proto: tcp, service: https\n",
        encoding="utf-8",
    )
    plan.add_task(Task("Z1", "zypheron", "www.example.com", {"live": False}))

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True, fixture_registry={"zypheron": str(fixture)})
    results = runner.execute(plan)

    assert len(results) == 1
    assert results[0].status == "completed"
    assert results[0].artifacts


def test_plan_runner_executes_validator_and_writes_artifact(tmp_path: Path):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok", request=request)

    transport = httpx.MockTransport(handler)
    plan = ExecutionPlan()
    plan.add_task(
        Task(
            "V1",
            "rate_limit_validator",
            "https://api.example.com/login",
            {
                "validation_inputs": {
                    "target_endpoint": "https://api.example.com/login",
                    "burst_count": 3,
                },
                "http_transport": transport,
            },
        )
    )

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)
    results = runner.execute(plan)

    assert len(results) == 1
    assert results[0].status == "completed"
    assert results[0].findings[0].validation_status == "confirmed"
    assert results[0].artifacts


def test_plan_runner_passes_recon_bundle_into_decepticon(tmp_path: Path):
    report = tmp_path / "report.md"
    report.write_text(
        "# Report\n\n## High: Reflected XSS\nSeverity: High\nEvidence:\n```html\n<script>alert(1)</script>\n```\n",
        encoding="utf-8",
    )

    plan = ExecutionPlan()
    plan.add_task(Task("R1", "vibepentester", "https://www.example.com", {"live": False}))
    plan.add_task(Task("R2", "decepticon", "https://www.example.com", {"live": False}))
    plan.add_dependency("R1", "R2")

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True, fixture_registry={"vibepentester": str(report)})
    results = runner.execute(plan)

    assert [result.status for result in results] == ["completed", "completed"]
    assert any(finding.title == "Decepticon enrichment analysis" for finding in results[1].findings)


def test_plan_runner_synthesizes_chain_from_validated_findings(tmp_path: Path):
    shannon_fixture = tmp_path / "shannon_idor.json"
    shannon_fixture.write_text(
        """
        {
          "findings": [
            {
              "title": "IDOR on profile endpoint",
              "description": "User profile endpoint leaks another user's record.",
              "severity": "high",
              "target": "https://api.example.com/users/7"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    plan = ExecutionPlan()
    plan.add_task(Task("S1", "shannon", "https://api.example.com/users/7", {"live": False}))
    plan.add_task(
        Task(
            "J1",
            "jwt_validator",
            "https://api.example.com/users/7",
            {"validation_inputs": {"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.", "allowed_algs": ("HS256",)}},
        )
    )
    plan.add_dependency("S1", "J1")

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True, fixture_registry={"shannon": str(shannon_fixture)})
    results = runner.execute(plan)

    chain_results = [result for result in results if result.task_id.startswith("chain-analysis:")]
    assert chain_results
    assert any(finding.finding_type == "EXPLOIT_CHAIN" for finding in chain_results[0].findings)
    assert chain_results[0].artifacts
    chain_artifact = Path(chain_results[0].artifacts[0]["path"])
    assert chain_artifact.exists()
    assert '"rule_id": "idor_jwt_takeover"' in chain_artifact.read_text(encoding="utf-8")
    artifact_types = {artifact["artifact_type"] for artifact in chain_results[0].artifacts}
    assert "chain_replay_manifest" in artifact_types
    assert "poc_bundle" in artifact_types

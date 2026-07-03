import json
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

    result_map = {r.task_id: r for r in results}
    assert result_map["A"].status == "failed"
    # B was never executed — it must appear as blocked, not silently absent
    assert result_map["B"].status == "blocked"


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


def test_plan_runner_executes_zap_adapter(tmp_path: Path):
    plan = ExecutionPlan()
    fixture = tmp_path / "zap.json"
    fixture.write_text(
        """
        {
          "target": "https://www.example.com",
          "alerts": [
            {
              "pluginid": "40012",
              "name": "Cross Site Scripting (Reflected)",
              "risk": "High",
              "confidence": "Medium",
              "url": "https://www.example.com/search?q=test",
              "param": "q",
              "description": "Reflected XSS detected."
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    plan.add_task(Task("ZAP1", "zap", "https://www.example.com", {"live": False}))

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True, fixture_registry={"zap": str(fixture)})
    results = runner.execute(plan)

    assert len(results) == 1
    assert results[0].status == "completed"
    assert results[0].findings[0].tool_source == "zap"
    assert any(artifact["artifact_type"] == "report" for artifact in results[0].artifacts)


def test_plan_runner_executes_hexstrike_adapter(tmp_path: Path):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "endpoint": "https://www.example.com/login",
                "headers": {},
                "checks": {"x_frame_options": False, "content_security_policy": False},
            },
            request=request,
        )

    transport = httpx.MockTransport(handler)
    plan = ExecutionPlan()
    plan.add_task(
        Task(
            "HX1",
            "hexstrike",
            "https://www.example.com/login",
            {
                "tool_name": "probe",
                "agent": "deterministic_runner",
                "transport": transport,
            },
        )
    )

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)
    results = runner.execute(plan)

    assert len(results) == 1
    assert results[0].status == "completed"
    assert results[0].findings
    assert results[0].findings[0].tool_source == "hexstrike"
    artifact_types = {artifact["artifact_type"] for artifact in results[0].artifacts}
    assert {"request", "response", "normalized", "findings"} <= artifact_types


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


def test_plan_runner_recovers_shannon_candidates_from_raw_output(tmp_path: Path, monkeypatch) -> None:
    class RawOnlyShannonAdapter:
        def run(self, targets):
            return {
                "findings": [],
                "artifacts": [],
                "raw_output_refs": [
                    json.dumps(
                        {
                            "status": "completed",
                            "agent": {
                                "new_candidates": [
                                    {
                                        "candidate_id": "cand-raw-1",
                                        "source": "shannon-agent",
                                        "title": "Recovered open redirect",
                                        "claim_type": "open_redirect",
                                        "severity_claimed": "medium",
                                        "target": "https://www.example.com",
                                        "endpoint": "/login",
                                        "params": ["redirect"],
                                        "evidence_refs": ["artifact://tool-call.json"],
                                        "metadata": {
                                            "target": {
                                                "method": "GET",
                                                "endpoint": "/login",
                                                "params": {"redirect": "https://attacker.example"},
                                            }
                                        },
                                    }
                                ]
                            },
                        }
                    )
                ],
            }

    plan = ExecutionPlan()
    plan.add_task(
        Task(
            "S1",
            "shannon",
            "https://www.example.com",
            {"shannon_runtime": "autonomous", "live": False, "intent": "Investigate redirects"},
        )
    )

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)
    captured: dict[str, object] = {}

    monkeypatch.setattr(runner, "_adapter_for_task", lambda task: RawOnlyShannonAdapter())

    def fake_process(task, candidates):
        captured["task_id"] = task.task_id
        captured["candidates"] = candidates
        return [], []

    monkeypatch.setattr(runner, "_process_candidate_findings", fake_process)

    results = runner.execute(plan)

    assert results[0].status == "completed"
    assert captured["task_id"] == "S1"
    recovered = captured["candidates"]
    assert len(recovered) == 1
    assert recovered[0].claim_type == "open_redirect"
    assert recovered[0].endpoint == "/login"


def test_plan_runner_treats_autonomous_shannon_exploit_as_agent_runtime(tmp_path: Path) -> None:
    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)
    task = Task(
        "S2",
        "shannon",
        "https://www.example.com",
        {
            "shannon_runtime": "autonomous",
            "agent_role": "exploit",
            "analysis_domain": "xss",
            "live": False,
        },
    )

    assert runner._skip_reason_for_task(task) is None


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

    async def bola_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 7, "email": "victim@example.com"}, request=request)

    bola_transport = httpx.MockTransport(bola_handler)

    plan = ExecutionPlan()
    # http_transport is inherited by the auto-injected bola_validator so it can
    # make mock HTTP calls instead of hitting a real server.
    plan.add_task(Task("S1", "shannon", "https://api.example.com/users/7", {
        "live": False,
        "http_transport": bola_transport,
    }))
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


def test_plan_runner_skips_shannon_exploit_phase_when_analysis_queue_is_empty(tmp_path: Path):
    plan = ExecutionPlan()
    plan.add_task(
        Task(
            "S-ANALYZE",
            "shannon",
            "https://www.example.com",
            {
                "live": False,
                "raw_output_override": "{\"findings\": []}",
                "agent_role": "analysis",
                "analysis_domain": "xss",
            },
            stage="vulnerability_analysis",
        )
    )
    plan.add_task(
        Task(
            "S-EXPLOIT",
            "shannon",
            "https://www.example.com",
            {
                "live": False,
                "raw_output_override": "{\"findings\": [{\"title\": \"should not run\", \"severity\": \"high\", \"target\": \"https://www.example.com\"}]}",
                "agent_role": "exploit",
                "analysis_domain": "xss",
            },
            stage="exploitation",
        )
    )
    plan.add_dependency("S-ANALYZE", "S-EXPLOIT")

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)
    results = runner.execute(plan)

    result_map = {result.task_id: result for result in results}
    assert result_map["S-ANALYZE"].status == "completed"
    assert result_map["S-EXPLOIT"].status == "skipped"


def test_independent_chain_continues_after_failure(tmp_path: Path):
    """A failing task should only block its own dependents, not independent chains."""
    # Chain 1: A (fails, out-of-scope) → B (should be blocked)
    # Chain 2: C (independent, should complete normally)
    fixtures_dir = Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger"
    fixtures = {"autoswagger": str(fixtures_dir / "output.json")}

    plan = ExecutionPlan()
    plan.add_task(Task("A", "autoswagger", "https://evil.com", {"live": False}))
    plan.add_task(Task("B", "autoswagger", "https://api.example.com/api", {"live": False}))
    plan.add_task(Task("C", "autoswagger", "https://api.example.com/api", {"live": False}))
    plan.add_dependency("A", "B")
    # C has no dependency on A or B — independent chain

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=3, stop_on_fail=True, fixture_registry=fixtures)
    results = runner.execute(plan)

    result_map = {r.task_id: r for r in results}
    assert result_map["A"].status == "failed"
    assert result_map["B"].status == "blocked"
    # C is independent — must complete even though A failed
    assert result_map["C"].status == "completed"


def test_only_dependents_blocked_not_siblings(tmp_path: Path):
    """task_blocked must only fire for A's subtree, not for sibling chains."""
    fixtures_dir = Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger"
    fixtures = {"autoswagger": str(fixtures_dir / "output.json")}

    plan = ExecutionPlan()
    # A fails → B blocked
    plan.add_task(Task("A", "autoswagger", "https://evil.com", {"live": False}))
    plan.add_task(Task("B", "autoswagger", "https://api.example.com/api", {"live": False}))
    plan.add_dependency("A", "B")
    # D and E are siblings — independent of A/B
    plan.add_task(Task("D", "autoswagger", "https://api.example.com/api", {"live": False}))
    plan.add_task(Task("E", "autoswagger", "https://api.example.com/api", {"live": False}))
    plan.add_dependency("D", "E")

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=4, stop_on_fail=True, fixture_registry=fixtures)
    results = runner.execute(plan)

    result_map = {r.task_id: r for r in results}
    assert result_map["A"].status == "failed"
    assert result_map["B"].status == "blocked"
    assert result_map["D"].status == "completed"
    assert result_map["E"].status == "completed"

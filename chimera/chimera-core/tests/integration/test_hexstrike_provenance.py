from pathlib import Path

import httpx

from chimera_core.event_store import EventStore
from chimera_core.plan import ExecutionPlan, Task
from chimera_core.runner import PlanRunner
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def _make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-hexstrike-provenance"
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


def test_hexstrike_planrunner_emits_provenance_and_persists_artifacts(tmp_path: Path):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "info": {"name": "Exposed Admin Panel", "severity": "medium"},
                        "matched-at": "https://www.example.com/admin",
                        "template-id": "exposed-admin-panel",
                    }
                ]
            },
            request=request,
        )

    runtime = _make_runtime(tmp_path)
    transport = httpx.MockTransport(handler)
    plan = ExecutionPlan()
    plan.add_task(
        Task(
            "HX-PROV-1",
            "hexstrike",
            "https://www.example.com",
            {
                "tool_name": "nuclei",
                "agent": "deterministic_runner",
                "transport": transport,
            },
        )
    )

    results = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True).execute(plan)

    assert len(results) == 1
    assert results[0].status == "completed"
    assert results[0].findings

    events = list(runtime.event_store.replay())
    event_types = [event["event_type"] for event in events]
    expected_order = [
        "task_executing",
        "hexstrike_call_started",
        "artifact_saved",
        "artifact_saved",
        "artifact_saved",
        "artifact_saved",
        "hexstrike_call_finished",
    ]
    cursor = 0
    for expected in expected_order:
        while cursor < len(event_types) and event_types[cursor] != expected:
            cursor += 1
        assert cursor < len(event_types), f"Missing event: {expected}"
        cursor += 1

    artifact_events = [event for event in events if event["event_type"] == "artifact_saved"]
    assert artifact_events
    for event in artifact_events:
        payload = event["payload"]
        path = Path(payload["path"])
        assert path.exists(), f"artifact_saved path missing on disk: {path}"
        assert payload["artifact_type"] in {"request", "response", "normalized", "findings"}

    finished = next(event for event in events if event["event_type"] == "hexstrike_call_finished")
    assert finished["payload"]["finding_count"] == len(results[0].findings)
    assert len(finished["payload"]["artifact_paths"]) == 4

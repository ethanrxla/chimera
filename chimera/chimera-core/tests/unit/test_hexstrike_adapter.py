from pathlib import Path

import httpx
import pytest

from chimera_core.adapters.hexstrike_adapter import HexStrikeAdapter
from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["https://example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-hx"
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


def test_hexstrike_adapter_run_writes_artifacts_and_events(tmp_path: Path) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"endpoint": "https://example.com/login", "checks": {"csp": False, "x_frame": ""}},
            request=request,
        )

    transport = httpx.MockTransport(handler)
    adapter = HexStrikeAdapter(
        runtime=make_runtime(tmp_path),
        options={"tool_name": "probe", "params": {"endpoint": "https://example.com/login"}, "transport": transport},
        run_id="run-hx",
        task_id="HX1",
        scope_hash="scope-hx",
    )

    result = adapter.run(["https://example.com/login"])

    assert len(result["findings"]) == 1
    artifact_types = {artifact["artifact_type"] for artifact in result["artifacts"]}
    assert {"request", "response", "normalized", "findings"} <= artifact_types

    events = list(adapter.runtime.event_store.replay())
    event_types = [event["event_type"] for event in events]
    assert "hexstrike_call_started" in event_types
    assert "hexstrike_call_finished" in event_types
    assert event_types.count("artifact_saved") >= 4


def test_hexstrike_adapter_emits_scope_violation_and_fails_closed(tmp_path: Path) -> None:
    adapter = HexStrikeAdapter(
        runtime=make_runtime(tmp_path),
        options={"tool_name": "probe", "params": {"endpoint": "https://evil.com/login"}},
        run_id="run-hx",
        task_id="HX2",
        scope_hash="scope-hx",
    )

    with pytest.raises(ValueError):
        adapter.run(["https://evil.com/login"])

    events = list(adapter.runtime.event_store.replay())
    assert any(event["event_type"] == "scope_violation" for event in events)

"""
Integration tests for HexStrike MCP bridge.

C1 — Health endpoint reachable (requires hexstrike:8888)
C2 — /api/probe returns a response with security-relevant fields (requires hexstrike)
C3 — HexstrikeAdapter.run() emits events and writes artifact (requires hexstrike)
"""
import json
import socket
from pathlib import Path

import httpx
import pytest

from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------

def _can_reach(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


_HEXSTRIKE_URL = "http://hexstrike:8888"
_hexstrike_reachable = _can_reach("hexstrike", 8888)

skip_no_hexstrike = pytest.mark.skipif(
    not _hexstrike_reachable,
    reason="hexstrike:8888 not reachable — run inside container network",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["http://juice-shop:3000", "http://juice-shop:3000/rest"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-hexstrike-test"
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


# ---------------------------------------------------------------------------
# C1 — Health endpoint
# ---------------------------------------------------------------------------

@skip_no_hexstrike
def test_hexstrike_health_endpoint():
    """GET /health returns status=ok and a non-empty capabilities list."""
    resp = httpx.get(f"{_HEXSTRIKE_URL}/health", timeout=10)
    assert resp.status_code == 200, f"HexStrike /health returned {resp.status_code}"
    data = resp.json()
    assert data.get("status") == "ok", f"Expected status=ok, got: {data}"
    caps = data.get("capabilities", [])
    assert len(caps) > 0, "capabilities list must not be empty"


# ---------------------------------------------------------------------------
# C2 — /api/probe returns security-relevant fields
# ---------------------------------------------------------------------------

@skip_no_hexstrike
def test_hexstrike_probe_returns_response():
    """POST /api/probe returns a dict with target and source fields."""
    resp = httpx.post(
        f"{_HEXSTRIKE_URL}/api/probe",
        json={"endpoint": "http://juice-shop:3000/rest/user/login", "method": "GET"},
        timeout=30,
    )
    assert resp.status_code == 200, f"POST /api/probe returned {resp.status_code}: {resp.text}"
    data = resp.json()
    assert isinstance(data, dict), f"Expected dict response, got: {type(data)}"
    # Probe must at least echo back the target or source
    assert "target" in data or "endpoint" in data or "source" in data, (
        f"Response missing expected fields: {data}"
    )


# ---------------------------------------------------------------------------
# C3 — HexstrikeAdapter.run() emits events and writes artifact
# ---------------------------------------------------------------------------

@skip_no_hexstrike
def test_hexstrike_adapter_emits_events_and_artifact(tmp_path: Path):
    """
    HexstrikeAdapter.run() against juice-shop must:
    - emit task_executing + artifact_saved events
    - write raw_output.json artifact to the expected path
    """
    from chimera_core.adapters.hexstrike_adapter import HexstrikeAdapter  # RED until created

    runtime = _make_runtime(tmp_path)
    adapter = HexstrikeAdapter(
        runtime=runtime,
        run_id="run-hexstrike-test",
        task_id="T-hexstrike-1",
        scope_hash="scope-hex",
    )

    result = adapter.run(["http://juice-shop:3000"])

    # Artifacts
    artifacts = result.get("artifacts", [])
    raw_paths = [
        Path(a["path"]) for a in artifacts if a.get("artifact_type") == "raw_output"
    ]
    assert len(raw_paths) >= 1, "Expected at least one raw_output artifact"
    assert raw_paths[0].exists(), f"Artifact file not written: {raw_paths[0]}"

    # Events
    events = list(runtime.event_store.replay())
    event_types = [e.get("event_type") for e in events]
    assert "task_executing" in event_types or "task_started" in event_types, (
        f"task_executing/task_started event missing. Events: {event_types}"
    )
    assert "artifact_saved" in event_types, (
        f"artifact_saved event missing. Events: {event_types}"
    )

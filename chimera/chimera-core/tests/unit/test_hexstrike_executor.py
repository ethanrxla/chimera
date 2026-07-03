import httpx

from chimera_core.artifacts import ArtifactWriter
from chimera_core.event_store import EventStore
from chimera_core.hexstrike.executor import HexStrikeCall, HexStrikeExecutor
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def make_runtime(tmp_path):
    scope_manifest = {"allowlist": ["https://example.com", "https://example.com/*"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-hex"
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


def test_hexstrike_executor_writes_request_response_and_normalized_artifacts(tmp_path) -> None:
    runtime = make_runtime(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status_code": 302,
                "headers": {"Location": "https://attacker.example"},
                "body": "",
            },
        )

    transport = httpx.MockTransport(handler)
    executor = HexStrikeExecutor(
        runtime=runtime,
        base_url="http://hexstrike:8888",
        artifact_writer=ArtifactWriter(runtime.artifacts_root, event_store=runtime.event_store),
        transport=transport,
    )
    result = executor.execute_call(
        run_id="run-hex",
        call=HexStrikeCall(
            call_id="call-1",
            verification_id="ver-1",
            check_id="check-1",
            probe_type="http_redirect_check",
            tool_name="probe",
            probe_input={"endpoint": "https://example.com/login", "method": "GET"},
        ),
        scope_manifest={"allowlist": ["https://example.com", "https://example.com/*"], "denylist": []},
    )

    assert result.request_artifact_ref.endswith("request.json")
    assert result.response_artifact_ref.endswith("response.json")
    assert result.normalized_artifact_ref.endswith("normalized.json")
    events = list(runtime.event_store.replay())
    event_types = [event["event_type"] for event in events]
    assert "hexstrike_call_started" in event_types
    assert "hexstrike_call_finished" in event_types

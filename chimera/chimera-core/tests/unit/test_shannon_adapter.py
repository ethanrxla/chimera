from pathlib import Path

from chimera_core.adapters.shannon_adapter import ShannonAdapter
from chimera_core.event_store import EventStore
from chimera_core.findings import stable_finding_id
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def load_fixture(name: str) -> str:
    base = Path(__file__).resolve().parents[1] / "fixtures" / "shannon"
    return (base / name).read_text(encoding="utf-8")


def make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-321"
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


def make_adapter(tmp_path: Path, options=None) -> ShannonAdapter:
    runtime = make_runtime(tmp_path)
    return ShannonAdapter(
        runtime=runtime,
        options=options,
        run_id="run-321",
        task_id="T9",
        scope_hash="scope-321",
    )


def test_shannon_normalizes_fixture_output(tmp_path: Path) -> None:
    adapter = make_adapter(tmp_path=tmp_path)
    raw_output = load_fixture("output.json")
    findings = adapter.normalize(raw_output)
    assert len(findings) == 1
    finding = findings[0]
    expected_id = stable_finding_id(
        "SQL Injection in login", "https://example.com/login", "shannon"
    )
    assert finding.to_dict() == {
        "finding_id": expected_id,
        "severity": "high",
        "title": "SQL Injection in login",
        "description": "Payload bypassed authentication on the login endpoint.",
        "affected_target": "https://example.com/login",
        "evidence_refs": ["poc.sql"],
        "tool_source": "shannon",
        "tool_version": "shannon",
        "repro_guidance": "Use payload ' OR 1=1-- on the username field.",
        "timestamps": finding.timestamps.isoformat(),
        "run_id": "run-321",
        "scope_hash": "scope-321",
        "status": "new",
    }


def test_shannon_run_uses_fixture_output(tmp_path: Path) -> None:
    raw_output = load_fixture("output.json")
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={"raw_output_override": raw_output},
    )

    result = adapter.run(["https://example.com"])

    assert result["findings"]
    raw_output_path = (
        tmp_path / "artifacts" / "run-321" / "shannon" / "T9" / "raw_output.json"
    )
    assert raw_output_path.exists()


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def json(self) -> dict:
        return self.payload

    def raise_for_status(self) -> None:
        return None


class FakeClient:
    def __init__(self, fixture_payload: dict) -> None:
        self.fixture_payload = fixture_payload
        self.posted = False

    def post(self, url: str, json=None, headers=None) -> FakeResponse:
        self.posted = True
        return FakeResponse({"task_id": "task-1", "status": "running"})

    def get(self, url: str, headers=None) -> FakeResponse:
        return FakeResponse(self.fixture_payload)

    def close(self) -> None:
        return None


def test_shannon_http_driver_uses_client(tmp_path: Path) -> None:
    payload = json_payload()
    fake_client = FakeClient(payload)
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "live": True,
            "driver": "http",
            "http_client": fake_client,
            "poll_interval_s": 0,
        },
    )

    result = adapter.run(["https://example.com/login"])

    assert fake_client.posted is True
    assert len(result["findings"]) == 1


def json_payload() -> dict:
    return {
        "status": "completed",
        "result": {
            "findings": [
                {
                    "title": "Reflected XSS",
                    "description": "Payload executed in the browser.",
                    "severity": "high",
                    "target": "https://example.com/search",
                    "evidence_refs": ["xss-proof.html"],
                }
            ]
        },
    }

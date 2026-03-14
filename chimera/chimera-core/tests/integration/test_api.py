import json
import asyncio
from pathlib import Path

import httpx
import pytest
from contextlib import asynccontextmanager
import threading

from chimera_core.api.app import create_app


@asynccontextmanager
async def _make_client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.mark.anyio
async def test_api_run_and_reports(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.fixture_registry = {
        "autoswagger": str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")
    }
    async with _make_client(app) as client:
        scope = {
            "allowlist": ["https://api.example.com/api"],
            "denylist": []
        }
        response = await client.post("/v1/runs", json={"scope_text": json.dumps(scope)})
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        for _ in range(50):
            status = await client.get(f"/v1/runs/{run_id}")
            if status.json().get("status") == "completed":
                break
            await asyncio.sleep(0.01)

        run_info = (await client.get(f"/v1/runs/{run_id}")).json()
        artifacts_dir = Path(run_info["artifacts_dir"])
        assert (artifacts_dir / "findings.json").exists()
        assert (artifacts_dir / "report.md").exists()
        assert (artifacts_dir / "summary.json").exists()

@pytest.mark.anyio
async def test_api_events_and_findings(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.fixture_registry = {
        "autoswagger": str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")
    }
    async with _make_client(app) as client:
        scope = {
            "allowlist": ["https://api.example.com/api"],
            "denylist": []
        }
        response = await client.post("/v1/runs", json={"scope_text": json.dumps(scope)})
        run_id = response.json()["run_id"]

        for _ in range(50):
            status = await client.get(f"/v1/runs/{run_id}")
            if status.json().get("status") == "completed":
                break
            await asyncio.sleep(0.01)

        events_resp = await client.get(f"/v1/runs/{run_id}/events")
        assert events_resp.status_code == 200
        assert "data:" in events_resp.text

        findings_resp = await client.get(f"/v1/runs/{run_id}/findings")
        assert findings_resp.status_code == 200
        assert isinstance(findings_resp.json(), list)


@pytest.mark.anyio
async def test_api_artifact_download(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.fixture_registry = {
        "autoswagger": str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")
    }
    async with _make_client(app) as client:
        scope = {
            "allowlist": ["https://api.example.com/api"],
            "denylist": []
        }
        response = await client.post("/v1/runs", json={"scope_text": json.dumps(scope)})
        run_id = response.json()["run_id"]

        for _ in range(50):
            status = await client.get(f"/v1/runs/{run_id}")
            if status.json().get("status") == "completed":
                break
            await asyncio.sleep(0.01)

        run_info = (await client.get(f"/v1/runs/{run_id}")).json()
        artifacts_dir = Path(run_info["artifacts_dir"])
        findings_path = artifacts_dir / "findings.json"
        rel_path = findings_path.relative_to(artifacts_dir)

        artifact_resp = await client.get(f"/v1/runs/{run_id}/artifacts/{rel_path}")
        assert artifact_resp.status_code == 200
        assert artifact_resp.content


@pytest.mark.anyio
async def test_api_diff_includes_changed_summary(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.fixture_registry = {
        "autoswagger": str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")
    }
    async with _make_client(app) as client:
        scope = {"allowlist": ["https://api.example.com/api"], "denylist": []}
        base_resp = await client.post("/v1/runs", json={"scope_text": json.dumps(scope)})
        compare_resp = await client.post("/v1/runs", json={"scope_text": json.dumps(scope)})
        base_run_id = base_resp.json()["run_id"]
        compare_run_id = compare_resp.json()["run_id"]

        for _ in range(50):
            base_status = await client.get(f"/v1/runs/{base_run_id}")
            compare_status = await client.get(f"/v1/runs/{compare_run_id}")
            if base_status.json().get("status") == "completed" and compare_status.json().get("status") == "completed":
                break
            await asyncio.sleep(0.01)

        compare_info = (await client.get(f"/v1/runs/{compare_run_id}")).json()
        compare_dir = Path(compare_info["artifacts_dir"])
        findings_path = compare_dir / "findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        assert findings
        findings[0]["confidence"] = 0.95
        findings_path.write_text(json.dumps(findings, indent=2, sort_keys=True), encoding="utf-8")

        diff_resp = await client.get(
            f"/v1/runs/diff?base_run_id={base_run_id}&compare_run_id={compare_run_id}"
        )
        assert diff_resp.status_code == 200
        payload = diff_resp.json()
        changed = payload.get("changed", [])
        assert changed
        summary = changed[0].get("summary", {})
        assert "severity" in summary
        assert "title" in summary
        assert "target" in summary
        assert "tool" in summary
        assert "classification" in summary
        assert "confidence" in summary

@pytest.mark.anyio
async def test_api_plan_endpoint_parses_scope_and_returns_tasks(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    async with _make_client(app) as client:
        scope = {"allowlist": ["https://api.example.com/api"], "denylist": []}
        response = await client.post(
            "/v1/runs/plan",
            json={"scope_text": json.dumps(scope), "live": False, "max_workers": 2},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["scope"]["allowlist"] == scope["allowlist"]
        assert isinstance(payload["plan"]["tasks"], list)
        assert payload["plan"]["tasks"]


@pytest.mark.anyio
async def test_api_plan_endpoint_blocks_live_without_confirm(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    async with _make_client(app) as client:
        scope = {"allowlist": ["https://api.example.com/api"], "denylist": []}
        response = await client.post(
            "/v1/runs/plan",
            json={"scope_text": json.dumps(scope), "live": True},
        )
        assert response.status_code == 400

        response = await client.post(
            "/v1/runs/plan",
            json={"scope_text": json.dumps(scope), "live": True, "live_confirm": "I UNDERSTAND"},
        )
        assert response.status_code == 200


@pytest.mark.anyio
async def test_api_run_blocks_live_without_confirm(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    async with _make_client(app) as client:
        scope = {"allowlist": ["https://api.example.com/api"], "denylist": []}
        response = await client.post(
            "/v1/runs",
            json={"scope_text": json.dumps(scope), "live": True},
        )
        assert response.status_code == 400

        response = await client.post(
            "/v1/runs",
            json={"scope_text": json.dumps(scope), "live": True, "live_confirm": "I UNDERSTAND"},
        )
        assert response.status_code == 200


@pytest.mark.anyio
async def test_api_plan_endpoint_returns_dag_dependencies(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    async with _make_client(app) as client:
        scope = {"allowlist": ["https://example.com"], "denylist": []}
        response = await client.post(
            "/v1/runs/plan",
            json={"scope_text": json.dumps(scope), "live": False},
        )
        assert response.status_code == 200
        tasks = response.json()["plan"]["tasks"]
        assert all("depends_on" in task for task in tasks)
        assert all(isinstance(task["depends_on"], list) for task in tasks)


@pytest.mark.anyio
async def test_api_plan_endpoint_is_side_effect_free(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    async with _make_client(app) as client:
        scope = {"allowlist": ["https://example.com"], "denylist": []}
        response = await client.post(
            "/v1/runs/plan",
            json={"scope_text": json.dumps(scope), "live": False},
        )
        assert response.status_code == 200
        assert app.state.runs == {}
        assert not app.state.artifacts_root.exists()


@pytest.mark.anyio
async def test_api_cancel_sets_flag(tmp_path: Path):
    app = create_app(testing=True)
    run_id = "run-123"
    cancel_event = threading.Event()
    app.state.runs[run_id] = {"status": "running", "cancel_event": cancel_event}
    async with _make_client(app) as client:
        response = await client.post(f"/v1/runs/{run_id}/cancel")
        assert response.status_code == 200
        assert cancel_event.is_set()


@pytest.mark.anyio
async def test_api_list_runs_sorted_desc(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.run_store = app.state.run_store.__class__(app.state.artifacts_root)
    app.state.run_store.create_run(
        "run-old",
        scope_raw="allowlist: ['example.com']\n",
        scope_normalized={"allowlist": ["example.com"], "denylist": []},
        plan={"tasks": []},
        options={"live": False},
        created_at="2020-01-01T00:00:00+00:00",
    )
    app.state.run_store.create_run(
        "run-new",
        scope_raw="allowlist: ['example.com']\n",
        scope_normalized={"allowlist": ["example.com"], "denylist": []},
        plan={"tasks": []},
        options={"live": False},
        created_at="2021-01-01T00:00:00+00:00",
    )
    async with _make_client(app) as client:
        response = await client.get("/v1/runs")
        assert response.status_code == 200
        payload = response.json()
        assert payload[0]["run_id"] == "run-new"
        assert payload[1]["run_id"] == "run-old"


@pytest.mark.anyio
async def test_api_get_run_reads_from_run_store(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.run_store = app.state.run_store.__class__(app.state.artifacts_root)
    app.state.run_store.create_run(
        "run-abc",
        scope_raw="allowlist: ['example.com']\n",
        scope_normalized={"allowlist": ["example.com"], "denylist": []},
        plan={"tasks": []},
        options={"live": False},
    )
    async with _make_client(app) as client:
        response = await client.get("/v1/runs/run-abc")
        assert response.status_code == 200
        assert response.json()["run_id"] == "run-abc"


@pytest.mark.anyio
async def test_api_run_persists_rate_limits_and_clamps(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.fixture_registry = {
        "autoswagger": str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")
    }
    async with _make_client(app) as client:
        scope = {"allowlist": ["https://api.example.com/api"], "denylist": []}
        response = await client.post(
            "/v1/runs",
            json={
                "scope_text": json.dumps(scope),
                "rate_limit_rps": 999,
                "per_task_timeout_s": 999,
                "max_workers": 50,
                "program_name": "HackerOne",
            },
        )
        run_id = response.json()["run_id"]

        for _ in range(50):
            status = await client.get(f"/v1/runs/{run_id}")
            if status.json().get("status") in {"completed", "failed", "cancelled"}:
                break
            await asyncio.sleep(0.01)

        run_info = (await client.get(f"/v1/runs/{run_id}")).json()
        options = run_info.get("options", {})
        assert options.get("rate_limit_rps") == 50
        assert options.get("per_task_timeout_s") == 300
        assert options.get("max_workers") == 8
        assert options.get("program_name") == "HackerOne"


@pytest.mark.anyio
async def test_api_health_ok(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.run_store = app.state.run_store.__class__(app.state.artifacts_root)
    async with _make_client(app) as client:
        response = await client.get("/v1/health")
        assert response.status_code == 200
        assert response.json()["ok"] is True


@pytest.mark.anyio
async def test_api_health_fails_on_unwritable_artifacts(tmp_path: Path, monkeypatch):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.run_store = app.state.run_store.__class__(app.state.artifacts_root)

    def fake_mkdir(*args, **kwargs):
        raise PermissionError("nope")

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)

    async with _make_client(app) as client:
        response = await client.get("/v1/health")
        assert response.status_code == 503
        payload = response.json()
        assert payload["ok"] is False

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


class FakeShannonResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeShannonHttpClient:
    def post(self, url, json=None, headers=None):
        return FakeShannonResponse({"task_id": "task-1", "status": "queued"})

    def get(self, url, headers=None):
        return FakeShannonResponse(
            {
                "task_id": "task-1",
                "status": "completed",
                "findings": [
                    {
                        "title": "JWT alg:none accepted",
                        "description": "Token verification can be bypassed.",
                        "severity": "high",
                        "target": "https://api.example.com",
                    }
                ],
            }
        )

    def close(self):
        return None


class FakePage:
    def __init__(self) -> None:
        self.url = ""
        self._handlers = {}
        self._content = "<script>node.innerHTML = location.search; window.addEventListener('message', handler)</script>"

    def on(self, event: str, handler) -> None:
        self._handlers[event] = handler

    async def goto(self, url: str, timeout: int = 0):
        self.url = url
        return None

    async def click(self, selector: str, timeout: int = 0):
        return None

    async def fill(self, selector: str, value: str, timeout: int = 0):
        return None

    async def wait_for_selector(self, selector: str, timeout: int = 0):
        return None

    async def wait_for_load_state(self, state: str, timeout: int = 0):
        return None

    async def evaluate(self, js_code: str):
        if "document.scripts" in js_code:
            return ["window.addEventListener('message', handler)"]
        return {"ok": True}

    async def eval_on_selector_all(self, selector: str, script: str):
        return ["https://cdn.example.com/app.js"]

    async def content(self) -> str:
        return self._content

    async def screenshot(self) -> bytes:
        return b"fake"


class FakeContext:
    def __init__(self) -> None:
        self.tracing = self

    async def new_page(self):
        return FakePage()

    async def add_cookies(self, cookies):
        return None

    async def start(self, screenshots: bool = True, snapshots: bool = True):
        return None

    async def stop(self):
        return None


class FakeBrowser:
    async def new_context(self):
        return FakeContext()

    async def close(self):
        return None


async def fake_browser_factory(headless: bool):
    browser = FakeBrowser()
    context = await browser.new_context()
    page = await context.new_page()
    return browser, context, page


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

        _done = {"completed", "failed", "cancelled"}
        for _ in range(100):
            status = await client.get(f"/v1/runs/{run_id}")
            if status.json().get("status") in _done:
                break
            await asyncio.sleep(0.05)

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

        _done = {"completed", "failed", "cancelled"}
        for _ in range(100):
            status = await client.get(f"/v1/runs/{run_id}")
            if status.json().get("status") in _done:
                break
            await asyncio.sleep(0.05)

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

        _done = {"completed", "failed", "cancelled"}
        for _ in range(100):
            status = await client.get(f"/v1/runs/{run_id}")
            if status.json().get("status") in _done:
                break
            await asyncio.sleep(0.05)

        run_info = (await client.get(f"/v1/runs/{run_id}")).json()
        artifacts_dir = Path(run_info["artifacts_dir"])
        findings_path = artifacts_dir / "findings.json"
        rel_path = findings_path.relative_to(artifacts_dir)

        artifact_resp = await client.get(f"/v1/runs/{run_id}/artifacts/{rel_path}")
        assert artifact_resp.status_code == 200
        assert artifact_resp.content


@pytest.mark.anyio
async def test_policy_evaluate_allows_get_defers_post_and_denies_out_of_scope():
    app = create_app(testing=True)
    async with _make_client(app) as client:
        payload = {
            "tool": "hexstrike",
            "target": "https://app.example.com/api/events",
            "method": "GET",
            "action_class": "low_impact",
            "risk_class": "low_impact",
            "scope_summary": {
                "allowlist": ["https://app.example.com"],
                "denylist": [],
                "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
            },
        }
        allow_resp = await client.post("/v1/policy/evaluate", json=payload)
        assert allow_resp.status_code == 200
        assert allow_resp.json()["decision"]["decision"] == "allow"

        payload["method"] = "POST"
        payload["action_class"] = "state_changing"
        payload["risk_class"] = "state_changing"
        defer_resp = await client.post("/v1/policy/evaluate", json=payload)
        assert defer_resp.status_code == 200
        assert defer_resp.json()["decision"]["decision"] == "defer"

        payload["target"] = "https://evil.example.net/api/events"
        deny_resp = await client.post("/v1/policy/evaluate", json=payload)
        assert deny_resp.status_code == 200
        assert deny_resp.json()["decision"]["decision"] == "deny"


@pytest.mark.anyio
async def test_policy_evaluate_distinguishes_passive_and_active_zap():
    app = create_app(testing=True)
    async with _make_client(app) as client:
        passive = {
            "tool": "zap",
            "target": "https://app.example.com",
            "action_class": "passive",
            "risk_class": "passive",
            "scope_summary": {"allowlist": ["https://app.example.com"], "denylist": []},
        }
        passive_resp = await client.post("/v1/policy/evaluate", json=passive)
        assert passive_resp.status_code == 200
        assert passive_resp.json()["decision"]["decision"] == "allow"

        active = dict(passive)
        active["action_class"] = "active_scan"
        active["risk_class"] = "active_scan"
        active_resp = await client.post("/v1/policy/evaluate", json=active)
        assert active_resp.status_code == 200
        assert active_resp.json()["decision"]["decision"] == "defer"

        terminal = {
            "tool": "terminal",
            "target": "https://app.example.com",
            "action_class": "low_impact",
            "risk_class": "low_impact",
            "command": ["bash"],
            "scope_summary": {"allowlist": ["https://app.example.com"], "denylist": []},
        }
        terminal_resp = await client.post("/v1/policy/evaluate", json=terminal)
        assert terminal_resp.status_code == 200
        assert terminal_resp.json()["decision"]["decision"] == "allow"


@pytest.mark.anyio
async def test_zap_sites_and_alerts_routes_use_policy_and_proxy(monkeypatch):
    app = create_app(testing=True)

    async def fake_zap_api_get(path: str, *, params: dict[str, object]):
        if path.endswith("/sites/"):
            return {"sites": ["https://app.example.com", "https://admin.example.com"]}
        if path.endswith("/alerts/"):
            return {"alerts": [{"name": "X-Frame-Options Header Not Set", "risk": "Medium"}]}
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr("chimera_core.api.routes._zap_api_get", fake_zap_api_get)

    async with _make_client(app) as client:
        payload = {"target": "https://app.example.com", "scope_summary": {"allowlist": ["https://app.example.com"], "denylist": []}}
        sites_resp = await client.post("/v1/zap/sites", json=payload)
        assert sites_resp.status_code == 200
        assert sites_resp.json()["count"] == 1
        assert sites_resp.json()["sites"] == ["https://app.example.com"]

        alerts_resp = await client.post("/v1/zap/alerts", json=payload)
        assert alerts_resp.status_code == 200
        assert alerts_resp.json()["count"] == 1
        assert alerts_resp.json()["alerts"][0]["name"] == "X-Frame-Options Header Not Set"


@pytest.mark.anyio
async def test_zap_spider_route_returns_scan_metadata(monkeypatch):
    app = create_app(testing=True)

    async def fake_zap_api_get(path: str, *, params: dict[str, object]):
        if path.endswith("/scan/"):
            return {"scan": "3"}
        if path.endswith("/status/"):
            return {"status": "17"}
        if path.endswith("/results/"):
            return {"results": ["https://app.example.com/app", "https://app.example.com/api/openapi.json"]}
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr("chimera_core.api.routes._zap_api_get", fake_zap_api_get)

    async with _make_client(app) as client:
        payload = {
            "target": "https://app.example.com",
            "recurse": True,
            "max_children": 20,
            "scope_summary": {"allowlist": ["https://app.example.com"], "denylist": []},
        }
        spider_resp = await client.post("/v1/zap/spider", json=payload)
        assert spider_resp.status_code == 200
        assert spider_resp.json()["scan_id"] == "3"
        assert spider_resp.json()["status"] == "17"
        assert spider_resp.json()["results_count"] == 2
        assert spider_resp.json()["results"][0] == "https://app.example.com/app"


@pytest.mark.anyio
async def test_zap_spider_results_route_returns_results(monkeypatch):
    app = create_app(testing=True)

    async def fake_zap_api_get(path: str, *, params: dict[str, object]):
        if path.endswith("/results/"):
            assert params["scanId"] == "7"
            return {"results": ["https://app.example.com/app", "https://app.example.com/api/health"]}
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr("chimera_core.api.routes._zap_api_get", fake_zap_api_get)

    async with _make_client(app) as client:
        payload = {
            "scan_id": "7",
            "limit": 10,
            "scope_summary": {"allowlist": ["https://app.example.com"], "denylist": []},
            "target": "https://app.example.com",
        }
        results_resp = await client.post("/v1/zap/spider/results", json=payload)
        assert results_resp.status_code == 200
        assert results_resp.json()["count"] == 2
        assert results_resp.json()["results"][1] == "https://app.example.com/api/health"


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

        _done = {"completed", "failed", "cancelled"}
        for _ in range(100):
            base_status = await client.get(f"/v1/runs/{base_run_id}")
            compare_status = await client.get(f"/v1/runs/{compare_run_id}")
            if base_status.json().get("status") in _done and compare_status.json().get("status") in _done:
                break
            await asyncio.sleep(0.05)

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
        assert options.get("per_task_timeout_s") == 999
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


@pytest.mark.anyio
async def test_browser_session_endpoints(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"

    async def fake_llm(prompt: str) -> str:
        return '{"actions":[{"type":"navigate","url":"https://www.example.com/search"}],"context":{"source":"llm"}}'

    app.state.browser_playwright_factory = fake_browser_factory
    app.state.browser_llm_callable = fake_llm

    async with _make_client(app) as client:
        create_resp = await client.post("/v1/browser/sessions", json={"target": "https://www.example.com/search"})
        assert create_resp.status_code == 201
        session_id = create_resp.json()["session_id"]

        analyze_resp = await client.post(f"/v1/browser/sessions/{session_id}/analyze", json={})
        assert analyze_resp.status_code == 200
        analyze_payload = analyze_resp.json()
        assert analyze_payload["findings"]
        assert analyze_payload["capture"]["dom_sinks"]

        suggest_resp = await client.post(
            f"/v1/browser/sessions/{session_id}/suggest-task",
            json={"hypothesis": "Test reflected DOM XSS", "context": {"dom_snapshot": "<input name=q>"}},
        )
        assert suggest_resp.status_code == 200
        assert suggest_resp.json()["task"]["actions"][0]["url"] == "https://www.example.com/search"

        trace_resp = await client.post(
            f"/v1/browser/sessions/{session_id}/trace-xss",
            json={"parameter": "q", "payload": "<svg/onload=alert(1)>"},
        )
        assert trace_resp.status_code == 200
        trace_payload = trace_resp.json()
        assert trace_payload["trace"]["status"] == "confirmed"
        assert trace_payload["findings"][0]["validation_status"] == "confirmed"

        get_resp = await client.get(f"/v1/browser/sessions/{session_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["last_action"] == "trace-xss"

        console_resp = await client.get(f"/v1/browser/sessions/{session_id}/console")
        assert console_resp.status_code == 200
        assert "capture_artifact_ref" in console_resp.json()

        network_resp = await client.get(f"/v1/browser/sessions/{session_id}/network")
        assert network_resp.status_code == 200
        assert isinstance(network_resp.json()["network"], list)

        screenshot_resp = await client.get(f"/v1/browser/sessions/{session_id}/screenshot")
        assert screenshot_resp.status_code == 200
        assert screenshot_resp.headers["content-type"] == "image/png"

        delete_resp = await client.delete(f"/v1/browser/sessions/{session_id}")
        assert delete_resp.status_code == 200


@pytest.mark.anyio
async def test_browser_execute_endpoint_runs_task(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.browser_playwright_factory = fake_browser_factory

    async with _make_client(app) as client:
        create_resp = await client.post("/v1/browser/sessions", json={"target": "https://www.example.com/app"})
        session_id = create_resp.json()["session_id"]
        execute_resp = await client.post(
            f"/v1/browser/sessions/{session_id}/execute",
            json={"task": {"actions": [{"type": "navigate", "url": "https://www.example.com/app"}]}},
        )
        assert execute_resp.status_code == 200
        payload = execute_resp.json()
        assert payload["capture"]["url"] == "https://www.example.com/app"
        assert payload["findings"][0]["finding_type"] == "DOM_XSS"


@pytest.mark.anyio
async def test_browser_execute_preserves_current_page_when_url_omitted(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.browser_playwright_factory = fake_browser_factory

    async with _make_client(app) as client:
        create_resp = await client.post("/v1/browser/sessions", json={"target": "https://www.example.com/app"})
        session_id = create_resp.json()["session_id"]

        first_resp = await client.post(
            f"/v1/browser/sessions/{session_id}/execute",
            json={"task": {"actions": [{"type": "navigate", "url": "https://www.example.com/dashboard"}]}},
        )
        assert first_resp.status_code == 200
        assert first_resp.json()["capture"]["url"] == "https://www.example.com/dashboard"

        second_resp = await client.post(
            f"/v1/browser/sessions/{session_id}/execute",
            json={"task": {"actions": [{"type": "extract_dom"}]}},
        )
        assert second_resp.status_code == 200
        assert second_resp.json()["capture"]["url"] == "https://www.example.com/dashboard"


@pytest.mark.anyio
async def test_terminal_session_endpoints(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.runtime_allowlist = ["sh"]

    async with _make_client(app) as client:
        create_resp = await client.post(
            "/v1/terminal/sessions",
            json={
                "command": ["sh", "-c", "printf ready; cat"],
                "target": "https://www.example.com",
                "scope_summary": {"allowlist": ["https://www.example.com"], "denylist": []},
            },
        )
        assert create_resp.status_code == 201
        session_id = create_resp.json()["session_id"]

        read_resp = await client.post(f"/v1/terminal/sessions/{session_id}/read", json={"timeout_ms": 100})
        assert read_resp.status_code == 200
        assert "ready" in read_resp.json()["output"]

        write_resp = await client.post(f"/v1/terminal/sessions/{session_id}/write", json={"data": "hello\n"})
        assert write_resp.status_code == 200
        assert write_resp.json()["bytes_written"] >= 1

        echoed_resp = await client.post(f"/v1/terminal/sessions/{session_id}/read", json={"timeout_ms": 100})
        assert echoed_resp.status_code == 200
        assert "hello" in echoed_resp.json()["output"]

        resize_resp = await client.post(f"/v1/terminal/sessions/{session_id}/resize", json={"cols": 140, "rows": 42})
        assert resize_resp.status_code == 200
        assert resize_resp.json()["cols"] == 140

        get_resp = await client.get(f"/v1/terminal/sessions/{session_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["status"] in {"running", "exited"}

        delete_resp = await client.delete(f"/v1/terminal/sessions/{session_id}")
        assert delete_resp.status_code == 200


@pytest.mark.anyio
async def test_shannon_task_endpoints(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.shannon_http_client = FakeShannonHttpClient()

    async with _make_client(app) as client:
        create_resp = await client.post(
            "/v1/shannon/tasks",
            json={
                "target": "https://api.example.com",
                "query": "Assess JWT verification weaknesses.",
                "base_url": "http://shannon.local",
            },
        )
        assert create_resp.status_code == 202
        task_id = create_resp.json()["task_id"]

        for _ in range(50):
            status_resp = await client.get(f"/v1/shannon/tasks/{task_id}")
            assert status_resp.status_code == 200
            payload = status_resp.json()
            if payload["status"] == "completed":
                break
            await asyncio.sleep(0.01)

        assert payload["status"] == "completed"
        assert payload["result"]["findings"]
        assert payload["result"]["findings"][0]["finding_type"] == "JWT"


@pytest.mark.anyio
async def test_parser_and_oracle_endpoints(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"

    async def fake_oracle(question: str, *, target=None, context=None):
        return {"question": question, "target": target, "answer": "Try GraphQL batching.", "suggestions": [{"vector": "graphql_batching"}]}

    app.state.shannon_oracle_callable = fake_oracle

    async with _make_client(app) as client:
        parse_resp = await client.post("/v1/parser/interpret", json={"text": "scan https://crapi.example.com with recon pipeline"})
        assert parse_resp.status_code == 200
        parsed = parse_resp.json()
        assert parsed["kind"] == "command"
        assert parsed["command"]["pipeline"] == "recon"
        assert parsed["command"]["target"] == "https://crapi.example.com"

        scope_resp = await client.post("/v1/parser/interpret", json={"text": "https://a.example.com\nhttps://b.example.com"})
        assert scope_resp.status_code == 200
        assert scope_resp.json()["kind"] == "scope"

        oracle_resp = await client.post("/v1/shannon/oracle", json={"question": "What could go wrong with this GraphQL endpoint?", "target": "https://api.example.com/graphql"})
        assert oracle_resp.status_code == 200
        assert oracle_resp.json()["answer"] == "Try GraphQL batching."


@pytest.mark.anyio
async def test_chain_and_replay_endpoints(tmp_path: Path):
    app = create_app(testing=True)
    app.state.artifacts_root = tmp_path / "artifacts"
    app.state.run_store = app.state.run_store.__class__(app.state.artifacts_root)
    run_id = "run-chain"
    run_dir = app.state.artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    app.state.run_store.create_run(
        run_id,
        scope_raw="allowlist: ['https://api.example.com']\n",
        scope_normalized={"allowlist": ["https://api.example.com"], "denylist": []},
        plan={"tasks": []},
        options={"live": True},
    )
    finding_id = "chain-123"
    findings = [
        {
            "finding_id": finding_id,
            "title": "Exploit chain: IDOR plus JWT weakness enables account takeover",
            "severity": "critical",
            "validation_status": "confirmed",
            "replay_steps": [{"step": 1, "action": "GET /api/users/42", "expected_result": "Other user's data is returned."}],
            "proof_artifacts": [{"type": "http", "ref": "/artifacts/request-1.json"}],
            "chain_parent_ids": ["f1", "f2"],
        }
    ]
    (run_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (run_dir / "chains.json").write_text(json.dumps(findings), encoding="utf-8")
    (run_dir / "chain_graphs.json").write_text(
        json.dumps([{"finding_id": finding_id, "ascii": "[CRITICAL] chain", "title": findings[0]["title"], "severity": "critical"}]),
        encoding="utf-8",
    )
    poc_dir = run_dir / "poc_bundles"
    poc_dir.mkdir(parents=True, exist_ok=True)
    (poc_dir / "chain.json").write_text(json.dumps({"finding": findings[0], "replay_manifest": findings[0]["replay_steps"]}), encoding="utf-8")

    async with _make_client(app) as client:
        chains_resp = await client.get(f"/v1/runs/{run_id}/chains")
        assert chains_resp.status_code == 200
        assert chains_resp.json()[0]["finding_id"] == finding_id

        chain_detail_resp = await client.get(f"/v1/runs/{run_id}/chains/{finding_id}")
        assert chain_detail_resp.status_code == 200
        assert chain_detail_resp.json()["chain"]["finding_id"] == finding_id
        assert chain_detail_resp.json()["graph"]["ascii"] == "[CRITICAL] chain"

        replay_resp = await client.get(f"/v1/runs/{run_id}/replays/{finding_id}")
        assert replay_resp.status_code == 200
        assert replay_resp.json()["replay_steps"][0]["action"] == "GET /api/users/42"

from pathlib import Path

import pytest

from chimera_core.adapters.browser_adapter import BrowserAdapter
from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    run_id = "run-browser"
    artifacts_root = tmp_path / "artifacts"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=EventStore(run_dir / "events.jsonl"),
        artifacts_root=artifacts_root,
        run_id=run_id,
    )


@pytest.mark.asyncio
async def test_browser_trace_xss_sink_confirms_payload() -> None:
    class _Page:
        url = ""
        def on(self, event, handler): pass
        async def goto(self, url, timeout=0): self.url = url
        async def fill(self, selector, value, timeout=0): pass
        async def wait_for_load_state(self, state, timeout=0): pass
        async def content(self): return "reflected: <svg>"
        async def screenshot(self): return b"fake"
        async def eval_on_selector_all(self, sel, script): return []
        async def evaluate(self, js): return []

    class _Tracing:
        async def start(self, **kw): pass
        async def stop(self): pass

    class _Context:
        def __init__(self):
            self.tracing = _Tracing()
        async def new_page(self): return _Page()
        async def add_cookies(self, cookies): pass

    class _Browser:
        async def new_context(self): return _Context()
        async def close(self): pass

    async def fake_playwright_factory(headless: bool):
        b = _Browser()
        ctx = await b.new_context()
        page = await ctx.new_page()
        return b, ctx, page

    adapter = BrowserAdapter(make_runtime(Path("/tmp")), options={"playwright_factory": fake_playwright_factory})
    result = await adapter.trace_xss_sink("https://www.example.com/search", "q", "<svg>")

    assert result["status"] == "confirmed"


def test_browser_normalizes_capture(tmp_path: Path) -> None:
    adapter = BrowserAdapter(make_runtime(tmp_path), run_id="run-browser", task_id="T9", scope_hash="scope")
    findings = adapter.normalize(
        {
            "url": "https://www.example.com/search",
            "dom_sinks": [{"type": "innerHTML", "evidence": "innerHTML = location.search", "parameter": "q"}],
            "console": [{"type": "error", "text": "boom"}],
            "postmessage_listeners": ["window.addEventListener('message', handler)"],
        }
    )

    assert len(findings) == 3
    assert findings[0].finding_type == "DOM_XSS"


def test_browser_run_trace_mode_writes_validated_finding(tmp_path: Path) -> None:
    adapter = BrowserAdapter(
        make_runtime(tmp_path),
        run_id="run-browser",
        task_id="T10",
        scope_hash="scope",
        options={
            "mode": "trace_xss",
            "parameter": "q",
            "capture_override": None,
            "browser_factory": None,
        },
    )

    async def fake_trace(url: str, parameter: str, payload: str):
        return {
            "status": "confirmed",
            "confidence": 0.91,
            "proof_artifacts": [{"type": "browser_capture", "ref": url}],
            "replay_steps": [{"action": "open_browser", "request": {"url": url}, "expected_diff": "Payload reaches a DOM sink."}],
            "explanation": "Payload reached a DOM sink.",
        }

    adapter.trace_xss_sink = fake_trace  # type: ignore[assignment]
    result = adapter.run(["https://www.example.com/search"])

    assert result["findings"][0].validation_status == "confirmed"
    assert any(artifact["artifact_type"] == "xss_trace" for artifact in result["artifacts"])


@pytest.mark.asyncio
async def test_browser_suggest_task_uses_llm_callable(tmp_path: Path) -> None:
    async def fake_llm(prompt: str) -> str:
        return '{"actions":[{"type":"navigate","url":"https://www.example.com/search"}]}'

    adapter = BrowserAdapter(make_runtime(tmp_path), options={"llm_callable": fake_llm})
    task = await adapter.suggest_task({"dom_snapshot": "<input name=q>"}, "test reflected DOM XSS")

    assert task.actions[0].url == "https://www.example.com/search"

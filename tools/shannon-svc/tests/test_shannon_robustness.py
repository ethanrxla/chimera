"""
TDD tests for Shannon robustness against non-JSON WhiteRabbitNeo responses.

Tests cover the 3-stage chain (openai_compatible provider):
- Stage parse failure raises RuntimeError → task record has raw_output snippet.
- Raw LLM text saved to artifact before each parse attempt (_save_raw_llm_artifact
  called once per stage, 3 times total on success path).
- Error record includes raw_output snippet (first 500 chars of failing stage output).
- Startup health check reports per-model availability including model_available bool.
"""
import asyncio
import json
import os
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers to import main.py without starting the FastAPI app.
# We reload the module so patches take effect on module-level state.
# Stub out `anthropic` (not installed in chimera-core venv) before import.
# ---------------------------------------------------------------------------

SHANNON_SVC_DIR = Path(__file__).resolve().parents[1]
if str(SHANNON_SVC_DIR) not in sys.path:
    sys.path.insert(0, str(SHANNON_SVC_DIR))
CHIMERA_CORE_DIR = Path(__file__).resolve().parents[3] / "chimera" / "chimera-core"
if str(CHIMERA_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CHIMERA_CORE_DIR))


def _stub_anthropic():
    """Inject a minimal anthropic stub so main.py can be imported without the package."""
    if "anthropic" not in sys.modules:
        stub = types.ModuleType("anthropic")
        stub.AsyncAnthropic = MagicMock  # type: ignore[attr-defined]
        sys.modules["anthropic"] = stub


def _stub_openai():
    """Inject a minimal openai stub so main.py can be imported without the package."""
    if "openai" not in sys.modules:
        stub = types.ModuleType("openai")
        stub.AsyncOpenAI = MagicMock  # type: ignore[attr-defined]
        sys.modules["openai"] = stub


def _reload_main(env: dict):
    """Import (or re-import) main with specific env overrides."""
    import importlib
    _stub_anthropic()
    _stub_openai()
    with patch.dict(os.environ, env, clear=False):
        if "main" in sys.modules:
            import main as m
            importlib.reload(m)
            return m
        import main as m
        return m


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PROSE_RESPONSE = """\
# Juice Shop Security Analysis

## SQL Injection (A1)
The login endpoint is vulnerable to SQL injection.
Payload: ' OR 1=1--
Impact: authentication bypass.

## XSS (A7)
The search box reflects unsanitized input.
"""

PLAN_JSON = json.dumps({
    "attack_classes": ["SQLi", "XSS"],
    "checks": [
        {"id": "c1", "class": "SQLi", "target": "/rest/user/login",
         "what_to_test": "username field", "expected_vulnerability": "auth bypass"}
    ],
    "context_notes": "OWASP Juice Shop",
})

FINDINGS_JSON = json.dumps({
    "findings": [
        {
            "title": "SQL Injection in login",
            "severity": "critical",
            "target": "http://juice-shop:3000/rest/user/login",
            "description": "Login endpoint vulnerable to SQLi.",
            "repro_guidance": "POST with ' OR 1=1--",
        }
    ]
})

VALID_JSON_RESPONSE = FINDINGS_JSON  # alias for backward compat

REPAIR_JSON_RESPONSE = json.dumps({"findings": []})

FINAL_JSON = FINDINGS_JSON  # validator returns same schema


# ---------------------------------------------------------------------------
# Test: chain completes when all 3 stages return valid JSON
# ---------------------------------------------------------------------------

def test_chain_completes_with_three_valid_stages(tmp_path):
    """
    Happy path: planner, executor, and validator all return valid JSON.
    Task status must be 'completed', findings must match validator output,
    and stages dict must identify all three model roles.
    """
    call_count = 0

    async def mock_call_model(model, system_prompt, user_content):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return PLAN_JSON, None       # planner
        if call_count == 2:
            return FINDINGS_JSON, None   # executor
        return FINAL_JSON, None          # validator

    m = _reload_main({"SHANNON_PROVIDER": "openai_compatible",
                       "SHANNON_PLANNER_MODEL": "qwen2.5:7b",
                       "SHANNON_EXECUTOR_MODEL": "whiterabbitneo-13b",
                       "SHANNON_VALIDATOR_MODEL": "dolphin-llama3:8b",
                       "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1"})

    task_id = "t-chain-happy"
    m._tasks[task_id] = {"status": "running", "findings": [], "provider": "openai_compatible",
                          "model": "qwen2.5:7b|whiterabbitneo-13b|dolphin-llama3:8b"}

    with patch.object(m, "_call_model", side_effect=mock_call_model):
        asyncio.run(m._run_analysis(task_id, "check http://juice-shop:3000"))

    result = m._tasks[task_id]
    assert result["status"] == "completed", (
        f"Expected completed, got status={result['status']} error={result.get('error')}"
    )
    assert call_count == 3, f"Expected exactly 3 model calls (one per stage), got {call_count}"
    assert "stages" in result
    assert result["stages"]["planner"] == "qwen2.5:7b"
    assert result["stages"]["executor"] == "whiterabbitneo-13b"
    assert result["stages"]["validator"] == "dolphin-llama3:8b"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["title"] == "SQL Injection in login"


# ---------------------------------------------------------------------------
# Test: retry on non-JSON response (stage failure → task failed with raw_output)
# ---------------------------------------------------------------------------

def test_chain_fails_with_raw_output_when_planner_returns_prose(tmp_path):
    """
    When the planner stage returns prose (not JSON), the chain must:
    1. Detect the parse failure (RuntimeError from _parse_stage).
    2. Record task as failed.
    3. Include 'raw_output' with model content in the task record.
    """
    async def mock_call_model(model, system_prompt, user_content):
        return PROSE_RESPONSE, None   # always prose

    m = _reload_main({"SHANNON_PROVIDER": "openai_compatible",
                       "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1"})

    task_id = "t-retry-test"
    m._tasks[task_id] = {"status": "running", "findings": [], "provider": "openai_compatible",
                          "model": "qwen2.5:7b|whiterabbitneo-13b|dolphin-llama3:8b"}

    with patch.object(m, "_call_model", side_effect=mock_call_model):
        asyncio.run(m._run_analysis(task_id, "check http://juice-shop:3000"))

    result = m._tasks[task_id]
    assert result["status"] == "failed", (
        f"Expected failed when planner returns prose, got status={result['status']}"
    )
    assert "raw_output" in result, "Task record missing 'raw_output' key on chain failure"


# ---------------------------------------------------------------------------
# Test: raw LLM text artifact saved before parse (once per stage)
# ---------------------------------------------------------------------------

def test_raw_llm_text_artifact_saved(tmp_path):
    """
    _save_raw_llm_artifact must be called at least once (before the first parse attempt).
    The first call must receive raw model output containing recognisable content.
    """
    async def mock_call_model(model, system_prompt, user_content):
        return PROSE_RESPONSE, None   # first stage returns prose; chain will fail

    m = _reload_main({"SHANNON_PROVIDER": "openai_compatible",
                       "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1"})

    task_id = "t-artifact-test"
    m._tasks[task_id] = {"status": "running", "findings": [], "provider": "openai_compatible",
                          "model": "qwen2.5:7b|whiterabbitneo-13b|dolphin-llama3:8b"}

    with (
        patch.object(m, "_call_model", side_effect=mock_call_model),
        patch.object(m, "_save_raw_llm_artifact") as mock_save,
    ):
        asyncio.run(m._run_analysis(task_id, "check http://juice-shop:3000"))

    assert mock_save.called, (
        "_save_raw_llm_artifact must be called to persist raw LLM text before parse"
    )
    # The raw text passed to the first save must contain the model's prose
    call_args = mock_save.call_args_list[0]
    raw_text = call_args[0][0] if call_args[0] else call_args[1].get("text", "")
    assert "Juice Shop" in raw_text or "SQL" in raw_text, (
        f"Raw text artifact doesn't contain expected model output; got: {raw_text[:200]!r}"
    )


# ---------------------------------------------------------------------------
# Test: error includes raw text snippet on chain failure
# ---------------------------------------------------------------------------

def test_error_includes_raw_text_on_final_failure(tmp_path):
    """
    When a chain stage produces unparseable output, the task failure record must
    include 'raw_output' with the first 500 chars of the failing stage's output.
    """
    async def mock_call_model(model, system_prompt, user_content):
        return PROSE_RESPONSE, None  # always returns prose, never JSON

    m = _reload_main({"SHANNON_PROVIDER": "openai_compatible",
                       "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1"})

    task_id = "t-error-snippet"
    m._tasks[task_id] = {"status": "running", "findings": [], "provider": "openai_compatible",
                          "model": "qwen2.5:7b|whiterabbitneo-13b|dolphin-llama3:8b"}

    with patch.object(m, "_call_model", side_effect=mock_call_model):
        asyncio.run(m._run_analysis(task_id, "check http://juice-shop:3000"))

    result = m._tasks[task_id]
    assert result["status"] == "failed"
    assert "raw_output" in result, (
        f"Task record missing 'raw_output' key on failure; keys: {list(result.keys())}"
    )
    raw_snippet = result["raw_output"]
    assert len(raw_snippet) > 0, "raw_output snippet must not be empty"
    assert any(kw in raw_snippet for kw in ("Juice Shop", "SQL", "Injection", "XSS")), (
        f"raw_output snippet doesn't look like model output; got: {raw_snippet[:200]!r}"
    )


# ---------------------------------------------------------------------------
# Test: model availability at health endpoint
# ---------------------------------------------------------------------------

def test_health_endpoint_includes_model_availability_status():
    """
    GET /health should include 'model_available' field (backward compat bool) and
    'models' dict with per-stage availability so the operator can diagnose which
    model is missing without reading logs.
    """
    m = _reload_main({"SHANNON_PROVIDER": "openai_compatible",
                       "SHANNON_PLANNER_MODEL": "qwen2.5:7b",
                       "SHANNON_EXECUTOR_MODEL": "whiterabbitneo-13b",
                       "SHANNON_VALIDATOR_MODEL": "dolphin-llama3:8b",
                       "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1"})

    # Simulate backend returning all three models
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": [
            {"id": "qwen2.5:7b"},
            {"id": "whiterabbitneo-13b:latest"},
            {"id": "dolphin-llama3:8b"},
        ]
    }

    with patch("httpx.get", return_value=mock_response):
        from fastapi.testclient import TestClient
        client = TestClient(m.app)
        resp = client.get("/health")

    assert resp.status_code == 200
    data = resp.json()
    assert "model_available" in data, (
        f"/health response missing 'model_available' field; got keys: {list(data.keys())}"
    )
    assert "models" in data, (
        f"/health response missing 'models' dict; got keys: {list(data.keys())}"
    )
    assert data["model_available"] is True
    assert data["models"]["planner"] is True
    assert data["models"]["executor"] is True
    assert data["models"]["validator"] is True


def test_executor_with_hexstrike_tool_loop_uses_supported_local_tools():
    """
    The Shannon executor should only rely on the locally supported HexStrike
    surface. A tool-call turn for `probe` must dispatch through _hexstrike_call,
    then a second executor turn should consume the injected result and return
    normal findings JSON.
    """
    first_turn = (
        '<hexstrike_call>{"tool":"probe","endpoint":"https://example.com/login","method":"GET"}</hexstrike_call>'
    )
    second_turn = json.dumps(
        {
            "findings": [
                {
                    "title": "Weak login surface",
                    "severity": "medium",
                    "target": "https://example.com/login",
                    "description": "Probe output indicates missing hardening headers.",
                    "repro_guidance": "Replay the probe and inspect the response headers.",
                }
            ]
        }
    )

    async def mock_call_model(model, system_prompt, user_content):
        mock_call_model.calls += 1
        return (first_turn, None) if mock_call_model.calls == 1 else (second_turn, None)

    mock_call_model.calls = 0

    async def mock_hexstrike_call(tool_name, params):
        assert tool_name == "probe"
        assert params["endpoint"] == "https://example.com/login"
        return json.dumps({"status_code": 200, "checks": {"csp": False}})

    m = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1",
            "HEXSTRIKE_ENABLED": "true",
        }
    )

    with (
        patch.object(m, "_call_model", side_effect=mock_call_model),
        patch.object(m, "_hexstrike_call", side_effect=mock_hexstrike_call) as mock_tool,
    ):
        findings_data, usage = asyncio.run(m._executor_with_tools("t-tool-loop", '{"query":"check"}'))

    assert mock_tool.call_count == 1
    assert mock_call_model.calls == 2
    assert usage["total_tokens"] == 0
    assert findings_data["findings"][0]["title"] == "Weak login surface"


def test_hexstrike_call_routes_upstream_and_analysis_tools():
    """
    HexStrike calls must route through the unified launcher surface:
    - upstream execution tools via /api/tools/*
    - local analysis tools via /api/recon, /api/probe, etc.
    """
    posted_urls = []

    class _Resp:
        def json(self):
            return {"ok": True}

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url, json=None):
            posted_urls.append(url)
            return _Resp()

    m = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1",
            "HEXSTRIKE_BASE_URL": "http://hexstrike:8888",
        }
    )

    with patch.object(m._httpx, "AsyncClient", _Client):
        scope_input = '{"query":"check https://example.com","plan":{"checks":[{"target":"https://example.com/login"}]}}'
        asyncio.run(m._hexstrike_call("nuclei", {"target": "https://example.com"}, scope_input))
        asyncio.run(m._hexstrike_call("probe", {"endpoint": "https://example.com/login"}, scope_input))

    assert "http://hexstrike:8888/api/tools/nuclei" in posted_urls
    assert "http://hexstrike:8888/api/probe" in posted_urls


def test_executor_tool_prompt_lists_unified_hexstrike_tools():
    """
    The executor prompt must match the unified launcher surface:
    upstream execution tools plus local analysis tools.
    """
    m = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1",
        }
    )

    prompt = m.HEXSTRIKE_TOOLS_PROMPT

    assert '"tool":"recon"' in prompt
    assert '"tool":"probe"' in prompt
    assert '"tool":"nuclei"' in prompt
    assert '"tool":"sqlmap"' in prompt
    assert '"tool":"command"' in prompt


def test_supported_hexstrike_tools_match_shared_catalog_for_shannon_executor():
    from chimera_core.hexstrike.catalog import get_tool_catalog

    m = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1",
        }
    )

    expected = {
        name
        for name, spec in get_tool_catalog().items()
        if "shannon_executor" in spec.allowed_agents
    }

    assert set(m.SUPPORTED_HEXSTRIKE_TOOLS) == expected


def test_hexstrike_call_blocks_out_of_scope_target():
    m = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1",
            "HEXSTRIKE_BASE_URL": "http://hexstrike:8888",
        }
    )

    result = asyncio.run(
        m._hexstrike_call(
            "probe",
            {"endpoint": "https://evil.com/login"},
            '{"query":"check https://example.com","plan":{"checks":[]}}',
        )
    )

    parsed = json.loads(result)
    assert parsed["error"] == "scope_violation"


def test_hexstrike_call_blocks_dangerous_tool_for_shannon():
    m = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_OPENAI_BASE_URL": "http://ollama:11434/v1",
            "HEXSTRIKE_BASE_URL": "http://hexstrike:8888",
        }
    )

    result = asyncio.run(
        m._hexstrike_call(
            "command",
            {"command": "id"},
            '{"query":"check https://example.com","plan":{"checks":[]}}',
        )
    )

    parsed = json.loads(result)
    assert parsed["error"] == "scope_violation"

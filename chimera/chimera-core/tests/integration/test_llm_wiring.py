"""
Integration tests for LLM / Shannon wiring.

A1 — Ollama health + model available (requires OLLAMA_URL env)
A2 — Shannon health reflects ollama config (requires shannon reachable)
A3 — Shannon oracle returns structured findings (requires Shannon + Ollama)
A4 — _clip_to_budget() truncation (pure unit, no external deps)
A5 — LLM call metadata (provider/model/usage) present in task response (requires Shannon)
"""
import os
import socket
import time
import uuid

import httpx
import pytest


# ---------------------------------------------------------------------------
# Reachability helpers
# ---------------------------------------------------------------------------

def _can_reach(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
_SHANNON_URL = os.getenv("SHANNON_URL", "http://shannon:8080")

_ollama_reachable = _can_reach("ollama", 11434)
_shannon_reachable = _can_reach("shannon", 8080)

skip_no_ollama = pytest.mark.skipif(
    not _ollama_reachable,
    reason="ollama:11434 not reachable — run inside container network",
)
skip_no_shannon = pytest.mark.skipif(
    not _shannon_reachable,
    reason="shannon:8080 not reachable — run inside container network",
)


# ---------------------------------------------------------------------------
# A1 — Ollama health and model available
# ---------------------------------------------------------------------------

@skip_no_ollama
def test_ollama_health_and_model_available():
    """GET /api/tags returns 200 and qwen2.5-coder:7b is in models[].name."""
    resp = httpx.get(f"{_OLLAMA_URL}/api/tags", timeout=10)
    assert resp.status_code == 200, f"Ollama /api/tags returned {resp.status_code}"
    data = resp.json()
    model_names = [m.get("name", "") for m in data.get("models", [])]
    assert any("qwen2.5-coder" in name.lower() for name in model_names), (
        f"qwen2.5-coder model not found in ollama. Available: {model_names}"
    )


# ---------------------------------------------------------------------------
# A2 — Shannon health reflects ollama config
# ---------------------------------------------------------------------------

@skip_no_shannon
def test_shannon_health_reflects_ollama_config():
    """GET /health must show provider=openai_compatible and chain models containing qwen2.5-coder."""
    resp = httpx.get(f"{_SHANNON_URL}/health", timeout=10)
    assert resp.status_code == 200, f"Shannon /health returned {resp.status_code}"
    data = resp.json()
    assert data.get("provider") == "openai_compatible", (
        f"Expected provider=openai_compatible, got: {data.get('provider')}"
    )
    chain = data.get("chain") or {}
    planner = (chain.get("planner") or "").lower()
    executor = (chain.get("executor") or "").lower()
    validator = (chain.get("validator") or "").lower()
    assert "qwen2.5-coder" in planner, f"Expected qwen2.5-coder planner, got: {planner!r}"
    assert "qwen2.5-coder" in executor, f"Expected qwen2.5-coder executor, got: {executor!r}"
    assert "qwen2.5-coder" in validator, f"Expected qwen2.5-coder validator, got: {validator!r}"
    base_url = data.get("base_url", "")
    assert "ollama" in base_url.lower(), (
        f"Expected base_url to reference ollama, got: {base_url!r}"
    )


# ---------------------------------------------------------------------------
# A3 — Shannon oracle returns structured findings
# ---------------------------------------------------------------------------

@skip_no_shannon
def test_shannon_oracle_returns_structured_findings():
    """
    POST /api/v1/tasks with a security query → poll until completed →
    assert findings list shape is correct.
    """
    query = (
        "Target: http://juice-shop:3000\n"
        "Check for: SQL injection on /rest/user/login (email parameter)\n"
        "Return findings JSON only."
    )
    resp = httpx.post(
        f"{_SHANNON_URL}/api/v1/tasks",
        json={"query": query, "session_id": "test-a3"},
        timeout=15,
    )
    assert resp.status_code == 200, f"Submit failed: {resp.text}"
    task_id = resp.json()["task_id"]

    # Poll up to 120s for the LLM to respond
    deadline = time.time() + 120
    status = "running"
    data: dict = {}
    while time.time() < deadline:
        poll = httpx.get(f"{_SHANNON_URL}/api/v1/tasks/{task_id}", timeout=10)
        data = poll.json()
        status = data.get("status", "running")
        if status in {"completed", "failed"}:
            break
        time.sleep(2)

    assert status == "completed", (
        f"Shannon task failed — 3-model chain must not produce JSON parse errors: {data}"
    )
    findings = data.get("findings", [])
    assert isinstance(findings, list), "findings must be a list"
    for finding in findings:
        assert "title" in finding, f"Finding missing 'title': {finding}"
        assert "severity" in finding, f"Finding missing 'severity': {finding}"
    # 3-model chain must report all three stage names.
    if data.get("provider") == "openai_compatible":
        assert "stages" in data, f"Chain response missing 'stages' dict: {data}"
        assert {"planner", "executor", "validator"} == set(data["stages"].keys())


# ---------------------------------------------------------------------------
# A4 — _clip_to_budget() truncation (pure unit, no external deps)
# ---------------------------------------------------------------------------

def test_context_budget_enforcement():
    """
    Shannon's _clip_to_budget() must truncate a query that exceeds the token budget.
    Budget: (8096 - 512) * 4 = 30336 chars.
    """
    # Import from shannon service — this will fail RED until _clip_to_budget is added
    import ast
    from pathlib import Path

    # Search parent dirs for tools/shannon-svc/main.py (container: /app, host: repo root)
    shannon_main = None
    for depth in range(2, 7):
        candidate = Path(__file__).resolve().parents[depth] / "tools" / "shannon-svc" / "main.py"
        if candidate.exists():
            shannon_main = candidate
            break
    assert shannon_main is not None, "Cannot find tools/shannon-svc/main.py"

    source = shannon_main.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Extract only the constants and function defs we need (avoids import deps)
    needed_names = {"LOCAL_LLM_MAX_TOKENS", "CONTEXT_HEADROOM", "_clip_to_budget"}
    selected_nodes = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any(t in needed_names for t in targets):
                selected_nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in needed_names:
            selected_nodes.append(node)

    fn_names = {n.name for n in selected_nodes if isinstance(n, ast.FunctionDef)}
    assert "_clip_to_budget" in fn_names, (
        "_clip_to_budget() not found in tools/shannon-svc/main.py — "
        "add it as described in the Shannon context-limit guard plan"
    )

    # Build a minimal module with just the extracted nodes and exec it
    mini_module = ast.Module(body=selected_nodes, type_ignores=[])
    ast.fix_missing_locations(mini_module)
    import os as _os
    ns: dict = {"os": _os}
    exec(compile(mini_module, str(shannon_main), "exec"), ns)  # noqa: S102
    clip = ns["_clip_to_budget"]

    budget_chars = (8096 - 512) * 4  # 30336
    long_query = "A" * (budget_chars + 5000)
    result = clip(long_query)
    assert len(result) <= budget_chars + len("\n[truncated: context budget]") + 50, (
        f"_clip_to_budget did not truncate: result length {len(result)}"
    )
    assert "[truncated" in result, "Expected truncation marker in result"

    short_query = "Is /login vulnerable to SQLi?"
    assert clip(short_query) == short_query, "Short queries must not be modified"


# ---------------------------------------------------------------------------
# A5 — LLM call metadata (provider/model/usage) in task response
# ---------------------------------------------------------------------------

@skip_no_shannon
def test_llm_call_metadata_logged():
    """
    After a task completes, the response must include provider and model fields.
    usage (token counts) should be present when the backend provides them.
    """
    resp = httpx.post(
        f"{_SHANNON_URL}/api/v1/tasks",
        json={"query": "List security headers for http://juice-shop:3000", "session_id": "test-a5"},
        timeout=15,
    )
    assert resp.status_code == 200
    task_id = resp.json()["task_id"]

    deadline = time.time() + 120
    data: dict = {}
    while time.time() < deadline:
        poll = httpx.get(f"{_SHANNON_URL}/api/v1/tasks/{task_id}", timeout=10)
        data = poll.json()
        if data.get("status") in {"completed", "failed"}:
            break
        time.sleep(2)

    assert "provider" in data, f"'provider' not in task response: {data}"
    assert "model" in data, f"'model' not in task response: {data}"
    # usage is logged when the backend supports it; only assert key presence if completed
    if data.get("status") == "completed":
        # usage is optional but preferred — warn rather than fail hard
        if "usage" not in data:
            pytest.xfail("Shannon does not yet return token usage metadata (add it in Phase 2-A)")

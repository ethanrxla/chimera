import json
from pathlib import Path

from chimera_core.planner import generate_plan
from chimera_core.scope import ScopeGraph, ScopePolicy


def test_generate_plan_adds_shannon_task(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"shannon": {"enabled": True}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = generate_plan(scope_graph, scope_policy, None)

    assert "autoswagger-0-0" in plan.tasks
    assert "strix-0-1" in plan.tasks
    assert "shannon-0-2" in plan.tasks
    assert "shannon-0-2" in plan.graph["strix-0-1"]
    assert plan.stages == ["discover", "classify", "validate", "chain", "report"]


def test_generate_plan_emits_rate_limit_validator_for_api_targets(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"shannon": {"enabled": True}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["https://api.example.com/v1"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = generate_plan(scope_graph, scope_policy, {"asset_type": "api_rest"})

    assert "autoswagger-0-0" in plan.tasks
    assert "rate_limit_validator-0-2" in plan.tasks
    assert "shannon-0-3" in plan.tasks


def test_generate_plan_routes_subfinder_for_bare_domain(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"shannon": {"enabled": True}}), encoding="utf-8")
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = generate_plan(scope_graph, scope_policy, None)

    assert "subfinder-0-0" in plan.tasks
    assert "zypheron-0-1" in plan.tasks


def test_generate_plan_routes_browser_for_web_targets(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"shannon": {"enabled": True}}), encoding="utf-8")
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = generate_plan(scope_graph, scope_policy, None)

    assert "browser-0-1" in plan.tasks

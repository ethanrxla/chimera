import json
from pathlib import Path

import chimera_core.planner as planner
from chimera_core.scope import ScopeGraph, ScopePolicy


def test_generate_plan_adds_shannon_task(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"shannon": {"enabled": True, "verify_availability": False}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = planner.generate_plan(scope_graph, scope_policy, None)

    assert "subfinder-0-0" in plan.tasks
    assert "zypheron-0-1" in plan.tasks
    assert "shannon-0-2" in plan.tasks
    assert "shannon-0-2" in plan.graph["zypheron-0-1"]
    assert plan.stages == ["discover", "classify", "validate", "chain", "report"]


def test_generate_plan_emits_rate_limit_validator_for_api_targets(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"shannon": {"enabled": True, "verify_availability": False}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["https://api.example.com/v1"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = planner.generate_plan(scope_graph, scope_policy, {"asset_type": "api_rest"})

    assert "autoswagger-0-0" in plan.tasks
    assert "rate_limit_validator-0-1" in plan.tasks
    assert "shannon-0-2" in plan.tasks


def test_generate_plan_routes_subfinder_for_bare_domain(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"shannon": {"enabled": True, "verify_availability": False}}), encoding="utf-8")
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = planner.generate_plan(scope_graph, scope_policy, None)

    assert "subfinder-0-0" in plan.tasks
    assert "zypheron-0-1" in plan.tasks


def test_generate_plan_routes_browser_for_web_targets(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"shannon": {"enabled": True, "verify_availability": False}}), encoding="utf-8")
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = planner.generate_plan(scope_graph, scope_policy, None)

    assert "browser-0-1" in plan.tasks


def test_generate_plan_skips_shannon_when_backend_is_unavailable(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"shannon": {"enabled": True}}), encoding="utf-8")
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))
    monkeypatch.setattr(planner, "_shannon_is_available", lambda _config: False)

    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = planner.generate_plan(scope_graph, scope_policy, None)

    assert "strix-0-0" in plan.tasks
    assert "browser-0-1" in plan.tasks
    assert not any(task.tool == "shannon" for task in plan.tasks.values())

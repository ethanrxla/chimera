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

    assert "strix-scan-0" in plan.tasks
    assert "shannon-verify-0" in plan.tasks
    assert "shannon-verify-0" in plan.graph["strix-scan-0"]

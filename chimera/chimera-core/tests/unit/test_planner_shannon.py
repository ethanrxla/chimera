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
    assert plan.stages == [
        "pre_reconnaissance",
        "reconnaissance",
        "vulnerability_analysis",
        "exploitation",
        "reporting",
    ]


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
    assert plan.metadata["targets"]["https://www.example.com"]["capability_sequence"] == [
        "strix",
        "zap",
        "hexstrike",
        "browser",
        "shannon",
    ]


def test_generate_plan_routes_zap_for_web_targets(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"shannon": {"enabled": True, "verify_availability": False}}), encoding="utf-8")
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = planner.generate_plan(scope_graph, scope_policy, None)

    assert "zap-0-2" in plan.tasks
    assert "hexstrike-0-3" in plan.tasks
    assert "subfinder-0-4" in plan.tasks
    assert "shannon-0-5" in plan.tasks
    assert "zap-0-2" in plan.graph["strix-0-0"]
    assert "hexstrike-0-3" in plan.graph["strix-0-0"]
    assert "subfinder-0-4" in plan.graph["strix-0-0"]
    assert "shannon-0-5" in plan.graph["browser-0-1"]
    assert "shannon-0-5" in plan.graph["zap-0-2"]
    assert "shannon-0-5" in plan.graph["hexstrike-0-3"]
    assert "shannon-0-5" in plan.graph["subfinder-0-4"]


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
    assert "zap-0-1" in plan.tasks
    assert "hexstrike-0-2" in plan.tasks
    assert "browser-0-3" in plan.tasks
    assert not any(task.tool == "shannon" for task in plan.tasks.values())


def test_generate_plan_builds_autonomous_web_phases(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "shannon": {
                    "enabled": True,
                    "verify_availability": False,
                    "autonomous": {
                        "enabled": True,
                        "provider_preset": "nvidia_nim",
                        "model": "meta/llama-4-maverick-17b-128e-instruct",
                        "base_url": "https://integrate.api.nvidia.com/v1",
                        "max_turns": 80,
                        "max_tool_calls": 14,
                        "max_retries": 2,
                        "reasoning_effort": "medium",
                        "repo_path": "/tmp/repo",
                        "browser_session_mode": "mediated",
                        "zap_mcp_enabled": True,
                        "role_assignments": {
                            "exploit": {
                                "provider_preset": "anthropic",
                                "model": "claude-sonnet-4-20250514",
                                "base_url": "",
                                "max_turns": 120,
                            },
                            "report": {
                                "provider_preset": "ollama",
                                "model": "qwen2.5-coder:7b",
                                "base_url": "http://ollama:11434/v1",
                                "max_turns": 20,
                            },
                        },
                    },
                },
                "pipeline": {"strategy": "phased_autonomous"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = planner.generate_plan(scope_graph, scope_policy, None)

    analysis_tasks = [
        task for task in plan.tasks.values()
        if task.tool == "shannon" and task.options.get("agent_role") == "analysis"
    ]
    exploit_tasks = [
        task for task in plan.tasks.values()
        if task.tool == "shannon" and task.options.get("agent_role") == "exploit"
    ]

    assert plan.stages == [
        "pre_reconnaissance",
        "reconnaissance",
        "vulnerability_analysis",
        "exploitation",
        "reporting",
    ]
    assert plan.tasks["strix-0-0"].stage == "pre_reconnaissance"
    assert plan.tasks["browser-0-1"].stage == "reconnaissance"
    assert plan.tasks["zap-0-2"].stage == "reconnaissance"
    assert plan.tasks["hexstrike-0-3"].stage == "reconnaissance"
    assert plan.tasks["subfinder-0-4"].stage == "reconnaissance"
    assert len(analysis_tasks) == 7
    assert len(exploit_tasks) == 7
    assert sorted(task.options.get("analysis_domain") for task in analysis_tasks) == [
        "auth",
        "authz",
        "business",
        "injection",
        "ssrf",
        "upload",
        "xss",
    ]
    assert sorted(task.options.get("analysis_domain") for task in exploit_tasks) == [
        "auth",
        "authz",
        "business",
        "injection",
        "ssrf",
        "upload",
        "xss",
    ]
    report_tasks = [
        task for task in plan.tasks.values()
        if task.tool == "shannon" and task.options.get("agent_role") == "report"
    ]
    assert len(report_tasks) == 1
    assert all(task.options.get("shannon_runtime") == "autonomous" for task in analysis_tasks + exploit_tasks + report_tasks)
    assert all(task.options.get("agent_flow") is not True for task in analysis_tasks + exploit_tasks + report_tasks)
    assert all(task.options.get("live") is True for task in analysis_tasks + exploit_tasks + report_tasks)
    assert all(task.options.get("mode") == "investigate" for task in analysis_tasks)
    assert all(task.options.get("mode") == "exploit" for task in exploit_tasks)
    assert all(task.options.get("mode") == "report" for task in report_tasks)
    assert all(task.options.get("provider_preset") == "nvidia_nim" for task in analysis_tasks)
    assert all(task.options.get("llm_provider") == "nvidia_nim" for task in analysis_tasks)
    assert all(task.options.get("model") == "meta/llama-4-maverick-17b-128e-instruct" for task in analysis_tasks)
    assert all(task.options.get("max_turns") == 80 for task in analysis_tasks)
    assert all(task.options.get("max_tool_calls") == 14 for task in analysis_tasks)
    assert all(task.options.get("max_retries") == 2 for task in analysis_tasks)
    assert all(task.options.get("reasoning_effort") == "medium" for task in analysis_tasks)
    assert all(task.options.get("provider_base_url") == "https://integrate.api.nvidia.com/v1" for task in analysis_tasks)
    assert all(task.options.get("repo_path") == "/tmp/repo" for task in analysis_tasks)
    assert all(task.options.get("browser_session_mode") == "mediated" for task in analysis_tasks)
    assert all(task.options.get("zap_mcp_enabled") is True for task in analysis_tasks)
    assert all(task.options.get("provider_preset") == "anthropic" for task in exploit_tasks)
    assert all(task.options.get("llm_provider") == "anthropic" for task in exploit_tasks)
    assert all(task.options.get("model") == "claude-sonnet-4-20250514" for task in exploit_tasks)
    assert all(task.options.get("max_turns") == 120 for task in exploit_tasks)
    assert all(task.options.get("provider_preset") == "ollama" for task in report_tasks)
    assert all(task.options.get("provider_base_url") == "http://ollama:11434/v1" for task in report_tasks)
    assert all(task.options.get("max_turns") == 20 for task in report_tasks)


def test_generate_plan_skips_autonomous_phases_when_disabled(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "shannon": {
                    "enabled": True,
                    "verify_availability": False,
                    "autonomous": {"enabled": False},
                },
                "pipeline": {"strategy": "phased_autonomous"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CHIMERA_CONFIG", str(config_path))

    scope_manifest = {"allowlist": ["https://www.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    plan = planner.generate_plan(scope_graph, scope_policy, None)

    browser_tasks = [task for task in plan.tasks.values() if task.tool == "browser"]
    zap_tasks = [task for task in plan.tasks.values() if task.tool == "zap"]
    hexstrike_tasks = [task for task in plan.tasks.values() if task.tool == "hexstrike"]
    shannon_tasks = [task for task in plan.tasks.values() if task.tool == "shannon"]

    assert len(browser_tasks) == 1
    assert len(zap_tasks) == 1
    assert len(hexstrike_tasks) == 1
    assert len(shannon_tasks) == 1
    assert all(task.options.get("shannon_runtime") != "autonomous" for task in shannon_tasks)
    assert all(task.options.get("mode") != "investigate" for task in shannon_tasks)

import asyncio
import json
import os
from unittest.mock import patch
from pathlib import Path

from test_shannon_robustness import _reload_main


def test_health_exposes_oracle_configuration() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_ORACLE_PROVIDER": "openai",
            "SHANNON_ORACLE_MODEL": "gpt-5.4",
            "SHANNON_ORACLE_REASONING": "medium",
            "SHANNON_ANTHROPIC_PROMPT_CACHING": "true",
            "SHANNON_ANTHROPIC_CACHE_TTL": "1h",
            "SHANNON_BROWSER_HEADLESS": "false",
            "SHANNON_BROWSER_DEVTOOLS": "true",
            "SHANNON_BROWSER_SLOW_MO_MS": "250",
        }
    )

    response = module.health()

    assert response["oracle"]["enabled"] is True
    assert response["oracle"]["provider"] == "openai"
    assert response["oracle"]["provider_preset"] == "openai"
    assert response["oracle"]["provider_family"] == "openai_compatible"
    assert response["oracle"]["model"] == "gpt-5.4"
    assert response["oracle"]["reasoning"] == "medium"
    assert response["browser_tools"]["headless"] is False
    assert response["browser_tools"]["devtools"] is True
    assert response["browser_tools"]["slow_mo_ms"] == 250
    assert response["local_hypotheses"]["enabled"] is True
    assert response["agent_compaction"]["threshold"] == 6
    assert response["agent_compaction"]["keep_recent_turns"] == 2
    assert response["autonomous_agent"]["request_schema"] == "shannon.agent_request.v1"
    assert response["autonomous_agent"]["result_schema"] == "shannon.agent_result.v1"
    assert response["autonomous_agent"]["defaults"]["max_turns"] == 6
    assert response["autonomous_agent"]["defaults"]["max_tool_calls"] == 12
    assert response["oracle"]["prompt_caching"]["enabled"] is False
    assert response["autonomous_agent"]["prompt_caching"]["ttl"] is None


def test_resolve_provider_runtime_supports_nvidia_nim_preset() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_ORACLE_PROVIDER": "nvidia_nim",
            "NVIDIA_API_KEY": "nvapi-test",
        }
    )

    with patch.dict(os.environ, {"NVIDIA_API_KEY": "nvapi-test"}, clear=False):
        runtime = module._resolve_provider_runtime("nvidia_nim", max_turns=9)

    assert runtime["preset"] == "nvidia_nim"
    assert runtime["family"] == "openai_compatible"
    assert runtime["base_url"] == "https://integrate.api.nvidia.com/v1"
    assert runtime["api_key"] == "nvapi-test"
    assert runtime["max_turns"] == 9


def test_oracle_system_prompt_composes_role_scope_and_context(tmp_path: Path) -> None:
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()
    (prompt_dir / "xss.txt").write_text("You are the XSS domain specialist.", encoding="utf-8")

    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_PROMPT_DIR": str(prompt_dir),
        }
    )

    req = module.AgentRequest(
        **{
            "run_id": "run-prompt",
            "mode": "investigate",
            "agent_role": "analysis",
            "analysis_domain": "xss",
            "intent": "Investigate reflected XSS",
            "targets": ["https://example.com"],
            "scope_summary": {"allowlist": ["https://example.com"], "denylist": ["https://admin.example.com"]},
        }
    )

    prompt = module._oracle_system_prompt(
        req,
        prior_findings=[{"title": "Search reflection", "severity": "medium", "affected_target": "https://example.com/search"}],
        local_hypotheses=[{"title": "DOM sink in search results", "success_condition": "Observe HTML execution in rendered results"}],
    )

    assert "Agent role: analysis" in prompt
    assert "Analysis domain: xss" in prompt
    assert "You are the XSS domain specialist." in prompt
    assert "Scope Summary:" in prompt
    assert "Prior Findings:" in prompt
    assert "Local Hypotheses:" in prompt
    assert "Search reflection" in prompt
    assert "DOM sink in search results" in prompt


def test_prompt_filename_selection_covers_roles_and_domains() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    recon_req = module.AgentRequest(run_id="r1", mode="recon", intent="map", targets=["https://example.com"])
    report_req = module.AgentRequest(run_id="r2", mode="report", intent="summarize", targets=["https://example.com"])
    injection_req = module.AgentRequest(
        run_id="r3",
        mode="investigate",
        agent_role="analysis",
        analysis_domain="injection",
        intent="test injection",
        targets=["https://example.com"],
    )
    exploit_req = module.AgentRequest(
        run_id="r4",
        mode="exploit",
        analysis_domain="ssrf",
        intent="test ssrf",
        targets=["https://example.com"],
    )

    assert module._prompt_filename_for_request(recon_req) == "recon.txt"
    assert module._prompt_filename_for_request(report_req) == "report.txt"
    assert module._prompt_filename_for_request(injection_req) == "injection.txt"
    assert module._prompt_filename_for_request(exploit_req) == "ssrf.txt"


def test_prompt_pack_files_load_expected_specialist_language() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    expectations = {
        "recon": "reconnaissance specialist",
        "injection": "injection specialist",
        "xss": "XSS specialist",
        "auth": "authentication specialist",
        "authz": "authorization specialist",
        "ssrf": "SSRF specialist",
        "report": "reporting specialist",
    }

    for domain, phrase in expectations.items():
        req = module.AgentRequest(
            run_id=f"run-{domain}",
            mode="report" if domain == "report" else ("recon" if domain == "recon" else "investigate"),
            agent_role="report" if domain == "report" else ("recon" if domain == "recon" else "analysis"),
            analysis_domain=None if domain in {"report", "recon"} else domain,
            intent="test",
            targets=["https://example.com"],
        )
        prompt = module._load_role_prompt(req)
        assert phrase in prompt
        assert "Handoff contract:" in prompt or "Output contract:" in prompt or "Rules:" in prompt


def test_oracle_system_prompt_uses_report_prompt_for_report_role() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    req = module.AgentRequest(
        run_id="run-report",
        mode="report",
        intent="Summarize findings",
        targets=["https://example.com"],
        scope_summary={"allowlist": ["https://example.com"]},
    )

    prompt = module._oracle_system_prompt(req, prior_findings=[], local_hypotheses=[])

    assert "Agent role: report" in prompt
    assert "reporting specialist" in prompt
    assert "Output contract:" in prompt


def test_oracle_prompt_bundle_marks_stable_cacheable_blocks_for_anthropic() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_ORACLE_PROVIDER": "anthropic",
            "SHANNON_ANTHROPIC_PROMPT_CACHING": "true",
            "SHANNON_ANTHROPIC_CACHE_TTL": "1h",
        }
    )

    req = module.AgentRequest(
        run_id="run-bundle",
        mode="investigate",
        agent_role="analysis",
        analysis_domain="xss",
        intent="Investigate reflected XSS",
        targets=["https://example.com"],
        scope_summary={"allowlist": ["https://example.com"]},
    )

    bundle = module._oracle_prompt_bundle(
        req,
        prior_findings=[{"title": "Search reflection"}],
        local_hypotheses=[{"title": "DOM sink in search results"}],
        prompt_caching_enabled=True,
        prompt_cache_ttl="1h",
    )

    blocks = bundle["system_prompt_blocks"]
    assert bundle["schema"] == "shannon.prompt_bundle.v1"
    assert bundle["cache"]["enabled"] is True
    assert bundle["cache"]["ttl"] == "1h"
    assert any(block["name"] == "role_prompt" and block["cacheable"] for block in blocks)
    assert any(block["name"] == "scope_summary" and not block["cacheable"] for block in blocks)
    assert bundle["cache"]["stable_block_count"] >= bundle["cache"]["cacheable_block_count"] >= 1
    assert "Investigate reflected XSS" not in bundle["system_prompt"]


def test_prompt_pack_contains_expected_files_and_sections() -> None:
    prompt_dir = Path(__file__).resolve().parent.parent / "prompts"
    expected = {"recon.txt", "injection.txt", "xss.txt", "auth.txt", "authz.txt", "ssrf.txt", "report.txt"}

    present = {path.name for path in prompt_dir.glob("*.txt")}

    assert expected.issubset(present)
    for filename in expected:
        content = (prompt_dir / filename).read_text(encoding="utf-8")
        assert "Goals:" in content
        assert "Workflow:" in content
        assert "Rules:" in content


def test_resolve_agent_runtime_honors_request_provider_override() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_ORACLE_PROVIDER": "openai",
            "SHANNON_ORACLE_MODEL": "gpt-5.4",
        }
    )

    req = module.AgentRequest(
        run_id="run-ollama",
        mode="investigate",
        intent="Use local preset",
        targets=["https://example.com"],
        provider_preset="ollama",
        budget={"max_turns": 11},
    )

    runtime = module._resolve_agent_runtime(req)

    assert runtime["preset"] == "ollama"
    assert runtime["family"] == "openai_compatible"
    assert runtime["base_url"] == "http://ollama:11434/v1"
    assert runtime["model"] == "qwen2.5-coder:7b"
    assert runtime["api_key"] == "ollama"
    assert runtime["max_turns"] == 11


def test_oracle_tool_registry_role_gates_recon_and_exploit_tools() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible", "SHANNON_ORACLE_ENABLED": "true"})
    registry = __import__("tool_registry")

    recon_tools = {tool["name"] for tool in registry.get_oracle_tools(agent_role="recon")}
    exploit_tools = {tool["name"] for tool in registry.get_oracle_tools(agent_role="exploit", analysis_domain="injection")}
    report_tools = {tool["name"] for tool in registry.get_oracle_tools(agent_role="report")}

    assert "hexstrike_recon" in recon_tools
    assert "hexstrike_endpoints" in recon_tools
    assert "hexstrike_exploit" not in recon_tools
    assert "hexstrike_nuclei" not in recon_tools

    assert "hexstrike_probe" in exploit_tools
    assert "hexstrike_exploit" in exploit_tools
    assert "hexstrike_nuclei" in exploit_tools
    assert "hexstrike_ffuf" in exploit_tools

    assert report_tools == {"read_artifact"}


def test_oracle_tool_registry_domain_adds_specialist_tools() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible", "SHANNON_ORACLE_ENABLED": "true"})
    registry = __import__("tool_registry")

    xss_tools = {tool["name"] for tool in registry.get_oracle_tools(agent_role="analysis", analysis_domain="xss")}
    auth_tools = {tool["name"] for tool in registry.get_oracle_tools(agent_role="analysis", analysis_domain="auth")}

    assert "hexstrike_dalfox" in xss_tools
    assert "hexstrike_jwt_analyzer" not in xss_tools
    assert "hexstrike_jwt_analyzer" in auth_tools
    assert "hexstrike_dalfox" not in auth_tools


def test_oracle_tool_registry_exposes_source_tools_for_analysis() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible", "SHANNON_ORACLE_ENABLED": "true"})
    registry = __import__("tool_registry")

    analysis_tools = {tool["name"] for tool in registry.get_oracle_tools(agent_role="analysis", analysis_domain="injection")}
    report_tools = {tool["name"] for tool in registry.get_oracle_tools(agent_role="report")}

    assert {"list_source_files", "search_source_code", "read_source_file"}.issubset(analysis_tools)
    assert "read_source_file" not in report_tools


def test_oracle_tool_registry_exposes_observable_browser_and_terminal_tools_for_analysis() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible", "SHANNON_ORACLE_ENABLED": "true"})
    registry = __import__("tool_registry")

    analysis_tools = {tool["name"] for tool in registry.get_oracle_tools(agent_role="analysis", analysis_domain="authz")}

    assert {
        "browser_click",
        "browser_fill",
        "browser_execute_js",
        "browser_get_console",
        "browser_get_network",
        "terminal_start",
        "terminal_write",
        "terminal_read",
    }.issubset(analysis_tools)


def test_oracle_tool_registry_exposes_zap_tools_for_recon() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible", "SHANNON_ORACLE_ENABLED": "true"})
    registry = __import__("tool_registry")

    recon_tools = {tool["name"] for tool in registry.get_oracle_tools(agent_role="recon")}

    assert {"zap_get_sites", "zap_spider", "zap_list_alerts"}.issubset(recon_tools)


def test_agent_endpoint_returns_structured_agent_result() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_ORACLE_PROVIDER": "openai",
            "SHANNON_ORACLE_MODEL": "gpt-5.4",
        }
    )

    with patch.object(
        module,
        "_run_agent_mode",
        return_value={
            "status": "completed",
            "agent_trace_ref": "artifacts/run-1/shannon/agent-trace.json",
            "tool_call_refs": ["artifacts/run-1/shannon/tool-call-1.json"],
            "new_candidates": [
                {
                    "title": "Open Redirect on /login",
                    "claim_type": "open_redirect",
                    "target": "https://example.com/login",
                }
            ],
            "evidence_refs": ["artifacts/run-1/shannon/tool-call-1.json"],
            "validator_handoff": {"recommended_mode": "typed_verify", "candidate_ids": ["cand-1"]},
            "usage": {"total_tokens": 42},
        },
    ):
        response = asyncio.run(
            module.agent_mode(
                module.AgentRequest(
                    **{
                        "run_id": "run-1",
                        "mode": "investigate",
                        "intent": "Investigate auth bypass on /login",
                        "targets": ["https://example.com"],
                        "candidate": None,
                        "prior_findings": [],
                        "prior_evidence_refs": [],
                        "scope_summary": {"allowlist": ["example.com"]},
                        "budget": {"max_turns": 4, "max_tool_calls": 6},
                    }
                )
            )
        )

    assert response["status"] == "completed"
    assert response["task_id"]
    assert response["schema"] == "shannon.agent_result.v1"
    assert response["request"]["schema"] == "shannon.agent_request.v1"
    assert response["validator_handoff"]["recommended_mode"] == "typed_verify"
    assert response["new_candidates"][0]["claim_type"] == "open_redirect"
    assert response["artifacts"]["task_state_ref"] == response["task_state_ref"]
    assert module._tasks[response["task_id"]]["status"] == "completed"
    assert module._tasks[response["task_id"]]["schema"] == "shannon.agent_result.v1"
    assert module._tasks[response["task_id"]]["request"]["schema"] == "shannon.agent_request.v1"
    assert module._tasks[response["task_id"]]["task_state_ref"]


def test_agent_mode_persists_compaction_refs_in_task_state(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    async def fake_loop(**kwargs):
        kwargs["persist_compaction"](
            {
                "type": "context_compaction",
                "start_turn": 1,
                "end_turn": 3,
                "turn_count": 3,
                "summary": "Turn 1 tool call: hexstrike_endpoints",
                "kept_recent_turns": 2,
            }
        )
        return {
            "output_text": "done",
            "tool_results": [{"tool_name": "hexstrike_probe", "arguments": {"endpoint": "https://example.com/login"}, "result": {"status": "ok"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }

    with (
        patch.object(module, "run_responses_tool_loop", side_effect=fake_loop),
        patch.object(module, "_resolve_prior_context", return_value={"prior_findings": [], "prior_evidence_refs": [], "context_run_id": None, "context_source": "none"}),
        patch.object(module, "_generate_local_hypotheses", return_value={"status": "completed", "findings": [], "checks": [], "usage": {}}),
        patch.object(module, "_ensure_browser_session", return_value=(None, False, None)),
    ):
        response = asyncio.run(
            module._run_agent_mode(
                module.AgentRequest(
                    **{
                        "run_id": "run-compaction",
                        "mode": "investigate",
                        "intent": "Inspect auth",
                        "targets": ["https://example.com"],
                        "prior_findings": [],
                        "prior_evidence_refs": [],
                        "scope_summary": {"allowlist": ["https://example.com"]},
                        "budget": {"max_turns": 4},
                    }
                )
            )
        )

    assert response["compaction_refs"]
    state = module._tasks[response["task_id"]]
    assert state["compaction_refs"] == response["compaction_refs"]
    assert Path(response["compaction_refs"][0]).exists()


def test_agent_mode_uses_persisted_tool_artifact_refs_for_evidence(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    async def fake_loop(**kwargs):
        wrapped = module._wrap_oracle_tool_result(
            req=module.AgentRequest(
                run_id="run-evidence",
                mode="investigate",
                intent="Inspect authz",
                targets=["https://example.com"],
            ),
            task_id="agent-evidence",
            tool_name="browser_capture_dom",
            call_index=1,
            arguments={"url": "https://example.com/app"},
            result={"url": "https://example.com/app", "status_code": 200, "title": "App"},
        )
        return {
            "output_text": "done",
            "tool_results": [wrapped],
            "usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11},
        }

    with (
        patch.object(module, "run_responses_tool_loop", side_effect=fake_loop),
        patch.object(module, "_resolve_prior_context", return_value={"prior_findings": [], "prior_evidence_refs": [], "context_run_id": None, "context_source": "none"}),
        patch.object(module, "_generate_local_hypotheses", return_value={"status": "completed", "local_hypotheses": [], "usage": {}, "error": None}),
        patch.object(module, "_ensure_browser_session", return_value=(None, False, None)),
    ):
        response = asyncio.run(
            module._run_agent_mode(
                module.AgentRequest(
                    run_id="run-evidence",
                    mode="investigate",
                    intent="Inspect authz",
                    targets=["https://example.com"],
                    scope_summary={"allowlist": ["https://example.com"]},
                )
            )
        )

    artifact_ref = response["tool_call_refs"][0]
    assert artifact_ref == response["evidence_refs"][0]
    assert artifact_ref.endswith("tool_call_01_browser_capture_dom.json")
    assert Path(artifact_ref).exists()
    assert response["new_candidates"] == []


def test_wrap_oracle_tool_result_persists_standard_artifact_contract(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    req = module.AgentRequest(
        **{
            "run_id": "run-artifact",
            "mode": "investigate",
            "agent_role": "analysis",
            "analysis_domain": "xss",
            "intent": "Inspect tool artifact",
            "targets": ["https://example.com"],
        }
    )

    wrapped = module._wrap_oracle_tool_result(
        req=req,
        task_id="agent-artifact",
        tool_name="browser_capture_dom",
        call_index=2,
        arguments={"url": "https://example.com/search?q=test"},
        result={"url": "https://example.com/search?q=test", "status_code": 200, "title": "Search"},
    )

    assert wrapped["schema"] == "shannon.oracle_tool_result.v1"
    assert wrapped["tool_name"] == "browser_capture_dom"
    assert wrapped["call_index"] == 2
    payload = json.loads(Path(wrapped["artifact_ref"]).read_text(encoding="utf-8"))
    assert payload["schema"] == "shannon.oracle_tool_result.v1"
    assert payload["run_id"] == "run-artifact"
    assert payload["task_id"] == "agent-artifact"
    assert payload["agent_role"] == "analysis"
    assert payload["analysis_domain"] == "xss"
    assert payload["tool_name"] == "browser_capture_dom"
    assert payload["call_index"] == 2
    assert payload["tool_family"] == "local"
    assert payload["summary"]["status_code"] == 200


def test_oracle_tool_handlers_follow_role_gated_registry() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    req = module.AgentRequest(
        run_id="run-report-tools",
        mode="report",
        intent="Summarize artifacts",
        targets=["https://example.com"],
    )

    handlers = module._oracle_tool_handlers(req, task_id="agent-report")

    assert set(handlers) == {"read_artifact"}


def test_source_tools_read_list_and_search_with_repo_root(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    source_dir = repo_root / "src" / "routes"
    source_dir.mkdir(parents=True)
    login_file = source_dir / "login.ts"
    login_file.write_text(
        "export const login = () => {\n"
        "  app.get('/login', handler)\n"
        "  return 'ok'\n"
        "}\n",
        encoding="utf-8",
    )

    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_SOURCE_REPO_ROOT": str(repo_root),
        }
    )

    req = module.AgentRequest(
        run_id="run-source",
        mode="investigate",
        intent="inspect source",
        targets=["https://example.com"],
    )

    listed = asyncio.run(module._list_source_files({"glob": "src/**/*.ts", "limit": 10}, req))
    searched = asyncio.run(module._search_source_code({"pattern": "app\\.get", "glob": "src/**/*.ts", "limit": 10}, req))
    read = asyncio.run(module._read_source_file({"path": "src/routes/login.ts", "start_line": 1, "end_line": 3}, req))

    assert listed["files"] == ["src/routes/login.ts"]
    assert searched["matches"][0]["path"] == "src/routes/login.ts"
    assert searched["matches"][0]["line"] == 2
    assert read["path"] == "src/routes/login.ts"
    assert "2:   app.get('/login', handler)" in read["excerpt"]


def test_source_tools_reject_path_escape(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_SOURCE_REPO_ROOT": str(repo_root),
        }
    )

    req = module.AgentRequest(
        run_id="run-source-escape",
        mode="investigate",
        intent="inspect source",
        targets=["https://example.com"],
    )

    try:
        asyncio.run(module._read_source_file({"path": "../etc/passwd"}, req))
        assert False, "expected path escape to fail"
    except ValueError as exc:
        assert "escapes source repo root" in str(exc)


def test_source_tools_request_repo_path_must_stay_within_configured_root(tmp_path: Path) -> None:
    configured_root = tmp_path / "allowed"
    configured_root.mkdir()
    outside_root = tmp_path / "outside"
    outside_root.mkdir()

    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_SOURCE_REPO_ROOT": str(configured_root),
        }
    )

    req = module.AgentRequest(
        run_id="run-source-outside",
        mode="investigate",
        intent="inspect source",
        targets=["https://example.com"],
        repo_path=str(outside_root),
    )

    try:
        asyncio.run(module._list_source_files({"glob": "**/*"}, req))
        assert False, "expected repo_path outside configured root to fail"
    except ValueError as exc:
        assert "outside configured source root" in str(exc)


def test_zap_get_sites_calls_core_after_policy_allow() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    req = module.AgentRequest(
        run_id="run-zap",
        mode="recon",
        intent="inspect zap",
        targets=["https://example.com"],
        scope_summary={"allowlist": ["https://example.com"]},
    )

    with (
        patch.object(module, "_evaluate_policy", return_value={"decision": "allow"}),
        patch.object(module, "_call_core_json", return_value={"target": "https://example.com", "sites": ["https://example.com"], "count": 1, "source": "zap_rest"}),
    ):
        result = asyncio.run(module._zap_get_sites({"target": "https://example.com"}, req))

    assert result["count"] == 1
    assert result["sites"] == ["https://example.com"]


def test_zap_spider_returns_policy_block_when_deferred() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    req = module.AgentRequest(
        run_id="run-zap-policy",
        mode="recon",
        intent="inspect zap",
        targets=["https://example.com"],
        scope_summary={"allowlist": ["https://example.com"]},
    )

    with patch.object(
        module,
        "_evaluate_policy",
        return_value={"decision": "defer", "reason": "approval required", "matched_rule": "defer-zap-active-scan", "require_approval_if_deferred": True},
    ):
        result = asyncio.run(module._zap_spider({"target": "https://example.com"}, req))

    assert result["error"] == "policy_deferred"


def test_tool_artifact_refs_extract_persisted_refs_only() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    refs = module._tool_artifact_refs(
        [
            {"tool_name": "browser_navigate", "artifact_ref": "/tmp/artifacts/tool_call_01.json"},
            {"tool_name": "browser_capture_dom", "artifact_ref": ""},
            {"tool_name": "shell_run_scoped"},
            "not-a-dict",
            {"tool_name": "read_artifact", "artifact_ref": "/tmp/artifacts/tool_call_02.json"},
        ]
    )

    assert refs == ["/tmp/artifacts/tool_call_01.json", "/tmp/artifacts/tool_call_02.json"]


def test_browser_tools_use_mediated_executor() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    calls = []

    async def fake_browser_executor(task):
        calls.append(task)
        return {"status": "ok", "url": "https://example.com"}

    module.BROWSER_TOOL_EXECUTOR = fake_browser_executor
    result = asyncio.run(module._browser_capture_dom({"url": "https://example.com"}, {"allowlist": ["example.com"]}))

    assert result["status"] == "ok"
    assert calls
    assert calls[0]["actions"][0]["type"] == "navigate"
    assert calls[0]["actions"][-1]["type"] == "extract_console"


def test_agent_browser_session_uses_chimera_mediator() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_BROWSER_EXECUTOR_MODE": "mediated",
            "CHIMERA_CORE_URL": "http://chimera-core:8000",
        }
    )

    calls = []

    class FakeMediator:
        async def execute(self, task, *, url=None):
            calls.append({"task": task, "url": url})
            return {"status": "ok", "url": "https://example.com/app"}

    req = module.AgentRequest(
        **{
            "run_id": "run-3",
            "mode": "investigate",
            "intent": "Inspect app",
            "targets": ["https://example.com"],
            "browser_session_id": "browser-session-1",
            "prior_findings": [],
            "prior_evidence_refs": [],
            "scope_summary": {"allowlist": ["example.com"]},
            "budget": {"max_turns": 2, "max_tool_calls": 2},
        }
    )

    with patch.object(module, "_browser_executor_for_request", return_value=FakeMediator()):
        handlers = module._oracle_tool_handlers(req, task_id="agent-1")
        result = asyncio.run(handlers["browser_capture_dom"]({}))

    assert result["status"] == "ok"
    assert result["artifact_ref"]
    assert result["summary"]["url"] == "https://example.com/app"
    assert calls
    assert calls[0]["url"] is None
    assert calls[0]["task"]["actions"][0]["type"] == "extract_dom"
    assert calls[0]["task"]["actions"][-1]["type"] == "extract_console"


def test_agent_browser_session_reads_console_and_network_from_chimera() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_BROWSER_EXECUTOR_MODE": "mediated",
        }
    )

    class FakeMediator:
        async def get_console(self, *, limit=200):
            return {"session": {"session_id": "browser-session-2"}, "count": 1, "console": [{"text": "ready"}], "artifact_ref": "console.json"}

        async def get_network(self, *, limit=200):
            return {"session": {"session_id": "browser-session-2"}, "count": 1, "network": [{"event": "response", "status": 200}], "artifact_ref": "network.json"}

    req = module.AgentRequest(
        run_id="run-4",
        mode="investigate",
        intent="Inspect browser session",
        targets=["https://example.com"],
        browser_session_id="browser-session-2",
        scope_summary={"allowlist": ["example.com"]},
    )

    with patch.object(module, "_browser_executor_for_request", return_value=FakeMediator()):
        handlers = module._oracle_tool_handlers(req, task_id="agent-2")
        console_result = asyncio.run(handlers["browser_get_console"]({"limit": 10}))
        network_result = asyncio.run(handlers["browser_get_network"]({"limit": 10}))

    assert console_result["summary"]["count"] == 1
    assert console_result["summary"]["artifact_ref"] == "console.json"
    assert network_result["summary"]["count"] == 1
    assert network_result["summary"]["artifact_ref"] == "network.json"


def test_agent_terminal_tools_use_chimera_terminal_mediator() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    class FakeTerminalMediator:
        async def start(self, **kwargs):
            return {"session_id": "term-1", "command": kwargs["command"], "transcript_artifact_ref": "transcript.jsonl", "status": "running"}

        async def write(self, session_id, *, data):
            return {"session_id": session_id, "bytes_written": len(data), "artifact_ref": "transcript.jsonl"}

        async def read(self, session_id, *, max_bytes=8192, timeout_ms=50):
            return {"session_id": session_id, "output": "pwd\n/home/chimera\n", "bytes_read": 18, "artifact_ref": "transcript.jsonl"}

    req = module.AgentRequest(
        run_id="run-5",
        mode="investigate",
        intent="Inspect terminal mediation",
        targets=["https://example.com"],
        scope_summary={"allowlist": ["example.com"]},
    )

    with patch.object(module, "_terminal_mediator", return_value=FakeTerminalMediator()):
        handlers = module._oracle_tool_handlers(req, task_id="agent-3")
        start_result = asyncio.run(handlers["terminal_start"]({"command": ["bash"]}))
        write_result = asyncio.run(handlers["terminal_write"]({"session_id": "term-1", "data": "pwd\n"}))
        read_result = asyncio.run(handlers["terminal_read"]({"session_id": "term-1"}))

    assert start_result["summary"]["terminal_session_id"] == "term-1"
    assert start_result["summary"]["status"] == "running"
    assert write_result["summary"]["bytes_written"] == 4
    assert "pwd" in read_result["summary"]["output"]


def test_read_artifact_handler_reads_current_run_artifact(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    payload_ref = module._persist_agent_payload("agent-7", "run-7", "sample.json", {"summary": {"value": "ok"}})
    req = module.AgentRequest(
        **{
            "run_id": "run-7",
            "mode": "investigate",
            "intent": "Inspect artifacts",
            "targets": ["https://example.com"],
            "prior_findings": [],
            "prior_evidence_refs": [],
            "scope_summary": {"allowlist": ["example.com"]},
            "budget": {"max_turns": 1},
        }
    )

    result = asyncio.run(module._read_artifact({"artifact_ref": payload_ref, "json_path": "summary.value"}, req, task_id="agent-7"))

    assert result["kind"] == "json"
    assert result["excerpt"] == "ok"
    assert result["resolved_path"].endswith("sample.json")


def test_read_artifact_handler_accepts_jsonpath_root_selector(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    payload_ref = module._persist_agent_payload("agent-8", "run-8", "sample.json", {"summary": {"value": ["ok", "still-ok"]}})
    req = module.AgentRequest(
        **{
            "run_id": "run-8",
            "mode": "investigate",
            "intent": "Inspect artifacts",
            "targets": ["https://example.com"],
            "prior_findings": [],
            "prior_evidence_refs": [],
            "scope_summary": {"allowlist": ["example.com"]},
            "budget": {"max_turns": 1},
        }
    )

    result = asyncio.run(
        module._read_artifact(
            {"artifact_ref": payload_ref, "json_path": "$.summary.value[1]"},
            req,
            task_id="agent-8",
        )
    )

    assert result["kind"] == "json"
    assert result["excerpt"] == "still-ok"
    assert result["json_path"] == "$.summary.value[1]"


def test_read_artifact_handler_aliases_body_to_browser_page_source(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    payload_ref = module._persist_agent_payload(
        "agent-9",
        "run-9",
        "browser.json",
        {
            "schema": "shannon.oracle_tool_result.v1",
            "tool_name": "browser_navigate",
            "result": {"page_source": "<html><body>ok</body></html>"},
            "summary": {"url": "https://example.com/admin"},
        },
    )
    req = module.AgentRequest(
        **{
            "run_id": "run-9",
            "mode": "investigate",
            "intent": "Inspect browser artifacts",
            "targets": ["https://example.com"],
            "prior_findings": [],
            "prior_evidence_refs": [],
            "scope_summary": {"allowlist": ["example.com"]},
            "budget": {"max_turns": 1},
        }
    )

    result = asyncio.run(
        module._read_artifact(
            {"artifact_ref": payload_ref, "json_path": "$.body"},
            req,
            task_id="agent-9",
        )
    )

    assert result["excerpt"] == "<html><body>ok</body></html>"
    assert result["resolved_json_path"] == "$.result.page_source"


def test_read_artifact_handler_aliases_response_body_to_browser_page_source(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    payload_ref = module._persist_agent_payload(
        "agent-10",
        "run-10",
        "browser.json",
        {
            "schema": "shannon.oracle_tool_result.v1",
            "tool_name": "browser_navigate",
            "result": {"page_source": "<html><body>still-ok</body></html>"},
            "summary": {"url": "https://example.com/admin"},
        },
    )
    req = module.AgentRequest(
        **{
            "run_id": "run-10",
            "mode": "investigate",
            "intent": "Inspect browser artifacts",
            "targets": ["https://example.com"],
            "prior_findings": [],
            "prior_evidence_refs": [],
            "scope_summary": {"allowlist": ["example.com"]},
            "budget": {"max_turns": 1},
        }
    )

    result = asyncio.run(
        module._read_artifact(
            {"artifact_ref": payload_ref, "json_path": "$.response.body"},
            req,
            task_id="agent-10",
        )
    )

    assert result["excerpt"] == "<html><body>still-ok</body></html>"
    assert result["resolved_json_path"] == "$.result.page_source"


def test_prioritizes_high_yield_hypotheses_for_oracle() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    ranked = module._prioritize_records(
        [
            {"title": "Generic note", "severity": "low"},
            {"title": "Admin token leak on /rest/user/whoami", "severity": "high", "affected_target": "https://example.com/rest/user/whoami", "evidence_refs": ["one"]},
        ],
        intent="Investigate auth token exposure",
        targets=["https://example.com"],
        limit=1,
    )

    assert len(ranked) == 1
    assert ranked[0]["title"] == "Admin token leak on /rest/user/whoami"


def test_agent_scope_allows_url_with_port_when_host_is_allowlisted() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    module._ensure_agent_scope(
        {"url": "http://127.0.0.1:3000/#/login"},
        {"allowlist": ["127.0.0.1"]},
    )


def test_agent_scope_allows_full_url_with_port_in_allowlist() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    module._ensure_agent_scope(
        {"url": "http://juice-shop:3000/#/login"},
        {"allowlist": ["http://juice-shop:3000"]},
    )


def test_browser_tool_returns_scope_violation_instead_of_raising() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    result = asyncio.run(
        module._browser_navigate(
            {"url": "https://example.com"},
            {"allowlist": ["http://juice-shop:3000"]},
        )
    )

    assert result["error"] == "scope_violation"
    assert "out of scope target" in result["detail"]
    assert result["target"] == "https://example.com"


def test_agent_artifacts_persist_under_run_directory(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
        }
    )

    trace_ref = module._persist_agent_trace("agent-1", "run-1", {"status": "completed"})
    state_ref = module._persist_agent_task_state("agent-1", "run-1", {"status": "completed", "run_id": "run-1"})

    assert trace_ref.endswith("artifacts/run-1/shannon/agent/agent-1/agent_trace.json")
    assert state_ref.endswith("artifacts/run-1/shannon/agent/agent-1/task_state.json")
    assert Path(trace_ref).exists()
    assert Path(state_ref).exists()
    loaded = module._load_agent_task_state("agent-1")
    assert loaded is not None
    assert loaded["run_id"] == "run-1"


def test_agent_mode_resumes_from_persisted_checkpoint_state(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    local_ref = module._persist_agent_payload("agent-resume", "run-resume", "local_hypotheses.json", [{"title": "Stored hypothesis"}])
    module._persist_agent_task_state(
        "agent-resume",
        "run-resume",
        {
            "status": "running",
            "run_id": "run-resume",
            "browser_session_id": "browser-session-7",
            "browser_session_created": True,
            "local_hypotheses_ref": local_ref,
            "local_hypothesis_status": "completed",
            "local_hypothesis_error": None,
            "compaction_refs": ["artifact-1"],
            "checkpoint": {
                "status": "running",
                "attempt": 1,
                "turn_count": 1,
                "tool_result_count": 1,
                "turns": [
                    {
                        "assistant_text": "calling hexstrike_probe",
                        "tool_calls": [{"call_id": "call-1", "name": "hexstrike_probe", "arguments": {"endpoint": "https://example.com/login"}}],
                        "tool_results": [{"tool_name": "hexstrike_probe", "call_id": "call-1", "output": "{\"status\":200}", "result": {"status": 200}}],
                    }
                ],
                "compactions": [{"start_turn": 1, "end_turn": 1, "turn_count": 1, "summary": "Turn 1", "artifact_ref": "artifact-1"}],
                "compaction_refs": ["artifact-1"],
                "tool_results": [{"tool_name": "hexstrike_probe", "arguments": {"endpoint": "https://example.com/login"}, "result": {"status": 200}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                "last_output_text": "partial",
            },
        },
    )

    captured = {}

    async def fake_loop(**kwargs):
        captured["initial_turns"] = kwargs.get("initial_turns")
        captured["initial_compactions"] = kwargs.get("initial_compactions")
        captured["initial_tool_results"] = kwargs.get("initial_tool_results")
        captured["initial_usage"] = kwargs.get("initial_usage")
        kwargs["persist_checkpoint"](
            {
                "status": "running",
                "turn_count": 2,
                "tool_result_count": 1,
                "turns": list(kwargs.get("initial_turns") or []),
                "compactions": list(kwargs.get("initial_compactions") or []),
                "tool_results": list(kwargs.get("initial_tool_results") or []),
                "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
                "last_output_text": "resuming",
            }
        )
        return {
            "output_text": "done",
            "tool_results": list(kwargs.get("initial_tool_results") or []),
            "turns": list(kwargs.get("initial_turns") or []),
            "compactions": list(kwargs.get("initial_compactions") or []),
            "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
        }

    with (
        patch.object(module, "run_responses_tool_loop", side_effect=fake_loop),
        patch.object(module, "_resolve_prior_context", return_value={"prior_findings": [], "prior_evidence_refs": [], "context_run_id": None, "context_source": "none"}),
        patch.object(module, "_generate_local_hypotheses", side_effect=AssertionError("should not regenerate local hypotheses on resume")),
    ):
        response = asyncio.run(
            module._run_agent_mode(
                module.AgentRequest(
                    run_id="run-resume",
                    mode="investigate",
                    intent="Resume investigation",
                    targets=["https://example.com"],
                    resume_task_id="agent-resume",
                    scope_summary={"allowlist": ["https://example.com"]},
                )
            )
        )

    assert response["task_id"] == "agent-resume"
    assert captured["initial_turns"][0]["assistant_text"] == "calling hexstrike_probe"
    assert captured["initial_compactions"][0]["artifact_ref"] == "artifact-1"
    assert captured["initial_tool_results"][0]["tool_name"] == "hexstrike_probe"
    assert captured["initial_usage"]["total_tokens"] == 15
    assert response["browser_session_id"] == "browser-session-7"
    assert response["local_hypotheses_ref"] == local_ref
    assert module._tasks["agent-resume"]["checkpoint"]["status"] == "completed"


def test_get_agent_task_loads_persisted_checkpoint_state_after_cache_clear(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    state_ref = module._persist_agent_task_state(
        "agent-status",
        "run-status",
        {
            "schema": "shannon.autonomous_agent_result.v1",
            "status": "running",
            "run_id": "run-status",
            "request": {
                "schema": "shannon.agent_request.v1",
                "mode": "investigate",
                "intent": "Continue authz review",
                "targets": ["https://example.com"],
                "resume_task_id": None,
            },
            "checkpoint": {
                "status": "running",
                "attempt": 2,
                "turn_count": 3,
                "tool_result_count": 2,
                "last_output_text": "partial authz analysis",
            },
            "compaction_refs": ["artifact-1"],
            "task_state_ref": "placeholder",
        },
    )

    module._tasks.clear()
    response = module.get_agent_task("agent-status")

    assert response["task_id"] == "agent-status"
    assert response["status"] == "running"
    assert response["run_id"] == "run-status"
    assert response["checkpoint"]["attempt"] == 2
    assert response["checkpoint"]["turn_count"] == 3
    assert response["request"]["intent"] == "Continue authz review"
    assert state_ref.endswith("task_state.json")


def test_resolve_prior_context_loads_matching_run_findings(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    run_dir = tmp_path / "artifacts" / "run-juice"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "run_id": "run-juice",
                "status": "completed",
                "scope_normalized": {"allowlist": ["http://juice-shop:3000"], "denylist": []},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "findings.json").write_text(
        json.dumps(
            [
                {
                    "finding_id": "f-1",
                    "title": "Open Redirect",
                    "severity": "medium",
                    "description": "Potential redirect issue",
                    "tool_source": "strix",
                    "tool_version": "strix-1.0.0",
                    "affected_target": "http://juice-shop:3000/redirect",
                    "evidence_refs": ["artifacts/run-juice/strix/findings/f-1.md"],
                    "confidence": 0.7,
                }
            ]
        ),
        encoding="utf-8",
    )

    req = module.AgentRequest(
        **{
            "run_id": "missing-run",
            "mode": "investigate",
            "intent": "Investigate Juice Shop",
            "targets": ["http://juice-shop:3000"],
            "scope_summary": {"allowlist": ["http://juice-shop:3000"]},
        }
    )

    context = module._resolve_prior_context(req)

    assert context["context_run_id"] == "run-juice"
    assert context["context_source"] == "latest_target_match"
    assert len(context["prior_findings"]) == 1
    assert context["prior_findings"][0]["tool_source"] == "strix"


def test_resolve_prior_context_prefers_strix_backed_run(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    artifacts_root = tmp_path / "artifacts"
    strix_run = artifacts_root / "run-strix"
    browser_run = artifacts_root / "run-browser"
    strix_run.mkdir(parents=True)
    browser_run.mkdir(parents=True)

    run_payload = {
        "status": "completed",
        "scope_normalized": {"allowlist": ["http://juice-shop:3000"], "denylist": []},
    }
    (strix_run / "run.json").write_text(json.dumps({"run_id": "run-strix", **run_payload}), encoding="utf-8")
    (browser_run / "run.json").write_text(json.dumps({"run_id": "run-browser", **run_payload}), encoding="utf-8")
    (strix_run / "findings.json").write_text(
        json.dumps([{"finding_id": "f-1", "title": "Open Redirect", "tool_source": "strix", "affected_target": "http://juice-shop:3000"}]),
        encoding="utf-8",
    )
    (browser_run / "findings.json").write_text(
        json.dumps([{"finding_id": "f-2", "title": "Console Leak", "tool_source": "browser", "affected_target": "http://juice-shop:3000"}]),
        encoding="utf-8",
    )

    req = module.AgentRequest(
        **{
            "run_id": "fresh-run",
            "mode": "investigate",
            "intent": "Investigate Juice Shop",
            "targets": ["http://juice-shop:3000"],
            "scope_summary": {"allowlist": ["http://juice-shop:3000"]},
        }
    )

    context = module._resolve_prior_context(req)

    assert context["context_run_id"] == "run-strix"
    assert context["prior_findings"][0]["tool_source"] == "strix"


def test_ensure_browser_session_creates_mediated_session() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_BROWSER_EXECUTOR_MODE": "mediated",
            "CHIMERA_CORE_URL": "http://chimera-core:8000",
        }
    )

    req = module.AgentRequest(
        **{
            "run_id": "run-browser",
            "mode": "investigate",
            "intent": "Investigate Juice Shop",
            "targets": ["http://juice-shop:3000"],
            "scope_summary": {"allowlist": ["http://juice-shop:3000"], "denylist": []},
        }
    )

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"session_id": "browser-session-123"}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url, json):
            assert url == "http://chimera-core:8000/v1/browser/sessions"
            assert json["target"] == "http://juice-shop:3000"
            assert json["run_id"] == "run-browser"
            return FakeResponse()

    with patch.object(module._httpx, "AsyncClient", FakeClient):
        session_id, created, error = asyncio.run(module._ensure_browser_session(req))

    assert session_id == "browser-session-123"
    assert created is True
    assert error is None


def test_shell_scope_ignores_non_target_code_tokens() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    targets = module.extract_targets_from_command(["curl", "-s", "http://juice-shop:3000", "requests.get"])

    assert targets == ["http://juice-shop:3000"]


def test_shell_run_scoped_returns_scope_violation_instead_of_raising() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    result = asyncio.run(
        module._shell_run_scoped(
            {"command": ["curl", "-s", "https://example.com"]},
            {"allowlist": ["http://juice-shop:3000"]},
        )
    )

    assert result["error"] == "scope_violation"
    assert result["target"] == ["https://example.com"]


def test_agent_mode_retries_exploit_queue_until_tool_evidence() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    calls = 0

    async def fake_loop(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return {"output_text": "first", "tool_results": [], "usage": {"total_tokens": 3}}
        return {
            "output_text": "second",
            "tool_results": [
                {
                    "tool_name": "hexstrike_probe",
                    "result": {"summary": {"url": "https://example.com/login"}},
                    "artifact_ref": "/artifacts/run-2/shannon/agent/agent-1/tool_call_01_hexstrike_probe.json",
                }
            ],
            "usage": {"total_tokens": 4},
        }

    with patch.object(module, "run_responses_tool_loop", side_effect=fake_loop):
        response = asyncio.run(
            module._run_agent_mode(
                module.AgentRequest(
                    **{
                        "run_id": "run-2",
                        "mode": "exploit",
                        "intent": "Exploit login issue",
                        "targets": ["https://example.com"],
                        "candidate": {
                            "candidate_id": "cand-1",
                            "title": "Open Redirect",
                            "claim_type": "open_redirect",
                            "target": "https://example.com",
                            "endpoint": "/login",
                        },
                        "prior_findings": [],
                        "prior_evidence_refs": [],
                        "scope_summary": {"allowlist": ["example.com"]},
                        "budget": {"max_turns": 2, "max_tool_calls": 3, "max_retries": 2},
                    }
                )
            )
        )

    assert calls == 2
    assert response["exploit_queue"][0]["attempts"] == 2
    assert response["tool_call_refs"]
    assert module._tasks[response["task_id"]]["exploit_queue"][0]["status"] == "ready"


def test_agent_mode_passes_local_hypotheses_into_oracle_input(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
        }
    )

    captured = {}

    async def fake_loop(**kwargs):
        captured["payload"] = json.loads(kwargs["user_input"])
        captured["system_prompt"] = kwargs["system_prompt"]
        return {"output_text": "done", "tool_results": [], "usage": {"total_tokens": 5}}

    with (
        patch.object(module, "_resolve_prior_context", return_value={
            "prior_findings": [{"title": "Open Redirect", "tool_source": "strix"}],
            "prior_evidence_refs": ["artifacts/run-1/findings/f-1.md"],
            "context_run_id": "run-1",
            "context_source": "latest_target_match",
        }),
        patch.object(module, "_ensure_browser_session", return_value=("browser-session-1", True, None)),
        patch.object(module, "_generate_local_hypotheses", return_value={
            "status": "completed",
            "local_hypotheses": [{"title": "Admin Exposure", "tool_source": "shannon_local"}],
            "plan": {},
            "probe_results": [],
            "usage": {"total_tokens": 3},
            "error": None,
        }),
        patch.object(module, "run_responses_tool_loop", side_effect=fake_loop),
    ):
        response = asyncio.run(
            module._run_agent_mode(
                module.AgentRequest(
                    **{
                        "run_id": "run-2",
                        "mode": "investigate",
                        "intent": "Investigate Juice Shop",
                        "targets": ["http://juice-shop:3000"],
                        "scope_summary": {"allowlist": ["http://juice-shop:3000"]},
                    }
                )
            )
        )

    assert captured["payload"]["context_run_id"] == "run-1"
    assert captured["payload"]["browser_session_id"] == "browser-session-1"
    assert "Open Redirect" in captured["system_prompt"]
    assert "Admin Exposure" in captured["system_prompt"]
    assert response["local_hypotheses_count"] == 1
    assert response["local_hypothesis_status"] == "completed"
    assert response["local_hypotheses_ref"]


def test_agent_mode_honors_explicit_request_limits_and_runtime_shape(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    captured = {}

    async def fake_loop(**kwargs):
        captured["max_turns"] = kwargs["max_turns"]
        captured["max_tool_calls"] = kwargs["max_tool_calls"]
        captured["reasoning_effort"] = kwargs["reasoning_effort"]
        captured["payload"] = json.loads(kwargs["user_input"])
        return {"output_text": "done", "tool_results": [], "usage": {"total_tokens": 5}}

    with (
        patch.object(module, "run_responses_tool_loop", side_effect=fake_loop),
        patch.object(module, "_resolve_prior_context", return_value={"prior_findings": [], "prior_evidence_refs": [], "context_run_id": None, "context_source": "none"}),
        patch.object(module, "_generate_local_hypotheses", return_value={"status": "completed", "local_hypotheses": [], "usage": {}, "error": None}),
        patch.object(module, "_ensure_browser_session", return_value=(None, False, None)),
    ):
        response = asyncio.run(
            module._run_agent_mode(
                module.AgentRequest(
                    run_id="run-explicit",
                    mode="investigate",
                    intent="Inspect target",
                    targets=["https://example.com"],
                    agent_role="analysis",
                    analysis_domain="xss",
                    provider_preset="ollama",
                    repo_path="/workspace/repo",
                    max_turns=5,
                    max_tool_calls=7,
                    max_retries=1,
                    reasoning_effort="low",
                    scope_summary={"allowlist": ["https://example.com"]},
                )
            )
        )

    assert captured["max_turns"] == 5
    assert captured["max_tool_calls"] == 7
    assert captured["reasoning_effort"] == "low"
    assert captured["payload"]["request"]["budget"]["max_turns"] == 5
    assert response["schema"] == "shannon.agent_result.v1"
    assert response["request"]["provider_preset"] == "ollama"
    assert response["request"]["repo_path"] == "/workspace/repo"
    assert response["request"]["budget"]["max_tool_calls"] == 7
    assert response["request"]["scope_summary"]["allowlist"] == ["https://example.com"]
    assert response["runtime"]["limits"]["max_turns"] == 5
    assert response["runtime"]["limits"]["max_tool_calls"] == 7
    assert response["runtime"]["reasoning_effort"] == "low"
    assert response["artifacts"]["task_state_ref"] == response["task_state_ref"]
    assert response["context"]["local_hypotheses_count"] == 0
    assert response["results"]["new_candidates"] == response["new_candidates"]
    assert response["findings"] == response["new_candidates"]


def test_agent_mode_surfaces_cache_and_cost_metadata_for_anthropic_runtime(tmp_path: Path) -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
            "SHANNON_ORACLE_PROVIDER": "anthropic",
            "SHANNON_ORACLE_MODEL": "claude-sonnet-4-20250514",
            "SHANNON_ANTHROPIC_PROMPT_CACHING": "true",
            "SHANNON_ANTHROPIC_CACHE_TTL": "1h",
            "SHANNON_AGENT_ARTIFACT_ROOT": str(tmp_path / "artifacts"),
            "CHIMERA_ARTIFACTS_ROOT": str(tmp_path / "artifacts"),
        }
    )

    captured = {}

    async def fake_loop(**kwargs):
        captured["enable_prompt_caching"] = kwargs["enable_prompt_caching"]
        captured["prompt_cache_ttl"] = kwargs["prompt_cache_ttl"]
        return {
            "output_text": "done",
            "tool_results": [],
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 500,
                "total_tokens": 1500,
                "cache_creation_input_tokens": 200,
                "cache_read_input_tokens": 100,
                "cache_creation": {"ephemeral_1h_input_tokens": 200},
            },
        }

    with (
        patch.object(module, "run_responses_tool_loop", side_effect=fake_loop),
        patch.object(module, "_resolve_prior_context", return_value={"prior_findings": [], "prior_evidence_refs": [], "context_run_id": None, "context_source": "none"}),
        patch.object(module, "_generate_local_hypotheses", return_value={"status": "completed", "local_hypotheses": [], "usage": {}, "error": None}),
        patch.object(module, "_ensure_browser_session", return_value=(None, False, None)),
    ):
        response = asyncio.run(
            module._run_agent_mode(
                module.AgentRequest(
                    run_id="run-anthropic-usage",
                    mode="investigate",
                    intent="Inspect target",
                    targets=["https://example.com"],
                    model="claude-sonnet-4-20250514",
                    scope_summary={"allowlist": ["https://example.com"]},
                )
            )
        )

    assert captured["enable_prompt_caching"] is True
    assert captured["prompt_cache_ttl"] == "1h"
    assert response["runtime"]["prompt_caching_enabled"] is True
    assert response["runtime"]["prompt_cache_ttl"] == "1h"
    assert response["usage"]["provider"] == "anthropic"
    assert response["usage"]["provider_preset"] == "anthropic"
    assert response["usage"]["model"] == "claude-sonnet-4-20250514"
    assert response["usage"]["cache_creation_input_tokens"] == 200
    assert response["usage"]["cache_read_input_tokens"] == 100
    assert response["usage"]["cost_estimate_available"] is True
    assert response["usage"]["cost_estimate_usd"] is not None
    assert response["usage"]["pricing_source"] == "builtin_official_anthropic_prompt_caching_2026_04_11"
    assert response["runtime"]["prompt_blocks"]["cacheable_count"] >= 1
    assert response["artifacts"]["prompt_bundle_ref"]
    assert Path(response["artifacts"]["prompt_bundle_ref"]).exists()
    assert module._tasks[response["task_id"]]["usage"]["cost_estimate_available"] is True


def test_candidate_extraction_produces_multiple_typed_candidates() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    candidates = module.extract_candidates_from_tool_results(
        intent="Investigate Juice Shop",
        targets=["http://juice-shop:3000"],
        tool_results=[
            {"tool_name": "browser_navigate", "result": {"url": "http://juice-shop:3000/admin", "status_code": 200}},
            {"tool_name": "browser_navigate", "result": {"url": "http://juice-shop:3000/openapi.json", "status_code": 200}},
            {"tool_name": "browser_navigate", "result": {"url": "http://juice-shop:3000/rest/basket/1", "status_code": 401}},
        ],
    )

    claim_types = {item["claim_type"] for item in candidates}
    assert "admin_exposure" in claim_types
    assert "api_surface_exposure" in claim_types
    assert "idor" in claim_types
    assert all(item["claim_type"] != "unknown" for item in candidates)
    assert len(candidates) >= 3


def test_candidate_extraction_supports_digest_wrapped_tool_results() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    candidates = module.extract_candidates_from_tool_results(
        intent="Investigate Juice Shop",
        targets=["http://juice-shop:3000"],
        tool_results=[
            {
                "tool_name": "browser_navigate",
                "result": {
                    "status": "ok",
                    "summary": {
                        "url": "http://juice-shop:3000/admin",
                        "status_code": 200,
                    },
                    "artifact_ref": "/artifacts/run-x/tool_call_01_browser_navigate.json",
                },
            },
            {
                "tool_name": "hexstrike_endpoints",
                "result": {
                    "status": "ok",
                    "summary": {
                        "target": "http://juice-shop:3000",
                        "endpoints": [
                            "http://juice-shop:3000/openapi.json",
                        ],
                    },
                    "artifact_ref": "/artifacts/run-x/tool_call_02_hexstrike_endpoints.json",
                },
            },
        ],
    )

    claim_types = {item["claim_type"] for item in candidates}
    assert "admin_exposure" in claim_types
    assert "api_surface_exposure" in claim_types
    assert any("/artifacts/run-x/tool_call_01_browser_navigate.json" in item["evidence_refs"] for item in candidates)


def test_candidate_extraction_promotes_octopus_authz_reads() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_ORACLE_ENABLED": "true",
        }
    )

    candidates = module.extract_candidates_from_tool_results(
        intent="Investigate Octopus authorization",
        targets=["http://100.117.29.79:1322"],
        tool_results=[
            {
                "tool_name": "browser_navigate",
                "result": {
                    "status": "ok",
                    "summary": {
                        "url": "http://100.117.29.79:1322/api/users/Users-1/apikeys",
                        "status_code": 200,
                    },
                    "artifact_ref": "/artifacts/run-o/tool_call_01_browser_navigate.json",
                },
            },
            {
                "tool_name": "browser_navigate",
                "result": {
                    "status": "ok",
                    "summary": {
                        "url": "http://100.117.29.79:1322/api/octopusservernodes",
                        "status_code": 200,
                    },
                    "artifact_ref": "/artifacts/run-o/tool_call_02_browser_navigate.json",
                },
            },
        ],
    )

    claim_types = {item["claim_type"] for item in candidates}
    assert "idor" in claim_types
    assert "admin_exposure" in claim_types
    assert any(item["target"]["endpoint"] == "/api/users/Users-1/apikeys" for item in candidates)
    assert any(item["target"]["endpoint"] == "/api/octopusservernodes" for item in candidates)

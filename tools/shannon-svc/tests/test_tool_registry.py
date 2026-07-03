from test_shannon_robustness import _reload_main


def test_oracle_tool_registry_exposes_hexstrike_functions() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible"})
    registry = __import__("tool_registry")

    tools = registry.get_oracle_tools()
    tool_names = {tool["name"] for tool in tools}

    assert "hexstrike_probe" in tool_names
    assert "hexstrike_httpx" in tool_names
    assert "hexstrike_recon" in tool_names
    assert "hexstrike_endpoints" in tool_names
    assert "hexstrike_attack_surface" in tool_names
    assert "hexstrike_nmap" in tool_names
    assert "hexstrike_masscan" in tool_names
    assert "hexstrike_nuclei" in tool_names
    assert "hexstrike_nikto" in tool_names
    assert "hexstrike_katana" in tool_names
    assert "hexstrike_gobuster" in tool_names
    assert "hexstrike_ffuf" in tool_names
    assert "hexstrike_dalfox" in tool_names
    assert "hexstrike_subfinder" in tool_names
    assert "hexstrike_waybackurls" in tool_names
    assert "hexstrike_gau" in tool_names
    assert "hexstrike_curl" in tool_names
    assert "hexstrike_jwt_analyzer" in tool_names
    assert "hexstrike_checksec" in tool_names
    assert "hexstrike_anew" in tool_names
    assert "hexstrike_wpscan" in tool_names
    assert "browser_navigate" in tool_names
    assert "browser_capture_dom" in tool_names
    assert "shell_run_scoped" in tool_names
    assert "read_artifact" in tool_names


def test_oracle_tool_registry_is_scoped_to_safe_hexstrike_tools() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible"})
    registry = __import__("tool_registry")

    tools = registry.get_oracle_tools()
    tool_names = {tool["name"] for tool in tools}

    assert "hexstrike_sqlmap" not in tool_names
    assert "hexstrike_command" not in tool_names


def test_role_gating_separates_recon_report_and_exploit_tools() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible"})
    registry = __import__("tool_registry")

    recon = set(registry.get_allowed_oracle_tool_names(agent_role="recon"))
    report = set(registry.get_allowed_oracle_tool_names(agent_role="report"))
    analysis = set(registry.get_allowed_oracle_tool_names(agent_role="analysis", analysis_domain="auth"))
    exploit = set(registry.get_allowed_oracle_tool_names(agent_role="exploit", analysis_domain="xss"))

    assert "read_artifact" in report
    assert report == {"read_artifact"}

    assert "hexstrike_recon" in recon
    assert "hexstrike_masscan" in recon
    assert "browser_navigate" in recon
    assert "shell_run_scoped" not in recon
    assert "list_source_files" in recon

    assert "shell_run_scoped" in analysis
    assert "hexstrike_jwt_analyzer" in analysis
    assert "hexstrike_curl" in analysis
    assert "hexstrike_dalfox" not in analysis
    assert "read_source_file" in analysis

    assert "hexstrike_dalfox" in exploit
    assert "hexstrike_ffuf" in exploit
    assert "hexstrike_gobuster" in exploit
    assert "hexstrike_sqlmap" in exploit
    assert "hexstrike_checksec" in exploit
    assert "hexstrike_anew" in exploit

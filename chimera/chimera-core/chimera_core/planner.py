"""
Handles the conversion of a testing goal into a concrete, executable plan.

The planner is responsible for selecting the right tools and structuring their
execution as a Directed Acyclic Graph (DAG). This allows for managing
dependencies and scheduling concurrent tasks safely.
"""
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from typing import Dict, List, Tuple

from chimera_core.capabilities.registry import get_capabilities_for_target
from chimera_core.plan import ExecutionPlan, Task
from chimera_core.config import load_config

def _is_api_target(target: str) -> bool:
    lowered = target.lower()
    return any(marker in lowered for marker in ["/api", "/v1", "/swagger.json", "/openapi.json"])


def _is_graphql_target(target: str) -> bool:
    return "graphql" in target.lower()


def _asset_type_for_target(target: str, context: Dict[str, object]) -> str:
    lowered = target.lower()
    if _is_graphql_target(target):
        return "graphql"
    if _is_api_target(target) or context.get("asset_type") == "api_rest":
        return "api_rest"
    if context.get("subdomain_enumeration") or lowered.startswith("*."):
        return "subdomain"
    if "://" not in lowered and lowered.count(".") >= 1:
        return "subdomain"
    if context.get("auth_surface"):
        return "auth"
    if context.get("llm_endpoint"):
        return "llm_endpoint"
    if "http://" in lowered or "https://" in lowered:
        return "web_app"
    return "unknown"


def _task_stage(tool_name: str) -> str:
    if tool_name in {"autoswagger", "strix", "zap", "zypheron", "vibepentester", "subfinder", "browser"}:
        return "reconnaissance"
    if tool_name in {"shannon", "decepticon"}:
        return "vulnerability_analysis"
    if tool_name in {"bola_validator", "rate_limit_validator", "jwt_validator"}:
        return "exploitation"
    return "reconnaissance"


def _executable_capabilities(capabilities: List[str], context: Dict[str, object]) -> List[str]:
    executable = {
        "autoswagger",
        "strix",
        "zap",
        "hexstrike",
        "shannon",
        "zypheron",
        "vibepentester",
        "decepticon",
        "subfinder",
        "browser",
        "rate_limit_validator",
    }
    if context.get("validation_inputs"):
        executable.update({"bola_validator", "jwt_validator"})
    return [capability for capability in capabilities if capability in executable]


def _fallback_sequence(shannon_enabled: bool) -> List[str]:
    sequence = ["autoswagger", "strix"]
    if shannon_enabled:
        sequence.append("shannon")
    return sequence


def _is_hostname_like(target: str) -> bool:
    lowered = target.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        lowered = lowered.split("://", 1)[1].split("/", 1)[0]
    return lowered.count(".") >= 1 and "*" not in lowered


def _build_phased_web_plan(
    plan: ExecutionPlan,
    *,
    index: int,
    target: str,
    shannon_options: Dict[str, object],
    autonomous_options: Dict[str, object],
    analysis_domains: List[str],
) -> None:
    pre_task = Task(
        task_id=f"strix-{index}-0",
        tool="strix",
        target=target,
        options={
            "scan_mode": "standard",
            "phase": "pre_reconnaissance",
            "instruction": (
                "Perform pre-reconnaissance static architectural analysis first. "
                "Map entry points, auth systems, database patterns, and security sinks. "
                "Do not spend effort on browser-driven probing in this phase."
            ),
        },
        stage="pre_reconnaissance",
        capability="strix",
    )
    plan.add_task(pre_task)

    recon_specs: List[Tuple[str, str, Dict[str, object]]] = [
        ("browser", f"browser-{index}-1", {"phase": "reconnaissance", "mode": "analyze"}),
        ("zap", f"zap-{index}-2", {"phase": "reconnaissance", "scan_mode": "standard"}),
        (
            "hexstrike",
            f"hexstrike-{index}-3",
            {
                "phase": "reconnaissance",
                "tool_name": "recon",
                "agent": "deterministic_runner",
                "params": {"passive_only": True},
            },
        ),
    ]
    if _is_hostname_like(target):
        recon_specs.append(
            (
                "subfinder",
                f"subfinder-{index}-4",
                {"phase": "reconnaissance"},
            )
        )

    recon_task_ids: List[str] = []
    for tool, task_id, options in recon_specs:
        task = Task(
            task_id=task_id,
            tool=tool,
            target=target,
            options=options,
            stage="reconnaissance",
            capability=tool,
        )
        plan.add_task(task)
        plan.add_dependency(pre_task.task_id, task_id)
        recon_task_ids.append(task_id)

    analysis_task_ids: List[str] = []
    base_index = len(recon_specs) + 1
    for offset, domain in enumerate(analysis_domains):
        task_id = f"shannon-{index}-{base_index + offset}"
        task = Task(
            task_id=task_id,
            tool="shannon",
            target=target,
            options={
                **dict(shannon_options),
                **_autonomous_role_options(autonomous_options, "analysis"),
                "live": True,
                "mode": "investigate",
                "agent_role": "analysis",
                "analysis_domain": domain,
                "phase": "vulnerability_analysis",
                "vuln_types": [domain],
            },
            stage="vulnerability_analysis",
            capability="shannon",
        )
        plan.add_task(task)
        for recon_task_id in recon_task_ids:
            plan.add_dependency(recon_task_id, task_id)
        analysis_task_ids.append(task_id)

    exploit_task_ids: List[str] = []
    exploit_base = base_index + len(analysis_domains)
    for offset, domain in enumerate(analysis_domains):
        task_id = f"shannon-exploit-{index}-{exploit_base + offset}"
        task = Task(
            task_id=task_id,
            tool="shannon",
            target=target,
            options={
                **dict(shannon_options),
                **_autonomous_role_options(autonomous_options, "exploit"),
                "live": True,
                "mode": "exploit",
                "agent_role": "exploit",
                "analysis_domain": domain,
                "phase": "exploitation",
                "vuln_types": [domain],
            },
            stage="exploitation",
            capability="shannon",
        )
        plan.add_task(task)
        plan.add_dependency(analysis_task_ids[offset], task_id)
        exploit_task_ids.append(task_id)

    report_task = Task(
        task_id=f"shannon-report-{index}-{exploit_base + len(analysis_domains)}",
        tool="shannon",
        target=target,
        options={
            **dict(shannon_options),
            **_autonomous_role_options(autonomous_options, "report"),
            "live": True,
            "mode": "report",
            "agent_role": "report",
            "phase": "reporting",
        },
        stage="reporting",
        capability="shannon",
    )
    plan.add_task(report_task)
    for exploit_task_id in exploit_task_ids:
        plan.add_dependency(exploit_task_id, report_task.task_id)


def _shannon_is_available(shannon_config: Dict[str, object]) -> bool:
    if not bool(shannon_config.get("enabled")):
        return False
    if not bool(shannon_config.get("verify_availability", True)):
        return True

    driver = str(shannon_config.get("driver", "http")).lower()
    if driver != "http":
        return True

    base_url = str(shannon_config.get("base_url") or "").rstrip("/")
    candidates = []
    healthcheck_url = str(shannon_config.get("healthcheck_url") or "").strip()
    if healthcheck_url:
        candidates.append(healthcheck_url)
    if base_url:
        default_health_url = f"{base_url}/health"
        if default_health_url not in candidates:
            candidates.append(default_health_url)

    timeout_s = float(shannon_config.get("availability_timeout_s") or 2.0)
    for candidate in candidates:
        try:
            with urlopen(candidate, timeout=timeout_s):
                return True
        except HTTPError:
            return True
        except (URLError, OSError, ValueError):
            continue
    return False


def _autonomous_role_options(autonomous_config: Dict[str, object], role: str) -> Dict[str, object]:
    role_assignments = autonomous_config.get("role_assignments") if isinstance(autonomous_config.get("role_assignments"), dict) else {}
    role_assignment = role_assignments.get(role) if isinstance(role_assignments, dict) else {}
    options = {
        "shannon_runtime": autonomous_config.get("task_runtime") or "autonomous",
        "provider_preset": (role_assignment or {}).get("provider_preset") or autonomous_config.get("provider_preset"),
        "llm_provider": (role_assignment or {}).get("provider_preset") or autonomous_config.get("provider_preset"),
        "model": (role_assignment or {}).get("model") or autonomous_config.get("model"),
        "provider_base_url": (role_assignment or {}).get("base_url") or autonomous_config.get("base_url"),
        "max_turns": (role_assignment or {}).get("max_turns") or autonomous_config.get("max_turns"),
        "max_input_tokens": (role_assignment or {}).get("max_input_tokens") or autonomous_config.get("max_input_tokens"),
        "max_output_tokens": (role_assignment or {}).get("max_output_tokens") or autonomous_config.get("max_output_tokens"),
        "max_tool_calls": (role_assignment or {}).get("max_tool_calls") or autonomous_config.get("max_tool_calls"),
        "max_retries": (role_assignment or {}).get("max_retries") or autonomous_config.get("max_retries"),
        "reasoning_effort": (role_assignment or {}).get("reasoning_effort") or autonomous_config.get("reasoning_effort"),
        "repo_path": (role_assignment or {}).get("repo_path") or autonomous_config.get("repo_path"),
        "browser_session_id": autonomous_config.get("browser_session_id"),
        "auto_create_browser_session": autonomous_config.get("auto_create_browser_session"),
        "browser_session_mode": autonomous_config.get("browser_session_mode"),
        "zap_mcp_enabled": autonomous_config.get("zap_mcp_enabled"),
    }
    return {key: value for key, value in options.items() if value not in (None, "")}


def _resolve_autonomous_config(shannon_config: Dict[str, object], agent_config: Dict[str, object]) -> Dict[str, object]:
    autonomous = dict(shannon_config.get("autonomous") or {})
    role_assignments = autonomous.get("role_assignments") if isinstance(autonomous.get("role_assignments"), dict) else {}
    agent_role_assignments = agent_config.get("role_assignments") if isinstance(agent_config.get("role_assignments"), dict) else {}

    merged = {
        "enabled": bool(autonomous.get("enabled", True)),
        "task_runtime": autonomous.get("task_runtime") or "autonomous",
        "provider_preset": autonomous.get("provider_preset") or agent_config.get("provider") or "ollama",
        "model": autonomous.get("model") or agent_config.get("model"),
        "base_url": autonomous.get("base_url") or agent_config.get("base_url"),
        "max_turns": autonomous.get("max_turns") or agent_config.get("max_turns"),
        "max_tool_calls": autonomous.get("max_tool_calls"),
        "max_retries": autonomous.get("max_retries"),
        "reasoning_effort": autonomous.get("reasoning_effort"),
        "max_input_tokens": autonomous.get("max_input_tokens") or agent_config.get("max_input_tokens"),
        "max_output_tokens": autonomous.get("max_output_tokens") or agent_config.get("max_output_tokens"),
        "repo_path": autonomous.get("repo_path") or agent_config.get("repo_path"),
        "browser_session_id": autonomous.get("browser_session_id"),
        "auto_create_browser_session": autonomous.get("auto_create_browser_session", True),
        "browser_session_mode": autonomous.get("browser_session_mode"),
        "zap_mcp_enabled": autonomous.get("zap_mcp_enabled", True),
        "role_assignments": {},
    }

    for role in ("analysis", "exploit", "report"):
        auto_role = role_assignments.get(role) if isinstance(role_assignments, dict) else {}
        agent_role = agent_role_assignments.get(role) if isinstance(agent_role_assignments, dict) else {}
        merged["role_assignments"][role] = {
            "provider_preset": (auto_role or {}).get("provider_preset") or merged["provider_preset"] or (agent_role or {}).get("provider"),
            "model": (auto_role or {}).get("model") or merged["model"] or (agent_role or {}).get("model"),
            "base_url": (auto_role or {}).get("base_url") or merged["base_url"] or (agent_role or {}).get("base_url"),
            "max_turns": (auto_role or {}).get("max_turns") or merged["max_turns"],
            "max_input_tokens": (auto_role or {}).get("max_input_tokens") or merged["max_input_tokens"],
            "max_output_tokens": (auto_role or {}).get("max_output_tokens") or merged["max_output_tokens"],
            "max_tool_calls": (auto_role or {}).get("max_tool_calls") or merged["max_tool_calls"],
            "max_retries": (auto_role or {}).get("max_retries") or merged["max_retries"],
            "reasoning_effort": (auto_role or {}).get("reasoning_effort") or merged["reasoning_effort"],
            "repo_path": (auto_role or {}).get("repo_path") or merged["repo_path"],
        }
    return merged


def _build_tasks_for_target(
    plan: ExecutionPlan,
    *,
    index: int,
    target: str,
    capabilities: List[str],
    shannon_options: Dict[str, object],
    target_context: Dict[str, object],
) -> None:
    previous_task_id = None
    for step_index, capability in enumerate(capabilities):
        options: Dict[str, object] = {}
        if capability == "autoswagger":
            options = {"json": True}
        elif capability == "strix":
            options = {"scan_mode": "standard"}
        elif capability == "shannon":
            options = dict(shannon_options)
        elif capability in {"bola_validator", "jwt_validator"}:
            validation_inputs = target_context.get("validation_inputs")
            if validation_inputs:
                options = {"validation_inputs": dict(validation_inputs)}
        task_id = f"{capability}-{index}-{step_index}"
        task = Task(
            task_id=task_id,
            tool=capability,
            target=target,
            options=options,
            stage=_task_stage(capability),
            capability=capability,
        )
        plan.add_task(task)
        if previous_task_id:
            plan.add_dependency(previous_task_id, task_id)
        previous_task_id = task_id


def generate_plan(scope_graph, scope_policy, context) -> ExecutionPlan:
    """
    The core planning logic. Selects tools and builds the execution DAG.
    """
    plan = ExecutionPlan()
    config = load_config()
    shannon_config = config.get("shannon", {})
    agent_config = config.get("agent", {})
    autonomous_config = _resolve_autonomous_config(shannon_config, agent_config)
    pipeline_config = config.get("pipeline", {})
    pipeline_strategy = str(pipeline_config.get("strategy") or "phased_autonomous")
    analysis_domains = list(pipeline_config.get("analysis_domains") or ["injection", "xss", "ssrf", "auth", "authz", "upload", "business"])
    shannon_enabled = _shannon_is_available(shannon_config)
    shannon_options = {
        "vuln_types": shannon_config.get(
            "vuln_types",
            ["injection", "xss", "ssrf", "broken_auth", "authz", "upload", "business_logic"],
        ),
        "mode": shannon_config.get("mode", "verify"),
        "driver": shannon_config.get("driver", "http"),
        "base_url": shannon_config.get("base_url"),
        "config_path": shannon_config.get("config_path"),
        "output_file": shannon_config.get("output_file"),
        "query_template": shannon_config.get("query_template"),
        "healthcheck_url": shannon_config.get("healthcheck_url"),
    }
    shannon_options = {key: value for key, value in shannon_options.items() if value is not None}
    context = context or {}

    for i, domain in enumerate(scope_graph.allowed_domains):
        target_context = dict(context.get(domain, {})) if isinstance(context.get(domain), dict) else dict(context)
        asset_type = _asset_type_for_target(domain, target_context)
        capability_sequence = get_capabilities_for_target(asset_type, target_context)
        executable = _executable_capabilities(capability_sequence, target_context)
        if not executable:
            executable = _fallback_sequence(shannon_enabled)
            asset_type = "unknown"
        elif not shannon_enabled:
            executable = [name for name in executable if name != "shannon"]
        if not executable:
            executable = ["autoswagger", "strix"]

        plan.set_target_metadata(domain, asset_type=asset_type, capability_sequence=capability_sequence)
        if asset_type == "web_app" and shannon_enabled and pipeline_strategy == "phased_autonomous" and autonomous_config.get("enabled", True):
            _build_phased_web_plan(
                plan,
                index=i,
                target=domain,
                shannon_options=shannon_options,
                autonomous_options=autonomous_config,
                analysis_domains=analysis_domains,
            )
            continue
        _build_tasks_for_target(
            plan,
            index=i,
            target=domain,
            capabilities=executable,
            shannon_options=shannon_options,
            target_context=target_context,
        )

    plan.validate_acyclic()
    return plan

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
    if tool_name in {"autoswagger", "strix", "zypheron", "vibepentester", "subfinder", "browser"}:
        return "discover"
    if tool_name in {"shannon", "decepticon"}:
        return "classify"
    if tool_name in {"bola_validator", "rate_limit_validator", "jwt_validator"}:
        return "validate"
    return "discover"


def _executable_capabilities(capabilities: List[str], context: Dict[str, object]) -> List[str]:
    executable = {
        "autoswagger",
        "strix",
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
    shannon_enabled = _shannon_is_available(shannon_config)
    shannon_options = {
        "vuln_types": shannon_config.get(
            "vuln_types",
            ["injection", "xss", "ssrf", "broken_auth"],
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
        _build_tasks_for_target(
            plan,
            index=i,
            target=domain,
            capabilities=executable,
            shannon_options=shannon_options,
            target_context=target_context,
        )

    return plan

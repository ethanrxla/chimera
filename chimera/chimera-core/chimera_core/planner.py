"""
Handles the conversion of a testing goal into a concrete, executable plan.

The planner is responsible for selecting the right tools and structuring their
execution as a Directed Acyclic Graph (DAG). This allows for managing
dependencies and scheduling concurrent tasks safely.
"""
from typing import List

from chimera_core.plan import ExecutionPlan, Task
from chimera_core.config import load_config

def _is_api_target(target: str) -> bool:
    lowered = target.lower()
    return any(marker in lowered for marker in ["/api", "/v1", "/swagger.json", "/openapi.json"])


def generate_plan(scope_graph, scope_policy, context) -> ExecutionPlan:
    """
    The core planning logic. Selects tools and builds the execution DAG.
    """
    plan = ExecutionPlan()
    config = load_config()
    shannon_config = config.get("shannon", {})
    shannon_enabled = bool(shannon_config.get("enabled"))
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
    }
    shannon_options = {key: value for key, value in shannon_options.items() if value is not None}

    # --- Simple Planning Logic (Placeholder) ---
    # For now, create a single task for each allowed domain using net-utils.
    # In the future, this will be a sophisticated capability-based router.

    for i, domain in enumerate(scope_graph.allowed_domains):
        # Run Autoswagger first to discover APIs and generate OpenAPI specs
        autoswagger_task = Task(
            task_id=f"autoswagger-scan-{i}",
            tool="autoswagger",
            target=domain,
            options={"json": True}
        )
        plan.add_task(autoswagger_task)

        # Run Strix for general web app security testing
        strix_task = Task(
            task_id=f"strix-scan-{i}",
            tool="strix",
            target=domain,
            options={"scan_mode": "default"}
        )
        plan.add_task(strix_task)
        plan.add_dependency(autoswagger_task.task_id, strix_task.task_id)

        # Add Shannon verification after both tools complete (if enabled)
        if shannon_enabled:
            shannon_task = Task(
                task_id=f"shannon-verify-{i}",
                tool="shannon",
                target=domain,
                options=shannon_options,
            )
            plan.add_task(shannon_task)
            # Shannon verifies findings from both Autoswagger and Strix
            plan.add_dependency(autoswagger_task.task_id, shannon_task.task_id)
            plan.add_dependency(strix_task.task_id, shannon_task.task_id)

    # Example of adding a dependency:
    # fingerprint_task = Task(...)
    # plan.add_task(fingerprint_task)
    # subdomain_task = Task(...)
    # plan.add_task(subdomain_task)
    # plan.add_dependency(fingerprint_task.task_id, subdomain_task.task_id)

    return plan

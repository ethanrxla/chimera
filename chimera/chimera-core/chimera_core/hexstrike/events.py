from __future__ import annotations

from typing import Iterable, List


def emit_hexstrike_call_started(event_store, *, run_id: str, task_id: str, agent: str, tool_name: str, route: str, target_refs: Iterable[str]) -> None:
    event_store.emit(
        {
            "event_type": "hexstrike_call_started",
            "payload": {
                "run_id": run_id,
                "task_id": task_id,
                "agent": agent,
                "tool_name": tool_name,
                "route": route,
                "target_refs": list(target_refs),
            },
        }
    )


def emit_hexstrike_call_finished(
    event_store,
    *,
    run_id: str,
    task_id: str,
    agent: str,
    tool_name: str,
    status: str,
    duration_ms: int,
    artifact_paths: List[str],
    finding_count: int,
) -> None:
    event_store.emit(
        {
            "event_type": "hexstrike_call_finished",
            "payload": {
                "run_id": run_id,
                "task_id": task_id,
                "agent": agent,
                "tool_name": tool_name,
                "status": status,
                "duration_ms": duration_ms,
                "artifact_paths": artifact_paths,
                "finding_count": finding_count,
            },
        }
    )


def emit_scope_violation(
    event_store,
    *,
    run_id: str,
    task_id: str,
    agent: str,
    tool_name: str,
    rejected_targets: List[str],
    reason: str,
) -> None:
    event_store.emit(
        {
            "event_type": "scope_violation",
            "payload": {
                "run_id": run_id,
                "task_id": task_id,
                "agent": agent,
                "tool_name": tool_name,
                "rejected_targets": rejected_targets,
                "reason": reason,
            },
        }
    )

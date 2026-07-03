from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from chimera_core.artifacts import ArtifactWriter
from chimera_core.hexstrike.catalog import get_tool_spec
from chimera_core.hexstrike.client import HexStrikeClient
from chimera_core.hexstrike.events import (
    emit_hexstrike_call_finished,
    emit_hexstrike_call_started,
    emit_scope_violation,
)
from chimera_core.hexstrike.schemas import HexStrikeResult, HttpResponseSummary
from chimera_core.target_extraction import extract_targets_from_params


@dataclass(frozen=True)
class HexStrikeCall:
    call_id: str
    verification_id: str
    check_id: str
    probe_type: str
    tool_name: str
    probe_input: dict[str, Any]
    task_id: str | None = None


class HexStrikeExecutor:
    def __init__(
        self,
        *,
        runtime,
        base_url: str,
        artifact_writer: ArtifactWriter,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.runtime = runtime
        self.base_url = base_url.rstrip("/")
        self.artifact_writer = artifact_writer
        self.transport = transport

    def execute_call(self, *, run_id: str, call: HexStrikeCall, scope_manifest: dict) -> HexStrikeResult:
        spec = get_tool_spec(call.tool_name)
        targets = extract_targets_from_params(call.probe_input, spec.target_fields)
        for target in targets:
            if not self.runtime.scope_graph.is_in_scope(target):
                emit_scope_violation(
                    self.runtime.event_store,
                    run_id=run_id,
                    task_id=call.task_id or call.check_id,
                    agent="deterministic_runner",
                    tool_name=call.tool_name,
                    rejected_targets=[target],
                    reason="out_of_scope",
                )
                raise ValueError(f"HexStrike target out of scope: {target}")

        emit_hexstrike_call_started(
            self.runtime.event_store,
            run_id=run_id,
            task_id=call.task_id or call.check_id,
            agent="deterministic_runner",
            tool_name=call.tool_name,
            route=spec.route,
            target_refs=targets,
        )
        start = time.time()
        request_ref = self.artifact_writer.write_json(
            run_id=run_id,
            relpath=f"hexstrike/{call.verification_id}/{call.check_id}/request.json",
            kind="http_request",
            obj=call.probe_input,
            source="hexstrike",
            task_id=call.task_id or call.check_id,
        )
        client = HexStrikeClient(base_url=self.base_url, transport=self.transport)
        response = asyncio.run(client.call_tool(call.tool_name, call.probe_input))
        response_ref = self.artifact_writer.write_json(
            run_id=run_id,
            relpath=f"hexstrike/{call.verification_id}/{call.check_id}/response.json",
            kind="http_response",
            obj=response,
            source="hexstrike",
            task_id=call.task_id or call.check_id,
        )
        normalized = {
            "status_code": int(response.get("status_code", 0)),
            "headers": response.get("headers") or {},
            "body_excerpt": str(response.get("body_excerpt") or response.get("body") or "")[:2048],
            "body_sha256": str(response.get("body_sha256") or ""),
        }
        normalized_ref = self.artifact_writer.write_json(
            run_id=run_id,
            relpath=f"hexstrike/{call.verification_id}/{call.check_id}/normalized.json",
            kind="http_normalized",
            obj=normalized,
            source="hexstrike",
            task_id=call.task_id or call.check_id,
        )
        emit_hexstrike_call_finished(
            self.runtime.event_store,
            run_id=run_id,
            task_id=call.task_id or call.check_id,
            agent="deterministic_runner",
            tool_name=call.tool_name,
            status="completed",
            duration_ms=int((time.time() - start) * 1000),
            artifact_paths=[request_ref.relpath, response_ref.relpath, normalized_ref.relpath],
            finding_count=0,
        )
        return HexStrikeResult(
            call_id=call.call_id,
            ok=True,
            error=None,
            observed_targets=targets,
            request_artifact_ref=request_ref.relpath,
            response_artifact_ref=response_ref.relpath,
            normalized_artifact_ref=normalized_ref.relpath,
            summary=HttpResponseSummary(
                status_code=normalized["status_code"],
                headers={str(k): str(v) for k, v in normalized["headers"].items()},
                body_excerpt=normalized["body_excerpt"],
                body_sha256=normalized["body_sha256"],
            ),
        )

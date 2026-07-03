from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional

import httpx

from chimera_core.adapters.base import AdapterBase
from chimera_core.hexstrike.catalog import get_tool_spec
from chimera_core.hexstrike.client import HexStrikeClient
from chimera_core.hexstrike.events import (
    emit_hexstrike_call_finished,
    emit_hexstrike_call_started,
    emit_scope_violation,
)
from chimera_core.hexstrike.normalize import normalize_tool_output
from chimera_core.hexstrike.policy import HexStrikePolicy
from chimera_core.runtime import Runtime


class HexStrikeAdapter(AdapterBase):
    id = "hexstrike"
    capabilities = ["web-probe", "recon"]

    def __init__(
        self,
        runtime: Runtime,
        options: Optional[Dict[str, object]] = None,
        run_id: str = "mock_run_id",
        task_id: str = "mock_task_id",
        scope_hash: str = "mock_scope_hash",
        artifacts_root: Optional[Path] = None,
        base_url: str = "http://hexstrike:8888",
    ) -> None:
        self.runtime = runtime
        self.scope_graph = runtime.scope_graph
        self.options = options or {}
        self.run_id = run_id
        self.task_id = task_id
        self.scope_hash = scope_hash
        self.artifacts_root = artifacts_root or runtime.artifacts_root
        self.base_url = base_url.rstrip("/")
        self.policy = HexStrikePolicy(allow_dangerous=bool(self.options.get("allow_dangerous", False)))

    def _artifact_dir(self) -> Path:
        return Path(self.artifacts_root) / self.run_id / self.id / self.task_id

    def _artifact_path(self, filename: str) -> Path:
        return self._artifact_dir() / filename

    def _save_artifact(self, filename: str, payload: str, artifact_type: str) -> Dict[str, object]:
        path = self._artifact_path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
        self.runtime.event_store.emit(
            {
                "event_type": "artifact_saved",
                "payload": {
                    "run_id": self.run_id,
                    "task_id": self.task_id,
                    "path": str(path),
                    "artifact_type": artifact_type,
                    "tool": self.id,
                },
            }
        )
        return {"path": str(path), "artifact_type": artifact_type, "tool": self.id}

    def run(self, targets: List[str]) -> dict:
        tool_name = str(self.options.get("tool_name") or "probe")
        params = dict(self.options.get("params") or {})
        spec = get_tool_spec(tool_name)
        agent = str(self.options.get("agent") or "deterministic_runner")

        if targets and spec.target_fields:
            params.setdefault(spec.target_fields[0], targets[0])

        try:
            target_refs = self.policy.validate_call(
                agent=agent,
                tool_name=tool_name,
                params=params,
                scope_graph=self.scope_graph,
            )
        except ValueError:
            rejected = [str(params.get(field)) for field in spec.target_fields if isinstance(params.get(field), str)]
            emit_scope_violation(
                self.runtime.event_store,
                run_id=self.run_id,
                task_id=self.task_id,
                agent=agent,
                tool_name=tool_name,
                rejected_targets=rejected,
                reason="out_of_scope",
            )
            raise

        transport = self.options.get("transport")
        client = HexStrikeClient(base_url=self.base_url, transport=transport if isinstance(transport, httpx.AsyncBaseTransport) else transport)

        emit_hexstrike_call_started(
            self.runtime.event_store,
            run_id=self.run_id,
            task_id=self.task_id,
            agent=agent,
            tool_name=tool_name,
            route=spec.route,
            target_refs=target_refs,
        )

        start = time.time()
        raw_response = json.dumps({})
        try:
            response = __import__("asyncio").run(client.call_tool(tool_name, params))
            raw_response = json.dumps(response, indent=2)
            findings = normalize_tool_output(tool_name, response, run_id=self.run_id, scope_hash=self.scope_hash)
            normalized = json.dumps([finding.to_dict() for finding in findings], indent=2)

            artifacts = [
                self._save_artifact("request.json", json.dumps(params, indent=2), "request"),
                self._save_artifact("response.json", raw_response, "response"),
                self._save_artifact("normalized.json", normalized, "normalized"),
                self._save_artifact("findings.json", normalized, "findings"),
            ]

            emit_hexstrike_call_finished(
                self.runtime.event_store,
                run_id=self.run_id,
                task_id=self.task_id,
                agent=agent,
                tool_name=tool_name,
                status="completed",
                duration_ms=int((time.time() - start) * 1000),
                artifact_paths=[artifact["path"] for artifact in artifacts],
                finding_count=len(findings),
            )
            return {
                "events": [{"level": "info", "message": f"{self.id} completed", "targets": targets}],
                "artifacts": artifacts,
                "raw_output_refs": [raw_response],
                "findings": findings,
                "command": None,
            }
        except Exception:
            emit_hexstrike_call_finished(
                self.runtime.event_store,
                run_id=self.run_id,
                task_id=self.task_id,
                agent=agent,
                tool_name=tool_name,
                status="failed",
                duration_ms=int((time.time() - start) * 1000),
                artifact_paths=[],
                finding_count=0,
            )
            raise

    def normalize(self, raw_output: str):
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return []
        tool_name = str(self.options.get("tool_name") or "probe")
        return normalize_tool_output(tool_name, data, run_id=self.run_id, scope_hash=self.scope_hash)


HexstrikeAdapter = HexStrikeAdapter

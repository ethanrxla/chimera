from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Dict, List, Optional

from chimera_core.adapters.base import AdapterBase
from chimera_core.findings import Finding
from chimera_core.runtime import Runtime
from chimera_core.tool_runner import ToolRunner


class SubfinderAdapter(AdapterBase):
    id = "subfinder"
    capabilities = ["subdomain-enumeration"]

    def __init__(
        self,
        runtime: Runtime,
        options: Optional[Dict[str, object]] = None,
        run_id: str = "mock_run_id",
        task_id: str = "mock_task_id",
        scope_hash: str = "mock_scope_hash",
        artifacts_root: Optional[Path] = None,
    ) -> None:
        self.runtime = runtime
        self.scope_graph = runtime.scope_graph
        self.scope_policy = runtime.scope_policy
        self.options = options or {}
        self.run_id = run_id
        self.task_id = task_id
        self.scope_hash = scope_hash
        self.artifacts_root = artifacts_root or runtime.artifacts_root
        self.tool_runner = ToolRunner(runtime)

    def build_command(self, domain: str) -> List[str]:
        if not self.scope_graph.is_in_scope(domain):
            raise ValueError(f"Target out of scope: {domain}")
        command = self.tool_runner.base_command(self.id, ["/usr/bin/subfinder"])
        command.extend(["-d", domain, "-silent", "-json"])
        return command

    def _artifact_path(self, filename: str) -> Path:
        return Path(self.artifacts_root) / self.run_id / self.id / self.task_id / filename

    def run(self, targets: List[str], *args, **kwargs) -> dict:
        if not targets:
            raise ValueError("Subfinder requires at least one domain target")
        target = targets[0]
        live = bool(self.options.get("live", False))
        fixture_path = self.options.get("fixture_path")
        raw_output_override = self.options.get("raw_output_override")

        if live:
            command = self.build_command(target)
            result = self.tool_runner.run(self.id, command, task_id=self.task_id, timeout_s=self.options.get("timeout_s"))
            raw_output = result.stdout
        else:
            command = None
            if raw_output_override is not None:
                raw_output = str(raw_output_override)
            elif fixture_path:
                raw_output = Path(str(fixture_path)).read_text(encoding="utf-8")
            else:
                raw_output = ""

        output_path = self._artifact_path("raw_output.jsonl")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(raw_output, encoding="utf-8")
        findings = self.normalize(raw_output)
        findings_path = self._artifact_path("findings.json")
        findings_path.write_text(json.dumps([finding.to_dict() for finding in findings], indent=2), encoding="utf-8")
        return {
            "events": [{"level": "info", "message": f"{self.id} completed", "targets": targets}],
            "artifacts": [
                {"path": str(output_path), "artifact_type": "raw_output", "tool": self.id},
                {"path": str(findings_path), "artifact_type": "findings", "tool": self.id},
            ],
            "raw_output_refs": [raw_output],
            "findings": findings,
            "command": command,
        }

    def normalize(self, raw_output: str) -> List[Finding]:
        findings: List[Finding] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = str(payload.get("host") or payload.get("subdomain") or "")
            if not host:
                continue
            resolved = self._resolves(host)
            title = "Discovered subdomain"
            description = f"Subfinder discovered {host}."
            severity = "info" if resolved else "medium"
            if not resolved:
                title = "Potential subdomain takeover candidate"
                description = f"Subdomain {host} did not resolve during enumeration."
            findings.append(
                Finding(
                    finding_id=f"subfinder:{host}",
                    severity=severity,
                    title=title,
                    description=description,
                    affected_target=host,
                    tool_source=self.id,
                    tool_version="subfinder",
                    run_id=self.run_id,
                    scope_hash=self.scope_hash,
                    finding_type="SUBDOMAIN",
                    asset={"host": host, "endpoint": "/", "method": None, "parameter": None},
                    confidence=0.85 if resolved else 0.72,
                )
            )
        return findings

    def _resolves(self, hostname: str) -> bool:
        try:
            socket.getaddrinfo(hostname, None)
            return True
        except socket.gaierror:
            return False

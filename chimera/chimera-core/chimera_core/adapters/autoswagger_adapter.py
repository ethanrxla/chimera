import json
import sys
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Optional

from chimera_core.adapters.base import AdapterBase
from chimera_core.findings import Finding
from chimera_core.runtime import Runtime
from chimera_core.tool_runner import ToolRunner
from chimera_core.scope import ScopeGraph, ScopePolicy


class AutoswaggerAdapter(AdapterBase):
    id = "autoswagger"
    capabilities = ["api-testing"]

    def __init__(
        self,
        runtime: Runtime,
        options: Optional[Dict[str, object]] = None,
        rate_limits: Optional[Dict[str, int]] = None,
        run_id: str = "mock_run_id",
        task_id: str = "mock_task_id",
        scope_hash: str = "mock_scope_hash",
        artifacts_root: Optional[Path] = None,
    ) -> None:
        self.runtime = runtime
        self.scope_graph = runtime.scope_graph
        self.scope_policy = runtime.scope_policy
        self.options = options or {}
        self.rate_limits = rate_limits or {}
        self.run_id = run_id
        self.task_id = task_id
        self.scope_hash = scope_hash
        self.artifacts_root = artifacts_root or runtime.artifacts_root
        self.tool_path = Path(__file__).resolve().parents[3] / "tools" / "autoswagger" / "autoswagger.py"
        self.tool_runner = ToolRunner(runtime)

    def validate_targets(self, targets: List[str]) -> None:
        for target in targets:
            if not self.scope_graph.is_in_scope(target):
                raise ValueError(f"Target out of scope: {target}")

    def build_command(self, targets: List[str]) -> List[str]:
        self.validate_targets(targets)

        command = self.tool_runner.base_command(self.id, [sys.executable, str(self.tool_path)])
        if self.options.get("verbose"):
            command.append("-v")
        if self.options.get("risk"):
            command.append("-risk")
        if self.options.get("include_all"):
            command.append("-all")
        if self.options.get("product"):
            command.append("-product")
        if self.options.get("stats"):
            command.append("-stats")
        if self.options.get("brute"):
            command.append("-b")
        if self.options.get("json"):
            command.append("-json")

        rate = self.rate_limits.get("requests_per_second", self.scope_policy.max_rps)
        command.extend(["-rate", str(rate)])
        command.extend(targets)
        return command

    def _artifact_path(self, filename: str) -> Optional[Path]:
        if not self.artifacts_root:
            return None
        return self.artifacts_root / self.run_id / self.id / self.task_id / filename

    def _save_raw_output(self, raw_output: str) -> Optional[str]:
        output_path = self._artifact_path("raw_output.json")
        if not output_path:
            return None
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(raw_output, encoding="utf-8")
        return str(output_path)

    def _emit_event(self, event_type: str, payload: Dict[str, object]) -> None:
        if not self.runtime or not self.runtime.event_store:
            return
        self.runtime.event_store.emit({"event_type": event_type, "payload": payload})

    def run(self, targets: List[str]) -> dict:
        live = bool(self.options.get("live", False))
        fixture_path = self.options.get("fixture_path")
        raw_output_override = self.options.get("raw_output_override")

        self.validate_targets(targets)
        self._emit_event("task_started", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})

        raw_output = None
        command = None
        if live:
            command = self.build_command(targets)
            timeout = self.options.get("timeout_s")
            result = self.tool_runner.run(
                self.id,
                command,
                task_id=self.task_id,
                timeout_s=timeout,
                cwd=Path(self.tool_path).parent,
            )
            raw_output = result.stdout
        else:
            self._emit_event("cmd_started", {"run_id": self.run_id, "task_id": self.task_id, "mode": "fixture"})
            if raw_output_override is not None:
                raw_output = raw_output_override
            elif fixture_path:
                raw_output = Path(fixture_path).read_text(encoding="utf-8")
            else:
                raw_output = json.dumps({"endpoints": []})

        artifact_path = self._save_raw_output(raw_output)
        artifacts = []
        if artifact_path:
            artifacts.append({"path": artifact_path, "artifact_type": "raw_output", "tool": self.id})
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": artifact_path, "tool": self.id},
            )

        findings = self.normalize(raw_output)
        findings_path = self._artifact_path("findings.json")
        if findings_path:
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_payload = [finding.to_dict() for finding in findings]
            findings_path.write_text(json.dumps(findings_payload, indent=2), encoding="utf-8")
            artifacts.append({"path": str(findings_path), "artifact_type": "findings", "tool": self.id})
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": str(findings_path), "tool": self.id},
            )

        if not live:
            self._emit_event("cmd_finished", {"run_id": self.run_id, "task_id": self.task_id, "returncode": 0})

        self._emit_event("task_finished", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})

        return {
            "events": [{"level": "info", "message": f"{self.id} completed", "targets": targets}],
            "artifacts": artifacts,
            "raw_output_refs": [raw_output],
            "findings": findings,
            "command": command,
        }

    def _parse_output(self, raw_output: str) -> Dict[str, object]:
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError:
            start = raw_output.find("{")
            end = raw_output.rfind("}")
            if start == -1 or end == -1 or end <= start:
                return {}
            try:
                return json.loads(raw_output[start : end + 1])
            except json.JSONDecodeError:
                return {}

    def normalize(self, raw_output: str) -> List[Finding]:
        data = self._parse_output(raw_output)
        findings: List[Finding] = []
        endpoints = data.get("endpoints")
        if endpoints is None:
            endpoints = data.get("results", [])
        for endpoint in endpoints:
            pii = endpoint.get("pii", [])
            secrets = endpoint.get("secrets", [])
            large = endpoint.get("large_response", False)
            if not (pii or secrets or large):
                continue

            url = endpoint.get("url", "unknown")
            method = endpoint.get("method", "GET")
            status = endpoint.get("status", endpoint.get("status_code", 0))
            title = "Unauthenticated API data exposure"
            description = (
                f"{method} {url} returned {status} with "
                f"{'secrets' if secrets else 'PII' if pii else 'large response'}."
            )
            finding_id = f"{self.id}:{method}:{url}:{status}"

            findings.append(
                Finding(
                    finding_id=finding_id,
                    severity="medium" if secrets else "low",
                    title=title,
                    description=description,
                    affected_target=url,
                    tool_source=self.id,
                    tool_version="0.1.0",
                    run_id=self.run_id,
                    scope_hash=self.scope_hash,
                    finding_type="AUTH_EXPOSURE" if pii or secrets else "DATA_EXPOSURE",
                    asset={
                        "host": urlparse(url).hostname or url,
                        "endpoint": urlparse(url).path or "/",
                        "method": method,
                        "parameter": None,
                    },
                    confidence=0.7 if secrets else 0.55,
                )
            )
        return findings

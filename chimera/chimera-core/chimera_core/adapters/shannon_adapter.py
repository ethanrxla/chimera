import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import httpx

from chimera_core.adapters.base import AdapterBase
from chimera_core.config import load_config
from chimera_core.findings import Finding, stable_finding_id
from chimera_core.runtime import Runtime
from chimera_core.tool_runner import ToolRunner


class ShannonAdapter(AdapterBase):
    id = "shannon"
    capabilities = ["verification", "pentest"]

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
        self.options = options or {}
        self.run_id = run_id
        self.task_id = task_id
        self.scope_hash = scope_hash
        self.artifacts_root = artifacts_root or runtime.artifacts_root
        self.tool_runner = ToolRunner(runtime)

    def run(self, targets: List[str]) -> dict:
        opts = self._effective_options()
        live = bool(opts.get("live", False))
        fixture_path = opts.get("fixture_path")
        raw_output_override = opts.get("raw_output_override")

        self._emit_event("task_started", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})

        raw_output = None
        command = None
        if live:
            driver = str(opts.get("driver", "http")).lower()
            if driver == "http":
                raw_output = self._run_http(targets, opts)
            elif driver == "command":
                raw_output, command = self._run_command(targets, opts)
            else:
                raise ValueError(f"Unsupported Shannon driver: {driver}")
        else:
            self._emit_event("cmd_started", {"run_id": self.run_id, "task_id": self.task_id, "mode": "fixture"})
            if raw_output_override is not None:
                raw_output = raw_output_override
            elif fixture_path:
                raw_output = Path(fixture_path).read_text(encoding="utf-8")
            else:
                raw_output = json.dumps({"findings": []})

        artifacts = []
        artifact_path = self._save_raw_output(raw_output)
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

    def normalize(self, raw_output: str) -> List[Finding]:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return []

        findings_payload = self._extract_findings_payload(data)
        if not isinstance(findings_payload, list):
            return []

        findings: List[Finding] = []
        for item in findings_payload:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or item.get("name") or "Shannon Finding")
            description = str(item.get("description") or item.get("details") or "")
            severity = str(item.get("severity") or "medium").lower()
            target = str(item.get("target") or item.get("affected_target") or item.get("url") or "unknown")
            signature = item.get("signature") or item.get("id")

            evidence = item.get("evidence") or {}
            evidence_refs = item.get("evidence_refs") or evidence.get("evidence_refs") or []
            if isinstance(evidence_refs, str):
                evidence_refs = [evidence_refs]

            repro_guidance = item.get("repro_guidance") or evidence.get("repro_guidance") or item.get("poc")
            finding_id = stable_finding_id(title, target, self.id, str(signature) if signature else None)
            inferred_type = _infer_finding_type(title, description, repro_guidance)

            findings.append(
                Finding(
                    finding_id=finding_id,
                    severity=severity,
                    title=title,
                    description=description,
                    affected_target=target,
                    tool_source=self.id,
                    tool_version="shannon",
                    run_id=self.run_id,
                    scope_hash=self.scope_hash,
                    evidence_refs=list(evidence_refs) if evidence_refs else [],
                    repro_guidance=repro_guidance,
                    timestamps=datetime.now(timezone.utc),
                    finding_type=inferred_type,
                    asset={
                        "host": _target_host(target),
                        "endpoint": _target_path(target),
                        "method": item.get("method"),
                        "parameter": item.get("parameter"),
                    },
                    confidence=_confidence_from_severity(severity),
                )
            )
        return findings

    def _extract_findings_payload(self, data: object) -> Optional[Sequence[Dict[str, object]]]:
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            return None
        if isinstance(data.get("findings"), list):
            return data.get("findings")
        result = data.get("result")
        if isinstance(result, dict) and isinstance(result.get("findings"), list):
            return result.get("findings")
        output = data.get("output")
        if isinstance(output, dict) and isinstance(output.get("findings"), list):
            return output.get("findings")
        return None

    def _run_http(self, targets: List[str], opts: Dict[str, object]) -> str:
        base_url = str(opts.get("base_url") or "http://localhost:8080").rstrip("/")
        api_key_env = str(opts.get("api_key_env") or "SHANNON_API_KEY")
        api_key = str(opts.get("api_key") or os.getenv(api_key_env) or "")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key

        query = self._build_query(targets, opts)
        session_id = str(opts.get("session_id") or f"chimera-{self.run_id}")
        payload = {"query": query, "session_id": session_id}

        timeout_s = float(opts.get("request_timeout_s") or opts.get("timeout_s") or 900)
        poll_interval = float(opts.get("poll_interval_s") or 2)
        client = opts.get("http_client")
        close_client = client is None
        if client is None:
            client = httpx.Client(timeout=timeout_s, headers=headers)

        try:
            response = client.post(f"{base_url}/api/v1/tasks", json=payload, headers=headers)
            response.raise_for_status()
            submit_data = response.json()
            task_id = submit_data.get("task_id") or submit_data.get("id")
            if not task_id:
                raise RuntimeError("Shannon task submission did not return task_id")

            status = "running"
            data = submit_data
            while status in {"queued", "running", "in_progress"}:
                time.sleep(poll_interval)
                status_resp = client.get(f"{base_url}/api/v1/tasks/{task_id}", headers=headers)
                status_resp.raise_for_status()
                data = status_resp.json()
                status = str(data.get("status") or "").lower()
                if status in {"completed", "succeeded", "success"}:
                    break
                if status in {"failed", "error"}:
                    raise RuntimeError(f"Shannon task failed: {data}")
            return json.dumps(data)
        finally:
            if close_client and hasattr(client, "close"):
                client.close()

    def _run_command(self, targets: List[str], opts: Dict[str, object]) -> tuple[str, List[str]]:
        command = opts.get("command")
        if not command:
            raise ValueError("Shannon command driver requires a command option")
        if not isinstance(command, list):
            raise ValueError("Shannon command must be a list of arguments")
        output_dir = self._artifact_dir() / "deliverables"
        output_dir.mkdir(parents=True, exist_ok=True)
        mapping = {
            "target": targets[0],
            "targets": " ".join(targets),
            "output_dir": str(output_dir),
            "config_path": str(opts.get("config_path") or ""),
            "run_id": self.run_id,
            "task_id": self.task_id,
        }
        formatted = [str(item).format(**mapping) for item in command]
        if formatted:
            base = self.tool_runner.base_command(self.id, [formatted[0]])
            formatted = base + formatted[1:]
        timeout = opts.get("timeout_s")
        result = self.tool_runner.run(
            self.id,
            formatted,
            task_id=self.task_id,
            timeout_s=timeout,
        )
        output_file = str(opts.get("output_file") or "findings.json")
        output_path = output_dir / output_file
        if output_path.exists():
            raw_output = output_path.read_text(encoding="utf-8")
        else:
            raw_output = result.stdout or result.stderr or ""
        return raw_output, formatted

    def _build_query(self, targets: List[str], opts: Dict[str, object]) -> str:
        if opts.get("query"):
            return str(opts["query"])
        vuln_types = opts.get("vuln_types") or ["injection", "xss", "ssrf", "broken_auth"]
        if isinstance(vuln_types, str):
            vuln_types = [vuln_types]
        template = str(
            opts.get("query_template")
            or "Verify {targets} for {vuln_types} and report findings with proof-of-exploit steps."
        )
        return template.format(
            target=targets[0],
            targets=", ".join(targets),
            vuln_types=", ".join(vuln_types),
            mode=str(opts.get("mode") or "verify"),
        )

    def _artifact_dir(self) -> Path:
        return Path(self.artifacts_root) / self.run_id / self.id / self.task_id

    def _artifact_path(self, filename: str) -> Optional[Path]:
        return self._artifact_dir() / filename

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

    def _effective_options(self) -> Dict[str, object]:
        config = load_config()
        base = dict(config.get("shannon", {}))
        base.update(self.options)
        return base


def _infer_finding_type(title: str, description: str, repro_guidance: Optional[str]) -> str:
    text = f"{title} {description} {repro_guidance or ''}".lower()
    if "idor" in text or "bola" in text:
        return "IDOR"
    if "jwt" in text:
        return "JWT"
    if "rate limit" in text or "throttl" in text:
        return "RATE_LIMIT"
    if "xss" in text:
        return "XSS"
    if re.search(r"\bsqli?\b|sql injection", text):
        return "SQLI"
    if "auth" in text:
        return "BROKEN_AUTH"
    return "HYPOTHESIS"


def _target_host(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        from urllib.parse import urlparse
        return urlparse(target).hostname or target
    return target


def _target_path(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        from urllib.parse import urlparse
        return urlparse(target).path or "/"
    return "/"


def _confidence_from_severity(severity: str) -> float:
    return {
        "critical": 0.97,
        "high": 0.9,
        "medium": 0.72,
        "low": 0.55,
    }.get(str(severity).lower(), 0.5)

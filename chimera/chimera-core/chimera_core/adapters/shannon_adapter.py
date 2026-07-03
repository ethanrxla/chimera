import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence
from urllib.parse import urljoin, urlparse

import httpx

from chimera_core.adapters.base import AdapterBase
from chimera_core.agents.agent_loop import AgentLoop
from chimera_core.agents.llm_provider import create_provider
from chimera_core.agents.prompts import load_prompt
from chimera_core.agents.tool_executor import ToolExecutor
from chimera_core.artifacts import ArtifactWriter
from chimera_core.config import load_config
from chimera_core.exploits import (
    AdminExposureExploitHandler,
    AuthMissingExploitHandler,
    BusinessLogicExploitHandler,
    SQLiExploitHandler,
    SSRFExploitHandler,
    TwoUserIDORExploitHandler,
    UploadBugExploitHandler,
    XSSExploitHandler,
)
from chimera_core.exploits.juice_shop_credentials import (
    get_default_admin_credentials,
    get_default_bootstrap_credentials,
)
from chimera_core.findings import Finding, stable_finding_id
from chimera_core.runtime import Runtime
from chimera_core.shannon.session import SessionPool
from chimera_core.shannon.schemas import (
    CandidateFinding,
    ExploitResult,
    ProbeInput,
    SuccessCondition,
    ValidationStatus,
    ValidatorDecision,
    VerificationCheck,
    VerificationPlan,
)
from chimera_core.tool_runner import ToolRunner


class ShannonAdapter(AdapterBase):
    id = "shannon"
    capabilities = ["verification", "pentest"]
    agent_request_schema = "shannon.agent_request.v1"
    agent_result_schema = "shannon.autonomous_agent_result.v1"

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
        self.artifact_writer = ArtifactWriter(self.artifacts_root, event_store=runtime.event_store)

    def run(self, targets: List[str]) -> dict:
        opts = self._effective_options()
        if str(opts.get("mode") or "").lower() == "autonomous":
            return self._run_autonomous_agent(targets, opts)
        if self._uses_shannon_agent_runtime(opts):
            opts = {**opts, "agent_flow": True}
        agent_role = str(opts.get("agent_role") or "").lower()
        if agent_role in {"analysis", "exploit"} and bool(opts.get("live", False)):
            opts = {**opts, "agent_flow": True}
        if bool(opts.get("agent_flow")):
            return self._run_agent_flow(targets, opts)
        if bool(opts.get("typed_flow")):
            return self._run_typed_flow(targets, opts)

        live = bool(opts.get("live", False))
        fixture_path = opts.get("fixture_path")
        raw_output_override = opts.get("raw_output_override")
        prompt_artifact = self._save_prompt_artifact(targets, opts)

        self._emit_event("task_started", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})
        self._emit_event(
            "llm_started",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": str(opts.get("model") or opts.get("driver") or "shannon"),
                "stage": "analysis",
                "prompt_artifact": prompt_artifact,
                "response_artifact": None,
                "usage": {},
            },
        )

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
        self._emit_event(
            "llm_finished",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": str(opts.get("model") or opts.get("driver") or "shannon"),
                "stage": "analysis",
                "prompt_artifact": prompt_artifact,
                "response_artifact": artifact_path,
                "usage": {},
            },
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

    def _run_autonomous_agent(self, targets: List[str], opts: Dict[str, object]) -> dict:
        return asyncio.run(self._run_autonomous_agent_async(targets, opts))

    async def _run_autonomous_agent_async(self, targets: List[str], opts: Dict[str, object]) -> dict:
        prompt_artifact = self._save_prompt_artifact(targets, opts)
        agent_role = str(opts.get("agent_role") or "analysis").lower()
        analysis_domain = str(opts.get("analysis_domain") or "").lower()
        provider_config = self._resolve_autonomous_role_config(agent_role, opts)
        prior_findings = self._relevant_prior_findings_from_opts(opts)

        self._emit_event("task_started", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})
        self._emit_event(
            "llm_started",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": str(provider_config.get("model") or provider_config.get("provider") or "autonomous"),
                "stage": "autonomous_agent",
                "prompt_artifact": prompt_artifact,
                "response_artifact": None,
                "usage": {},
            },
        )

        provider_name = str(provider_config.get("provider") or "anthropic")
        provider_kwargs = {}
        if provider_name == "anthropic":
            provider_kwargs["prompt_caching"] = bool(provider_config.get("prompt_caching", True))
        provider = create_provider(
            provider_name,
            model=str(provider_config.get("model") or "") or None,
            base_url=str(provider_config.get("base_url") or "") or None,
            api_key=str(provider_config.get("api_key") or "") or None,
            **provider_kwargs,
        )

        repo_path_value = provider_config.get("repo_path")
        repo_path = Path(str(repo_path_value)).expanduser() if repo_path_value else None
        tool_executor = ToolExecutor(
            scope_graph=self.runtime.scope_graph,
            scope_policy=self.runtime.scope_policy,
            artifacts_dir=self.runtime.artifacts_root,
            run_id=self.run_id,
            task_id=self.task_id,
            repo_path=repo_path,
            artifact_namespace=self.id,
        )
        prompt = load_prompt(
            agent_role=agent_role,
            analysis_domain=analysis_domain,
            context={
                "target_url": targets[0] if targets else "unknown",
                "repo_path": str(repo_path) if repo_path else None,
                "prior_findings": [finding.to_dict() for finding in prior_findings],
            },
        )
        agent = AgentLoop(
            llm=provider,
            tool_executor=tool_executor,
            system_prompt=prompt,
            agent_role=agent_role,
            analysis_domain=analysis_domain,
            max_turns=int(provider_config.get("max_turns") or 200),
            max_input_tokens=int(provider_config.get("max_input_tokens") or 5_000_000),
            max_output_tokens=int(provider_config.get("max_output_tokens") or 500_000),
            run_id=self.run_id,
            task_id=self.task_id,
            event_emitter=self._emit_event,
        )

        try:
            result = await agent.run(initial_context=self._build_autonomous_initial_context(targets, opts, prior_findings))
        finally:
            close = getattr(provider, "close", None)
            if callable(close):
                maybe_coro = close()
                if hasattr(maybe_coro, "__await__"):
                    await maybe_coro

        raw_payload = {
            "status": "completed",
            "mode": "autonomous",
            "agent_role": agent_role,
            "analysis_domain": analysis_domain,
            "provider": provider_config.get("provider"),
            "model": provider_config.get("model"),
            "turns": result.turns,
            "stop_reason": result.stop_reason,
            "usage": result.usage.to_dict(),
            "reported_findings": [item.to_dict() for item in result.reported],
            "findings": [finding.to_dict() for finding in result.findings],
            "artifacts": list(result.artifact_paths),
            "errors": list(result.errors),
        }
        raw_output = json.dumps(raw_payload, indent=2, default=str)
        raw_output_path = self._save_raw_output(raw_output)
        artifacts = []
        if prompt_artifact:
            artifacts.append({"path": prompt_artifact, "artifact_type": "prompt", "tool": self.id})
        for path in result.artifact_paths:
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": path, "tool": self.id, "artifact_type": "agent_trace"},
            )
            artifacts.append({"path": path, "artifact_type": "agent_trace", "tool": self.id})
        if raw_output_path:
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": raw_output_path, "tool": self.id, "artifact_type": "raw_output"},
            )
            artifacts.append({"path": raw_output_path, "artifact_type": "raw_output", "tool": self.id})

        findings_path = self._artifact_path("findings.json")
        if findings_path:
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_payload = [finding.to_dict() for finding in result.findings]
            findings_path.write_text(json.dumps(findings_payload, indent=2, default=str), encoding="utf-8")
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": str(findings_path), "tool": self.id, "artifact_type": "findings"},
            )
            artifacts.append({"path": str(findings_path), "artifact_type": "findings", "tool": self.id})

        self._emit_event(
            "llm_finished",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": str(provider_config.get("model") or provider_config.get("provider") or "autonomous"),
                "stage": "autonomous_agent",
                "prompt_artifact": prompt_artifact,
                "response_artifact": raw_output_path,
                "usage": result.usage.to_dict(),
            },
        )
        self._emit_event("task_finished", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})
        return {
            "events": [{"level": "info", "message": f"{self.id} autonomous agent completed", "targets": targets}],
            "artifacts": artifacts,
            "raw_output_refs": [raw_output],
            "findings": result.findings,
            "command": None,
            "usage": result.usage.to_dict(),
            "turns": result.turns,
        }

    def _run_agent_flow(self, targets: List[str], opts: Dict[str, object]) -> dict:
        base_url = str(opts.get("base_url") or "http://localhost:8080").rstrip("/")
        client = opts.get("http_client")
        close_client = client is None
        if client is None:
            client = httpx.Client(timeout=float(opts.get("timeout_s") or 180))

        prompt_artifact = self._save_prompt_artifact(targets, opts)
        self._emit_event("task_started", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})
        self._emit_event(
            "llm_started",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": "agent_flow",
                "stage": "investigation",
                "prompt_artifact": prompt_artifact,
                "response_artifact": None,
                "usage": {},
            },
        )

        target = targets[0] if targets else "unknown"
        request_payload = self._build_agent_request_payload(targets, opts)
        agent_resp = client.post(
            f"{base_url}/agent",
            json=request_payload,
        )
        agent_resp.raise_for_status()
        agent_payload = self._normalize_agent_result(agent_resp.json(), request_payload)
        trace_ref = str(agent_payload.get("agent_trace_ref") or "").strip()
        if isinstance(trace_ref, str) and trace_ref:
            self._emit_event(
                "artifact_saved",
                {
                    "run_id": self.run_id,
                    "task_id": self.task_id,
                    "path": trace_ref,
                    "tool": self.id,
                    "artifact_type": "agent_trace",
                },
            )
        local_hypotheses_ref = str(agent_payload.get("local_hypotheses_ref") or "").strip()
        if local_hypotheses_ref:
            self._emit_event(
                "artifact_saved",
                {
                    "run_id": self.run_id,
                    "task_id": self.task_id,
                    "path": local_hypotheses_ref,
                    "tool": self.id,
                    "artifact_type": "local_hypotheses",
                },
            )
        for compaction_ref in list(agent_payload.get("compaction_refs") or []):
            compaction_path = str(compaction_ref).strip()
            if not compaction_path:
                continue
            self._emit_event(
                "artifact_saved",
                {
                    "run_id": self.run_id,
                    "task_id": self.task_id,
                    "path": compaction_path,
                    "tool": self.id,
                    "artifact_type": "agent_compaction",
                },
            )
        task_state_ref = str(agent_payload.get("task_state_ref") or "").strip()
        if task_state_ref:
            self._emit_event(
                "artifact_saved",
                {
                    "run_id": self.run_id,
                    "task_id": self.task_id,
                    "path": task_state_ref,
                    "tool": self.id,
                    "artifact_type": "task_state",
                },
            )

        raw_output = json.dumps({"status": "agent_completed", "agent": agent_payload, "findings": []})
        findings_payload: List[dict] = []
        candidate_findings: List[CandidateFinding] = []
        candidates = list(agent_payload.get("new_candidates") or agent_payload.get("findings") or [])
        exploit_results: Dict[str, ExploitResult] = {}
        self._emit_event(
            "agent_started",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "mode": str(opts.get("mode") or "investigate"),
                "agent_role": str(opts.get("agent_role") or "analysis"),
            },
        )
        if str(opts.get("agent_role") or "").lower() == "exploit" or str(opts.get("mode") or "").lower() == "exploit":
            exploit_results = self._run_exploitation_queue(candidates, opts)
        for index, tool_result in enumerate(list(agent_payload.get("tool_results") or []), start=1):
            if not isinstance(tool_result, dict):
                continue
            result_payload = tool_result.get("result")
            target_refs = []
            if isinstance(result_payload, dict):
                for key in ("url", "target", "endpoint", "targets"):
                    value = result_payload.get(key)
                    if isinstance(value, str) and value:
                        target_refs.append(value)
            self._emit_event(
                "agent_tool_called",
                {
                    "run_id": self.run_id,
                    "task_id": self.task_id,
                    "call_id": f"{self.task_id}-agent-{index}",
                    "tool_name": str(tool_result.get("tool_name") or "unknown"),
                    "target_refs": target_refs,
                },
            )
        for item in candidates:
            exploit_result = exploit_results.get(str(item.get("candidate_id") or ""))
            if exploit_result is not None:
                item["exploit_status"] = exploit_result.classification
                item["evidence_refs"] = list(dict.fromkeys(list(item.get("evidence_refs") or []) + list(exploit_result.final_evidence_refs)))
                metadata = dict(item.get("metadata") or {})
                metadata["exploit_result"] = exploit_result.to_dict()
                metadata["exploit_result_ref"] = f"exploits/{str(item.get('candidate_id') or '')}/exploit_result.json"
                item["metadata"] = metadata
            target_spec = dict(item.get("metadata", {}).get("target") or {})
            endpoint = item.get("endpoint") or target_spec.get("endpoint")
            target_url = str(item.get("target") or target_spec.get("url") or target)
            candidate = CandidateFinding(
                candidate_id=str(item.get("candidate_id") or f"{self.task_id}-candidate"),
                source=str(item.get("source") or "shannon-agent"),
                title=str(item.get("title") or "Shannon Agent Candidate"),
                claim_type=str(item.get("claim_type") or ""),
                severity_claimed=str(item.get("severity_claimed") or "medium"),
                endpoint=endpoint,
                target=target_url,
                params=list(item.get("params") or []),
                evidence_refs=list(item.get("evidence_refs") or []),
                metadata=dict(item.get("metadata") or {}),
            )
            if not candidate.claim_type:
                continue
            self._emit_event(
                "agent_handoff_created",
                {
                    "run_id": self.run_id,
                    "task_id": self.task_id,
                    "candidate_id": candidate.candidate_id,
                    "claim_type": candidate.claim_type,
                },
            )
            candidate_findings.append(candidate)

        deduped_candidates: List[CandidateFinding] = []
        seen_candidate_ids = set()
        for candidate in candidate_findings:
            if candidate.candidate_id in seen_candidate_ids:
                continue
            seen_candidate_ids.add(candidate.candidate_id)
            deduped_candidates.append(candidate)
        candidate_findings = deduped_candidates

        artifacts: List[dict] = []
        candidate_artifact = self._write_candidate_artifact(candidate_findings)
        if candidate_artifact is not None:
            artifacts.append({"path": candidate_artifact.relpath, "artifact_type": "candidate_finding", "tool": self.id})
        if trace_ref:
            artifacts.append({"path": trace_ref, "artifact_type": "agent_trace", "tool": self.id})
        if local_hypotheses_ref:
            artifacts.append({"path": local_hypotheses_ref, "artifact_type": "local_hypotheses", "tool": self.id})
        if task_state_ref:
            artifacts.append({"path": task_state_ref, "artifact_type": "task_state", "tool": self.id})
        for compaction_ref in list(agent_payload.get("compaction_refs") or []):
            compaction_path = str(compaction_ref).strip()
            if compaction_path:
                artifacts.append({"path": compaction_path, "artifact_type": "agent_compaction", "tool": self.id})
        for tool_ref in list(agent_payload.get("tool_call_refs") or []):
            tool_path = str(tool_ref).strip()
            if tool_path:
                artifacts.append({"path": tool_path, "artifact_type": "agent_tool_call", "tool": self.id})

        raw_output = json.dumps(
            {
                "status": "completed",
                "agent": agent_payload,
                "candidates": [candidate.to_dict() for candidate in candidate_findings],
                "findings": findings_payload,
            }
        )
        artifact_path = self._save_raw_output(raw_output)
        if artifact_path:
            artifacts.append({"path": artifact_path, "artifact_type": "raw_output", "tool": self.id})
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": artifact_path, "tool": self.id},
            )
        self._emit_event(
            "llm_finished",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": "agent_flow",
                "stage": "investigation",
                "prompt_artifact": prompt_artifact,
                "response_artifact": artifact_path,
                "usage": dict(agent_payload.get("usage") or {}),
            },
        )
        self._emit_event("task_finished", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})
        if close_client and hasattr(client, "close"):
            client.close()
        findings = self.normalize(raw_output)
        return {
            "events": [{"level": "info", "message": f"{self.id} agent flow completed", "targets": targets}],
            "artifacts": artifacts,
            "raw_output_refs": [raw_output],
            "findings": findings,
            "candidate_findings": candidate_findings,
            "command": None,
        }

    def _uses_shannon_agent_runtime(self, opts: Dict[str, object]) -> bool:
        return str(opts.get("shannon_runtime") or "").strip().lower() == "autonomous"

    def _agent_scope_summary(self, opts: Dict[str, object]) -> Dict[str, object]:
        allowlist = list(
            opts.get("scope_allowlist")
            or getattr(self.runtime.scope_graph, "allowed_domains", [])
            or []
        )
        summary: Dict[str, object] = {"allowlist": allowlist}
        denylist = list(opts.get("scope_denylist") or [])
        if denylist:
            summary["denylist"] = denylist
        allowed_methods = list(opts.get("allowed_methods") or [])
        if allowed_methods:
            summary["allowed_methods"] = allowed_methods
        return summary

    def _build_agent_request_payload(self, targets: List[str], opts: Dict[str, object]) -> Dict[str, object]:
        reasoning_effort = str(opts.get("reasoning_effort") or "").strip().lower()
        max_turns = int(opts.get("agent_max_turns") or opts.get("max_turns") or 4)
        max_tool_calls = int(opts.get("agent_max_tool_calls") or opts.get("max_tool_calls") or 8)
        max_retries = int(opts.get("agent_max_retries") or opts.get("max_retries") or 0)
        provider_preset = (
            opts.get("provider_preset")
            or opts.get("llm_provider")
            or opts.get("provider")
        )
        return {
            "schema": self.agent_request_schema,
            "run_id": self.run_id,
            "mode": str(opts.get("mode") or "investigate"),
            "intent": str(opts.get("intent") or self._build_query(targets, opts)),
            "targets": targets,
            "agent_role": str(opts.get("agent_role") or "") or None,
            "analysis_domain": str(opts.get("analysis_domain") or "") or None,
            "provider_preset": str(provider_preset) if provider_preset else None,
            "model": str(opts.get("model") or "") or None,
            "base_url": str(
                opts.get("provider_base_url")
                or opts.get("llm_base_url")
                or opts.get("agent_provider_base_url")
                or ""
            )
            or None,
            "repo_path": str(opts.get("repo_path") or "") or None,
            "max_turns": max_turns,
            "max_tool_calls": max_tool_calls,
            "max_retries": max_retries,
            "reasoning_effort": reasoning_effort or None,
            "browser_session_id": str(opts.get("browser_session_id") or "") or None,
            "auto_create_browser_session": bool(opts.get("auto_create_browser_session", True)),
            "candidate": opts.get("candidate"),
            "prior_findings": [f.to_dict() for f in self._relevant_prior_findings_from_opts(opts)],
            "prior_evidence_refs": list(opts.get("prior_evidence_refs") or []),
            "auto_context": bool(opts.get("auto_context", True)),
            "scope_summary": self._agent_scope_summary(opts),
            "budget": {
                "max_turns": max_turns,
                "max_tool_calls": max_tool_calls,
                "max_retries": max_retries,
                **({"reasoning_effort": reasoning_effort} if reasoning_effort else {}),
            },
        }

    def _normalize_agent_result(self, payload: Dict[str, object], request_payload: Dict[str, object]) -> Dict[str, object]:
        raw = payload if isinstance(payload, dict) else {}
        request_view = raw.get("request") if isinstance(raw.get("request"), dict) else {}
        merged_request = dict(request_payload)
        merged_request.update({key: value for key, value in request_view.items() if value not in (None, "", [], {})})

        runtime_view = raw.get("runtime") if isinstance(raw.get("runtime"), dict) else {}
        context_view = raw.get("context") if isinstance(raw.get("context"), dict) else {}
        results_view = raw.get("results") if isinstance(raw.get("results"), dict) else {}
        artifacts_view = raw.get("artifacts") if isinstance(raw.get("artifacts"), dict) else {}
        usage_view = raw.get("usage") if isinstance(raw.get("usage"), dict) else {}
        result_findings = list(results_view.get("findings") or raw.get("findings") or raw.get("new_candidates") or [])
        result_candidates = list(results_view.get("new_candidates") or raw.get("new_candidates") or result_findings)

        normalized = {
            "schema": str(raw.get("schema") or self.agent_result_schema),
            "task_id": str(raw.get("task_id") or self.task_id),
            "run_id": str(raw.get("run_id") or self.run_id),
            "status": str(raw.get("status") or "completed"),
            "request": merged_request,
            "runtime": {
                "provider": runtime_view.get("provider") or raw.get("provider"),
                "provider_preset": runtime_view.get("provider_preset") or raw.get("provider_preset") or merged_request.get("provider_preset"),
                "model": runtime_view.get("model") or raw.get("model") or merged_request.get("model"),
                "browser_session_id": runtime_view.get("browser_session_id") or raw.get("browser_session_id") or merged_request.get("browser_session_id"),
                "browser_session_created": runtime_view.get("browser_session_created") or raw.get("browser_session_created") or False,
                "browser_session_error": runtime_view.get("browser_session_error") or raw.get("browser_session_error"),
                "context_run_id": runtime_view.get("context_run_id") or raw.get("context_run_id"),
                "context_source": runtime_view.get("context_source") or raw.get("context_source"),
                "repo_path": runtime_view.get("repo_path") or merged_request.get("repo_path"),
                "reasoning_effort": runtime_view.get("reasoning_effort") or merged_request.get("reasoning_effort"),
                "limits": dict(runtime_view.get("limits") or {
                    "max_turns": merged_request.get("max_turns"),
                    "max_tool_calls": merged_request.get("max_tool_calls"),
                    "max_retries": merged_request.get("max_retries"),
                }),
            },
            "context": {
                "context_run_id": context_view.get("context_run_id") or raw.get("context_run_id"),
                "context_source": context_view.get("context_source") or raw.get("context_source"),
                "prior_findings_count": context_view.get("prior_findings_count") or raw.get("prior_findings_count") or len(list(request_payload.get("prior_findings") or [])),
                "local_hypotheses_count": context_view.get("local_hypotheses_count") or raw.get("local_hypotheses_count") or 0,
                "oracle_focus_hypotheses_count": context_view.get("oracle_focus_hypotheses_count") or raw.get("oracle_focus_hypotheses_count") or 0,
                "local_hypothesis_status": context_view.get("local_hypothesis_status") or raw.get("local_hypothesis_status"),
                "local_hypothesis_error": context_view.get("local_hypothesis_error") or raw.get("local_hypothesis_error"),
            },
            "artifacts": {
                "agent_trace_ref": artifacts_view.get("agent_trace_ref") or raw.get("agent_trace_ref"),
                "local_hypotheses_ref": artifacts_view.get("local_hypotheses_ref") or raw.get("local_hypotheses_ref"),
                "tool_call_refs": list(artifacts_view.get("tool_call_refs") or raw.get("tool_call_refs") or []),
                "compaction_refs": list(artifacts_view.get("compaction_refs") or raw.get("compaction_refs") or []),
                "evidence_refs": list(artifacts_view.get("evidence_refs") or raw.get("evidence_refs") or []),
                "task_state_ref": artifacts_view.get("task_state_ref") or raw.get("task_state_ref"),
            },
            "results": {
                "findings": result_findings,
                "tool_results": list(results_view.get("tool_results") or raw.get("tool_results") or []),
                "local_hypotheses": list(results_view.get("local_hypotheses") or raw.get("local_hypotheses") or []),
                "oracle_focus_hypotheses": list(results_view.get("oracle_focus_hypotheses") or raw.get("oracle_focus_hypotheses") or []),
                "new_candidates": result_candidates,
                "exploit_queue": list(results_view.get("exploit_queue") or raw.get("exploit_queue") or []),
                "validator_handoff": dict(results_view.get("validator_handoff") or raw.get("validator_handoff") or {"recommended_mode": "typed_verify", "candidate_ids": []}),
                "raw_output": results_view.get("raw_output") or raw.get("raw_output") or "",
            },
            "summary": dict(raw.get("summary") or {}),
            "usage": usage_view,
            # Legacy compatibility mirrors.
            "provider": runtime_view.get("provider") or raw.get("provider"),
            "provider_preset": runtime_view.get("provider_preset") or raw.get("provider_preset") or merged_request.get("provider_preset"),
            "model": runtime_view.get("model") or raw.get("model") or merged_request.get("model"),
            "browser_session_id": raw.get("browser_session_id") or runtime_view.get("browser_session_id") or merged_request.get("browser_session_id"),
            "browser_session_created": raw.get("browser_session_created") or runtime_view.get("browser_session_created") or False,
            "browser_session_error": raw.get("browser_session_error") or runtime_view.get("browser_session_error"),
            "context_run_id": context_view.get("context_run_id") or raw.get("context_run_id"),
            "context_source": context_view.get("context_source") or raw.get("context_source"),
            "prior_findings_count": context_view.get("prior_findings_count") or raw.get("prior_findings_count") or len(list(request_payload.get("prior_findings") or [])),
            "local_hypotheses_count": context_view.get("local_hypotheses_count") or raw.get("local_hypotheses_count") or 0,
            "oracle_focus_hypotheses_count": context_view.get("oracle_focus_hypotheses_count") or raw.get("oracle_focus_hypotheses_count") or 0,
            "local_hypotheses_ref": artifacts_view.get("local_hypotheses_ref") or raw.get("local_hypotheses_ref"),
            "local_hypothesis_status": context_view.get("local_hypothesis_status") or raw.get("local_hypothesis_status"),
            "local_hypothesis_error": context_view.get("local_hypothesis_error") or raw.get("local_hypothesis_error"),
            "agent_trace_ref": artifacts_view.get("agent_trace_ref") or raw.get("agent_trace_ref"),
            "tool_call_refs": list(artifacts_view.get("tool_call_refs") or raw.get("tool_call_refs") or []),
            "compaction_refs": list(artifacts_view.get("compaction_refs") or raw.get("compaction_refs") or []),
            "task_state_ref": artifacts_view.get("task_state_ref") or raw.get("task_state_ref"),
            "tool_results": list(results_view.get("tool_results") or raw.get("tool_results") or []),
            "local_hypotheses": list(results_view.get("local_hypotheses") or raw.get("local_hypotheses") or []),
            "oracle_focus_hypotheses": list(results_view.get("oracle_focus_hypotheses") or raw.get("oracle_focus_hypotheses") or []),
            "findings": result_findings,
            "new_candidates": result_candidates,
            "evidence_refs": list(artifacts_view.get("evidence_refs") or raw.get("evidence_refs") or []),
            "exploit_queue": list(results_view.get("exploit_queue") or raw.get("exploit_queue") or []),
            "validator_handoff": dict(results_view.get("validator_handoff") or raw.get("validator_handoff") or {"recommended_mode": "typed_verify", "candidate_ids": []}),
            "raw_output": results_view.get("raw_output") or raw.get("raw_output") or "",
        }
        if not normalized["usage"]:
            normalized["usage"] = {}
        return normalized

    def _run_typed_flow(self, targets: List[str], opts: Dict[str, object]) -> dict:
        prompt_artifact = self._save_prompt_artifact(targets, opts)
        self._emit_event("task_started", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})
        self._emit_event(
            "llm_started",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": "typed_flow",
                "stage": "planning",
                "prompt_artifact": prompt_artifact,
                "response_artifact": None,
                "usage": {},
            },
        )

        if bool(opts.get("typed_skeleton_only")):
            raw_output = json.dumps({"status": "planned", "typed_flow": True, "findings": []})
            artifact_path = self._save_raw_output(raw_output)
            if artifact_path:
                self._emit_event(
                    "artifact_saved",
                    {"run_id": self.run_id, "task_id": self.task_id, "path": artifact_path, "tool": self.id},
                )
            self._emit_event(
                "llm_finished",
                {
                    "run_id": self.run_id,
                    "task_id": self.task_id,
                    "model": "typed_flow",
                    "stage": "planning",
                    "prompt_artifact": prompt_artifact,
                    "response_artifact": artifact_path,
                    "usage": {},
                },
            )
            self._emit_event("task_finished", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})
            return {
                "events": [{"level": "info", "message": f"{self.id} typed flow planned", "targets": targets}],
                "artifacts": [{"path": artifact_path, "artifact_type": "raw_output", "tool": self.id}] if artifact_path else [],
                "raw_output_refs": [raw_output],
                "findings": [],
                "command": None,
            }

        base_url = str(opts.get("base_url") or "http://localhost:8080").rstrip("/")
        client = opts.get("http_client")
        close_client = client is None
        if client is None:
            client = httpx.Client(timeout=float(opts.get("timeout_s") or 120))

        target = targets[0] if targets else "unknown"
        candidate = CandidateFinding(
            candidate_id=f"{self.task_id}-candidate",
            source="strix",
            title=str(opts.get("candidate_title") or "Open Redirect"),
            claim_type=str(opts.get("claim_type") or "open_redirect"),
            severity_claimed=str(opts.get("severity_claimed") or "medium"),
            endpoint=str(opts.get("endpoint") or "/"),
            target=target,
            evidence_refs=list(opts.get("prior_evidence_refs") or []),
        )
        candidate_findings = [candidate]
        candidate_artifact = self._write_candidate_artifact(candidate_findings)
        findings_payload: List[dict] = []
        raw_output = json.dumps(
            {
                "status": "handoff_created",
                "typed_flow": True,
                "candidate": candidate.to_dict(),
                "candidates": [candidate.to_dict()],
                "findings": findings_payload,
            }
        )
        artifact_path = self._save_raw_output(raw_output)
        artifacts: List[dict] = []
        if candidate_artifact is not None:
            artifacts.append({"path": candidate_artifact.relpath, "artifact_type": "candidate_finding", "tool": self.id})
        if artifact_path:
            artifacts.append({"path": artifact_path, "artifact_type": "raw_output", "tool": self.id})
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": artifact_path, "tool": self.id},
            )
        self._emit_event(
            "llm_finished",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": "typed_flow",
                "stage": "planning",
                "prompt_artifact": prompt_artifact,
                "response_artifact": artifact_path,
                "usage": {},
            },
        )
        self._emit_event("task_finished", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})
        if close_client and hasattr(client, "close"):
            client.close()
        findings = self.normalize(raw_output)
        return {
            "events": [{"level": "info", "message": f"{self.id} typed flow queued for core verification", "targets": targets}],
            "artifacts": artifacts,
            "raw_output_refs": [raw_output],
            "findings": findings,
            "candidate_findings": candidate_findings,
            "command": None,
        }

    def _resolve_autonomous_role_config(self, agent_role: str, opts: Dict[str, object]) -> Dict[str, object]:
        config = load_config()
        agent_config = dict(config.get("agent", {}))
        role_assignments = agent_config.get("role_assignments") if isinstance(agent_config.get("role_assignments"), dict) else {}
        role_assignment = dict(role_assignments.get(agent_role) or {})
        merged = {
            "provider": role_assignment.get("provider") or agent_config.get("provider"),
            "model": role_assignment.get("model") or agent_config.get("model"),
            "base_url": role_assignment.get("base_url") or agent_config.get("base_url"),
            "repo_path": agent_config.get("repo_path"),
            "max_turns": agent_config.get("max_turns"),
            "max_input_tokens": agent_config.get("max_input_tokens"),
            "max_output_tokens": agent_config.get("max_output_tokens"),
            "prompt_caching": bool(agent_config.get("prompt_caching", True)),
        }
        for key in ("llm_provider", "provider", "model", "base_url", "repo_path", "max_turns", "max_input_tokens", "max_output_tokens", "prompt_caching"):
            if key in opts and opts.get(key) not in (None, ""):
                merged["provider" if key == "llm_provider" else key] = opts.get(key)
        return merged

    def _build_autonomous_initial_context(self, targets: List[str], opts: Dict[str, object], prior_findings: List[Finding]) -> str:
        lines = [
            f"Begin security assessment of {targets[0] if targets else 'unknown target'}.",
            f"Phase: {str(opts.get('phase') or opts.get('mode') or 'analysis')}",
        ]
        if targets:
            lines.append("Targets:")
            lines.extend(f"- {target}" for target in targets)
        allowlist = list(opts.get("scope_allowlist") or getattr(self.runtime.scope_graph, "allowed_domains", []) or [])
        if allowlist:
            lines.append("In-scope hosts:")
            lines.extend(f"- {entry}" for entry in allowlist)
        if prior_findings:
            lines.append("Prior findings are available in the system prompt context. Re-use them where relevant.")
        instruction = str(opts.get("instruction") or "").strip()
        if instruction:
            lines.append("Additional instructions:")
            lines.append(instruction)
        return "\n".join(lines)

    def _relevant_prior_findings_from_opts(self, opts: Dict[str, object]) -> List[Finding]:
        prior = opts.get("prior_findings") or []
        findings: List[Finding] = []
        for item in prior:
            if isinstance(item, Finding):
                findings.append(item)
        return findings

    def normalize(self, raw_output: str) -> List[Finding]:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return []

        findings_payload = self._extract_findings_payload(data)
        if not isinstance(findings_payload, list):
            return []

        default_target = self._default_target_from_output(data)
        findings: List[Finding] = []
        for item in findings_payload:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or item.get("name") or item.get("vulnerability") or item.get("issue") or "Shannon Finding")
            description = str(item.get("description") or item.get("details") or item.get("proof_of_exploit") or item.get("summary") or "")
            severity = str(item.get("severity") or "medium").lower()
            target = str(item.get("target") or item.get("affected_target") or item.get("url") or default_target or "unknown")
            signature = item.get("signature") or item.get("id")
            evidence = item.get("evidence") or {}
            evidence_refs = item.get("evidence_refs") or evidence.get("evidence_refs") or []
            if isinstance(evidence_refs, str):
                evidence_refs = [evidence_refs]
            repro_guidance = item.get("repro_guidance") or evidence.get("repro_guidance") or item.get("poc") or item.get("proof_of_exploit")
            replay_steps = _normalize_repro_steps(item.get("repro_steps"))
            exploit_status = item.get("exploit_status")
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
                    replay_steps=replay_steps,
                    exploit_status=str(exploit_status) if exploit_status else None,
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
        vulns = data.get("vulnerabilities")
        if isinstance(vulns, list):
            return [_normalise_vuln_item(v) for v in vulns if isinstance(v, dict)]
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
            query_excerpt = query[:200] + ("…" if len(query) > 200 else "")
            self._emit_event("ai_query_sent", {"run_id": self.run_id, "task_id": self.task_id, "query_excerpt": query_excerpt})
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
            findings_list = []
            raw_findings = data.get("findings") or data.get("result", {}).get("findings") or []
            if isinstance(raw_findings, list):
                findings_list = [f.get("title", "") for f in raw_findings if isinstance(f, dict)]
            self._emit_event("ai_analysis", {"run_id": self.run_id, "task_id": self.task_id, "findings_count": len(findings_list), "finding_titles": findings_list[:5], "status": status})
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
        result = self.tool_runner.run(self.id, formatted, task_id=self.task_id, timeout_s=timeout)
        output_file = str(opts.get("output_file") or "findings.json")
        output_path = output_dir / output_file
        raw_output = output_path.read_text(encoding="utf-8") if output_path.exists() else (result.stdout or result.stderr or "")
        return raw_output, formatted

    def _build_query(self, targets: List[str], opts: Dict[str, object]) -> str:
        if opts.get("query"):
            return str(opts["query"])
        agent_role = str(opts.get("agent_role") or "").lower()
        analysis_domain = str(opts.get("analysis_domain") or "").lower()
        vuln_types = opts.get("vuln_types") or ["injection", "xss", "ssrf", "broken_auth"]
        if isinstance(vuln_types, str):
            vuln_types = [vuln_types]
        scope_allowlist = opts.get("scope_allowlist") or []
        scope_section = ""
        if scope_allowlist:
            scope_section = f"\n\nIn-scope targets (DO NOT probe any URL outside this list):\n" + "\n".join(f"  - {t}" for t in scope_allowlist)
        prior_findings = opts.get("prior_findings") or []
        if agent_role == "analysis":
            findings_json = json.dumps(prior_findings, indent=2) if prior_findings else "[]"
            return (
                f"Phase 3: Vulnerability Analysis\n"
                f"Target(s): {', '.join(targets)}{scope_section}\n\n"
                f"You are the Shannon {analysis_domain or 'general'} analysis agent. "
                "Use prior findings plus live tool probing to build a focused exploitation queue. "
                "If there is no concrete evidence in this domain, return {\"findings\": []}.\n\n"
                f"Prior findings:\n{findings_json}\n"
            )
        if agent_role == "exploit":
            findings_json = json.dumps(prior_findings, indent=2) if prior_findings else "[]"
            return (
                f"Phase 4: Exploitation\n"
                f"Target(s): {', '.join(targets)}{scope_section}\n\n"
                f"You are the Shannon {analysis_domain or 'general'} exploit agent. "
                "Consume the queued candidates below and attempt real attacks via allowed tools only. "
                "Classify each item as EXPLOITED, POTENTIAL, or FALSE POSITIVE. "
                "Only return EXPLOITED findings with concrete evidence.\n\n"
                f"Queued candidates:\n{findings_json}\n"
            )
        if agent_role == "report":
            findings_json = json.dumps(prior_findings, indent=2) if prior_findings else "[]"
            return (
                f"Phase 5: Reporting\n"
                f"Target(s): {', '.join(targets)}{scope_section}\n\n"
                "Synthesize only confirmed evidence into a pentest-grade deliverable. "
                "Strip hypotheses, potential findings, and false positives. "
                "Return only findings backed by evidence refs.\n\n"
                f"Confirmed findings:\n{findings_json}\n"
            )
        if prior_findings:
            findings_json = json.dumps(prior_findings, indent=2)
            template = str(opts.get("query_template") or ("Target(s): {targets}{scope_section}\n\nPrior tool findings (verify each one with an active probe, enrich, and look for exploit chains):\n{findings_summary}\n\nAdditionally check for: {vuln_types}\n\nIMPORTANT: Only report a finding if you can probe it with a HexStrike tool and get evidence."))
            return template.format(target=targets[0], targets=", ".join(targets), vuln_types=", ".join(str(v) for v in vuln_types), mode=str(opts.get("mode") or "verify"), findings_summary=findings_json, scope_section=scope_section)
        if scope_section:
            return f"Target(s): {', '.join(targets)}{scope_section}\n\nCheck for: {', '.join(str(v) for v in vuln_types)}\n\nIMPORTANT: You MUST call a HexStrike probe tool for each endpoint before reporting any finding. Do NOT report findings without active probe evidence."
        template = str(opts.get("query_template") or ("Verify {targets} for {vuln_types} and report findings with proof-of-exploit steps.\n\nIMPORTANT: You MUST call a HexStrike probe tool for each endpoint before reporting any finding. Do NOT report findings without active probe evidence."))
        return template.format(target=targets[0], targets=", ".join(targets), vuln_types=", ".join(str(v) for v in vuln_types), mode=str(opts.get("mode") or "verify"))

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

    def _save_prompt_artifact(self, targets: List[str], opts: Dict[str, object]) -> Optional[str]:
        prompt_path = self._artifact_path("prompt.json")
        if not prompt_path:
            return None
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "targets": targets,
            "query": self._build_query(targets, opts),
            "driver": opts.get("driver", "http"),
            "mode": opts.get("mode", "verify"),
            "llm_provider": opts.get("llm_provider"),
            "model": opts.get("model"),
        }
        prompt_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self._emit_event("artifact_saved", {"run_id": self.run_id, "task_id": self.task_id, "path": str(prompt_path), "tool": self.id})
        return str(prompt_path)

    def _write_candidate_artifact(self, candidates: List[CandidateFinding]):
        if not candidates:
            return None
        return self.artifact_writer.write_json(
            run_id=self.run_id,
            relpath=f"{self.id}/{self.task_id}/candidates.json",
            kind="candidate_finding",
            obj={"candidates": [candidate.to_dict() for candidate in candidates]},
            source=self.id,
            task_id=self.task_id,
            metadata={"count": len(candidates)},
        )

    def _run_exploitation_queue(self, candidates: List[dict], opts: Dict[str, object]) -> Dict[str, ExploitResult]:
        results: Dict[str, ExploitResult] = {}
        session_pool = SessionPool()
        session_context = {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "session_id": f"{self.task_id}-session",
            "http_client": opts.get("exploit_http_client") or opts.get("http_client") or httpx.Client(timeout=float(opts.get("timeout_s") or 30)),
            "auth_headers": dict(opts.get("auth_headers") or {}),
            "playwright_factory": opts.get("playwright_factory"),
            "headless": bool(opts.get("headless", True)),
            "session_pool": session_pool,
            "session_bootstrapper": opts.get("session_bootstrapper"),
            "session_bootstrap_callable": opts.get("session_bootstrap_callable"),
            "session_credentials": list(opts.get("session_credentials") or opts.get("bootstrap_credentials") or get_default_bootstrap_credentials()),
            "idor_credentials": list(opts.get("idor_credentials") or opts.get("session_credentials") or opts.get("bootstrap_credentials") or get_default_bootstrap_credentials()),
            "admin_credentials": list(opts.get("admin_credentials") or get_default_admin_credentials()),
            "login_config": dict(opts.get("session_bootstrap_config") or {}),
        }
        for item in candidates:
            candidate_id = str(item.get("candidate_id") or "")
            claim_type = str(item.get("claim_type") or "")
            candidate_context = dict(session_context)
            candidate_context["target_url"] = str(item.get("target") or opts.get("target_url") or (candidates[0].get("target") if candidates else ""))
            handler = self._get_exploit_handler(claim_type, candidate_context)
            if handler is None:
                continue
            result = handler.run(candidate=item)
            results[candidate_id] = result
            self._persist_exploit_result(candidate_id, result)
        return results

    def _get_exploit_handler(self, claim_type: str, session_context: Dict[str, object]):
        handlers = {
            "idor": TwoUserIDORExploitHandler,
            "admin_exposure": AdminExposureExploitHandler,
            "auth_missing": AuthMissingExploitHandler,
            "xss": XSSExploitHandler,
            "reflected_xss": XSSExploitHandler,
            "stored_xss": XSSExploitHandler,
            "dom_xss": XSSExploitHandler,
            "sqli": SQLiExploitHandler,
            "sql_injection": SQLiExploitHandler,
            "nosql_injection": SQLiExploitHandler,
            "ssrf": SSRFExploitHandler,
            "upload_bug": UploadBugExploitHandler,
            "file_upload": UploadBugExploitHandler,
            "xxe": UploadBugExploitHandler,
            "yaml_injection": UploadBugExploitHandler,
            "business_logic": BusinessLogicExploitHandler,
            "payment_bypass": BusinessLogicExploitHandler,
            "workflow_bypass": BusinessLogicExploitHandler,
        }
        handler_class = handlers.get(claim_type)
        if handler_class is None:
            return None
        return handler_class(
            session_context=session_context,
            artifact_writer=self.artifact_writer,
            event_emitter=self._emit_event,
        )

    def _persist_exploit_result(self, candidate_id: str, result: ExploitResult) -> None:
        artifact = self.artifact_writer.write_json(
            run_id=self.run_id,
            relpath=f"exploits/{candidate_id}/exploit_result.json",
            kind="analysis_notes",
            obj=result.to_dict(),
            source=self.id,
            task_id=self.task_id,
            metadata={"candidate_id": candidate_id, "claim_type": result.claim_type, "classification": result.classification},
        )
        self._emit_event(
            "exploit_result_saved",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "candidate_id": candidate_id,
                "claim_type": result.claim_type,
                "classification": result.classification,
                "exploit_result_ref": artifact.relpath,
                "evidence_refs": list(result.final_evidence_refs),
            },
        )

    def _emit_event(self, event_type: str, payload: Dict[str, object]) -> None:
        if not self.runtime or not self.runtime.event_store:
            return
        self.runtime.event_store.emit({"event_type": event_type, "payload": payload})

    def _default_target_from_output(self, data: object) -> str:
        if isinstance(data, dict):
            target = data.get("target") or data.get("affected_target") or data.get("url")
            if isinstance(target, str) and target.strip():
                return target
        configured_target = self.options.get("target")
        if isinstance(configured_target, str) and configured_target.strip():
            return configured_target
        return "unknown"

    def _effective_options(self) -> Dict[str, object]:
        config = load_config()
        base = dict(config.get("shannon", {}))
        base.update(self.options)
        return base


def _verification_plan_from_dict(data: Dict[str, object]) -> VerificationPlan:
    checks = []
    for item in list(data.get("checks") or []):
        probe = item.get("probe_input") or {}
        condition = item.get("success_condition") or {}
        checks.append(
            VerificationCheck(
                check_id=str(item.get("check_id")),
                probe_type=str(item.get("probe_type")),
                description=str(item.get("description") or ""),
                probe_input=ProbeInput(
                    method=str(probe.get("method") or "GET"),
                    url=str(probe.get("url") or ""),
                    headers=dict(probe.get("headers") or {}),
                    query=dict(probe.get("query") or {}),
                    body=probe.get("body"),
                    follow_redirects=bool(probe.get("follow_redirects", False)),
                    timeout_s=int(probe.get("timeout_s") or 30),
                ),
                success_condition=SuccessCondition(type=str(condition.get("type") or "unknown"), rules=dict(condition.get("rules") or {})),
            )
        )
    return VerificationPlan(
        verification_id=str(data.get("verification_id")),
        candidate_id=str(data.get("candidate_id")),
        target=str(data.get("target")),
        claim_type=str(data.get("claim_type")),
        checks=checks,
        required_artifact_kinds=list(data.get("required_artifact_kinds") or []),
        planner_notes=str(data.get("planner_notes") or ""),
    )


def _bind_candidate_endpoint(plan: VerificationPlan, candidate: CandidateFinding) -> VerificationPlan:
    endpoint = str(candidate.endpoint or "").strip()
    if not endpoint:
        return plan
    bound_target = _join_candidate_target(str(candidate.target or ""), endpoint)
    checks: List[VerificationCheck] = []
    for check in plan.checks:
        probe_input = check.probe_input
        bound_url = _join_candidate_target(probe_input.url or str(candidate.target or ""), endpoint)
        checks.append(
            VerificationCheck(
                check_id=check.check_id,
                probe_type=check.probe_type,
                description=check.description,
                probe_input=ProbeInput(
                    method=probe_input.method,
                    url=bound_url,
                    headers=dict(probe_input.headers),
                    query=dict(probe_input.query),
                    body=probe_input.body,
                    follow_redirects=probe_input.follow_redirects,
                    timeout_s=probe_input.timeout_s,
                ),
                success_condition=SuccessCondition(
                    type=check.success_condition.type,
                    rules=dict(check.success_condition.rules),
                ),
            )
        )
    return VerificationPlan(
        verification_id=plan.verification_id,
        candidate_id=plan.candidate_id,
        target=bound_target,
        claim_type=plan.claim_type,
        checks=checks,
        required_artifact_kinds=list(plan.required_artifact_kinds),
        planner_notes=plan.planner_notes,
    )


def _join_candidate_target(target: str, endpoint: str) -> str:
    target = (target or "").strip()
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return target
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint
    if not target:
        return endpoint
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return urljoin(base.rstrip("/") + "/", endpoint.lstrip("/"))
    return endpoint


def _validator_decision_from_dict(data: Dict[str, object], evidence_refs: List[str]) -> ValidatorDecision:
    return ValidatorDecision(
        status=str(data.get("status")),
        final_claim_type=str(data.get("final_claim_type")),
        severity=str(data.get("severity")),
        rationale=str(data.get("rationale") or ""),
        duplicate_of=data.get("duplicate_of"),
        evidence_refs=list(evidence_refs),
    )


def _verifier_claim_type(candidate: CandidateFinding, plan: VerificationPlan) -> str:
    verifier_hint = str((candidate.metadata or {}).get("verifier_hint") or "")
    if verifier_hint == "probe_api_surface":
        return "api_surface_exposure" if candidate.claim_type == "api_surface_exposure" else plan.claim_type
    if verifier_hint == "probe_admin_access":
        return "admin_exposure"
    if verifier_hint == "probe_idor":
        return "idor"
    if verifier_hint == "probe_auth_missing":
        return "auth_missing"
    if verifier_hint == "probe_xss":
        return "xss"
    if verifier_hint == "probe_sqli":
        return "sqli"
    if verifier_hint == "probe_ssrf":
        return "ssrf"
    if verifier_hint == "probe_upload_bug":
        return "upload_bug"
    if verifier_hint == "probe_business_logic":
        return "business_logic"
    return plan.claim_type


def _route_probe_from_candidate(candidate: CandidateFinding, check: VerificationCheck) -> tuple[str, str, Dict[str, object]]:
    verifier_hint = str((candidate.metadata or {}).get("verifier_hint") or "")
    endpoint = str(check.probe_input.url)
    probe_type = check.probe_type
    tool_name = "probe"
    probe_input: Dict[str, object] = {
        "endpoint": endpoint,
        "method": check.probe_input.method,
        "follow_redirects": check.probe_input.follow_redirects,
    }
    if check.probe_input.headers:
        probe_input["headers"] = dict(check.probe_input.headers)
    if check.probe_input.query:
        probe_input["query"] = dict(check.probe_input.query)
    if check.probe_input.body is not None:
        probe_input["body"] = check.probe_input.body
    if verifier_hint == "probe_idor":
        probe_type = "http_idor_check"
    elif verifier_hint == "probe_admin_access":
        probe_type = "http_admin_access_check"
    elif verifier_hint == "probe_api_surface":
        probe_type = "http_api_surface_check"
    elif verifier_hint == "probe_auth_missing":
        probe_type = "http_auth_missing_check"
    elif verifier_hint == "probe_xss":
        probe_type = "http_xss_check"
    elif verifier_hint == "probe_sqli":
        probe_type = "http_sqli_check"
    elif verifier_hint == "probe_ssrf":
        probe_type = "http_ssrf_check"
    elif verifier_hint == "probe_upload_bug":
        probe_type = "http_upload_check"
    elif verifier_hint == "probe_business_logic":
        probe_type = "http_business_logic_check"
    return probe_type, tool_name, probe_input


def _normalise_vuln_item(item: Dict[str, object]) -> Dict[str, object]:
    return {
        "title": item.get("name") or item.get("title") or "Finding",
        "description": item.get("description") or item.get("proof_of_exploit") or "",
        "severity": str(item.get("severity") or "medium").lower(),
        "target": item.get("url") or item.get("target") or "",
        "repro_guidance": item.get("repro_guidance") or item.get("proof_of_exploit") or item.get("exploitation") or "",
        "repro_steps": item.get("repro_steps") or [],
        "evidence": item.get("evidence") or {},
    }


def _normalize_repro_steps(value: object) -> List[Dict[str, object]]:
    if not isinstance(value, list):
        return []
    steps: List[Dict[str, object]] = []
    for index, item in enumerate(value, start=1):
        if isinstance(item, dict):
            steps.append({"step": item.get("step") or index, "action": item.get("description") or item.get("action") or "reproduce finding", "expected_result": item.get("expected_result")})
        elif isinstance(item, str) and item.strip():
            steps.append({"step": index, "action": item.strip()})
    return steps


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
    if "ssrf" in text:
        return "SSRF"
    if re.search(r"\bsqli?\b|sql injection", text):
        return "SQLI"
    if "xxe" in text or "yaml" in text or "upload" in text:
        return "UPLOAD_BUG"
    if "business logic" in text or "payment bypass" in text or "workflow bypass" in text:
        return "BUSINESS_LOGIC"
    if "open redirect" in text or "redirect" in text:
        return "OPEN_REDIRECT"
    if "exposed docs" in text or "api docs" in text or "/docs/api" in text:
        return "EXPOSED_DOCS"
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
    return {"critical": 0.97, "high": 0.9, "medium": 0.72, "low": 0.55}.get(str(severity).lower(), 0.5)

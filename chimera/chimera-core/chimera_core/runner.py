"""
Hadles the safe and observable execution of an ExecutionPlan.

The Runner is the component that actually invokes the tool adapters. It manages
the job queue, worker pools for concurrency, and enforces safety policies like
rate limiting and circuit breaking.
"""
import asyncio
import hashlib
import json
import time
from contextlib import contextmanager
from types import SimpleNamespace

from chimera_core.planner import ExecutionPlan, Task
from chimera_core.context import RunContext
from chimera_core.adapters.net_utils_adapter import NetUtilsAdapter
from chimera_core.adapters.autoswagger_adapter import AutoswaggerAdapter
from chimera_core.adapters.browser_adapter import BrowserAdapter
from chimera_core.adapters.hexstrike_adapter import HexStrikeAdapter
from chimera_core.adapters.strix_adapter import StrixAdapter
from chimera_core.adapters.zap_adapter import ZapAdapter
from chimera_core.adapters.subfinder_adapter import SubfinderAdapter
from chimera_core.adapters.shannon_adapter import (
    ShannonAdapter,
    _bind_candidate_endpoint,
    _route_probe_from_candidate,
    _validator_decision_from_dict,
    _verification_plan_from_dict,
    _verifier_claim_type,
)
from chimera_core.artifacts import ArtifactWriter
from chimera_core.chain_analysis import ChainRecord, synthesize_chains
from chimera_core.finding_cache import FindingCache, fingerprint_claim
from chimera_core.findings import Finding
from chimera_core.findings_gate import PromotionDecision, promote_validated_finding
from chimera_core.hexstrike.executor import HexStrikeCall, HexStrikeExecutor
from chimera_core.policy.kernel import ExecutionContext, PolicyKernel, ToolCall
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.recon_gatherers.decepticon_adapter import DecepticonAdapter
from chimera_core.modules.recon_gatherers.schemas import Artifact as ReconArtifact
from chimera_core.modules.recon_gatherers.schemas import Finding as ReconFinding
from chimera_core.modules.recon_gatherers.schemas import ReconBundle
from chimera_core.modules.recon_gatherers.vibepentester_adapter import VibePenTesterAdapter
from chimera_core.modules.recon_gatherers.zypheron_adapter import ZypheronAdapter
from chimera_core.scheduler import Scheduler # Import Scheduler
from chimera_core.scope import ScopeGraph, ScopePolicy # Import ScopeGraph and ScopePolicy
from typing import List, Optional, Any, Dict
from datetime import datetime, UTC
from pathlib import Path
from collections import deque
from dataclasses import dataclass
import httpx

from chimera_core.plan import ExecutionPlan as DagPlan, Task as DagTask
from chimera_core.runtime import Runtime, RuntimeCancelledError
from chimera_core.logging import log_event, setup_logging
from chimera_core.shannon.schemas import AttackContract, CandidateFinding, VerificationCheck
from chimera_core.validators.auth_validator import AuthComparatorValidator
from chimera_core.validators.bola_validator import BOLAValidator
from chimera_core.validators.jwt_validator import JWTValidator
from chimera_core.validators.rate_limit_validator import RateLimitValidator
from chimera_core.verifiers.base import VerificationResult
from chimera_core.verifiers.registry import VerifierRegistry

# Maps finding_type → validator tool name for auto-dispatch.
# Only types backed by a deterministic validator are included.
FINDING_TYPE_TO_VALIDATOR: Dict[str, str] = {
    "IDOR":        "bola_validator",
    "JWT":         "jwt_validator",
    "RATE_LIMIT":  "rate_limit_validator",
    "BROKEN_AUTH": "auth_validator",
}

# Auto-inject validators only after these oracle/LLM adapters complete.
# Recon tools (strix, autoswagger) produce preliminary findings — let
# Shannon/HexStrike enrich them first before running expensive validators.
_ORACLE_ADAPTERS = frozenset({"shannon", "hexstrike", "vibepentester"})


class Runner:
    """
    Executes a DAG of tasks from an ExecutionPlan.
    """
    def __init__(self, plan: ExecutionPlan, context: RunContext, scope_graph: ScopeGraph, scope_policy: ScopePolicy, event_sink: Optional[Any] = None, adapters: Optional[Dict[str, Any]] = None, artifacts_root: Optional[Path] = None):
        self.plan = plan
        self.context = context
        self.scope_graph = scope_graph # Store scope_graph
        self.scope_policy = scope_policy # Store scope_policy
        self.event_sink = event_sink
        self.adapters = adapters or {}
        self.artifacts_root = artifacts_root # Explicitly define artifacts_root
        self.scheduler = Scheduler(plan) # Instantiate Scheduler

    def _emit_event(self, event_type: str, payload: dict):
        if self.event_sink:
            event = {
                "event_type": event_type,
                "timestamp": datetime.now(UTC).isoformat(),
                "payload": payload,
            }
            self.event_sink.emit(event)

    def execute(self) -> List[Finding]:
        """
        Starts the execution of the plan.
        """
        print("[Runner] Starting execution of plan...")
        # Get execution order from the scheduler
        ready_tasks = self.scheduler.get_execution_order()
        all_findings = []

        for task in ready_tasks:
            print(f"[Runner] Executing task: {task}")
            self._emit_event("task_started", {"job_id": self.context.job_id, "task_id": task.task_id, "tool": task.tool, "target": task.target, "options": task.options})
            
            adapter = self.adapters.get(task.tool)
            if adapter:
                # Update adapter with task-specific run/task IDs and artifacts root
                adapter.run_id = self.context.job_id
                adapter.task_id = task.task_id
                adapter.scope_graph = self.scope_graph # Corrected: use Runner's own scope_graph
                adapter.scope_policy = self.scope_policy # Corrected: use Runner's own scope_policy
                adapter.artifacts_root = self.artifacts_root # Pass artifacts_root from Runner
                
                # For autoswagger, targets should be passed to run() directly
                run_output = adapter.run([task.target]) 
                findings = adapter.normalize(run_output["raw_output_refs"][0])
                all_findings.extend(findings)
                print(f"[Runner] Task {task.task_id} produced {len(findings)} findings.")

                for finding in findings:
                    # Emit individual finding events
                    self._emit_event("finding_emitted", {"job_id": self.context.job_id, "task_id": task.task_id, "finding": finding.to_dict()})

                for artifact in run_output.get("artifacts", []):
                    # Emit artifact events
                    self._emit_event("artifact_saved", {"job_id": self.context.job_id, "task_id": task.task_id, **artifact})

            else:
                print(f"[Runner] Warning: No adapter found for tool '{task.tool}'. Skipping task.")
                self._emit_event("task_failed", {"job_id": self.context.job_id, "task_id": task.task_id, "error_message": f"No adapter for tool {task.tool}"})

            self._emit_event("task_finished", {"job_id": self.context.job_id, "task_id": task.task_id, "status": "completed"})

        print("[Runner] Execution of plan finished.")
        return all_findings


@dataclass
class TaskResult:
    task_id: str
    findings: List[Finding]
    status: str
    artifacts: List[Dict[str, object]] | None = None
    error: Optional[str] = None


class PlanRunner:
    def __init__(
        self,
        runtime: Runtime,
        max_workers: int = 2,
        stop_on_fail: bool = True,
        fixture_registry: Optional[Dict[str, str]] = None,
    ) -> None:
        self.runtime = runtime
        self.max_workers = max_workers
        self.stop_on_fail = stop_on_fail
        self.fixture_registry = fixture_registry or {}
        self.peak_concurrency = 0
        self.logger = setup_logging()
        self._autoswagger_endpoints: Dict[str, List[Dict[str, object]]] = {}
        self._findings_by_target: Dict[str, List[Finding]] = {}
        self._recon_bundles_by_target: Dict[str, List[ReconBundle]] = {}
        self.artifact_writer = ArtifactWriter(self.runtime.artifacts_root, event_store=self.runtime.event_store)
        self.finding_cache = FindingCache(Path(self.runtime.artifacts_root) / "_finding_cache.json")
        self.verifier_registry = VerifierRegistry()

    def _finding_matches_domain(self, finding: Finding, domain: str) -> bool:
        haystack = " ".join(
            [
                str(finding.finding_type or ""),
                str(finding.title or ""),
                str(finding.description or ""),
            ]
        ).lower()
        keywords = {
            "injection": ("sqli", "sql injection", "nosql", "command injection", "injection"),
            "xss": ("xss", "cross site scripting", "dom xss"),
            "ssrf": ("ssrf", "server-side request forgery"),
            "auth": ("auth", "login", "jwt", "session", "oauth", "broken authentication", "auth exposure"),
            "authz": ("idor", "bola", "authorization", "access control", "authz"),
            "upload": ("upload", "xxe", "yaml", "multipart", "file parser", "file upload"),
            "business": ("business logic", "workflow", "checkout", "payment bypass", "coupon", "membership"),
        }
        return any(keyword in haystack for keyword in keywords.get(domain, (domain,)))

    def _relevant_prior_findings(self, target: str, domain: str | None = None) -> List[Finding]:
        findings = list(self._findings_by_target.get(target, []))
        if not domain:
            return findings
        return [finding for finding in findings if self._finding_matches_domain(finding, domain)]

    def _skip_reason_for_task(self, task: DagTask) -> str | None:
        if task.tool != "shannon":
            return None
        agent_role = str(task.options.get("agent_role") or "")
        analysis_domain = str(task.options.get("analysis_domain") or "")
        if agent_role == "exploit":
            # Live/agent-flow tasks self-discover candidates via /agent — let the adapter
            # run and return empty results if there is nothing to exploit.
            # Non-live (fixture) tasks have no discovery path, so skip them when the
            # analysis queue is empty to avoid running stale raw_output_override data.
            is_live_agent = bool(task.options.get("live")) or self._uses_shannon_agent_runtime(task.options)
            if not is_live_agent and not self._relevant_prior_findings(task.target, analysis_domain):
                return f"no_analysis_queue:{analysis_domain or 'unknown'}"
        if agent_role == "report":
            if not self._relevant_prior_findings(task.target):
                return "no_verified_findings"
        return None

    def _uses_shannon_agent_runtime(self, options: Dict[str, object]) -> bool:
        return bool(options.get("agent_flow")) or str(options.get("shannon_runtime") or "").strip().lower() == "autonomous"

    def _parse_autoswagger_output(self, raw_output: str) -> List[Dict[str, object]]:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            start = raw_output.find("{")
            end = raw_output.rfind("}")
            if start == -1 or end == -1 or end <= start:
                return []
            try:
                data = json.loads(raw_output[start : end + 1])
            except json.JSONDecodeError:
                return []
        results = data.get("results")
        if isinstance(results, list):
            return results
        endpoints = data.get("endpoints")
        if isinstance(endpoints, list):
            return endpoints
        return []

    def _augment_strix_options(self, task: DagTask, options: Dict[str, object]) -> Dict[str, object]:
        endpoints = self._autoswagger_endpoints.get(task.target)
        if not endpoints:
            return options
        lines = ["Autoswagger endpoints (seed these paths):"]
        for item in endpoints:
            method = str(item.get("method", "GET")).upper()
            url = item.get("url") or item.get("path") or ""
            if not url:
                continue
            lines.append(f"- {method} {url}")
        if len(lines) == 1:
            return options
        addendum = "\n".join(lines)
        instruction = options.get("instruction")
        if instruction:
            instruction = f"{instruction}\n\n{addendum}"
        else:
            instruction = addendum
        options["instruction"] = instruction
        return options

    def _adapter_for_task(self, task: DagTask):
        options = dict(task.options)
        if task.tool == "strix":
            options = self._augment_strix_options(task, options)
        options["live"] = self.runtime.mode == "live"
        if not options.get("live", False):
            fixture_path = self.fixture_registry.get(task.tool)
            if fixture_path:
                options["fixture_path"] = fixture_path
        if task.tool == "net-utils":
            return NetUtilsAdapter(
                scope_graph=self.runtime.scope_graph,
                scope_policy=self.runtime.scope_policy,
                options=options,
                rate_limits={},
                run_id=self.runtime.run_id,
                task_id=task.task_id,
                artifacts_root=self.runtime.artifacts_root / self.runtime.run_id,
            )
        if task.tool == "autoswagger":
            return AutoswaggerAdapter(
                runtime=self.runtime,
                options=options,
                run_id=self.runtime.run_id,
                task_id=task.task_id,
                scope_hash="scope-hash",
            )
        if task.tool == "shannon":
            return ShannonAdapter(
                runtime=self.runtime,
                options=options,
                run_id=self.runtime.run_id,
                task_id=task.task_id,
                scope_hash="scope-hash",
            )
        if task.tool == "subfinder":
            return SubfinderAdapter(
                runtime=self.runtime,
                options=options,
                run_id=self.runtime.run_id,
                task_id=task.task_id,
                scope_hash="scope-hash",
            )
        if task.tool == "browser":
            return BrowserAdapter(
                runtime=self.runtime,
                options=options,
                run_id=self.runtime.run_id,
                task_id=task.task_id,
                scope_hash="scope-hash",
            )
        if task.tool == "zap":
            return ZapAdapter(
                runtime=self.runtime,
                options=options,
                run_id=self.runtime.run_id,
                task_id=task.task_id,
                scope_hash="scope-hash",
            )
        if task.tool == "hexstrike":
            return HexStrikeAdapter(
                runtime=self.runtime,
                options=options,
                run_id=self.runtime.run_id,
                task_id=task.task_id,
                scope_hash="scope-hash",
            )
        if task.tool == "strix":
            return StrixAdapter(
                runtime=self.runtime,
                options=options,
                rate_limits={"requests_per_second": self.runtime.scope_policy.max_rps},
                run_id=self.runtime.run_id,
                task_id=task.task_id,
                scope_hash="scope-hash",
            )
        raise ValueError(f"Unsupported tool: {task.tool}")

    def _record_findings(self, target: str, findings: List[Finding]) -> None:
        self._findings_by_target.setdefault(target, []).extend(findings)

    def _candidate_from_payload(self, task: DagTask, payload: Dict[str, object]) -> CandidateFinding | None:
        claim_type = str(payload.get("claim_type") or "").strip()
        if not claim_type:
            return None
        target_spec = dict(payload.get("metadata", {}).get("target") or {})
        endpoint = str(payload.get("endpoint") or target_spec.get("endpoint") or "") or None
        target = str(payload.get("target") or target_spec.get("url") or task.target)
        return CandidateFinding(
            candidate_id=str(payload.get("candidate_id") or f"{task.task_id}-candidate"),
            source=str(payload.get("source") or "shannon-agent"),
            title=str(payload.get("title") or "Shannon Candidate"),
            claim_type=claim_type,
            severity_claimed=str(payload.get("severity_claimed") or "medium"),
            endpoint=endpoint,
            target=target,
            params=list(payload.get("params") or []),
            narrative=str(payload.get("narrative") or ""),
            evidence_refs=list(payload.get("evidence_refs") or []),
            metadata=dict(payload.get("metadata") or {}),
        )

    def _candidate_findings_from_output(self, task: DagTask, output: Dict[str, object]) -> List[CandidateFinding]:
        def _dedupe(items: List[CandidateFinding]) -> List[CandidateFinding]:
            seen_ids = set()
            deduped: List[CandidateFinding] = []
            for candidate in items:
                if candidate.candidate_id in seen_ids:
                    continue
                seen_ids.add(candidate.candidate_id)
                deduped.append(candidate)
            return deduped

        explicit = list(output.get("candidate_findings") or [])
        normalized: List[CandidateFinding] = []
        for item in explicit:
            if isinstance(item, CandidateFinding):
                normalized.append(item)
            elif isinstance(item, dict):
                candidate = self._candidate_from_payload(task, item)
                if candidate is not None:
                    normalized.append(candidate)
        if normalized:
            return _dedupe(normalized)
        if task.tool != "shannon":
            return []

        raw_output_refs = list(output.get("raw_output_refs") or [])
        if not raw_output_refs:
            return []
        raw_text = raw_output_refs[0]
        if not isinstance(raw_text, str) or not raw_text.strip():
            return []
        try:
            raw = json.loads(raw_text)
        except json.JSONDecodeError:
            return []

        candidate_payloads = []
        if isinstance(raw.get("candidates"), list):
            candidate_payloads = list(raw.get("candidates") or [])
        else:
            agent_payload = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
            if isinstance(agent_payload.get("new_candidates"), list):
                candidate_payloads = list(agent_payload.get("new_candidates") or [])
            elif isinstance(agent_payload.get("findings"), list):
                candidate_payloads = list(agent_payload.get("findings") or [])
            elif isinstance(raw.get("findings"), list) and raw.get("findings") and isinstance(raw.get("findings")[0], dict) and raw.get("findings")[0].get("claim_type"):
                candidate_payloads = list(raw.get("findings") or [])

        for item in candidate_payloads:
            if not isinstance(item, dict):
                continue
            candidate = self._candidate_from_payload(task, item)
            if candidate is not None:
                normalized.append(candidate)
        return _dedupe(normalized)

    def _scope_manifest(self) -> Dict[str, object]:
        return {
            "allowlist": list(getattr(self.runtime.scope_graph, "allowed_domains", [])),
            "denylist": list(getattr(self.runtime.scope_graph, "denied_patterns", [])),
        }

    def _policy_context(self, scope_manifest: dict) -> ExecutionContext:
        return ExecutionContext(
            allowlist=list(scope_manifest.get("allowlist") or []),
            denylist=list(scope_manifest.get("denylist") or []),
            allowed_methods=list(scope_manifest.get("allowed_methods") or self.runtime.scope_policy.allowed_methods or []),
            runtime_mode=str(self.runtime.mode or "live"),
        )

    def _policy_kernel(self) -> PolicyKernel:
        return PolicyKernel()

    def _candidate_target_spec(self, candidate: CandidateFinding) -> Dict[str, object]:
        return dict((candidate.metadata or {}).get("target") or {})

    def _candidate_method(self, candidate: CandidateFinding) -> str:
        target_spec = self._candidate_target_spec(candidate)
        return str(target_spec.get("method") or "GET").upper()

    def _candidate_risk_class(self, candidate: CandidateFinding) -> str:
        metadata = dict(candidate.metadata or {})
        declared = str(metadata.get("risk_class") or "").strip().lower()
        if declared in {"passive", "low_impact", "state_changing", "exploit_like"}:
            return declared
        method = self._candidate_method(candidate)
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return "state_changing"
        claim_type = str(candidate.claim_type or "").lower()
        if claim_type in {"rce", "ssti", "sqli", "command_injection", "template_injection"}:
            return "exploit_like"
        if claim_type in {"api_surface_exposure", "exposed_docs"}:
            return "passive"
        return "low_impact"

    def _build_attack_contract(self, candidate: CandidateFinding, task: DagTask) -> AttackContract:
        metadata = dict(candidate.metadata or {})
        auth_context = dict(metadata.get("auth_context") or {})
        method = self._candidate_method(candidate)
        risk_class = self._candidate_risk_class(candidate)
        max_requests = 5 if risk_class == "passive" else 8 if risk_class == "low_impact" else 3
        max_duration = int(task.options.get("verification_budget_seconds") or task.options.get("timeout_s") or 120)
        preconditions = [
            "target_in_scope",
            f"method_{method.lower()}_allowed",
        ]
        if candidate.endpoint:
            preconditions.append("endpoint_resolved")
        if auth_context.get("authenticated"):
            preconditions.append(f"identity_role:{auth_context.get('role') or 'authenticated'}")
        forbidden_actions = ["external_callbacks", "file_upload"]
        if risk_class in {"passive", "low_impact"}:
            forbidden_actions.extend(["POST", "PUT", "PATCH", "DELETE"])
        elif risk_class == "state_changing":
            forbidden_actions.append("DELETE")
        success_signal = str(metadata.get("success_condition") or f"Verifier confirms {candidate.claim_type} with independent evidence.")
        return AttackContract(
            contract_id=f"{task.task_id}:{candidate.candidate_id}:contract",
            hypothesis_id=candidate.candidate_id,
            claim_type=str(candidate.claim_type or "unknown"),
            target=str(candidate.target or task.target),
            allowed_actions=["hexstrike_probe", "response_diffing", "session_reset", "browser_navigation"],
            preconditions=preconditions,
            forbidden_actions=forbidden_actions,
            success_signals=[success_signal],
            failure_signals=[
                "Policy rejection or deferral before execution.",
                "Verifier fails to reproduce expected signal.",
                "Budget exhausted without producing evidence.",
            ],
            budget={"max_requests": max_requests, "max_duration_sec": max_duration},
            risk_class=risk_class,
            metadata={
                "candidate_title": candidate.title,
                "endpoint": candidate.endpoint,
                "method": method,
                "analysis_domain": task.options.get("analysis_domain"),
            },
        )

    def _tool_call_for_contract(self, contract: AttackContract) -> ToolCall:
        method = str(contract.metadata.get("method") or "GET").upper()
        return ToolCall(
            tool="attack_contract",
            target=contract.target,
            action_class=contract.risk_class,
            risk_class=contract.risk_class,
            method=method,
            metadata={"contract_id": contract.contract_id, "claim_type": contract.claim_type},
        )

    def _tool_call_for_check(self, contract: AttackContract, check: VerificationCheck) -> ToolCall:
        return ToolCall(
            tool="hexstrike",
            target=check.probe_input.url,
            action_class=contract.risk_class,
            risk_class=contract.risk_class,
            method=str(check.probe_input.method or "GET").upper(),
            metadata={
                "contract_id": contract.contract_id,
                "verification_id": check.check_id,
                "probe_type": check.probe_type,
            },
        )

    def _candidate_verification_client(self, task: DagTask):
        client = task.options.get("http_client")
        if client is not None:
            return client, False
        return httpx.Client(timeout=float(task.options.get("timeout_s") or 120)), True

    def _finding_from_promoted_payload(self, payload: Dict[str, object], candidate: CandidateFinding) -> Finding:
        affected_target = str(payload.get("affected_target") or candidate.target or "unknown")
        claim_type = str(payload.get("claim_type") or candidate.claim_type or "")
        endpoint = str(payload.get("endpoint") or candidate.endpoint or "") or None
        host = self._host_from_target(affected_target)
        asset_endpoint = endpoint or self._path_from_target(affected_target)
        return Finding(
            finding_id=str(payload.get("finding_id") or candidate.candidate_id),
            severity=str(payload.get("severity") or candidate.severity_claimed or "medium"),
            title=str(payload.get("title") or candidate.title),
            description=str(payload.get("rationale") or ""),
            affected_target=affected_target,
            tool_source=str(payload.get("source") or candidate.source or "shannon"),
            tool_version="shannon-core",
            run_id=self.runtime.run_id,
            scope_hash="scope-hash",
            evidence_refs=list(payload.get("evidence_refs") or []),
            status=str(payload.get("status") or "verified"),
            finding_type=claim_type.upper() if claim_type else None,
            confidence=0.95 if str(payload.get("status") or "") in {"verified", "downgraded"} else None,
            asset={
                "host": host,
                "endpoint": asset_endpoint,
                "method": None,
                "parameter": None,
            },
        )

    def process_candidate_finding(
        self,
        *,
        run_id: str,
        candidate: CandidateFinding,
        scope_manifest: dict,
        task: DagTask,
        prior_findings: Optional[List[Finding]] = None,
    ) -> tuple[PromotionDecision, List[Dict[str, object]]]:
        fingerprint = fingerprint_claim(
            claim_type=candidate.claim_type,
            target=candidate.target,
            endpoint=candidate.endpoint,
            params=candidate.params,
        )
        cached_finding = self.finding_cache.get_verified(fingerprint)
        if cached_finding is not None:
            self.runtime.event_store.emit(
                {
                    "event_type": "verification_skipped",
                    "payload": {
                        "run_id": run_id,
                        "task_id": task.task_id,
                        "candidate_id": candidate.candidate_id,
                        "reason": "cache_hit",
                    },
                }
            )
            return PromotionDecision(True, "verified", "cache_hit", cached_finding), []

        base_url = str(task.options.get("base_url") or "http://localhost:8080").rstrip("/")
        client, close_client = self._candidate_verification_client(task)
        artifacts: List[Dict[str, object]] = []
        policy_kernel = self._policy_kernel()
        policy_context = self._policy_context(scope_manifest)
        try:
            attack_contract = self._build_attack_contract(candidate, task)
            contract_artifact = self.artifact_writer.write_json(
                run_id=run_id,
                relpath=f"contracts/{attack_contract.contract_id}.json",
                kind="attack_contract",
                obj=attack_contract.to_dict(),
                source="chimera",
                task_id=task.task_id,
                metadata={"candidate_id": candidate.candidate_id, "claim_type": attack_contract.claim_type},
            )
            artifacts.append({"path": contract_artifact.relpath, "artifact_type": "attack_contract", "tool": task.tool})
            self.runtime.event_store.emit(
                {
                    "event_type": "attack_contract_created",
                    "payload": {
                        "run_id": run_id,
                        "task_id": task.task_id,
                        "candidate_id": candidate.candidate_id,
                        "contract_id": attack_contract.contract_id,
                        "risk_class": attack_contract.risk_class,
                        "artifact_ref": contract_artifact.relpath,
                    },
                }
            )
            contract_policy = policy_kernel.evaluate(self._tool_call_for_contract(attack_contract), policy_context)
            contract_policy_artifact = self.artifact_writer.write_json(
                run_id=run_id,
                relpath=f"contracts/{attack_contract.contract_id}.policy.json",
                kind="policy_decision",
                obj={
                    "decision": contract_policy.to_dict(),
                    "tool_call": self._tool_call_for_contract(attack_contract).to_dict(),
                    "context": policy_context.to_dict(),
                },
                source="chimera",
                task_id=task.task_id,
                metadata={"candidate_id": candidate.candidate_id, "contract_id": attack_contract.contract_id},
            )
            artifacts.append({"path": contract_policy_artifact.relpath, "artifact_type": "policy_decision", "tool": task.tool})
            self.runtime.event_store.emit(
                {
                    "event_type": "policy_decision_recorded",
                    "payload": {
                        "run_id": run_id,
                        "task_id": task.task_id,
                        "candidate_id": candidate.candidate_id,
                        "contract_id": attack_contract.contract_id,
                        "decision": contract_policy.decision,
                        "matched_rule": contract_policy.matched_rule,
                        "policy_ref": contract_policy_artifact.relpath,
                    },
                }
            )
            if contract_policy.decision != "allow":
                event_type = "attack_contract_deferred" if contract_policy.decision == "defer" else "attack_contract_denied"
                self.runtime.event_store.emit(
                    {
                        "event_type": event_type,
                        "payload": {
                            "run_id": run_id,
                            "task_id": task.task_id,
                            "candidate_id": candidate.candidate_id,
                            "contract_id": attack_contract.contract_id,
                            "reason": contract_policy.reason,
                        },
                    }
                )
                return PromotionDecision(False, contract_policy.decision, contract_policy.reason, None), artifacts

            plan_resp = client.post(
                f"{base_url}/plan",
                json={
                    "run_id": run_id,
                    "candidate": candidate.to_dict(),
                    "prior_evidence_refs": list(candidate.evidence_refs),
                    "scope_summary": {"allowlist": list(scope_manifest.get("allowlist") or [])},
                },
            )
            plan_resp.raise_for_status()
            verification_plan = _verification_plan_from_dict(plan_resp.json()["verification_plan"])
            verification_plan = _bind_candidate_endpoint(verification_plan, candidate)
            plan_artifact = self.artifact_writer.write_json(
                run_id=run_id,
                relpath=f"verifications/{verification_plan.verification_id}/plan.json",
                kind="verification_plan",
                obj=verification_plan.to_dict(),
                source="chimera",
                task_id=task.task_id,
                metadata={
                    "candidate_id": candidate.candidate_id,
                    "claim_type": verification_plan.claim_type,
                    "contract_id": attack_contract.contract_id,
                },
            )
            artifacts.append({"path": plan_artifact.relpath, "artifact_type": "verification_plan", "tool": task.tool})
            self.runtime.event_store.emit(
                {
                    "event_type": "verification_planned",
                    "payload": {
                        "run_id": run_id,
                        "task_id": task.task_id,
                        "candidate_id": candidate.candidate_id,
                        "verification_id": verification_plan.verification_id,
                        "claim_type": verification_plan.claim_type,
                        "contract_id": attack_contract.contract_id,
                        "plan_artifact_ref": plan_artifact.relpath,
                    },
                }
            )

            executor = HexStrikeExecutor(
                runtime=self.runtime,
                base_url=str(task.options.get("hexstrike_base_url") or "http://hexstrike:8888"),
                artifact_writer=self.artifact_writer,
                transport=task.options.get("hexstrike_transport"),
            )
            verification_results: List[VerificationResult] = list(self._exploit_verification_results(candidate))
            evidence_refs: List[str] = [
                ref
                for result in verification_results
                for ref in list(result.evidence_refs or [])
                if isinstance(ref, str) and ref
            ]
            deadline = time.monotonic() + int(attack_contract.budget.get("max_duration_sec") or 0)
            remaining_requests = int(attack_contract.budget.get("max_requests") or 0)
            for check in verification_plan.checks:
                if remaining_requests <= 0 or (attack_contract.budget.get("max_duration_sec") and time.monotonic() > deadline):
                    verification_result = VerificationResult(
                        verification_id=verification_plan.verification_id,
                        check_id=check.check_id,
                        claim_type=_verifier_claim_type(candidate, verification_plan),
                        outcome="failed",
                        rationale="Attack contract budget exhausted before executing this check.",
                        evidence_refs=[],
                        extracted_targets=[str(check.probe_input.url or "")] if check.probe_input.url else [],
                        metadata={"contract_id": attack_contract.contract_id, "reason": "budget_exhausted"},
                    )
                    verification_results.append(verification_result)
                    verification_artifact = self.artifact_writer.write_json(
                        run_id=run_id,
                        relpath=f"verifications/{verification_plan.verification_id}/{check.check_id}-result.json",
                        kind="verification_result",
                        obj=verification_result.to_dict(),
                        source="chimera",
                        task_id=task.task_id,
                    )
                    artifacts.append({"path": verification_artifact.relpath, "artifact_type": "verification_result", "tool": task.tool})
                    self.runtime.event_store.emit(
                        {
                            "event_type": "verification_failed",
                            "payload": {
                                "run_id": run_id,
                                "task_id": task.task_id,
                                "candidate_id": candidate.candidate_id,
                                "verification_id": verification_result.verification_id,
                                "check_id": verification_result.check_id,
                                "claim_type": verification_result.claim_type,
                                "verification_result_ref": verification_artifact.relpath,
                                "evidence_refs": [],
                            },
                        }
                    )
                    break
                check_policy_call = self._tool_call_for_check(attack_contract, check)
                check_policy = policy_kernel.evaluate(check_policy_call, policy_context)
                if check_policy.decision != "allow":
                    policy_artifact = self.artifact_writer.write_json(
                        run_id=run_id,
                        relpath=f"verifications/{verification_plan.verification_id}/{check.check_id}-policy.json",
                        kind="policy_decision",
                        obj={
                            "decision": check_policy.to_dict(),
                            "tool_call": check_policy_call.to_dict(),
                            "context": policy_context.to_dict(),
                        },
                        source="chimera",
                        task_id=task.task_id,
                    )
                    artifacts.append({"path": policy_artifact.relpath, "artifact_type": "policy_decision", "tool": task.tool})
                    self.runtime.event_store.emit(
                        {
                            "event_type": "policy_decision_recorded",
                            "payload": {
                                "run_id": run_id,
                                "task_id": task.task_id,
                                "candidate_id": candidate.candidate_id,
                                "verification_id": verification_plan.verification_id,
                                "check_id": check.check_id,
                                "decision": check_policy.decision,
                                "matched_rule": check_policy.matched_rule,
                                "policy_ref": policy_artifact.relpath,
                            },
                        }
                    )
                    verification_result = VerificationResult(
                        verification_id=verification_plan.verification_id,
                        check_id=check.check_id,
                        claim_type=_verifier_claim_type(candidate, verification_plan),
                        outcome="failed",
                        rationale=check_policy.reason,
                        evidence_refs=[],
                        extracted_targets=[str(check.probe_input.url or "")] if check.probe_input.url else [],
                        metadata={"contract_id": attack_contract.contract_id, "policy_decision": check_policy.to_dict()},
                    )
                    verification_results.append(verification_result)
                    verification_artifact = self.artifact_writer.write_json(
                        run_id=run_id,
                        relpath=f"verifications/{verification_plan.verification_id}/{check.check_id}-result.json",
                        kind="verification_result",
                        obj=verification_result.to_dict(),
                        source="chimera",
                        task_id=task.task_id,
                    )
                    artifacts.append({"path": verification_artifact.relpath, "artifact_type": "verification_result", "tool": task.tool})
                    self.runtime.event_store.emit(
                        {
                            "event_type": "verification_failed",
                            "payload": {
                                "run_id": run_id,
                                "task_id": task.task_id,
                                "candidate_id": candidate.candidate_id,
                                "verification_id": verification_result.verification_id,
                                "check_id": verification_result.check_id,
                                "claim_type": verification_result.claim_type,
                                "verification_result_ref": verification_artifact.relpath,
                                "evidence_refs": [],
                            },
                        }
                    )
                    continue
                probe_type, tool_name, probe_input = _route_probe_from_candidate(candidate, check)
                result = executor.execute_call(
                    run_id=run_id,
                    call=HexStrikeCall(
                        call_id=f"{verification_plan.verification_id}-{check.check_id}",
                        verification_id=verification_plan.verification_id,
                        check_id=check.check_id,
                        probe_type=probe_type,
                        tool_name=tool_name,
                        probe_input=probe_input,
                        task_id=task.task_id,
                    ),
                    scope_manifest=scope_manifest,
                )
                remaining_requests -= 1
                verifier = self.verifier_registry.get(_verifier_claim_type(candidate, verification_plan))
                verification_result = verifier.verify(run_id=run_id, plan=verification_plan, hexstrike_result=result)
                verification_results.append(verification_result)
                evidence_refs.extend(list(verification_result.evidence_refs))
                verification_artifact = self.artifact_writer.write_json(
                    run_id=run_id,
                    relpath=f"verifications/{verification_plan.verification_id}/{check.check_id}-result.json",
                    kind="verification_result",
                    obj=verification_result.to_dict(),
                    source="chimera",
                    task_id=task.task_id,
                )
                artifacts.append({"path": verification_artifact.relpath, "artifact_type": "verification_result", "tool": task.tool})
                self.runtime.event_store.emit(
                    {
                        "event_type": "verification_passed" if verification_result.outcome == "passed" else "verification_failed",
                        "payload": {
                            "run_id": run_id,
                            "task_id": task.task_id,
                            "candidate_id": candidate.candidate_id,
                            "verification_id": verification_result.verification_id,
                            "check_id": verification_result.check_id,
                            "claim_type": verification_result.claim_type,
                            "verification_result_ref": verification_artifact.relpath,
                            "evidence_refs": verification_result.evidence_refs,
                        },
                    }
                )

            validate_resp = client.post(
                f"{base_url}/validate",
                json={
                    "run_id": run_id,
                    "candidate": candidate.to_dict(),
                    "verification_results": [result.to_dict() for result in verification_results],
                    "evidence_refs": evidence_refs,
                    "prior_findings": [finding.to_dict() for finding in (prior_findings or [])],
                },
            )
            validate_resp.raise_for_status()
            validator_decision = _validator_decision_from_dict(validate_resp.json()["decision"], evidence_refs)
            validator_artifact = self.artifact_writer.write_json(
                run_id=run_id,
                relpath=f"verifications/{verification_plan.verification_id}/validator_decision.json",
                kind="validator_decision",
                obj=validator_decision.to_dict(),
                source="chimera",
                task_id=task.task_id,
                metadata={
                    "candidate_id": candidate.candidate_id,
                    "verification_id": verification_plan.verification_id,
                    "contract_id": attack_contract.contract_id,
                },
            )
            artifacts.append({"path": validator_artifact.relpath, "artifact_type": "validator_decision", "tool": task.tool})
            self.runtime.event_store.emit(
                {
                    "event_type": "validator_decision_recorded",
                    "payload": {
                        "run_id": run_id,
                        "task_id": task.task_id,
                        "candidate_id": candidate.candidate_id,
                        "verification_id": verification_plan.verification_id,
                        "decision_artifact_ref": validator_artifact.relpath,
                        "status": validator_decision.status,
                        "claim_type": validator_decision.final_claim_type,
                    },
                }
            )
            promotion = promote_validated_finding(
                run_id=run_id,
                candidate=candidate,
                validator_decision=validator_decision,
                verification_results=verification_results,
                artifact_writer=self.artifact_writer,
                event_store=self.runtime.event_store,
            )
            if promotion.finding is not None and promotion.status == "verified":
                self.finding_cache.put_verified(fingerprint, promotion.finding)
            return promotion, artifacts
        finally:
            if close_client and hasattr(client, "close"):
                client.close()

    def _exploit_verification_results(self, candidate: CandidateFinding) -> List[VerificationResult]:
        metadata = dict(candidate.metadata or {})
        exploit_result = dict(metadata.get("exploit_result") or {})
        if str(exploit_result.get("classification") or "").upper() != "EXPLOITED":
            return []
        evidence_refs = [ref for ref in list(exploit_result.get("final_evidence_refs") or []) if isinstance(ref, str) and ref]
        if not evidence_refs:
            return []
        verification_id = str(exploit_result.get("verification_id") or candidate.candidate_id)
        return [
            VerificationResult(
                verification_id=verification_id,
                check_id="exploit-result",
                claim_type=str(candidate.claim_type or exploit_result.get("claim_type") or "unknown"),
                outcome="passed",
                rationale="Deterministic exploit handler produced exploitable evidence.",
                evidence_refs=evidence_refs,
                extracted_targets=[str(candidate.target or "")] if candidate.target else [],
                metadata={"source": "exploit_result"},
            )
        ]

    def _process_candidate_findings(self, task: DagTask, candidates: List[CandidateFinding]) -> tuple[List[Finding], List[Dict[str, object]]]:
        processed: List[Finding] = []
        artifacts: List[Dict[str, object]] = []
        prior = self._relevant_prior_findings(task.target, str(task.options.get("analysis_domain") or "") or None)
        for candidate in candidates:
            promotion, candidate_artifacts = self.process_candidate_finding(
                run_id=self.runtime.run_id,
                candidate=candidate,
                scope_manifest=self._scope_manifest(),
                task=task,
                prior_findings=prior,
            )
            artifacts.extend(candidate_artifacts)
            if promotion.finding is not None:
                processed.append(self._finding_from_promoted_payload(promotion.finding, candidate))
        return processed, artifacts

    def _enrich_finding_metadata(self, finding: Finding) -> Finding:
        if not finding.asset:
            finding.asset = {
                "host": self._host_from_target(finding.affected_target),
                "endpoint": self._path_from_target(finding.affected_target),
                "method": None,
                "parameter": None,
            }
        if not finding.finding_type:
            title = f"{finding.title} {finding.description}".lower()
            if "idor" in title or "bola" in title:
                finding.finding_type = "IDOR"
            elif "jwt" in title:
                finding.finding_type = "JWT"
            elif "rate limit" in title:
                finding.finding_type = "RATE_LIMIT"
            elif "auth" in title or "exposure" in title:
                finding.finding_type = "AUTH_EXPOSURE"
            elif "xss" in title:
                finding.finding_type = "XSS"
        return finding

    def _host_from_target(self, target: str) -> str:
        if target.startswith("http://") or target.startswith("https://"):
            return httpx.URL(target).host
        return target.split("/")[0]

    def _path_from_target(self, target: str) -> str:
        if target.startswith("http://") or target.startswith("https://"):
            return httpx.URL(target).path or "/"
        parts = target.split("/", 1)
        return f"/{parts[1]}" if len(parts) > 1 else "/"

    def _with_default_validation_inputs(self, task: DagTask, findings: List[Finding]) -> Dict[str, object]:
        provided = dict(task.options.get("validation_inputs") or {})
        if task.tool == "rate_limit_validator":
            provided.setdefault("target_endpoint", task.target)
            provided.setdefault("burst_count", 5)
            return provided

        if task.tool == "bola_validator":
            candidate = next((finding for finding in findings if (finding.finding_type or "").upper() in {"IDOR", "BOLA"}), None)
            endpoint = provided.get("target_endpoint")
            if not endpoint and candidate and candidate.asset and candidate.asset.get("endpoint"):
                host = candidate.asset.get("host") or self._host_from_target(task.target)
                raw_endpoint = str(candidate.asset.get("endpoint"))
                endpoint = raw_endpoint if raw_endpoint.startswith("http") else f"https://{host}{raw_endpoint}"
            if not endpoint:
                endpoint = self._derive_object_endpoint(task.target)
            provided.setdefault("target_endpoint", endpoint or task.target)
            provided.setdefault("object_id", self._derive_object_id(candidate.affected_target if candidate else task.target))
            creds = (candidate.auth_context if candidate else None) or {}
            provided.setdefault("user_a_creds", creds.get("owner_credentials") or {"token": "owner-token"})
            provided.setdefault("user_b_creds", creds.get("peer_credentials") or {"token": "peer-token"})
            return provided

        if task.tool == "jwt_validator":
            token = provided.get("token")
            if not token:
                for finding in findings:
                    joined = " ".join([finding.description or "", finding.repro_guidance or "", *finding.evidence_refs])
                    if "eyj" in joined.lower():
                        for piece in joined.split():
                            cleaned = piece.strip("`'\",")
                            if cleaned.lower().startswith("eyj") and cleaned.count(".") >= 2:
                                token = cleaned
                                break
                    if token:
                        break
            if token:
                provided["token"] = token
            provided.setdefault("allowed_algs", ("HS256", "RS256"))
            return provided

        if task.tool == "auth_validator":
            candidate = next((finding for finding in findings if (finding.finding_type or "").upper() in {"AUTH_EXPOSURE", "BROKEN_AUTH"}), None)
            provided.setdefault("target_endpoint", candidate.affected_target if candidate else task.target)
            creds = (candidate.auth_context if candidate else None) or {}
            provided.setdefault("authenticated_creds", creds.get("owner_credentials") or {"token": "owner-token"})
            provided.setdefault("unauthenticated_headers", {})
            return provided

        return provided

    def _derive_object_endpoint(self, target: str) -> Optional[str]:
        endpoints = self._autoswagger_endpoints.get(target) or []
        for endpoint in endpoints:
            path = str(endpoint.get("url") or endpoint.get("path") or "")
            if "{id}" in path or "{object_id}" in path or "/users/" in path:
                if path.startswith("http"):
                    return path
                host = self._host_from_target(target)
                return f"https://{host}{path}"
        return None

    def _derive_object_id(self, target: str) -> str:
        parts = [part for part in target.strip("/").split("/") if part]
        for part in reversed(parts):
            if part.isdigit():
                return part
        return "1"

    def _artifact_sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _convert_recon_finding(self, task: DagTask, recon_finding: ReconFinding) -> Finding:
        finding_type = None
        tags = recon_finding.tags or []
        if tags:
            finding_type = tags[0].upper().replace("-", "_")
        finding = Finding(
            finding_id=f"{task.tool}:{task.task_id}:{recon_finding.title}",
            severity=recon_finding.severity,
            title=recon_finding.title,
            description=recon_finding.reproduction or "",
            affected_target=task.target,
            tool_source=task.tool,
            tool_version="integrated",
            run_id=self.runtime.run_id,
            scope_hash="scope-hash",
            evidence_refs=list(recon_finding.evidence_refs),
            repro_guidance=recon_finding.reproduction,
            finding_type=finding_type,
            confidence=float(recon_finding.confidence) if str(recon_finding.confidence or "").replace(".", "", 1).isdigit() else None,
            impact_path=[recon_finding.chain_metadata] if recon_finding.chain_metadata else [],
        )
        return self._enrich_finding_metadata(finding)

    @contextmanager
    def _mock_external_tool(self, result: SimpleNamespace):
        original = self.runtime.run_external_tool
        self.runtime.run_external_tool = lambda *args, **kwargs: result
        try:
            yield
        finally:
            self.runtime.run_external_tool = original

    def _fixture_result(self, *, stdout: str = "", stderr: str = "", exit_code: int = 0) -> SimpleNamespace:
        return SimpleNamespace(ok=exit_code == 0, exit_code=exit_code, stdout=stdout, stderr=stderr)

    def _fixture_path(self, task: DagTask) -> Optional[Path]:
        explicit = task.options.get("fixture_path")
        if explicit:
            return Path(str(explicit))
        registry = self.fixture_registry.get(task.tool)
        return Path(registry) if registry else None

    def _run_zypheron_task(self, task: DagTask) -> tuple[List[Finding], List[Dict[str, object]], ReconBundle]:
        adapter = ZypheronAdapter(runtime=self.runtime)
        fixture_path = self._fixture_path(task)
        if self.runtime.mode != "live":
            stdout = fixture_path.read_text(encoding="utf-8") if fixture_path and fixture_path.exists() else ""
            with self._mock_external_tool(self._fixture_result(stdout=stdout)):
                bundle = adapter.run_scan(task.target, timeout_s=task.options.get("timeout_s"))
        else:
            bundle = adapter.run_scan(task.target, timeout_s=task.options.get("timeout_s"))
        findings = [self._convert_recon_finding(task, finding) for finding in bundle.findings]
        artifacts = [{"path": artifact.path, "artifact_type": artifact.kind, "tool": task.tool} for artifact in bundle.artifacts]
        return findings, artifacts, bundle

    def _run_vibepentester_task(self, task: DagTask) -> tuple[List[Finding], List[Dict[str, object]], ReconBundle]:
        adapter = VibePenTesterAdapter(runtime=self.runtime)
        output_dir = Path(self.runtime.artifacts_root) / self.runtime.run_id / task.tool / task.task_id / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        config = VibePenTesterConfig(
            workdir=Path(task.options.get("workdir") or Path.cwd()),
            output_dir=output_dir,
            entrypoint=list(task.options.get("entrypoint") or ["python", "main.py"]),
            extra_args=list(task.options.get("extra_args") or []),
            timeout_s=int(task.options.get("timeout_s") or 1800),
        )
        fixture_path = self._fixture_path(task)
        if self.runtime.mode != "live":
            if fixture_path and fixture_path.exists():
                destination = output_dir / fixture_path.name
                destination.write_text(fixture_path.read_text(encoding="utf-8"), encoding="utf-8")
            with self._mock_external_tool(self._fixture_result(stdout="fixture", stderr="")):
                bundle = adapter.run_scan(target_url=task.target, config=config)
        else:
            bundle = adapter.run_scan(target_url=task.target, config=config)
        findings = [self._convert_recon_finding(task, finding) for finding in bundle.findings]
        artifacts = [{"path": artifact.path, "artifact_type": artifact.kind, "tool": task.tool} for artifact in bundle.artifacts]
        return findings, artifacts, bundle

    def _run_decepticon_task(self, task: DagTask) -> tuple[List[Finding], List[Dict[str, object]]]:
        bundles = list(self._recon_bundles_by_target.get(task.target, []))
        if not bundles:
            raise ValueError(f"No recon bundles available for decepticon target {task.target}")
        adapter = DecepticonAdapter(runtime=self.runtime)
        output_dir = Path(self.runtime.artifacts_root) / self.runtime.run_id / task.tool / task.task_id / "outputs"
        output_dir.mkdir(parents=True, exist_ok=True)
        config = VibePenTesterConfig(
            workdir=Path(task.options.get("workdir") or Path.cwd()),
            output_dir=output_dir,
            entrypoint=list(task.options.get("entrypoint") or ["python", "decepticon.py"]),
            extra_args=list(task.options.get("extra_args") or []),
            timeout_s=int(task.options.get("timeout_s") or 1800),
        )
        fixture_path = self._fixture_path(task)
        if self.runtime.mode != "live":
            if fixture_path and fixture_path.exists():
                destination = output_dir / fixture_path.name
                destination.write_text(fixture_path.read_text(encoding="utf-8"), encoding="utf-8")
            with self._mock_external_tool(self._fixture_result(stdout="fixture", stderr="")):
                enrichment = adapter.run_enrichment(bundles=bundles, config=config)
        else:
            enrichment = adapter.run_enrichment(bundles=bundles, config=config)

        findings: List[Finding] = [
            Finding(
                finding_id=f"decepticon:{task.task_id}:analysis",
                severity="info",
                title="Decepticon enrichment analysis",
                description=enrichment.notes_markdown,
                affected_target=task.target,
                tool_source="decepticon",
                tool_version="integrated",
                run_id=self.runtime.run_id,
                scope_hash="scope-hash",
                evidence_refs=[artifact.path for artifact in enrichment.artifacts],
            )
        ]
        findings.extend(self._convert_recon_finding(task, finding) for finding in enrichment.promoted_findings)

        notes_path = output_dir.parent / "notes.md"
        notes_path.write_text(enrichment.notes_markdown or "", encoding="utf-8")
        actions_path = output_dir.parent / "suggested_actions.json"
        actions_path.write_text(json.dumps([action.__dict__ for action in enrichment.suggested_actions], indent=2), encoding="utf-8")
        artifacts = [
            {"path": str(notes_path), "artifact_type": "analysis_notes", "tool": task.tool},
            {"path": str(actions_path), "artifact_type": "suggested_actions", "tool": task.tool},
        ]
        artifacts.extend({"path": artifact.path, "artifact_type": artifact.kind, "tool": task.tool} for artifact in enrichment.artifacts)
        return findings, artifacts

    def _validator_client(self, task: DagTask) -> Optional[httpx.AsyncClient]:
        transport = task.options.get("http_transport")
        if transport is None:
            return None
        return httpx.AsyncClient(transport=transport)

    def _write_validation_artifact(self, task: DagTask, finding: Finding, payload: Dict[str, object]) -> Dict[str, object]:
        safe_task_id = task.task_id.replace(":", "_").replace("/", "_").replace("\\", "_")
        validations_dir = Path(self.runtime.artifacts_root) / self.runtime.run_id / "validators" / safe_task_id
        try:
            validations_dir.mkdir(parents=True, exist_ok=True)
            artifact_path = validations_dir / f"{finding.finding_id}.json"
            artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return {"path": str(artifact_path), "artifact_type": "validation_result", "tool": task.tool}
        except Exception as exc:
            log_event("validation_artifact_write_failed", {"task_id": task.task_id, "finding_id": finding.finding_id, "error": str(exc)})
            return {"path": None, "artifact_type": "validation_result", "tool": task.tool}

    def _run_validator_task(self, task: DagTask) -> tuple[List[Finding], List[Dict[str, object]]]:
        findings = list(self._findings_by_target.get(task.target, []))
        validated: List[Finding] = []
        artifacts: List[Dict[str, object]] = []
        validation_inputs = self._with_default_validation_inputs(task, findings)

        if task.tool == "rate_limit_validator":
            targets = findings or [
                Finding(
                    finding_id=f"{task.task_id}:candidate",
                    severity="medium",
                    title="Rate limit candidate",
                    description="Generated from routed validator stage.",
                    affected_target=task.target,
                    tool_source=task.tool,
                    tool_version="integrated",
                    run_id=self.runtime.run_id,
                    scope_hash="scope-hash",
                    finding_type="RATE_LIMIT",
                )
            ]
            for finding in targets:
                client = self._validator_client(task)
                try:
                    result = asyncio.run(
                        RateLimitValidator().validate(
                            finding,
                            validation_inputs.get("target_endpoint", task.target),
                            burst_count=int(validation_inputs.get("burst_count", 5)),
                            client=client,
                        )
                    )
                finally:
                    if client is not None:
                        asyncio.run(client.aclose())
                self.runtime.event_store.emit(
                    {
                        "event_type": "FindingValidated",
                        "payload": {
                            "finding_id": finding.finding_id,
                            "validation_status": finding.validation_status,
                            "confidence": result.confidence,
                            "validator_name": task.tool,
                        },
                    }
                )
                artifacts.append(self._write_validation_artifact(task, finding, result.__dict__))
                validated.append(self._enrich_finding_metadata(finding))
            return validated, artifacts

        if task.tool == "bola_validator":
            candidates = [finding for finding in findings if (finding.finding_type or "").upper() in {"BOLA", "IDOR"}] or findings
            for finding in candidates:
                endpoint = validation_inputs.get("target_endpoint") or task.target
                object_id = validation_inputs.get("object_id")
                user_a_creds = validation_inputs.get("user_a_creds")
                user_b_creds = validation_inputs.get("user_b_creds")
                if not (object_id and user_a_creds and user_b_creds):
                    continue
                client = self._validator_client(task)
                try:
                    result = asyncio.run(
                        BOLAValidator().validate(
                            finding,
                            endpoint,
                            user_a_creds=user_a_creds,
                            user_b_creds=user_b_creds,
                            object_id=str(object_id),
                            client=client,
                        )
                    )
                finally:
                    if client is not None:
                        asyncio.run(client.aclose())
                self.runtime.event_store.emit(
                    {
                        "event_type": "FindingValidated",
                        "payload": {
                            "finding_id": finding.finding_id,
                            "validation_status": finding.validation_status,
                            "confidence": result.confidence,
                            "validator_name": task.tool,
                        },
                    }
                )
                artifacts.append(self._write_validation_artifact(task, finding, result.__dict__))
                validated.append(self._enrich_finding_metadata(finding))
            return validated, artifacts

        if task.tool == "jwt_validator":
            token = validation_inputs.get("token")
            if not token:
                return [], []
            candidates = [finding for finding in findings if "JWT" in (finding.finding_type or "").upper()] or [
                Finding(
                    finding_id=f"{task.task_id}:jwt",
                    severity="medium",
                    title="JWT validation candidate",
                    description="Generated from routed validator stage.",
                    affected_target=task.target,
                    tool_source=task.tool,
                    tool_version="integrated",
                    run_id=self.runtime.run_id,
                    scope_hash="scope-hash",
                    finding_type="JWT",
                )
            ]
            for finding in candidates:
                result = JWTValidator().validate(finding, token=str(token), allowed_algs=validation_inputs.get("allowed_algs", ("HS256", "RS256")))
                self.runtime.event_store.emit(
                    {
                        "event_type": "FindingValidated",
                        "payload": {
                            "finding_id": finding.finding_id,
                            "validation_status": finding.validation_status,
                            "confidence": result.confidence,
                            "validator_name": task.tool,
                        },
                    }
                )
                artifacts.append(self._write_validation_artifact(task, finding, result.__dict__))
                validated.append(self._enrich_finding_metadata(finding))
            return validated, artifacts

        if task.tool == "auth_validator":
            candidates = findings or []
            for finding in candidates:
                client = self._validator_client(task)
                try:
                    result = asyncio.run(
                        AuthComparatorValidator().validate(
                            finding,
                            validation_inputs.get("target_endpoint", task.target),
                            authenticated_creds=validation_inputs.get("authenticated_creds", {}),
                            unauthenticated_headers=validation_inputs.get("unauthenticated_headers"),
                            client=client,
                        )
                    )
                finally:
                    if client is not None:
                        asyncio.run(client.aclose())
                self.runtime.event_store.emit(
                    {
                        "event_type": "FindingValidated",
                        "payload": {
                            "finding_id": finding.finding_id,
                            "validation_status": finding.validation_status,
                            "confidence": result.confidence,
                            "validator_name": task.tool,
                        },
                    }
                )
                artifacts.append(self._write_validation_artifact(task, finding, result.__dict__))
                validated.append(self._enrich_finding_metadata(finding))
            return validated, artifacts

        raise ValueError(f"Unsupported validator task: {task.tool}")

    def _execute_task(self, task: DagTask) -> tuple[List[Finding], List[Dict[str, object]]]:
        if task.tool in {"autoswagger", "strix", "shannon", "net-utils", "subfinder", "browser", "zap", "hexstrike"}:
            if task.tool == "shannon":
                analysis_domain = str(task.options.get("analysis_domain") or "")
                agent_role = str(task.options.get("agent_role") or "")
                prior = self._relevant_prior_findings(task.target, analysis_domain if agent_role == "exploit" else None)
                extra: Dict[str, object] = {}
                if prior:
                    extra["prior_findings"] = [f.to_dict() for f in prior]
                try:
                    extra["scope_allowlist"] = list(self.runtime.scope_graph.allowed_domains)
                except Exception:
                    pass
                if extra:
                    task.options = {**task.options, **extra}
            adapter = self._adapter_for_task(task)
            output = adapter.run([task.target])
            if task.tool == "autoswagger":
                raw_output_refs = output.get("raw_output_refs") or []
                if raw_output_refs:
                    endpoints = self._parse_autoswagger_output(raw_output_refs[0])
                    if endpoints:
                        self._autoswagger_endpoints[task.target] = endpoints
            findings = [self._enrich_finding_metadata(finding) for finding in output.get("findings", [])]
            artifacts = output.get("artifacts", [])
            candidate_findings = self._candidate_findings_from_output(task, output)
            if task.tool == "shannon" and candidate_findings:
                promoted_findings, promotion_artifacts = self._process_candidate_findings(task, candidate_findings)
                findings.extend(self._enrich_finding_metadata(finding) for finding in promoted_findings)
                artifacts.extend(promotion_artifacts)
            return findings, artifacts
        if task.tool == "zypheron":
            findings, artifacts, bundle = self._run_zypheron_task(task)
            self._recon_bundles_by_target.setdefault(task.target, []).append(bundle)
            return findings, artifacts
        if task.tool == "vibepentester":
            findings, artifacts, bundle = self._run_vibepentester_task(task)
            self._recon_bundles_by_target.setdefault(task.target, []).append(bundle)
            return findings, artifacts
        if task.tool == "decepticon":
            return self._run_decepticon_task(task)
        if task.tool in {"bola_validator", "rate_limit_validator", "jwt_validator", "auth_validator"}:
            return self._run_validator_task(task)
        raise ValueError(f"Unsupported tool: {task.tool}")

    def _inject_validators_for_findings(
        self,
        plan: DagPlan,
        completed_task: DagTask,
        findings: List[Finding],
        indegree: Dict[str, int],
    ) -> List[DagTask]:
        """
        After an oracle adapter completes, inspect its findings and inject a
        deterministic validator task for each unique finding_type that maps to
        a validator — unless that validator tool is already present in the plan.

        Returns the newly created tasks (all immediately ready because their
        sole dependency just completed).
        """
        if completed_task.tool not in _ORACLE_ADAPTERS:
            return []

        existing_validators = {t.tool for t in plan.tasks.values()}
        injected: List[DagTask] = []
        seen_this_task: set = set()

        for finding in findings:
            ft = (finding.finding_type or "").upper()
            validator_name = FINDING_TYPE_TO_VALIDATOR.get(ft)
            if not validator_name:
                continue
            if validator_name in existing_validators or validator_name in seen_this_task:
                continue
            seen_this_task.add(validator_name)

            v_task_id = f"auto-validate:{validator_name}:{completed_task.task_id}"
            # Propagate http_transport so test isolation (MockTransport) works
            # and live runs inherit the same client config as the oracle task.
            inherited_opts: Dict[str, object] = {}
            if "http_transport" in completed_task.options:
                inherited_opts["http_transport"] = completed_task.options["http_transport"]

            v_task = DagTask(
                task_id=v_task_id,
                tool=validator_name,
                target=completed_task.target,
                options=inherited_opts,
            )
            plan.add_task(v_task)
            plan.add_dependency(completed_task.task_id, v_task_id)
            # The sole dependency just completed — set indegree to 0 directly.
            indegree[v_task_id] = 0
            injected.append(v_task)

            self.runtime.event_store.emit({
                "event_type": "validator_injected",
                "payload": {
                    "run_id": self.runtime.run_id,
                    "task_id": v_task_id,
                    "validator": validator_name,
                    "trigger_task": completed_task.task_id,
                    "finding_type": ft,
                },
            })

        return injected

    def execute(self, plan: DagPlan) -> List[TaskResult]:
        indegree = plan.indegrees()
        ready = deque(sorted(plan.ready_tasks(indegree), key=lambda t: t.task_id))
        results: List[TaskResult] = []

        # Build transitive dependent map so a failure only blocks its own chain,
        # not independent chains targeting different scope entries.
        reverse_deps: Dict[str, set] = {tid: set() for tid in plan.tasks}
        for src, neighbors in plan.graph.items():
            for dst in neighbors:
                reverse_deps.setdefault(src, set()).add(dst)
        for tid in list(plan.tasks):
            visited: set = set()
            queue = list(reverse_deps.get(tid, set()))
            while queue:
                dep = queue.pop()
                if dep not in visited:
                    visited.add(dep)
                    queue.extend(reverse_deps.get(dep, set()))
            reverse_deps[tid] = visited
        blocked_chains: set = set()  # task IDs whose upstream failed

        self.runtime.event_store.emit(
            {
                "event_type": "plan_debug",
                "payload": {
                    "run_id": self.runtime.run_id,
                    "tasks": sorted(plan.tasks.keys()),
                    "graph": {task_id: list(neighbors) for task_id, neighbors in plan.graph.items()},
                    "indegree": dict(indegree),
                    "ready": [task.task_id for task in ready],
                },
            }
        )

        print(f"[PlanRunner] Initial ready queue: {[t.task_id for t in ready]}")
        print(f"[PlanRunner] Total tasks in plan: {len(plan.tasks)}")
        print(f"[PlanRunner] Indegrees: {indegree}")

        while ready:
            print(f"[PlanRunner] Ready queue size: {len(ready)}, tasks: {[t.task_id for t in ready]}")
            if self.runtime.cancel_event.is_set():
                raise RuntimeCancelledError("Run cancelled")
            batch: List[DagTask] = []
            while ready and len(batch) < self.max_workers:
                task_to_add = ready.popleft()
                batch.append(task_to_add)
                print(f"[PlanRunner] Added {task_to_add.task_id} to batch")

            self.peak_concurrency = max(self.peak_concurrency, len(batch))
            print(f"[PlanRunner] Batch size: {len(batch)}, tasks: {[t.task_id for t in batch]}")

            for task in batch:
                print(f"[PlanRunner] Processing task: {task.task_id}")
                if self.runtime.cancel_event.is_set():
                    raise RuntimeCancelledError("Run cancelled")
                # Skip tasks whose upstream chain failed — but leave independent chains running.
                if task.task_id in blocked_chains:
                    self.runtime.event_store.emit({
                        "event_type": "task_blocked",
                        "payload": {
                            "run_id": self.runtime.run_id,
                            "task_id": task.task_id,
                            "adapter": task.tool,
                            "target": task.target,
                            "reason": "upstream_failed",
                        },
                    })
                    results.append(TaskResult(task_id=task.task_id, findings=[], status="blocked"))
                    continue
                task_succeeded = False
                skip_reason = self._skip_reason_for_task(task)
                if skip_reason is not None:
                    self.runtime.event_store.emit(
                        {
                            "event_type": "task_skipped",
                            "payload": {
                                "run_id": self.runtime.run_id,
                                "task_id": task.task_id,
                                "adapter": task.tool,
                                "target": task.target,
                                "reason": skip_reason,
                            },
                        }
                    )
                    results.append(TaskResult(task_id=task.task_id, findings=[], status="skipped", artifacts=[]))
                    task_succeeded = True
                    neighbors = plan.graph.get(task.task_id, [])
                    for neighbor in neighbors:
                        indegree[neighbor] -= 1
                        if indegree[neighbor] == 0:
                            ready.append(plan.tasks[neighbor])
                    continue
                try:
                    log_event(
                        self.logger,
                        "INFO",
                        "task_started",
                        run_id=self.runtime.run_id,
                        task_id=task.task_id,
                        adapter=task.tool,
                        target=task.target,
                        mode=self.runtime.mode,
                        options=task.options,
                    )
                    self.runtime.event_store.emit({
                        "event_type": "task_executing",
                        "payload": {
                            "run_id": self.runtime.run_id,
                            "task_id": task.task_id,
                            "adapter": task.tool,
                            "target": task.target,
                            "mode": self.runtime.mode,
                            "message": f"Executing {task.tool} against {task.target} in {self.runtime.mode} mode"
                        }
                    })
                    findings, artifacts = self._execute_task(task)
                    self._record_findings(task.target, findings)
                    results.append(TaskResult(task_id=task.task_id, findings=findings, status="completed", artifacts=artifacts))
                    task_succeeded = True
                    # Dynamically inject validator tasks for any LLM-discovered findings.
                    injected = self._inject_validators_for_findings(plan, task, findings, indegree)
                    for v_task in injected:
                        ready.append(v_task)
                    log_event(
                        self.logger,
                        "INFO",
                        "task_completed",
                        run_id=self.runtime.run_id,
                        task_id=task.task_id,
                        findings_count=len(findings),
                        artifacts_count=len(artifacts),
                    )
                except RuntimeCancelledError:
                    raise
                except Exception as exc:
                    error_message = str(exc)
                    log_event(
                        self.logger,
                        "ERROR",
                        "task_failed",
                        run_id=self.runtime.run_id,
                        task_id=task.task_id,
                        adapter=task.tool,
                        target=task.target,
                        error=error_message,
                    )
                    self.runtime.event_store.emit(
                        {
                            "event_type": "task_failed",
                            "payload": {
                                "run_id": self.runtime.run_id,
                                "task_id": task.task_id,
                                "adapter": task.tool,
                                "target": task.target,
                                "mode": self.runtime.mode,
                                "error": error_message,
                            },
                        }
                    )
                    errors_root = Path(self.runtime.artifacts_root) / self.runtime.run_id / "errors"
                    errors_root.mkdir(parents=True, exist_ok=True)
                    error_path = errors_root / f"{task.task_id}.txt"
                    error_path.write_text(error_message, encoding="utf-8")
                    self.runtime.event_store.emit(
                        {
                            "event_type": "artifact_saved",
                            "payload": {
                                "run_id": self.runtime.run_id,
                                "task_id": task.task_id,
                                "path": str(error_path),
                                "artifact_type": "error",
                            },
                        }
                    )
                    results.append(TaskResult(task_id=task.task_id, findings=[], status="failed", error=str(exc)))
                    if self.stop_on_fail:
                        chain_victims = reverse_deps.get(task.task_id, set())
                        blocked_chains.update(chain_victims)
                        print(
                            f"[PlanRunner] Task {task.task_id} failed; blocking "
                            f"{len(chain_victims)} dependent(s), independent chains continue"
                        )
                else:
                    log_event(
                        self.logger,
                        "INFO",
                        "task_finished",
                        run_id=self.runtime.run_id,
                        task_id=task.task_id,
                        adapter=task.tool,
                        target=task.target,
                        status="completed",
                    )

                # Only unlock downstream tasks when this task succeeded.
                # A failed task must not propagate readiness to its dependents.
                if task_succeeded:
                    neighbors = plan.graph.get(task.task_id, [])
                    print(f"[PlanRunner] Task {task.task_id} succeeded; unlocking neighbors: {neighbors}")
                    for neighbor in neighbors:
                        indegree[neighbor] -= 1
                        print(f"[PlanRunner] Decremented indegree of {neighbor} to {indegree[neighbor]}")
                        if indegree[neighbor] == 0:
                            ready.append(plan.tasks[neighbor])
                            print(f"[PlanRunner] Added {neighbor} to ready queue")
                else:
                    print(f"[PlanRunner] Task {task.task_id} failed; downstream tasks will be blocked")

        # Emit task_blocked for every task that never executed: either its indegree
        # never reached 0 (upstream failed) or it was in the ready queue when
        # stop_on_fail halted the scheduler.
        recorded_ids = {r.task_id for r in results}
        remaining_ready = list(ready)  # tasks queued but not consumed due to stop_on_fail
        remaining_task_ids = (
            {tid for tid, deg in indegree.items() if deg > 0}
            | {t.task_id for t in remaining_ready}
        ) - recorded_ids

        for task_id in sorted(remaining_task_ids):
            task = plan.tasks[task_id]
            log_event(
                self.logger,
                "WARNING",
                "task_blocked",
                run_id=self.runtime.run_id,
                task_id=task_id,
                adapter=task.tool,
                target=task.target,
            )
            self.runtime.event_store.emit({
                "event_type": "task_blocked",
                "payload": {
                    "run_id": self.runtime.run_id,
                    "task_id": task_id,
                    "adapter": task.tool,
                    "target": task.target,
                    "reason": "upstream_failed_or_scheduler_halted",
                },
            })
            results.append(TaskResult(task_id=task_id, findings=[], status="blocked"))

        chain_results = self._synthesize_chain_results()
        results.extend(chain_results)
        print(f"[PlanRunner] Execution complete, processed {len(results)} tasks")
        return results

    def _write_chain_artifact(self, target: str, record: ChainRecord) -> Dict[str, object]:
        chains_dir = Path(self.runtime.artifacts_root) / self.runtime.run_id / "chains"
        chains_dir.mkdir(parents=True, exist_ok=True)
        safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
        artifact_path = chains_dir / f"{safe_target}_{record.rule_id}_{record.finding.finding_id[:12]}.json"
        artifact_path.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")
        self.runtime.event_store.emit(
            {
                "event_type": "artifact_saved",
                "payload": {
                    "run_id": self.runtime.run_id,
                    "task_id": f"chain-analysis:{target}",
                    "path": str(artifact_path),
                    "artifact_type": "chain_record",
                },
            }
        )
        return {"path": str(artifact_path), "artifact_type": "chain_record", "tool": "chain-analysis"}

    def _write_chain_bundle_artifacts(self, target: str, record: ChainRecord) -> List[Dict[str, object]]:
        chains_dir = Path(self.runtime.artifacts_root) / self.runtime.run_id / "chains"
        chains_dir.mkdir(parents=True, exist_ok=True)
        safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
        prefix = f"{safe_target}_{record.rule_id}_{record.finding.finding_id[:12]}"
        replay_path = chains_dir / f"{prefix}_replay_manifest.json"
        replay_path.write_text(json.dumps(record.replay_manifest, indent=2), encoding="utf-8")
        poc_path = chains_dir / f"{prefix}_poc_bundle.md"
        poc_lines = [
            f"# {record.finding.title}",
            "",
            f"Rule: `{record.rule_id}`",
            f"Severity: `{record.finding.severity}`",
            f"Confidence: `{record.finding.confidence:.2f}`" if record.finding.confidence is not None else "Confidence: `unknown`",
            "",
            "## Chain Graph",
            "```text",
            record.ascii_graph,
            "```",
            "",
            "## Replay Manifest",
        ]
        for step in record.replay_manifest:
            poc_lines.append(f"- Step {step['step']}: {step['action']}")
            poc_lines.append(f"  Expected: {step['expected_result']}")
        poc_path.write_text("\n".join(poc_lines), encoding="utf-8")
        artifacts = [
            {"path": str(replay_path), "artifact_type": "chain_replay_manifest", "tool": "chain-analysis"},
            {"path": str(poc_path), "artifact_type": "poc_bundle", "tool": "chain-analysis"},
        ]
        for artifact in artifacts:
            self.runtime.event_store.emit(
                {
                    "event_type": "artifact_saved",
                    "payload": {
                        "run_id": self.runtime.run_id,
                        "task_id": f"chain-analysis:{target}",
                        "path": artifact["path"],
                        "artifact_type": artifact["artifact_type"],
                    },
                }
            )
        return artifacts

    def _synthesize_chain_results(self) -> List[TaskResult]:
        synthesized: List[TaskResult] = []
        for target, findings in self._findings_by_target.items():
            chain_records = synthesize_chains(
                findings,
                run_id=self.runtime.run_id,
                scope_hash="scope-hash",
                target=target,
            )
            if not chain_records:
                continue
            chains = [record.finding for record in chain_records]
            self._findings_by_target[target].extend(chains)
            artifacts: List[Dict[str, object]] = []
            for record in chain_records:
                artifacts.append(self._write_chain_artifact(target, record))
                artifacts.extend(self._write_chain_bundle_artifacts(target, record))
            for record in chain_records:
                chain = record.finding
                self.runtime.event_store.emit(
                    {
                        "event_type": "ChainDiscovered",
                        "payload": {
                            "root_finding_id": chain.chain_parent_ids[0] if chain.chain_parent_ids else chain.finding_id,
                            "chain_ids": list(chain.chain_parent_ids),
                            "combined_severity": chain.severity,
                            "impact_summary": chain.to_chain_summary(),
                            "rule_id": record.rule_id,
                        },
                    }
                )
            synthesized.append(
                TaskResult(
                    task_id=f"chain-analysis:{target}",
                    findings=chains,
                    status="completed",
                    artifacts=artifacts,
                )
            )
        return synthesized

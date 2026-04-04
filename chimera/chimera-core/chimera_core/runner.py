"""
Hadles the safe and observable execution of an ExecutionPlan.

The Runner is the component that actually invokes the tool adapters. It manages
the job queue, worker pools for concurrency, and enforces safety policies like
rate limiting and circuit breaking.
"""
import asyncio
import hashlib
import json
from contextlib import contextmanager
from types import SimpleNamespace

from chimera_core.planner import ExecutionPlan, Task
from chimera_core.context import RunContext
from chimera_core.adapters.net_utils_adapter import NetUtilsAdapter
from chimera_core.adapters.autoswagger_adapter import AutoswaggerAdapter
from chimera_core.adapters.browser_adapter import BrowserAdapter
from chimera_core.adapters.strix_adapter import StrixAdapter
from chimera_core.adapters.subfinder_adapter import SubfinderAdapter
from chimera_core.adapters.shannon_adapter import ShannonAdapter
from chimera_core.chain_analysis import ChainRecord, synthesize_chains
from chimera_core.findings import Finding
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
from chimera_core.validators.auth_validator import AuthComparatorValidator
from chimera_core.validators.bola_validator import BOLAValidator
from chimera_core.validators.jwt_validator import JWTValidator
from chimera_core.validators.rate_limit_validator import RateLimitValidator

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
        validations_dir = Path(self.runtime.artifacts_root) / self.runtime.run_id / "validators" / task.task_id
        validations_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = validations_dir / f"{finding.finding_id}.json"
        artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {"path": str(artifact_path), "artifact_type": "validation_result", "tool": task.tool}

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
        if task.tool in {"autoswagger", "strix", "shannon", "net-utils", "subfinder", "browser"}:
            if task.tool == "shannon":
                prior = self._findings_by_target.get(task.target, [])
                if prior:
                    task.options = {**task.options, "prior_findings": [f.to_dict() for f in prior]}
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

    def execute(self, plan: DagPlan) -> List[TaskResult]:
        indegree = plan.indegrees()
        ready = deque(sorted(plan.ready_tasks(indegree), key=lambda t: t.task_id))
        results: List[TaskResult] = []
        should_stop = False  # Flag to stop after current batch

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

        while ready and not should_stop:
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
                        should_stop = True  # Set flag to stop after finishing current batch
                        print(f"[PlanRunner] Task {task.task_id} failed, will stop after current batch completes")
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

                print(f"[PlanRunner] Task {task.task_id} completed, processing neighbors")
                neighbors = plan.graph.get(task.task_id, [])
                print(f"[PlanRunner] Neighbors of {task.task_id}: {neighbors}")
                for neighbor in neighbors:
                    indegree[neighbor] -= 1
                    print(f"[PlanRunner] Decremented indegree of {neighbor} to {indegree[neighbor]}")
                    if indegree[neighbor] == 0:
                        ready.append(plan.tasks[neighbor])
                        print(f"[PlanRunner] Added {neighbor} to ready queue")

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

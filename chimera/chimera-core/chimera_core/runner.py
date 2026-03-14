"""
Hadles the safe and observable execution of an ExecutionPlan.

The Runner is the component that actually invokes the tool adapters. It manages
the job queue, worker pools for concurrency, and enforces safety policies like
rate limiting and circuit breaking.
"""
import json

from chimera_core.planner import ExecutionPlan, Task
from chimera_core.context import RunContext
from chimera_core.adapters.net_utils_adapter import NetUtilsAdapter
from chimera_core.adapters.autoswagger_adapter import AutoswaggerAdapter
from chimera_core.adapters.strix_adapter import StrixAdapter
from chimera_core.adapters.shannon_adapter import ShannonAdapter
from chimera_core.findings import Finding
from chimera_core.scheduler import Scheduler # Import Scheduler
from chimera_core.scope import ScopeGraph, ScopePolicy # Import ScopeGraph and ScopePolicy
from typing import List, Optional, Any, Dict
from datetime import datetime, UTC
from pathlib import Path
from collections import deque
from dataclasses import dataclass

from chimera_core.plan import ExecutionPlan as DagPlan, Task as DagTask
from chimera_core.runtime import Runtime, RuntimeCancelledError
from chimera_core.logging import log_event, setup_logging

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
                    adapter = self._adapter_for_task(task)
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
                    output = adapter.run([task.target])
                    if task.tool == "autoswagger":
                        raw_output_refs = output.get("raw_output_refs") or []
                        if raw_output_refs:
                            endpoints = self._parse_autoswagger_output(raw_output_refs[0])
                            if endpoints:
                                self._autoswagger_endpoints[task.target] = endpoints
                    findings = output.get("findings", [])
                    artifacts = output.get("artifacts", [])
                    results.append(TaskResult(task_id=task.task_id, findings=findings, status="completed"))
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

        print(f"[PlanRunner] Execution complete, processed {len(results)} tasks")
        return results

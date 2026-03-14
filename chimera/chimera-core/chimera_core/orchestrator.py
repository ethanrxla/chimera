import hashlib
import os
import uuid
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from chimera_core.dedupe import dedupe_findings
from chimera_core.findings import Finding
from chimera_core.job import Job, JobStatus
from chimera_core.planner import generate_plan
from chimera_core.runner import PlanRunner
from chimera_core.run_manager import RunManager
from chimera_core.runtime import Runtime, RuntimeCancelledError
from chimera_core.run_store import RunStore
from chimera_core.scope import normalize_scope
from chimera_core.config import load_config
from chimera_core.sinks.local import LocalSink
from chimera_core.sinks.supabase import SupabaseSink
from chimera_core.sinks.tee import TeeSink
from chimera_core.modules.safety.policy import SafetyPolicy

class Orchestrator:
    def __init__(
        self,
        artifacts_root: Optional[Path] = None,
        fixture_registry: Optional[Dict[str, str]] = None,
        live: bool = False,
        max_workers: int = 2,
        stop_on_fail: bool = True,
        rate_limit_rps: Optional[int] = None,
        per_task_timeout_s: Optional[int] = None,
        program_name: Optional[str] = None,
    ):
        self.jobs: Dict[str, Job] = {}
        self.artifacts_root = artifacts_root or (Path.cwd() / "artifacts")
        self.fixture_registry = fixture_registry or {}
        self.live = live
        self.max_workers = max_workers
        self.stop_on_fail = stop_on_fail
        self.rate_limit_rps = rate_limit_rps
        self.per_task_timeout_s = per_task_timeout_s
        self.program_name = program_name

    def _emit_event(self, event_sink: Optional[Any], event_type: str, payload: Dict[str, Any]) -> None:
        if not event_sink:
            return
        event = {
            "event_type": event_type,
            "payload": payload,
        }
        if hasattr(event_sink, "emit_event"):
            event_sink.emit_event(event)
        else:
            event_sink.emit(event)

    def create_job(self, scope_file: str, mode: str) -> Job:
        """
        Creates and registers a new job from a scope file.
        """
        with open(scope_file, 'r') as f:
            scope_raw = f.read()
            scope_manifest = yaml.safe_load(scope_raw)

        scope_hash = hashlib.sha256(str(scope_manifest).encode()).hexdigest()
        job_id = str(uuid.uuid4())
        
        job = Job(
            job_id=job_id,
            scope_manifest=scope_manifest,
            scope_hash=scope_hash,
            mode=mode,
            scope_raw=scope_raw,
        )
        self.jobs[job_id] = job
        print(f"[Orchestrator] Created job {job_id} with status {job.status.value}")
        return job

    def create_job_from_manifest(self, scope_manifest: Dict[str, Any], mode: str, scope_raw: Optional[str] = None) -> Job:
        scope_hash = hashlib.sha256(str(scope_manifest).encode()).hexdigest()
        job_id = str(uuid.uuid4())

        job = Job(
            job_id=job_id,
            scope_manifest=scope_manifest,
            scope_hash=scope_hash,
            mode=mode,
            scope_raw=scope_raw,
        )
        self.jobs[job_id] = job
        print(f"[Orchestrator] Created job {job_id} with status {job.status.value}")
        return job

    def start_run(self, job_id: str, event_sink: Optional[Any] = None, cancel_event: Optional[Any] = None):
        """
        Executes the full agentic pipeline for a given job.
        """
        job = self.jobs.get(job_id)
        if not job:
            print(f"[Orchestrator] Error: Job {job_id} not found.")
            return

        sink = None
        try:
            print(f"--- Starting Run for Job {job_id} ---")
            job.started_at = datetime.now(timezone.utc)
            self._emit_event(event_sink, "run_created", {"job_id": job_id, "scope_hash": job.scope_hash})

            # 1. Requirement Analysis -> Scope Normalization
            job.status = JobStatus.VALIDATING_SCOPE
            print(f"[Orchestrator] Job {job_id} status: {job.status.value}")
            scope_graph, scope_policy = normalize_scope(job.scope_manifest)
            if self.rate_limit_rps is not None:
                scope_policy.max_rps = self.rate_limit_rps
            self._emit_event(event_sink, "scope_validated", {"job_id": job_id})

            # 2. Tool Selection & Planning
            job.status = JobStatus.PLANNING_TESTS
            print(f"[Orchestrator] Job {job_id} status: {job.status.value}")
            plan = generate_plan(scope_graph, scope_policy, None)
            self._emit_event(
                event_sink,
                "plan_created",
                {
                    "job_id": job_id,
                    "task_count": len(plan.tasks),
                    "stages": getattr(plan, "stages", []),
                    "metadata": getattr(plan, "metadata", {}),
                },
            )

            # 3. Run setup
            run_manager = RunManager(self.artifacts_root)
            run = run_manager.create_run(scope_hash=job.scope_hash, mode=job.mode)
            run_store = RunStore(self.artifacts_root)
            scope_normalized = {
                "allowlist": scope_graph.allowed_domains,
                "denylist": scope_graph.denied_patterns,
                "rate_limits": {
                    "requests_per_second": scope_policy.max_rps,
                    "concurrency": scope_policy.max_concurrency,
                },
                "allow_ip_targets": scope_policy.allow_ip_targets,
                "allow_private_ips": scope_policy.allow_private_ips,
                "allowed_methods": scope_policy.allowed_methods,
            }
            run_record = run_store.create_run(
                run.run_id,
                scope_raw=job.scope_raw or yaml.safe_dump(job.scope_manifest),
                scope_normalized=scope_normalized,
                plan=plan,
                options={
                    "live": self.live,
                    "fixture": not self.live,
                    "max_workers": self.max_workers,
                    "stop_on_fail": self.stop_on_fail,
                    "rate_limit_rps": self.rate_limit_rps,
                    "per_task_timeout_s": self.per_task_timeout_s,
                    "program_name": self.program_name,
                },
                status="created",
            )
            local_sink = LocalSink(run.artifacts_dir, run.run_id)
            sink = local_sink
            config = load_config()
            supabase_enabled = bool(config.get("supabase", {}).get("enabled"))
            supabase_url = os.getenv("SUPABASE_URL")
            supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
            if supabase_enabled and supabase_url and supabase_key:
                supabase_sink = SupabaseSink(
                    supabase_url=supabase_url,
                    service_role_key=supabase_key,
                    run_id=run.run_id,
                )
                sink = TeeSink(local_sink, supabase_sink)
            elif supabase_enabled:
                local_sink.emit_event(
                    {
                        "event_type": "sink_error",
                        "payload": {
                            "run_id": run.run_id,
                            "message": "Supabase enabled but missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY",
                        },
                    }
                )
            allowed_binaries = None
            extra_binaries = config.get("shannon", {}).get("allowed_binaries") or []
            if extra_binaries:
                allowed_binaries = {"python", "python3", "autoswagger", "strix", "curl"}
                allowed_binaries.update({str(name).lower() for name in extra_binaries})
            safety_policy = SafetyPolicy(
                allow_external_execution=self.live,
                require_live_confirm=True,
                live_confirm_token="I UNDERSTAND" if self.live else None,
                max_workers=self.max_workers,
                rps=float(self.rate_limit_rps or 10),
                timeout_s=int(self.per_task_timeout_s or 60),
            )
            runtime = Runtime(
                scope_graph=scope_graph,
                scope_policy=scope_policy,
                event_store=sink,
                artifacts_root=self.artifacts_root,
                run_id=run.run_id,
                cancel_event=cancel_event,
                allowed_binaries=allowed_binaries,
                safety_policy=safety_policy,
                mode="live" if self.live else "fixture",
            )
            if not self.live:
                for task in plan.tasks.values():
                    task.options.setdefault("live", False)
            else:
                for task in plan.tasks.values():
                    task.options.setdefault("live", True)
            if self.per_task_timeout_s is not None:
                for task in plan.tasks.values():
                    task.options.setdefault("timeout_s", self.per_task_timeout_s)

            sink.emit_event({"event_type": "run_created", "payload": {"run_id": run.run_id, "job_id": job_id}})
            sink.emit_event({"event_type": "run_upsert", "payload": self._run_payload(run_record.data)})
            indegree = plan.indegrees()
            sink.emit_event(
                {
                    "event_type": "plan_debug",
                    "payload": {
                        "run_id": run.run_id,
                        "tasks": sorted(plan.tasks.keys()),
                        "graph": {task_id: list(neighbors) for task_id, neighbors in plan.graph.items()},
                        "indegree": dict(indegree),
                        "ready": [task.task_id for task in plan.ready_tasks(indegree)],
                        "dependencies": {
                            task_id: sorted(task.dependencies) for task_id, task in plan.tasks.items()
                        },
                    },
                }
            )

            # 4. Automated Execution (fixture-first)
            job.status = JobStatus.RUNNING_TOOLS
            print(f"[Orchestrator] Job {job_id} status: {job.status.value}")
            sink.emit_event({
                "event_type": "execution_phase_started",
                "payload": {
                    "run_id": run.run_id,
                    "job_id": job_id,
                    "mode": "live" if self.live else "fixture",
                    "task_count": len(plan.tasks),
                    "message": f"Starting execution of {len(plan.tasks)} tasks in {'LIVE' if self.live else 'FIXTURE'} mode"
                }
            })
            run_store.update_run(run.run_id, status="running")

            runner = PlanRunner(
                runtime=runtime,
                max_workers=self.max_workers,
                stop_on_fail=False if self.live else self.stop_on_fail,
                fixture_registry=self.fixture_registry,
            )
            results = runner.execute(plan)

            sink.emit_event({
                "event_type": "execution_phase_completed",
                "payload": {
                    "run_id": run.run_id,
                    "job_id": job_id,
                    "tasks_completed": len(results),
                    "message": f"Completed execution of {len(results)} tasks"
                }
            })

            collected: List[Finding] = []
            for result in results:
                collected.extend(result.findings)

            deduped, duplicates = dedupe_findings(collected)

            for finding in deduped:
                sink.emit_finding(finding)
            local_sink.flush()
            run_store.update_run(
                run.run_id,
                status="completed",
                stats={
                    "tasks_total": len(plan.tasks),
                    "findings_total": len(deduped),
                    "duplicates": duplicates,
                    "exploit_chains": len([finding for finding in deduped if finding.finding_type == "EXPLOIT_CHAIN"]),
                },
            )
            if local_sink.report_artifacts:
                artifacts = [
                    local_sink.report_artifacts.findings_path,
                    local_sink.report_artifacts.chains_path,
                    local_sink.report_artifacts.chain_graphs_path,
                    local_sink.report_artifacts.rejected_findings_path,
                    local_sink.report_artifacts.report_path,
                    local_sink.report_artifacts.summary_path,
                ]
                for artifact in artifacts:
                    sink.emit_event(
                        {
                            "event_type": "artifact_saved",
                            "payload": {
                                "run_id": run.run_id,
                                "job_id": job_id,
                                "path": str(artifact),
                                "artifact_type": artifact.name,
                            },
                        }
                    )
                for artifact in local_sink.report_artifacts.poc_bundles_dir.glob("*.json"):
                    sink.emit_event(
                        {
                            "event_type": "artifact_saved",
                            "payload": {
                                "run_id": run.run_id,
                                "job_id": job_id,
                                "path": str(artifact),
                                "artifact_type": "poc_bundle",
                            },
                        }
                    )

            # 5. Results Analysis (Simplified)
            job.status = JobStatus.ANALYZING_RESULTS
            print(f"[Orchestrator] Job {job_id} status: {job.status.value}")
            job.findings.extend([finding.to_dict() for finding in deduped])
            for finding in deduped:
                self._emit_event(event_sink, "finding_created", {"job_id": job_id, "finding": finding.to_dict()})

            job.status = JobStatus.COMPLETED
            job.ended_at = datetime.now(timezone.utc)
            if sink:
                sink.emit_event({"event_type": "run_finished", "payload": {"run_id": run.run_id, "job_id": job_id}})
                sink.flush()
            self._emit_event(event_sink, "run_finished", {"job_id": job_id, "status": job.status.value})
            print(f"[Orchestrator] Job {job_id} completed with status {job.status.value}")
            print(f"[Orchestrator] Findings: {len(deduped)} (deduped {duplicates})")
            print(f"[Orchestrator] Artifacts: {run.artifacts_dir}")
            print(f"--- Run for Job {job_id} Finished ---")
            return run.run_id, run.artifacts_dir
        except RuntimeCancelledError:
            job.status = JobStatus.CANCELLED
            job.ended_at = datetime.now(timezone.utc)
            run_store = RunStore(self.artifacts_root)
            run_store.update_run(run.run_id, status="cancelled")
            if sink:
                sink.emit_event({"event_type": "run_cancelled", "payload": {"run_id": run.run_id, "job_id": job_id}})
                sink.flush()
            self._emit_event(event_sink, "run_cancelled", {"job_id": job_id})
            print(f"[Orchestrator] Job {job_id} cancelled")
            return run.run_id, run.artifacts_dir
        except Exception as exc:
            job.status = JobStatus.FAILED
            job.ended_at = datetime.now(timezone.utc)
            run_store = RunStore(self.artifacts_root)
            run_store.update_run(run.run_id, status="failed")
            self._emit_event(event_sink, "run_failed", {"job_id": job_id, "error": str(exc)})
            if sink:
                sink.flush()
            print(f"[Orchestrator] Job {job_id} failed: {exc}")
            return None, None


    def get_job_status(self, job_id: str) -> Optional[JobStatus]:
        job = self.jobs.get(job_id)
        return job.status if job else None

    def get_job_findings(self, job_id: str) -> List[Dict[str, Any]]:
        job = self.jobs.get(job_id)
        return job.findings if job else []

    def _run_payload(self, run_record: Dict[str, Any]) -> Dict[str, Any]:
        options = run_record.get("options", {})
        return {
            "run_id": run_record.get("run_id"),
            "created_at": run_record.get("created_at"),
            "started_at": run_record.get("started_at"),
            "ended_at": run_record.get("ended_at"),
            "status": run_record.get("status"),
            "program_name": options.get("program_name"),
            "scope_raw": run_record.get("scope_raw"),
            "scope_normalized": run_record.get("scope_normalized"),
            "plan": run_record.get("plan"),
            "options": options,
            "stats": run_record.get("stats"),
        }

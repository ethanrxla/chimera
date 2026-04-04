import json
import threading
import asyncio
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import yaml
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse, Response

from chimera_core.orchestrator import Orchestrator
from chimera_core.run_store import RunStore
from chimera_core.planner import generate_plan
from chimera_core.scope import normalize_scope
from chimera_core.modules.safety.policy import SafetyPolicy
from chimera_core.runtime import Runtime
from chimera_core.event_store import EventStore
from chimera_core.adapters.browser_adapter import BrowserAdapter
from chimera_core.adapters.shannon_adapter import ShannonAdapter
from chimera_core.capabilities.browser.browser_task import BrowserTask
from chimera_core.api.browser_sessions import PersistentBrowserSession
from chimera_core.api.input_parser import interpret_input
from chimera_core.api.oracle import heuristic_oracle
from chimera_core.modules.recon_gatherers.orchestrator import (
    run_zypheron_and_persist,
    run_vibepentester_and_persist,
    run_decepticon_and_persist,
)
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.recon_gatherers.decepticon_adapter import DecepticonConfig
from chimera_core.modules.recon_gatherers.sinks.recon_sink import ReconSink
from chimera_core.modules.runtime.run_manifest import RunManifest
from chimera_core.run_manager import RunManager


router = APIRouter()


def _load_scope(scope_text: str) -> Dict[str, object]:
    try:
        data = yaml.safe_load(scope_text)
        if not isinstance(data, dict):
            raise ValueError("Scope must be a mapping")
        return data
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _safe_artifact_path(base: Path, relative_path: str) -> Path:
    candidate = (base / relative_path).resolve()
    if base.resolve() not in candidate.parents and candidate != base.resolve():
        raise HTTPException(status_code=400, detail="Invalid artifact path")
    return candidate


def _infer_artifact_kind(path: Path) -> str:
    name = path.name.lower()
    if name == "stdout.txt":
        return "stdout"
    if name == "stderr.txt":
        return "stderr"
    if name == "run_manifest.json":
        return "run_manifest"
    if name == "provenance.json":
        return "provenance"
    if name == "parse_warnings.txt":
        return "parse_warning"
    if name == "notes.md":
        return "analysis_notes"
    if name == "suggested_actions.json":
        return "suggested_actions"
    if name.endswith(".md"):
        return "report"
    if name.endswith(".json"):
        return "report"
    return "artifact"


def _confidence_to_float(value: object) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        mapping = {"high": 0.9, "medium": 0.6, "low": 0.3}
        return mapping.get(str(value).lower(), 0.0)


def _load_provenance_map(artifacts_dir: Path) -> Dict[str, Dict[str, object]]:
    provenance_path = artifacts_dir / "provenance.json"
    if not provenance_path.exists():
        return {}
    payload = json.loads(provenance_path.read_text(encoding="utf-8"))
    return {record.get("subject_id"): record for record in payload if record.get("subject_id")}


def _stable_id_for_finding(finding: Dict[str, object]) -> str:
    raw = finding.get("raw_tool_fields", {}) or {}
    stable_id = raw.get("provenance_subject_id") or raw.get("stable_id")
    if stable_id:
        return str(stable_id)
    payload = {
        "title": finding.get("title", ""),
        "severity": finding.get("severity", ""),
        "type": finding.get("type", ""),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def _evidence_anchors(artifacts_dir: Path, evidence_refs: list) -> list:
    anchors = []
    for ref in evidence_refs:
        ref_str = str(ref)
        if ref_str.startswith("http://") or ref_str.startswith("https://"):
            anchors.append({"kind": "endpoint", "id": ref_str, "path": None})
            continue
        path = Path(ref_str)
        if not path.is_absolute():
            candidate = artifacts_dir / ref_str
        else:
            candidate = path
        if candidate.exists():
            rel_path = None
            try:
                rel_path = str(candidate.relative_to(artifacts_dir))
            except ValueError:
                rel_path = str(candidate)
            anchors.append({"kind": "artifact", "id": f"artifact:{rel_path}", "path": rel_path})
            continue
        anchors.append({"kind": "evidence", "id": ref_str, "path": None})
    return anchors


def _findings_summaries(
    artifacts_dir: Path,
    run_id: str,
    *,
    classification: Optional[str] = None,
    tool: Optional[str] = None,
    min_confidence: Optional[float] = None,
    q: Optional[str] = None,
) -> list:
    findings_path = Path(artifacts_dir) / "findings.json"
    if not findings_path.exists():
        return []
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    provenance_map = _load_provenance_map(artifacts_dir)
    results = []
    for finding in findings:
        raw = finding.get("raw_tool_fields", {}) or {}
        stable_id = _stable_id_for_finding(finding)
        record = provenance_map.get(stable_id, {})
        produced_by = record.get("produced_by") or raw.get("tool") or finding.get("tool_source") or "unknown"
        confidence = _confidence_to_float(finding.get("confidence"))
        classification_value = raw.get("report_ready_status", "NEEDS_REVIEW")
        evidence_refs = finding.get("evidence_refs", []) or []
        anchors = _evidence_anchors(artifacts_dir, evidence_refs)
        target = raw.get("target") or raw.get("affected_target") or finding.get("affected_target") or (anchors[0]["id"] if anchors else "")
        summary = {
            "stable_id": stable_id,
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "confidence": confidence,
            "classification": classification_value,
            "target": target,
            "tool": raw.get("tool") or finding.get("tool_source") or produced_by,
            "produced_by": produced_by,
            "created_at": record.get("created_at"),
            "run_id": run_id,
            "parent_run_id": raw.get("parent_run_id"),
            "evidence": {
                "anchors": anchors[:1],
                "count": len(anchors),
            },
            "provenance": {
                "has_provenance": bool(record),
                "derived_from_count": len(record.get("derived_from", []) or []),
            },
        }
        if classification and summary["classification"] != classification:
            continue
        if tool and summary["tool"] != tool:
            continue
        if min_confidence is not None and summary["confidence"] < min_confidence:
            continue
        if q and q.lower() not in summary["title"].lower():
            continue
        results.append(summary)
    return results


def _count_warning_artifacts(artifacts_dir: Path) -> int:
    if not artifacts_dir.exists():
        return 0
    count = 0
    for path in artifacts_dir.rglob("*"):
        if not path.is_file():
            continue
        kind = _infer_artifact_kind(path)
        if kind in {"parse_warning", "warning"}:
            count += 1
    return count


def _promoted_count(artifacts_dir: Path) -> int:
    findings_path = artifacts_dir / "findings.json"
    if not findings_path.exists():
        return 0
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    count = 0
    for finding in findings:
        raw = finding.get("raw_tool_fields", {}) or {}
        if raw.get("tool") != "decepticon":
            continue
        if finding.get("type") == "analysis":
            continue
        count += 1
    return count


def _plan_to_payload(plan) -> Dict[str, object]:
    tasks = []
    for task in plan.tasks.values():
        tasks.append({
            "task_id": task.task_id,
            "adapter": task.tool,
            "target": task.target,
            "depends_on": sorted(task.dependencies),
            "options": task.options,
        })
    return {"tasks": tasks}


def _generate_recon_plan(scope_graph, scope_policy):
    """Generate recon pipeline plan: Zypheron → VibePenTester → Decepticon (sequential)"""
    from chimera_core.plan import ExecutionPlan, Task

    plan = ExecutionPlan()

    for i, domain in enumerate(scope_graph.allowed_domains):
        # Phase 1: Zypheron (Asset Discovery)
        zypheron_task = Task(
            task_id=f"zypheron-scan-{i}",
            tool="zypheron",
            target=domain,
            options={"mode": "passive"}
        )
        plan.add_task(zypheron_task)

        # Phase 2: VibePenTester (Penetration Testing)
        # Depends on Zypheron completing
        vibe_task = Task(
            task_id=f"vibepentester-scan-{i}",
            tool="vibepentester",
            target=domain,
            options={"scan_mode": "standard"}
        )
        plan.add_task(vibe_task)
        plan.add_dependency(zypheron_task.task_id, vibe_task.task_id)

        # Phase 3: Decepticon (AI Enrichment & Analysis)
        # Depends on both Zypheron and VibePenTester completing
        decepticon_task = Task(
            task_id=f"decepticon-analyze-{i}",
            tool="decepticon",
            target=domain,
            options={"analyze_findings": True}
        )
        plan.add_task(decepticon_task)
        plan.add_dependency(vibe_task.task_id, decepticon_task.task_id)

    return plan


def _plan_notes_and_warnings(plan, live: bool) -> Dict[str, list]:
    notes = []
    warnings = []
    if live:
        notes.append("Live mode enabled")

    # Task Runner pipeline tools
    if any(task.tool == "autoswagger" for task in plan.tasks.values()):
        notes.append("Selected Autoswagger for API discovery")
    if any(task.tool == "strix" for task in plan.tasks.values()):
        notes.append("Selected Strix for web app testing")
    if any(task.tool == "shannon" for task in plan.tasks.values()):
        notes.append("Selected Shannon for AI-powered verification")

    # Recon pipeline tools
    if any(task.tool == "zypheron" for task in plan.tasks.values()):
        notes.append("Selected Zypheron for asset discovery")
    if any(task.tool == "vibepentester" for task in plan.tasks.values()):
        notes.append("Selected VibePenTester for penetration testing")
    if any(task.tool == "decepticon" for task in plan.tasks.values()):
        notes.append("Selected Decepticon for AI enrichment & analysis")

    return {"notes": notes, "warnings": warnings}


def _safety_state(policy: SafetyPolicy, mode: str) -> Dict[str, object]:
    blocked = []
    if mode == "live" and policy.require_live_confirm and not policy.live_confirm_token:
        blocked.append("live_confirm_missing")
    if not policy.allow_external_execution and mode == "live":
        blocked.append("external_execution_disabled")
    return {
        "mode": mode,
        "safety": {
            "enforce_scope": policy.enforce_scope,
            "external_exec_allowed": policy.allow_external_execution,
            "live_confirm_required": policy.require_live_confirm,
            "destructive_allowed": policy.allow_destructive,
        },
        "blocked_reasons": blocked,
    }


def _status_payload(request: Request) -> Dict[str, object]:
    runs = request.app.state.runs
    active_run = None
    if runs:
        for run_id, run_info in runs.items():
            if run_info.get("status") in {"running", "created"}:
                active_run = {"run_id": run_id, **run_info}
                break
        if not active_run:
            run_id, run_info = next(iter(runs.items()))
            active_run = {"run_id": run_id, **run_info}

    run_store = _get_run_store(request)
    records = run_store.list_runs(limit=1)
    last_record = records[0] if records else {}

    # Use active run's mode and scope if available, fallback to last record
    if active_run and "mode" in active_run:
        mode = active_run.get("mode")
    else:
        options = last_record.get("options", {})
        mode = "live" if options.get("live") else "fixture"

    policy = SafetyPolicy(
        allow_external_execution=mode == "live",
        require_live_confirm=True,
        live_confirm_token="I UNDERSTAND" if mode == "live" else None,
    )
    safety = _safety_state(policy, mode=mode)

    # Use active run's scope if available, fallback to last record
    if active_run and "scope_manifest" in active_run:
        scope_manifest = active_run.get("scope_manifest", {})
        if scope_manifest:
            _sg = normalize_scope(scope_manifest)[0]
            scope_normalized = {"allowlist": _sg.allowed_domains, "denylist": _sg.denied_patterns}
        else:
            scope_normalized = {}
    else:
        scope_normalized = last_record.get("scope_normalized", {}) if last_record else {}

    allowlist = scope_normalized.get("allowlist", [])
    scope_hash = ""

    # Try to get scope hash from active run's manifest first
    if active_run and active_run.get("run_id"):
        manifest_path = Path(request.app.state.artifacts_root) / active_run["run_id"] / "run_manifest.json"
        if manifest_path.exists():
            try:
                manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                scope_hash = manifest_payload.get("scope_spec_hash", "")
            except Exception:
                pass

    # Fallback to last record's manifest
    if not scope_hash and last_record.get("run_id"):
        manifest_path = Path(request.app.state.artifacts_root) / last_record.get("run_id", "") / "run_manifest.json"
        if manifest_path.exists():
            try:
                manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                scope_hash = manifest_payload.get("scope_spec_hash", "")
            except Exception:
                scope_hash = ""

    events_path = None
    if active_run and active_run.get("run_id"):
        events_path = Path(request.app.state.artifacts_root) / active_run["run_id"] / "events.jsonl"
    last_event_at = None
    if events_path and events_path.exists():
        last_event_at = datetime.fromtimestamp(events_path.stat().st_mtime, tz=timezone.utc).isoformat()

    phase_map = {
        "created": "planning",
        "running": "running",
        "completed": "done",
        "cancelled": "done",
        "failed": "error",
    }
    phase = "idle"
    if active_run:
        phase = phase_map.get(active_run.get("status", "idle"), "idle")

    return {
        "mode": safety["mode"],
        "active_run": {
            "run_id": active_run.get("run_id") if active_run else None,
            "phase": phase,
            "started_at": last_record.get("started_at") if last_record else None,
            "last_event_at": last_event_at,
        },
        "scope_state": {
            "loaded": bool(allowlist),
            "asset_count": len(allowlist),
            "scope_hash": scope_hash,
            "hash_ok": True if scope_hash else False,
        },
        "safety_state": {
            "external_exec_allowed": safety["safety"]["external_exec_allowed"],
            "live_confirm_required": safety["safety"]["live_confirm_required"],
            "destructive_allowed": safety["safety"]["destructive_allowed"],
            "blocked_reasons": safety["blocked_reasons"],
        },
        "quality_state": {
            "report_ready_threshold": 0.75,
        },
    }


def _resolve_artifacts_dir(request: Request, run_id: str) -> Optional[Path]:
    """
    Resolve artifacts directory for a given run_id or job_id.
    Handles both cases:
    - run_id is a job_id (stored in app.state.runs)
    - run_id is an actual run_id (stored on disk)
    """
    # First check if this is a job_id in app.state.runs
    run_info = request.app.state.runs.get(run_id)
    if run_info:
        # If we have the artifacts_dir, use it
        if run_info.get("artifacts_dir"):
            return Path(run_info["artifacts_dir"])
        # If we have the actual run_id, try to find it on disk
        if run_info.get("run_id"):
            actual_run_id = run_info["run_id"]
            artifacts_path = Path(request.app.state.artifacts_root) / actual_run_id
            if artifacts_path.exists():
                return artifacts_path

    # Try as a direct run_id on disk
    run_store = RunStore(Path(request.app.state.artifacts_root))
    try:
        run_store.get_run(run_id)
        artifacts_path = Path(request.app.state.artifacts_root) / run_id
        if artifacts_path.exists():
            return artifacts_path
    except FileNotFoundError:
        pass

    return None


def _get_run_store(request: Request) -> RunStore:
    return RunStore(Path(request.app.state.artifacts_root))


def _check_artifacts_writable(artifacts_root: Path) -> None:
    artifacts_root.mkdir(parents=True, exist_ok=True)
    probe = artifacts_root / ".healthcheck"
    probe.write_text("ok", encoding="utf-8")
    probe.unlink(missing_ok=True)


def _clamp_int(value: Optional[object], minimum: int, maximum: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def _default_scope_manifest(target: str) -> Dict[str, object]:
    return {"allowlist": [target], "denylist": []}


def _service_runtime(
    request: Request,
    *,
    scope_manifest: Dict[str, object],
    run_id: str,
    mode: str = "live",
) -> Runtime:
    scope_graph, scope_policy = normalize_scope(scope_manifest)
    artifacts_root = Path(request.app.state.artifacts_root)
    events_path = artifacts_root / run_id / "events.jsonl"
    events_path.parent.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(events_path)
    safety_policy = SafetyPolicy(
        enforce_scope=True,
        allow_external_execution=(mode == "live"),
        require_live_confirm=False,
        max_workers=2,
        rps=10,
        timeout_s=120,
    )
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
        safety_policy=safety_policy,
        mode=mode,
    )


def _browser_sessions(request: Request) -> Dict[str, Dict[str, object]]:
    return request.app.state.browser_sessions


def _shannon_tasks(request: Request) -> Dict[str, Dict[str, object]]:
    return request.app.state.shannon_tasks


def _serialize_browser_task(task) -> Dict[str, object]:
    if hasattr(task, "model_dump"):
        return task.model_dump()
    if hasattr(task, "dict"):
        return task.dict()
    return dict(task)


def _sanitize_browser_session(session: Dict[str, object]) -> Dict[str, object]:
    return {
        "session_id": session.get("session_id"),
        "run_id": session.get("run_id"),
        "target": session.get("target"),
        "scope_manifest": session.get("scope_manifest"),
        "headless": session.get("headless", True),
        "created_at": session.get("created_at"),
        "updated_at": session.get("updated_at"),
        "last_action": session.get("last_action"),
        "artifacts_dir": session.get("artifacts_dir"),
    }


def _load_json_artifact(artifacts_dir: Path, filename: str):
    path = artifacts_dir / filename
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@router.post("/runs/plan")
async def plan_run(payload: Dict[str, object]):
    scope_text = payload.get("scope_text")
    if not scope_text:
        raise HTTPException(status_code=400, detail="scope_text is required")
    live = bool(payload.get("live", False))
    live_confirm = payload.get("live_confirm")
    if live and live_confirm != "I UNDERSTAND":
        raise HTTPException(status_code=400, detail="Live confirmation required")

    pipeline = payload.get("pipeline", "task_runner")

    scope_manifest = _load_scope(scope_text)
    scope_graph, scope_policy = normalize_scope(scope_manifest)

    # Route to appropriate planner based on pipeline type
    if pipeline == "recon":
        # Generate recon pipeline plan (sequential: Zypheron → Vibe → Decepticon)
        plan = _generate_recon_plan(scope_graph, scope_policy)
    else:
        # Generate task runner plan (parallel: Autoswagger + Strix → Shannon)
        plan = generate_plan(scope_graph, scope_policy, None)

    normalized_scope = {
        "allowlist": scope_graph.allowed_domains,
        "denylist": scope_graph.denied_patterns,
        "rate_limits": {
            "requests_per_second": scope_policy.max_rps,
            "concurrency": scope_policy.max_concurrency,
        },
    }
    meta = _plan_notes_and_warnings(plan, live=live)

    policy = SafetyPolicy(
        allow_external_execution=live,
        require_live_confirm=True,
        live_confirm_token=live_confirm if live else None,
        max_workers=_clamp_int(payload.get("max_workers"), 1, 8, 2),
        rps=float(_clamp_int(payload.get("rate_limit_rps"), 1, 50, 10)),
        timeout_s=_clamp_int(payload.get("per_task_timeout_s"), 5, 1200, 1200),
    )
    safety = _safety_state(policy, mode="live" if live else "fixture")

    return JSONResponse({
        "scope": normalized_scope,
        "plan": _plan_to_payload(plan),
        "notes": meta["notes"],
        "warnings": meta["warnings"],
        "mode": safety["mode"],
        "safety": safety["safety"],
        "blocked_reasons": safety["blocked_reasons"],
    })


@router.get("/health")
async def health(request: Request):
    checks = {}
    ok = True
    try:
        _check_artifacts_writable(Path(request.app.state.artifacts_root))
        checks["artifacts_writable"] = True
    except Exception as exc:
        checks["artifacts_writable"] = False
        checks["artifacts_error"] = str(exc)
        ok = False

    try:
        allowlist = getattr(request.app.state, "runtime_allowlist", [])
        checks["runtime_allowlist_loaded"] = bool(allowlist)
        if not allowlist:
            ok = False
    except Exception as exc:
        checks["runtime_allowlist_loaded"] = False
        checks["runtime_allowlist_error"] = str(exc)
        ok = False

    try:
        normalize_scope({"allowlist": ["invalid.example"], "denylist": []})
        checks["scope_validator_ok"] = True
    except Exception as exc:
        checks["scope_validator_ok"] = False
        checks["scope_validator_error"] = str(exc)
        ok = False

    try:
        request.app.state.run_store.list_runs(limit=1)
        checks["run_store_ok"] = True
    except Exception as exc:
        checks["run_store_ok"] = False
        checks["run_store_error"] = str(exc)
        ok = False

    status = 200 if ok else 503
    return JSONResponse({"ok": ok, "checks": checks}, status_code=status)


@router.post("/parser/interpret")
async def parse_operator_input(payload: Dict[str, object]):
    text = str(payload.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="text is required")
    return JSONResponse(interpret_input(text))


@router.post("/shannon/oracle")
async def shannon_oracle(request: Request, payload: Dict[str, object]):
    question = str(payload.get("question") or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="question is required")
    target = payload.get("target")
    context = dict(payload.get("context") or {})
    oracle_callable = getattr(request.app.state, "shannon_oracle_callable", None)
    if oracle_callable is not None:
        result = await oracle_callable(question, target=target, context=context)
        return JSONResponse(result)
    response = heuristic_oracle(question, target=str(target) if target else None, context=context)
    if payload.get("request_browser_task") and getattr(request.app.state, "browser_llm_callable", None) is not None:
        adapter = BrowserAdapter(
            runtime=_service_runtime(
                request,
                scope_manifest=_default_scope_manifest(str(target or context.get("target") or "example.com")),
                run_id=f"oracle-{uuid.uuid4().hex[:12]}",
            ),
            options={"llm_callable": request.app.state.browser_llm_callable},
            run_id=f"oracle-{uuid.uuid4().hex[:12]}",
            task_id=f"oracle-{uuid.uuid4().hex[:8]}",
            scope_hash="oracle",
            artifacts_root=Path(request.app.state.artifacts_root),
        )
        task = await adapter.suggest_task(context, question)
        response["suggested_browser_task"] = _serialize_browser_task(task)
    return JSONResponse(response)


@router.post("/browser/sessions")
async def create_browser_session(request: Request, payload: Dict[str, object]):
    target = str(payload.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    scope_text = payload.get("scope_text")
    scope_manifest = _load_scope(scope_text) if scope_text else _default_scope_manifest(target)
    session_id = str(uuid.uuid4())
    run_id = str(payload.get("run_id") or f"browser-session-{session_id[:12]}")
    session = {
        "session_id": session_id,
        "run_id": run_id,
        "target": target,
        "scope_manifest": scope_manifest,
        "headless": bool(payload.get("headless", True)),
        "auth_cookies": dict(payload.get("auth_cookies") or {}),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "last_action": "created",
        "artifacts_dir": str(Path(request.app.state.artifacts_root) / run_id / "browser"),
        "backend": PersistentBrowserSession(
            target=target,
            headless=bool(payload.get("headless", True)),
            auth_cookies=dict(payload.get("auth_cookies") or {}),
            playwright_factory=getattr(request.app.state, "browser_playwright_factory", None),
        ),
    }
    _browser_sessions(request)[session_id] = session
    return JSONResponse(_sanitize_browser_session(session), status_code=201)


@router.get("/browser/sessions/{session_id}")
async def get_browser_session(request: Request, session_id: str):
    session = _browser_sessions(request).get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Browser session not found")
    return JSONResponse(_sanitize_browser_session(session))


@router.delete("/browser/sessions/{session_id}")
async def delete_browser_session(request: Request, session_id: str):
    session = _browser_sessions(request).pop(session_id, None)
    if not session:
        raise HTTPException(status_code=404, detail="Browser session not found")
    backend = session.get("backend")
    if backend is not None:
        await backend.close()
    return JSONResponse({"session_id": session_id, "status": "deleted"})


def _browser_adapter_for_session(request: Request, session: Dict[str, object], *, task_id: str, options: Optional[Dict[str, object]] = None) -> BrowserAdapter:
    runtime = _service_runtime(request, scope_manifest=session["scope_manifest"], run_id=str(session["run_id"]))
    merged_options = dict(options or {})
    merged_options.setdefault("headless", session.get("headless", True))
    merged_options.setdefault("auth_cookies", session.get("auth_cookies") or {})
    if getattr(request.app.state, "browser_playwright_factory", None) is not None:
        merged_options.setdefault("playwright_factory", request.app.state.browser_playwright_factory)
    if getattr(request.app.state, "browser_capture_factory", None) is not None:
        merged_options.setdefault("browser_factory", request.app.state.browser_capture_factory)
    if getattr(request.app.state, "browser_llm_callable", None) is not None:
        merged_options.setdefault("llm_callable", request.app.state.browser_llm_callable)
    return BrowserAdapter(
        runtime=runtime,
        options=merged_options,
        run_id=str(session["run_id"]),
        task_id=task_id,
        scope_hash=hashlib.sha256(json.dumps(session["scope_manifest"], sort_keys=True).encode()).hexdigest(),
        artifacts_root=Path(request.app.state.artifacts_root),
    )


@router.post("/browser/sessions/{session_id}/analyze")
async def browser_session_analyze(request: Request, session_id: str, payload: Dict[str, object]):
    session = _browser_sessions(request).get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Browser session not found")
    target = str(payload.get("url") or session["target"])
    adapter = _browser_adapter_for_session(request, session, task_id=f"analyze-{uuid.uuid4().hex[:8]}")
    backend = session.get("backend")
    capture = await backend.analyze(target) if backend is not None else await adapter.analyze_page(target, auth_cookies=session.get("auth_cookies"))
    findings = adapter.normalize(capture)
    session["updated_at"] = datetime.now(timezone.utc).isoformat()
    session["last_action"] = "analyze"
    return JSONResponse({"session": _sanitize_browser_session(session), "capture": capture, "findings": [item.to_dict() for item in findings]})


@router.post("/browser/sessions/{session_id}/suggest-task")
async def browser_session_suggest_task(request: Request, session_id: str, payload: Dict[str, object]):
    session = _browser_sessions(request).get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Browser session not found")
    hypothesis = str(payload.get("hypothesis") or "").strip()
    if not hypothesis:
        raise HTTPException(status_code=400, detail="hypothesis is required")
    context = dict(payload.get("context") or {})
    adapter = _browser_adapter_for_session(request, session, task_id=f"suggest-{uuid.uuid4().hex[:8]}")
    task = await adapter.suggest_task(context, hypothesis)
    session["updated_at"] = datetime.now(timezone.utc).isoformat()
    session["last_action"] = "suggest-task"
    return JSONResponse({"session": _sanitize_browser_session(session), "task": _serialize_browser_task(task)})


@router.post("/browser/sessions/{session_id}/execute")
async def browser_session_execute(request: Request, session_id: str, payload: Dict[str, object]):
    session = _browser_sessions(request).get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Browser session not found")
    task_payload = payload.get("task")
    if not isinstance(task_payload, dict):
        raise HTTPException(status_code=400, detail="task object is required")
    target = str(payload.get("url") or session["target"])
    adapter = _browser_adapter_for_session(request, session, task_id=f"execute-{uuid.uuid4().hex[:8]}")
    task = BrowserTask(**task_payload)
    backend = session.get("backend")
    capture = await backend.execute(task, url=target) if backend is not None else await adapter.analyze_page(target, auth_cookies=session.get("auth_cookies"))
    findings = adapter.normalize(capture)
    session["updated_at"] = datetime.now(timezone.utc).isoformat()
    session["last_action"] = "execute"
    return JSONResponse({"session": _sanitize_browser_session(session), "capture": capture, "findings": [item.to_dict() for item in findings]})


@router.post("/browser/sessions/{session_id}/trace-xss")
async def browser_session_trace_xss(request: Request, session_id: str, payload: Dict[str, object]):
    session = _browser_sessions(request).get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Browser session not found")
    target = str(payload.get("url") or session["target"])
    parameter = str(payload.get("parameter") or "q")
    payload_value = str(payload.get("payload") or "<svg/onload=alert(1)>")
    adapter = _browser_adapter_for_session(
        request,
        session,
        task_id=f"trace-xss-{uuid.uuid4().hex[:8]}",
        options={"parameter": parameter},
    )
    backend = session.get("backend")
    trace = await backend.trace_xss(url=target, parameter=parameter, payload=payload_value) if backend is not None else await adapter.trace_xss_sink(target, parameter, payload_value)
    findings = adapter._findings_from_trace_result(target, trace)
    session["updated_at"] = datetime.now(timezone.utc).isoformat()
    session["last_action"] = "trace-xss"
    return JSONResponse({"session": _sanitize_browser_session(session), "trace": trace, "findings": [item.to_dict() for item in findings]})


@router.post("/shannon/tasks")
async def create_shannon_task(request: Request, payload: Dict[str, object]):
    targets = payload.get("targets") or []
    if isinstance(targets, str):
        targets = [targets]
    if not targets:
        target = str(payload.get("target") or "").strip()
        if target:
            targets = [target]
    if not targets:
        raise HTTPException(status_code=400, detail="target or targets is required")

    query = str(payload.get("query") or "").strip()
    if not query:
        raise HTTPException(status_code=400, detail="query is required")

    scope_text = payload.get("scope_text")
    scope_manifest = _load_scope(scope_text) if scope_text else {"allowlist": list(targets), "denylist": []}
    task_id = str(uuid.uuid4())
    run_id = str(payload.get("run_id") or f"shannon-task-{task_id[:12]}")
    record = {
        "task_id": task_id,
        "run_id": run_id,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "query": query,
        "targets": list(targets),
        "error": None,
        "result": None,
    }
    _shannon_tasks(request)[task_id] = record

    def _run_task() -> None:
        record["status"] = "running"
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        try:
            runtime = _service_runtime(request, scope_manifest=scope_manifest, run_id=run_id)
            options = {
                "live": True,
                "driver": str(payload.get("driver") or "http"),
                "query": query,
                "base_url": payload.get("base_url"),
                "api_key": payload.get("api_key"),
                "session_id": payload.get("session_id") or f"chimera-api-{task_id}",
                "http_client": getattr(request.app.state, "shannon_http_client", None),
                "poll_interval_s": payload.get("poll_interval_s", 0.01 if getattr(request.app.state, "testing", False) else 2),
                "timeout_s": payload.get("timeout_s", 120),
            }
            options = {key: value for key, value in options.items() if value is not None}
            adapter = ShannonAdapter(
                runtime=runtime,
                options=options,
                run_id=run_id,
                task_id=task_id,
                scope_hash=hashlib.sha256(json.dumps(scope_manifest, sort_keys=True).encode()).hexdigest(),
                artifacts_root=Path(request.app.state.artifacts_root),
            )
            result = adapter.run(list(targets))
            record["status"] = "completed"
            record["result"] = {
                "findings": [item.to_dict() for item in result.get("findings", [])],
                "artifacts": result.get("artifacts", []),
                "command": result.get("command"),
            }
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = str(exc)
        finally:
            record["updated_at"] = datetime.now(timezone.utc).isoformat()

    thread = threading.Thread(target=_run_task, daemon=True)
    thread.start()

    return JSONResponse({"task_id": task_id, "run_id": run_id, "status": "queued"}, status_code=202)


@router.get("/shannon/tasks/{task_id}")
async def get_shannon_task(request: Request, task_id: str):
    task = _shannon_tasks(request).get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Shannon task not found")
    return JSONResponse(task)


@router.post("/runs")
async def create_run(request: Request, payload: Dict[str, object]):
    scope_text = payload.get("scope_text")
    if not scope_text:
        raise HTTPException(status_code=400, detail="scope_text is required")
    live = bool(payload.get("live", False))
    testing = getattr(request.app.state, "testing", False)
    if not live and not testing:
        raise HTTPException(status_code=400, detail="Fixture mode has been removed. Set live=true.")
    live_confirm = payload.get("live_confirm")
    if live and live_confirm != "I UNDERSTAND":
        raise HTTPException(status_code=400, detail="Live confirmation required")
    max_workers = _clamp_int(payload.get("max_workers"), 1, 8, 2)
    rate_limit_rps = _clamp_int(payload.get("rate_limit_rps"), 1, 50, 10)
    per_task_timeout_s = _clamp_int(payload.get("per_task_timeout_s"), 5, 1200, 1200)
    program_name = payload.get("program_name")
    policy = SafetyPolicy(
        allow_external_execution=live,
        require_live_confirm=True,
        live_confirm_token=live_confirm if live else None,
        max_workers=max_workers,
        rps=float(rate_limit_rps),
        timeout_s=per_task_timeout_s,
    )

    scope_manifest = _load_scope(scope_text)
    fixture_registry = request.app.state.fixture_registry
    orchestrator = Orchestrator(
        artifacts_root=request.app.state.artifacts_root,
        fixture_registry=fixture_registry,
        live=live,
        max_workers=max_workers,
        rate_limit_rps=rate_limit_rps,
        per_task_timeout_s=per_task_timeout_s,
        program_name=program_name,
    )

    cancel_event = threading.Event()
    job = orchestrator.create_job_from_manifest(scope_manifest, mode="live" if live else "safe", scope_raw=scope_text)
    run_info = {
        "status": "created",
        "job_id": job.job_id,
        "cancel_event": cancel_event,
        "mode": "live" if live else "fixture",
        "live": live,
        "scope_manifest": scope_manifest,
        "scope_text": scope_text,
    }
    request.app.state.runs[job.job_id] = run_info

    def _run_job():
        request.app.state.runs[job.job_id]["status"] = "running"
        run_id, artifacts_dir = orchestrator.start_run(job.job_id, cancel_event=cancel_event)
        status = "completed"
        if cancel_event.is_set():
            status = "cancelled"
        elif run_id:
            try:
                status = request.app.state.run_store.get_run(run_id).data.get("status", status)
            except FileNotFoundError:
                pass
        else:
            status = "failed"
        request.app.state.runs[job.job_id].update({
            "status": status,
            "run_id": run_id,
            "artifacts_dir": str(artifacts_dir),
        })

    thread = threading.Thread(target=_run_job, daemon=True)
    thread.start()

    safety = _safety_state(policy, mode="live" if live else "fixture")
    return JSONResponse({
        "run_id": job.job_id,  # This is actually a job_id - real run_id is created async
        "job_id": job.job_id,  # Also return as job_id for clarity
        "status": "created",
        "mode": safety["mode"],
        "safety": safety["safety"],
        "blocked_reasons": safety["blocked_reasons"],
        "note": "Poll /runs/{job_id} to get actual run_id once background execution starts"
    })


@router.post("/runs/{run_id}/cancel")
async def cancel_run(request: Request, run_id: str):
    run_info = request.app.state.runs.get(run_id)
    if not run_info:
        raise HTTPException(status_code=404, detail="Run not found")
    cancel_event = run_info.get("cancel_event")
    if cancel_event:
        cancel_event.set()
    run_info["status"] = "cancelled"
    return JSONResponse({"run_id": run_id, "status": "cancelled"})


@router.get("/runs")
async def list_runs(request: Request, limit: int = Query(20, ge=1, le=200), offset: int = Query(0, ge=0)):
    run_store = _get_run_store(request)
    records = run_store.list_runs(limit=limit, offset=offset)
    summaries = []
    for record in records:
        summaries.append({
            "run_id": record.get("run_id"),
            "status": record.get("status"),
            "created_at": record.get("created_at"),
            "started_at": record.get("started_at"),
            "ended_at": record.get("ended_at"),
            "scope": record.get("scope_normalized", {}),
            "stats": record.get("stats", {}),
        })
    return JSONResponse(summaries)


@router.get("/runs/diff")
async def get_runs_diff(
    request: Request,
    base_run_id: str,
    compare_run_id: str,
    classification: Optional[str] = None,
):
    base_dir = _resolve_artifacts_dir(request, base_run_id)
    compare_dir = _resolve_artifacts_dir(request, compare_run_id)
    if not base_dir or not compare_dir:
        raise HTTPException(status_code=404, detail="Artifacts not ready")

    base_summaries = _findings_summaries(
        Path(base_dir),
        base_run_id,
        classification=classification,
    )
    compare_summaries = _findings_summaries(
        Path(compare_dir),
        compare_run_id,
        classification=classification,
    )

    base_map = {item["stable_id"]: item for item in base_summaries}
    compare_map = {item["stable_id"]: item for item in compare_summaries}

    base_ids = set(base_map.keys())
    compare_ids = set(compare_map.keys())

    new_items = [compare_map[item_id] for item_id in sorted(compare_ids - base_ids)]
    removed_items = [base_map[item_id] for item_id in sorted(base_ids - compare_ids)]

    changed_items = []
    for item_id in sorted(base_ids & compare_ids):
        before = base_map[item_id]
        after = compare_map[item_id]
        fields_changed = []
        if before.get("severity") != after.get("severity"):
            fields_changed.append("severity")
        if before.get("classification") != after.get("classification"):
            fields_changed.append("classification")
        if before.get("title") != after.get("title"):
            fields_changed.append("title")
        if before.get("target") != after.get("target"):
            fields_changed.append("target")
        if before.get("tool") != after.get("tool"):
            fields_changed.append("tool")
        if abs((before.get("confidence") or 0.0) - (after.get("confidence") or 0.0)) >= 0.01:
            fields_changed.append("confidence")
        if fields_changed:
            changed_items.append({
                "stable_id": item_id,
                "summary": {
                    "severity": after.get("severity"),
                    "title": after.get("title"),
                    "target": after.get("target"),
                    "tool": after.get("tool"),
                    "classification": after.get("classification"),
                    "confidence": after.get("confidence"),
                },
                "fields_changed": fields_changed,
                "from": {
                    "confidence": before.get("confidence"),
                    "classification": before.get("classification"),
                    "severity": before.get("severity"),
                },
                "to": {
                    "confidence": after.get("confidence"),
                    "classification": after.get("classification"),
                    "severity": after.get("severity"),
                },
            })

    base_report_ready = sum(
        1 for item in base_summaries if item.get("classification") == "REPORT_READY"
    )
    compare_report_ready = sum(
        1 for item in compare_summaries if item.get("classification") == "REPORT_READY"
    )
    base_promoted = _promoted_count(Path(base_dir))
    compare_promoted = _promoted_count(Path(compare_dir))
    base_warnings = _count_warning_artifacts(Path(base_dir))
    compare_warnings = _count_warning_artifacts(Path(compare_dir))

    base_parent = None
    compare_parent = None
    for item in base_summaries:
        if item.get("parent_run_id"):
            base_parent = item["parent_run_id"]
            break
    for item in compare_summaries:
        if item.get("parent_run_id"):
            compare_parent = item["parent_run_id"]
            break

    payload = {
        "base_run_id": base_run_id,
        "compare_run_id": compare_run_id,
        "base_parent_run_id": base_parent,
        "compare_parent_run_id": compare_parent,
        "counts": {
            "findings": {
                "base": len(base_summaries),
                "compare": len(compare_summaries),
                "delta": len(compare_summaries) - len(base_summaries),
            },
            "report_ready": {
                "base": base_report_ready,
                "compare": compare_report_ready,
                "delta": compare_report_ready - base_report_ready,
            },
            "promoted": {
                "base": base_promoted,
                "compare": compare_promoted,
                "delta": compare_promoted - base_promoted,
            },
            "warnings": {
                "base": base_warnings,
                "compare": compare_warnings,
                "delta": compare_warnings - base_warnings,
            },
        },
        "new": [
            {
                "stable_id": item.get("stable_id"),
                "severity": item.get("severity"),
                "title": item.get("title"),
                "target": item.get("target"),
                "tool": item.get("tool"),
                "confidence": item.get("confidence"),
                "classification": item.get("classification"),
            }
            for item in new_items
        ],
        "removed": [
            {
                "stable_id": item.get("stable_id"),
                "severity": item.get("severity"),
                "title": item.get("title"),
                "target": item.get("target"),
                "tool": item.get("tool"),
                "confidence": item.get("confidence"),
                "classification": item.get("classification"),
            }
            for item in removed_items
        ],
        "changed": changed_items,
    }
    return JSONResponse(payload)


@router.get("/runs/{run_id}")
async def get_run(request: Request, run_id: str):
    run_info = request.app.state.runs.get(run_id)
    if run_info:
        payload = dict(run_info)
        payload.pop("cancel_event", None)
        if payload.get("run_id"):
            try:
                record = _get_run_store(request).get_run(payload["run_id"])
                payload.update(record.data)
            except FileNotFoundError:
                pass
        return payload
    try:
        record = _get_run_store(request).get_run(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Run not found") from exc
    payload = dict(record.data)
    payload["artifacts_dir"] = str(Path(request.app.state.artifacts_root) / run_id)
    return payload


@router.get("/status")
async def get_status(request: Request):
    return JSONResponse(_status_payload(request))


@router.get("/runs/{run_id}/events")
async def get_events(
    request: Request,
    run_id: str,
    cursor: int = Query(0, ge=0),
    tail: bool = Query(False),
):
    artifacts_dir = _resolve_artifacts_dir(request, run_id)
    if not artifacts_dir:
        raise HTTPException(status_code=404, detail="Artifacts not ready")
    events_path = Path(artifacts_dir) / "events.jsonl"
    if not events_path.exists():
        raise HTTPException(status_code=404, detail="Event log not found")

    async def _event_stream():
        with events_path.open("r", encoding="utf-8") as handle:
            handle.seek(cursor)
            while True:
                line = handle.readline()
                if line:
                    payload = line.strip()
                    if payload:
                        yield f"data: {payload}\n\n"
                else:
                    if not tail:
                        break
                    await asyncio.sleep(0.1)

    return StreamingResponse(_event_stream(), media_type="text/event-stream")


@router.get("/runs/{run_id}/findings")
async def get_findings(
    request: Request,
    run_id: str,
    classification: Optional[str] = None,
    tool: Optional[str] = None,
    min_confidence: Optional[float] = None,
    q: Optional[str] = None,
):
    artifacts_dir = _resolve_artifacts_dir(request, run_id)
    if not artifacts_dir:
        raise HTTPException(status_code=404, detail="Artifacts not ready")
    results = _findings_summaries(
        Path(artifacts_dir),
        run_id,
        classification=classification,
        tool=tool,
        min_confidence=min_confidence,
        q=q,
    )
    if not results:
        findings_path = Path(artifacts_dir) / "findings.json"
        if not findings_path.exists():
            raise HTTPException(status_code=404, detail="Findings not found")
    return JSONResponse(results)


@router.get("/runs/{run_id}/findings/{stable_id}")
async def get_finding_detail(request: Request, run_id: str, stable_id: str):
    artifacts_dir = _resolve_artifacts_dir(request, run_id)
    if not artifacts_dir:
        raise HTTPException(status_code=404, detail="Artifacts not ready")
    findings_path = Path(artifacts_dir) / "findings.json"
    if not findings_path.exists():
        raise HTTPException(status_code=404, detail="Findings not found")
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    provenance_map = _load_provenance_map(Path(artifacts_dir))

    selected = None
    for finding in findings:
        if _stable_id_for_finding(finding) == stable_id:
            selected = finding
            break
    if not selected:
        raise HTTPException(status_code=404, detail="Finding not found")

    raw = selected.get("raw_tool_fields", {}) or {}
    record = provenance_map.get(stable_id, {})
    evidence_refs = selected.get("evidence_refs", []) or []
    anchors = _evidence_anchors(Path(artifacts_dir), evidence_refs)

    detail = {
        "stable_id": stable_id,
        "title": selected.get("title", ""),
        "severity": selected.get("severity", ""),
        "confidence": _confidence_to_float(selected.get("confidence")),
        "classification": raw.get("report_ready_status", "NEEDS_REVIEW"),
        "target": raw.get("target") or raw.get("affected_target"),
        "tool": raw.get("tool") or record.get("produced_by") or "unknown",
        "description": selected.get("description") or "",
        "reproduction": selected.get("reproduction") or "",
        "tags": selected.get("tags", []) or [],
        "evidence": {
            "anchors": anchors,
        },
        "provenance": {
            "produced_by": record.get("produced_by") or raw.get("tool") or "unknown",
            "derived_from": record.get("derived_from", []) or [],
        },
        "raw": raw,
    }
    return JSONResponse(detail)


@router.get("/runs/{run_id}/chains")
async def get_chains(request: Request, run_id: str):
    artifacts_dir = _resolve_artifacts_dir(request, run_id)
    if not artifacts_dir:
        raise HTTPException(status_code=404, detail="Artifacts not ready")
    chains = _load_json_artifact(Path(artifacts_dir), "chains.json")
    if chains is None:
        raise HTTPException(status_code=404, detail="Chains not found")
    graphs = _load_json_artifact(Path(artifacts_dir), "chain_graphs.json") or []
    graphs_by_id = {item.get("finding_id"): item for item in graphs if item.get("finding_id")}
    summaries = []
    for chain in chains:
        summaries.append(
            {
                "finding_id": chain.get("finding_id"),
                "title": chain.get("title"),
                "severity": chain.get("severity"),
                "confidence": _confidence_to_float(chain.get("confidence")),
                "chain_parent_ids": chain.get("chain_parent_ids", []),
                "graph_ascii": (graphs_by_id.get(chain.get("finding_id")) or {}).get("ascii"),
            }
        )
    return JSONResponse(summaries)


@router.get("/runs/{run_id}/chains/{chain_id}")
async def get_chain_detail(request: Request, run_id: str, chain_id: str):
    artifacts_dir = _resolve_artifacts_dir(request, run_id)
    if not artifacts_dir:
        raise HTTPException(status_code=404, detail="Artifacts not ready")
    chains = _load_json_artifact(Path(artifacts_dir), "chains.json") or []
    graphs = _load_json_artifact(Path(artifacts_dir), "chain_graphs.json") or []
    graph_map = {item.get("finding_id"): item for item in graphs if item.get("finding_id")}
    selected = next((item for item in chains if item.get("finding_id") == chain_id), None)
    if selected is None:
        raise HTTPException(status_code=404, detail="Chain not found")
    bundle = None
    bundles_dir = Path(artifacts_dir) / "poc_bundles"
    if bundles_dir.exists():
        for path in bundles_dir.glob("*.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            finding = payload.get("finding") or {}
            if finding.get("finding_id") == chain_id:
                bundle = payload
                break
    return JSONResponse(
        {
            "chain": selected,
            "graph": graph_map.get(chain_id),
            "poc_bundle": bundle,
        }
    )


@router.get("/runs/{run_id}/replays/{finding_id}")
async def get_replay_manifest(request: Request, run_id: str, finding_id: str):
    artifacts_dir = _resolve_artifacts_dir(request, run_id)
    if not artifacts_dir:
        raise HTTPException(status_code=404, detail="Artifacts not ready")
    findings = _load_json_artifact(Path(artifacts_dir), "findings.json") or []
    selected = next((item for item in findings if item.get("finding_id") == finding_id), None)
    if selected is None:
        raise HTTPException(status_code=404, detail="Replay manifest not found")
    return JSONResponse(
        {
            "finding_id": finding_id,
            "title": selected.get("title"),
            "validation_status": selected.get("validation_status"),
            "replay_steps": selected.get("replay_steps", []),
            "proof_artifacts": selected.get("proof_artifacts", []),
            "chain_parent_ids": selected.get("chain_parent_ids", []),
        }
    )


@router.get("/runs/{run_id}/artifacts")
async def list_artifacts(request: Request, run_id: str):
    artifacts_dir = _resolve_artifacts_dir(request, run_id)
    if not artifacts_dir:
        # Return empty list instead of 404 if artifacts don't exist yet
        return JSONResponse([])
    base = Path(artifacts_dir).resolve()
    items = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel_path = str(path.relative_to(base))
        items.append({
            "artifact_id": hashlib.sha256(rel_path.encode()).hexdigest()[:16],
            "path": rel_path,
            "kind": _infer_artifact_kind(path),
            "size_bytes": path.stat().st_size,
        })
    return JSONResponse(items)


@router.get("/runs/{run_id}/artifacts/{artifact_path:path}")
async def get_artifact(request: Request, run_id: str, artifact_path: str):
    artifacts_dir = _resolve_artifacts_dir(request, run_id)
    if not artifacts_dir:
        raise HTTPException(status_code=404, detail="Artifacts not ready")
    base = Path(artifacts_dir).resolve()
    target = _safe_artifact_path(base, artifact_path)
    if not target.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")
    if getattr(request.app.state, "testing", False):
        return Response(content=target.read_bytes(), media_type="application/octet-stream")
    return FileResponse(target)


@router.get("/runs/{run_id}/events_tail")
async def get_events_tail(request: Request, run_id: str, limit: int = Query(200, ge=1, le=5000)):
    artifacts_dir = _resolve_artifacts_dir(request, run_id)
    if not artifacts_dir:
        # Return empty list instead of 404 if artifacts don't exist yet
        return JSONResponse([])
    events_path = Path(artifacts_dir) / "events.jsonl"
    if not events_path.exists():
        # Return empty list instead of 404 if events don't exist yet
        return JSONResponse([])
    lines = events_path.read_text(encoding="utf-8").splitlines()
    tail = lines[-limit:] if lines else []
    return JSONResponse(tail)

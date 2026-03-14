"""
Recon Pipeline API Routes
Handles Zypheron → VibePenTester → Decepticon sequential pipeline
"""
import json
import threading
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from chimera_core.runtime import Runtime
from chimera_core.scope import normalize_scope
from chimera_core.modules.safety.policy import SafetyPolicy
from chimera_core.run_manager import RunManager
from chimera_core.modules.recon_gatherers.orchestrator import (
    run_zypheron_and_persist,
    run_vibepentester_and_persist,
    run_decepticon_and_persist,
)
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.recon_gatherers.decepticon_adapter import DecepticonConfig
from chimera_core.modules.recon_gatherers.sinks.recon_sink import DatabaseReconSink
from chimera_core.modules.recon_gatherers.sinks.inmemory_repository import InMemoryRepository
from chimera_core.event_store import EventStore


router = APIRouter(prefix="/recon", tags=["recon"])


def _load_scope(scope_text: str) -> Dict[str, object]:
    try:
        data = yaml.safe_load(scope_text)
        if not isinstance(data, dict):
            raise ValueError("Scope must be a mapping")
        return data
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/run")
async def create_recon_run(request: Request, payload: Dict[str, object]):
    """
    Executes the Recon Pipeline (Zypheron → VibePenTester → Decepticon)

    Payload:
    - scope_text: YAML scope configuration
    - live: bool - whether to execute in live mode
    - live_confirm: str - must be "I UNDERSTAND" for live mode
    - targets: list - optional target override
    - program_name: str - bug bounty program name
    - rate_limit_rps: int - requests per second
    - timeout_s: int - per-tool timeout
    - allow_destructive: bool - allow sqlmap, ffuf, etc.
    - zypheron_config: dict - Zypheron configuration
    - vibe_entrypoint: list - VibePenTester command
    - vibe_workdir: str - VibePenTester working directory
    - vibe_output_dir: str - VibePenTester output directory
    - vibe_extra_args: list - additional arguments
    - vibe_env: dict - environment variables
    - vibe_timeout_s: int - VibePenTester timeout
    - decepticon_entrypoint: list - Decepticon command
    - decepticon_workdir: str - Decepticon working directory
    - decepticon_output_dir: str - Decepticon output directory
    - decepticon_extra_args: list - additional arguments
    - decepticon_env: dict - environment variables
    - decepticon_timeout_s: int - Decepticon timeout
    """
    scope_text = payload.get("scope_text")
    if not scope_text:
        raise HTTPException(status_code=400, detail="scope_text required")

    live = bool(payload.get("live", False))
    if not live:
        raise HTTPException(status_code=400, detail="Fixture mode has been removed. Set live=true.")
    live_confirm = payload.get("live_confirm", "")

    # Enforce live mode confirmation
    if live and live_confirm != "I UNDERSTAND":
        raise HTTPException(
            status_code=400,
            detail="Live mode requires live_confirm='I UNDERSTAND'. "
                   "Recon pipeline executes real security tools (nmap, sqlmap, etc.)"
        )

    # Parse scope
    try:
        scope_manifest = _load_scope(scope_text)
        scope_graph, scope_policy = normalize_scope(scope_manifest)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {exc}") from exc

    # Extract targets
    targets = payload.get("targets")
    if targets and not isinstance(targets, list):
        raise HTTPException(status_code=400, detail="targets must be a list")
    if not targets:
        targets = scope_graph.allowed_domains
    if not targets:
        raise HTTPException(status_code=400, detail="No targets specified in scope or payload")

    # Create run
    run_manager = RunManager(Path(request.app.state.artifacts_root))
    run = run_manager.create_run(
        scope_hash="recon-pipeline",
        mode="live" if live else "safe"
    )
    run_id = run.run_id

    # Build safety policy
    rate_limit_rps = payload.get("rate_limit_rps", 10)
    timeout_s = payload.get("timeout_s", 1800)
    allow_destructive = payload.get("allow_destructive", False)

    safety_policy = SafetyPolicy(
        enforce_scope=True,
        allow_external_execution=live,
        allowed_tools=frozenset({
            "zypheron", "vibepentester", "decepticon",
            "nmap", "masscan", "nuclei", "subfinder", "amass",
            "nikto", "sqlmap", "wfuzz", "ffuf", "httpx"
        }),
        blocked_tools=frozenset({"rm", "dd", "mkfs", "format"}),
        destructive_tool_markers=frozenset({"sqlmap", "ffuf", "hydra", "wfuzz"}),
        allow_destructive=allow_destructive,
        require_live_confirm=True,
        live_confirm_token=live_confirm if live else None,
        max_workers=payload.get("max_workers", 2),
        rps=rate_limit_rps,
        timeout_s=timeout_s,
    )

    # Build VibePenTester config
    vibe_config = VibePenTesterConfig(
        entrypoint=payload.get("vibe_entrypoint", ["python", "vibe-pentester.py"]),
        workdir=Path(payload.get("vibe_workdir", "/app/tools/vibe-pentester")),
        output_dir=Path(payload.get("vibe_output_dir", f"/artifacts/{run_id}/vibe-reports")),
        extra_args=payload.get("vibe_extra_args", []),
        env=payload.get("vibe_env", {}),
        timeout_s=payload.get("vibe_timeout_s", timeout_s),
        mode="live" if live else "fixture"
    )

    # Build Decepticon config
    decepticon_config = DecepticonConfig(
        entrypoint=payload.get("decepticon_entrypoint", ["python", "decepticon.py"]),
        workdir=Path(payload.get("decepticon_workdir", "/app/tools/decepticon")),
        output_dir=Path(payload.get("decepticon_output_dir", f"/artifacts/{run_id}/decepticon-out")),
        extra_args=payload.get("decepticon_extra_args", []),
        env=payload.get("decepticon_env", {}),
        timeout_s=payload.get("decepticon_timeout_s", timeout_s),
        mode="live" if live else "fixture"
    )

    # Create runtime
    artifacts_root = Path(request.app.state.artifacts_root)
    events_path = artifacts_root / run_id / "events.ndjson"
    events_path.parent.mkdir(parents=True, exist_ok=True)

    event_store = EventStore(events_path)

    runtime = Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
        safety_policy=safety_policy,
        mode="live" if live else "fixture"
    )

    # Create sink
    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)

    # Store run info
    run_info = {
        "status": "created",
        "run_id": run_id,
        "pipeline": "recon",
        "targets": targets,
        "mode": "live" if live else "fixture",
        "created_at": run.created_at.isoformat() if hasattr(run, 'created_at') else None,
    }

    if not hasattr(request.app.state, "recon_runs"):
        request.app.state.recon_runs = {}
    request.app.state.recon_runs[run_id] = run_info

    # Run pipeline in background
    def _run_pipeline():
        try:
            run_info["status"] = "running"
            event_store.emit({
                "event_type": "recon_pipeline_started",
                "payload": {
                    "run_id": run_id,
                    "targets": targets,
                    "mode": "live" if live else "fixture",
                    "message": f"Starting recon pipeline for {len(targets)} target(s)"
                }
            })

            # Step 1: Zypheron (Asset Discovery)
            event_store.emit({
                "event_type": "recon_phase_started",
                "payload": {
                    "run_id": run_id,
                    "phase": "asset_discovery",
                    "tool": "zypheron",
                    "targets": targets
                }
            })

            zypheron_results = []
            for target in targets:
                try:
                    result = run_zypheron_and_persist(
                        target=target,
                        runtime=runtime,
                        sink=sink,
                        program_handle=payload.get("program_name"),
                        replay=False,
                        manifest=None,
                    )
                    zypheron_results.append(result)
                except Exception as exc:
                    event_store.emit({
                        "event_type": "recon_error",
                        "payload": {
                            "run_id": run_id,
                            "phase": "asset_discovery",
                            "tool": "zypheron",
                            "target": target,
                            "error": str(exc)
                        }
                    })

            event_store.emit({
                "event_type": "recon_phase_completed",
                "payload": {
                    "run_id": run_id,
                    "phase": "asset_discovery",
                    "tool": "zypheron",
                    "results_count": len(zypheron_results)
                }
            })

            # Step 2: VibePenTester (Penetration Testing)
            event_store.emit({
                "event_type": "recon_phase_started",
                "payload": {
                    "run_id": run_id,
                    "phase": "penetration_testing",
                    "tool": "vibepentester",
                    "targets": targets
                }
            })

            vibe_results = []
            for target in targets:
                try:
                    result = run_vibepentester_and_persist(
                        target=target,
                        runtime=runtime,
                        config=vibe_config,
                        sink=sink,
                        program_handle=payload.get("program_name"),
                        replay=False,
                        manifest=None,
                    )
                    vibe_results.append(result)
                except Exception as exc:
                    event_store.emit({
                        "event_type": "recon_error",
                        "payload": {
                            "run_id": run_id,
                            "phase": "penetration_testing",
                            "tool": "vibepentester",
                            "target": target,
                            "error": str(exc)
                        }
                    })

            event_store.emit({
                "event_type": "recon_phase_completed",
                "payload": {
                    "run_id": run_id,
                    "phase": "penetration_testing",
                    "tool": "vibepentester",
                    "results_count": len(vibe_results)
                }
            })

            # Step 3: Decepticon (AI Enrichment)
            event_store.emit({
                "event_type": "recon_phase_started",
                "payload": {
                    "run_id": run_id,
                    "phase": "enrichment",
                    "tool": "decepticon",
                    "message": "Analyzing and enriching findings with AI"
                }
            })

            # Collect all bundles
            all_bundles = []
            for result in zypheron_results + vibe_results:
                if hasattr(result, 'bundles'):
                    all_bundles.extend(result.bundles)
                elif hasattr(result, 'bundle'):
                    all_bundles.append(result.bundle)

            decepticon_result = None
            if all_bundles:
                try:
                    decepticon_result = run_decepticon_and_persist(
                        bundles=all_bundles,
                        runtime=runtime,
                        config=decepticon_config,
                        sink=sink,
                        program_handle=payload.get("program_name"),
                        replay=False,
                        manifest=None,
                    )
                except Exception as exc:
                    event_store.emit({
                        "event_type": "recon_error",
                        "payload": {
                            "run_id": run_id,
                            "phase": "enrichment",
                            "tool": "decepticon",
                            "error": str(exc)
                        }
                    })

            event_store.emit({
                "event_type": "recon_phase_completed",
                "payload": {
                    "run_id": run_id,
                    "phase": "enrichment",
                    "tool": "decepticon",
                    "promoted_findings": len(decepticon_result.bundle.findings) if decepticon_result else 0
                }
            })

            # Pipeline completed
            event_store.emit({
                "event_type": "recon_pipeline_completed",
                "payload": {
                    "run_id": run_id,
                    "zypheron_results": len(zypheron_results),
                    "vibepentester_results": len(vibe_results),
                    "decepticon_result": "completed" if decepticon_result else "skipped",
                    "message": "Recon pipeline completed successfully"
                }
            })

            run_info["status"] = "completed"
            run_info["zypheron_results"] = len(zypheron_results)
            run_info["vibepentester_results"] = len(vibe_results)
            run_info["decepticon_completed"] = bool(decepticon_result)

        except Exception as exc:
            event_store.emit({
                "event_type": "recon_pipeline_failed",
                "payload": {
                    "run_id": run_id,
                    "error": str(exc),
                    "message": f"Recon pipeline failed: {exc}"
                }
            })
            run_info["status"] = "failed"
            run_info["error"] = str(exc)

        finally:
            event_store.flush()

    # Start pipeline in background thread
    thread = threading.Thread(target=_run_pipeline, daemon=True)
    thread.start()

    return JSONResponse({
        "run_id": run_id,
        "pipeline": "recon",
        "status": "created",
        "targets": targets,
        "mode": "live" if live else "fixture",
        "message": f"Recon pipeline queued for {len(targets)} target(s). "
                   f"Pipeline: Zypheron → VibePenTester → Decepticon",
        "note": "Monitor progress via GET /recon/runs/{run_id} or stream events via /runs/{run_id}/events"
    })


@router.get("/runs/{run_id}")
async def get_recon_run(request: Request, run_id: str):
    """Get recon pipeline run status and summary"""
    if not hasattr(request.app.state, "recon_runs"):
        request.app.state.recon_runs = {}

    run_info = request.app.state.recon_runs.get(run_id)
    if not run_info:
        raise HTTPException(status_code=404, detail="Recon run not found")

    return JSONResponse(run_info)


@router.get("/runs")
async def list_recon_runs(
    request: Request,
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """List all recon pipeline runs"""
    if not hasattr(request.app.state, "recon_runs"):
        request.app.state.recon_runs = {}

    runs = list(request.app.state.recon_runs.values())
    runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    return JSONResponse({
        "runs": runs[offset:offset+limit],
        "total": len(runs),
        "limit": limit,
        "offset": offset
    })


@router.get("/runs/{run_id}/bundles")
async def get_recon_bundles(request: Request, run_id: str):
    """Get all ReconBundles from a run"""
    artifacts_root = Path(request.app.state.artifacts_root)
    run_dir = artifacts_root / run_id

    if not run_dir.exists():
        raise HTTPException(status_code=404, detail="Run artifacts not found")

    bundles = []

    # Look for bundles in tool directories
    for tool_dir in ["zypheron", "vibepentester", "decepticon"]:
        tool_path = run_dir / tool_dir
        if tool_path.exists():
            bundles.append({
                "tool": tool_dir,
                "artifacts_dir": str(tool_path),
                "has_artifacts": any(tool_path.iterdir())
            })

    return JSONResponse({
        "run_id": run_id,
        "bundles": bundles
    })


@router.get("/runs/{run_id}/suggested_actions")
async def get_suggested_actions(request: Request, run_id: str):
    """Get Decepticon's suggested actions"""
    artifacts_root = Path(request.app.state.artifacts_root)
    actions_path = artifacts_root / run_id / "decepticon" / "suggested_actions.json"

    if not actions_path.exists():
        return JSONResponse({
            "run_id": run_id,
            "suggested_actions": [],
            "message": "No suggested actions yet. Decepticon may still be running or found no actions."
        })

    try:
        actions = json.loads(actions_path.read_text(encoding="utf-8"))
        return JSONResponse({
            "run_id": run_id,
            "suggested_actions": actions,
            "count": len(actions) if isinstance(actions, list) else 0
        })
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read actions: {exc}") from exc


@router.get("/runs/{run_id}/analysis_notes")
async def get_analysis_notes(request: Request, run_id: str):
    """Get Decepticon's analysis notes (markdown)"""
    artifacts_root = Path(request.app.state.artifacts_root)
    notes_path = artifacts_root / run_id / "decepticon" / "notes.md"

    if not notes_path.exists():
        return JSONResponse({
            "run_id": run_id,
            "notes": "",
            "message": "No analysis notes yet. Decepticon may still be running."
        })

    try:
        notes = notes_path.read_text(encoding="utf-8")
        return JSONResponse({
            "run_id": run_id,
            "notes": notes,
            "format": "markdown"
        })
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read notes: {exc}") from exc

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


def reconcile_run(
    *,
    run_id: str,
    artifacts_dir: Path,
    expected_status: str,
    failed_tasks: List[str],
    findings_total: int,
) -> Dict[str, object]:
    events_path = artifacts_dir / "events.jsonl"
    events = []
    if events_path.exists():
        for line in events_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))

    missing_artifacts: List[str] = []
    artifact_events = [event for event in events if event.get("event_type") == "artifact_saved"]
    for event in artifact_events:
        path = Path(str((event.get("payload") or {}).get("path") or ""))
        if not path.exists():
            missing_artifacts.append(str(path))

    findings_path = artifacts_dir / "findings.json"
    if findings_total > 0 and not findings_path.exists():
        missing_artifacts.append(str(findings_path))

    consistent = not missing_artifacts
    effective_status = expected_status
    if expected_status == "completed" and not consistent:
        effective_status = "failed"

    return {
        "run_id": run_id,
        "expected_status": expected_status,
        "effective_status": effective_status,
        "consistent": consistent,
        "missing_artifacts": missing_artifacts,
        "failed_tasks": list(failed_tasks),
        "findings_total": findings_total,
        "event_count": len(events),
    }

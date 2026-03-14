from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from chimera_core.findings import Finding
from chimera_core.sinks.supabase import SupabaseSink


def sync_run_directory(artifacts_root: Path, run_id: str, sink: SupabaseSink) -> Dict[str, int]:
    run_dir = Path(artifacts_root) / run_id
    run_payload = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    sink.emit_event({"event_type": "run_upsert", "payload": run_payload})

    events_count = 0
    for events_name in ("events.jsonl", "events.ndjson"):
        events_path = run_dir / events_name
        if not events_path.exists():
            continue
        for line in events_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            sink.emit_event(json.loads(line))
            events_count += 1

    findings_path = run_dir / "findings.json"
    findings_count = 0
    if findings_path.exists():
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        for payload in findings:
            sink.emit_finding(_finding_from_payload(payload))
            findings_count += 1
    sink.flush()
    return {"events": events_count, "findings": findings_count}


def _finding_from_payload(payload: Dict[str, object]) -> Finding:
    return Finding(
        finding_id=str(payload["finding_id"]),
        severity=str(payload["severity"]),
        title=str(payload["title"]),
        description=str(payload["description"]),
        affected_target=str(payload["affected_target"]),
        tool_source=str(payload["tool_source"]),
        tool_version=str(payload["tool_version"]),
        run_id=str(payload["run_id"]),
        scope_hash=str(payload["scope_hash"]),
        evidence_refs=list(payload.get("evidence_refs", [])),
        repro_guidance=payload.get("repro_guidance"),
        status=str(payload.get("status", "new")),
        finding_type=payload.get("finding_type"),
        asset=payload.get("asset"),
        auth_context=payload.get("auth_context"),
        validation_status=payload.get("validation_status"),
        validation_reason=payload.get("validation_reason"),
        confidence=payload.get("confidence"),
        prerequisites=list(payload.get("prerequisites", [])),
        chain_parent_ids=list(payload.get("chain_parent_ids", [])),
        impact_path=list(payload.get("impact_path", [])),
        proof_artifacts=list(payload.get("proof_artifacts", [])),
        sink=payload.get("sink"),
        replay_steps=list(payload.get("replay_steps", [])),
    )

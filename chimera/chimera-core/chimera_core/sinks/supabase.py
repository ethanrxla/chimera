from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import uuid4

import httpx

from chimera_core.findings import Finding
from chimera_core.sinks.base import EventSink


class SupabaseSink(EventSink):
    def __init__(
        self,
        supabase_url: str,
        service_role_key: str,
        run_id: str,
        *,
        batch_size: int = 50,
        batch_interval_s: float = 2.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.supabase_url = supabase_url.rstrip("/")
        self.service_role_key = service_role_key
        self.run_id = run_id
        self.batch_size = batch_size
        self.batch_interval_s = batch_interval_s
        self._events: List[Dict[str, object]] = []
        self._findings: List[Dict[str, object]] = []
        self._last_flush = time.monotonic()
        self._client = client or httpx.Client(
            timeout=10.0,
            headers={
                "apikey": service_role_key,
                "Authorization": f"Bearer {service_role_key}",
                "Content-Type": "application/json",
            },
        )

    def emit_event(self, event: dict) -> None:
        event_type = event.get("event_type") or event.get("type")
        if event_type == "run_upsert":
            payload = event.get("payload") or {}
            if payload:
                self._upsert_run(payload)
            return
        self._events.append(self._event_record(event))
        self._maybe_flush()

    def emit_finding(self, finding: Finding) -> None:
        self._findings.append(self._finding_record(finding))
        self._maybe_flush()

    def flush(self) -> None:
        self._flush_batches()

    def _event_record(self, event: dict) -> Dict[str, object]:
        payload = event.get("payload") or {}
        run_id = payload.get("run_id") or event.get("run_id") or self.run_id
        return {
            "id": event.get("event_id") or str(uuid4()),
            "run_id": run_id,
            "ts": event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "type": event.get("event_type") or event.get("type") or "event",
            "task_id": payload.get("task_id"),
            "adapter": payload.get("adapter") or payload.get("tool"),
            "target": payload.get("target"),
            "payload": payload,
        }

    def _finding_record(self, finding: Finding) -> Dict[str, object]:
        return {
            "finding_id": finding.finding_id,
            "run_id": finding.run_id,
            "tool": finding.tool_source,
            "target": finding.affected_target,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "evidence": {
                "evidence_refs": finding.evidence_refs,
                "repro_guidance": finding.repro_guidance,
            },
            "hash": finding.finding_id,
        }

    def _maybe_flush(self) -> None:
        if len(self._events) + len(self._findings) >= self.batch_size:
            self._flush_batches()
            return
        now = time.monotonic()
        if now - self._last_flush >= self.batch_interval_s:
            self._flush_batches()

    def _flush_batches(self) -> None:
        if self._events:
            payload = list(self._events)
            self._events.clear()
            self._post("events", payload)
        if self._findings:
            payload = list(self._findings)
            self._findings.clear()
            self._post("findings", payload)
        self._last_flush = time.monotonic()

    def _upsert_run(self, payload: Dict[str, object]) -> None:
        self._post("runs", [payload], upsert=True, on_conflict="run_id")

    def _post(
        self,
        table: str,
        payload: List[Dict[str, object]],
        *,
        upsert: bool = False,
        on_conflict: Optional[str] = None,
    ) -> None:
        if not payload:
            return
        query = f"?on_conflict={on_conflict}" if upsert and on_conflict else ""
        prefer = "return=minimal"
        if upsert:
            prefer = "resolution=merge-duplicates,return=minimal"
        response = self._client.post(
            f"{self.supabase_url}/rest/v1/{table}{query}",
            json=payload,
            headers={"Prefer": prefer},
        )
        response.raise_for_status()

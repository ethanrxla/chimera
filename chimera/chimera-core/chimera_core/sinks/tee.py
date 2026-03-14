from __future__ import annotations

from typing import Optional

from chimera_core.findings import Finding
from chimera_core.sinks.base import EventSink


class TeeSink(EventSink):
    def __init__(self, local_sink: EventSink, supabase_sink: Optional[EventSink]) -> None:
        self.local_sink = local_sink
        self.supabase_sink = supabase_sink
        self._supabase_enabled = bool(supabase_sink)

    def emit_event(self, event: dict) -> None:
        self.local_sink.emit_event(event)
        if not self._supabase_enabled:
            return
        try:
            if self.supabase_sink:
                self.supabase_sink.emit_event(event)
        except Exception as exc:
            self._disable_supabase(str(exc), event)

    def emit_finding(self, finding: Finding) -> None:
        self.local_sink.emit_finding(finding)
        if not self._supabase_enabled:
            return
        try:
            if self.supabase_sink:
                self.supabase_sink.emit_finding(finding)
        except Exception as exc:
            self._disable_supabase(str(exc), {"payload": {"run_id": finding.run_id}})

    def flush(self) -> None:
        self.local_sink.flush()
        if not self._supabase_enabled:
            return
        try:
            if self.supabase_sink:
                self.supabase_sink.flush()
        except Exception as exc:
            self._disable_supabase(str(exc), {})

    def _disable_supabase(self, message: str, event: dict) -> None:
        if not self._supabase_enabled:
            return
        self._supabase_enabled = False
        payload = event.get("payload") or {}
        run_id = payload.get("run_id")
        self.local_sink.emit_event(
            {
                "event_type": "sink_error",
                "payload": {
                    "run_id": run_id,
                    "message": message,
                },
            }
        )

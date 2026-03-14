from __future__ import annotations

from chimera_core.findings import Finding


class EventSink:
    def emit_event(self, event: dict) -> None:
        raise NotImplementedError

    def emit_finding(self, finding: Finding) -> None:
        raise NotImplementedError

    def flush(self) -> None:
        return None

    def emit(self, event: dict) -> None:
        self.emit_event(event)

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, UTC
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional
from uuid import uuid4


@dataclass(frozen=True)
class EventCursor:
    offset: int


@dataclass(frozen=True)
class FindingValidated:
    finding_id: str
    validation_status: str
    confidence: float
    validator_name: str


@dataclass(frozen=True)
class ChainDiscovered:
    root_finding_id: str
    chain_ids: List[str]
    combined_severity: str
    impact_summary: str


@dataclass(frozen=True)
class FalsePositiveRejected:
    finding_id: str
    reason: str
    validator_name: str


def event_payload(event: Any) -> Dict[str, Any]:
    if hasattr(event, "__dataclass_fields__"):
        return asdict(event)
    if isinstance(event, dict):
        return event
    raise TypeError(f"Unsupported event payload type: {type(event)!r}")


class EventStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def append(self, event: Dict[str, Any]) -> EventCursor:
        serialized = json.dumps(event, ensure_ascii=True)
        with self.path.open("a", encoding="utf-8") as handle:
            offset = handle.tell()
            handle.write(serialized + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return EventCursor(offset=offset)

    def replay(self, cursor: Optional[EventCursor] = None) -> Iterator[tuple[EventCursor, Dict[str, Any]]]:
        start = cursor.offset if cursor else 0
        with self.path.open("r", encoding="utf-8") as handle:
            handle.seek(start)
            while True:
                offset = handle.tell()
                line = handle.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                next_cursor = EventCursor(offset=handle.tell())
                yield next_cursor, event


class EventLogSink:
    def __init__(self, store: EventStore, run_id: str, source: str = "orchestrator") -> None:
        self.store = store
        self.run_id = run_id
        self.source = source
        self._seq = 0

    def emit(self, event: Dict[str, Any]) -> EventCursor:
        self._seq += 1
        envelope = {
            "event_id": event.get("event_id") or str(uuid4()),
            "run_id": event.get("run_id") or self.run_id,
            "seq": event.get("seq") or self._seq,
            "event_type": event["event_type"],
            "timestamp": event.get("timestamp") or datetime.now(UTC).isoformat(),
            "source": event.get("source") or self.source,
            "payload": event.get("payload") or {},
        }
        return self.store.append(envelope)


class EventBus:
    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callable[[Any], None]]] = {}

    def subscribe(self, event_name: str, handler: Callable[[Any], None]) -> None:
        self._subscribers.setdefault(event_name, []).append(handler)

    def emit(self, event_name: str, payload: Any = None) -> None:
        for handler in self._subscribers.get(event_name, []):
            handler(payload)


class DiskEventBus(EventBus):
    def __init__(self, sink: EventLogSink) -> None:
        super().__init__()
        self.sink = sink

    def emit(self, event_name: str, payload: Any = None) -> None:
        self.emit_event({"event_type": event_name, "payload": payload or {}})
        super().emit(event_name, payload)

    def emit_event(self, event: Dict[str, Any]) -> EventCursor:
        cursor = self.sink.emit(event)
        return cursor
        super().emit(event_name, payload)

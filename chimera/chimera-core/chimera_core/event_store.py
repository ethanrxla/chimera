from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, Generator, Optional
from uuid import uuid4


class EventStore:
    def __init__(self, events_file: Path, *, run_id: Optional[str] = None, source: str = "chimera") -> None:
        self.events_file = Path(events_file)
        self.events_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.events_file.exists():
            self.events_file.touch()
        self.run_id = run_id
        self.source = source
        self._lock = threading.Lock()
        self._seq = self._load_last_seq()

    def _load_last_seq(self) -> int:
        last_seq = 0
        try:
            with self.events_file.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(event, dict):
                        seq = event.get("seq")
                        if isinstance(seq, int):
                            last_seq = max(last_seq, seq)
        except FileNotFoundError:
            return 0
        return last_seq

    def _normalize(self, event: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(event.get("payload") or {})
        run_id = event.get("run_id") or payload.get("run_id") or self.run_id or "unknown-run"
        source = str(event.get("source") or self.source)
        with self._lock:
            seq = event.get("seq")
            if not isinstance(seq, int):
                self._seq += 1
                seq = self._seq
            else:
                self._seq = max(self._seq, seq)
        return {
            "event_id": str(event.get("event_id") or uuid4()),
            "run_id": str(run_id),
            "seq": seq,
            "event_type": str(event["event_type"]),
            "timestamp": str(event.get("timestamp") or datetime.now(UTC).isoformat()),
            "source": source,
            "payload": payload,
        }

    def emit(self, event: Dict[str, Any]) -> Dict[str, Any]:
        envelope = self._normalize(event)
        serialized = json.dumps(envelope, ensure_ascii=True)
        with self._lock:
            with self.events_file.open("a", encoding="utf-8") as handle:
                handle.write(serialized + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return envelope

    def emit_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return self.emit(event)

    def replay(self) -> Generator[Dict[str, Any], None, None]:
        if not self.events_file.exists():
            return
        with self.events_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)

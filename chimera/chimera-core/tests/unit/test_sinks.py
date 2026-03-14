import json
from pathlib import Path

from chimera_core.sinks.local import LocalSink
from chimera_core.sinks.supabase import SupabaseSink
from chimera_core.sinks.tee import TeeSink


class FailingSink:
    def emit_event(self, event: dict) -> None:
        raise RuntimeError("boom")

    def emit_finding(self, finding) -> None:
        raise RuntimeError("boom")

    def flush(self) -> None:
        raise RuntimeError("boom")


def _read_event_types(events_path: Path) -> list[str]:
    lines = events_path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line)["event_type"] for line in lines if line.strip()]


def test_tee_sink_always_writes_local(tmp_path: Path) -> None:
    local_sink = LocalSink(tmp_path, "run-1")
    tee = TeeSink(local_sink, FailingSink())

    tee.emit_event({"event_type": "cmd_started", "payload": {"run_id": "run-1"}})

    events_path = tmp_path / "events.jsonl"
    event_types = _read_event_types(events_path)
    assert "cmd_started" in event_types


def test_supabase_failure_emits_sink_error_and_continues(tmp_path: Path) -> None:
    local_sink = LocalSink(tmp_path, "run-2")
    tee = TeeSink(local_sink, FailingSink())

    tee.emit_event({"event_type": "cmd_started", "payload": {"run_id": "run-2"}})
    tee.emit_event({"event_type": "cmd_finished", "payload": {"run_id": "run-2"}})

    events_path = tmp_path / "events.jsonl"
    event_types = _read_event_types(events_path)
    assert event_types.count("sink_error") == 1
    assert event_types.count("cmd_started") == 1
    assert event_types.count("cmd_finished") == 1


def test_events_batched_and_flushed() -> None:
    calls = []

    def fake_post(table: str, payload: list[dict], **kwargs) -> None:
        calls.append((table, payload, kwargs))

    sink = SupabaseSink("http://example", "key", "run-3", batch_size=2, batch_interval_s=999)
    sink._post = fake_post  # type: ignore[assignment]

    sink.emit_event({"event_type": "cmd_started", "payload": {"run_id": "run-3"}})
    assert calls == []
    sink.emit_event({"event_type": "cmd_finished", "payload": {"run_id": "run-3"}})
    assert len(calls) == 1
    assert calls[0][0] == "events"
    assert len(calls[0][1]) == 2

    sink.emit_event({"event_type": "artifact_saved", "payload": {"run_id": "run-3"}})
    sink.flush()
    assert len(calls) == 2
    assert calls[1][0] == "events"
    assert len(calls[1][1]) == 1


def test_run_upsert_on_start() -> None:
    calls = []

    def fake_post(table: str, payload: list[dict], **kwargs) -> None:
        calls.append((table, payload, kwargs))

    sink = SupabaseSink("http://example", "key", "run-4")
    sink._post = fake_post  # type: ignore[assignment]

    payload = {"run_id": "run-4", "status": "created"}
    sink.emit_event({"event_type": "run_upsert", "payload": payload})

    assert len(calls) == 1
    assert calls[0][0] == "runs"
    assert calls[0][1] == [payload]
    assert calls[0][2].get("upsert") is True
    assert calls[0][2].get("on_conflict") == "run_id"

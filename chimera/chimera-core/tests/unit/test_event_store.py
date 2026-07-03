import pytest
import json
from pathlib import Path

from chimera_core.event_store import EventStore

@pytest.fixture
def events_file(tmp_path: Path) -> Path:
    file_path = tmp_path / "events.jsonl"
    file_path.touch()
    return file_path

def test_event_store_appends_event(events_file: Path):
    event_store = EventStore(events_file, run_id="run-1", source="unit-test")
    event = {"event_type": "test_event", "payload": {"data": "test"}}
    
    emitted = event_store.emit(event)
    
    # Read the file to verify
    lines = events_file.read_text().strip().split('\n')
    assert len(lines) == 1
    stored = json.loads(lines[0])
    assert stored == emitted
    assert stored["run_id"] == "run-1"
    assert stored["seq"] == 1
    assert stored["source"] == "unit-test"
    assert stored["event_type"] == "test_event"
    assert stored["payload"] == {"data": "test"}
    assert stored["event_id"]
    assert stored["timestamp"]

def test_event_store_appends_multiple_events(events_file: Path):
    event_store = EventStore(events_file, run_id="run-1", source="unit-test")
    event1 = {"event_type": "test_event_1", "payload": {"data": "test1"}}
    event2 = {"event_type": "test_event_2", "payload": {"data": "test2"}}
    
    event_store.emit(event1)
    event_store.emit(event2)
    
    lines = events_file.read_text().strip().split('\n')
    assert len(lines) == 2
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first["seq"] == 1
    assert second["seq"] == 2
    assert first["run_id"] == second["run_id"] == "run-1"
    assert first["event_type"] == "test_event_1"
    assert second["event_type"] == "test_event_2"

def test_event_store_replay(events_file: Path):
    event_store = EventStore(events_file, run_id="run-replay", source="unit-test")
    event_store.emit({"event_type": "replay_event_1", "payload": {"data": "replay1"}})
    event_store.emit({"event_type": "replay_event_2", "payload": {"data": "replay2"}})

    replayed_events = list(event_store.replay())
    assert len(replayed_events) == 2
    assert replayed_events[0]["seq"] == 1
    assert replayed_events[1]["seq"] == 2
    assert replayed_events[0]["event_type"] == "replay_event_1"
    assert replayed_events[1]["event_type"] == "replay_event_2"


def test_event_store_uses_payload_run_id_and_continues_seq(events_file: Path):
    event_store = EventStore(events_file, source="unit-test")
    first = event_store.emit({"event_type": "first", "payload": {"run_id": "run-a"}})
    second = event_store.emit({"event_type": "second", "payload": {"run_id": "run-a"}})

    reloaded = EventStore(events_file, source="unit-test")
    third = reloaded.emit({"event_type": "third", "payload": {"run_id": "run-a"}})

    assert first["run_id"] == "run-a"
    assert second["seq"] == 2
    assert third["seq"] == 3

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
    event_store = EventStore(events_file)
    event = {"event_type": "test_event", "payload": {"data": "test"}}
    
    event_store.emit(event)
    
    # Read the file to verify
    lines = events_file.read_text().strip().split('\n')
    assert len(lines) == 1
    assert json.loads(lines[0]) == event

def test_event_store_appends_multiple_events(events_file: Path):
    event_store = EventStore(events_file)
    event1 = {"event_type": "test_event_1", "payload": {"data": "test1"}}
    event2 = {"event_type": "test_event_2", "payload": {"data": "test2"}}
    
    event_store.emit(event1)
    event_store.emit(event2)
    
    lines = events_file.read_text().strip().split('\n')
    assert len(lines) == 2
    assert json.loads(lines[0]) == event1
    assert json.loads(lines[1]) == event2

def test_event_store_replay(events_file: Path):
    # Prepare a file with existing events
    event1 = {"event_type": "replay_event_1", "payload": {"data": "replay1"}}
    event2 = {"event_type": "replay_event_2", "payload": {"data": "replay2"}}
    with events_file.open("w") as f:
        f.write(json.dumps(event1) + "\n")
        f.write(json.dumps(event2) + "\n")

    event_store = EventStore(events_file)
    replayed_events = list(event_store.replay())

    assert len(replayed_events) == 2
    assert replayed_events[0] == event1
    assert replayed_events[1] == event2
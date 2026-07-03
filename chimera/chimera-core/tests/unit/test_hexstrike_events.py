from pathlib import Path

from chimera_core.event_store import EventStore
from chimera_core.hexstrike.events import (
    emit_hexstrike_call_finished,
    emit_hexstrike_call_started,
    emit_scope_violation,
)


def make_store(tmp_path: Path) -> EventStore:
    events_file = tmp_path / "events.jsonl"
    return EventStore(events_file)


def test_event_helpers_emit_expected_hexstrike_events(tmp_path: Path) -> None:
    store = make_store(tmp_path)

    emit_hexstrike_call_started(
        store,
        run_id="run-hx",
        task_id="HX1",
        agent="shannon_executor",
        tool_name="probe",
        route="/api/probe",
        target_refs=["https://example.com/login"],
    )
    emit_hexstrike_call_finished(
        store,
        run_id="run-hx",
        task_id="HX1",
        agent="shannon_executor",
        tool_name="probe",
        status="completed",
        duration_ms=12,
        artifact_paths=["/tmp/response.json"],
        finding_count=1,
    )
    emit_scope_violation(
        store,
        run_id="run-hx",
        task_id="HX2",
        agent="shannon_executor",
        tool_name="probe",
        rejected_targets=["https://evil.com/login"],
        reason="out_of_scope",
    )

    events = list(store.replay())
    assert [event["event_type"] for event in events] == [
        "hexstrike_call_started",
        "hexstrike_call_finished",
        "scope_violation",
    ]
    assert events[0]["payload"]["tool_name"] == "probe"
    assert events[1]["payload"]["finding_count"] == 1
    assert events[2]["payload"]["rejected_targets"] == ["https://evil.com/login"]

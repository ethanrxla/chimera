import json
from pathlib import Path

from chimera_core.db_sync import sync_run_directory
from chimera_core.findings import Finding


class FakeSink:
    def __init__(self) -> None:
        self.events = []
        self.findings = []
        self.flushed = False

    def emit_event(self, event: dict) -> None:
        self.events.append(event)

    def emit_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def flush(self) -> None:
        self.flushed = True


def test_sync_run_directory_replays_existing_artifacts(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    (run_dir / "run.json").write_text(json.dumps({"run_id": "run-1", "status": "completed"}), encoding="utf-8")
    (run_dir / "events.jsonl").write_text(json.dumps({"event_type": "run_created", "payload": {"run_id": "run-1"}}) + "\n", encoding="utf-8")
    (run_dir / "findings.json").write_text(
        json.dumps(
            [
                {
                    "finding_id": "f1",
                    "severity": "low",
                    "title": "Leak",
                    "description": "desc",
                    "affected_target": "https://example.com",
                    "tool_source": "tool",
                    "tool_version": "1.0",
                    "run_id": "run-1",
                    "scope_hash": "scope",
                    "status": "new",
                }
            ]
        ),
        encoding="utf-8",
    )

    sink = FakeSink()
    counts = sync_run_directory(tmp_path, "run-1", sink)

    assert counts == {"events": 1, "findings": 1}
    assert sink.flushed is True
    assert sink.events[0]["event_type"] == "run_upsert"
    assert sink.findings[0].finding_id == "f1"

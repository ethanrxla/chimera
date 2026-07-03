import json
from pathlib import Path

from chimera_core.reconciliation import reconcile_run


def test_reconcile_run_reports_missing_artifact_and_flips_completed_status(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)
    events_path = run_dir / "events.jsonl"
    events_path.write_text(
        json.dumps(
            {
                "event_id": "e1",
                "run_id": "run-1",
                "seq": 1,
                "event_type": "artifact_saved",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "source": "test",
                "payload": {"path": str(run_dir / "missing.json"), "artifact_type": "report"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = reconcile_run(
        run_id="run-1",
        artifacts_dir=run_dir,
        expected_status="completed",
        failed_tasks=[],
        findings_total=0,
    )

    assert result["consistent"] is False
    assert result["effective_status"] == "failed"
    assert result["missing_artifacts"]


def test_reconcile_run_accepts_consistent_run(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-2"
    run_dir.mkdir(parents=True, exist_ok=True)
    findings_path = run_dir / "findings.json"
    findings_path.write_text("[]", encoding="utf-8")
    events_path = run_dir / "events.jsonl"
    events_path.write_text(
        json.dumps(
            {
                "event_id": "e1",
                "run_id": "run-2",
                "seq": 1,
                "event_type": "artifact_saved",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "source": "test",
                "payload": {"path": str(findings_path), "artifact_type": "findings"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = reconcile_run(
        run_id="run-2",
        artifacts_dir=run_dir,
        expected_status="completed",
        failed_tasks=[],
        findings_total=0,
    )

    assert result["consistent"] is True
    assert result["effective_status"] == "completed"

import json
from datetime import datetime, timezone
from pathlib import Path

from chimera_core.run_store import RunStore


def test_run_json_written_on_create(tmp_path: Path):
    store = RunStore(tmp_path / "artifacts")
    run_id = "run-1"
    store.create_run(
        run_id,
        scope_raw="allowlist: ['example.com']\n",
        scope_normalized={"allowlist": ["example.com"], "denylist": []},
        plan={"tasks": [{"task_id": "t1", "adapter": "strix", "target": "example.com", "depends_on": [], "options": {}}]},
        options={"live": False},
    )
    run_file = tmp_path / "artifacts" / run_id / "run.json"
    assert run_file.exists()
    payload = json.loads(run_file.read_text(encoding="utf-8"))
    assert payload["run_id"] == run_id
    assert payload["plan"]["tasks"]


def test_run_json_updated_on_finish(tmp_path: Path):
    store = RunStore(tmp_path / "artifacts")
    run_id = "run-2"
    store.create_run(
        run_id,
        scope_raw="allowlist: ['example.com']\n",
        scope_normalized={"allowlist": ["example.com"], "denylist": []},
        plan={"tasks": []},
        options={"live": False},
    )
    record = store.update_run(run_id, status="completed", stats={"tasks_total": 0, "findings_total": 1, "duplicates": 0})
    assert record.data["status"] == "completed"
    assert record.data["ended_at"] is not None
    assert record.data["stats"]["findings_total"] == 1


def test_run_json_updated_on_cancel(tmp_path: Path):
    store = RunStore(tmp_path / "artifacts")
    run_id = "run-3"
    store.create_run(
        run_id,
        scope_raw="allowlist: ['example.com']\n",
        scope_normalized={"allowlist": ["example.com"], "denylist": []},
        plan={"tasks": []},
        options={"live": False},
    )
    record = store.update_run(run_id, status="cancelled")
    assert record.data["status"] == "cancelled"
    assert record.data["ended_at"] is not None


def test_list_runs_sorted_desc(tmp_path: Path):
    store = RunStore(tmp_path / "artifacts")
    store.create_run(
        "run-older",
        scope_raw="allowlist: ['example.com']\n",
        scope_normalized={"allowlist": ["example.com"], "denylist": []},
        plan={"tasks": []},
        options={"live": False},
        created_at=datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(),
    )
    store.create_run(
        "run-newer",
        scope_raw="allowlist: ['example.com']\n",
        scope_normalized={"allowlist": ["example.com"], "denylist": []},
        plan={"tasks": []},
        options={"live": False},
        created_at=datetime(2021, 1, 1, tzinfo=timezone.utc).isoformat(),
    )
    runs = store.list_runs()
    assert runs[0]["run_id"] == "run-newer"
    assert runs[1]["run_id"] == "run-older"


def test_get_run_returns_snapshots(tmp_path: Path):
    store = RunStore(tmp_path / "artifacts")
    run_id = "run-4"
    store.create_run(
        run_id,
        scope_raw="allowlist: ['example.com']\n",
        scope_normalized={"allowlist": ["example.com"], "denylist": []},
        plan={"tasks": []},
        options={"live": False},
    )
    record = store.get_run(run_id)
    assert record.data["scope_raw"]
    assert "scope_normalized" in record.data

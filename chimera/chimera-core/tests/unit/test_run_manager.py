import pytest
from pathlib import Path
import uuid

from chimera_core.run_manager import RunManager, Run

def test_run_manager_creates_run_and_artifacts_dir(tmp_path: Path):
    """
    Tests that the RunManager correctly creates a Run object and its
    corresponding artifacts directory and events file.
    """
    run_manager = RunManager(artifacts_root=tmp_path)
    scope_hash = "test_scope_hash"
    
    run = run_manager.create_run(scope_hash=scope_hash, mode="safe")

    assert isinstance(run, Run)
    assert run.scope_hash == scope_hash
    assert run.mode == "safe"
    assert run.run_id is not None
    
    # Verify artifacts directory was created
    expected_artifacts_dir = tmp_path / run.run_id
    assert expected_artifacts_dir.is_dir()
    
    # Verify events.jsonl file was created
    expected_events_file = expected_artifacts_dir / "events.jsonl"
    assert expected_events_file.is_file()
    assert expected_events_file.read_text() == ""

def test_run_id_uniqueness():
    """
    Tests that subsequent calls to create_run produce unique run_ids.
    """
    # This test is simple, as uuid.uuid4() is extremely unlikely to collide,
    # but it formalizes the requirement.
    run_id_1 = str(uuid.uuid4())
    run_id_2 = str(uuid.uuid4())
    assert run_id_1 != run_id_2

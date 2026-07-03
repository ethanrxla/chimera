from pathlib import Path

from chimera_core.orchestrator import Orchestrator


def test_orchestrator_applies_rate_limit(monkeypatch, tmp_path: Path):
    captured = {}

    class FakeRuntime:
        def __init__(self, scope_graph, scope_policy, event_store, artifacts_root, run_id, cancel_event=None, **kwargs):
            captured["max_rps"] = scope_policy.max_rps
            self.scope_graph = scope_graph
            self.scope_policy = scope_policy
            self.event_store = event_store
            self.artifacts_root = artifacts_root
            self.run_id = run_id

    def fake_execute(self, plan):
        return []

    monkeypatch.setattr("chimera_core.orchestrator.Runtime", FakeRuntime)
    monkeypatch.setattr("chimera_core.orchestrator.PlanRunner.execute", fake_execute)

    orchestrator = Orchestrator(
        artifacts_root=tmp_path / "artifacts",
        fixture_registry={},
        live=False,
        max_workers=1,
        rate_limit_rps=7,
    )
    job = orchestrator.create_job_from_manifest({"allowlist": ["example.com"], "denylist": []}, mode="safe")
    orchestrator.start_run(job.job_id)

    assert captured["max_rps"] == 7


def test_orchestrator_emits_run_reconciled(monkeypatch, tmp_path: Path):
    def fake_execute(self, plan):
        return []

    monkeypatch.setattr("chimera_core.orchestrator.PlanRunner.execute", fake_execute)

    orchestrator = Orchestrator(
        artifacts_root=tmp_path / "artifacts",
        fixture_registry={},
        live=False,
        max_workers=1,
    )
    job = orchestrator.create_job_from_manifest({"allowlist": ["example.com"], "denylist": []}, mode="safe")
    run_id, artifacts_dir = orchestrator.start_run(job.job_id)

    assert run_id is not None
    events_path = artifacts_dir / "events.jsonl"
    contents = events_path.read_text(encoding="utf-8")
    assert '"event_type": "run_reconciled"' in contents

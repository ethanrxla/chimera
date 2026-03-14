from pathlib import Path

from chimera_core.orchestrator import Orchestrator


def test_orchestrator_fixture_run(tmp_path: Path):
    scope_file = tmp_path / "scope.yml"
    scope_file.write_text(
        "allowlist:\n"
        "  - \"https://api.example.com/api\"\n"
        "denylist:\n"
        "  - \"https://blocked.example.com\"\n",
        encoding="utf-8",
    )

    fixtures = {
        "autoswagger": str(Path(__file__).resolve().parents[1] / "fixtures" / "autoswagger" / "output.json")
    }
    artifacts_root = tmp_path / "artifacts"
    orchestrator = Orchestrator(artifacts_root=artifacts_root, fixture_registry=fixtures, live=False)
    job = orchestrator.create_job(str(scope_file), mode="safe")
    orchestrator.start_run(job.job_id)

    run_dirs = [p for p in artifacts_root.iterdir() if p.is_dir()]
    assert run_dirs, "Expected a run artifacts directory"
    run_dir = run_dirs[0]
    assert (run_dir / "findings.json").exists()
    assert (run_dir / "chains.json").exists()
    assert (run_dir / "chain_graphs.json").exists()
    assert (run_dir / "rejected_findings.json").exists()
    assert (run_dir / "poc_bundles").exists()
    assert (run_dir / "report.md").exists()
    assert (run_dir / "summary.json").exists()

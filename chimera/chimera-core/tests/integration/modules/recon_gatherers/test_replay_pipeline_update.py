import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.modules.recon_gatherers.orchestrator import run_vibepentester_and_persist
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.recon_gatherers.schemas import Finding
from chimera_core.modules.recon_gatherers.sinks.recon_sink import DatabaseReconSink
from chimera_core.modules.recon_gatherers.sinks.inmemory_repository import InMemoryRepository
from chimera_core.modules.recon_gatherers.notify.shannon_client import ShannonClient
from chimera_core.modules.runtime.run_manifest import RunManifest


def _build_runtime(tmp_path: Path, run_id: str) -> MagicMock:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    runtime = MagicMock(spec=Runtime)
    runtime.run_id = run_id
    runtime.artifacts_root = tmp_path / "artifacts"
    runtime.scope_graph = ScopeGraph(scope_manifest)
    runtime.scope_policy = ScopePolicy(scope_manifest)
    runtime.run_external_tool = MagicMock()
    runtime.mode = "fixture"
    return runtime


def test_replay_updates_findings_without_execution(tmp_path: Path):
    runtime = _build_runtime(tmp_path, "run-1")
    output_dir = tmp_path / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / "report.md"
    report_path.write_text("## Low: Info\nSeverity: Low", encoding="utf-8")

    runtime.run_external_tool.return_value = MagicMock(ok=True, exit_code=0, stdout="ok", stderr="")

    config = VibePenTesterConfig(workdir=tmp_path, output_dir=output_dir, entrypoint=["python", "vibe.py"])
    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)
    notifier = MagicMock(spec=ShannonClient)

    run_vibepentester_and_persist(
        target="example.com",
        runtime=runtime,
        config=config,
        sink=sink,
        notifier=notifier,
    )

    manifest_path = runtime.artifacts_root / runtime.run_id / "run_manifest.json"
    manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest = RunManifest.from_dict(manifest_payload)

    replay_runtime = _build_runtime(tmp_path, "run-2")
    replay_runtime.run_external_tool = MagicMock()
    replay_repo = InMemoryRepository()
    replay_sink = DatabaseReconSink(repository=replay_repo)
    replay_notifier = MagicMock(spec=ShannonClient)

    extra_finding = Finding(title="New Finding", type="vuln", severity="high")
    with patch(
        "chimera_core.modules.recon_gatherers.orchestrator.parse_vibepentester_reports",
        return_value=([extra_finding], []),
    ):
        run_vibepentester_and_persist(
            target="example.com",
            runtime=replay_runtime,
            config=config,
            sink=replay_sink,
            notifier=replay_notifier,
            replay=True,
            manifest=manifest,
        )

    replay_runtime.run_external_tool.assert_not_called()

    replay_run_id = list(replay_repo.runs.keys())[0]
    assert replay_repo.findings[replay_run_id]
    assert replay_repo.findings[replay_run_id][0]["title"] == "New Finding"

    replay_notifier.send_recon_summary.assert_called_once()

    provenance_path = replay_runtime.artifacts_root / replay_runtime.run_id / "provenance.json"
    provenance_payload = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert provenance_payload
    derived_kinds = {ref["kind"] for ref in provenance_payload[0]["derived_from"]}
    assert "manifest" in derived_kinds
    assert "artifact" in derived_kinds

import json
import hashlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.modules.recon_gatherers.orchestrator import (
    run_vibepentester_and_persist,
    run_zypheron_and_persist,
)
from chimera_core.modules.recon_gatherers.sinks.recon_sink import DatabaseReconSink
from chimera_core.modules.recon_gatherers.sinks.inmemory_repository import InMemoryRepository
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.runtime.run_manifest import RunManifest


def _build_runtime(tmp_path: Path) -> MagicMock:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    runtime = MagicMock(spec=Runtime)
    runtime.run_id = "replay-run"
    runtime.artifacts_root = tmp_path / "artifacts"
    runtime.scope_graph = ScopeGraph(scope_manifest)
    runtime.scope_policy = ScopePolicy(scope_manifest)
    runtime.run_external_tool = MagicMock()
    runtime.mode = "fixture"
    return runtime


def _write_vibepentester_artifacts(artifacts_root: Path, run_id: str) -> None:
    report_dir = artifacts_root / run_id / "vibepentester"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "stdout.txt").write_text("ok", encoding="utf-8")
    (report_dir / "stderr.txt").write_text("", encoding="utf-8")
    (report_dir / "report.md").write_text("Report\n## High: SQLi\nSeverity: High", encoding="utf-8")


def _scope_spec_hash(runtime: Runtime) -> str:
    payload = {
        "allowlist": runtime.scope_graph.allowed_domains,
        "denylist": runtime.scope_graph.denied_patterns,
        "rate_limits": {
            "requests_per_second": runtime.scope_policy.max_rps,
            "concurrency": runtime.scope_policy.max_concurrency,
        },
        "allow_ip_targets": runtime.scope_policy.allow_ip_targets,
        "allow_private_ips": runtime.scope_policy.allow_private_ips,
        "allowed_methods": runtime.scope_policy.allowed_methods,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _manifest_for_run(runtime: Runtime, run_id: str) -> RunManifest:
    return RunManifest.create(
        run_id=run_id,
        pipeline=["vibepentester"],
        targets=["example.com"],
        scope_spec_hash=_scope_spec_hash(runtime),
    )


def test_replay_skips_runtime_execution(tmp_path: Path):
    runtime = _build_runtime(tmp_path)
    original_run_id = "orig-run"
    _write_vibepentester_artifacts(runtime.artifacts_root, original_run_id)

    manifest = _manifest_for_run(runtime, original_run_id)
    manifest_path = runtime.artifacts_root / original_run_id / "run_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")

    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)
    config = VibePenTesterConfig(workdir=tmp_path, output_dir=tmp_path / "out", entrypoint=["python", "vibe.py"])

    run_vibepentester_and_persist(
        target="example.com",
        runtime=runtime,
        config=config,
        sink=sink,
        replay=True,
        manifest=manifest,
    )

    runtime.run_external_tool.assert_not_called()


def test_replay_raises_if_manifest_missing(tmp_path: Path):
    runtime = _build_runtime(tmp_path)
    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)

    with pytest.raises(ValueError, match="RunManifest"):
        run_zypheron_and_persist(
            target="example.com",
            runtime=runtime,
            sink=sink,
            replay=True,
            manifest=None,
        )


def test_replay_uses_existing_artifacts(tmp_path: Path):
    runtime = _build_runtime(tmp_path)
    original_run_id = "orig-run"
    _write_vibepentester_artifacts(runtime.artifacts_root, original_run_id)

    manifest = _manifest_for_run(runtime, original_run_id)

    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)
    config = VibePenTesterConfig(workdir=tmp_path, output_dir=tmp_path / "out", entrypoint=["python", "vibe.py"])

    run_vibepentester_and_persist(
        target="example.com",
        runtime=runtime,
        config=config,
        sink=sink,
        replay=True,
        manifest=manifest,
    )

    run_id = list(repo.runs.keys())[0]
    assert repo.findings[run_id]

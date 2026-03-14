import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chimera_core.runtime import Runtime
from chimera_core.event_store import EventStore
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.modules.safety.policy import SafetyPolicy
from chimera_core.modules.safety.enforcer import SafetyPolicyViolation
from chimera_core.modules.runtime.tool_profile import ToolProfile
from chimera_core.modules.recon_gatherers.orchestrator import (
    run_zypheron_and_persist,
    run_vibepentester_and_persist,
    run_decepticon_and_persist,
)
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.recon_gatherers.schemas import ReconBundle, Finding
from chimera_core.modules.recon_gatherers.sinks.recon_sink import DatabaseReconSink
from chimera_core.modules.recon_gatherers.sinks.inmemory_repository import InMemoryRepository
from chimera_core.modules.runtime.run_manifest import RunManifest


def _scope_runtime(tmp_path: Path, run_id: str, policy: SafetyPolicy, mode: str) -> Runtime:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(run_dir / "events.jsonl")
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
        safety_policy=policy,
        mode=mode,
        allowed_binaries={"zypheron", "python", "python3", "autoswagger", "strix", "curl"},
    )


def _load_manifest(path: Path) -> RunManifest:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return RunManifest.from_dict(payload)


def _fixture_runtime(tmp_path: Path, run_id: str, policy: SafetyPolicy) -> MagicMock:
    runtime = MagicMock(spec=Runtime)
    runtime.run_id = run_id
    runtime.artifacts_root = tmp_path / "artifacts"
    runtime.scope_graph = ScopeGraph({"allowlist": ["example.com"], "denylist": []})
    runtime.scope_policy = ScopePolicy({"allowlist": ["example.com"], "denylist": []})
    runtime.safety_policy = policy
    runtime.mode = "fixture"
    runtime.run_external_tool = MagicMock()
    return runtime


def test_pilot_golden_path(tmp_path: Path):
    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)

    # Fixture mode run (mocked external exec)
    fixture_policy = SafetyPolicy(allow_external_execution=False, require_live_confirm=False)
    zy_runtime = _fixture_runtime(tmp_path, "zypheron-run", fixture_policy)
    vibe_runtime = _fixture_runtime(tmp_path, "vibe-run", fixture_policy)
    dece_runtime = _fixture_runtime(tmp_path, "decepticon-run", fixture_policy)

    zy_runtime.run_external_tool.return_value = MagicMock(
        ok=True,
        exit_code=0,
        stdout="[ASSET] host: www.example.com\n",
        stderr="",
    )

    run_zypheron_and_persist(
        target="example.com",
        runtime=zy_runtime,
        sink=sink,
    )

    vibe_output = tmp_path / "reports"
    vibe_output.mkdir(parents=True, exist_ok=True)
    (vibe_output / "report.md").write_text("Report\n## High: SQLi\nSeverity: High", encoding="utf-8")
    vibe_config = VibePenTesterConfig(workdir=tmp_path, output_dir=vibe_output, entrypoint=["python", "vibe.py"])
    vibe_runtime.run_external_tool.return_value = MagicMock(ok=True, exit_code=0, stdout="Scan complete.", stderr="")
    run_vibepentester_and_persist(
        target="example.com",
        runtime=vibe_runtime,
        config=vibe_config,
        sink=sink,
    )

    dece_output = tmp_path / "dec-out"
    dece_output.mkdir(parents=True, exist_ok=True)
    (dece_output / "output.json").write_text(
        json.dumps({"notes_markdown": "notes", "suggested_actions": []}),
        encoding="utf-8",
    )
    dece_config = VibePenTesterConfig(workdir=tmp_path, output_dir=dece_output, entrypoint=["python", "decepticon.py"])
    dece_runtime.run_external_tool.return_value = MagicMock(ok=True, exit_code=0, stdout="ok", stderr="")
    bundles = [
        ReconBundle(run_id="bundle-1", target="example.com", tool="zypheron"),
        ReconBundle(run_id="bundle-2", target="example.com", tool="vibepentester"),
    ]
    run_decepticon_and_persist(
        bundles=bundles,
        runtime=dece_runtime,
        config=dece_config,
        sink=sink,
    )

    for run_id in ("zypheron-run", "vibe-run", "decepticon-run"):
        manifest_path = tmp_path / "artifacts" / run_id / "run_manifest.json"
        manifest = _load_manifest(manifest_path)
        assert manifest.config_hashes.get("safety_policy")
        provenance_path = tmp_path / "artifacts" / run_id / "provenance.json"
        assert provenance_path.exists()

    run_ids_by_tool = {data["tool"]: run_id for run_id, data in repo.runs.items()}
    assert repo.artifacts[run_ids_by_tool["zypheron"]]
    assert repo.artifacts[run_ids_by_tool["vibepentester"]]
    assert repo.artifacts[run_ids_by_tool["decepticon"]]

    # Live mode attempt without live_confirm_token
    live_policy_blocked = SafetyPolicy(allow_external_execution=True, require_live_confirm=True, live_confirm_token=None)
    live_runtime_blocked = _scope_runtime(tmp_path, "live-blocked", live_policy_blocked, mode="live")
    with pytest.raises(SafetyPolicyViolation, match="Live confirmation required"):
        live_runtime_blocked.run_external_tool(
            ["zypheron", "scan", "example.com"],
            tool_profile=ToolProfile(name="zypheron"),
            mode="live",
            timeout_s=30,
        )

    # Live mode with confirm token (no real tools)
    live_policy_ok = SafetyPolicy(allow_external_execution=True, require_live_confirm=True, live_confirm_token="I UNDERSTAND")
    live_runtime_ok = _scope_runtime(tmp_path, "live-ok", live_policy_ok, mode="live")
    with patch.object(live_runtime_ok, "_execute_subprocess") as exec_mock:
        exec_mock.return_value = MagicMock(stdout="ok", stderr="", returncode=0)
        live_runtime_ok.run_external_tool(
            ["zypheron", "scan", "example.com"],
            tool_profile=ToolProfile(name="zypheron"),
            mode="live",
            timeout_s=30,
        )
        exec_mock.assert_called_once()

    # Replay after parser update
    replay_runtime = _fixture_runtime(tmp_path, "replay-run", fixture_policy)
    manifest_path = tmp_path / "artifacts" / "vibe-run" / "run_manifest.json"
    manifest = _load_manifest(manifest_path)

    original_provenance_path = tmp_path / "artifacts" / "vibe-run" / "provenance.json"
    original_provenance = json.loads(original_provenance_path.read_text(encoding="utf-8"))
    original_ids = {record["subject_id"] for record in original_provenance}

    new_finding = Finding(title="New Finding", type="vuln", severity="high", confidence="0.9")
    original_finding = Finding(title="SQLi", type="vuln", severity="high", confidence="medium")
    with patch(
        "chimera_core.modules.recon_gatherers.orchestrator.parse_vibepentester_reports",
        return_value=(
            [
                original_finding,
                new_finding,
            ],
            [],
        ),
    ):
        run_vibepentester_and_persist(
            target="example.com",
            runtime=replay_runtime,
            config=vibe_config,
            sink=sink,
            replay=True,
            manifest=manifest,
        )

    replay_runtime.run_external_tool.assert_not_called()

    replay_provenance_path = replay_runtime.artifacts_root / replay_runtime.run_id / "provenance.json"
    replay_provenance = json.loads(replay_provenance_path.read_text(encoding="utf-8"))
    replay_ids = {record["subject_id"] for record in replay_provenance}
    assert original_ids.intersection(replay_ids)

    replay_run_id = next(
        run_id for run_id, data in repo.runs.items() if data["meta"].get("parent_run_id") == manifest.run_id
    )
    assert len(repo.findings[replay_run_id]) >= 2

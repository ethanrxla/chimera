import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.modules.recon_gatherers.orchestrator import run_decepticon_and_persist
from chimera_core.modules.recon_gatherers.decepticon_adapter import DecepticonAdapter
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.recon_gatherers.schemas import ReconBundle, Finding
from chimera_core.modules.recon_gatherers.sinks.recon_sink import DatabaseReconSink
from chimera_core.modules.recon_gatherers.sinks.inmemory_repository import InMemoryRepository
from chimera_core.modules.recon_gatherers.notify.shannon_client import ShannonClient


def test_decepticon_enrichment_to_sink(tmp_path: Path):
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    runtime = MagicMock(spec=Runtime)
    runtime.run_id = "run-decepticon"
    runtime.artifacts_root = tmp_path / "artifacts"
    runtime.scope_graph = ScopeGraph(scope_manifest)
    runtime.scope_policy = ScopePolicy(scope_manifest)
    runtime.mode = "fixture"

    output_dir = tmp_path / "decepticon-output"
    output_dir.mkdir(parents=True, exist_ok=True)

    def _run_cmd(*args, **kwargs):
        output_path = output_dir / "output.json"
        output_payload = {
            "notes_markdown": "Enrichment notes",
            "suggested_actions": [
                {
                    "action_id": "a1",
                    "description": "Check login endpoints",
                    "tool": "curl",
                    "targets": ["example.com"],
                    "confidence": 0.9,
                }
            ],
        }
        output_path.write_text(json.dumps(output_payload), encoding="utf-8")
        return MagicMock(ok=True, exit_code=0, stdout=f"Output dir: {output_dir}", stderr="")

    runtime.run_external_tool.side_effect = _run_cmd

    config = VibePenTesterConfig(
        workdir=tmp_path,
        output_dir=output_dir,
        entrypoint=["python", "decepticon.py"],
    )

    bundles = [
        ReconBundle(run_id="bundle-1", target="example.com", tool="zypheron"),
        ReconBundle(run_id="bundle-2", target="example.com", tool="vibepentester"),
    ]

    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)
    notifier = MagicMock(spec=ShannonClient)

    original_run_enrichment = DecepticonAdapter.run_enrichment

    def run_enrichment_with_promoted(self, bundles, config):
        result = original_run_enrichment(self, bundles, config)
        result.promoted_findings.append(
            Finding(
                title="Promoted Finding",
                type="vuln",
                severity="high",
                confidence="0.9",
                evidence_refs=["https://example.com/login"],
            )
        )
        return result

    with patch.object(DecepticonAdapter, "run_enrichment", new=run_enrichment_with_promoted):
        persist_result = run_decepticon_and_persist(
            bundles=bundles,
            runtime=runtime,
            config=config,
            sink=sink,
            notifier=notifier,
            program_handle="test-program",
        )

    assert persist_result.artifacts_persisted >= 2
    assert len(repo.runs) == 1
    run_id = list(repo.runs.keys())[0]

    artifact_kinds = {artifact["kind"] for artifact in repo.artifacts[run_id]}
    assert "analysis_notes" in artifact_kinds
    assert "suggested_actions" in artifact_kinds
    assert "provenance" in artifact_kinds

    finding_titles = {finding["title"] for finding in repo.findings[run_id]}
    assert "Promoted Finding" in finding_titles

    notifier.send_recon_summary.assert_called_once()
    summary = notifier.send_recon_summary.call_args[0][0]
    assert summary.top_actions
    assert summary.promoted_findings_count == 1
    assert summary.artifact_ids

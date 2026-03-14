import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.modules.recon_gatherers.orchestrator import (
    run_vibepentester_and_persist,
    run_decepticon_and_persist,
)
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.recon_gatherers.schemas import ReconBundle, Finding
from chimera_core.modules.recon_gatherers.sinks.recon_sink import DatabaseReconSink
from chimera_core.modules.recon_gatherers.sinks.inmemory_repository import InMemoryRepository
from chimera_core.modules.recon_gatherers.enrichment.models import EnrichmentResult, SuggestedAction, ArtifactRef
from chimera_core.modules.recon_gatherers.enrichment.decepticon_enricher import DecepticonEnricher
from chimera_core.modules.recon_gatherers.provenance.models import ProvenanceRef


def _build_runtime(tmp_path: Path, run_id: str) -> MagicMock:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    runtime = MagicMock(spec=Runtime)
    runtime.run_id = run_id
    runtime.artifacts_root = tmp_path / "artifacts"
    runtime.scope_graph = ScopeGraph(scope_manifest)
    runtime.scope_policy = ScopePolicy(scope_manifest)
    runtime.run_external_tool = MagicMock()
    return runtime


def test_vibepentester_finding_has_report_and_manifest_provenance(tmp_path: Path):
    runtime = _build_runtime(tmp_path, "vibe-run")
    output_dir = tmp_path / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "report.md").write_text("Report\n## Low: Info\nSeverity: Low", encoding="utf-8")

    runtime.run_external_tool.return_value = MagicMock(ok=True, exit_code=0, stdout="ok", stderr="")
    config = VibePenTesterConfig(workdir=tmp_path, output_dir=output_dir, entrypoint=["python", "vibe.py"])

    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)

    run_vibepentester_and_persist(
        target="example.com",
        runtime=runtime,
        config=config,
        sink=sink,
    )

    provenance_path = runtime.artifacts_root / runtime.run_id / "provenance.json"
    payload = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert payload

    derived_kinds = {ref["kind"] for ref in payload[0]["derived_from"]}
    assert "manifest" in derived_kinds
    assert "artifact" in derived_kinds


def test_decepticon_action_has_transcript_and_bundle_provenance(tmp_path: Path):
    runtime = _build_runtime(tmp_path, "dec-run")
    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)

    config = VibePenTesterConfig(workdir=tmp_path, output_dir=tmp_path / "out", entrypoint=["python", "decepticon.py"])
    bundles = [ReconBundle(run_id="bundle-1", target="example.com", tool="zypheron")]

    transcript_path = runtime.artifacts_root / runtime.run_id / "decepticon" / "outputs" / "output.json"
    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    transcript_path.write_text(
        json.dumps(
            {
                "notes_markdown": "notes",
                "suggested_actions": [
                    {
                        "action_id": "a1",
                        "description": "Check endpoints",
                        "tool": "curl",
                        "targets": ["example.com"],
                        "confidence": 0.9,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    fake_result = EnrichmentResult(
        notes_markdown="",
        suggested_actions=[],
        artifacts=[ArtifactRef(path=str(transcript_path), kind="decepticon_output", sha256="hash")],
    )

    with patch(
        "chimera_core.modules.recon_gatherers.decepticon_adapter.DecepticonAdapter.run_enrichment",
        return_value=fake_result,
    ):
        run_decepticon_and_persist(
            bundles=bundles,
            runtime=runtime,
            config=config,
            sink=sink,
        )

    provenance_path = runtime.artifacts_root / runtime.run_id / "provenance.json"
    payload = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert payload

    action_record = next(record for record in payload if record["subject_kind"] == "action")
    derived_kinds = {ref["kind"] for ref in action_record["derived_from"]}
    assert "artifact" in derived_kinds
    assert "bundle" in derived_kinds


def test_promoted_finding_fails_without_evidence_anchor(tmp_path: Path):
    runtime = _build_runtime(tmp_path, "dec-enrich")
    manifest_ref = ProvenanceRef(kind="manifest", id="manifest-id")

    adapter = MagicMock()
    adapter.runtime = runtime
    enricher = DecepticonEnricher(
        adapter=adapter,
        config=VibePenTesterConfig(workdir=tmp_path, output_dir=tmp_path / "out", entrypoint=["python", "decepticon.py"]),
        scope_graph=runtime.scope_graph,
        manifest_ref=manifest_ref,
    )

    result = EnrichmentResult(
        artifacts=[ArtifactRef(path="stdout.txt", kind="stdout", sha256="hash")],
        promoted_findings=[
            Finding(title="Promoted", type="vuln", severity="high", confidence="0.9", evidence_refs=[])
        ],
    )

    enriched = enricher._apply_parsing_and_guards(result)
    assert not enriched.promoted_findings

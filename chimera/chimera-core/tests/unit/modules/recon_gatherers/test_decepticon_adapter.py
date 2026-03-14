import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from chimera_core.runtime import Runtime
from chimera_core.modules.recon_gatherers.config import VibePenTesterConfig
from chimera_core.modules.recon_gatherers.decepticon_adapter import (
    DecepticonAdapter,
    DecepticonExecutionError,
)
from chimera_core.modules.recon_gatherers.schemas import ReconBundle


def _build_runtime(tmp_path: Path) -> MagicMock:
    runtime = MagicMock(spec=Runtime)
    runtime.run_id = "run-decepticon"
    runtime.artifacts_root = tmp_path / "artifacts"
    runtime.mode = "fixture"
    return runtime


def test_enrich_success_writes_input_runs_runtime_collects_artifacts(tmp_path: Path):
    runtime = _build_runtime(tmp_path)
    output_dir = tmp_path / "decepticon-output"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "output.json").write_text('{"notes_markdown": "ok"}', encoding="utf-8")

    config = VibePenTesterConfig(
        workdir=tmp_path,
        output_dir=output_dir,
        entrypoint=["python", "decepticon.py"],
    )
    runtime.run_external_tool.return_value = MagicMock(ok=True, exit_code=0, stdout=f"Output dir: {output_dir}", stderr="")

    adapter = DecepticonAdapter(runtime=runtime)
    bundles = [ReconBundle(run_id="bundle-run", target="example.com", tool="zypheron")]

    result = adapter.run_enrichment(bundles=bundles, config=config)

    input_path = runtime.artifacts_root / runtime.run_id / "decepticon" / "input" / "bundles.json"
    assert input_path.exists()
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    assert payload["bundles"][0]["target"] == "example.com"

    expected_cmd = config.entrypoint + ["--input", str(input_path), "--output", str(output_dir)] + config.extra_args
    runtime.run_external_tool.assert_called_once()

    kinds = {artifact.kind for artifact in result.artifacts}
    assert "stdout" in kinds
    assert "stderr" in kinds
    assert "decepticon_output" in kinds


def test_enrich_failure_raises_decepticon_execution_error(tmp_path: Path):
    runtime = _build_runtime(tmp_path)
    output_dir = tmp_path / "decepticon-output"
    output_dir.mkdir(parents=True, exist_ok=True)

    config = VibePenTesterConfig(
        workdir=tmp_path,
        output_dir=output_dir,
        entrypoint=["python", "decepticon.py"],
    )
    runtime.run_external_tool.return_value = MagicMock(ok=False, exit_code=1, stdout="", stderr="boom")

    adapter = DecepticonAdapter(runtime=runtime)
    bundles = [ReconBundle(run_id="bundle-run", target="example.com", tool="zypheron")]

    with pytest.raises(DecepticonExecutionError, match="boom"):
        adapter.run_enrichment(bundles=bundles, config=config)


def test_enrich_no_outputs_still_returns_result_with_logs(tmp_path: Path):
    runtime = _build_runtime(tmp_path)
    output_dir = tmp_path / "decepticon-output"
    output_dir.mkdir(parents=True, exist_ok=True)

    config = VibePenTesterConfig(
        workdir=tmp_path,
        output_dir=output_dir,
        entrypoint=["python", "decepticon.py"],
    )
    runtime.run_external_tool.return_value = MagicMock(ok=True, exit_code=0, stdout="ok", stderr="")

    adapter = DecepticonAdapter(runtime=runtime)
    bundles = [ReconBundle(run_id="bundle-run", target="example.com", tool="zypheron")]

    result = adapter.run_enrichment(bundles=bundles, config=config)

    kinds = {artifact.kind for artifact in result.artifacts}
    assert "stdout" in kinds
    assert "stderr" in kinds
    assert "decepticon_output" not in kinds
    assert result.warnings

import hashlib
from pathlib import Path
from typing import List

from chimera_core.modules.recon_gatherers.enrichment.models import ArtifactRef


def _infer_kind(path: Path) -> str:
    name = path.name.lower()
    if name == "stdout.txt":
        return "stdout"
    if name == "stderr.txt":
        return "stderr"
    if name == "parse_warnings.txt":
        return "parse_warning"
    if name == "run_manifest.json":
        return "run_manifest"
    if name == "notes.md":
        return "analysis_notes"
    if name == "suggested_actions.json":
        return "suggested_actions"
    parts = [part.lower() for part in path.parts]
    if "vibepentester" in parts:
        return "report"
    if "decepticon" in parts and "outputs" in parts:
        return "decepticon_output"
    return "artifact"


def load_artifacts_for_run(run_id: str, artifacts_root: Path) -> List[ArtifactRef]:
    """
    Loads artifact references for a given run_id from the artifacts directory.
    """
    run_dir = artifacts_root / run_id
    if not run_dir.exists():
        return []

    artifacts: List[ArtifactRef] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        content = path.read_bytes()
        sha256 = hashlib.sha256(content).hexdigest()
        artifacts.append(
            ArtifactRef(
                path=str(path),
                kind=_infer_kind(path),
                sha256=sha256,
            )
        )
    return artifacts


def load_stdout_for_run(run_id: str, artifacts_root: Path) -> str:
    """
    Loads the first stdout artifact content for a given run.
    """
    artifacts = load_artifacts_for_run(run_id, artifacts_root)
    stdout_paths = sorted(
        [Path(artifact.path) for artifact in artifacts if artifact.kind == "stdout"]
    )
    if not stdout_paths:
        return ""
    return stdout_paths[0].read_text(encoding="utf-8")

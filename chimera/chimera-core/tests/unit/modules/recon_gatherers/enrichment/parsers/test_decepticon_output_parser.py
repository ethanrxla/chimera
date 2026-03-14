from pathlib import Path

from chimera_core.modules.recon_gatherers.enrichment.models import ArtifactRef
from chimera_core.modules.recon_gatherers.enrichment.parsers.decepticon_output_parser import (
    parse_decepticon_output,
)


def test_parses_mocked_json_transcript_into_actions(tmp_path: Path):
    output_path = tmp_path / "decepticon_output.json"
    output_path.write_text(
        '{"notes_markdown":"Notes","suggested_actions":[{"action_id":"a1","description":"Do thing","tool":"curl","targets":["example.com"],"confidence":0.9}]}',
        encoding="utf-8",
    )

    artifacts = [
        ArtifactRef(path=str(output_path), kind="decepticon_output", sha256="hash"),
    ]

    notes, actions, warnings = parse_decepticon_output(artifacts)

    assert notes == "Notes"
    assert not warnings
    assert len(actions) == 1
    assert actions[0].action_id == "a1"
    assert actions[0].tool == "curl"


def test_handles_invalid_json_as_warnings(tmp_path: Path):
    output_path = tmp_path / "decepticon_output.json"
    output_path.write_text("{", encoding="utf-8")

    artifacts = [
        ArtifactRef(path=str(output_path), kind="decepticon_output", sha256="hash"),
    ]

    notes, actions, warnings = parse_decepticon_output(artifacts)

    assert notes == "{"
    assert not actions
    assert warnings


def test_ignores_unsupported_artifacts(tmp_path: Path):
    output_path = tmp_path / "stdout.txt"
    output_path.write_text("ignored", encoding="utf-8")

    artifacts = [
        ArtifactRef(path=str(output_path), kind="stdout", sha256="hash"),
    ]

    notes, actions, warnings = parse_decepticon_output(artifacts)

    assert notes == ""
    assert not actions
    assert not warnings

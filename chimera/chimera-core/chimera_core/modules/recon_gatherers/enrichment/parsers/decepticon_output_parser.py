import json
from pathlib import Path
from typing import List, Tuple

from chimera_core.modules.recon_gatherers.enrichment.models import ArtifactRef, SuggestedAction
from chimera_core.modules.recon_gatherers.parsers.vibepentester_parser import ParseWarning


SUPPORTED_OUTPUT_KINDS = {"decepticon_output", "output", "report"}


def _coerce_confidence(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered.replace(".", "", 1).isdigit():
            return float(lowered)
        mapping = {"high": 0.9, "medium": 0.6, "low": 0.3}
        if lowered in mapping:
            return mapping[lowered]
    return 0.0


def _coerce_action(raw_action: dict, index: int) -> SuggestedAction:
    return SuggestedAction(
        action_id=str(raw_action.get("action_id") or raw_action.get("id") or f"action-{index}"),
        description=str(raw_action.get("description") or raw_action.get("text") or raw_action.get("summary") or ""),
        tool=str(raw_action.get("tool") or raw_action.get("source") or "unknown"),
        targets=list(raw_action.get("targets") or raw_action.get("target") or []),
        confidence=_coerce_confidence(raw_action.get("confidence")),
    )


def parse_decepticon_output(
    artifacts: List[ArtifactRef],
) -> Tuple[str, List[SuggestedAction], List[ParseWarning]]:
    """
    Parses Decepticon output artifacts into notes and suggested actions.
    This parser is best-effort and never raises.
    """
    notes_markdown = ""
    suggested_actions: List[SuggestedAction] = []
    warnings: List[ParseWarning] = []

    for artifact in artifacts:
        if artifact.kind not in SUPPORTED_OUTPUT_KINDS:
            continue
        path = Path(artifact.path)
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as exc:
            warnings.append(ParseWarning(artifact_path=artifact.path, reason=f"Failed to read artifact: {exc}"))
            continue

        is_json_hint = path.suffix.lower() == ".json" or content.strip().startswith(("{", "["))
        if is_json_hint:
            try:
                data = json.loads(content)
            except json.JSONDecodeError as exc:
                warnings.append(ParseWarning(artifact_path=artifact.path, reason=f"Invalid JSON output: {exc}"))
                if not notes_markdown:
                    notes_markdown = content
                continue

            if isinstance(data, dict):
                if not notes_markdown:
                    notes_markdown = str(data.get("notes_markdown") or data.get("notes") or "")
                actions_data = data.get("suggested_actions") or data.get("actions") or []
            elif isinstance(data, list):
                actions_data = [item for item in data if isinstance(item, dict)]
            else:
                warnings.append(ParseWarning(artifact_path=artifact.path, reason="Unsupported JSON output shape."))
                continue

            for index, action_data in enumerate(actions_data):
                if not isinstance(action_data, dict):
                    continue
                suggested_actions.append(_coerce_action(action_data, index))
            continue

        if not notes_markdown:
            notes_markdown = content
        warnings.append(
            ParseWarning(
                artifact_path=artifact.path,
                reason="Plain text output detected; stored as notes.",
            )
        )

    return notes_markdown, suggested_actions, warnings

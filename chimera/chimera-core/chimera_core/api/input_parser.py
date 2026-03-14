from __future__ import annotations

import json
import re
from typing import Dict, List

import yaml


def interpret_input(text: str) -> Dict[str, object]:
    stripped = text.strip()
    if not stripped:
        return {"kind": "empty", "notes": ["No input provided."]}

    scope_manifest = _parse_scope_manifest(stripped)
    if scope_manifest is not None:
        return {"kind": "scope", "scope_manifest": scope_manifest, "notes": ["Parsed as scope manifest."]}

    targets = _extract_targets(stripped)
    command = {
        "action": _infer_action(stripped),
        "pipeline": _infer_pipeline(stripped),
        "target": targets[0] if targets else None,
        "targets": targets,
        "program_name": _infer_program_name(stripped),
        "question": stripped if _infer_action(stripped) == "oracle" else None,
        "chain_id": _infer_chain_id(stripped),
    }
    notes: List[str] = []
    if targets:
        notes.append("Extracted target candidates from natural language input.")
    if command["pipeline"] == "recon":
        notes.append("Recon pipeline selected from text.")
    return {"kind": "command", "command": command, "notes": notes}


def _parse_scope_manifest(text: str):
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict) and ("allowlist" in data or "denylist" in data):
            return data
    except Exception:
        pass
    try:
        data = json.loads(text)
        if isinstance(data, dict) and ("allowlist" in data or "denylist" in data):
            return data
    except Exception:
        pass
    targets = _extract_targets(text)
    lines = [line.strip(" -*\t") for line in text.splitlines() if line.strip()]
    if targets and len(lines) <= len(targets) + 2 and "scan" not in text.lower():
        return {"allowlist": targets, "denylist": []}
    return None


def _extract_targets(text: str) -> List[str]:
    pattern = re.compile(r"(https?://[^\s,]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s,]*)?)")
    seen: List[str] = []
    for match in pattern.findall(text):
        if match not in seen:
            seen.append(match)
    return seen


def _infer_action(text: str) -> str:
    lowered = text.lower()
    if "oracle" in lowered or lowered.endswith("?") or lowered.startswith("what ") or lowered.startswith("how "):
        return "oracle"
    if "viz" in lowered or "graph" in lowered or "chain " in lowered:
        return "viz"
    if "exploit" in lowered or "replay" in lowered:
        return "exploit"
    if "status" in lowered:
        return "status"
    return "scan"


def _infer_pipeline(text: str) -> str:
    lowered = text.lower()
    if "recon" in lowered or "zypheron" in lowered or "vibepentester" in lowered or "decepticon" in lowered:
        return "recon"
    return "task_runner"


def _infer_program_name(text: str) -> str | None:
    match = re.search(r"(?:program|scope)\s+(?:for\s+)?([A-Z][A-Za-z0-9._ -]+)", text)
    return match.group(1).strip() if match else None


def _infer_chain_id(text: str) -> str | None:
    match = re.search(r"\b([a-f0-9]{12,64})\b", text.lower())
    return match.group(1) if match else None

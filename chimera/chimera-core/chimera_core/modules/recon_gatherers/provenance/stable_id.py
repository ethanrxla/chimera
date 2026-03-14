import hashlib
import json
from typing import Optional, List

from chimera_core.modules.recon_gatherers.schemas import Finding
from chimera_core.modules.recon_gatherers.enrichment.models import SuggestedAction


def _hash_payload(payload: dict) -> str:
    serialized = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def stable_id_for_finding(
    finding: Finding,
    target: str,
    tool: str,
    evidence_anchor: Optional[str] = None,
) -> str:
    payload = {
        "title": finding.title,
        "severity": finding.severity,
        "type": finding.type,
        "target": target,
        "tool": tool,
        "evidence_anchor": evidence_anchor or "",
        "confidence": finding.confidence or "",
    }
    return _hash_payload(payload)


def stable_id_for_action(
    action: SuggestedAction,
    source_artifact_id: Optional[str] = None,
) -> str:
    payload = {
        "action_id": action.action_id,
        "description": action.description,
        "tool": action.tool,
        "targets": sorted(action.targets),
        "source_artifact": source_artifact_id or "",
    }
    return _hash_payload(payload)

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional

from chimera_core.event_store import EventStore


ArtifactKind = Literal[
    "stdout",
    "stderr",
    "run_manifest",
    "provenance",
    "analysis_notes",
    "attack_contract",
    "http_request",
    "http_response",
    "http_normalized",
    "hexstrike_result",
    "verification_plan",
    "verification_result",
    "llm_prompt",
    "llm_response",
    "validator_decision",
    "policy_decision",
    "findings",
    "candidate_finding",
    "session_capture",
    "scope_violation_record",
]


@dataclass(frozen=True)
class ArtifactRef:
    run_id: str
    relpath: str
    kind: ArtifactKind
    sha256: str
    bytes: int


class ArtifactWriter:
    def __init__(self, root: Path, *, event_store: Optional[EventStore] = None) -> None:
        self.root = Path(root)
        self.event_store = event_store

    def _emit_saved(
        self,
        *,
        run_id: str,
        relpath: str,
        kind: ArtifactKind,
        source: str,
        task_id: str | None,
        metadata: dict[str, Any] | None,
    ) -> None:
        if not self.event_store:
            return
        payload: dict[str, Any] = {
            "run_id": run_id,
            "path": relpath,
            "artifact_type": kind,
            "source": source,
        }
        if task_id:
            payload["task_id"] = task_id
        if metadata:
            payload["metadata"] = metadata
        self.event_store.emit({"event_type": "artifact_saved", "source": source, "payload": payload})

    def write_bytes(
        self,
        *,
        run_id: str,
        relpath: str,
        kind: ArtifactKind,
        content: bytes,
        source: str,
        task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        path = self.root / run_id / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        ref = ArtifactRef(run_id=run_id, relpath=relpath, kind=kind, sha256=digest, bytes=len(content))
        self._emit_saved(
            run_id=run_id,
            relpath=relpath,
            kind=kind,
            source=source,
            task_id=task_id,
            metadata=metadata,
        )
        return ref

    def write_json(
        self,
        *,
        run_id: str,
        relpath: str,
        kind: ArtifactKind,
        obj: dict[str, Any],
        source: str,
        task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ArtifactRef:
        content = json.dumps(obj, indent=2, ensure_ascii=True).encode("utf-8")
        return self.write_bytes(
            run_id=run_id,
            relpath=relpath,
            kind=kind,
            content=content,
            source=source,
            task_id=task_id,
            metadata=metadata,
        )

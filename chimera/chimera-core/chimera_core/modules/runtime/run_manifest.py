import json
import platform
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_runtime_env() -> Dict[str, str]:
    return {
        "os": platform.platform(),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
    }


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    created_at: str
    pipeline: List[str]
    targets: List[str]
    scope_spec_hash: str
    adapter_versions: Dict[str, str] = field(default_factory=dict)
    runtime_env: Dict[str, str] = field(default_factory=_default_runtime_env)
    config_hashes: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        run_id: str,
        pipeline: List[str],
        targets: List[str],
        scope_spec_hash: str,
        adapter_versions: Optional[Dict[str, str]] = None,
        runtime_env: Optional[Dict[str, str]] = None,
        config_hashes: Optional[Dict[str, str]] = None,
    ) -> "RunManifest":
        return cls(
            run_id=run_id,
            created_at=_utc_now_iso(),
            pipeline=list(pipeline),
            targets=list(targets),
            scope_spec_hash=scope_spec_hash,
            adapter_versions=dict(adapter_versions or {}),
            runtime_env=dict(runtime_env) if runtime_env is not None else _default_runtime_env(),
            config_hashes=dict(config_hashes or {}),
        )

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "RunManifest":
        return cls(
            run_id=str(payload.get("run_id", "")),
            created_at=str(payload.get("created_at", "")),
            pipeline=list(payload.get("pipeline", [])),
            targets=list(payload.get("targets", [])),
            scope_spec_hash=str(payload.get("scope_spec_hash", "")),
            adapter_versions=dict(payload.get("adapter_versions", {})),
            runtime_env=dict(payload.get("runtime_env", {})),
            config_hashes=dict(payload.get("config_hashes", {})),
        )


def write_manifest(manifest: RunManifest, artifacts_dir: Path) -> Path:
    """
    Writes a run manifest to disk. This is intended to be called once per run.
    """
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = artifacts_dir / "run_manifest.json"
    manifest_path.write_text(manifest.to_json(), encoding="utf-8")
    return manifest_path

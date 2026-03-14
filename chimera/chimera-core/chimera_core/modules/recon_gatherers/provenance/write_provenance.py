import json
import hashlib
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

from chimera_core.modules.recon_gatherers.provenance.models import ProvenanceRecord
from chimera_core.modules.recon_gatherers.schemas import Artifact


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_provenance(records: Iterable[ProvenanceRecord], artifacts_dir: Path) -> Artifact:
    """
    Writes provenance records to disk as JSON and returns an Artifact reference.
    """
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    payload: List[dict] = []
    for record in records:
        data = asdict(record)
        if not data.get("created_at"):
            data["created_at"] = _utc_now_iso()
        payload.append(data)

    provenance_path = artifacts_dir / "provenance.json"
    content = json.dumps(payload, indent=2, sort_keys=True)
    provenance_path.write_text(content, encoding="utf-8")
    sha256 = hashlib.sha256(content.encode()).hexdigest()
    return Artifact(path=str(provenance_path), kind="provenance", sha256=sha256)

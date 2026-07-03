from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional


def fingerprint_claim(*, claim_type: str, target: str | None, endpoint: str | None, params: list[str] | None = None) -> str:
    payload = {
        "claim_type": claim_type or "unknown",
        "target": (target or "").strip().lower(),
        "endpoint": (endpoint or "").strip().lower(),
        "params": sorted([str(p).strip().lower() for p in (params or []) if str(p).strip()]),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


class FindingCache:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("{}", encoding="utf-8")

    def _load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save(self, data: Dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    def get_verified(self, fingerprint: str) -> Optional[dict]:
        data = self._load()
        item = data.get(fingerprint)
        if isinstance(item, dict) and item.get("status") == "verified":
            return item
        return None

    def put_verified(self, fingerprint: str, finding: dict) -> None:
        data = self._load()
        data[fingerprint] = dict(finding)
        self._save(data)

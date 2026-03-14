import uuid
from datetime import datetime
from typing import Dict, Any, List, Tuple
from collections import defaultdict

from chimera_core.modules.recon_gatherers.schemas import Finding
from chimera_core.modules.recon_gatherers.sinks.recon_repository import ReconRepository

class InMemoryRepository(ReconRepository):
    """
    An in-memory implementation of the ReconRepository for testing purposes.
    """
    def __init__(self):
        self.runs: Dict[str, Dict[str, Any]] = {}
        self.assets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.services: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.artifacts: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        self._asset_dedupe: Dict[Tuple[str, str], str] = {}

    def create_run(self, tool: str, target: str, started_at: datetime, finished_at: datetime, exit_code: int, meta: Dict[str, Any]) -> str:
        run_id = str(uuid.uuid4())
        self.runs[run_id] = {
            "tool": tool,
            "target": target,
            "started_at": started_at,
            "finished_at": finished_at,
            "exit_code": exit_code,
            "meta": meta,
        }
        return run_id

    def upsert_asset(self, run_id: str, asset_type: str, value: str, source_tool: str) -> str:
        # Deduplicate based on (type, value)
        dedupe_key = (asset_type, value)
        if dedupe_key in self._asset_dedupe:
            return self._asset_dedupe[dedupe_key]

        asset_id = f"asset_{len(self.assets[run_id]) + 1}"
        self.assets[run_id].append({
            "asset_id": asset_id,
            "asset_type": asset_type,
            "value": value,
            "source_tool": source_tool,
        })
        self._asset_dedupe[dedupe_key] = asset_id
        return asset_id

    def insert_service(self, run_id: str, host: str, port: int, proto: str, service: str, banner: str, confidence: str) -> str:
        service_id = f"service_{len(self.services[run_id]) + 1}"
        self.services[run_id].append({
            "service_id": service_id,
            "host": host,
            "port": port,
            "proto": proto,
            "service": service,
            "banner": banner,
            "confidence": confidence,
        })
        return service_id

    def insert_finding(self, run_id: str, finding_obj: Finding) -> str:
        finding_id = f"finding_{len(self.findings[run_id]) + 1}"
        # In a real implementation, we would serialize the finding object
        self.findings[run_id].append(finding_obj.__dict__)
        return finding_id

    def insert_artifact(self, run_id: str, path: str, kind: str, sha256: str, mime: str) -> str:
        artifact_id = f"artifact_{len(self.artifacts[run_id]) + 1}"
        self.artifacts[run_id].append({
            "artifact_id": artifact_id,
            "path": path,
            "kind": kind,
            "sha256": sha256,
            "mime": mime,
        })
        return artifact_id

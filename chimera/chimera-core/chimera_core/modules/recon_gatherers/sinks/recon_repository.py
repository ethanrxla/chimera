from typing import Protocol, Any, Dict
from datetime import datetime

class ReconRepository(Protocol):
    """
    Defines the contract for a repository that stores recon data.
    """
    def create_run(self, tool: str, target: str, started_at: datetime, finished_at: datetime, exit_code: int, meta: Dict[str, Any]) -> str:
        ...

    def upsert_asset(self, run_id: str, asset_type: str, value: str, source_tool: str) -> str:
        ...

    def insert_service(self, run_id: str, host: str, port: int, proto: str, service: str, banner: str, confidence: str) -> str:
        ...

    def insert_finding(self, run_id: str, finding_obj: Any) -> str:
        ...

    def insert_artifact(self, run_id: str, path: str, kind: str, sha256: str, mime: str) -> str:
        ...

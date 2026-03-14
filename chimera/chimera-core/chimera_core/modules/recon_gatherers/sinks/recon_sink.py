from typing import Protocol, List, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

from chimera_core.modules.recon_gatherers.schemas import ReconBundle
from chimera_core.modules.recon_gatherers.sinks.recon_repository import ReconRepository

@dataclass
class PersistResult:
    """
    Represents the outcome of a sink persistence operation.
    """
    run_id: str
    assets_persisted: int = 0
    services_persisted: int = 0
    findings_persisted: int = 0
    artifacts_persisted: int = 0
    asset_ids: List[str] = field(default_factory=list)
    service_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    artifact_ids: List[str] = field(default_factory=list)

class ReconSink(Protocol):
    """
    Defines the contract for a sink that can persist a ReconBundle.
    """
    def persist(self, bundle: ReconBundle) -> PersistResult:
        """
        Persists the given ReconBundle to a storage backend.
        """
        ...

class DatabaseReconSink:
    """
    An implementation of ReconSink that persists bundles to a database via a repository.
    """
    def __init__(self, repository: ReconRepository):
        self.repository = repository

    def persist(self, bundle: ReconBundle) -> PersistResult:
        meta = {}
        if bundle.parent_run_id:
            meta["parent_run_id"] = bundle.parent_run_id

        run_id = self.repository.create_run(
            tool=bundle.tool,
            target=bundle.target,
            started_at=datetime.now(timezone.utc), # Placeholder, real value would be in bundle
            finished_at=datetime.now(timezone.utc), # Placeholder
            exit_code=0, # Placeholder
            meta=meta, # Placeholder
        )

        result = PersistResult(run_id=run_id)
        
        # Deduplicate assets before persisting
        unique_assets: Set[Tuple[str, str]] = set()
        for asset in bundle.observed_assets:
            unique_assets.add((asset.type, asset.value, asset.source_tool))
        
        for asset_type, value, source_tool in unique_assets:
            asset_id = self.repository.upsert_asset(
                run_id=run_id, asset_type=asset_type, value=value, source_tool=source_tool
            )
            result.asset_ids.append(asset_id)
        result.assets_persisted = len(result.asset_ids)

        for service in bundle.services:
            service_id = self.repository.insert_service(
                run_id=run_id,
                host=service.host,
                port=service.port,
                proto=service.proto,
                service=service.service,
                banner=service.banner,
                confidence=service.confidence,
            )
            result.service_ids.append(service_id)
        result.services_persisted = len(result.service_ids)

        for finding in bundle.findings:
            finding_id = self.repository.insert_finding(run_id=run_id, finding_obj=finding)
            result.finding_ids.append(finding_id)
        result.findings_persisted = len(result.finding_ids)

        for artifact in bundle.artifacts:
            artifact_id = self.repository.insert_artifact(
                run_id=run_id,
                path=artifact.path,
                kind=artifact.kind,
                sha256=artifact.sha256,
                mime=None, # Placeholder
            )
            result.artifact_ids.append(artifact_id)
        result.artifacts_persisted = len(result.artifact_ids)

        return result

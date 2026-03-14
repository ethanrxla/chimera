from typing import Protocol, List, Optional
from dataclasses import dataclass, field

@dataclass
class ShannonSummary:
    """
    Represents a summary of a recon run for notification purposes.
    """
    program_handle: Optional[str]
    target: str
    run_id: str
    top_assets: List[str]
    top_services: List[str]
    top_findings: List[str]
    asset_count: int
    service_count: int
    finding_count: int
    artifact_ids: List[str]
    top_actions: List[str] = field(default_factory=list)
    promoted_findings_count: int = 0
    report_ready_count: int = 0
    needs_review_count: int = 0
    noise_count: int = 0

class ShannonClient(Protocol):
    """
    Defines the contract for a client that can send recon summaries.
    """
    def send_recon_summary(self, summary: ShannonSummary) -> None:
        ...

from typing import Optional

from chimera_core.modules.recon_gatherers.schemas import ReconBundle, Finding
from chimera_core.modules.recon_gatherers.enrichment.models import SuggestedAction
from chimera_core.modules.recon_gatherers.sinks.recon_sink import PersistResult
from chimera_core.modules.recon_gatherers.quality.report_ready import summarize_report_ready
from chimera_core.modules.recon_gatherers.notify.shannon_client import ShannonSummary

def build_summary(
    bundle: ReconBundle,
    persist_result: PersistResult,
    program_handle: Optional[str] = None,
    top_n: int = 5,
) -> ShannonSummary:
    """
    Builds a ShannonSummary from a ReconBundle and a PersistResult.
    """
    
    top_assets = [asset.value for asset in bundle.observed_assets[:top_n]]
    top_services = [f"{s.service} on {s.host}:{s.port}" for s in bundle.services[:top_n]]
    top_findings = [f.title for f in bundle.findings[:top_n]]
    report_ready_counts = summarize_report_ready(bundle.findings)

    return ShannonSummary(
        program_handle=program_handle,
        target=bundle.target,
        run_id=bundle.run_id,
        top_assets=top_assets,
        top_services=top_services,
        top_findings=top_findings,
        asset_count=persist_result.assets_persisted,
        service_count=persist_result.services_persisted,
        finding_count=persist_result.findings_persisted,
        artifact_ids=persist_result.artifact_ids,
        report_ready_count=report_ready_counts["report_ready"],
        needs_review_count=report_ready_counts["needs_review"],
        noise_count=report_ready_counts["noise"],
    )


def build_enrichment_summary(
    target: str,
    run_id: str,
    suggested_actions: list[SuggestedAction],
    promoted_findings: list[Finding],
    persist_result: PersistResult,
    program_handle: Optional[str] = None,
    top_n: int = 5,
) -> ShannonSummary:
    top_actions = [action.description for action in suggested_actions[:top_n]]
    top_findings = [finding.title for finding in promoted_findings[:top_n]]
    report_ready_counts = summarize_report_ready(promoted_findings)

    return ShannonSummary(
        program_handle=program_handle,
        target=target,
        run_id=run_id,
        top_assets=[],
        top_services=[],
        top_findings=top_findings,
        asset_count=0,
        service_count=0,
        finding_count=len(promoted_findings),
        artifact_ids=persist_result.artifact_ids,
        top_actions=top_actions,
        promoted_findings_count=len(promoted_findings),
        report_ready_count=report_ready_counts["report_ready"],
        needs_review_count=report_ready_counts["needs_review"],
        noise_count=report_ready_counts["noise"],
    )

import pytest
import uuid

from chimera_core.modules.recon_gatherers.schemas import ReconBundle, ObservedAsset, Service, Finding
from chimera_core.modules.recon_gatherers.sinks.recon_sink import PersistResult
from chimera_core.modules.recon_gatherers.notify.shannon_client import ShannonSummary
# This function doesn't exist yet, so the import will fail.
from chimera_core.modules.recon_gatherers.notify.summary import build_summary

@pytest.fixture
def sample_bundle():
    """Provides a sample ReconBundle for testing summary generation."""
    return ReconBundle(
        run_id=str(uuid.uuid4()),
        target="example.com",
        tool="zypheron",
        observed_assets=[
            ObservedAsset(type="host", value=f"host-{i}.example.com", source_tool="zypheron") for i in range(10)
        ],
        services=[
            Service(host="host-1.example.com", port=i, proto="tcp", service=f"service-{i}") for i in range(10)
        ],
        findings=[
            Finding(title=f"Finding {i}", type="vuln", severity="high", confidence="high") for i in range(10)
        ]
    )

@pytest.fixture
def sample_persist_result():
    """Provides a sample PersistResult for testing summary generation."""
    return PersistResult(
        run_id=str(uuid.uuid4()),
        assets_persisted=10,
        services_persisted=10,
        findings_persisted=10,
        artifacts_persisted=2,
        artifact_ids=["artifact_1", "artifact_2"]
    )

def test_summary_includes_top_findings_and_counts(sample_bundle, sample_persist_result):
    # Act
    summary = build_summary(sample_bundle, sample_persist_result, program_handle="test_program")

    # Assert
    assert isinstance(summary, ShannonSummary)
    assert summary.program_handle == "test_program"
    assert summary.target == "example.com"
    assert summary.run_id == sample_bundle.run_id
    assert summary.asset_count == 10
    assert summary.service_count == 10
    assert summary.finding_count == 10
    assert summary.needs_review_count == 10
    assert summary.report_ready_count == 0
    assert summary.noise_count == 0
    assert len(summary.top_assets) == 5  # Default truncation
    assert len(summary.top_services) == 5 # Default truncation
    assert len(summary.top_findings) == 5 # Default truncation

    assert "host-0.example.com" in summary.top_assets
    assert "service-0 on host-1.example.com:0" in summary.top_services
    assert "Finding 0" in summary.top_findings
    assert summary.artifact_ids == ["artifact_1", "artifact_2"]

def test_summary_truncates_long_lists(sample_bundle, sample_persist_result):
    # Act
    summary = build_summary(sample_bundle, sample_persist_result, top_n=3)

    # Assert
    assert len(summary.top_assets) == 3
    assert len(summary.top_services) == 3
    assert len(summary.top_findings) == 3

def test_summary_handles_no_findings():
    # Arrange
    bundle = ReconBundle(run_id=str(uuid.uuid4()), target="nohost.com", tool="test")
    result = PersistResult(run_id=bundle.run_id)

    # Act
    summary = build_summary(bundle, result)

    # Assert
    assert summary.asset_count == 0
    assert summary.service_count == 0
    assert summary.finding_count == 0
    assert not summary.top_assets
    assert not summary.top_services
    assert not summary.top_findings
    assert summary.report_ready_count == 0
    assert summary.needs_review_count == 0
    assert summary.noise_count == 0

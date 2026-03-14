import pytest
from unittest.mock import MagicMock, call
from datetime import datetime
import uuid

from chimera_core.modules.recon_gatherers.schemas import ReconBundle, ObservedAsset, Service, Finding, Artifact
from chimera_core.modules.recon_gatherers.sinks.recon_repository import ReconRepository

# This is the class we will be testing, which doesn't exist yet.
# The test will fail until we create it in recon_sink.py
from chimera_core.modules.recon_gatherers.sinks.recon_sink import DatabaseReconSink, PersistResult

@pytest.fixture
def mock_repo():
    """Provides a mock ReconRepository for testing the sink."""
    return MagicMock(spec=ReconRepository)

@pytest.fixture
def sample_bundle():
    """Provides a sample ReconBundle populated with data."""
    run_id = str(uuid.uuid4())
    return ReconBundle(
        run_id=run_id,
        target="example.com",
        tool="zypheron",
        observed_assets=[
            ObservedAsset(type="host", value="www.example.com", source_tool="zypheron"),
            ObservedAsset(type="domain", value="sub.example.com", source_tool="zypheron"),
            # Duplicate asset to test deduplication
            ObservedAsset(type="host", value="www.example.com", source_tool="zypheron"),
        ],
        services=[
            Service(host="www.example.com", port=443, proto="tcp", service="https")
        ],
        findings=[
            Finding(title="Test Finding", type="vuln", severity="high", confidence="high")
        ],
        artifacts=[
            Artifact(path="/tmp/stdout.txt", kind="stdout", sha256="abc"),
            Artifact(path="/tmp/stderr.txt", kind="stderr", sha256="def"),
        ],
    )

def test_persist_happy_path_calls_repo_methods_in_order(mock_repo, sample_bundle):
    # Arrange
    sink = DatabaseReconSink(repository=mock_repo)

    # Mock the return values of repository methods
    mock_repo.create_run.return_value = sample_bundle.run_id
    mock_repo.upsert_asset.side_effect = ["asset_1", "asset_2"] # Two unique assets
    mock_repo.insert_service.return_value = "service_1"
    mock_repo.insert_finding.return_value = "finding_1"
    mock_repo.insert_artifact.side_effect = ["artifact_1", "artifact_2"]

    # Act
    result = sink.persist(sample_bundle)

    # Assert
    assert isinstance(result, PersistResult)
    assert result.run_id == sample_bundle.run_id
    assert result.assets_persisted == 2
    assert result.services_persisted == 1
    assert result.findings_persisted == 1
    assert result.artifacts_persisted == 2

    # Verify that the repository methods were called with the correct data
    mock_repo.create_run.assert_called_once()
    
    # Check that upsert_asset was called for each unique asset
    assert mock_repo.upsert_asset.call_count == 2
    mock_repo.upsert_asset.assert_has_calls([
        call(run_id=sample_bundle.run_id, asset_type='host', value='www.example.com', source_tool='zypheron'),
        call(run_id=sample_bundle.run_id, asset_type='domain', value='sub.example.com', source_tool='zypheron'),
    ], any_order=True)

    mock_repo.insert_service.assert_called_once_with(
        run_id=sample_bundle.run_id, host='www.example.com', port=443, proto='tcp', service='https', banner=None, confidence=None
    )
    mock_repo.insert_finding.assert_called_once_with(
        run_id=sample_bundle.run_id, finding_obj=sample_bundle.findings[0]
    )
    mock_repo.insert_artifact.assert_has_calls([
        call(run_id=sample_bundle.run_id, path='/tmp/stdout.txt', kind='stdout', sha256='abc', mime=None),
        call(run_id=sample_bundle.run_id, path='/tmp/stderr.txt', kind='stderr', sha256='def', mime=None),
    ], any_order=True)


def test_persist_handles_empty_bundle_gracefully(mock_repo):
    # Arrange
    sink = DatabaseReconSink(repository=mock_repo)
    empty_bundle = ReconBundle(run_id=str(uuid.uuid4()), target="empty.com", tool="test")

    mock_repo.create_run.return_value = empty_bundle.run_id

    # Act
    result = sink.persist(empty_bundle)

    # Assert
    assert result.run_id == empty_bundle.run_id
    assert result.assets_persisted == 0
    assert result.services_persisted == 0
    assert result.findings_persisted == 0
    assert result.artifacts_persisted == 0

    mock_repo.create_run.assert_called_once()
    mock_repo.upsert_asset.assert_not_called()
    mock_repo.insert_service.assert_not_called()
    mock_repo.insert_finding.assert_not_called()
    mock_repo.insert_artifact.assert_not_called()


import pytest
from unittest.mock import MagicMock
import uuid

from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.modules.recon_gatherers.orchestrator import run_zypheron_and_persist
from chimera_core.modules.recon_gatherers.sinks.recon_sink import DatabaseReconSink
from chimera_core.modules.recon_gatherers.sinks.inmemory_repository import InMemoryRepository
from chimera_core.modules.recon_gatherers.notify.shannon_client import ShannonClient, ShannonSummary

# Re-using the sample output from the unit tests
ZYPHERON_SAMPLE_OUTPUT = """
[INFO] Starting Zypheron scan for target: example.com
[ASSET] host: www.example.com
[ASSET] domain: sub.example.com
[SERVICE] host: example.com, port: 443, proto: tcp, service: https
[INFO] Scan finished.
"""

@pytest.fixture
def mock_runtime():
    runtime = MagicMock(spec=Runtime)
    runtime.run_id = str(uuid.uuid4())
    runtime.mode = "fixture"
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    runtime.scope_graph = ScopeGraph(scope_manifest)
    runtime.scope_policy = ScopePolicy(scope_manifest)
    # Mock run_external_tool to return a successful result with sample output
    runtime.run_external_tool.return_value = MagicMock(
        stdout=ZYPHERON_SAMPLE_OUTPUT,
        stderr="",
        exit_code=0,
        ok=True,
    )
    # Mock the artifacts path to avoid filesystem operations
    runtime.artifacts_root = MagicMock()
    runtime.artifacts_root.__truediv__.return_value.mkdir.return_value = None
    runtime.artifacts_root.__truediv__.return_value.write_text.return_value = None
    return runtime

def test_zypheron_to_sink_integration(mock_runtime):
    # Arrange
    target = "example.com"
    program_handle = "test-program"

    # Use the real InMemoryRepository and DatabaseReconSink
    repo = InMemoryRepository()
    sink = DatabaseReconSink(repository=repo)

    # Create a fake Shannon client to capture the sent payload
    mock_shannon_client = MagicMock(spec=ShannonClient)

    # Act
    result = run_zypheron_and_persist(
        target=target,
        runtime=mock_runtime,
        sink=sink,
        notifier=mock_shannon_client,
        program_handle=program_handle,
    )

    # Assert
    # 1. Check that the external command was called
    mock_runtime.run_external_tool.assert_called_once()

    # 2. Check the data in the in-memory repository
    assert len(repo.runs) == 1
    run_id = list(repo.runs.keys())[0]
    assert repo.runs[run_id]["target"] == target

    assert len(repo.assets[run_id]) == 2
    asset_values = {asset["value"] for asset in repo.assets[run_id]}
    assert "www.example.com" in asset_values
    assert "sub.example.com" in asset_values

    assert len(repo.services[run_id]) == 1
    assert repo.services[run_id][0]["port"] == 443

    assert len(repo.artifacts[run_id]) == 4

    # 3. Check that the Shannon client was called with the correct summary
    mock_shannon_client.send_recon_summary.assert_called_once()
    sent_summary = mock_shannon_client.send_recon_summary.call_args[0][0]
    
    assert isinstance(sent_summary, ShannonSummary)
    assert sent_summary.program_handle == program_handle
    assert sent_summary.target == target
    assert sent_summary.run_id is not None
    assert sent_summary.asset_count == 2
    assert sent_summary.service_count == 1
    assert "www.example.com" in sent_summary.top_assets
    assert "https on example.com:443" in sent_summary.top_services

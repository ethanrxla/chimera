import pytest
from unittest.mock import MagicMock, patch
import uuid
import hashlib
from pathlib import Path

from chimera_core.runtime import Runtime, ExternalToolTimeout, ToolOutputError # Assuming these exceptions exist
from chimera_core.modules.recon_gatherers.zypheron_adapter import ZypheronAdapter
from chimera_core.modules.recon_gatherers.schemas import ReconBundle, ObservedAsset, Service, Artifact

# Sample Zypheron CLI output for testing
ZYPHERON_SAMPLE_OUTPUT = """
[INFO] Starting Zypheron scan for target: example.com
[ASSET] host: www.example.com
[ASSET] domain: sub.example.com
[SERVICE] host: example.com, port: 80, proto: tcp, service: http
[SERVICE] host: example.com, port: 443, proto: tcp, service: https
[INFO] Scan finished.
"""

# Mock Runtime class for testing purposes
@pytest.fixture
def mock_runtime():
    runtime = MagicMock(spec=Runtime)
    runtime.run_id = str(uuid.uuid4())
    runtime.mode = "fixture"

    # Mock artifacts_root to behave like a Path object
    mock_artifacts_root = MagicMock(spec=Path)
    
    def recursive_path_mock(current_path_str):
        mock_path = MagicMock(spec=Path)
        mock_path.name = Path(current_path_str).name
        mock_path.suffix = Path(current_path_str).suffix
        mock_path.write_text = MagicMock()
        mock_path.mkdir = MagicMock() # Mock mkdir
        mock_path.__str__.side_effect = lambda: current_path_str

        def inner_truediv_side_effect(other):
            new_path_str = f"{current_path_str}/{other}"
            return recursive_path_mock(new_path_str)

        mock_path.__truediv__.side_effect = inner_truediv_side_effect
        return mock_path

    mock_artifacts_root.__truediv__.side_effect = lambda other: recursive_path_mock(f"/mock/artifacts/{runtime.run_id}/{other}")
    runtime.artifacts_root = mock_artifacts_root

    # Mock event_store as a MagicMock that can have methods set on it
    runtime.event_store = MagicMock()
    runtime.event_store.emit_event = MagicMock()
    runtime.event_store.emit = MagicMock()

    return runtime

def test_run_scan_success_parses_assets_and_services(mock_runtime):
    # Arrange
    adapter = ZypheronAdapter(runtime=mock_runtime)
    target = "example.com"

    # Configure the mock to return successful output
    mock_runtime.run_external_tool.return_value = MagicMock(
        stdout=ZYPHERON_SAMPLE_OUTPUT,
        stderr="",
        exit_code=0,
        duration_s=10.0,
        command="zypheron scan example.com",
        ok=True,
    )

    # Act
    bundle = adapter.run_scan(target)

    # Assert
    mock_runtime.run_external_tool.assert_called_once()

    assert isinstance(bundle, ReconBundle)
    assert bundle.run_id == mock_runtime.run_id
    assert bundle.target == target
    assert bundle.tool == "zypheron"
    assert len(bundle.observed_assets) == 2
    assert len(bundle.services) == 2
    assert len(bundle.findings) == 0 # ZypheronAdapter is for recon, not findings initially
    assert len(bundle.artifacts) == 2 # For stdout and stderr

    # Check specific assets
    asset_www = next((a for a in bundle.observed_assets if a.value == "www.example.com"), None)
    assert asset_www is not None
    assert asset_www.type == "host"
    assert asset_www.source_tool == "zypheron"

    asset_sub = next((a for a in bundle.observed_assets if a.value == "sub.example.com"), None)
    assert asset_sub is not None
    assert asset_sub.type == "domain"
    assert asset_sub.source_tool == "zypheron"

    # Check specific services
    service_http = next((s for s in bundle.services if s.port == 80), None)
    assert service_http is not None
    assert service_http.host == "example.com"
    assert service_http.proto == "tcp"
    assert service_http.service == "http"

    service_https = next((s for s in bundle.services if s.port == 443), None)
    assert service_https is not None
    assert service_https.host == "example.com"
    assert service_https.proto == "tcp"
    assert service_https.service == "https"

    # Check artifact for stdout
    stdout_artifact = next((a for a in bundle.artifacts if a.kind == "stdout"), None)
    assert stdout_artifact is not None
    assert stdout_artifact.path.endswith(f"{mock_runtime.run_id}/zypheron/zypheron_stdout.txt")
    assert stdout_artifact.sha256 == hashlib.sha256(ZYPHERON_SAMPLE_OUTPUT.encode()).hexdigest()

def test_run_scan_tool_failure(mock_runtime):
    # Arrange
    adapter = ZypheronAdapter(runtime=mock_runtime)
    target = "example.com"

    stderr_output = "[ERROR] Zypheron failed to scan the target.\n"

    # Configure the mock to simulate a tool failure
    mock_runtime.run_external_tool.return_value = MagicMock(
        stdout="",
        stderr=stderr_output,
        exit_code=1,
        duration_s=5.0,
        command="zypheron scan example.com",
        ok=False,
    )

    # Act
    bundle = adapter.run_scan(target)

    # Assert that a bundle is still returned, but it should indicate failure
    assert isinstance(bundle, ReconBundle)
    assert bundle.run_id == mock_runtime.run_id
    assert bundle.target == target
    assert bundle.tool == "zypheron"
    assert not bundle.observed_assets
    assert not bundle.services
    assert len(bundle.findings) == 1
    assert bundle.findings[0].title == "Zypheron command execution failed"
    assert bundle.findings[0].severity == "high"
    assert len(bundle.artifacts) == 2 # stdout and stderr

    stderr_artifact = next((a for a in bundle.artifacts if a.kind == "stderr"), None)
    assert stderr_artifact is not None
    assert stderr_artifact.path.endswith(f"{mock_runtime.run_id}/zypheron/zypheron_stderr.txt")
    assert stderr_artifact.sha256 == hashlib.sha256(stderr_output.encode()).hexdigest()

def test_run_scan_timeout(mock_runtime):
    # Arrange
    adapter = ZypheronAdapter(runtime=mock_runtime)
    target = "example.com"

    # Configure the mock to raise an ExternalToolTimeout
    mock_runtime.run_external_tool.side_effect = ExternalToolTimeout("Zypheron timed out.")

    # Act & Assert
    with pytest.raises(ExternalToolTimeout):
        adapter.run_scan(target)

    mock_runtime.run_external_tool.assert_called_once()

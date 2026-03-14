import pytest
import socket
from pathlib import Path
from unittest.mock import Mock

from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.event_store import EventStore

@pytest.fixture
def runtime_setup(tmp_path: Path):
    scope_manifest = {"allowlist": ["example.com"], "denylist": ["blocked.example.com"]}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    events_file = tmp_path / "events.jsonl"
    event_store = EventStore(events_file)
    artifacts_root = tmp_path / "artifacts"
    
    runtime = Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
    )
    return runtime, scope_graph


@pytest.fixture
def public_dns(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return fake_getaddrinfo

def test_runtime_blocks_out_of_scope(runtime_setup, public_dns):
    runtime, _ = runtime_setup
    # This command targets an out-of-scope domain
    command = ["curl", "https://evil.com"]
    
    with pytest.raises(ValueError, match="Target out of scope"):
        # We need to modify execute_cmd to extract the target and check it
        runtime.execute_cmd(command)

def test_runtime_blocks_denied_scope(runtime_setup, public_dns):
    runtime, _ = runtime_setup
    command = ["curl", "https://blocked.example.com"]
    
    with pytest.raises(ValueError, match="Target out of scope"):
        runtime.execute_cmd(command)

def test_runtime_allows_in_scope(runtime_setup, public_dns):
    runtime, _ = runtime_setup
    # We need to mock subprocess.run to avoid a real network call
    runtime._execute_subprocess = Mock(return_value=Mock(stdout="", stderr="", returncode=0))
    command = ["curl", "https://example.com"]
    
    try:
        runtime.execute_cmd(command)
    except ValueError:
        pytest.fail("Runtime blocked an in-scope target, but it should have been allowed.")

def test_runtime_rate_limiter_caps_requests(runtime_setup, public_dns):
    runtime, _ = runtime_setup
    runtime.rate_limiter = Mock() # Mock the rate limiter for this test
    runtime.rate_limiter.acquire.side_effect = [True, True, False] # Allow 2, block the 3rd
    
    runtime._execute_subprocess = Mock(return_value=Mock(stdout="", stderr="", returncode=0))
    command = ["curl", "https://example.com"]

    # First two should pass
    runtime.execute_cmd(command)
    runtime.execute_cmd(command)

    # Third should raise an exception
    with pytest.raises(Exception, match="Rate limit exceeded"):
        runtime.execute_cmd(command)

    assert runtime.rate_limiter.acquire.call_count == 3

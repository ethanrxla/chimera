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
    command = ["curl", "https://evil.com"]

    with pytest.raises(ValueError, match="Target out of scope"):
        runtime.run_cmd(command)

def test_runtime_blocks_denied_scope(runtime_setup, public_dns):
    runtime, _ = runtime_setup
    command = ["curl", "https://blocked.example.com"]

    with pytest.raises(ValueError, match="Target out of scope"):
        runtime.run_cmd(command)

def test_runtime_allows_in_scope(runtime_setup, public_dns):
    runtime, _ = runtime_setup
    runtime._execute_subprocess = Mock(return_value=Mock(stdout="", stderr="", returncode=0))
    command = ["curl", "https://example.com"]

    try:
        runtime.run_cmd(command)
    except ValueError:
        pytest.fail("Runtime blocked an in-scope target, but it should have been allowed.")

def test_runtime_rate_limiter_caps_requests(runtime_setup, public_dns):
    runtime, _ = runtime_setup
    runtime.rate_limiter = Mock()
    runtime.rate_limiter.acquire.side_effect = [True, True, False]

    runtime._execute_subprocess = Mock(return_value=Mock(stdout="", stderr="", returncode=0))
    command = ["curl", "https://example.com"]

    runtime.run_cmd(command)
    runtime.run_cmd(command)

    with pytest.raises(Exception, match="Rate limit exceeded"):
        runtime.run_cmd(command)

    assert runtime.rate_limiter.acquire.call_count == 3


def test_execute_subprocess_merges_parent_environment(runtime_setup, monkeypatch):
    runtime, _ = runtime_setup
    captured = {}

    class DummyProcess:
        def __init__(self, *args, **kwargs):
            captured["env"] = kwargs.get("env")
            self.returncode = 0

        def communicate(self, timeout=None):
            return ("", "")

    monkeypatch.setenv("PARENT_ONLY_VAR", "present")
    monkeypatch.setattr("subprocess.Popen", DummyProcess)

    result = runtime._execute_subprocess(["python", "-c", "print('ok')"], env={"CHILD_ONLY_VAR": "set"})

    assert result.returncode == 0
    assert captured["env"]["PARENT_ONLY_VAR"] == "present"
    assert captured["env"]["CHILD_ONLY_VAR"] == "set"

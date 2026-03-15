import json
import socket
from pathlib import Path
from unittest.mock import Mock

import pytest

from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


@pytest.fixture
def runtime(tmp_path: Path):
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    event_store = EventStore(tmp_path / "events.jsonl")
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=tmp_path / "artifacts",
        max_output_bytes=50,
    )


def _mock_public_dns(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


def test_runtime_blocks_unknown_binary(runtime, monkeypatch):
    _mock_public_dns(monkeypatch)
    command = ["unknown-tool", "https://example.com"]
    with pytest.raises(ValueError, match="Command not allowed"):
        runtime.run_cmd(command)


def test_runtime_blocks_suspicious_arg(runtime, monkeypatch):
    _mock_public_dns(monkeypatch)
    command = ["curl", "https://example.com", ";rm -rf /"]
    with pytest.raises(ValueError, match="Suspicious argument"):
        runtime.run_cmd(command)


def test_runtime_blocks_target_override(runtime, monkeypatch):
    _mock_public_dns(monkeypatch)
    command = ["curl", "https://example.com", "https://evil.com"]
    with pytest.raises(ValueError, match="Target out of scope"):
        runtime.run_cmd(command)


def test_runtime_blocks_private_ip_resolution(tmp_path, monkeypatch):
    scope_manifest = {"allowlist": ["example.com"], "denylist": [], "allow_private_ips": False}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    event_store = EventStore(tmp_path / "events.jsonl")
    rt = Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=tmp_path / "artifacts",
    )

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    rt._execute_subprocess = Mock(return_value=Mock(stdout="", stderr="", returncode=0))
    with pytest.raises(ValueError, match="Target out of scope"):
        rt.run_cmd(["curl", "https://example.com"])


def test_runtime_blocks_raw_ip_without_allow(runtime):
    runtime._execute_subprocess = Mock(return_value=Mock(stdout="", stderr="", returncode=0))
    with pytest.raises(ValueError, match="Target out of scope"):
        runtime.run_cmd(["curl", "1.2.3.4"])


def test_runtime_allows_raw_ip_when_explicit(tmp_path: Path):
    scope_manifest = {"allowlist": ["1.2.3.4"], "denylist": [], "allow_ip_targets": True}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    event_store = EventStore(tmp_path / "events.jsonl")
    runtime = Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=tmp_path / "artifacts",
    )
    runtime._execute_subprocess = Mock(return_value=Mock(stdout="", stderr="", returncode=0))
    runtime.run_cmd(["curl", "1.2.3.4"])


def test_runtime_truncates_output_and_emits_event(runtime, monkeypatch):
    _mock_public_dns(monkeypatch)
    runtime._execute_subprocess = Mock(return_value=Mock(stdout="x" * 200, stderr="", returncode=0))
    runtime.run_cmd(["python", "-c", "print('hello')"])
    events = runtime.event_store.replay()
    payloads = [event for event in events if event.get("event_type") == "output_truncated"]
    assert payloads


def test_runtime_emits_run_limit_warning(runtime, monkeypatch):
    _mock_public_dns(monkeypatch)
    runtime.max_artifacts_bytes = 10
    runtime._execute_subprocess = Mock(return_value=Mock(stdout="x" * 50, stderr="", returncode=0))
    runtime.run_cmd(["python", "-c", "print('hello')"])
    events = list(runtime.event_store.replay())
    warnings = [event for event in events if event.get("event_type") == "run_limit_warning"]
    assert warnings

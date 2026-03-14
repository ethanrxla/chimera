import socket
from pathlib import Path

from chimera_core.adapters.subfinder_adapter import SubfinderAdapter
from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    run_id = "run-subfinder"
    artifacts_root = tmp_path / "artifacts"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=EventStore(run_dir / "events.jsonl"),
        artifacts_root=artifacts_root,
        run_id=run_id,
    )


def test_subfinder_normalizes_jsonl(monkeypatch, tmp_path: Path) -> None:
    adapter = SubfinderAdapter(make_runtime(tmp_path), run_id="run-subfinder", task_id="T1", scope_hash="scope")

    def fake_getaddrinfo(host, port):
        if host == "ghost.example.com":
            raise socket.gaierror("missing")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    findings = adapter.normalize('{"host":"api.example.com"}\n{"host":"ghost.example.com"}\n')

    assert len(findings) == 2
    assert findings[0].finding_type == "SUBDOMAIN"
    assert findings[1].title == "Potential subdomain takeover candidate"

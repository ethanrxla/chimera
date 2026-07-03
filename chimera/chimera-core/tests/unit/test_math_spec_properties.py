from pathlib import Path
from types import SimpleNamespace
from tempfile import TemporaryDirectory

from hypothesis import given, strategies as st

from chimera_core.event_store import EventStore
from chimera_core.graph.builder import build_evidence_graph
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def _make_runtime(tmp_path: Path, *, max_output_bytes: int = 50) -> Runtime:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=EventStore(tmp_path / "events.jsonl", run_id="run-prop"),
        artifacts_root=tmp_path / "artifacts",
        run_id="run-prop",
        max_output_bytes=max_output_bytes,
    )


@given(st.lists(st.sampled_from(["alpha", "beta", "gamma"]), min_size=1, max_size=12))
def test_p_event_seq(events: list[str]) -> None:
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        store = EventStore(tmp_path / "events.jsonl", run_id="run-prop", source="property-test")
        for name in events:
            store.emit({"event_type": name, "payload": {}})
        replayed = list(store.replay())
        seqs = [event["seq"] for event in replayed]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == len(seqs)


@given(st.lists(st.text(alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=8), min_size=1, max_size=5))
def test_p_artifact_saved_exists(names: list[str]) -> None:
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        store = EventStore(tmp_path / "events.jsonl", run_id="run-prop")
        for name in names:
            path = tmp_path / f"{name}.txt"
            path.write_text("ok", encoding="utf-8")
            store.emit({"event_type": "artifact_saved", "payload": {"path": str(path), "artifact_type": "test"}})
        for event in store.replay():
            if event["event_type"] == "artifact_saved":
                assert Path(event["payload"]["path"]).exists()


@given(st.integers(min_value=0, max_value=250))
def test_p_output_bounds_or_truncated(stdout_size: int) -> None:
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        runtime = _make_runtime(tmp_path, max_output_bytes=40)
        runtime._execute_subprocess = lambda *args, **kwargs: SimpleNamespace(stdout="x" * stdout_size, stderr="", returncode=0)
        runtime.run_cmd(["python", "-c", "print('ok')"])
        events = list(runtime.event_store.replay())
        truncated = [event for event in events if event["event_type"] == "output_truncated"]
        if stdout_size > 40:
            assert truncated
        else:
            assert not truncated


@given(st.booleans())
def test_p_scope_fail_closed(out_of_scope: bool) -> None:
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        runtime = _make_runtime(tmp_path)
        runtime._execute_subprocess = lambda *args, **kwargs: SimpleNamespace(stdout="", stderr="", returncode=0)
        target = "https://evil.com" if out_of_scope else "https://example.com"
        if out_of_scope:
            try:
                runtime.run_cmd(["curl", target])
            except ValueError:
                pass
            else:
                raise AssertionError("Expected out-of-scope execution to fail closed")
            events = list(runtime.event_store.replay())
            assert any(event["event_type"] == "scope_violation" for event in events)
        else:
            runtime.run_cmd(["curl", target])


@given(st.integers(min_value=1, max_value=4))
def test_p_graph_construction_consistency(count: int) -> None:
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        artifacts_root = tmp_path / "artifacts"
        run_root = artifacts_root / "run-prop"
        run_root.mkdir(parents=True, exist_ok=True)
        events = []
        for index in range(count):
            path = run_root / f"a{index}.txt"
            path.write_text("ok", encoding="utf-8")
            events.append(
                {
                    "event_id": f"e{index}",
                    "run_id": "run-prop",
                    "seq": index + 1,
                    "event_type": "artifact_saved",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "source": "property-test",
                    "payload": {"task_id": "t1", "path": str(path), "artifact_type": "test"},
                }
            )
        graph = build_evidence_graph(events=events, artifacts_root=artifacts_root)
        emits = [edge for edge in graph.edges if edge.label == "EMITS_ARTIFACT"]
        assert len(emits) == count


@given(st.integers(min_value=1, max_value=3))
def test_p_findings_evidence_anchors(count: int) -> None:
    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        artifacts_root = tmp_path / "artifacts"
        run_root = artifacts_root / "run-prop"
        run_root.mkdir(parents=True, exist_ok=True)
        evidence_refs = []
        events = []
        for index in range(count):
            path = run_root / f"evidence-{index}.txt"
            path.write_text("ok", encoding="utf-8")
            evidence_refs.append(str(path))
            events.append(
                {
                    "event_id": f"e{index}",
                    "run_id": "run-prop",
                    "seq": index + 1,
                    "event_type": "artifact_saved",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "source": "property-test",
                    "payload": {"task_id": "t1", "path": str(path), "artifact_type": "evidence"},
                }
            )
        findings_path = run_root / "findings.json"
        findings_path.write_text(
            __import__("json").dumps(
                [
                    {
                        "finding_id": "finding-prop",
                        "severity": "medium",
                        "title": "Property finding",
                        "affected_target": "https://example.com",
                        "evidence_refs": evidence_refs,
                    }
                ]
            ),
            encoding="utf-8",
        )
        graph = build_evidence_graph(events=events, artifacts_root=artifacts_root, findings_path=findings_path)
        anchors = [edge for edge in graph.edges if edge.label == "EVIDENCE_FOR"]
        assert len(anchors) == count

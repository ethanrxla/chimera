"""
Tests for strix_adapter partial-success detection, deduplication, and contradiction logic.
"""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from chimera_core.adapters.strix_adapter import (
    _check_contradictions,
    _deduplicate_findings,
    _strix_run_completed,
)


# ---------------------------------------------------------------------------
# _strix_run_completed
# ---------------------------------------------------------------------------

def test_run_completed_from_events_jsonl(tmp_path: Path):
    run_dir = tmp_path / "test-run"
    run_dir.mkdir()
    events = [
        {"event_type": "agent.status.updated"},
        {"event_type": "run.completed", "status": "completed"},
    ]
    (run_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    assert _strix_run_completed(run_dir) is True


def test_run_completed_from_csv(tmp_path: Path):
    run_dir = tmp_path / "test-run"
    run_dir.mkdir()
    (run_dir / "vulnerabilities.csv").write_text(
        "id,title,severity,timestamp,file\nvuln-0001,XSS,HIGH,2026-01-01,vulns/v1.md\n",
        encoding="utf-8",
    )
    assert _strix_run_completed(run_dir) is True


def test_run_completed_empty_csv_header_only(tmp_path: Path):
    run_dir = tmp_path / "test-run"
    run_dir.mkdir()
    (run_dir / "vulnerabilities.csv").write_text(
        "id,title,severity,timestamp,file\n", encoding="utf-8"
    )
    assert _strix_run_completed(run_dir) is False


def test_run_completed_empty_dir(tmp_path: Path):
    run_dir = tmp_path / "test-run"
    run_dir.mkdir()
    assert _strix_run_completed(run_dir) is False


def test_run_completed_events_without_run_completed(tmp_path: Path):
    run_dir = tmp_path / "test-run"
    run_dir.mkdir()
    events = [{"event_type": "agent.status.updated"}, {"event_type": "chat.message"}]
    (run_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events), encoding="utf-8"
    )
    assert _strix_run_completed(run_dir) is False


# ---------------------------------------------------------------------------
# _deduplicate_findings
# ---------------------------------------------------------------------------

def test_dedup_collapses_identical_xss():
    """vuln-0001 and vuln-0003 (same XSS, slightly different titles) collapse to 1."""
    entries = [
        {
            "title": "XSS Vulnerability in Search Input on https://scholarcal.com",
            "severity": "high",
            "url": "https://scholarcal.com",
            "description": "Short description.",
            "evidence_refs": ["path/vuln-0001.md"],
        },
        {
            "title": "XSS Vulnerability in Search Input Field on https://scholarcal.com",
            "severity": "high",
            "url": "https://scholarcal.com",
            "description": "A longer and more detailed description of the same XSS issue.",
            "evidence_refs": ["path/vuln-0003.md"],
        },
    ]
    result = _deduplicate_findings(entries)
    assert len(result) == 1
    # Richer description wins
    assert "longer" in result[0]["description"]
    # Evidence refs merged
    assert len(result[0]["evidence_refs"]) == 2


def test_dedup_keeps_distinct_findings():
    """Different severity or different vuln type should not be merged."""
    entries = [
        {
            "title": "XSS Vulnerability in Search Input",
            "severity": "high",
            "url": "https://scholarcal.com",
            "description": "XSS",
            "evidence_refs": [],
        },
        {
            "title": "Clickjacking Vulnerability",
            "severity": "medium",
            "url": "https://scholarcal.com",
            "description": "Clickjacking",
            "evidence_refs": [],
        },
    ]
    result = _deduplicate_findings(entries)
    assert len(result) == 2


def test_dedup_keeps_same_vuln_different_url():
    """Same title but different target URL should not be merged."""
    entries = [
        {
            "title": "XSS in Search",
            "severity": "high",
            "url": "https://scholarcal.com",
            "description": "xss",
            "evidence_refs": [],
        },
        {
            "title": "XSS in Search",
            "severity": "high",
            "url": "https://other.com",
            "description": "xss",
            "evidence_refs": [],
        },
    ]
    result = _deduplicate_findings(entries)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# _check_contradictions
# ---------------------------------------------------------------------------

def test_contradiction_downgrades_clickjacking_confidence(tmp_path: Path):
    report_dir = tmp_path / "run"
    report_dir.mkdir()
    (report_dir / "penetration_test_report.md").write_text(
        "The application is robust against clickjacking and all headers are set correctly.",
        encoding="utf-8",
    )
    entries = [
        {
            "title": "Clickjacking Vulnerability",
            "description": "Missing X-Frame-Options.",
            "severity": "medium",
            "url": "https://scholarcal.com",
            "evidence_refs": [],
        }
    ]
    result = _check_contradictions(entries, report_dir)
    assert result[0].get("confidence_override") == 0.3
    assert "robust against clickjacking" in result[0].get("contradiction_note", "")


def test_contradiction_no_override_when_report_agrees(tmp_path: Path):
    report_dir = tmp_path / "run"
    report_dir.mkdir()
    (report_dir / "penetration_test_report.md").write_text(
        "An XSS vulnerability was found in the search input.",
        encoding="utf-8",
    )
    entries = [
        {
            "title": "XSS Vulnerability in Search",
            "description": "Reflected XSS.",
            "severity": "high",
            "url": "https://scholarcal.com",
            "evidence_refs": [],
        }
    ]
    result = _check_contradictions(entries, report_dir)
    assert "confidence_override" not in result[0]


def test_contradiction_no_report_file(tmp_path: Path):
    """If penetration_test_report.md is absent, entries pass through unchanged."""
    report_dir = tmp_path / "run"
    report_dir.mkdir()
    entries = [
        {
            "title": "Clickjacking Vulnerability",
            "description": "Missing X-Frame-Options.",
            "severity": "medium",
            "url": "https://scholarcal.com",
            "evidence_refs": [],
        }
    ]
    result = _check_contradictions(entries, report_dir)
    assert "confidence_override" not in result[0]


# ---------------------------------------------------------------------------
# Adapter integration: partial success (non-zero exit + completed run)
# ---------------------------------------------------------------------------

def _make_adapter(tmp_path: Path, strix_runs_root: Path):
    """Return a StrixAdapter wired to tmp_path artifacts and a custom strix_runs_root."""
    from chimera_core.adapters.strix_adapter import StrixAdapter
    from chimera_core.event_store import EventStore
    from chimera_core.runtime import Runtime
    from chimera_core.scope import ScopeGraph, ScopePolicy

    scope_manifest = {"allowlist": ["https://scholarcal.com", "https://scholarcal.com/*"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    run_id = "test-partial-run"
    artifacts_root = tmp_path / "artifacts"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(run_dir / "events.jsonl")
    runtime = Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
    )
    adapter = StrixAdapter(
        runtime=runtime,
        options={"live": True, "timeout_s": 60},
        run_id=run_id,
        task_id="strix-0-0",
        scope_hash="testhash",
        artifacts_root=artifacts_root,
    )
    # Override strix_runs_root to our tmp dir
    adapter.strix_runs_root = strix_runs_root
    return adapter


def _make_completed_strix_run(strix_runs_root: Path, run_name: str) -> Path:
    """Create a minimal completed Strix run directory."""
    run_dir = strix_runs_root / run_name
    run_dir.mkdir(parents=True)
    (run_dir / "events.jsonl").write_text(
        json.dumps({"event_type": "run.completed", "status": "completed"}),
        encoding="utf-8",
    )
    (run_dir / "vulnerabilities.csv").write_text(
        "id,title,severity,timestamp,file\n"
        "vuln-0001,XSS in Search,HIGH,2026-04-07 09:51:38 UTC,\n",
        encoding="utf-8",
    )
    return run_dir


def test_adapter_partial_success_no_raise(tmp_path: Path):
    """Exit code 2 with a completed Strix run dir → returns findings, does not raise."""
    strix_runs_root = tmp_path / "strix_runs"
    strix_runs_root.mkdir()
    run_dir = _make_completed_strix_run(strix_runs_root, "scholarcal-com_test")

    adapter = _make_adapter(tmp_path, strix_runs_root)

    fake_result = SimpleNamespace(
        returncode=2,
        stdout="some output",
        stderr="",
    )

    with patch.object(adapter.tool_runner, "run", return_value=fake_result):
        with patch.object(adapter, "_cleanup_sandbox_container"):
            result = adapter.run(["https://scholarcal.com"])

    assert result["findings"]  # at least one finding returned
    # No exception raised
    assert isinstance(result, dict)


def test_adapter_hard_failure_raises(tmp_path: Path):
    """Exit code 2 with NO completed Strix run dir → RuntimeError raised."""
    strix_runs_root = tmp_path / "strix_runs"
    strix_runs_root.mkdir()
    # No run dir created — empty strix_runs_root

    adapter = _make_adapter(tmp_path, strix_runs_root)

    fake_result = SimpleNamespace(
        returncode=2,
        stdout="fatal: something went wrong",
        stderr="",
    )

    with patch.object(adapter.tool_runner, "run", return_value=fake_result):
        with patch.object(adapter, "_cleanup_sandbox_container"):
            with pytest.raises(RuntimeError):
                adapter.run(["https://scholarcal.com"])

from pathlib import Path

from chimera_core.dedupe import dedupe_findings
from chimera_core.findings import Finding, stable_finding_id
from chimera_core.reporting import ReportBuilder


def make_finding(title: str, target: str, severity: str, run_id: str = "run-1") -> Finding:
    return Finding(
        finding_id=stable_finding_id(title, target, "tool-x"),
        severity=severity,
        title=title,
        description="desc",
        affected_target=target,
        tool_source="tool-x",
        tool_version="1.0.0",
        run_id=run_id,
        scope_hash="scope",
    )


def test_stable_hash_is_deterministic():
    id1 = stable_finding_id("Title", "https://example.com", "tool-x")
    id2 = stable_finding_id("Title", "https://example.com", "tool-x")
    assert id1 == id2


def test_dedupe_merges_evidence_and_severity():
    finding_a = make_finding("Leak", "https://example.com", "low")
    finding_a.evidence_refs = ["a.txt"]
    finding_b = make_finding("Leak", "https://example.com", "high")
    finding_b.evidence_refs = ["b.txt"]

    deduped, duplicates = dedupe_findings([finding_a, finding_b])
    assert duplicates == 1
    assert len(deduped) == 1
    assert deduped[0].severity == "high"
    assert sorted(deduped[0].evidence_refs) == ["a.txt", "b.txt"]


def test_report_builder_writes_outputs(tmp_path: Path):
    findings = [
        make_finding("Leak", "https://example.com", "low", run_id="run-2"),
        make_finding("XSS", "https://example.com/search", "high", run_id="run-2"),
    ]
    report = ReportBuilder(tmp_path)
    artifacts = report.write_reports("run-2", findings)

    assert artifacts.findings_path.exists()
    assert artifacts.report_path.exists()
    assert artifacts.summary_path.exists()

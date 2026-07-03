import json
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
    assert artifacts.chains_path.exists()
    assert artifacts.chain_graphs_path.exists()
    assert artifacts.rejected_findings_path.exists()
    assert artifacts.report_path.exists()
    assert artifacts.summary_path.exists()


def test_chain_summary_includes_extended_fields() -> None:
    finding = make_finding("IDOR", "https://example.com/api/users/7", "high")
    finding.finding_type = "IDOR"
    finding.asset = {"endpoint": "/api/users/{id}", "method": "GET"}
    finding.confidence = 0.85
    finding.chain_parent_ids = ["root-1"]
    finding.impact_path = [{"step": "pivot", "impact": "AccountTakeover", "evidence": "token reuse"}]

    summary = finding.to_chain_summary()

    assert "IDOR on GET /api/users/{id}" in summary
    assert "0.85" in summary
    assert "AccountTakeover" in summary


def test_report_builder_counts_exploit_chains(tmp_path: Path) -> None:
    finding = make_finding("Exploit chain", "https://example.com", "critical", run_id="run-3")
    finding.finding_type = "EXPLOIT_CHAIN"
    finding.validation_status = "confirmed"
    finding.chain_parent_ids = ["f1", "f2"]

    report = ReportBuilder(tmp_path)
    artifacts = report.write_reports("run-3", [finding])
    summary = artifacts.summary_path.read_text(encoding="utf-8")
    markdown = artifacts.report_path.read_text(encoding="utf-8")
    chains = artifacts.chains_path.read_text(encoding="utf-8")
    chain_graphs = artifacts.chain_graphs_path.read_text(encoding="utf-8")

    assert '"exploit_chains": 1' in summary
    assert "## Exploit Chains" in markdown
    assert "EXPLOIT_CHAIN" in chains
    assert "ascii" in chain_graphs


def test_report_builder_lists_rejected_findings(tmp_path: Path) -> None:
    finding = make_finding("Rejected finding", "https://example.com", "medium", run_id="run-4")
    finding.validation_status = "false_positive"
    finding.validation_reason = "Cross-user replay was blocked."

    report = ReportBuilder(tmp_path)
    artifacts = report.write_reports("run-4", [finding])

    rejected = artifacts.rejected_findings_path.read_text(encoding="utf-8")
    markdown = artifacts.report_path.read_text(encoding="utf-8")

    assert "Cross-user replay was blocked." in rejected
    assert "## Rejected Findings" in markdown


def test_report_builder_includes_verification_summary(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    events = [
        {
            "event_type": "verification_passed",
            "payload": {
                "verification_result_ref": "artifacts/run-5/verifications/ver-1/check-1-result.json",
            },
        },
        {
            "event_type": "verification_skipped",
            "payload": {
                "reason": "cache_hit",
            },
        },
    ]
    events_path.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")

    finding = make_finding("Open Redirect", "https://example.com/login", "medium", run_id="run-5")
    report = ReportBuilder(tmp_path)
    artifacts = report.write_reports("run-5", [finding])

    summary = json.loads(artifacts.summary_path.read_text(encoding="utf-8"))
    markdown = artifacts.report_path.read_text(encoding="utf-8")

    assert summary["verification"]["passed"] == 1
    assert summary["verification"]["failed"] == 0
    assert summary["verification"]["cache_hits"] == 1
    assert len(summary["verification"]["artifact_refs"]) == 1
    assert "Verification Passes: 1" in markdown
    assert "Verification Cache Skips: 1" in markdown


def test_report_builder_strips_unverified_findings_from_deliverable(tmp_path: Path) -> None:
    verified = make_finding("Confirmed IDOR", "https://example.com/api/users/7", "high", run_id="run-6")
    verified.validation_status = "confirmed"
    verified.evidence_refs = ["artifacts/run-6/verifications/idor.json"]

    unvalidated = make_finding("Speculative XSS", "https://example.com/search", "medium", run_id="run-6")

    report = ReportBuilder(tmp_path)
    artifacts = report.write_reports("run-6", [verified, unvalidated])

    markdown = artifacts.report_path.read_text(encoding="utf-8")

    assert "Confirmed IDOR" in markdown
    assert "Speculative XSS" not in markdown


def test_report_builder_strips_potential_exploit_findings(tmp_path: Path) -> None:
    exploited = make_finding("Confirmed SSRF", "https://example.com/fetch", "high", run_id="run-7")
    exploited.validation_status = "confirmed"
    exploited.exploit_status = "EXPLOITED"
    exploited.evidence_refs = ["artifacts/run-7/verifications/ssrf.json"]

    potential = make_finding("Possible Auth Bypass", "https://example.com/login", "high", run_id="run-7")
    potential.validation_status = "confirmed"
    potential.exploit_status = "POTENTIAL"
    potential.evidence_refs = ["artifacts/run-7/verifications/auth.json"]

    report = ReportBuilder(tmp_path)
    artifacts = report.write_reports("run-7", [exploited, potential])

    markdown = artifacts.report_path.read_text(encoding="utf-8")
    summary = json.loads(artifacts.summary_path.read_text(encoding="utf-8"))

    assert "Confirmed SSRF" in markdown
    assert "Possible Auth Bypass" not in markdown
    assert summary["exploit_status_counts"]["exploited"] == 1
    assert summary["exploit_status_counts"]["potential"] == 1

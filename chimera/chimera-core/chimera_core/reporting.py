import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from chimera_core.findings import Finding, SEVERITY_ORDER


@dataclass
class ReportArtifacts:
    findings_path: Path
    chains_path: Path
    chain_graphs_path: Path
    rejected_findings_path: Path
    report_path: Path
    summary_path: Path
    poc_bundles_dir: Path


class ReportBuilder:
    def __init__(self, artifacts_dir: Path) -> None:
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def write_reports(self, run_id: str, findings: List[Finding]) -> ReportArtifacts:
        findings_path = self.artifacts_dir / "findings.json"
        chains_path = self.artifacts_dir / "chains.json"
        chain_graphs_path = self.artifacts_dir / "chain_graphs.json"
        rejected_findings_path = self.artifacts_dir / "rejected_findings.json"
        report_path = self.artifacts_dir / "report.md"
        summary_path = self.artifacts_dir / "summary.json"
        poc_bundles_dir = self.artifacts_dir / "poc_bundles"
        poc_bundles_dir.mkdir(parents=True, exist_ok=True)

        findings_payload = [finding.to_dict() for finding in findings]
        findings_path.write_text(json.dumps(findings_payload, indent=2), encoding="utf-8")
        chain_findings = [finding for finding in findings if finding.finding_type == "EXPLOIT_CHAIN"]
        chain_payload = [finding.to_dict() for finding in chain_findings]
        chains_path.write_text(json.dumps(chain_payload, indent=2), encoding="utf-8")
        chain_graph_payload = [self._chain_graph_payload(finding) for finding in chain_findings]
        chain_graphs_path.write_text(json.dumps(chain_graph_payload, indent=2), encoding="utf-8")
        rejected_findings = [finding.to_dict() for finding in findings if finding.validation_status == "false_positive"]
        rejected_findings_path.write_text(json.dumps(rejected_findings, indent=2), encoding="utf-8")
        self._write_poc_bundles(chain_findings, poc_bundles_dir)

        summary = self._build_summary(run_id, findings)
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

        report_path.write_text(self._render_markdown(summary, findings), encoding="utf-8")

        return ReportArtifacts(
            findings_path=findings_path,
            chains_path=chains_path,
            chain_graphs_path=chain_graphs_path,
            rejected_findings_path=rejected_findings_path,
            report_path=report_path,
            summary_path=summary_path,
            poc_bundles_dir=poc_bundles_dir,
        )

    def _build_summary(self, run_id: str, findings: List[Finding]) -> Dict[str, object]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        validated = 0
        chained = 0
        exploit_chains = 0
        rejected = 0
        unvalidated = 0
        exploited = 0
        potential = 0
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
            if finding.validation_status:
                validated += 1
                if finding.validation_status == "false_positive":
                    rejected += 1
            else:
                unvalidated += 1
            if finding.chain_parent_ids:
                chained += 1
            if finding.finding_type == "EXPLOIT_CHAIN":
                exploit_chains += 1
            if (finding.exploit_status or "").upper() == "EXPLOITED":
                exploited += 1
            elif (finding.exploit_status or "").upper() == "POTENTIAL":
                potential += 1
        highest_impact_chain = next(
            (finding.to_chain_summary() for finding in findings if finding.finding_type == "EXPLOIT_CHAIN"),
            None,
        )
        verification = self._verification_summary()
        return {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "severity_counts": counts,
            "validated_findings": validated,
            "chained_findings": chained,
            "exploit_chains": exploit_chains,
            "rejected_findings": rejected,
            "unvalidated_findings": unvalidated,
            "highest_impact_chain": highest_impact_chain,
            "verification": verification,
            "exploit_status_counts": {"exploited": exploited, "potential": potential},
        }

    def _render_markdown(self, summary: Dict[str, object], findings: List[Finding]) -> str:
        deliverable_findings = self._deliverable_findings(findings)
        chain_findings = [finding for finding in deliverable_findings if finding.finding_type == "EXPLOIT_CHAIN"]
        rejected_findings = [finding for finding in findings if finding.validation_status == "false_positive"]
        lines = [
            "# Chimera Report",
            "",
            f"Run ID: {summary['run_id']}",
            f"Generated: {summary['generated_at']}",
            f"Total Findings: {summary['total_findings']}",
            "",
            "## Executive Summary",
            f"- Confirmed exploit chains: {summary['exploit_chains']}",
            f"- Confirmed/validated findings: {summary['validated_findings']}",
            f"- Unvalidated findings: {summary['unvalidated_findings']}",
            f"- Rejected findings: {summary['rejected_findings']}",
            f"- Verification passes: {summary['verification']['passed']}",
            f"- Verification failures: {summary['verification']['failed']}",
            f"- Verification cache skips: {summary['verification']['cache_hits']}",
            f"- Exploited findings: {summary['exploit_status_counts']['exploited']}",
            f"- Potential findings retained: {summary['exploit_status_counts']['potential']}",
            f"- Highest impact chain: {summary['highest_impact_chain'] or 'none'}",
            "",
            "## Severity Counts",
        ]
        for severity, count in summary["severity_counts"].items():
            lines.append(f"- {severity}: {count}")
        lines.append("")
        lines.append(f"Validated Findings: {summary['validated_findings']}")
        lines.append(f"Chained Findings: {summary['chained_findings']}")
        lines.append(f"Exploit Chains: {summary['exploit_chains']}")
        lines.append(f"Verification Passes: {summary['verification']['passed']}")
        lines.append(f"Verification Failures: {summary['verification']['failed']}")
        lines.append(f"Verification Cache Skips: {summary['verification']['cache_hits']}")
        lines.append(f"Exploited Findings: {summary['exploit_status_counts']['exploited']}")
        lines.append(f"Potential Findings Retained: {summary['exploit_status_counts']['potential']}")
        lines.append("")
        if chain_findings:
            lines.append("## Exploit Chains")
            for finding in chain_findings:
                lines.append(f"- {finding.to_chain_summary()}")
                lines.append("```text")
                lines.extend(self._chain_graph_lines(finding))
                lines.append("```")
            lines.append("")
        lines.append("## Findings")
        for finding in deliverable_findings:
            lines.extend(self._render_finding_section(finding))
        if rejected_findings:
            lines.append("")
            lines.append("## Rejected Findings")
            for finding in rejected_findings:
                lines.append(f"- {finding.title}: {finding.validation_reason or 'validator rejected'}")
        lines.append("")
        return "\n".join(lines)

    def _deliverable_findings(self, findings: List[Finding]) -> List[Finding]:
        deliverable: List[Finding] = []
        for finding in findings:
            status = (finding.validation_status or "").lower()
            exploit_status = (finding.exploit_status or "").upper()
            if status in {"false_positive", "needs_replay"}:
                continue
            if exploit_status and exploit_status not in {"EXPLOITED"}:
                continue
            if status in {"confirmed", "verified", "exploited"}:
                deliverable.append(finding)
                continue
            if finding.finding_type == "EXPLOIT_CHAIN":
                deliverable.append(finding)
                continue
            if finding.evidence_refs:
                deliverable.append(finding)
        return deliverable

    def _render_finding_section(self, finding: Finding) -> List[str]:
        badge = (finding.validation_status or "unvalidated").upper()
        lines = [
            f"### [{finding.severity.upper()}] {finding.title}",
            f"- Target: {finding.affected_target}",
            f"- Validation: {badge}",
        ]
        if finding.exploit_status:
            lines.append(f"- Exploit Status: {finding.exploit_status}")
        if finding.validation_reason:
            lines.append(f"- Reason: {finding.validation_reason}")
        if finding.confidence is not None:
            lines.append(f"- Confidence: {finding.confidence:.2f}")
        narrative = self._exploitability_narrative(finding)
        if narrative:
            lines.append(f"- Why exploitable: {narrative}")
        if finding.chain_parent_ids or finding.impact_path:
            lines.append(f"- Chain: {finding.to_chain_summary()}")
        if finding.replay_steps:
            lines.append("- Replay Steps:")
            for step in finding.replay_steps:
                lines.append(f"  - {step.get('action', 'step')}: {step.get('expected_diff', '')}")
        if finding.proof_artifacts:
            lines.append("- Proof Artifacts:")
            for artifact in finding.proof_artifacts:
                artifact_ref = artifact.get("ref") or artifact.get("request", {}).get("url") or artifact.get("type")
                lines.append(f"  - {artifact_ref}")
        return lines + [""]

    def _exploitability_narrative(self, finding: Finding) -> str:
        if finding.description and finding.repro_guidance:
            return f"{finding.description} Replay with: {finding.repro_guidance}"
        if finding.description:
            return finding.description
        if finding.validation_reason:
            return finding.validation_reason
        return ""

    def _chain_graph_payload(self, finding: Finding) -> Dict[str, object]:
        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "severity": finding.severity,
            "chain_parent_ids": list(finding.chain_parent_ids),
            "impact_path": list(finding.impact_path),
            "ascii": "\n".join(self._chain_graph_lines(finding)),
        }

    def _chain_graph_lines(self, finding: Finding) -> List[str]:
        lines: List[str] = []
        for index, step in enumerate(finding.impact_path or []):
            label = step.get("step") or "step"
            impact = step.get("impact") or "impact"
            if index == 0:
                lines.append(f"[LOW] {label}")
            else:
                prefix = "    " * index + "└─► "
                lines.append(f"{prefix}[{finding.severity.upper()}] {label} ({impact})")
        if not lines:
            lines.append(f"[{finding.severity.upper()}] {finding.title}")
        if finding.confidence is not None:
            lines.append(f"IMPACT: {finding.impact_path[-1].get('impact') if finding.impact_path else finding.title}")
            lines.append(f"CONFIDENCE: {finding.confidence:.2f}")
            lines.append(f"REPLAY: {len(finding.replay_steps)} steps, all artifacts stored")
        return lines

    def _verification_summary(self) -> Dict[str, object]:
        events_path = self.artifacts_dir / "events.jsonl"
        summary = {
            "passed": 0,
            "failed": 0,
            "cache_hits": 0,
            "artifact_refs": [],
        }
        if not events_path.exists():
            return summary
        for raw_line in events_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_type = event.get("event_type")
            payload = event.get("payload") or {}
            if event_type == "verification_passed":
                summary["passed"] += 1
            elif event_type == "verification_failed":
                summary["failed"] += 1
            elif event_type == "verification_skipped" and payload.get("reason") == "cache_hit":
                summary["cache_hits"] += 1
            artifact_ref = payload.get("verification_result_ref")
            if artifact_ref:
                summary["artifact_refs"].append(artifact_ref)
        return summary

    def _write_poc_bundles(self, findings: List[Finding], bundles_dir: Path) -> None:
        for finding in findings:
            bundle_path = bundles_dir / f"{finding.finding_id[:24]}.json"
            payload = {
                "finding": finding.to_dict(),
                "chain_graph": self._chain_graph_payload(finding),
                "replay_manifest": list(finding.replay_steps),
                "proof_artifacts": list(finding.proof_artifacts),
            }
            bundle_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

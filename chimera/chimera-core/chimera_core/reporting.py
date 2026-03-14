import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from chimera_core.findings import Finding, SEVERITY_ORDER


@dataclass
class ReportArtifacts:
    findings_path: Path
    report_path: Path
    summary_path: Path


class ReportBuilder:
    def __init__(self, artifacts_dir: Path) -> None:
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    def write_reports(self, run_id: str, findings: List[Finding]) -> ReportArtifacts:
        findings_path = self.artifacts_dir / "findings.json"
        report_path = self.artifacts_dir / "report.md"
        summary_path = self.artifacts_dir / "summary.json"

        findings_payload = [finding.to_dict() for finding in findings]
        findings_path.write_text(json.dumps(findings_payload, indent=2), encoding="utf-8")

        summary = self._build_summary(run_id, findings)
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

        report_path.write_text(self._render_markdown(summary, findings), encoding="utf-8")

        return ReportArtifacts(
            findings_path=findings_path,
            report_path=report_path,
            summary_path=summary_path,
        )

    def _build_summary(self, run_id: str, findings: List[Finding]) -> Dict[str, object]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "severity_counts": counts,
        }

    def _render_markdown(self, summary: Dict[str, object], findings: List[Finding]) -> str:
        lines = [
            "# Chimera Report",
            "",
            f"Run ID: {summary['run_id']}",
            f"Generated: {summary['generated_at']}",
            f"Total Findings: {summary['total_findings']}",
            "",
            "## Severity Counts",
        ]
        for severity, count in summary["severity_counts"].items():
            lines.append(f"- {severity}: {count}")
        lines.append("")
        lines.append("## Findings")
        for finding in findings:
            lines.append(f"- [{finding.severity}] {finding.title} ({finding.affected_target})")
        lines.append("")
        return "\n".join(lines)

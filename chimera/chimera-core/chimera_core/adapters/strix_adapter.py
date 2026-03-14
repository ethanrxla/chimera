import csv
import json
import sys
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Optional

from chimera_core.adapters.base import AdapterBase
from chimera_core.findings import Finding
from chimera_core.runtime import Runtime
from chimera_core.tool_runner import ToolRunner


class StrixAdapter(AdapterBase):
    id = "strix"
    capabilities = ["web-testing", "recon"]

    def __init__(
        self,
        runtime: Runtime,
        options: Optional[Dict[str, object]] = None,
        rate_limits: Optional[Dict[str, int]] = None,
        run_id: str = "mock_run_id",
        task_id: str = "mock_task_id",
        scope_hash: str = "mock_scope_hash",
        artifacts_root: Optional[Path] = None,
    ) -> None:
        self.runtime = runtime
        self.scope_graph = runtime.scope_graph
        self.scope_policy = runtime.scope_policy
        self.options = options or {}
        self.rate_limits = rate_limits or {}
        self.run_id = run_id
        self.task_id = task_id
        self.scope_hash = scope_hash
        self.artifacts_root = artifacts_root or runtime.artifacts_root
        self.strix_root = Path(__file__).resolve().parents[3] / "tools" / "strix"
        self.strix_runs_root = self.strix_root / "strix_runs"
        self.tool_runner = ToolRunner(runtime)

    def validate_targets(self, targets: List[str]) -> None:
        for target in targets:
            if not self.scope_graph.is_in_scope(target):
                raise ValueError(f"Target out of scope: {target}")

    def build_command(self, targets: List[str]) -> List[str]:
        self.validate_targets(targets)

        command = self.tool_runner.base_command(self.id, [sys.executable, "-m", "strix.interface.main", "-n"])
        mode = self.options.get("scan_mode", "standard")
        command.extend(["--scan-mode", str(mode)])

        run_name = f"chimera-{self.run_id}-{self.task_id}"
        command.extend(["--run-name", run_name])

        rate = self.rate_limits.get("requests_per_second", self.scope_policy.max_rps)
        instruction = self.options.get("instruction")
        if instruction:
            instruction = f"{instruction}\n\nRespect rate limit: {rate} rps."
        else:
            instruction = f"Respect rate limit: {rate} rps."
        command.extend(["--instruction", instruction])

        for target in targets:
            command.extend(["--target", target])
        return command

    def _artifact_path(self, filename: str) -> Optional[Path]:
        if not self.artifacts_root:
            return None
        return self.artifacts_root / self.run_id / self.id / self.task_id / filename

    def _save_raw_output(self, raw_output: str) -> Optional[str]:
        output_path = self._artifact_path("raw_output.json")
        if not output_path:
            return None
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(raw_output, encoding="utf-8")
        return str(output_path)

    def _emit_event(self, event_type: str, payload: Dict[str, object]) -> None:
        if not self.runtime or not self.runtime.event_store:
            return
        self.runtime.event_store.emit({"event_type": event_type, "payload": payload})

    def _collect_strix_reports(self, run_name: str) -> List[Dict[str, str]]:
        report_dir = self.strix_runs_root / run_name
        if not report_dir.exists():
            return []
        dest_root = self._artifact_path("strix_reports")
        if not dest_root:
            return []
        dest_root.mkdir(parents=True, exist_ok=True)
        artifacts: List[Dict[str, str]] = []

        for filename in ("penetration_test_report.md", "vulnerabilities.csv"):
            src = report_dir / filename
            if not src.exists():
                continue
            dest = dest_root / filename
            dest.write_bytes(src.read_bytes())
            artifacts.append({"path": str(dest), "artifact_type": "strix_report", "tool": self.id})

        vuln_dir = report_dir / "vulnerabilities"
        if vuln_dir.exists():
            dest_vuln_dir = dest_root / "vulnerabilities"
            dest_vuln_dir.mkdir(parents=True, exist_ok=True)
            for src in vuln_dir.glob("*.md"):
                dest = dest_vuln_dir / src.name
                dest.write_bytes(src.read_bytes())
                artifacts.append({"path": str(dest), "artifact_type": "strix_report", "tool": self.id})

        return artifacts

    def _parse_strix_findings(self, run_name: str, targets: List[str]) -> List[Dict[str, object]]:
        report_dir = self.strix_runs_root / run_name
        csv_path = report_dir / "vulnerabilities.csv"
        if not csv_path.exists():
            return []

        entries: List[Dict[str, object]] = []
        with csv_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                title = row.get("title") or "Strix Finding"
                severity = (row.get("severity") or "low").lower()
                report_file = row.get("file") or ""
                evidence_refs = []
                description = ""
                if report_file:
                    report_path = report_dir / report_file
                    if report_path.exists():
                        description = report_path.read_text(encoding="utf-8")
                        evidence_refs.append(str(report_path))
                entries.append(
                    {
                        "title": title,
                        "description": description,
                        "severity": severity,
                        "url": targets[0] if targets else "unknown",
                        "evidence_refs": evidence_refs,
                    }
                )
        return entries

    def run(self, targets: List[str]) -> dict:
        live = bool(self.options.get("live", False))
        fixture_path = self.options.get("fixture_path")
        raw_output_override = self.options.get("raw_output_override")

        self.validate_targets(targets)
        self._emit_event("task_started", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})

        raw_output = None
        command = None
        if live:
            command = self.build_command(targets)
            timeout = self.options.get("timeout_s")
            run_name = f"chimera-{self.run_id}-{self.task_id}"
            result = self.tool_runner.run(
                self.id,
                command,
                task_id=self.task_id,
                timeout_s=timeout,
                cwd=self.strix_root,
            )
            parsed = self._parse_strix_findings(run_name, targets)
            raw_output = json.dumps({"findings": parsed})
        else:
            self._emit_event("cmd_started", {"run_id": self.run_id, "task_id": self.task_id, "mode": "fixture"})
            if raw_output_override is not None:
                raw_output = raw_output_override
            elif fixture_path:
                raw_output = Path(fixture_path).read_text(encoding="utf-8")
            else:
                raw_output = json.dumps({"findings": []})

        artifact_path = self._save_raw_output(raw_output)
        artifacts = []
        if artifact_path:
            artifacts.append({"path": artifact_path, "artifact_type": "raw_output", "tool": self.id})
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": artifact_path, "tool": self.id},
            )

        findings = self.normalize(raw_output)
        if live:
            artifacts.extend(self._collect_strix_reports(f"chimera-{self.run_id}-{self.task_id}"))
        findings_path = self._artifact_path("findings.json")
        if findings_path:
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_payload = [finding.to_dict() for finding in findings]
            findings_path.write_text(json.dumps(findings_payload, indent=2), encoding="utf-8")
            artifacts.append({"path": str(findings_path), "artifact_type": "findings", "tool": self.id})
            self._emit_event(
                "artifact_saved",
                {"run_id": self.run_id, "task_id": self.task_id, "path": str(findings_path), "tool": self.id},
            )

        if not live:
            self._emit_event("cmd_finished", {"run_id": self.run_id, "task_id": self.task_id, "returncode": 0})

        self._emit_event("task_finished", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})

        return {
            "events": [{"level": "info", "message": f"{self.id} completed", "targets": targets}],
            "artifacts": artifacts,
            "raw_output_refs": [raw_output],
            "findings": findings,
            "command": command,
        }

    def normalize(self, raw_output: str) -> List[Finding]:
        data = json.loads(raw_output)
        findings: List[Finding] = []
        for entry in data.get("findings", []):
            title = entry.get("title", "Strix Finding")
            description = entry.get("description", "")
            severity = entry.get("severity", "low")
            url = entry.get("url", "unknown")
            evidence_refs = entry.get("evidence_refs") or []
            finding_id = f"{self.id}:{title}:{url}"

            findings.append(
                Finding(
                    finding_id=finding_id,
                    severity=severity,
                    title=title,
                    description=description,
                    affected_target=url,
                    evidence_refs=evidence_refs,
                    tool_source=self.id,
                    tool_version="strix-1.0.0",
                    run_id=self.run_id,
                    scope_hash=self.scope_hash,
                    finding_type=_infer_finding_type(title, description),
                    asset={
                        "host": urlparse(url).hostname or url,
                        "endpoint": urlparse(url).path or "/",
                        "method": entry.get("method"),
                        "parameter": entry.get("parameter"),
                    },
                    confidence=_confidence_from_severity(severity),
                )
            )
        return findings


def _infer_finding_type(title: str, description: str) -> str:
    text = f"{title} {description}".lower()
    if "xss" in text:
        return "XSS"
    if "idor" in text or "bola" in text:
        return "IDOR"
    if "csrf" in text:
        return "CSRF"
    if "auth" in text:
        return "BROKEN_AUTH"
    return "WEB_FINDING"


def _confidence_from_severity(severity: str) -> float:
    return {
        "critical": 0.95,
        "high": 0.9,
        "medium": 0.75,
        "low": 0.55,
    }.get(str(severity).lower(), 0.5)

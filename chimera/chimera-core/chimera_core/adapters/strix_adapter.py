import csv
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Optional

from chimera_core.adapters.base import AdapterBase
from chimera_core.findings import Finding
from chimera_core.runtime import Runtime
from chimera_core.tool_runner import ToolRunner


def _command_return_code(result: object) -> int:
    return int(getattr(result, "returncode", getattr(result, "exit_code", 0)))


def _normalize_instruction_text(instruction: str) -> str:
    return re.sub(r"\s+", " ", instruction).strip()


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

        strix_bin = os.environ.get("STRIX_BIN") or str(Path(sys.executable).parent / "strix")
        command = self.tool_runner.base_command(self.id, [strix_bin, "-n"])
        mode = self.options.get("scan_mode", "standard")
        command.extend(["--scan-mode", str(mode)])

        rate = self.rate_limits.get("requests_per_second", self.scope_policy.max_rps)
        instruction = self.options.get("instruction")
        if instruction:
            instruction = _normalize_instruction_text(
                f"{instruction} Respect rate limit: {rate} rps."
            )
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

    def _existing_strix_run_dirs(self) -> set[Path]:
        if not self.strix_runs_root.exists():
            return set()
        return {path for path in self.strix_runs_root.iterdir() if path.is_dir()}

    def _resolve_run_dir(self, before_dirs: set[Path]) -> Optional[Path]:
        after_dirs = self._existing_strix_run_dirs()
        new_dirs = [path for path in after_dirs - before_dirs if path.is_dir()]
        if len(new_dirs) == 1:
            return new_dirs[0]
        if new_dirs:
            return max(new_dirs, key=lambda path: path.stat().st_mtime)
        if after_dirs:
            return max(after_dirs, key=lambda path: path.stat().st_mtime)
        return None

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
        entries = _deduplicate_findings(entries)
        entries = _check_contradictions(entries, report_dir)
        return entries

    def _cleanup_sandbox_container(self, run_name: str) -> None:
        """Stop and remove the strix Docker sandbox container for this run."""
        import subprocess
        container_name = f"strix-scan-{run_name}"
        try:
            subprocess.run(["docker", "stop", "--time", "5", container_name], capture_output=True, timeout=15)
            subprocess.run(["docker", "rm", "--force", container_name], capture_output=True, timeout=10)
        except Exception:
            pass

    def run(self, targets: List[str]) -> dict:
        live = bool(self.options.get("live", False))
        fixture_path = self.options.get("fixture_path")
        raw_output_override = self.options.get("raw_output_override")
        prompt_artifact = self._save_prompt_artifact(targets)

        self.validate_targets(targets)
        self._emit_event("task_started", {"run_id": self.run_id, "task_id": self.task_id, "tool": self.id})
        self._emit_event(
            "llm_started",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": "strix",
                "stage": "agentic_scan",
                "prompt_artifact": prompt_artifact,
                "response_artifact": None,
                "usage": {},
            },
        )

        raw_output = None
        command = None
        if live:
            before_dirs = self._existing_strix_run_dirs()
            command = self.build_command(targets)
            timeout = self.options.get("timeout_s")
            max_attempts = 3
            retry_delay_s = 8
            last_error: Optional[str] = None
            result = None
            for attempt in range(1, max_attempts + 1):
                try:
                    result = self.tool_runner.run(
                        self.id,
                        command,
                        task_id=self.task_id,
                        timeout_s=timeout,
                        cwd=self.strix_root,
                    )
                finally:
                    resolved_run_dir = self._resolve_run_dir(before_dirs)
                    if resolved_run_dir is not None:
                        self._cleanup_sandbox_container(resolved_run_dir.name)
                return_code = _command_return_code(result)
                if return_code == 0:
                    break
                last_error = _pick_error_message(result.stdout, result.stderr, self.id, return_code)
                if attempt < max_attempts and _is_transient_sandbox_error(last_error):
                    self._emit_event(
                        "task_retry",
                        {
                            "run_id": self.run_id,
                            "task_id": self.task_id,
                            "attempt": attempt,
                            "reason": last_error[:200],
                        },
                    )
                    time.sleep(retry_delay_s)
                    before_dirs = self._existing_strix_run_dirs()
                else:
                    break
            run_dir = self._resolve_run_dir(before_dirs)
            if _command_return_code(result) != 0:
                if run_dir is not None and _strix_run_completed(run_dir):
                    self._emit_event("task_warning", {
                        "run_id": self.run_id,
                        "task_id": self.task_id,
                        "message": (
                            f"Strix exited {_command_return_code(result)} but produced a "
                            f"completed run at {run_dir.name}; treating as partial_success"
                        ),
                        "return_code": _command_return_code(result),
                        "outcome": "partial_success",
                    })
                else:
                    raise RuntimeError(last_error)
            parsed = self._parse_strix_findings(run_dir.name, targets) if run_dir is not None else []
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
        self._emit_event(
            "llm_finished",
            {
                "run_id": self.run_id,
                "task_id": self.task_id,
                "model": "strix",
                "stage": "agentic_scan",
                "prompt_artifact": prompt_artifact,
                "response_artifact": artifact_path,
                "usage": {},
            },
        )

        findings = self.normalize(raw_output)
        if live:
            run_dir = self._resolve_run_dir(before_dirs)
            if run_dir is not None:
                artifacts.extend(self._collect_strix_reports(run_dir.name))
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
                    confidence=float(entry.get("confidence_override") or _confidence_from_severity(severity)),
                )
            )
        return findings

    def _save_prompt_artifact(self, targets: List[str]) -> Optional[str]:
        prompt_path = self._artifact_path("prompt.json")
        if not prompt_path:
            return None
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "targets": targets,
            "options": self.options,
        }
        prompt_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self._emit_event(
            "artifact_saved",
            {"run_id": self.run_id, "task_id": self.task_id, "path": str(prompt_path), "tool": self.id},
        )
        return str(prompt_path)


def _strix_run_completed(run_dir: Path) -> bool:
    """Return True if the Strix run directory contains completion markers.

    Checks (in order):
    1. events.jsonl contains a ``run.completed`` event
    2. vulnerabilities.csv exists with at least one data row (beyond the header)
    """
    events_path = run_dir / "events.jsonl"
    if events_path.exists():
        try:
            for line in events_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                e = json.loads(line)
                if e.get("event_type") == "run.completed":
                    return True
        except Exception:
            pass
    csv_path = run_dir / "vulnerabilities.csv"
    if csv_path.exists():
        lines = [ln for ln in csv_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        return len(lines) > 1
    return False


import re as _re

_DEDUP_STOP = frozenset({
    "in", "on", "the", "a", "an", "at", "of", "via", "for", "to", "by", "is", "are",
})


def _title_words(title: str) -> frozenset:
    return frozenset(
        w.lower() for w in _re.split(r"\W+", title)
        if w and w.lower() not in _DEDUP_STOP
    )


def _deduplicate_findings(entries: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Merge findings whose titles share >50% Jaccard word overlap at same severity+url."""
    result: List[Dict[str, object]] = []
    for entry in entries:
        ew = _title_words(str(entry.get("title", "")))
        merged = False
        for existing in result:
            xw = _title_words(str(existing.get("title", "")))
            union = ew | xw
            if (
                existing.get("severity") == entry.get("severity")
                and existing.get("url") == entry.get("url")
                and union
                and len(ew & xw) / len(union) > 0.5
            ):
                # Keep the entry with the richer description
                if len(str(entry.get("description", ""))) > len(str(existing.get("description", ""))):
                    existing.update({k: v for k, v in entry.items() if k != "evidence_refs"})
                existing["evidence_refs"] = list(
                    {*existing.get("evidence_refs", []), *entry.get("evidence_refs", [])}
                )
                merged = True
                break
        if not merged:
            result.append(dict(entry))
    return result


_CONTRADICTION_PATTERNS: Dict[str, List[str]] = {
    "clickjack": [
        "robust against clickjacking",
        "no clickjacking",
        "protected against clickjacking",
    ],
    "xss": [
        "no xss",
        "protected against xss",
        "no cross-site scripting",
    ],
    "csrf": ["no csrf", "protected against csrf"],
    "injection": ["no sql injection", "no injection"],
}


def _check_contradictions(
    entries: List[Dict[str, object]], report_dir: Path
) -> List[Dict[str, object]]:
    """Downgrade confidence when the Strix summary report contradicts a finding."""
    report_path = report_dir / "penetration_test_report.md"
    if not report_path.exists():
        return entries
    report_lower = report_path.read_text(encoding="utf-8").lower()
    for entry in entries:
        combined = f"{entry.get('title', '')} {entry.get('description', '')}".lower()
        for vuln_key, phrases in _CONTRADICTION_PATTERNS.items():
            if vuln_key in combined:
                for phrase in phrases:
                    if phrase in report_lower:
                        entry["confidence_override"] = 0.3
                        entry["contradiction_note"] = (
                            f"Summary says '{phrase}' but finding exists; confidence downgraded"
                        )
                        break
    return entries


_TRANSIENT_SANDBOX_ERRORS = frozenset({
    "container initialization timed out",
    "tool server failed to start",
    "please try again",
})

_FATAL_KEYWORDS = frozenset({"failed", "error", "timed out", "timeout", "exception", "traceback", "fatal"})


def _is_transient_sandbox_error(message: str) -> bool:
    """Return True if the error is a recoverable Docker sandbox startup failure."""
    lower = message.lower()
    return any(phrase in lower for phrase in _TRANSIENT_SANDBOX_ERRORS)


def _pick_error_message(stdout: str, stderr: str, tool_id: str, return_code: int) -> str:
    """Return the most informative error string from stdout/stderr on non-zero exit.

    Strix emits Python DeprecationWarning / UserWarning noise to stderr even on
    clean runs.  The actual fatal message (e.g. SandboxInitializationError) goes to
    stdout.  Prefer stdout when it contains a fatal keyword; fall back to stderr if
    stdout is empty or looks like pure noise; fall back to a generic code message last.
    """
    stdout = (stdout or "").strip()
    stderr = (stderr or "").strip()

    stdout_lower = stdout.lower()
    if stdout and any(kw in stdout_lower for kw in _FATAL_KEYWORDS):
        return stdout

    if stderr:
        return stderr

    if stdout:
        return stdout

    return f"{tool_id} exited with code {return_code}"


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

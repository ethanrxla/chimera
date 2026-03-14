from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from chimera_core.event_store import EventStore
from chimera_core.findings import Finding
from chimera_core.reporting import ReportArtifacts, ReportBuilder
from chimera_core.sinks.base import EventSink


class LocalSink(EventSink):
    def __init__(self, artifacts_dir: Path, run_id: str) -> None:
        self.artifacts_dir = artifacts_dir
        self.run_id = run_id
        self.event_store = EventStore(artifacts_dir / "events.jsonl")
        self.report_builder = ReportBuilder(artifacts_dir)
        self._findings: List[Finding] = []
        self.report_artifacts: Optional[ReportArtifacts] = None
        self._reports_written = False

    def emit_event(self, event: dict) -> None:
        self.event_store.emit(event)

    def emit_finding(self, finding: Finding) -> None:
        self._findings.append(finding)

    def flush(self) -> None:
        if self._reports_written:
            return
        self.report_artifacts = self.report_builder.write_reports(self.run_id, self._findings)
        self._reports_written = True

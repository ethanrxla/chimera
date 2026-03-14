from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any, Optional

class JobStatus(Enum):
    CREATED = "created"
    VALIDATING_SCOPE = "validating_scope"
    PLANNING_TESTS = "planning_tests"
    RUNNING_TOOLS = "running_tools"
    ANALYZING_RESULTS = "analyzing_results"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class Job:
    job_id: str
    scope_manifest: Dict[str, Any]
    scope_hash: str
    mode: str
    scope_raw: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"  # Placeholder for user ID
    status: JobStatus = JobStatus.CREATED
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    targets: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self):
        return {
            "job_id": self.job_id,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "scope_manifest": self.scope_manifest,
            "scope_hash": self.scope_hash,
            "mode": self.mode,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "targets": self.targets,
            "events": self.events,
            "findings": self.findings,
            "artifacts": self.artifacts,
        }

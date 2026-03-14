from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import List, Optional

@dataclass
class Finding:
    finding_id: str  # stable hash
    severity: str    # info/low/med/high/critical
    title: str
    description: str
    affected_target: str  # host/path/method
    tool_source: str
    tool_version: str
    run_id: str
    scope_hash: str
    evidence_refs: List[str] = field(default_factory=list) # file pointers, screenshots, sanitized excerpts
    repro_guidance: Optional[str] = None # careful: keep non-exploitative
    timestamps: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: str = "new" # new/triaged/duplicate/invalid

    def to_dict(self):
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "affected_target": self.affected_target,
            "evidence_refs": self.evidence_refs,
            "tool_source": self.tool_source,
            "tool_version": self.tool_version,
            "repro_guidance": self.repro_guidance,
            "timestamps": self.timestamps.isoformat(),
            "run_id": self.run_id,
            "scope_hash": self.scope_hash,
            "status": self.status,
        }

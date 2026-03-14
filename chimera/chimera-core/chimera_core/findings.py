import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def stable_finding_id(title: str, affected_target: str, tool_source: str, signature: Optional[str] = None) -> str:
    base = f"{title}|{affected_target}|{tool_source}"
    if signature:
        base = f"{base}|{signature}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


@dataclass
class Finding:
    finding_id: str
    severity: str
    title: str
    description: str
    affected_target: str
    tool_source: str
    tool_version: str
    run_id: str
    scope_hash: str
    evidence_refs: List[str] = field(default_factory=list)
    repro_guidance: Optional[str] = None
    timestamps: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "new"

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

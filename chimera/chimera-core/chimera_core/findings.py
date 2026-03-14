import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


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
    finding_type: Optional[str] = None
    asset: Optional[Dict[str, Any]] = None
    auth_context: Optional[Dict[str, Any]] = None
    validation_status: Optional[str] = None
    validation_reason: Optional[str] = None
    confidence: Optional[float] = None
    prerequisites: List[str] = field(default_factory=list)
    chain_parent_ids: List[str] = field(default_factory=list)
    impact_path: List[Dict[str, Any]] = field(default_factory=list)
    proof_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    sink: Optional[str] = None
    replay_steps: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self):
        payload = {
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
        if self.finding_type:
            payload["finding_type"] = self.finding_type
        if self.asset:
            payload["asset"] = self.asset
        if self.auth_context:
            payload["auth_context"] = self.auth_context
        if self.validation_status:
            payload["validation_status"] = self.validation_status
        if self.validation_reason:
            payload["validation_reason"] = self.validation_reason
        if self.confidence is not None:
            payload["confidence"] = self.confidence
        if self.prerequisites:
            payload["prerequisites"] = self.prerequisites
        if self.chain_parent_ids:
            payload["chain_parent_ids"] = self.chain_parent_ids
        if self.impact_path:
            payload["impact_path"] = self.impact_path
        if self.proof_artifacts:
            payload["proof_artifacts"] = self.proof_artifacts
        if self.sink:
            payload["sink"] = self.sink
        if self.replay_steps:
            payload["replay_steps"] = self.replay_steps
        return payload

    def to_chain_summary(self) -> str:
        finding_label = self.finding_type or self.title
        asset_ref = self._asset_reference()
        confidence = self.confidence if self.confidence is not None else 0.5
        if self.impact_path:
            terminal_impact = str(self.impact_path[-1].get("impact") or "reported impact")
        elif self.chain_parent_ids:
            terminal_impact = "follow-on impact"
        else:
            terminal_impact = "standalone impact"
        return f"{finding_label} on {asset_ref} [confidence: {confidence:.2f}] -> enables {terminal_impact}"

    def _asset_reference(self) -> str:
        if not self.asset:
            return self.affected_target
        endpoint = self.asset.get("endpoint")
        host = self.asset.get("host")
        method = self.asset.get("method")
        if endpoint and method:
            return f"{method} {endpoint}"
        if endpoint:
            return str(endpoint)
        if host:
            return str(host)
        parameter = self.asset.get("parameter")
        if parameter:
            return str(parameter)
        return self.affected_target

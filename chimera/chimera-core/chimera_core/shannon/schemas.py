from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


ValidationStatus = Literal["verified", "rejected", "downgraded", "duplicate"]
ExploitClassification = Literal["EXPLOITED", "POTENTIAL", "FALSE_POSITIVE"]
RiskClass = Literal["passive", "low_impact", "state_changing", "exploit_like"]


@dataclass(frozen=True)
class TargetSpec:
    method: str
    endpoint: str
    params: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    body: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuthContext:
    authenticated: bool
    role: str
    session_fixed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AgentCandidate:
    candidate_id: str
    claim_type: str
    title: str
    target: TargetSpec
    evidence_refs: list[str] = field(default_factory=list)
    auth_context: AuthContext | None = None
    success_condition: str | None = None
    verifier_hint: str | None = None
    target_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["target"] = self.target.to_dict()
        if self.auth_context is not None:
            payload["auth_context"] = self.auth_context.to_dict()
        return payload


@dataclass(frozen=True)
class CandidateFinding:
    candidate_id: str
    source: str
    title: str
    claim_type: str
    severity_claimed: str
    endpoint: str | None = None
    target: str | None = None
    params: list[str] = field(default_factory=list)
    narrative: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttackContract:
    contract_id: str
    hypothesis_id: str
    claim_type: str
    target: str
    allowed_actions: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    success_signals: list[str] = field(default_factory=list)
    failure_signals: list[str] = field(default_factory=list)
    budget: dict[str, int] = field(default_factory=dict)
    risk_class: RiskClass = "low_impact"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProbeInput:
    method: str
    url: str
    headers: dict[str, str]
    query: dict[str, str]
    body: str | None
    follow_redirects: bool
    timeout_s: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SuccessCondition:
    type: str
    rules: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VerificationCheck:
    check_id: str
    probe_type: str
    description: str
    probe_input: ProbeInput
    success_condition: SuccessCondition

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["probe_input"] = self.probe_input.to_dict()
        payload["success_condition"] = self.success_condition.to_dict()
        return payload


@dataclass(frozen=True)
class VerificationPlan:
    verification_id: str
    candidate_id: str
    target: str
    claim_type: str
    checks: list[VerificationCheck]
    required_artifact_kinds: list[str]
    planner_notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "candidate_id": self.candidate_id,
            "target": self.target,
            "claim_type": self.claim_type,
            "checks": [check.to_dict() for check in self.checks],
            "required_artifact_kinds": list(self.required_artifact_kinds),
            "planner_notes": self.planner_notes,
        }


@dataclass(frozen=True)
class ValidatorDecision:
    status: ValidationStatus
    final_claim_type: str
    severity: str
    rationale: str
    duplicate_of: str | None
    evidence_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ExploitAttempt:
    attempt_number: int
    payload_used: str
    request_ref: str
    response_ref: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat()
        return payload


@dataclass(frozen=True)
class ExploitResult:
    verification_id: str
    candidate_id: str
    claim_type: str
    classification: ExploitClassification
    attempts: list[ExploitAttempt] = field(default_factory=list)
    final_evidence_refs: list[str] = field(default_factory=list)
    session_refs: list[str] = field(default_factory=list)
    notes: str | None = None
    exploited_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "candidate_id": self.candidate_id,
            "claim_type": self.claim_type,
            "classification": self.classification,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "final_evidence_refs": list(self.final_evidence_refs),
            "session_refs": list(self.session_refs),
            "notes": self.notes,
            "exploited_at": self.exploited_at.isoformat() if self.exploited_at else None,
        }

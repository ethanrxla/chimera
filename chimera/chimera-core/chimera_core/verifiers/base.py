from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


VerifierOutcome = Literal["passed", "failed", "inconclusive"]


@dataclass(frozen=True)
class VerificationResult:
    verification_id: str
    check_id: str
    claim_type: str
    outcome: VerifierOutcome
    rationale: str
    evidence_refs: list[str] = field(default_factory=list)
    extracted_targets: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "check_id": self.check_id,
            "claim_type": self.claim_type,
            "outcome": self.outcome,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
            "extracted_targets": list(self.extracted_targets),
            "metadata": dict(self.metadata),
        }


class BaseVerifier:
    claim_type: str

    def verify(self, *, run_id: str, plan, hexstrike_result) -> VerificationResult:
        raise NotImplementedError

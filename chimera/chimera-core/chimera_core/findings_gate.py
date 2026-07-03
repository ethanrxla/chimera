from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from chimera_core.artifacts import ArtifactWriter
from chimera_core.findings import stable_finding_id


@dataclass(frozen=True)
class PromotionDecision:
    accepted: bool
    status: str
    reason: str
    finding: dict[str, Any] | None


def promote_validated_finding(
    *,
    run_id: str,
    candidate,
    validator_decision,
    verification_results,
    artifact_writer: ArtifactWriter,
    event_store: EventStore,
) -> PromotionDecision:
    passed = [result for result in verification_results if getattr(result, "outcome", None) == "passed"]
    passed_evidence_refs = {
        ref
        for result in passed
        for ref in list(getattr(result, "evidence_refs", []) or [])
        if isinstance(ref, str) and ref
    }
    requested_evidence_refs = [
        ref for ref in list(getattr(validator_decision, "evidence_refs", []) or []) if isinstance(ref, str) and ref
    ]
    if validator_decision.status == "duplicate":
        reason = f"Duplicate of {validator_decision.duplicate_of or 'existing finding'}."
        event_store.emit(
            {
                "event_type": "finding_rejected",
                "payload": {
                    "run_id": run_id,
                    "candidate_id": candidate.candidate_id,
                    "reason": reason,
                    "duplicate_of": validator_decision.duplicate_of,
                },
            }
        )
        return PromotionDecision(False, "duplicate", reason, None)
    if validator_decision.status not in {"verified", "downgraded"}:
        event_store.emit(
            {
                "event_type": "finding_rejected",
                "payload": {
                    "run_id": run_id,
                    "candidate_id": candidate.candidate_id,
                    "reason": validator_decision.rationale,
                },
            }
        )
        return PromotionDecision(False, "rejected", validator_decision.rationale, None)
    if not passed:
        reason = "No passed verifier result."
        event_store.emit({"event_type": "finding_rejected", "payload": {"run_id": run_id, "candidate_id": candidate.candidate_id, "reason": reason}})
        return PromotionDecision(False, "rejected", reason, None)
    if not requested_evidence_refs:
        reason = "Verified findings require non-empty evidence_refs."
        event_store.emit({"event_type": "finding_rejected", "payload": {"run_id": run_id, "candidate_id": candidate.candidate_id, "reason": reason}})
        return PromotionDecision(False, "rejected", reason, None)
    invented = [ref for ref in requested_evidence_refs if ref not in passed_evidence_refs]
    if invented:
        reason = f"Validator may not invent evidence_refs: {invented}"
        event_store.emit({"event_type": "finding_rejected", "payload": {"run_id": run_id, "candidate_id": candidate.candidate_id, "reason": reason}})
        return PromotionDecision(False, "rejected", reason, None)
    missing = [ref for ref in requested_evidence_refs if not (artifact_writer.root / run_id / ref).exists()]
    if missing:
        reason = f"Missing evidence artifacts: {missing}"
        event_store.emit({"event_type": "finding_rejected", "payload": {"run_id": run_id, "candidate_id": candidate.candidate_id, "reason": reason}})
        return PromotionDecision(False, "rejected", reason, None)

    target = candidate.target or "unknown"
    affected_target = candidate.endpoint if str(candidate.endpoint or "").startswith(("http://", "https://")) else (candidate.target or "unknown")
    if candidate.endpoint and not str(candidate.endpoint).startswith(("http://", "https://")) and str(candidate.target or "").startswith(("http://", "https://")):
        affected_target = f"{str(candidate.target).rstrip('/')}/{str(candidate.endpoint).lstrip('/')}"
    finding = {
        "finding_id": stable_finding_id(candidate.title, target, candidate.source, candidate.candidate_id),
        "run_id": run_id,
        "source": candidate.source,
        "status": "downgraded" if validator_decision.status == "downgraded" else "verified",
        "title": candidate.title,
        "claim_type": validator_decision.final_claim_type,
        "severity": validator_decision.severity,
        "target": candidate.target,
        "affected_target": affected_target,
        "endpoint": candidate.endpoint,
        "evidence_refs": list(requested_evidence_refs),
        "verification_refs": [result.verification_id for result in passed],
        "duplicate_of": validator_decision.duplicate_of,
        "rationale": validator_decision.rationale,
        "metadata": dict(getattr(validator_decision, "metadata", {}) or {}),
    }
    event_type = "finding_downgraded" if validator_decision.status == "downgraded" else "finding_promoted"
    event_store.emit(
        {
            "event_type": event_type,
            "payload": {
                "run_id": run_id,
                "candidate_id": candidate.candidate_id,
                "finding_id": finding["finding_id"],
                "status": finding["status"],
                "original_claim_type": candidate.claim_type,
                "claim_type": finding["claim_type"],
                "severity": finding["severity"],
                "evidence_refs": finding["evidence_refs"],
            },
        }
    )
    return PromotionDecision(True, finding["status"], "promoted", finding)

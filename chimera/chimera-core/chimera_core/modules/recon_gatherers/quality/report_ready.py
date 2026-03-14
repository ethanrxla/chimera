from dataclasses import dataclass
from typing import List, Optional, Tuple

from chimera_core.modules.recon_gatherers.schemas import Finding
from chimera_core.scope import ScopeGraph


REPORT_READY = "REPORT_READY"
NEEDS_REVIEW = "NEEDS_REVIEW"
NOISE = "NOISE"


def _confidence_to_float(value: Optional[str]) -> float:
    if value is None:
        return 0.0
    try:
        return float(value)
    except ValueError:
        mapping = {"high": 0.9, "medium": 0.6, "low": 0.3}
        return mapping.get(value.lower(), 0.0)


def _evidence_anchor(finding: Finding) -> str:
    if not finding.evidence_refs:
        return ""
    return str(finding.evidence_refs[0])


def _scope_ok(scope_graph: Optional[ScopeGraph], target: str, evidence: str) -> bool:
    if not scope_graph:
        return True
    candidate = evidence or target
    if not candidate:
        return False
    return scope_graph.is_in_scope(candidate)


def _provenance_ok(finding: Finding) -> bool:
    raw = finding.raw_tool_fields or {}
    if raw.get("provenance_subject_id"):
        return True
    refs = raw.get("provenance_refs") or []
    return bool(refs)


def classify_finding(
    finding: Finding,
    *,
    scope_graph: Optional[ScopeGraph],
    target: str,
    confidence_threshold: float = 0.75,
) -> Tuple[str, str]:
    severity = (finding.severity or "").lower()
    confidence = _confidence_to_float(finding.confidence)
    evidence = _evidence_anchor(finding)

    if confidence < confidence_threshold or not evidence:
        reason = "low_confidence" if confidence < confidence_threshold else "missing_evidence"
        return NOISE, reason

    if severity in {"", "unknown"}:
        return NEEDS_REVIEW, "severity_unknown"

    if not _scope_ok(scope_graph, target, evidence):
        return NEEDS_REVIEW, "out_of_scope"

    if not _provenance_ok(finding):
        return NEEDS_REVIEW, "missing_provenance"

    return REPORT_READY, "ready"


def apply_report_ready(
    findings: List[Finding],
    *,
    scope_graph: Optional[ScopeGraph],
    target: str,
    confidence_threshold: float = 0.75,
) -> None:
    for finding in findings:
        status, reason = classify_finding(
            finding,
            scope_graph=scope_graph,
            target=target,
            confidence_threshold=confidence_threshold,
        )
        finding.raw_tool_fields.setdefault("report_ready_status", status)
        finding.raw_tool_fields.setdefault("report_ready_reason", reason)


def summarize_report_ready(findings: List[Finding]) -> dict:
    counts = {REPORT_READY: 0, NEEDS_REVIEW: 0, NOISE: 0}
    for finding in findings:
        status = finding.raw_tool_fields.get("report_ready_status", NEEDS_REVIEW)
        if status not in counts:
            status = NEEDS_REVIEW
        counts[status] += 1
    return {
        "report_ready": counts[REPORT_READY],
        "needs_review": counts[NEEDS_REVIEW],
        "noise": counts[NOISE],
    }

from typing import Dict, List, Tuple

from chimera_core.findings import Finding, SEVERITY_ORDER


class FindingIndex:
    def __init__(self) -> None:
        self._index: Dict[str, Finding] = {}

    def add(self, finding: Finding) -> Tuple[Finding, bool]:
        existing = self._index.get(finding.finding_id)
        if not existing:
            self._index[finding.finding_id] = finding
            return finding, False

        existing.evidence_refs = sorted(set(existing.evidence_refs + finding.evidence_refs))
        existing.prerequisites = sorted(set(existing.prerequisites + finding.prerequisites))
        existing.chain_parent_ids = sorted(set(existing.chain_parent_ids + finding.chain_parent_ids))
        if finding.impact_path:
            existing.impact_path = existing.impact_path or []
            for step in finding.impact_path:
                if step not in existing.impact_path:
                    existing.impact_path.append(step)
        if finding.proof_artifacts:
            existing.proof_artifacts = existing.proof_artifacts or []
            for artifact in finding.proof_artifacts:
                if artifact not in existing.proof_artifacts:
                    existing.proof_artifacts.append(artifact)
        if finding.replay_steps:
            existing.replay_steps = existing.replay_steps or []
            for step in finding.replay_steps:
                if step not in existing.replay_steps:
                    existing.replay_steps.append(step)
        if SEVERITY_ORDER.get(finding.severity, 0) > SEVERITY_ORDER.get(existing.severity, 0):
            existing.severity = finding.severity
        if finding.confidence is not None:
            existing.confidence = max(existing.confidence or 0.0, finding.confidence)
        if finding.validation_status:
            existing.validation_status = finding.validation_status
        if finding.validation_reason:
            existing.validation_reason = finding.validation_reason
        if finding.finding_type and not existing.finding_type:
            existing.finding_type = finding.finding_type
        if finding.asset and not existing.asset:
            existing.asset = finding.asset
        if finding.auth_context and not existing.auth_context:
            existing.auth_context = finding.auth_context
        if finding.sink and not existing.sink:
            existing.sink = finding.sink
        return existing, True

    def all(self) -> List[Finding]:
        return list(self._index.values())


def dedupe_findings(findings: List[Finding]) -> Tuple[List[Finding], int]:
    index = FindingIndex()
    duplicates = 0
    for finding in findings:
        _, is_duplicate = index.add(finding)
        if is_duplicate:
            duplicates += 1
    return index.all(), duplicates

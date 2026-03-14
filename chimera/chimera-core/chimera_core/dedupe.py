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
        if SEVERITY_ORDER.get(finding.severity, 0) > SEVERITY_ORDER.get(existing.severity, 0):
            existing.severity = finding.severity
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

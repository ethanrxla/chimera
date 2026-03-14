from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence

from chimera_core.findings import Finding, stable_finding_id


@dataclass(frozen=True)
class ChainRule:
    rule_id: str
    title: str
    required_types: Sequence[str]
    impact: str
    combined_severity: str
    narrative: str
    confidence_floor: float = 0.75
    require_confirmed: bool = True


@dataclass
class ChainRecord:
    rule_id: str
    finding: Finding
    supporting_ids: List[str] = field(default_factory=list)
    replay_manifest: List[Dict[str, object]] = field(default_factory=list)
    ascii_graph: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "finding": self.finding.to_dict(),
            "supporting_ids": list(self.supporting_ids),
            "replay_manifest": list(self.replay_manifest),
            "ascii_graph": self.ascii_graph,
        }


CHAIN_RULES: List[ChainRule] = [
    ChainRule(
        rule_id="idor_jwt_takeover",
        title="IDOR plus JWT weakness enables account takeover",
        required_types=("IDOR", "JWT"),
        impact="AccountTakeover",
        combined_severity="critical",
        narrative="Broken object authorization combined with token weakness can yield arbitrary account access.",
        confidence_floor=0.9,
    ),
    ChainRule(
        rule_id="idor_auth_privilege_escalation",
        title="IDOR plus auth exposure enables privilege escalation",
        required_types=("IDOR", "AUTH_EXPOSURE"),
        impact="PrivilegeEscalation",
        combined_severity="high",
        narrative="Unauthorized object access chained with exposed auth context enables escalation into another user's data plane.",
        confidence_floor=0.82,
    ),
    ChainRule(
        rule_id="auth_rate_limit_abuse",
        title="Auth weakness plus missing throttling enables brute-force abuse",
        required_types=("AUTH_EXPOSURE", "RATE_LIMIT"),
        impact="CredentialStuffing",
        combined_severity="high",
        narrative="Authentication exposure paired with missing throttling materially increases exploitability.",
        confidence_floor=0.8,
    ),
]


def synthesize_chains(findings: List[Finding], *, run_id: str, scope_hash: str, target: str) -> List[ChainRecord]:
    if not findings:
        return []

    normalized = [finding for finding in findings if finding.finding_type]
    generated: List[ChainRecord] = []
    for rule in CHAIN_RULES:
        matches = _match_rule(rule, normalized)
        for matched in matches:
            finding = _build_chain_finding(
                rule,
                matched,
                run_id=run_id,
                scope_hash=scope_hash,
                target=target,
            )
            replay_manifest = _chain_replay_manifest(rule, matched)
            generated.append(
                ChainRecord(
                    rule_id=rule.rule_id,
                    finding=finding,
                    supporting_ids=[item.finding_id for item in matched],
                    replay_manifest=replay_manifest,
                    ascii_graph=_ascii_graph(finding),
                )
            )
    return _dedupe_records(generated)


def _match_rule(rule: ChainRule, findings: Iterable[Finding]) -> List[List[Finding]]:
    grouped: Dict[str, List[Finding]] = {required: [] for required in rule.required_types}
    for finding in findings:
        finding_type = (finding.finding_type or "").upper()
        if finding_type in grouped and _eligible_for_rule(rule, finding):
            grouped[finding_type].append(finding)

    if not all(grouped.values()):
        return []

    ordered_groups = [grouped[required] for required in rule.required_types]
    combinations: List[List[Finding]] = []
    _combine_findings(ordered_groups, 0, [], combinations)
    filtered: List[List[Finding]] = []
    for combo in combinations:
        ids = {finding.finding_id for finding in combo}
        if len(ids) != len(combo):
            continue
        filtered.append(combo)
    return filtered


def _eligible_for_rule(rule: ChainRule, finding: Finding) -> bool:
    if not rule.require_confirmed:
        return True
    return finding.validation_status == "confirmed" or finding.finding_type in {"AUTH_EXPOSURE", "IDOR"}


def _combine_findings(groups: Sequence[List[Finding]], index: int, current: List[Finding], output: List[List[Finding]]) -> None:
    if index >= len(groups):
        output.append(list(current))
        return
    for finding in groups[index]:
        current.append(finding)
        _combine_findings(groups, index + 1, current, output)
        current.pop()


def _build_chain_finding(
    rule: ChainRule,
    matched: Sequence[Finding],
    *,
    run_id: str,
    scope_hash: str,
    target: str,
) -> Finding:
    chain_id = stable_finding_id(
        f"Exploit chain: {rule.title}",
        target,
        "chain-analysis",
        ":".join(item.finding_id for item in matched),
    )
    confidence = max(rule.confidence_floor, max(item.confidence or 0.5 for item in matched))
    impact_path = [
        {
            "step": item.title,
            "impact": item.finding_type or "finding",
            "evidence": item.finding_id,
        }
        for item in matched
    ]
    impact_path.append(
        {
            "step": rule.title,
            "impact": rule.impact,
            "evidence": rule.rule_id,
        }
    )
    proof_artifacts: List[Dict[str, object]] = []
    replay_steps: List[Dict[str, object]] = []
    for item in matched:
        proof_artifacts.extend(item.proof_artifacts or [])
        replay_steps.extend(item.replay_steps or [])
    return Finding(
        finding_id=chain_id,
        severity=rule.combined_severity,
        title=f"Exploit chain: {rule.title}",
        description=rule.narrative,
        affected_target=target,
        tool_source="chain-analysis",
        tool_version="2026.2",
        run_id=run_id,
        scope_hash=scope_hash,
        finding_type="EXPLOIT_CHAIN",
        validation_status="confirmed",
        confidence=confidence,
        prerequisites=[item.finding_id for item in matched],
        chain_parent_ids=[item.finding_id for item in matched],
        impact_path=impact_path,
        proof_artifacts=proof_artifacts,
        replay_steps=replay_steps,
    )


def _dedupe_records(records: List[ChainRecord]) -> List[ChainRecord]:
    unique: Dict[str, ChainRecord] = {}
    for record in records:
        unique[record.finding.finding_id] = record
    return list(unique.values())


def _chain_replay_manifest(rule: ChainRule, matched: Sequence[Finding]) -> List[Dict[str, object]]:
    steps: List[Dict[str, object]] = []
    for index, item in enumerate(matched, start=1):
        steps.append(
            {
                "step": index,
                "finding_id": item.finding_id,
                "action": item.title,
                "expected_result": item.validation_reason or item.description,
                "replay_steps": list(item.replay_steps or []),
            }
        )
    steps.append(
        {
            "step": len(matched) + 1,
            "finding_id": rule.rule_id,
            "action": f"Exploit chain outcome: {rule.impact}",
            "expected_result": rule.narrative,
            "replay_steps": [],
        }
    )
    return steps


def _ascii_graph(finding: Finding) -> str:
    steps = list(finding.impact_path or [])
    if not steps:
        return f"[{finding.severity.upper()}] {finding.title}"
    lines: List[str] = []
    for index, step in enumerate(steps):
        label = step.get("step") or "step"
        impact = step.get("impact") or "impact"
        if index == 0:
            lines.append(f"[{finding.severity.upper()}] {label}")
        else:
            lines.append(f"    -> {label} => {impact}")
    return "\n".join(lines)

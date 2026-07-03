from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from chimera_core.graph.models import EvidenceGraph, GraphEdge, GraphNode
from chimera_core.target_extraction import extract_targets_from_command


def build_evidence_graph(
    *,
    events: Iterable[Dict[str, object]],
    artifacts_root: Path,
    findings_path: Optional[Path] = None,
) -> EvidenceGraph:
    graph = EvidenceGraph()
    nodes: Dict[str, GraphNode] = {}
    edges_seen: set[tuple[str, str, str]] = set()
    previous_event_id: Optional[str] = None

    def ensure_node(node_id: str, node_type: str, **attrs: object) -> None:
        existing = nodes.get(node_id)
        if existing is None:
            node = GraphNode(node_id=node_id, node_type=node_type, attrs=dict(attrs))
            nodes[node_id] = node
            graph.nodes.append(node)
            return
        existing.attrs.update({k: v for k, v in attrs.items() if v is not None})

    def add_edge(src: str, dst: str, label: str, **attrs: object) -> None:
        key = (src, dst, label)
        if key in edges_seen:
            return
        edges_seen.add(key)
        graph.edges.append(GraphEdge(src=src, dst=dst, label=label, attrs=dict(attrs)))

    artifact_map: Dict[str, str] = {}
    for event in events:
        event_id = str(event["event_id"])
        run_id = str(event["run_id"])
        payload = dict(event.get("payload") or {})
        ensure_node(f"run:{run_id}", "run", run_id=run_id)
        ensure_node(f"event:{event_id}", "event", event_type=event.get("event_type"), seq=event.get("seq"))
        add_edge(f"run:{run_id}", f"event:{event_id}", "HAS_EVENT")
        if previous_event_id is not None:
            add_edge(f"event:{previous_event_id}", f"event:{event_id}", "NEXT")
        previous_event_id = event_id

        task_id = payload.get("task_id")
        if task_id:
            ensure_node(f"task:{task_id}", "task", task_id=task_id)
            add_edge(f"run:{run_id}", f"task:{task_id}", "HAS_TASK")

        if event.get("event_type") == "cmd_started" and task_id:
            add_edge(f"task:{task_id}", f"event:{event_id}", "TASK_STARTED_BY")
            for target in extract_targets_from_command(payload.get("command") or []):
                ensure_node(f"asset:{target}", "asset", target=target)
                add_edge(f"task:{task_id}", f"asset:{target}", "TARGETS")

        if event.get("event_type") == "artifact_saved":
            path = str(payload.get("path") or "")
            if path:
                artifact_id = _artifact_id(path=Path(path), artifacts_root=artifacts_root)
                artifact_map[path] = artifact_id
                ensure_node(f"artifact:{artifact_id}", "artifact", path=path, artifact_type=payload.get("artifact_type"))
                add_edge(f"event:{event_id}", f"artifact:{artifact_id}", "EMITS_ARTIFACT")
                if task_id:
                    add_edge(f"task:{task_id}", f"artifact:{artifact_id}", "TASK_PRODUCED")
        if event.get("event_type") == "verification_passed":
            verification_id = str(payload.get("verification_id") or "")
            if verification_id:
                ensure_node(f"verification:{verification_id}", "verification", claim_type=payload.get("claim_type"))
                for evidence_ref in payload.get("evidence_refs") or []:
                    if not isinstance(evidence_ref, str):
                        continue
                    artifact_id = artifact_map.get(evidence_ref)
                    if artifact_id is None:
                        maybe_artifact = Path(evidence_ref)
                        if maybe_artifact.exists():
                            artifact_id = _artifact_id(path=maybe_artifact, artifacts_root=artifacts_root)
                            ensure_node(f"artifact:{artifact_id}", "artifact", path=str(maybe_artifact))
                    if artifact_id is not None:
                        add_edge(f"artifact:{artifact_id}", f"verification:{verification_id}", "EVIDENCE_FOR")
        if event.get("event_type") == "hexstrike_call_started":
            task_id = str(payload.get("task_id") or "")
            call_id = f"hexstrike_call:{event_id}"
            ensure_node(call_id, "hexstrike_call", tool_name=payload.get("tool_name"), route=payload.get("route"))
            if task_id:
                add_edge(f"task:{task_id}", call_id, "TASK_PRODUCED")
            for target in payload.get("target_refs") or []:
                if isinstance(target, str):
                    ensure_node(f"asset:{target}", "asset", target=target)
                    add_edge(call_id, f"asset:{target}", "TARGETS")
        if event.get("event_type") == "verification_failed":
            verification_id = str(payload.get("verification_id") or "")
            if verification_id:
                ensure_node(f"verification:{verification_id}", "verification", claim_type=payload.get("claim_type"), outcome="failed")
        if event.get("event_type") == "verification_planned":
            verification_id = str(payload.get("verification_id") or "")
            candidate_id = str(payload.get("candidate_id") or "")
            if verification_id:
                ensure_node(f"verification:{verification_id}", "verification", claim_type=payload.get("claim_type"), outcome="planned")
                plan_ref = str(payload.get("plan_artifact_ref") or "")
                if plan_ref:
                    artifact_id = artifact_map.get(plan_ref)
                    if artifact_id is not None:
                        add_edge(f"artifact:{artifact_id}", f"verification:{verification_id}", "EVIDENCE_FOR")
                if candidate_id:
                    ensure_node(f"candidate:{candidate_id}", "candidate", claim_type=payload.get("claim_type"))
                    add_edge(f"candidate:{candidate_id}", f"verification:{verification_id}", "TASK_PRODUCED")
        if event.get("event_type") == "validator_decision_recorded":
            verification_id = str(payload.get("verification_id") or "")
            decision_ref = str(payload.get("decision_artifact_ref") or "")
            if verification_id and decision_ref:
                artifact_id = artifact_map.get(decision_ref)
                if artifact_id is not None:
                    add_edge(f"artifact:{artifact_id}", f"verification:{verification_id}", "TASK_PRODUCED")
        if event.get("event_type") in {"finding_promoted", "finding_downgraded"}:
            finding_id = str(payload.get("finding_id") or "")
            if finding_id:
                ensure_node(
                    f"finding:{finding_id}",
                    "finding",
                    severity=payload.get("severity"),
                    claim_type=payload.get("claim_type"),
                    status=payload.get("status") or ("downgraded" if event.get("event_type") == "finding_downgraded" else "verified"),
                )
                for evidence_ref in payload.get("evidence_refs") or []:
                    if not isinstance(evidence_ref, str):
                        continue
                    artifact_id = artifact_map.get(evidence_ref)
                    if artifact_id is None:
                        maybe_artifact = Path(evidence_ref)
                        if maybe_artifact.exists():
                            artifact_id = _artifact_id(path=maybe_artifact, artifacts_root=artifacts_root)
                            ensure_node(f"artifact:{artifact_id}", "artifact", path=str(maybe_artifact))
                    if artifact_id is not None:
                        add_edge(f"artifact:{artifact_id}", f"finding:{finding_id}", "EVIDENCE_FOR")
        if event.get("event_type") == "agent_started":
            task_id = str(payload.get("task_id") or "")
            if task_id:
                ensure_node(f"agent:{task_id}", "agent", mode=payload.get("mode"), role=payload.get("agent_role"))
                add_edge(f"run:{run_id}", f"agent:{task_id}", "HAS_TASK")
        if event.get("event_type") == "agent_tool_called":
            task_id = str(payload.get("task_id") or "")
            call_id = str(payload.get("call_id") or "")
            tool_name = str(payload.get("tool_name") or "")
            if task_id and call_id:
                ensure_node(f"agent_call:{call_id}", "agent_call", tool_name=tool_name)
                add_edge(f"agent:{task_id}", f"agent_call:{call_id}", "TASK_PRODUCED")
                for target in payload.get("target_refs") or []:
                    if isinstance(target, str):
                        ensure_node(f"asset:{target}", "asset", target=target)
                        add_edge(f"agent_call:{call_id}", f"asset:{target}", "TARGETS")
        if event.get("event_type") == "agent_handoff_created":
            task_id = str(payload.get("task_id") or "")
            candidate_id = str(payload.get("candidate_id") or "")
            if task_id and candidate_id:
                ensure_node(f"candidate:{candidate_id}", "candidate", claim_type=payload.get("claim_type"))
                add_edge(f"agent:{task_id}", f"candidate:{candidate_id}", "TASK_PRODUCED")

    if findings_path and findings_path.exists():
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        for finding in findings if isinstance(findings, list) else []:
            if not isinstance(finding, dict):
                continue
            finding_id = str(finding.get("finding_id") or finding.get("stable_id") or finding.get("title") or "unknown-finding")
            ensure_node(f"finding:{finding_id}", "finding", severity=finding.get("severity"), title=finding.get("title"))
            for evidence_ref in finding.get("evidence_refs") or []:
                if not isinstance(evidence_ref, str):
                    continue
                artifact_id = artifact_map.get(evidence_ref)
                if artifact_id is None:
                    maybe_artifact = Path(evidence_ref)
                    if maybe_artifact.exists():
                        artifact_id = _artifact_id(path=maybe_artifact, artifacts_root=artifacts_root)
                        ensure_node(f"artifact:{artifact_id}", "artifact", path=str(maybe_artifact))
                if artifact_id is not None:
                    add_edge(f"artifact:{artifact_id}", f"finding:{finding_id}", "EVIDENCE_FOR")
                elif evidence_ref.startswith(("http://", "https://")):
                    ensure_node(f"asset:{evidence_ref}", "asset", target=evidence_ref)
                    add_edge(f"finding:{finding_id}", f"asset:{evidence_ref}", "TARGETS")
            target = finding.get("affected_target")
            if isinstance(target, str) and target:
                ensure_node(f"asset:{target}", "asset", target=target)
                add_edge(f"finding:{finding_id}", f"asset:{target}", "TARGETS")

    return graph


def _artifact_id(*, path: Path, artifacts_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(artifacts_root.resolve()))
    except ValueError:
        return str(path.resolve())

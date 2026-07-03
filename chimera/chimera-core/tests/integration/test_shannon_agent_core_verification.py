import json
from pathlib import Path

import httpx

from chimera_core.event_store import EventStore
from chimera_core.graph.builder import build_evidence_graph
from chimera_core.plan import ExecutionPlan, Task
from chimera_core.runner import PlanRunner
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


class CoreFlowClient:
    def post(self, url: str, json=None, headers=None):
        if url.endswith("/agent"):
            return _Response(
                {
                    "status": "completed",
                    "agent_trace_ref": "shannon/agent-trace.json",
                    "tool_call_refs": ["agent_tool_call:1"],
                    "new_candidates": [
                        {
                            "candidate_id": "cand-admin",
                            "source": "shannon-agent",
                            "title": "Admin surface exposed at /admin",
                            "claim_type": "admin_exposure",
                            "severity_claimed": "medium",
                            "endpoint": "/admin",
                            "target": "https://example.com",
                            "params": [],
                            "evidence_refs": ["agent_tool_call:1"],
                            "metadata": {
                                "target": {"method": "GET", "endpoint": "/admin", "params": None, "headers": None, "body": None},
                                "verifier_hint": "probe_admin_access",
                            },
                        }
                    ],
                    "usage": {"total_tokens": 5},
                }
            )
        if url.endswith("/plan"):
            return _Response(
                {
                    "verification_plan": {
                        "verification_id": "ver-admin",
                        "candidate_id": "cand-admin",
                        "target": "https://example.com/admin",
                        "claim_type": "admin_exposure",
                        "checks": [
                            {
                                "check_id": "check-1",
                                "probe_type": "http_admin_access_check",
                                "description": "verify anonymous admin access",
                                "probe_input": {
                                    "method": "GET",
                                    "url": "https://example.com/admin",
                                    "headers": {},
                                    "query": {},
                                    "body": None,
                                    "follow_redirects": True,
                                    "timeout_s": 30,
                                },
                                "success_condition": {
                                    "type": "admin_exposure",
                                    "rules": {
                                        "status_in": [200],
                                        "endpoint_contains_any": ["/admin"],
                                        "body_contains_any": ["admin"],
                                        "allow_path_only_match": True,
                                    },
                                },
                            }
                        ],
                        "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
                        "planner_notes": "verify admin exposure",
                    }
                }
            )
        if url.endswith("/validate"):
            return _Response(
                {
                    "decision": {
                        "status": "verified",
                        "final_claim_type": "admin_exposure",
                        "severity": "medium",
                        "rationale": "verified by admin exposure probe",
                        "duplicate_of": None,
                        "required_evidence_refs_present": True,
                    }
                }
            )
        raise AssertionError(f"unexpected url {url}")

    def close(self) -> None:
        return None


class _Response:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def json(self) -> dict:
        return self.payload

    def raise_for_status(self) -> None:
        return None


def make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-int"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(run_dir / "events.jsonl")
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
        mode="live",
    )


def _make_hexstrike_transport(*, status_code: int, body_excerpt: str):
    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "status_code": status_code,
                "headers": {"content-type": "text/html"},
                "body_excerpt": body_excerpt,
                "body_sha256": "abc123",
                "request": payload,
            },
        )

    return httpx.MockTransport(handler)


def test_agent_candidate_flows_through_runner_core_verification_and_graph(tmp_path: Path) -> None:
    runtime = make_runtime(tmp_path)
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)
    plan = ExecutionPlan()
    plan.add_task(
        Task(
            "task-shannon",
            "shannon",
            "https://example.com",
            {
                "agent_flow": True,
                "live": True,
                "driver": "http",
                "base_url": "http://shannon:8080",
                "http_client": CoreFlowClient(),
                "hexstrike_base_url": "http://hexstrike:8888",
                "hexstrike_transport": _make_hexstrike_transport(status_code=200, body_excerpt="<html>admin</html>"),
            },
        )
    )

    results = runner.execute(plan)

    assert len(results) == 1
    assert len(results[0].findings) == 1
    finding = results[0].findings[0]
    assert finding.finding_type == "ADMIN_EXPOSURE"
    assert finding.evidence_refs

    run_root = tmp_path / "artifacts" / "run-int"
    assert (run_root / "shannon" / "task-shannon" / "candidates.json").exists()
    assert (run_root / "verifications" / "ver-admin" / "plan.json").exists()
    assert (run_root / "verifications" / "ver-admin" / "check-1-result.json").exists()
    assert (run_root / "verifications" / "ver-admin" / "validator_decision.json").exists()

    events = list(runtime.event_store.replay())
    event_types = [event["event_type"] for event in events]
    assert "agent_started" in event_types
    assert "agent_handoff_created" in event_types
    assert "verification_planned" in event_types
    assert "verification_passed" in event_types
    assert "finding_promoted" in event_types

    findings_path = run_root / "findings.json"
    findings_path.write_text(json.dumps([finding.to_dict()], indent=2), encoding="utf-8")
    graph = build_evidence_graph(events=events, artifacts_root=tmp_path / "artifacts", findings_path=findings_path)
    edge_labels = {(edge.src, edge.dst, edge.label) for edge in graph.edges}
    assert any(label == "EVIDENCE_FOR" and "finding:" in dst for _, dst, label in edge_labels)

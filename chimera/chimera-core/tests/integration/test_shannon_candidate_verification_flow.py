import json
from pathlib import Path

import httpx

from chimera_core.event_store import EventStore
from chimera_core.plan import ExecutionPlan, Task
from chimera_core.runner import PlanRunner
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.shannon.session import AuthToken, BrowserSession, SessionRole


class CandidateFlowClient:
    def __init__(self, *, validator_status: str) -> None:
        self.validator_status = validator_status
        self.calls: list[str] = []

    def post(self, url: str, json=None, headers=None):
        self.calls.append(url)
        if url.endswith("/agent"):
            return _Response(
                {
                    "task_id": "agent-typed",
                    "status": "completed",
                    "agent_trace_ref": "/tmp/shannon_agent/agent-typed.json",
                    "tool_results": [],
                    "new_candidates": [
                        {
                            "candidate_id": "cand-admin",
                            "source": "shannon-agent",
                            "title": "Admin surface exposed at /admin",
                            "claim_type": "admin_exposure",
                            "severity_claimed": "medium",
                            "target": "https://example.com",
                            "endpoint": "/admin",
                            "params": [],
                            "evidence_refs": ["agent_tool_call:1"],
                            "metadata": {
                                "target": {"method": "GET", "endpoint": "/admin", "params": None, "headers": None, "body": None},
                                "verifier_hint": "probe_admin_access",
                            },
                        }
                    ],
                    "usage": {"total_tokens": 12},
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
                                "description": "verify anonymous access to admin surface",
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
                                        "body_contains_any": ["admin", "dashboard"],
                                        "allow_path_only_match": True,
                                    },
                                },
                            }
                        ],
                        "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
                        "planner_notes": "admin exposure",
                    }
                }
            )
        if url.endswith("/validate"):
            return _Response(
                {
                    "decision": {
                        "status": self.validator_status,
                        "final_claim_type": "admin_exposure",
                        "severity": "medium",
                        "rationale": "validator reviewed deterministic output",
                        "duplicate_of": None,
                        "required_evidence_refs_present": self.validator_status in {"verified", "downgraded"},
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


def _make_runtime(tmp_path: Path, run_id: str) -> Runtime:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    events_path = tmp_path / "artifacts" / run_id / "events.jsonl"
    events_path.parent.mkdir(parents=True, exist_ok=True)
    return Runtime(
        scope_graph=ScopeGraph(scope_manifest),
        scope_policy=ScopePolicy(scope_manifest),
        event_store=EventStore(events_path, run_id=run_id),
        artifacts_root=tmp_path / "artifacts",
        run_id=run_id,
        mode="live",
    )


def _make_hexstrike_transport(*, status_code: int, body_excerpt: str):
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/probe"
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


def _events(tmp_path: Path, run_id: str) -> list[dict]:
    events_path = tmp_path / "artifacts" / run_id / "events.jsonl"
    return [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _plan_with_shannon_task(client: CandidateFlowClient, transport: httpx.MockTransport) -> ExecutionPlan:
    plan = ExecutionPlan()
    plan.add_task(
        Task(
            "shannon-typed",
            "shannon",
            "https://example.com",
            {
                "live": True,
                "driver": "http",
                "agent_flow": True,
                "base_url": "http://shannon:8080",
                "http_client": client,
                "hexstrike_base_url": "http://hexstrike:8888",
                "hexstrike_transport": transport,
                "intent": "Investigate admin surface",
            },
        )
    )
    return plan


def test_runner_rejects_candidate_without_verifier_backed_evidence(tmp_path: Path) -> None:
    run_id = "run-core-reject"
    runtime = _make_runtime(tmp_path, run_id)
    client = CandidateFlowClient(validator_status="verified")
    transport = _make_hexstrike_transport(status_code=403, body_excerpt="forbidden")
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)

    results = runner.execute(_plan_with_shannon_task(client, transport))

    assert list(dict.fromkeys(client.calls)) == [
        "http://shannon:8080/agent",
        "http://shannon:8080/plan",
        "http://shannon:8080/validate",
    ]
    assert results[0].findings == []
    event_types = [event["event_type"] for event in _events(tmp_path, run_id)]
    assert "verification_planned" in event_types
    assert "hexstrike_call_started" in event_types
    assert "verification_failed" in event_types
    assert "finding_rejected" in event_types


def test_runner_promotes_candidate_when_verifier_passes_and_evidence_resolves(tmp_path: Path) -> None:
    run_id = "run-core-accept"
    runtime = _make_runtime(tmp_path, run_id)
    client = CandidateFlowClient(validator_status="verified")
    transport = _make_hexstrike_transport(status_code=200, body_excerpt="admin dashboard")
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)

    results = runner.execute(_plan_with_shannon_task(client, transport))

    assert len(results[0].findings) == 1
    finding = results[0].findings[0]
    assert finding.finding_type == "ADMIN_EXPOSURE"
    assert finding.evidence_refs

    run_root = tmp_path / "artifacts" / run_id
    assert (run_root / "shannon" / "shannon-typed" / "candidates.json").exists()
    assert (run_root / "verifications" / "ver-admin" / "plan.json").exists()
    assert (run_root / "hexstrike" / "ver-admin" / "check-1" / "request.json").exists()
    assert (run_root / "hexstrike" / "ver-admin" / "check-1" / "response.json").exists()
    assert (run_root / "hexstrike" / "ver-admin" / "check-1" / "normalized.json").exists()
    assert (run_root / "verifications" / "ver-admin" / "check-1-result.json").exists()
    assert (run_root / "verifications" / "ver-admin" / "validator_decision.json").exists()

    events = _events(tmp_path, run_id)
    event_types = [event["event_type"] for event in events]
    assert "verification_planned" in event_types
    assert "hexstrike_call_started" in event_types
    assert "hexstrike_call_finished" in event_types
    assert "verification_passed" in event_types
    assert "finding_promoted" in event_types
    promoted = next(event for event in events if event["event_type"] == "finding_promoted")
    assert promoted["payload"]["evidence_refs"]


def test_runner_promotes_candidate_from_autonomous_agent_result_v1(tmp_path: Path) -> None:
    run_id = "run-core-autonomous-v1"
    runtime = _make_runtime(tmp_path, run_id)

    class AutonomousResultClient(CandidateFlowClient):
        def post(self, url: str, json=None, headers=None):
            self.calls.append(url)
            if url.endswith("/agent"):
                return _Response(
                    {
                        "schema": "shannon.autonomous_agent_result.v1",
                        "task_id": "agent-autonomous-v1",
                        "run_id": run_id,
                        "status": "completed",
                        "request": {
                            "schema": "shannon.agent_request.v1",
                            "mode": "investigate",
                            "agent_role": "analysis",
                            "analysis_domain": "authz",
                            "provider_preset": "ollama",
                            "max_turns": 8,
                            "max_tool_calls": 12,
                            "max_retries": 1,
                            "reasoning_effort": "medium",
                        },
                        "runtime": {
                            "provider": "openai_compatible",
                            "provider_preset": "ollama",
                            "model": "qwen2.5-coder:7b",
                            "limits": {"max_turns": 8, "max_tool_calls": 12, "max_retries": 1},
                        },
                        "artifacts": {
                            "agent_trace_ref": "/tmp/shannon_agent/agent-autonomous-v1.json",
                            "tool_call_refs": ["artifact://tool-call.json"],
                            "evidence_refs": ["artifact://tool-call.json"],
                            "task_state_ref": "/tmp/shannon_agent/task-state.json",
                        },
                        "findings": [
                            {
                                "candidate_id": "cand-admin-v1",
                                "source": "shannon-agent",
                                "title": "Admin surface exposed at /admin",
                                "claim_type": "admin_exposure",
                                "severity_claimed": "medium",
                                "target": "https://example.com",
                                "endpoint": "/admin",
                                "params": [],
                                "evidence_refs": ["artifact://tool-call.json"],
                                "metadata": {
                                    "target": {"method": "GET", "endpoint": "/admin", "params": None, "headers": None, "body": None},
                                    "verifier_hint": "probe_admin_access",
                                },
                            }
                        ],
                        "summary": {"finding_count": 1, "tool_result_count": 1},
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                    }
                )
            if url.endswith("/plan"):
                return super().post(url, json=json, headers=headers)
            if url.endswith("/validate"):
                return super().post(url, json=json, headers=headers)
            raise AssertionError(f"unexpected url {url}")

    client = AutonomousResultClient(validator_status="verified")
    transport = _make_hexstrike_transport(status_code=200, body_excerpt="admin dashboard")
    plan = ExecutionPlan()
    plan.add_task(
        Task(
            "shannon-autonomous-analysis",
            "shannon",
            "https://example.com",
            {
                "live": True,
                "driver": "http",
                "agent_flow": True,
                "mode": "investigate",
                "agent_role": "analysis",
                "analysis_domain": "authz",
                "provider_preset": "ollama",
                "model": "qwen2.5-coder:7b",
                "provider_base_url": "http://ollama:11434/v1",
                "max_turns": 8,
                "max_tool_calls": 12,
                "max_retries": 1,
                "reasoning_effort": "medium",
                "repo_path": str(tmp_path / "repo"),
                "browser_session_mode": "mediated",
                "zap_mcp_enabled": True,
                "base_url": "http://shannon:8080",
                "http_client": client,
                "hexstrike_base_url": "http://hexstrike:8888",
                "hexstrike_transport": transport,
                "intent": "Investigate admin surface",
            },
        )
    )
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)

    results = runner.execute(plan)

    assert list(dict.fromkeys(client.calls)) == [
        "http://shannon:8080/agent",
        "http://shannon:8080/plan",
        "http://shannon:8080/validate",
    ]
    assert len(results[0].findings) == 1
    finding = results[0].findings[0]
    assert finding.finding_type == "ADMIN_EXPOSURE"
    events = _events(tmp_path, run_id)
    task_state_events = [
        event for event in events
        if event["event_type"] == "artifact_saved" and event["payload"].get("artifact_type") == "task_state"
    ]
    assert task_state_events
    assert task_state_events[0]["payload"]["path"] == "/tmp/shannon_agent/task-state.json"
    assert "attack_contract_created" in [event["event_type"] for event in events]


def test_runner_promotes_exploited_candidate_from_persisted_exploit_evidence(tmp_path: Path) -> None:
    run_id = "run-core-exploit-seed"
    runtime = _make_runtime(tmp_path, run_id)
    run_root = tmp_path / "artifacts" / run_id
    exploit_ref = "exploits/cand-admin/exploit_result.json"
    comparison_ref = "exploits/cand-admin/idor_comparison.json"
    for relpath, payload in (
        (
            exploit_ref,
            {
                "classification": "EXPLOITED",
                "notes": "seeded exploit artifact",
            },
        ),
        (
            comparison_ref,
            {
                "same_data_detected": True,
                "target_endpoint": "/admin",
            },
        ),
    ):
        target = run_root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload), encoding="utf-8")

    class ExploitSeedClient(CandidateFlowClient):
        def post(self, url: str, json=None, headers=None):
            self.calls.append(url)
            if url.endswith("/agent"):
                return _Response(
                    {
                        "task_id": "agent-typed",
                        "status": "completed",
                        "agent_trace_ref": "/tmp/shannon_agent/agent-typed.json",
                        "tool_results": [],
                        "new_candidates": [
                            {
                                "candidate_id": "cand-admin",
                                "source": "shannon-agent",
                                "title": "Admin surface exposed at /admin",
                                "claim_type": "admin_exposure",
                                "severity_claimed": "medium",
                                "target": "https://example.com",
                                "endpoint": "/admin",
                                "params": [],
                                "evidence_refs": [exploit_ref, comparison_ref],
                                "metadata": {
                                    "target": {"method": "GET", "endpoint": "/admin", "params": None, "headers": None, "body": None},
                                    "verifier_hint": "probe_admin_access",
                                    "exploit_result": {
                                        "verification_id": "ver-exploit",
                                        "candidate_id": "cand-admin",
                                        "claim_type": "admin_exposure",
                                        "classification": "EXPLOITED",
                                        "final_evidence_refs": [exploit_ref, comparison_ref],
                                    },
                                },
                            }
                        ],
                        "usage": {"total_tokens": 7},
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
                                    "description": "verify anonymous access to admin surface",
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
                                            "body_contains_any": ["admin", "dashboard"],
                                            "allow_path_only_match": True,
                                        },
                                    },
                                }
                            ],
                            "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
                            "planner_notes": "admin exposure",
                        }
                    }
                )
            if url.endswith("/validate"):
                assert json is not None
                verification_results = list(json.get("verification_results") or [])
                assert any(result.get("check_id") == "exploit-result" and result.get("outcome") == "passed" for result in verification_results)
                return _Response(
                    {
                        "decision": {
                            "status": "verified",
                            "final_claim_type": "admin_exposure",
                            "severity": "medium",
                            "rationale": "exploit evidence plus verification context is sufficient",
                            "duplicate_of": None,
                            "required_evidence_refs_present": True,
                        }
                    }
                )
            raise AssertionError(f"unexpected url {url}")

    client = ExploitSeedClient(validator_status="verified")
    transport = _make_hexstrike_transport(status_code=403, body_excerpt="forbidden")
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)

    results = runner.execute(_plan_with_shannon_task(client, transport))

    assert len(results[0].findings) == 1
    finding = results[0].findings[0]
    assert finding.finding_type == "ADMIN_EXPOSURE"
    assert exploit_ref in finding.evidence_refs
    assert comparison_ref in finding.evidence_refs

    events = _events(tmp_path, run_id)
    event_types = [event["event_type"] for event in events]
    assert "verification_failed" in event_types
    assert "finding_promoted" in event_types
    promoted = next(event for event in events if event["event_type"] == "finding_promoted")
    assert exploit_ref in promoted["payload"]["evidence_refs"]


class ExploitReplayClient:
    def request(self, method: str, url: str, headers=None, cookies=None, params=None, json=None):
        class Response:
            status_code = 200
            headers = {"content-type": "application/json"}
            text = '{"basket":{"id":1,"owner":"user-a","items":["apple"]}}'

            def json(self):
                return {"basket": {"id": 1, "owner": "user-a", "items": ["apple"]}}

        return Response()


def test_runner_promotes_exploit_mode_candidate_from_handler_evidence(tmp_path: Path) -> None:
    run_id = "run-core-exploit-live-path"
    runtime = _make_runtime(tmp_path, run_id)

    class ExploitModeClient(CandidateFlowClient):
        def post(self, url: str, json=None, headers=None):
            self.calls.append(url)
            if url.endswith("/agent"):
                return _Response(
                    {
                        "task_id": "agent-exploit",
                        "status": "completed",
                        "agent_trace_ref": "/tmp/shannon_agent/agent-exploit.json",
                        "tool_results": [],
                        "new_candidates": [
                            {
                                "candidate_id": "cand-idor",
                                "source": "shannon-agent",
                                "title": "IDOR on basket endpoint",
                                "claim_type": "idor",
                                "severity_claimed": "high",
                                "target": "https://example.com",
                                "endpoint": "/rest/basket/1",
                                "params": [],
                                "evidence_refs": [],
                                "metadata": {
                                    "target": {"method": "GET", "endpoint": "/rest/basket/1", "params": {}, "headers": None, "body": None},
                                    "verifier_hint": "probe_idor",
                                },
                            }
                        ],
                        "usage": {"total_tokens": 8},
                    }
                )
            if url.endswith("/plan"):
                return _Response(
                    {
                        "verification_plan": {
                            "verification_id": "ver-idor",
                            "candidate_id": "cand-idor",
                            "target": "https://example.com/rest/basket/1",
                            "claim_type": "idor",
                            "checks": [
                                {
                                    "check_id": "check-1",
                                    "probe_type": "http_idor_check",
                                    "description": "verify alternate object access",
                                    "probe_input": {
                                        "method": "GET",
                                        "url": "https://example.com/rest/basket/1",
                                        "headers": {},
                                        "query": {},
                                        "body": None,
                                        "follow_redirects": True,
                                        "timeout_s": 30,
                                    },
                                    "success_condition": {
                                        "type": "idor",
                                        "rules": {
                                            "status_in": [200],
                                            "require_numeric_object_id": True,
                                        },
                                    },
                                }
                            ],
                            "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
                            "planner_notes": "idor verification",
                        }
                    }
                )
            if url.endswith("/validate"):
                assert json is not None
                verification_results = list(json.get("verification_results") or [])
                exploit_result = next(
                    (result for result in verification_results if result.get("check_id") == "exploit-result"),
                    None,
                )
                assert exploit_result is not None
                assert exploit_result.get("outcome") == "passed"
                assert exploit_result.get("evidence_refs")
                return _Response(
                    {
                        "decision": {
                            "status": "verified",
                            "final_claim_type": "idor",
                            "severity": "high",
                            "rationale": "two-user replay produced deterministic exploit evidence",
                            "duplicate_of": None,
                            "required_evidence_refs_present": True,
                        }
                    }
                )
            raise AssertionError(f"unexpected url {url}")

    def bootstrap_callable(role, credentials: dict, target_url: str, login_config: dict, cache_key: str):
        suffix = "a" if cache_key.endswith("_a") else "b"
        role_value = role if isinstance(role, SessionRole) else SessionRole(str(role))
        return BrowserSession(
            session_id=f"{cache_key}-session",
            role=role_value,
            cookies={"sid": suffix},
            headers={"Authorization": f"Bearer token-{suffix}"},
            tokens=[AuthToken(type="JWT", value=f"token-{suffix}", source="test-bootstrap")],
            storage={"token": f"token-{suffix}"},
        )

    client = ExploitModeClient(validator_status="verified")
    transport = _make_hexstrike_transport(status_code=403, body_excerpt="forbidden")
    runner = PlanRunner(runtime=runtime, max_workers=1, stop_on_fail=True)
    plan = ExecutionPlan()
    plan.add_task(
        Task(
            "shannon-exploit",
            "shannon",
            "https://example.com",
            {
                "live": True,
                "driver": "http",
                "agent_flow": True,
                "agent_role": "exploit",
                "mode": "exploit",
                "base_url": "http://shannon:8080",
                "http_client": client,
                "exploit_http_client": ExploitReplayClient(),
                "session_bootstrap_callable": bootstrap_callable,
                "session_credentials": [{"email": "user-a@example.com"}, {"email": "user-b@example.com"}],
                "hexstrike_base_url": "http://hexstrike:8888",
                "hexstrike_transport": transport,
                "intent": "Exploit queued IDOR candidate",
            },
        )
    )

    results = runner.execute(plan)

    assert len(results[0].findings) == 1
    finding = results[0].findings[0]
    assert finding.finding_type == "IDOR"
    assert finding.evidence_refs
    assert any("exploits/cand-idor/attempt-1/" in ref for ref in finding.evidence_refs)

    run_root = tmp_path / "artifacts" / run_id
    assert (run_root / "exploits" / "cand-idor" / "exploit_result.json").exists()
    assert (run_root / "exploits" / "cand-idor" / "attempt-1" / "user-a-baseline-request.json").exists()
    assert (run_root / "exploits" / "cand-idor" / "attempt-1" / "user-a-baseline-response.json").exists()
    assert (run_root / "exploits" / "cand-idor" / "attempt-1" / "user-b-idor-attempt-request.json").exists()
    assert (run_root / "exploits" / "cand-idor" / "attempt-1" / "user-b-idor-attempt-response.json").exists()
    assert (run_root / "sessions" / "low_privilege_a-session.json").exists()
    assert (run_root / "sessions" / "low_privilege_b-session.json").exists()
    assert (run_root / "verifications" / "ver-idor" / "plan.json").exists()
    assert (run_root / "verifications" / "ver-idor" / "validator_decision.json").exists()

    events = _events(tmp_path, run_id)
    event_types = [event["event_type"] for event in events]
    assert "session_bootstrap_started" in event_types
    assert "session_bootstrap_completed" in event_types
    assert "exploit_attempted" in event_types
    assert "exploit_result_saved" in event_types
    assert "verification_failed" in event_types
    assert "finding_promoted" in event_types
    promoted = next(event for event in events if event["event_type"] == "finding_promoted")
    assert any("exploits/cand-idor/attempt-1/" in ref for ref in promoted["payload"]["evidence_refs"])

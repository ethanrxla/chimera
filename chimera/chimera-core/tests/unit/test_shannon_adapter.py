import json
from pathlib import Path

from chimera_core.adapters.shannon_adapter import (
    ShannonAdapter,
    _bind_candidate_endpoint,
    _route_probe_from_candidate,
    _verification_plan_from_dict,
)
from chimera_core.agents.agent_loop import AgentResult
from chimera_core.agents.llm_provider import TokenUsage
from chimera_core.artifacts import ArtifactWriter
from chimera_core.event_store import EventStore
from chimera_core.findings import Finding, stable_finding_id
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.shannon.schemas import CandidateFinding


def load_fixture(name: str) -> str:
    base = Path(__file__).resolve().parents[1] / "fixtures" / "shannon"
    return (base / name).read_text(encoding="utf-8")


def make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-321"
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(run_dir / "events.jsonl")
    return Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id=run_id,
    )


def make_adapter(tmp_path: Path, options=None) -> ShannonAdapter:
    runtime = make_runtime(tmp_path)
    return ShannonAdapter(
        runtime=runtime,
        options=options,
        run_id="run-321",
        task_id="T9",
        scope_hash="scope-321",
    )


def test_shannon_normalizes_fixture_output(tmp_path: Path) -> None:
    adapter = make_adapter(tmp_path=tmp_path)
    raw_output = load_fixture("output.json")
    findings = adapter.normalize(raw_output)
    assert len(findings) == 1
    finding = findings[0]
    expected_id = stable_finding_id(
        "SQL Injection in login", "https://example.com/login", "shannon"
    )
    assert finding.to_dict() == {
        "finding_id": expected_id,
        "severity": "high",
        "title": "SQL Injection in login",
        "description": "Payload bypassed authentication on the login endpoint.",
        "affected_target": "https://example.com/login",
        "evidence_refs": ["poc.sql"],
        "tool_source": "shannon",
        "tool_version": "shannon",
        "repro_guidance": "Use payload ' OR 1=1-- on the username field.",
        "timestamps": finding.timestamps.isoformat(),
        "run_id": "run-321",
        "scope_hash": "scope-321",
        "status": "new",
        "finding_type": "SQLI",
        "asset": {
            "host": "example.com",
            "endpoint": "/login",
            "method": None,
            "parameter": None,
        },
        "confidence": 0.9,
    }


def test_shannon_run_uses_fixture_output(tmp_path: Path) -> None:
    raw_output = load_fixture("output.json")
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={"raw_output_override": raw_output},
    )

    result = adapter.run(["https://example.com"])

    assert result["findings"]
    raw_output_path = (
        tmp_path / "artifacts" / "run-321" / "shannon" / "T9" / "raw_output.json"
    )
    assert raw_output_path.exists()
    event_types = [event["event_type"] for event in adapter.runtime.event_store.replay()]
    assert "llm_started" in event_types
    assert "llm_finished" in event_types


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def json(self) -> dict:
        return self.payload

    def raise_for_status(self) -> None:
        return None


class FakeClient:
    def __init__(self, fixture_payload: dict) -> None:
        self.fixture_payload = fixture_payload
        self.posted = False

    def post(self, url: str, json=None, headers=None) -> FakeResponse:
        self.posted = True
        return FakeResponse({"task_id": "task-1", "status": "running"})

    def get(self, url: str, headers=None) -> FakeResponse:
        return FakeResponse(self.fixture_payload)

    def close(self) -> None:
        return None


def test_shannon_http_driver_uses_client(tmp_path: Path) -> None:
    payload = json_payload()
    fake_client = FakeClient(payload)
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "live": True,
            "driver": "http",
            "http_client": fake_client,
            "poll_interval_s": 0,
        },
    )

    result = adapter.run(["https://example.com/login"])

    assert fake_client.posted is True
    assert len(result["findings"]) == 1


def test_shannon_typed_mode_does_not_promote_unverified_findings(tmp_path: Path) -> None:
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "typed_flow": True,
            "typed_skeleton_only": True,
            "query": "verify this",
        },
    )

    result = adapter.run(["https://example.com/login"])

    assert result["findings"] == []
    raw_output_path = (
        tmp_path / "artifacts" / "run-321" / "shannon" / "T9" / "raw_output.json"
    )
    assert raw_output_path.exists()


def test_shannon_autonomous_mode_runs_agent_loop(tmp_path: Path, monkeypatch) -> None:
    loop_calls = {}
    created_executor = {}

    class FakeProvider:
        async def close(self) -> None:
            return None

    class FakeToolExecutor:
        def __init__(self, **kwargs) -> None:
            created_executor.update(kwargs)
            self.reported_findings = []
            self.artifacts_dir = kwargs["artifacts_dir"]
            self.run_id = kwargs["run_id"]
            self.task_id = kwargs["task_id"]
            self.artifact_namespace = kwargs.get("artifact_namespace")

        def _artifact_dir(self):
            path = self.artifacts_dir / self.run_id / self.artifact_namespace / self.task_id
            path.mkdir(parents=True, exist_ok=True)
            return path

        def save_call_log(self):
            path = self._artifact_dir() / "tool_call_log.json"
            path.write_text("[]", encoding="utf-8")
            return path

        async def close(self) -> None:
            return None

    class FakeAgentLoop:
        def __init__(self, **kwargs) -> None:
            loop_calls["init"] = kwargs

        async def run(self, initial_context: str) -> AgentResult:
            loop_calls["initial_context"] = initial_context
            return AgentResult(
                findings=[
                    Finding(
                        finding_id="agent-f-1",
                        severity="high",
                        title="SQL Injection in /rest/user/login",
                        description="Confirmed via autonomous agent",
                        affected_target="https://example.com/rest/user/login",
                        tool_source="chimera-agent",
                        tool_version="agent/analysis/injection",
                        run_id="run-321",
                        scope_hash="agent-scope",
                        evidence_refs=["artifact://tool_call_log.json"],
                        repro_guidance="curl ...",
                    )
                ],
                reported=[],
                usage=TokenUsage(input_tokens=111, output_tokens=22),
                turns=3,
                duration_seconds=1.5,
                stop_reason="agent_done",
                artifact_paths=[str(tmp_path / "artifacts" / "run-321" / "shannon" / "T9" / "agent_trace.json")],
                errors=[],
            )

    monkeypatch.setattr("chimera_core.adapters.shannon_adapter.create_provider", lambda *args, **kwargs: FakeProvider())
    monkeypatch.setattr("chimera_core.adapters.shannon_adapter.ToolExecutor", FakeToolExecutor)
    monkeypatch.setattr("chimera_core.adapters.shannon_adapter.AgentLoop", FakeAgentLoop)

    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "mode": "autonomous",
            "agent_role": "analysis",
            "analysis_domain": "injection",
            "llm_provider": "ollama",
            "model": "qwen2.5-coder:7b",
            "base_url": "http://ollama:11434/v1",
            "max_turns": 12,
            "max_input_tokens": 9999,
            "max_output_tokens": 555,
            "repo_path": str(tmp_path / "repo"),
        },
    )

    result = adapter.run(["https://example.com/rest/user/login"])

    assert len(result["findings"]) == 1
    assert result["findings"][0].title == "SQL Injection in /rest/user/login"
    assert loop_calls["init"]["agent_role"] == "analysis"
    assert loop_calls["init"]["analysis_domain"] == "injection"
    assert loop_calls["init"]["max_turns"] == 12
    assert loop_calls["init"]["max_input_tokens"] == 9999
    assert loop_calls["init"]["max_output_tokens"] == 555
    assert "https://example.com/rest/user/login" in loop_calls["initial_context"]
    assert created_executor["artifact_namespace"] == "shannon"
    assert created_executor["task_id"] == "T9"
    raw_output_path = tmp_path / "artifacts" / "run-321" / "shannon" / "T9" / "raw_output.json"
    assert raw_output_path.exists()


def test_build_agent_request_payload_uses_explicit_autonomous_fields(tmp_path: Path) -> None:
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "mode": "investigate",
            "agent_role": "analysis",
            "analysis_domain": "xss",
            "provider_preset": "ollama",
            "model": "qwen2.5-coder:7b",
            "provider_base_url": "http://ollama:11434/v1",
            "repo_path": "/workspace/repo",
            "browser_session_id": "browser-session-1",
            "max_turns": 9,
            "max_tool_calls": 12,
            "max_retries": 2,
            "reasoning_effort": "low",
        },
    )

    payload = adapter._build_agent_request_payload(["https://example.com"], adapter.options)

    assert payload["schema"] == "shannon.agent_request.v1"
    assert payload["provider_preset"] == "ollama"
    assert payload["base_url"] == "http://ollama:11434/v1"
    assert payload["repo_path"] == "/workspace/repo"
    assert payload["browser_session_id"] == "browser-session-1"
    assert payload["max_turns"] == 9
    assert payload["max_tool_calls"] == 12
    assert payload["max_retries"] == 2
    assert payload["reasoning_effort"] == "low"
    assert payload["budget"]["max_turns"] == 9


def test_normalize_agent_result_handles_v1_autonomous_shape(tmp_path: Path) -> None:
    adapter = make_adapter(tmp_path=tmp_path)
    request_payload = adapter._build_agent_request_payload(["https://example.com"], {"mode": "investigate"})

    normalized = adapter._normalize_agent_result(
        {
            "schema": "shannon.autonomous_agent_result.v1",
            "task_id": "agent-123",
            "run_id": "run-321",
            "status": "completed",
            "request": {
                "provider_preset": "ollama",
                "max_turns": 5,
                "max_tool_calls": 7,
                "max_retries": 1,
                "reasoning_effort": "low",
            },
            "runtime": {
                "provider": "openai_compatible",
                "provider_preset": "ollama",
                "model": "qwen2.5-coder:7b",
                "browser_session_id": "browser-session-1",
                "limits": {"max_turns": 5, "max_tool_calls": 7, "max_retries": 1},
                "reasoning_effort": "low",
            },
            "artifacts": {
                "agent_trace_ref": "/tmp/agent_trace.json",
                "tool_call_refs": ["/tmp/tool_call_01.json"],
                "compaction_refs": ["/tmp/compaction_01.json"],
                "task_state_ref": "/tmp/task_state.json",
                "evidence_refs": ["/tmp/tool_call_01.json"],
            },
            "findings": [
                {
                    "candidate_id": "cand-1",
                    "source": "shannon-agent",
                    "title": "Open Redirect",
                    "claim_type": "open_redirect",
                    "severity_claimed": "medium",
                    "target": "https://example.com/login",
                }
            ],
            "summary": {"tool_result_count": 1, "finding_count": 1},
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        },
        request_payload,
    )

    assert normalized["schema"] == "shannon.autonomous_agent_result.v1"
    assert normalized["request"]["provider_preset"] == "ollama"
    assert normalized["runtime"]["limits"]["max_turns"] == 5
    assert normalized["runtime"]["reasoning_effort"] == "low"
    assert normalized["artifacts"]["task_state_ref"] == "/tmp/task_state.json"
    assert normalized["findings"][0]["claim_type"] == "open_redirect"
    assert normalized["new_candidates"][0]["claim_type"] == "open_redirect"
    assert normalized["summary"]["finding_count"] == 1


def test_bind_candidate_endpoint_overrides_root_plan_target() -> None:
    plan = _verification_plan_from_dict(
        {
            "verification_id": "ver-1",
            "candidate_id": "cand-1",
            "target": "https://example.com",
            "claim_type": "open_redirect",
            "checks": [
                {
                    "check_id": "check-1",
                    "probe_type": "http_redirect_check",
                    "description": "verify redirect",
                    "probe_input": {
                        "method": "GET",
                        "url": "https://example.com",
                        "headers": {},
                        "query": {"redirect": "https://attacker.example"},
                        "body": None,
                        "follow_redirects": False,
                        "timeout_s": 30,
                    },
                    "success_condition": {
                        "type": "open_redirect",
                        "rules": {"expected_redirect_statuses": [302], "location_equals": "https://attacker.example"},
                    },
                }
            ],
            "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
            "planner_notes": "verify redirect",
        }
    )
    candidate = CandidateFinding(
        candidate_id="cand-1",
        source="strix",
        title="Open Redirect",
        claim_type="open_redirect",
        severity_claimed="medium",
        endpoint="/auth/signin",
        target="https://example.com",
    )

    bound = _bind_candidate_endpoint(plan, candidate)

    assert bound.target == "https://example.com/auth/signin"
    assert bound.checks[0].probe_input.url == "https://example.com/auth/signin"


class TypedFlowClient:
    def __init__(self) -> None:
        self.calls = []

    def post(self, url: str, json=None, headers=None) -> FakeResponse:
        self.calls.append((url, json))
        if url.endswith("/plan"):
            return FakeResponse(
                {
                    "verification_plan": {
                        "verification_id": "ver-1",
                        "candidate_id": "cand-1",
                        "target": "https://example.com/login",
                        "claim_type": "open_redirect",
                        "checks": [
                            {
                                "check_id": "check-1",
                                "probe_type": "http_redirect_check",
                                "description": "verify redirect",
                                "probe_input": {
                                    "method": "GET",
                                    "url": "https://example.com/login",
                                    "headers": {},
                                    "query": {"redirect": "https://attacker.example"},
                                    "body": None,
                                    "follow_redirects": False,
                                    "timeout_s": 30,
                                },
                                "success_condition": {
                                    "type": "open_redirect",
                                    "rules": {
                                        "expected_redirect_statuses": [302],
                                        "location_equals": "https://attacker.example",
                                    },
                                },
                            }
                        ],
                        "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
                        "planner_notes": "verify redirect",
                    }
                }
            )
        if url.endswith("/validate"):
            return FakeResponse(
                {
                    "decision": {
                        "status": "verified",
                        "final_claim_type": "open_redirect",
                        "severity": "medium",
                        "rationale": "verified",
                        "duplicate_of": None,
                        "required_evidence_refs_present": True,
                    }
                }
            )
        raise AssertionError(f"unexpected url {url}")

    def close(self) -> None:
        return None


class FakeTypedExecutor:
    artifact_writer = None

    def execute_call(self, *, run_id, call, scope_manifest):
        from chimera_core.hexstrike.schemas import HexStrikeResult, HttpResponseSummary

        if self.artifact_writer is not None:
            self.artifact_writer.write_json(
                run_id=run_id,
                relpath="hexstrike/ver-1/check-1/request.json",
                kind="http_request",
                obj={"url": "https://example.com/login?redirect=https://attacker.example"},
                source="hexstrike",
                task_id=call.check_id,
            )
            self.artifact_writer.write_json(
                run_id=run_id,
                relpath="hexstrike/ver-1/check-1/response.json",
                kind="http_response",
                obj={"status_code": 302, "headers": {"Location": "https://attacker.example"}},
                source="hexstrike",
                task_id=call.check_id,
            )
            self.artifact_writer.write_json(
                run_id=run_id,
                relpath="hexstrike/ver-1/check-1/normalized.json",
                kind="http_normalized",
                obj={"status_code": 302, "headers": {"Location": "https://attacker.example"}, "body_excerpt": "", "body_sha256": "abc"},
                source="hexstrike",
                task_id=call.check_id,
            )

        return HexStrikeResult(
            call_id=call.call_id,
            ok=True,
            error=None,
            observed_targets=["https://example.com/login"],
            request_artifact_ref="hexstrike/ver-1/check-1/request.json",
            response_artifact_ref="hexstrike/ver-1/check-1/response.json",
            normalized_artifact_ref="hexstrike/ver-1/check-1/normalized.json",
            summary=HttpResponseSummary(
                status_code=302,
                headers={"Location": "https://attacker.example"},
                body_excerpt="",
                body_sha256="abc",
            ),
        )


def test_shannon_typed_mode_returns_candidate_handoff_for_core_verification(tmp_path: Path) -> None:
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "typed_flow": True,
            "live": True,
            "driver": "http",
            "base_url": "http://shannon:8080",
            "http_client": TypedFlowClient(),
        },
    )

    result = adapter.run(["https://example.com/login"])

    assert result["findings"] == []
    assert len(result["candidate_findings"]) == 1
    assert result["candidate_findings"][0].claim_type == "open_redirect"


def test_route_probe_preserves_query_and_body_for_extended_claims() -> None:
    candidate = CandidateFinding(
        candidate_id="cand-1",
        source="shannon-agent",
        title="Business logic bypass",
        claim_type="business_logic",
        severity_claimed="high",
        endpoint="/rest/basket/2/checkout",
        target="https://example.com",
        params=["coupon"],
        metadata={"verifier_hint": "probe_business_logic"},
    )
    plan = _verification_plan_from_dict(
        {
            "verification_id": "ver-1",
            "candidate_id": "cand-1",
            "target": "https://example.com/rest/basket/2/checkout",
            "claim_type": "business_logic",
            "checks": [
                {
                    "check_id": "check-1",
                    "probe_type": "http_business_logic_check",
                    "description": "verify checkout bypass",
                    "probe_input": {
                        "method": "POST",
                        "url": "https://example.com/rest/basket/2/checkout",
                        "headers": {"Content-Type": "application/json"},
                        "query": {"coupon": "FREE100"},
                        "body": {"basketId": 2},
                        "follow_redirects": True,
                        "timeout_s": 30,
                    },
                    "success_condition": {"type": "business_logic", "rules": {}},
                }
            ],
            "required_artifact_kinds": [],
            "planner_notes": "",
        }
    )

    probe_type, tool_name, probe_input = _route_probe_from_candidate(candidate, plan.checks[0])

    assert probe_type == "http_business_logic_check"
    assert tool_name == "probe"
    assert probe_input["query"] == {"coupon": "FREE100"}
    assert probe_input["body"] == {"basketId": 2}
    assert probe_input["headers"] == {"Content-Type": "application/json"}


class AgentFlowClient:
    def __init__(self) -> None:
        self.calls = []

    def post(self, url: str, json=None, headers=None) -> FakeResponse:
        self.calls.append((url, json))
        if url.endswith("/agent"):
            return FakeResponse(
                {
                    "status": "completed",
                    "agent_trace_ref": "artifacts/run-321/shannon/agent-trace.json",
                    "tool_call_refs": ["agent_tool_call:1"],
                    "new_candidates": [
                        {
                            "candidate_id": "cand-1",
                            "source": "shannon-agent",
                            "title": "Open Redirect on /login",
                            "claim_type": "open_redirect",
                            "severity_claimed": "medium",
                            "endpoint": "/login",
                            "target": "https://example.com",
                            "params": [],
                            "evidence_refs": [],
                        }
                    ],
                    "evidence_refs": ["agent_tool_call:1"],
                    "validator_handoff": {"recommended_mode": "typed_verify", "candidate_ids": ["cand-1"]},
                    "usage": {"total_tokens": 33},
                }
            )
        if url.endswith("/plan"):
            return FakeResponse(
                {
                    "verification_plan": {
                        "verification_id": "ver-1",
                        "candidate_id": "cand-1",
                        "target": "https://example.com/login",
                        "claim_type": "open_redirect",
                        "checks": [
                            {
                                "check_id": "check-1",
                                "probe_type": "http_redirect_check",
                                "description": "verify redirect",
                                "probe_input": {
                                    "method": "GET",
                                    "url": "https://example.com/login",
                                    "headers": {},
                                    "query": {"redirect": "https://attacker.example"},
                                    "body": None,
                                    "follow_redirects": False,
                                    "timeout_s": 30,
                                },
                                "success_condition": {
                                    "type": "open_redirect",
                                    "rules": {
                                        "expected_redirect_statuses": [302],
                                        "location_equals": "https://attacker.example",
                                    },
                                },
                            }
                        ],
                        "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
                        "planner_notes": "verify redirect",
                    }
                }
            )
        if url.endswith("/validate"):
            return FakeResponse(
                {
                    "decision": {
                        "status": "verified",
                        "final_claim_type": "open_redirect",
                        "severity": "medium",
                        "rationale": "verified",
                        "duplicate_of": None,
                        "required_evidence_refs_present": True,
                    }
                }
            )
        raise AssertionError(f"unexpected url {url}")

    def close(self) -> None:
        return None


def test_shannon_agent_flow_returns_candidates_for_core_verification(tmp_path: Path) -> None:
    client = AgentFlowClient()
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "agent_flow": True,
            "live": True,
            "driver": "http",
            "base_url": "http://shannon:8080",
            "http_client": client,
            "intent": "Investigate auth redirect issues",
            "provider_preset": "ollama",
            "model": "qwen2.5-coder:7b",
            "provider_base_url": "http://ollama:11434/v1",
            "repo_path": str(tmp_path / "repo"),
            "browser_session_id": "browser-1",
            "agent_max_retries": 2,
            "reasoning_effort": "low",
        },
    )

    result = adapter.run(["https://example.com"])

    assert result["findings"] == []
    assert len(result["candidate_findings"]) == 1
    assert result["candidate_findings"][0].claim_type == "open_redirect"
    assert result["raw_output_refs"]
    agent_request = client.calls[0][1]
    assert agent_request["schema"] == "shannon.agent_request.v1"
    assert agent_request["provider_preset"] == "ollama"
    assert agent_request["model"] == "qwen2.5-coder:7b"
    assert agent_request["base_url"] == "http://ollama:11434/v1"
    assert agent_request["repo_path"] == str(tmp_path / "repo")
    assert agent_request["browser_session_id"] == "browser-1"
    assert agent_request["budget"]["max_retries"] == 2
    assert agent_request["budget"]["reasoning_effort"] == "low"
    event_types = [event["event_type"] for event in adapter.runtime.event_store.replay()]
    assert "agent_started" in event_types
    assert "agent_handoff_created" in event_types


class StructuredAgentFlowClient:
    def __init__(self) -> None:
        self.calls = []

    def post(self, url: str, json=None, headers=None) -> FakeResponse:
        self.calls.append((url, json))
        if url.endswith("/agent"):
            return FakeResponse(
                {
                    "schema": "shannon.agent_result.v1",
                    "task_id": "agent-structured",
                    "status": "completed",
                    "request": {
                        "schema": "shannon.agent_request.v1",
                        "mode": "investigate",
                        "intent": "Investigate admin surface",
                        "targets": ["https://example.com"],
                        "agent_role": "analysis",
                        "analysis_domain": "authz",
                        "provider_preset": "anthropic",
                        "budget": {"max_turns": 5, "max_tool_calls": 7, "max_retries": 1},
                    },
                    "runtime": {
                        "provider": "openai_compatible",
                        "provider_preset": "anthropic",
                        "model": "gpt-5.4-mini",
                    },
                    "context": {
                        "context_run_id": "run-prior",
                        "context_source": "strix",
                        "prior_findings_count": 2,
                        "local_hypotheses_count": 1,
                        "oracle_focus_hypotheses_count": 1,
                    },
                    "artifacts": {
                        "agent_trace_ref": "/tmp/shannon_agent/agent-structured.json",
                        "local_hypotheses_ref": "/tmp/shannon_agent/local_hypotheses.json",
                        "tool_call_refs": ["agent_tool_call:1"],
                        "compaction_refs": ["/tmp/shannon_agent/compaction_01.json"],
                        "evidence_refs": ["agent_tool_call:1"],
                    },
                    "results": {
                        "tool_results": [],
                        "new_candidates": [
                            {
                                "candidate_id": "cand-structured",
                                "source": "shannon-agent",
                                "title": "Admin surface exposed at /admin",
                                "claim_type": "admin_exposure",
                                "severity_claimed": "medium",
                                "target": "https://example.com",
                                "endpoint": "/admin",
                                "params": [],
                                "evidence_refs": ["agent_tool_call:1"],
                            }
                        ],
                        "exploit_queue": [],
                        "validator_handoff": {"recommended_mode": "typed_verify", "candidate_ids": ["cand-structured"]},
                        "raw_output": "done",
                    },
                    "usage": {"total_tokens": 99},
                }
            )
        raise AssertionError(f"unexpected url {url}")

    def close(self) -> None:
        return None


def test_shannon_agent_flow_normalizes_structured_agent_result_shape(tmp_path: Path) -> None:
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "agent_flow": True,
            "live": True,
            "driver": "http",
            "base_url": "http://shannon:8080",
            "http_client": StructuredAgentFlowClient(),
            "agent_role": "analysis",
            "analysis_domain": "authz",
            "intent": "Investigate admin surface",
        },
    )

    result = adapter.run(["https://example.com"])

    raw = json.loads(result["raw_output_refs"][0])
    agent = raw["agent"]
    assert agent["schema"] == "shannon.agent_result.v1"
    assert agent["request"]["schema"] == "shannon.agent_request.v1"
    assert agent["artifacts"]["local_hypotheses_ref"] == "/tmp/shannon_agent/local_hypotheses.json"
    assert agent["artifacts"]["compaction_refs"] == ["/tmp/shannon_agent/compaction_01.json"]
    assert agent["new_candidates"][0]["claim_type"] == "admin_exposure"
    assert len(result["candidate_findings"]) == 1


def test_shannon_analysis_role_defaults_to_agent_flow(tmp_path: Path) -> None:
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "live": True,
            "driver": "http",
            "base_url": "http://shannon:8080",
            "http_client": AgentFlowClient(),
            "agent_role": "analysis",
            "mode": "agent",
            "intent": "Investigate login redirects",
        },
    )
    result = adapter.run(["https://example.com"])

    assert result["findings"] == []
    assert len(result["candidate_findings"]) == 1
    assert result["candidate_findings"][0].claim_type == "open_redirect"


def test_shannon_autonomous_runtime_flag_routes_to_agent_flow(tmp_path: Path) -> None:
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "live": False,
            "driver": "http",
            "base_url": "http://shannon:8080",
            "http_client": AgentFlowClient(),
            "shannon_runtime": "autonomous",
            "agent_role": "report",
            "mode": "report",
            "intent": "Summarize confirmed findings",
        },
    )

    result = adapter.run(["https://example.com"])

    assert result["findings"] == []
    assert len(result["candidate_findings"]) == 1
    assert result["candidate_findings"][0].claim_type == "open_redirect"


class AgentTypedClient:
    def post(self, url: str, json=None, headers=None) -> FakeResponse:
        if url.endswith("/agent"):
            return FakeResponse(
                {
                    "task_id": "agent-typed",
                    "status": "completed",
                    "agent_trace_ref": "/tmp/shannon_agent/agent-typed.json",
                    "tool_results": [],
                    "new_candidates": [
                        {
                            "candidate_id": "cand-typed",
                            "source": "shannon-agent",
                            "title": "Admin surface exposed at /admin",
                            "claim_type": "admin_exposure",
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
            return FakeResponse(
                {
                    "verification_plan": {
                        "verification_id": "ver-admin",
                        "candidate_id": "cand-typed",
                        "target": "https://example.com/admin",
                        "claim_type": "admin_exposure",
                        "checks": [],
                        "required_artifact_kinds": [],
                        "planner_notes": "admin exposure",
                    }
                }
            )
        if url.endswith("/validate"):
            return FakeResponse(
                {
                    "decision": {
                        "status": "rejected",
                        "final_claim_type": "admin_exposure",
                        "severity": "medium",
                        "rationale": "Insufficient evidence for promotion.",
                        "duplicate_of": None,
                        "required_evidence_refs_present": False,
                    }
                }
            )
        raise AssertionError(f"unexpected url {url}")

    def close(self) -> None:
        return None


def test_shannon_agent_flow_consumes_typed_candidate_target_shape(tmp_path: Path) -> None:
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "agent_flow": True,
            "live": True,
            "driver": "http",
            "base_url": "http://shannon:8080",
            "http_client": AgentTypedClient(),
            "intent": "Investigate admin surface",
        },
    )

    result = adapter.run(["https://example.com"])

    assert result["findings"] == []
    assert len(result["candidate_findings"]) == 1
    raw = json.loads(result["raw_output_refs"][0])
    assert raw["agent"]["new_candidates"][0]["claim_type"] == "admin_exposure"


class RejectingTypedClient:
    def post(self, url: str, json=None, headers=None) -> FakeResponse:
        if url.endswith("/plan"):
            return FakeResponse(
                {
                    "verification_plan": {
                        "verification_id": "ver-api",
                        "candidate_id": "cand-api",
                        "target": "https://example.com/openapi.json",
                        "claim_type": "api_surface_exposure",
                        "checks": [
                            {
                                "check_id": "check-1",
                                "probe_type": "http_api_surface_check",
                                "description": "verify api surface",
                                "probe_input": {
                                    "method": "GET",
                                    "url": "https://example.com/openapi.json",
                                    "headers": {},
                                    "query": {},
                                    "body": None,
                                    "follow_redirects": True,
                                    "timeout_s": 30,
                                },
                                "success_condition": {
                                    "type": "api_surface_exposure",
                                    "rules": {
                                        "status_in": [200],
                                        "endpoint_contains_any": ["/openapi.json"],
                                        "body_contains_any": ["openapi"],
                                        "allow_endpoint_match": True,
                                    },
                                },
                            }
                        ],
                        "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
                        "planner_notes": "verify api surface",
                    }
                }
            )
        if url.endswith("/validate"):
            return FakeResponse(
                {
                    "decision": {
                        "status": "rejected",
                        "final_claim_type": "api_surface_exposure",
                        "severity": "medium",
                        "rationale": "Insufficient evidence for promotion.",
                        "duplicate_of": None,
                        "required_evidence_refs_present": False,
                    }
                }
            )
        raise AssertionError(f"unexpected url {url}")

    def close(self) -> None:
        return None


class FakeApiSurfaceExecutor:
    artifact_writer = None

    def execute_call(self, *, run_id, call, scope_manifest):
        from chimera_core.hexstrike.schemas import HexStrikeResult, HttpResponseSummary

        if self.artifact_writer is not None:
            self.artifact_writer.write_json(
                run_id=run_id,
                relpath="hexstrike/ver-api/check-1/request.json",
                kind="http_request",
                obj={"url": "https://example.com/openapi.json"},
                source="hexstrike",
                task_id=call.check_id,
            )
            self.artifact_writer.write_json(
                run_id=run_id,
                relpath="hexstrike/ver-api/check-1/response.json",
                kind="http_response",
                obj={"status_code": 404, "headers": {}, "body_excerpt": "missing"},
                source="hexstrike",
                task_id=call.check_id,
            )
            self.artifact_writer.write_json(
                run_id=run_id,
                relpath="hexstrike/ver-api/check-1/normalized.json",
                kind="http_normalized",
                obj={"status_code": 404, "headers": {}, "body_excerpt": "missing", "body_sha256": "abc"},
                source="hexstrike",
                task_id=call.check_id,
            )
        return HexStrikeResult(
            call_id=call.call_id,
            ok=True,
            error=None,
            observed_targets=["https://example.com/openapi.json"],
            request_artifact_ref="hexstrike/ver-api/check-1/request.json",
            response_artifact_ref="hexstrike/ver-api/check-1/response.json",
            normalized_artifact_ref="hexstrike/ver-api/check-1/normalized.json",
            summary=HttpResponseSummary(
                status_code=404,
                headers={},
                body_excerpt="missing",
                body_sha256="abc",
            ),
        )


def test_route_probe_from_candidate_uses_verifier_hint() -> None:
    candidate = CandidateFinding(
        candidate_id="cand-1",
        source="shannon-agent",
        title="Potential IDOR on /rest/basket/1",
        claim_type="idor",
        severity_claimed="medium",
        endpoint="/rest/basket/1",
        target="http://juice-shop:3000",
        metadata={"verifier_hint": "probe_idor"},
    )
    plan = _verification_plan_from_dict(
        {
            "verification_id": "ver-1",
            "candidate_id": "cand-1",
            "target": "http://juice-shop:3000/rest/basket/2",
            "claim_type": "idor",
            "checks": [
                {
                    "check_id": "check-1",
                    "probe_type": "http_idor_check",
                    "description": "verify alternate object identifier access",
                    "probe_input": {
                        "method": "GET",
                        "url": "http://juice-shop:3000/rest/basket/2",
                        "headers": {},
                        "query": {},
                        "body": None,
                        "follow_redirects": True,
                        "timeout_s": 30,
                    },
                    "success_condition": {
                        "type": "idor",
                        "rules": {"status_in": [200], "require_numeric_object_id": True},
                    },
                }
            ],
            "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
            "planner_notes": "verify idor",
        }
    )

    probe_type, tool_name, probe_input = _route_probe_from_candidate(candidate, plan.checks[0])

    assert probe_type == "http_idor_check"
    assert tool_name == "probe"
    assert probe_input["endpoint"] == "http://juice-shop:3000/rest/basket/2"


class ExploitHTTPClient:
    def request(self, method: str, url: str, headers=None, cookies=None, params=None, json=None):
        class Response:
            pass

        response = Response()
        if url.endswith("/admin") and not url.endswith("/rest/admin"):
            response.status_code = 403
            response.text = "Forbidden"
        else:
            response.status_code = 200
            response.text = '{"admin":true,"users":[1]}'
        return response


class FakeBootstrapper:
    def __init__(self, *args, **kwargs) -> None:
        self.calls = []

    def bootstrap_authenticated_session(self, role: str, credentials: dict, *, cache_key: str | None = None):
        from chimera_core.shannon.session import AuthToken, BrowserSession

        self.calls.append((role, credentials, cache_key))
        suffix = "a" if str(cache_key or role).endswith("_a") else "b"
        return BrowserSession(
            session_id=f"{cache_key or role}-session",
            role="low_privilege",
            cookies={"sid": suffix},
            headers={"Authorization": f"Bearer token-{suffix}"},
            tokens=[AuthToken(type="JWT", value=f"token-{suffix}", source="test")],
            storage={"token": f"token-{suffix}"},
        )


def test_shannon_exploit_mode_persists_exploit_result_artifact(tmp_path: Path) -> None:
    adapter = make_adapter(
        tmp_path=tmp_path,
        options={
            "agent_flow": True,
            "live": True,
            "driver": "http",
            "base_url": "http://shannon:8080",
            "http_client": AgentTypedClient(),
            "agent_role": "exploit",
            "mode": "exploit",
            "exploit_http_client": ExploitHTTPClient(),
            "session_bootstrapper": FakeBootstrapper(),
            "bootstrap_credentials": [{"email": "user1@example.com"}, {"email": "user2@example.com"}],
            "intent": "Exploit admin surface",
        },
    )

    result = adapter.run(["https://example.com"])

    exploit_path = tmp_path / "artifacts" / "run-321" / "exploits" / "cand-typed" / "exploit_result.json"
    assert exploit_path.exists()
    raw = json.loads(result["raw_output_refs"][0])
    assert raw["candidates"][0]["metadata"]["exploit_result"]["classification"] == "EXPLOITED"
    assert raw["candidates"][0]["metadata"]["exploit_result_ref"] == "exploits/cand-typed/exploit_result.json"
    assert result["candidate_findings"][0].metadata["exploit_result"]["classification"] == "EXPLOITED"
    assert result["candidate_findings"][0].metadata["exploit_result_ref"] == "exploits/cand-typed/exploit_result.json"
    events = list(adapter.runtime.event_store.replay())
    event_types = [event["event_type"] for event in events]
    assert "exploit_attempted" in event_types
    assert "exploit_classified" in event_types
    assert "exploit_result_saved" in event_types


def json_payload() -> dict:
    return {
        "status": "completed",
        "result": {
            "findings": [
                {
                    "title": "Reflected XSS",
                    "description": "Payload executed in the browser.",
                    "severity": "high",
                    "target": "https://example.com/search",
                    "evidence_refs": ["xss-proof.html"],
                }
            ]
        },
    }

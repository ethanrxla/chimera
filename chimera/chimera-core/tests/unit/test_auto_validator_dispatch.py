"""
TDD tests for auto-validator dispatch in PlanRunner.

RED → GREEN targets:
- IDOR finding from Shannon triggers bola_validator injection.
- JWT finding triggers jwt_validator injection.
- RATE_LIMIT finding triggers rate_limit_validator injection.
- Multiple IDOR findings result in exactly one bola_validator (no duplicates).
- Pre-wired validator prevents a second injection of the same type.
- HYPOTHESIS finding_type produces no injection.
"""
import json
from pathlib import Path

import httpx
import pytest

from chimera_core.event_store import EventStore
from chimera_core.plan import ExecutionPlan, Task
from chimera_core.runner import PlanRunner
from chimera_core.runtime import Runtime
from chimera_core.scope import ScopeGraph, ScopePolicy


def make_runtime(tmp_path: Path) -> Runtime:
    scope_manifest = {"allowlist": ["api.example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    run_id = "run-dispatch"
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


def _shannon_fixture(tmp_path: Path, findings: list) -> Path:
    """Write a Shannon-style fixture JSON and return its path."""
    f = tmp_path / "shannon_fixture.json"
    f.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return f


TARGET = "https://api.example.com/users/7"


# ---------------------------------------------------------------------------
# Test 1: IDOR → bola_validator
# ---------------------------------------------------------------------------

def test_idor_finding_triggers_bola_validator(tmp_path: Path):
    """
    When Shannon returns an IDOR finding, PlanRunner must automatically inject
    a bola_validator task and execute it, producing a completed result.
    """
    fixture = _shannon_fixture(tmp_path, [
        {
            "title": "IDOR on profile endpoint",
            "severity": "high",
            "target": TARGET,
            "description": "BOLA on /api/users/7 allows accessing another user's record.",
            "repro_guidance": "GET /api/users/2 with user-1 token.",
        }
    ])

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 7, "email": "user@example.com"}, request=request)

    transport = httpx.MockTransport(handler)
    plan = ExecutionPlan()
    plan.add_task(Task("S1", "shannon", TARGET, {"live": False, "http_transport": transport}))

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(
        runtime=runtime,
        max_workers=1,
        stop_on_fail=False,
        fixture_registry={"shannon": str(fixture)},
    )
    results = runner.execute(plan)

    result_map = {r.task_id: r for r in results}
    injected = [r for r in results if r.task_id.startswith("auto-validate:bola_validator:")]

    assert injected, (
        "Expected a bola_validator task to be auto-injected after IDOR finding; "
        f"got task_ids: {list(result_map.keys())}"
    )
    assert injected[0].status == "completed", (
        f"Auto-injected bola_validator must complete; got status={injected[0].status}"
    )


# ---------------------------------------------------------------------------
# Test 2: JWT → jwt_validator
# ---------------------------------------------------------------------------

def test_jwt_finding_triggers_jwt_validator(tmp_path: Path):
    """
    When Shannon returns a JWT finding, PlanRunner must inject a jwt_validator task.
    """
    fixture = _shannon_fixture(tmp_path, [
        {
            "title": "JWT alg:none accepted",
            "severity": "critical",
            "target": TARGET,
            "description": "The API accepts JWT tokens with alg:none, bypassing signature verification.",
            "repro_guidance": (
                "Craft a JWT with alg:none: "
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."
            ),
        }
    ])

    plan = ExecutionPlan()
    plan.add_task(Task("S1", "shannon", TARGET, {"live": False}))

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(
        runtime=runtime,
        max_workers=1,
        stop_on_fail=False,
        fixture_registry={"shannon": str(fixture)},
    )
    results = runner.execute(plan)

    injected = [r for r in results if r.task_id.startswith("auto-validate:jwt_validator:")]
    assert injected, (
        "Expected jwt_validator task auto-injected after JWT finding; "
        f"got task_ids: {[r.task_id for r in results]}"
    )
    assert injected[0].status == "completed"


# ---------------------------------------------------------------------------
# Test 3: RATE_LIMIT → rate_limit_validator
# ---------------------------------------------------------------------------

def test_rate_limit_finding_triggers_rate_limit_validator(tmp_path: Path):
    """
    When Shannon returns a RATE_LIMIT finding, PlanRunner must inject
    a rate_limit_validator task.
    """
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok", request=request)

    transport = httpx.MockTransport(handler)

    fixture = _shannon_fixture(tmp_path, [
        {
            "title": "No rate limiting on login endpoint",
            "severity": "medium",
            "target": TARGET,
            "description": "The login endpoint has no rate limit — brute force is possible.",
            "repro_guidance": "Send 50 rapid POST requests; all succeed.",
        }
    ])

    plan = ExecutionPlan()
    plan.add_task(Task("S1", "shannon", TARGET, {
        "live": False,
        "http_transport": transport,
    }))

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(
        runtime=runtime,
        max_workers=1,
        stop_on_fail=False,
        fixture_registry={"shannon": str(fixture)},
    )
    results = runner.execute(plan)

    injected = [r for r in results if r.task_id.startswith("auto-validate:rate_limit_validator:")]
    assert injected, (
        "Expected rate_limit_validator task auto-injected after RATE_LIMIT finding; "
        f"got task_ids: {[r.task_id for r in results]}"
    )
    assert injected[0].status == "completed"


# ---------------------------------------------------------------------------
# Test 4: Multiple IDOR findings → only one bola_validator injected
# ---------------------------------------------------------------------------

def test_no_duplicate_validator_for_multiple_idor_findings(tmp_path: Path):
    """
    Two IDOR findings from the same Shannon task must produce exactly one
    auto-injected bola_validator, not two.
    """
    fixture = _shannon_fixture(tmp_path, [
        {
            "title": "IDOR on user profile",
            "severity": "high",
            "target": TARGET,
            "description": "BOLA on /api/users/7.",
            "repro_guidance": "GET /api/users/2 with user-1 token.",
        },
        {
            "title": "IDOR on orders endpoint",
            "severity": "high",
            "target": "https://api.example.com/orders/3",
            "description": "BOLA — accessing another user's order via ID.",
            "repro_guidance": "GET /api/orders/1 with user-2 token.",
        },
    ])

    plan = ExecutionPlan()
    plan.add_task(Task("S1", "shannon", TARGET, {"live": False}))

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(
        runtime=runtime,
        max_workers=1,
        stop_on_fail=False,
        fixture_registry={"shannon": str(fixture)},
    )
    results = runner.execute(plan)

    bola_results = [r for r in results if r.task_id.startswith("auto-validate:bola_validator:")]
    assert len(bola_results) == 1, (
        f"Expected exactly 1 auto-injected bola_validator, got {len(bola_results)}: "
        f"{[r.task_id for r in bola_results]}"
    )


# ---------------------------------------------------------------------------
# Test 5: Validator already in plan → no duplicate injection
# ---------------------------------------------------------------------------

def test_no_injection_when_validator_already_in_plan(tmp_path: Path):
    """
    If bola_validator is already wired in the plan, the auto-dispatch must not
    inject a second one after Shannon returns an IDOR finding.
    """
    fixture = _shannon_fixture(tmp_path, [
        {
            "title": "IDOR on user profile",
            "severity": "high",
            "target": TARGET,
            "description": "BOLA on /api/users/7.",
            "repro_guidance": "GET /api/users/2 with user-1 token.",
        }
    ])

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 7}, request=request)

    transport = httpx.MockTransport(handler)
    plan = ExecutionPlan()
    plan.add_task(Task("S1", "shannon", TARGET, {"live": False}))
    plan.add_task(Task(
        "V1",
        "bola_validator",
        TARGET,
        {
            "validation_inputs": {
                "target_endpoint": TARGET,
                "object_id": "7",
                "user_a_creds": {"token": "owner-token"},
                "user_b_creds": {"token": "peer-token"},
            },
            "http_transport": transport,
        },
    ))
    plan.add_dependency("S1", "V1")

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(
        runtime=runtime,
        max_workers=1,
        stop_on_fail=False,
        fixture_registry={"shannon": str(fixture)},
    )
    results = runner.execute(plan)

    # Pre-wired task ran (its task_id is "V1", not "auto-validate:...")
    v1_results = [r for r in results if r.task_id == "V1"]
    assert len(v1_results) == 1, (
        f"Expected pre-wired V1 task in results; got task_ids: {[r.task_id for r in results]}"
    )
    # No auto-injection occurred because bola_validator was already in the plan
    auto_injected = [r for r in results if r.task_id.startswith("auto-validate:bola_validator:")]
    assert not auto_injected, (
        f"Auto-injection must not duplicate a pre-wired validator; got: {[r.task_id for r in auto_injected]}"
    )


# ---------------------------------------------------------------------------
# Test 6: HYPOTHESIS finding_type → no injection
# ---------------------------------------------------------------------------

def test_hypothesis_finding_type_no_injection(tmp_path: Path):
    """
    A finding with HYPOTHESIS finding_type (no matching validator) must not
    trigger any auto-validator injection.
    """
    # A finding title/description that doesn't match any IDOR/JWT/RATE_LIMIT/AUTH keyword
    fixture = _shannon_fixture(tmp_path, [
        {
            "title": "Possible information disclosure",
            "severity": "low",
            "target": TARGET,
            "description": "The API may expose internal stack traces.",
            "repro_guidance": "Send malformed request and observe verbose error.",
        }
    ])

    plan = ExecutionPlan()
    plan.add_task(Task("S1", "shannon", TARGET, {"live": False}))

    runtime = make_runtime(tmp_path)
    runner = PlanRunner(
        runtime=runtime,
        max_workers=1,
        stop_on_fail=False,
        fixture_registry={"shannon": str(fixture)},
    )
    results = runner.execute(plan)

    auto_results = [r for r in results if r.task_id.startswith("auto-validate:")]
    assert not auto_results, (
        f"Expected no auto-injected validator for HYPOTHESIS finding; "
        f"got: {[r.task_id for r in auto_results]}"
    )

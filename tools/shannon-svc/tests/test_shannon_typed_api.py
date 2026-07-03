import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

from test_shannon_robustness import _reload_main


SHANNON_SVC_DIR = Path(__file__).resolve().parents[1]
if str(SHANNON_SVC_DIR) not in sys.path:
    sys.path.insert(0, str(SHANNON_SVC_DIR))


def test_plan_endpoint_returns_verification_plan() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_PLANNER_MODEL": "qwen2.5-coder:7b",
            "SHANNON_EXECUTOR_MODEL": "qwen2.5-coder:7b",
            "SHANNON_VALIDATOR_MODEL": "qwen2.5-coder:7b",
        }
    )
    with patch.object(module, "_plan_verification", return_value={
        "verification_plan": {
            "verification_id": "ver-1",
            "candidate_id": "cand-1",
            "target": "https://example.com",
            "claim_type": "open_redirect",
            "checks": [],
            "required_artifact_kinds": ["http_request"],
            "planner_notes": "none",
        },
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }):
        response = asyncio.run(module.plan_verification(module.PlanRequest(**{
            "run_id": "run-1",
            "candidate": {
                "candidate_id": "cand-1",
                "source": "strix",
                "title": "Open Redirect",
                "claim_type": "open_redirect",
                "severity_claimed": "medium",
                "endpoint": "/login",
                "target": "https://example.com/login",
            },
            "prior_evidence_refs": [],
            "scope_summary": {"allowlist": ["https://example.com"]},
        })))
    assert response["verification_plan"]["claim_type"] == "open_redirect"


def test_plan_endpoint_uses_llm_output_when_available() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_PLANNER_MODEL": "qwen2.5-coder:7b",
            "SHANNON_EXECUTOR_MODEL": "qwen2.5-coder:7b",
            "SHANNON_VALIDATOR_MODEL": "qwen2.5-coder:7b",
        }
    )
    plan_json = json.dumps(
        {
            "verification_id": "ver-1",
            "candidate_id": "cand-1",
            "target": "https://example.com/login",
            "claim_type": "open_redirect",
            "checks": [],
            "required_artifact_kinds": ["http_request"],
            "planner_notes": "llm plan",
        }
    )
    with patch.object(module, "_call_model", return_value=(plan_json, {"total_tokens": 5})):
        response = asyncio.run(module.plan_verification(module.PlanRequest(**{
            "run_id": "run-1",
            "candidate": {
                "candidate_id": "cand-1",
                "source": "strix",
                "title": "Open Redirect",
                "claim_type": "open_redirect",
                "severity_claimed": "medium",
                "endpoint": "/login",
                "target": "https://example.com/login",
            },
            "prior_evidence_refs": [],
            "scope_summary": {"allowlist": ["https://example.com"]},
        })))
    assert response["verification_plan"]["planner_notes"] == "llm plan"


def test_validate_endpoint_returns_validator_decision() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_PLANNER_MODEL": "qwen2.5-coder:7b",
            "SHANNON_EXECUTOR_MODEL": "qwen2.5-coder:7b",
            "SHANNON_VALIDATOR_MODEL": "qwen2.5-coder:7b",
        }
    )
    with patch.object(module, "_validate_verification", return_value={
        "decision": {
            "status": "verified",
            "final_claim_type": "open_redirect",
            "severity": "medium",
            "rationale": "verifier passed",
            "duplicate_of": None,
            "required_evidence_refs_present": True,
        },
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }):
        response = asyncio.run(module.validate_verification(module.ValidateRequest(**{
            "run_id": "run-1",
            "candidate": {
                "candidate_id": "cand-1",
                "source": "strix",
                "title": "Open Redirect",
                "claim_type": "open_redirect",
                "severity_claimed": "medium",
                "endpoint": "/login",
                "target": "https://example.com/login",
            },
            "verification_results": [
                {
                    "verification_id": "ver-1",
                    "check_id": "check-1",
                    "claim_type": "open_redirect",
                    "outcome": "passed",
                    "rationale": "redirect matched",
                    "evidence_refs": ["artifacts/run-1/response.json"],
                }
            ],
            "evidence_refs": ["artifacts/run-1/response.json"],
            "prior_findings": [],
        })))
    assert response["decision"]["status"] == "verified"


def test_validate_endpoint_uses_llm_output_when_available() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_PLANNER_MODEL": "qwen2.5-coder:7b",
            "SHANNON_EXECUTOR_MODEL": "qwen2.5-coder:7b",
            "SHANNON_VALIDATOR_MODEL": "qwen2.5-coder:7b",
        }
    )
    decision_json = json.dumps(
        {
            "status": "verified",
            "final_claim_type": "open_redirect",
            "severity": "medium",
            "rationale": "validator accepted",
            "duplicate_of": None,
            "required_evidence_refs_present": True,
        }
    )
    with patch.object(module, "_call_model", return_value=(decision_json, {"total_tokens": 5})):
        response = asyncio.run(module.validate_verification(module.ValidateRequest(**{
            "run_id": "run-1",
            "candidate": {
                "candidate_id": "cand-1",
                "source": "strix",
                "title": "Open Redirect",
                "claim_type": "open_redirect",
                "severity_claimed": "medium",
                "endpoint": "/login",
                "target": "https://example.com/login",
            },
            "verification_results": [
                {
                    "verification_id": "ver-1",
                    "check_id": "check-1",
                    "claim_type": "open_redirect",
                    "outcome": "passed",
                    "rationale": "redirect matched",
                    "evidence_refs": ["artifacts/run-1/response.json"],
                }
            ],
            "evidence_refs": ["artifacts/run-1/response.json"],
            "prior_findings": [],
        })))
    assert response["decision"]["rationale"] == "validator accepted"


def test_fallback_plan_uses_concrete_endpoint_url() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_PLANNER_MODEL": "qwen2.5-coder:7b",
            "SHANNON_EXECUTOR_MODEL": "qwen2.5-coder:7b",
            "SHANNON_VALIDATOR_MODEL": "qwen2.5-coder:7b",
        }
    )
    response = module._fallback_plan_verification(
        "run-1",
        {
            "candidate_id": "cand-1",
            "source": "strix",
            "title": "Open Redirect",
            "claim_type": "open_redirect",
            "severity_claimed": "medium",
            "endpoint": "/auth/signin",
            "target": "https://scholarcal.com",
        },
        [],
        {"allowlist": ["scholarcal.com"]},
    )
    plan = response["verification_plan"]
    assert plan["target"] == "https://scholarcal.com/auth/signin"
    assert plan["checks"][0]["probe_input"]["url"] == "https://scholarcal.com/auth/signin"


def test_fallback_plan_routes_idor_by_verifier_hint() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_PLANNER_MODEL": "qwen2.5-coder:7b",
            "SHANNON_EXECUTOR_MODEL": "qwen2.5-coder:7b",
            "SHANNON_VALIDATOR_MODEL": "qwen2.5-coder:7b",
        }
    )
    response = module._fallback_plan_verification(
        "run-1",
        {
            "candidate_id": "cand-1",
            "source": "shannon-agent",
            "title": "Potential IDOR on /rest/basket/1",
            "claim_type": "idor",
            "severity_claimed": "medium",
            "endpoint": "/rest/basket/1",
            "target": "http://juice-shop:3000",
            "metadata": {"verifier_hint": "probe_idor"},
        },
        [],
        {"allowlist": ["juice-shop"]},
    )
    check = response["verification_plan"]["checks"][0]
    assert check["probe_type"] == "http_idor_check"
    assert check["probe_input"]["url"] == "http://juice-shop:3000/rest/basket/2"


def test_fallback_plan_routes_api_surface_by_verifier_hint() -> None:
    module = _reload_main(
        {
            "SHANNON_PROVIDER": "openai_compatible",
            "SHANNON_PLANNER_MODEL": "qwen2.5-coder:7b",
            "SHANNON_EXECUTOR_MODEL": "qwen2.5-coder:7b",
            "SHANNON_VALIDATOR_MODEL": "qwen2.5-coder:7b",
        }
    )
    response = module._fallback_plan_verification(
        "run-1",
        {
            "candidate_id": "cand-1",
            "source": "shannon-agent",
            "title": "API surface exposed",
            "claim_type": "api_surface_exposure",
            "severity_claimed": "medium",
            "endpoint": "/openapi.json",
            "target": "http://juice-shop:3000",
            "metadata": {"verifier_hint": "probe_api_surface"},
        },
        [],
        {"allowlist": ["juice-shop"]},
    )
    check = response["verification_plan"]["checks"][0]
    assert check["probe_type"] == "http_api_surface_check"
    assert check["success_condition"]["type"] == "api_surface_exposure"

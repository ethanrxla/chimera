import pytest

from chimera_core.hexstrike.policy import HexStrikePolicy
from chimera_core.scope import ScopeGraph


def make_scope_graph() -> ScopeGraph:
    return ScopeGraph({"allowlist": ["https://example.com"], "denylist": []})


def test_policy_allows_curated_shannon_executor_tools() -> None:
    policy = HexStrikePolicy()

    policy.validate_call(
        agent="shannon_executor",
        tool_name="probe",
        params={"endpoint": "https://example.com/login", "method": "GET"},
        scope_graph=make_scope_graph(),
    )


def test_policy_blocks_dangerous_tool_for_shannon_executor() -> None:
    policy = HexStrikePolicy()

    with pytest.raises(PermissionError):
        policy.validate_call(
            agent="shannon_executor",
            tool_name="command",
            params={"command": "id"},
            scope_graph=make_scope_graph(),
        )


def test_policy_rejects_out_of_scope_targets() -> None:
    policy = HexStrikePolicy()

    with pytest.raises(ValueError):
        policy.validate_call(
            agent="shannon_executor",
            tool_name="probe",
            params={"endpoint": "https://evil.com/login", "method": "GET"},
            scope_graph=make_scope_graph(),
        )

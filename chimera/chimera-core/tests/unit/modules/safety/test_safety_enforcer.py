import pytest

from chimera_core.modules.safety.policy import SafetyPolicy
from chimera_core.modules.safety.enforcer import SafetyEnforcer, SafetyPolicyViolation
from chimera_core.modules.runtime.tool_profile import ToolProfile


def test_blocks_external_exec_when_tool_not_allowed():
    policy = SafetyPolicy(allowed_tools=frozenset({"allowed"}))
    enforcer = SafetyEnforcer(policy)
    with pytest.raises(SafetyPolicyViolation):
        enforcer.check_before_external_exec(
            tool="blocked",
            cmd=["blocked"],
            mode="fixture",
            scope_ok=True,
            timeout_s=30,
        )


def test_blocks_external_exec_when_live_confirm_missing():
    policy = SafetyPolicy(require_live_confirm=True, live_confirm_token=None, allowed_tools=frozenset({"zypheron"}))
    enforcer = SafetyEnforcer(policy)
    with pytest.raises(SafetyPolicyViolation):
        enforcer.check_before_external_exec(
            tool="zypheron",
            cmd=["zypheron"],
            mode="live",
            scope_ok=True,
            timeout_s=30,
        )


def test_blocks_destructive_when_not_allowed():
    policy = SafetyPolicy(allow_destructive=False, allowed_tools=frozenset({"scanner"}))
    enforcer = SafetyEnforcer(policy)
    with pytest.raises(SafetyPolicyViolation):
        enforcer.check_before_external_exec(
            tool="scanner",
            cmd=["sqlmap", "-u", "https://example.com"],
            mode="fixture",
            scope_ok=True,
            timeout_s=30,
        )


def test_allows_non_destructive_when_live_confirm_ok():
    policy = SafetyPolicy(require_live_confirm=True, live_confirm_token="I UNDERSTAND", allowed_tools=frozenset({"zypheron"}))
    enforcer = SafetyEnforcer(policy)
    timeout = enforcer.check_before_external_exec(
        tool="zypheron",
        cmd=["zypheron", "scan", "example.com"],
        mode="live",
        scope_ok=True,
        timeout_s=30,
    )
    assert timeout == 30


def test_timeout_is_capped():
    policy = SafetyPolicy(timeout_s=60, allowed_tools=frozenset({"zypheron"}))
    enforcer = SafetyEnforcer(policy)
    profile = ToolProfile(name="zypheron", max_timeout_s=45)
    timeout = enforcer.check_before_external_exec(
        tool="zypheron",
        cmd=["zypheron", "scan", "example.com"],
        mode="fixture",
        scope_ok=True,
        timeout_s=120,
        tool_profile=profile,
    )
    assert timeout == 45

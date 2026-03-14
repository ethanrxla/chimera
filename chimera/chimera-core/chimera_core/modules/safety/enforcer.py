from dataclasses import dataclass
from typing import List, Optional

from chimera_core.modules.safety.policy import SafetyPolicy
from chimera_core.modules.runtime.tool_profile import ToolProfile


class SafetyPolicyViolation(ValueError):
    pass


@dataclass(frozen=True)
class SafetyEnforcer:
    policy: SafetyPolicy

    def check_before_external_exec(
        self,
        *,
        tool: str,
        cmd: List[str],
        mode: str,
        scope_ok: bool,
        timeout_s: Optional[int],
        tool_profile: Optional[ToolProfile] = None,
    ) -> int:
        tool_name = tool.lower()
        if not self.policy.allow_external_execution:
            raise SafetyPolicyViolation("External execution disabled by policy")

        if self.policy.allowed_tools and tool_name not in self.policy.allowed_tools:
            raise SafetyPolicyViolation(f"Tool not allowed: {tool_name}")

        if tool_name in self.policy.blocked_tools:
            raise SafetyPolicyViolation(f"Tool blocked: {tool_name}")

        if self.policy.enforce_scope and not scope_ok:
            raise SafetyPolicyViolation("Scope enforcement blocked external execution")

        if mode == "live" and self.policy.require_live_confirm and not self.policy.live_confirm_token:
            raise SafetyPolicyViolation("Live confirmation required")

        destructive = False
        if tool_profile and tool_profile.is_destructive:
            destructive = True
        else:
            lowered_cmd = " ".join(cmd).lower()
            if any(marker in lowered_cmd for marker in self.policy.destructive_tool_markers):
                destructive = True

        if destructive and not self.policy.allow_destructive:
            raise SafetyPolicyViolation("Destructive tool usage blocked")

        effective_timeout = timeout_s or self.policy.timeout_s
        if effective_timeout > self.policy.timeout_s:
            effective_timeout = self.policy.timeout_s

        if tool_profile:
            if effective_timeout > tool_profile.max_timeout_s:
                effective_timeout = tool_profile.max_timeout_s

        return int(effective_timeout)

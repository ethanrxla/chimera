from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional
from urllib.parse import urlparse

import yaml


PolicyDecisionKind = Literal["allow", "defer", "deny"]


@dataclass(frozen=True)
class ToolCall:
    tool: str
    target: str | None = None
    action_class: str = "passive"
    risk_class: str | None = None
    method: str | None = None
    command: list[str] = field(default_factory=list)
    browser_actions: list[str] = field(default_factory=list)
    has_env_vars: bool = False
    file_upload: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "action_class": self.action_class,
            "risk_class": self.risk_class,
            "method": self.method,
            "command": list(self.command),
            "browser_actions": list(self.browser_actions),
            "has_env_vars": self.has_env_vars,
            "file_upload": self.file_upload,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class ExecutionContext:
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
    runtime_mode: str = "live"

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowlist": list(self.allowlist),
            "denylist": list(self.denylist),
            "allowed_methods": list(self.allowed_methods),
            "runtime_mode": self.runtime_mode,
        }


@dataclass(frozen=True)
class PolicyDecision:
    decision: PolicyDecisionKind
    reason: str
    matched_rule: str
    require_approval_if_deferred: bool = False
    target_scope: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "require_approval_if_deferred": self.require_approval_if_deferred,
            "target_scope": self.target_scope,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PolicyRule:
    name: str
    decision: PolicyDecisionKind
    reason: str
    tools: frozenset[str] | None = None
    action_classes: frozenset[str] | None = None
    methods: frozenset[str] | None = None
    target_scopes: frozenset[str] | None = None
    has_env_vars: bool | None = None
    file_upload: bool | None = None
    browser_actions_any: frozenset[str] | None = None
    command_binaries: frozenset[str] | None = None
    require_approval_if_deferred: bool = False

    def matches(self, call: ToolCall, *, target_scope: str) -> bool:
        method = (call.method or "").upper()
        if self.tools is not None and call.tool not in self.tools:
            return False
        if self.action_classes is not None and call.action_class not in self.action_classes:
            return False
        if self.methods is not None and method not in self.methods:
            return False
        if self.target_scopes is not None and target_scope not in self.target_scopes:
            return False
        if self.has_env_vars is not None and call.has_env_vars is not self.has_env_vars:
            return False
        if self.file_upload is not None and call.file_upload is not self.file_upload:
            return False
        if self.browser_actions_any is not None and not (set(call.browser_actions) & set(self.browser_actions_any)):
            return False
        if self.command_binaries is not None:
            binary = Path(call.command[0]).name if call.command else ""
            if binary not in self.command_binaries:
                return False
        return True


def _normalize_host(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlparse(value)
        if parsed.hostname:
            return parsed.hostname.lower()
    except Exception:
        pass
    return value.split("/", 1)[0].lower()


def _target_scope(target: Optional[str], context: ExecutionContext) -> str:
    if not target:
        return "in_scope" if not context.allowlist else "unknown"
    host = _normalize_host(target)
    if not host:
        return "unknown"
    denied = any(denied.lower() in host for denied in context.denylist)
    if denied:
        return "denylist"
    if not context.allowlist:
        return "in_scope"
    for entry in context.allowlist:
        allowed = _normalize_host(entry)
        if host == allowed or host.endswith(f".{allowed}"):
            return "in_scope"
    return "out_of_scope"


class PolicyKernel:
    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self.rules = rules or self.default_rules()

    @classmethod
    def from_path(cls, path: str | Path | None) -> "PolicyKernel":
        if not path:
            return cls()
        config_path = Path(path)
        if not config_path.exists():
            return cls()
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        rules = []
        for item in list(data.get("policies") or []):
            if not isinstance(item, dict):
                continue
            match = dict(item.get("match") or {})
            rules.append(
                PolicyRule(
                    name=str(item.get("name") or "unnamed"),
                    decision=str(item.get("decision") or "deny"),
                    reason=str(item.get("reason") or item.get("question") or "policy decision"),
                    tools=frozenset(str(value) for value in list(match.get("tool") or [])) or None,
                    action_classes=frozenset(str(value) for value in list(match.get("action_class") or [])) or None,
                    methods=frozenset(str(value).upper() for value in list(match.get("method") or [])) or None,
                    target_scopes=frozenset(str(value) for value in list(match.get("target_scope") or [])) or None,
                    has_env_vars=match.get("has_env_vars"),
                    file_upload=match.get("file_upload"),
                    browser_actions_any=frozenset(str(value) for value in list(match.get("browser_action") or [])) or None,
                    command_binaries=frozenset(str(value) for value in list(match.get("command_binary") or [])) or None,
                    require_approval_if_deferred=bool(item.get("decision") == "defer"),
                )
            )
        return cls(rules=rules or None)

    @staticmethod
    def default_rules() -> list[PolicyRule]:
        return [
            PolicyRule(
                name="deny-out-of-scope",
                decision="deny",
                reason="Target is outside the authorized scope.",
                target_scopes=frozenset({"out_of_scope", "denylist"}),
            ),
            PolicyRule(
                name="deny-exploit-like",
                decision="deny",
                reason="Exploit-like execution is blocked by policy.",
                action_classes=frozenset({"exploit_like"}),
            ),
            PolicyRule(
                name="defer-state-changing-http",
                decision="defer",
                reason="This HTTP action may change application state and requires approval.",
                methods=frozenset({"POST", "PUT", "PATCH", "DELETE"}),
                target_scopes=frozenset({"in_scope"}),
                require_approval_if_deferred=True,
            ),
            PolicyRule(
                name="defer-browser-mutation",
                decision="defer",
                reason="Interactive browser mutations require approval.",
                tools=frozenset({"browser"}),
                browser_actions_any=frozenset({"click", "fill", "execute_js"}),
                target_scopes=frozenset({"in_scope"}),
                require_approval_if_deferred=True,
            ),
            PolicyRule(
                name="defer-file-upload",
                decision="defer",
                reason="File uploads require explicit approval.",
                file_upload=True,
                target_scopes=frozenset({"in_scope"}),
                require_approval_if_deferred=True,
            ),
            PolicyRule(
                name="defer-zap-active-scan",
                decision="defer",
                reason="Active ZAP actions require approval.",
                tools=frozenset({"zap"}),
                action_classes=frozenset({"active_scan", "state_changing"}),
                target_scopes=frozenset({"in_scope", "unknown"}),
                require_approval_if_deferred=True,
            ),
            PolicyRule(
                name="defer-shell-env",
                decision="defer",
                reason="Shell commands carrying environment-variable style inputs require approval.",
                tools=frozenset({"shell"}),
                has_env_vars=True,
                require_approval_if_deferred=True,
            ),
            PolicyRule(
                name="defer-terminal-env",
                decision="defer",
                reason="Terminal sessions carrying environment-variable style inputs require approval.",
                tools=frozenset({"terminal"}),
                has_env_vars=True,
                require_approval_if_deferred=True,
            ),
            PolicyRule(
                name="allow-passive-browser",
                decision="allow",
                reason="Read-only browser activity is allowed.",
                tools=frozenset({"browser"}),
                action_classes=frozenset({"passive", "low_impact"}),
                target_scopes=frozenset({"in_scope", "unknown"}),
            ),
            PolicyRule(
                name="allow-passive-zap",
                decision="allow",
                reason="Passive ZAP activity is allowed.",
                tools=frozenset({"zap"}),
                action_classes=frozenset({"passive", "low_impact"}),
                target_scopes=frozenset({"in_scope", "unknown"}),
            ),
            PolicyRule(
                name="allow-low-impact-http",
                decision="allow",
                reason="In-scope read-oriented HTTP probing is allowed.",
                methods=frozenset({"GET", "HEAD", "OPTIONS"}),
                target_scopes=frozenset({"in_scope", "unknown"}),
            ),
            PolicyRule(
                name="allow-low-impact-shell",
                decision="allow",
                reason="Allowlisted read-oriented shell commands are allowed.",
                tools=frozenset({"shell"}),
                action_classes=frozenset({"passive", "low_impact"}),
                has_env_vars=False,
                target_scopes=frozenset({"in_scope", "unknown"}),
            ),
            PolicyRule(
                name="allow-low-impact-terminal",
                decision="allow",
                reason="Allowlisted mediated terminal activity is allowed.",
                tools=frozenset({"terminal"}),
                action_classes=frozenset({"passive", "low_impact"}),
                has_env_vars=False,
                target_scopes=frozenset({"in_scope", "unknown"}),
            ),
        ]

    def evaluate(self, call: ToolCall, context: ExecutionContext) -> PolicyDecision:
        target_scope = _target_scope(call.target, context)
        method = (call.method or "").upper()
        if method and context.allowed_methods and method not in {item.upper() for item in context.allowed_methods}:
            return PolicyDecision(
                decision="deny",
                reason=f"HTTP method {method} is not allowed by scope policy.",
                matched_rule="deny-disallowed-method",
                target_scope=target_scope,
            )
        for rule in self.rules:
            if rule.matches(call, target_scope=target_scope):
                return PolicyDecision(
                    decision=rule.decision,
                    reason=rule.reason,
                    matched_rule=rule.name,
                    require_approval_if_deferred=rule.require_approval_if_deferred,
                    target_scope=target_scope,
                )
        fallback = "allow" if target_scope in {"in_scope", "unknown"} else "deny"
        return PolicyDecision(
            decision=fallback,
            reason="Default policy fallback.",
            matched_rule="default-fallback",
            target_scope=target_scope,
        )

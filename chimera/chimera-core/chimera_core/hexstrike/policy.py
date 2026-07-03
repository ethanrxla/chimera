from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from chimera_core.hexstrike.catalog import HexStrikeToolSpec, get_tool_spec
from chimera_core.target_extraction import extract_targets_from_params


@dataclass
class HexStrikePolicy:
    allow_dangerous: bool = False

    def validate_call(self, *, agent: str, tool_name: str, params: Dict[str, object], scope_graph) -> List[str]:
        spec = get_tool_spec(tool_name)
        self._validate_agent_access(agent, spec)
        targets = self._extract_targets(spec, params)
        self._validate_scope(targets, scope_graph)
        return targets

    def _validate_agent_access(self, agent: str, spec: HexStrikeToolSpec) -> None:
        if agent not in spec.allowed_agents:
            raise PermissionError(f"Agent '{agent}' may not use HexStrike tool '{spec.tool_name}'")
        if spec.risk_tier == "dangerous" and not self.allow_dangerous:
            raise PermissionError(f"HexStrike tool '{spec.tool_name}' is dangerous and disabled by policy")

    def _extract_targets(self, spec: HexStrikeToolSpec, params: Dict[str, object]) -> List[str]:
        return extract_targets_from_params(params, spec.target_fields)

    def _validate_scope(self, targets: List[str], scope_graph) -> None:
        for target in targets:
            if not scope_graph.is_in_scope(target):
                raise ValueError(f"HexStrike target out of scope: {target}")

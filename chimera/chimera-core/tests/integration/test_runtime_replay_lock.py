from pathlib import Path

import pytest

from chimera_core.event_store import EventStore
from chimera_core.runtime import Runtime, RuntimeReplayViolation
from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.modules.safety.policy import SafetyPolicy
from chimera_core.modules.runtime.tool_profile import ToolProfile


def test_replay_lock_blocks_external_exec(tmp_path: Path):
    scope_manifest = {"allowlist": ["example.com"], "denylist": []}
    scope_graph = ScopeGraph(scope_manifest)
    scope_policy = ScopePolicy(scope_manifest)
    artifacts_root = tmp_path / "artifacts"
    artifacts_root.mkdir(parents=True, exist_ok=True)
    event_store = EventStore(tmp_path / "events.jsonl")

    policy = SafetyPolicy(allow_external_execution=True, allowed_tools=frozenset({"zypheron"}))
    runtime = Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=event_store,
        artifacts_root=artifacts_root,
        run_id="replay-run",
        replay_mode=True,
        safety_policy=policy,
        mode="fixture",
    )

    with pytest.raises(RuntimeReplayViolation):
        runtime.run_external_tool(
            ["zypheron", "scan", "example.com"],
            tool_profile=ToolProfile(name="zypheron"),
            mode="fixture",
            timeout_s=10,
        )

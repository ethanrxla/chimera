from dataclasses import dataclass
from typing import FrozenSet, Optional


@dataclass(frozen=True)
class SafetyPolicy:
    enforce_scope: bool = True
    enforce_scope_hash: bool = True

    # External execution controls
    allow_external_execution: bool = True
    allowed_tools: FrozenSet[str] = frozenset({"zypheron", "vibepentester", "decepticon"})
    blocked_tools: FrozenSet[str] = frozenset()

    # Live safety confirmations
    require_live_confirm: bool = True
    live_confirm_token: Optional[str] = None

    # Destructive actions (OFF by default)
    allow_destructive: bool = False
    destructive_tool_markers: FrozenSet[str] = frozenset({"sqlmap", "ffuf", "hydra"})

    # Rate/concurrency (global caps)
    max_workers: int = 2
    rps: float = 10.0
    timeout_s: int = 60

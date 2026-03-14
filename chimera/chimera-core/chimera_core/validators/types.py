from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ValidationResult:
    status: str
    confidence: float
    proof_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    replay_steps: List[Dict[str, Any]] = field(default_factory=list)
    explanation: str = ""

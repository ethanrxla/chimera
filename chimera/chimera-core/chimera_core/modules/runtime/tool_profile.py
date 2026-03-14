from dataclasses import dataclass


@dataclass(frozen=True)
class ToolProfile:
    name: str
    is_destructive: bool = False
    default_timeout_s: int = 600
    max_timeout_s: int = 3600

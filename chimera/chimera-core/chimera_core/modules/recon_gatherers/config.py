from dataclasses import dataclass, field
from typing import List, Dict, Literal
from pathlib import Path

@dataclass
class VibePenTesterConfig:
    """
    Configuration for running the VibePenTester tool.
    """
    mode: Literal["python", "cli", "docker"] = "python"
    workdir: Path = Path(".")
    output_dir: Path = Path("./reports")
    entrypoint: List[str] = field(default_factory=lambda: ["python", "main.py"])
    extra_args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    timeout_s: int = 1800

import uuid
from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional

@dataclass
class Run:
    run_id: str
    scope_hash: str
    mode: str
    artifacts_dir: Path
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

class RunManager:
    def __init__(self, artifacts_root: Path):
        self.artifacts_root = artifacts_root
        self.artifacts_root.mkdir(parents=True, exist_ok=True)

    def create_run(self, scope_hash: str, mode: str) -> Run:
        run_id = str(uuid.uuid4())
        run_artifacts_dir = self.artifacts_root / run_id
        run_artifacts_dir.mkdir(parents=True, exist_ok=False)

        # Create the initial events file
        (run_artifacts_dir / "events.jsonl").touch()

        return Run(
            run_id=run_id,
            scope_hash=scope_hash,
            mode=mode,
            artifacts_dir=run_artifacts_dir
        )
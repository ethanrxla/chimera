import json
from pathlib import Path
from typing import Dict, Any, Generator

class EventStore:
    def __init__(self, events_file: Path):
        self.events_file = events_file
        if not self.events_file.exists():
            self.events_file.touch()

    def emit(self, event: Dict[str, Any]):
        with self.events_file.open("a") as f:
            f.write(json.dumps(event) + "\n")

    def replay(self) -> Generator[Dict[str, Any], None, None]:
        if not self.events_file.exists():
            return

        with self.events_file.open("r") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)
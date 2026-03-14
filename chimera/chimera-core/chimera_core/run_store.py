import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(value: Optional[str]) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    return datetime.fromisoformat(value)


def _plan_snapshot(plan: Any) -> Dict[str, Any]:
    if isinstance(plan, dict):
        return plan
    tasks = []
    for task in plan.tasks.values():
        tasks.append({
            "task_id": task.task_id,
            "adapter": task.tool,
            "target": task.target,
            "depends_on": sorted(task.dependencies),
            "options": task.options,
        })
    return {"tasks": tasks}


@dataclass
class RunRecord:
    run_id: str
    data: Dict[str, Any]


class RunStore:
    def __init__(self, artifacts_root: Path):
        self.artifacts_root = artifacts_root

    def _run_dir(self, run_id: str) -> Path:
        return self.artifacts_root / run_id

    def _run_file(self, run_id: str) -> Path:
        return self._run_dir(run_id) / "run.json"

    def create_run(
        self,
        run_id: str,
        *,
        scope_raw: str,
        scope_normalized: Dict[str, Any],
        plan: Any,
        options: Dict[str, Any],
        status: str = "created",
        created_at: Optional[str] = None,
    ) -> RunRecord:
        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        plan_snapshot = _plan_snapshot(plan)
        tasks_total = len(plan_snapshot.get("tasks", []))
        data = {
            "run_id": run_id,
            "created_at": created_at or _now(),
            "started_at": None,
            "ended_at": None,
            "status": status,
            "scope_raw": scope_raw,
            "scope_normalized": scope_normalized,
            "plan": plan_snapshot,
            "options": options,
            "stats": {
                "tasks_total": tasks_total,
                "findings_total": 0,
                "duplicates": 0,
            },
        }
        self._run_file(run_id).write_text(json.dumps(data, indent=2), encoding="utf-8")
        return RunRecord(run_id=run_id, data=data)

    def update_run(self, run_id: str, **updates: Any) -> RunRecord:
        record = self.get_run(run_id)
        data = record.data
        data.update({k: v for k, v in updates.items() if v is not None})
        status = data.get("status")
        if status == "running" and not data.get("started_at"):
            data["started_at"] = _now()
        if status in {"completed", "failed", "cancelled"} and not data.get("ended_at"):
            data["ended_at"] = _now()
        self._run_file(run_id).write_text(json.dumps(data, indent=2), encoding="utf-8")
        return RunRecord(run_id=run_id, data=data)

    def get_run(self, run_id: str) -> RunRecord:
        path = self._run_file(run_id)
        if not path.exists():
            raise FileNotFoundError(f"Run not found: {run_id}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return RunRecord(run_id=run_id, data=data)

    def list_runs(self, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
        if not self.artifacts_root.exists():
            return []
        records = []
        for run_dir in self.artifacts_root.iterdir():
            run_file = run_dir / "run.json"
            if run_file.exists():
                data = json.loads(run_file.read_text(encoding="utf-8"))
                records.append(data)
        records.sort(key=lambda item: _parse_dt(item.get("created_at")), reverse=True)
        return records[offset: offset + limit]

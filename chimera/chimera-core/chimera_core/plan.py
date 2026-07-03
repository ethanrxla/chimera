from typing import Dict, List, Optional, Set


class Task:
    def __init__(
        self,
        task_id: str,
        tool: str,
        target: str,
        options: Dict[str, object],
        stage: str = "discover",
        capability: Optional[str] = None,
    ):
        self.task_id = task_id
        self.tool = tool
        self.target = target
        self.options = options
        self.stage = stage
        self.capability = capability or tool
        self.dependencies: Set[str] = set()

    def __repr__(self) -> str:
        return f"Task(id={self.task_id}, tool={self.tool}, target={self.target}, stage={self.stage})"

    def __hash__(self) -> int:
        return hash(self.task_id)

    def __eq__(self, other) -> bool:
        return isinstance(other, Task) and self.task_id == other.task_id


class ExecutionPlan:
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.graph: Dict[str, List[str]] = {}
        self.stages: List[str] = [
            "pre_reconnaissance",
            "reconnaissance",
            "vulnerability_analysis",
            "exploitation",
            "reporting",
        ]
        self.metadata: Dict[str, object] = {"asset_types": {}, "targets": {}}

    def add_task(self, task: Task) -> None:
        if task.task_id in self.tasks:
            raise ValueError(f"Task with ID {task.task_id} already exists.")
        self.tasks[task.task_id] = task
        self.graph[task.task_id] = []

    def set_target_metadata(self, target: str, *, asset_type: str, capability_sequence: List[str]) -> None:
        asset_types = self.metadata.setdefault("asset_types", {})
        targets = self.metadata.setdefault("targets", {})
        asset_types[target] = asset_type
        targets[target] = {
            "asset_type": asset_type,
            "capability_sequence": capability_sequence,
        }

    def add_dependency(self, from_task_id: str, to_task_id: str) -> None:
        if from_task_id not in self.tasks or to_task_id not in self.tasks:
            raise ValueError("One or both task IDs not found in the plan.")
        self.graph[from_task_id].append(to_task_id)
        self.tasks[to_task_id].dependencies.add(from_task_id)

    def indegrees(self) -> Dict[str, int]:
        indegree = {task_id: 0 for task_id in self.tasks}
        for from_task, neighbors in self.graph.items():
            for to_task in neighbors:
                indegree[to_task] += 1
        return indegree

    def ready_tasks(self, indegree: Dict[str, int]) -> List[Task]:
        return [self.tasks[task_id] for task_id, degree in indegree.items() if degree == 0]

    def validate_acyclic(self) -> None:
        indegree = self.indegrees()
        ready = [task_id for task_id, degree in indegree.items() if degree == 0]
        seen = 0
        while ready:
            current = ready.pop()
            seen += 1
            for neighbor in self.graph.get(current, []):
                indegree[neighbor] -= 1
                if indegree[neighbor] == 0:
                    ready.append(neighbor)
        if seen != len(self.tasks):
            raise ValueError("Execution plan contains a cycle")

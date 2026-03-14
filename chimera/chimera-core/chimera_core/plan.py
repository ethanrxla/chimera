from typing import Dict, List, Set


class Task:
    def __init__(self, task_id: str, tool: str, target: str, options: Dict[str, object]):
        self.task_id = task_id
        self.tool = tool
        self.target = target
        self.options = options
        self.dependencies: Set[str] = set()

    def __repr__(self) -> str:
        return f"Task(id={self.task_id}, tool={self.tool}, target={self.target})"

    def __hash__(self) -> int:
        return hash(self.task_id)

    def __eq__(self, other) -> bool:
        return isinstance(other, Task) and self.task_id == other.task_id


class ExecutionPlan:
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.graph: Dict[str, List[str]] = {}

    def add_task(self, task: Task) -> None:
        if task.task_id in self.tasks:
            raise ValueError(f"Task with ID {task.task_id} already exists.")
        self.tasks[task.task_id] = task
        self.graph[task.task_id] = []

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

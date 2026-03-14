from typing import List, Dict, Callable
from concurrent.futures import ThreadPoolExecutor
import threading

from chimera_core.planner import ExecutionPlan, Task

class Scheduler:
    def __init__(self, plan: ExecutionPlan, max_workers: int = 5):
        self.plan = plan
        self.max_workers = max_workers
        self.lock = threading.Lock()
        self.peak_concurrency = 0
        self.running_tasks = 0

    def get_execution_order(self) -> List[Task]:
        # ... (Kahn's algorithm remains the same)
        graph = {k: v[:] for k, v in self.plan.graph.items()}
        in_degree = {task_id: len(self.plan.tasks[task_id].dependencies) for task_id in self.plan.tasks}
        queue = [task_id for task_id, degree in in_degree.items() if degree == 0]
        sorted_order = []
        while queue:
            task_id = queue.pop(0)
            sorted_order.append(self.plan.tasks[task_id])
            for neighbor_id in graph.get(task_id, []):
                in_degree[neighbor_id] -= 1
                if in_degree[neighbor_id] == 0:
                    queue.append(neighbor_id)
        if len(sorted_order) != len(self.plan.tasks):
            raise ValueError("Execution plan contains a cycle and cannot be sorted.")
        return sorted_order

    def run_plan(self, task_executor: Callable[[Task], None]):
        """
        Executes the plan using a thread pool, respecting concurrency.
        This implementation is simplified and doesn't handle dependencies yet.
        """
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # A simple way to track concurrency for the test
            def wrapper(task: Task):
                with self.lock:
                    self.running_tasks += 1
                    self.peak_concurrency = max(self.peak_concurrency, self.running_tasks)
                
                task_executor(task)

                with self.lock:
                    self.running_tasks -= 1

            # Submit all independent tasks for now
            tasks = self.get_execution_order()
            for task in tasks:
                executor.submit(wrapper, task)
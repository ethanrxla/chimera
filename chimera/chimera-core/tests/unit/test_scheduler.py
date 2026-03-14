import pytest
import time
import threading
from chimera_core.planner import ExecutionPlan, Task
from chimera_core.scheduler import Scheduler

def test_dag_scheduler_respects_dependencies():
    """
    Tests that the scheduler's execution order respects a simple
    A -> B -> C dependency chain, ensuring the order is always correct.
    """
    plan = ExecutionPlan()
    task_a = Task(task_id="A", tool="tool-a", target="target-a", options={})
    task_b = Task(task_id="B", tool="tool-b", target="target-b", options={})
    task_c = Task(task_id="C", tool="tool-c", target="target-c", options={})

    # Add tasks in a non-sequential order to avoid accidental passes
    plan.add_task(task_c)
    plan.add_task(task_b)
    plan.add_task(task_a)

    # A -> B -> C
    plan.add_dependency("A", "B")
    plan.add_dependency("B", "C")

    scheduler = Scheduler(plan)
    execution_order = scheduler.get_execution_order()

    # Get the index of each task in the execution order
    try:
        index_a = execution_order.index(task_a)
        index_b = execution_order.index(task_b)
        index_c = execution_order.index(task_c)

        assert index_a < index_b, "Task A must run before Task B"
        assert index_b < index_c, "Task B must run before Task C"
    except ValueError:
        pytest.fail("One or more tasks were not found in the execution order.")

def test_scheduler_respects_concurrency_cap():
    """
    Tests that the scheduler's run_plan method respects the max_workers
    concurrency limit.
    """
    plan = ExecutionPlan()
    for i in range(10):
        plan.add_task(Task(task_id=f"T{i}", tool="test", target="test", options=dict()))

    scheduler = Scheduler(plan, max_workers=3)

    # This function will be executed by the scheduler for each task
    def mock_task_executor(task: Task):
        # Simulate work
        time.sleep(0.05)

    # Execute the plan
    scheduler.run_plan(mock_task_executor)

    assert scheduler.peak_concurrency <= scheduler.max_workers, \
        f"Peak concurrency ({scheduler.peak_concurrency}) exceeded max_workers ({scheduler.max_workers})"
import pytest

from chimera_core.plan import ExecutionPlan, Task


def test_execution_plan_validate_acyclic_accepts_dag() -> None:
    plan = ExecutionPlan()
    plan.add_task(Task("A", "strix", "https://example.com", {}))
    plan.add_task(Task("B", "shannon", "https://example.com", {}))
    plan.add_dependency("A", "B")
    plan.validate_acyclic()


def test_execution_plan_validate_acyclic_rejects_cycle() -> None:
    plan = ExecutionPlan()
    plan.add_task(Task("A", "strix", "https://example.com", {}))
    plan.add_task(Task("B", "shannon", "https://example.com", {}))
    plan.add_dependency("A", "B")
    plan.add_dependency("B", "A")
    with pytest.raises(ValueError, match="cycle"):
        plan.validate_acyclic()

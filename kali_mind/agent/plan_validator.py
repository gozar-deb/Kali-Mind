"""Validate AI-generated execution plans before they reach the executor."""
from __future__ import annotations

import logging
from typing import List, Set, Tuple

from kali_mind.agent.models import ExecutionPlan
from kali_mind.exceptions import PlanValidationError
from kali_mind.security.scope import get_scope_manager
from kali_mind.tools.adapters.registry import get_adapter
from kali_mind.tools.registry import get_registry

logger = logging.getLogger(__name__)


class PlanValidator:
    """Structural + policy pre-checks for an ExecutionPlan."""

    def __init__(self) -> None:
        self.registry = get_registry()
        self.scope_mgr = get_scope_manager()

    def validate(self, plan: ExecutionPlan) -> Tuple[bool, List[str]]:
        """Return (ok, list_of_issues). Does not raise."""
        issues: List[str] = []

        if not plan.steps:
            issues.append("Plan has no steps")
            return False, issues

        seen_steps: Set[int] = set()
        step_positions = {step.step: index for index, step in enumerate(plan.steps)}
        available_tools = {t.name for t in self.registry.available_tools()}

        for index, step in enumerate(plan.steps):
            if step.step in seen_steps:
                issues.append(f"Duplicate step number: {step.step}")
            seen_steps.add(step.step)

            if not step.description:
                issues.append(f"Step {step.step}: missing description")

            if step.tool:
                if step.tool not in available_tools and get_adapter(step.tool) is None:
                    issues.append(
                        f"Step {step.step}: tool '{step.tool}' is not available/installed"
                    )

                if step.target:
                    in_scope, reason = self.scope_mgr.is_in_scope(step.target)
                    if not in_scope:
                        issues.append(
                            f"Step {step.step}: target '{step.target}' out of scope — {reason}"
                        )
                else:
                    # Tool steps without a target are often incomplete
                    issues.append(
                        f"Step {step.step}: tool '{step.tool}' has no target"
                    )

                # Adapter-level validation when possible
                adapter = get_adapter(step.tool)
                if adapter and step.target:
                    from kali_mind.tools.adapters.base import ToolRequest
                    req = ToolRequest(
                        tool=step.tool,
                        operation=step.operation or "default",
                        target=step.target,
                        options=step.options or {},
                    )
                    err = adapter.validate_request(req)
                    if err:
                        issues.append(f"Step {step.step}: {err}")

            if step.depends_on is not None:
                if step.depends_on not in step_positions:
                    issues.append(
                        f"Step {step.step}: depends_on {step.depends_on} does not exist"
                    )
                elif step_positions[step.depends_on] >= index:
                    issues.append(
                        f"Step {step.step}: dependency {step.depends_on} must appear earlier in the plan"
                    )
                else:
                    dependency = plan.steps[step_positions[step.depends_on]]
                    if step.parallel and dependency.parallel:
                        issues.append(
                            f"Step {step.step}: cannot depend on parallel step {step.depends_on}; "
                            "parallel batch steps execute concurrently"
                        )

        ok = len(issues) == 0
        if not ok:
            logger.warning("Plan validation failed with %d issue(s)", len(issues))
            for i in issues:
                logger.warning("  - %s", i)
        return ok, issues

    def validate_or_raise(self, plan: ExecutionPlan) -> None:
        ok, issues = self.validate(plan)
        if not ok:
            raise PlanValidationError("; ".join(issues))

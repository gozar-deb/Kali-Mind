"""Multi-step plan reflection: draft → critique → revise → verify (up to N rounds)."""
from __future__ import annotations

import logging
from typing import Any, List, Optional, Tuple

from kali_mind.agent.models import ExecutionPlan
from kali_mind.agent.plan_validator import PlanValidator

logger = logging.getLogger(__name__)


class ReflectionLoop:
    def __init__(self, planner: Any, max_rounds: int = 3) -> None:
        self.planner = planner
        self.max_rounds = max_rounds
        self.validator = PlanValidator()

    async def refine(self, objective: str, initial: Optional[ExecutionPlan] = None) -> Tuple[ExecutionPlan, List[str]]:
        """Return (final_plan, critique_log)."""
        log: List[str] = []
        plan = initial or await self.planner.plan(objective)
        for round_i in range(1, self.max_rounds + 1):
            ok, issues = self.validator.validate(plan)
            if ok:
                log.append(f"round {round_i}: validated clean")
                return plan, log
            log.append(f"round {round_i}: {len(issues)} issue(s)")
            critique = "\n".join(f"- {i}" for i in issues)
            # Second-pass critique quality questions
            quality = (
                f"Also ensure: steps are ordered, no duplicate tools on same target without reason, "
                f"prefer least-privilege operations first.\nIssues:\n{critique}"
            )
            try:
                plan = await self.planner.plan(
                    f"Revise the plan for: {objective}\n\n{quality}\n\nReturn only an improved plan."
                )
            except Exception as e:
                log.append(f"round {round_i}: revise failed: {e}")
                break
        ok, issues = self.validator.validate(plan)
        if not ok:
            log.append(f"final: still invalid: {issues}")
        return plan, log

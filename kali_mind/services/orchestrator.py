"""Service-layer orchestrator — shared by CLI, API, and TUI.

Owns the high-level flow: plan → validate → (approve) → execute → analyze.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, List, Optional

from kali_mind.agent.memory import AgentMemory
from kali_mind.agent.models import ExecutionPlan
from kali_mind.agent.plan_validator import PlanValidator
from kali_mind.agent.reflection import ReflectionLoop
from kali_mind.agent.planner import Planner
from kali_mind.exceptions import PlanValidationError
from kali_mind.security.prompt_guard import sanitize_user_message

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        gateway: Any,
        memory: AgentMemory,
        session_id: str,
        progress: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.gateway = gateway
        self.memory = memory
        self.session_id = session_id
        self.progress = progress or (lambda m: None)
        self.planner = Planner(gateway, memory)
        self.validator = PlanValidator()

    async def chat(self, user_text: str) -> str:
        cleaned, warnings = sanitize_user_message(user_text)
        for w in warnings:
            self.progress(f"[prompt-guard] {w}")
        # The AI gateway is the single source of truth for request limits and usage;
        # counting here as well double-charged every orchestrated request.
        return await self.planner.chat(cleaned)

    async def plan(self, objective: str) -> ExecutionPlan:
        cleaned, _ = sanitize_user_message(objective)
        plan = await self.planner.plan(cleaned)
        # Multi-step reflection
        loop = ReflectionLoop(self.planner, max_rounds=3)
        plan, log = await loop.refine(cleaned, initial=plan)
        for line in log:
            self.progress(f"[reflect] {line}")
        # Resolve omitted targets from current agent context before validation so the
        # planner and executor agree on which target will be policy-checked.
        inferred_target = (self.memory.targets[0] if self.memory.targets else
                           self.memory.discovered_hosts[0] if self.memory.discovered_hosts else None)
        for step in plan.steps:
            if step.tool and not step.target and inferred_target:
                step.target = inferred_target
        valid, issues = self.validator.validate(plan)
        if not valid:
            raise PlanValidationError("; ".join(issues))
        return plan

    async def _critique_and_revise(self, plan: ExecutionPlan, issues: List[str]) -> ExecutionPlan:
        """Formal plan → critique → revise loop."""
        self.progress("Plan issues detected; requesting revision…")
        critique = "\n".join(f"- {i}" for i in issues)
        prompt = (
            f"Your previous plan for '{plan.objective}' had these problems:\n{critique}\n\n"
            "Produce a revised plan JSON that fixes every issue. "
            "Only use available tools and in-scope targets."
        )
        try:
            revised = await self.planner.plan(prompt)
            return revised
        except Exception as e:
            logger.warning("Critique/revise failed: %s", e)
            return plan

    async def execute_plan(self, plan: ExecutionPlan, *, skip_validation: bool = False):
        from kali_mind.agent.executor import AgentExecutor
        from kali_mind.execution.executor import get_executor

        agent_ex = AgentExecutor(
            get_executor(),
            self.memory,
            self.session_id,
            progress_callback=self.progress,
        )
        return await agent_ex.execute_plan(plan, skip_validation=skip_validation)

    async def run_objective(self, objective: str):
        """End-to-end: plan → validate/revise → execute."""
        plan = await self.plan(objective)
        self.progress(f"Plan ready: {len(plan.steps)} step(s)")
        return await self.execute_plan(plan)

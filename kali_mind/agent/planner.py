"""AI agent planner — translates user objectives into execution plans."""
from __future__ import annotations

import json
import logging
import re
from typing import List

from kali_mind.ai.gateway import AIGateway
from kali_mind.ai.schemas import AIRequest, Message, Role
from kali_mind.agent.memory import AgentMemory
from kali_mind.agent.models import ExecutionPlan, PlanStep
from kali_mind.security.prompt_guard import sanitize_user_message
from kali_mind.tools.registry import get_registry

logger = logging.getLogger(__name__)

# Re-export for backward compatibility
__all__ = ["Planner", "ExecutionPlan", "PlanStep", "PLANNER_SYSTEM", "COPILOT_SYSTEM"]

PLANNER_SYSTEM = """You are Kali-Mind, an AI security orchestration assistant for authorized penetration testing.

CRITICAL RULES:
- Only suggest actions against authorized targets within scope
- Use structured tool requests, never raw shell injection
- Never fabricate results — distinguish observed facts from inferences
- If unsure about scope, ask before proceeding

When asked to plan, respond with analysis then a JSON block:
```json
{
  "plan": [
    {
      "step": 1,
      "description": "Host discovery",
      "tool": "nmap",
      "operation": "ping_scan",
      "target": "ACTUAL_IP_OR_HOSTNAME"
    }
  ]
}
```

IMPORTANT: Replace placeholder targets like <target> with the actual target from context.
For conversational questions, respond naturally without a JSON block.
"""

COPILOT_SYSTEM = """You are a Kali Linux command copilot. For each request:
1. Recommend the best tool and why
2. Show the exact command with all arguments
3. Explain each argument and its purpose
4. Mention risks and expected output format
5. Suggest the next logical step after this command
6. Note any prerequisites (sudo, wordlists, etc.)
Be specific and educational."""


class Planner:
    def __init__(self, gateway: AIGateway, memory: AgentMemory) -> None:
        self.gateway = gateway
        self.memory = memory

    async def plan(self, objective: str) -> ExecutionPlan:
        objective, _ = sanitize_user_message(objective)
        registry = get_registry()
        available = [t.name for t in registry.available_tools()]
        context = self.memory.get_context_summary()

        user_content = (
            f"Security objective: {objective}\n\n"
            f"Available tools: {', '.join(available) if available else 'none detected'}\n\n"
            f"Current session context:\n{context}\n\n"
            f"Targets in scope: {', '.join(self.memory.targets) if self.memory.targets else 'none set'}\n\n"
            f"Create a structured execution plan. Include a JSON block with the plan. "
            f"Use actual IP addresses or hostnames, not placeholders like <target>."
        )

        request = AIRequest(
            system=PLANNER_SYSTEM,
            messages=[Message(role=Role.user, content=user_content)],
            max_tokens=2048,
            temperature=0.1,
            session_id=self.memory.session_id,
        )

        response = await self.gateway.complete_with_role(request, "planner")
        self.memory.add_assistant_message(response.content)
        steps = self._parse_plan_from_response(response.content, objective)

        # FIX #4: resolve placeholder targets from memory
        steps = self._resolve_targets(steps)
        return ExecutionPlan(objective=objective, steps=steps)

    async def chat(self, message: str) -> str:
        message, _ = sanitize_user_message(message)
        self.memory.add_user_message(message)
        context = self.memory.get_context_summary()
        system = PLANNER_SYSTEM + f"\n\nSession context:\n{context}"
        request = AIRequest(
            system=system,
            messages=self.memory.get_recent_messages(8),
            max_tokens=1024,
            temperature=0.3,
            session_id=self.memory.session_id,
        )
        response = await self.gateway.complete(request)
        self.memory.add_assistant_message(response.content)
        return response.content

    async def copilot_chat(self, message: str) -> str:
        """Feature #19: dedicated copilot using COPILOT_SYSTEM prompt."""
        self.memory.add_user_message(message)
        request = AIRequest(
            system=COPILOT_SYSTEM,
            messages=self.memory.get_recent_messages(6),
            max_tokens=1200,
            temperature=0.3,
            session_id=self.memory.session_id,
        )
        response = await self.gateway.complete(request)
        self.memory.add_assistant_message(response.content)
        return response.content

    def _resolve_targets(self, steps: List[PlanStep]) -> List[PlanStep]:
        """FIX #4: Replace placeholder targets with real ones from memory."""
        placeholders = {"<target>", "<ip>", "<host>", "<url>", "TARGET", "HOSTNAME", "ACTUAL_IP_OR_HOSTNAME"}
        real_target = None
        if self.memory.targets:
            real_target = self.memory.targets[0]
        elif self.memory.discovered_hosts:
            real_target = self.memory.discovered_hosts[0]

        if real_target:
            for step in steps:
                if step.target is None or step.target in placeholders:
                    step.target = real_target
        return steps

    def _parse_plan_from_response(self, content: str, objective: str) -> List[PlanStep]:
        json_pattern = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
        match = json_pattern.search(content)
        if match:
            try:
                data = json.loads(match.group(1))
                raw_steps = data.get("plan", [])
                steps = []
                for s in raw_steps:
                    target = s.get("target")
                    steps.append(PlanStep(
                        step=s.get("step", len(steps) + 1),
                        description=s.get("description", ""),
                        tool=s.get("tool"),
                        operation=s.get("operation"),
                        target=target if target and target not in {"<target>", "ACTUAL_IP_OR_HOSTNAME"} else None,
                        options=s.get("options", {}),
                        parallel=s.get("parallel", False),
                    ))
                if steps:
                    return steps
            except Exception as e:
                logger.debug("Failed to parse JSON plan from AI response: %s", e)

        # Fallback: parse numbered list
        steps = []
        step_num = 1
        for line in content.split("\n"):
            line = line.strip()
            if re.match(r"^\d+\.", line):
                desc = re.sub(r"^\d+\.\s*", "", line)
                if desc:
                    steps.append(PlanStep(step=step_num, description=desc))
                    step_num += 1

        # FIX: never return a step with empty description
        steps = [s for s in steps if s.description.strip()]
        return steps or [PlanStep(step=1, description=objective)]

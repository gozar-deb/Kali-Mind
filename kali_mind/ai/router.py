"""Intelligent AI model router — auto-selects provider based on task characteristics."""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from kali_mind.config import settings


class TaskType(str, Enum):
    SIMPLE_EXPLANATION = "simple_explanation"
    OUTPUT_PARSING = "output_parsing"
    COMPLEX_REASONING = "complex_reasoning"
    SENSITIVE_ANALYSIS = "sensitive_analysis"
    REPORT_GENERATION = "report_generation"
    TOOL_SELECTION = "tool_selection"
    FINDING_CORRELATION = "finding_correlation"
    PLANNING = "planning"
    CHAT = "chat"


class RoutingPolicy(str, Enum):
    LOCAL_FIRST = "local_first"
    CLOUD_FIRST = "cloud_first"
    BALANCED = "balanced"
    PRIVACY = "privacy"
    PERFORMANCE = "performance"
    COST = "cost"


class ModelRouter:
    """
    Routes AI requests to the most appropriate provider based on:
    - Task complexity
    - Privacy requirements
    - Cost
    - Speed
    - Availability
    """

    def __init__(
        self,
        available_providers: List[str],
        policy: RoutingPolicy = RoutingPolicy.BALANCED,
    ) -> None:
        self.available_providers = set(available_providers)
        self.policy = policy

    def select_provider(
        self,
        task_type: TaskType,
        override: Optional[str] = None,
    ) -> str:
        """Return the best provider name for the given task."""
        # Privacy/offline constraints take precedence over every override.
        if settings.privacy_mode or settings.offline_mode or self.policy == RoutingPolicy.PRIVACY:
            local = self._prefer_local()
            if not local:
                raise ValueError("Privacy/offline routing requires an available local provider")
            if override and override != local:
                raise ValueError("Requested provider conflicts with privacy/offline routing policy")
            return local
        if override:
            if override not in self.available_providers:
                raise ValueError(f"Requested provider '{override}' is not available")
            return override
        selected = self._route_by_task(task_type)
        if not selected:
            raise ValueError("No AI providers are available")
        return selected

    def _route_by_task(self, task_type: TaskType) -> str:
        # Simple or fast tasks → local
        if task_type in (TaskType.SIMPLE_EXPLANATION, TaskType.OUTPUT_PARSING):
            return self._prefer_local()

        # Sensitive data → always local
        if task_type == TaskType.SENSITIVE_ANALYSIS:
            return self._prefer_local()

        # Complex tasks → prefer capable cloud models
        if task_type in (
            TaskType.COMPLEX_REASONING,
            TaskType.FINDING_CORRELATION,
            TaskType.PLANNING,
        ):
            return self._prefer_cloud_capable()

        # Reports → capable cloud
        if task_type == TaskType.REPORT_GENERATION:
            return self._prefer_cloud_capable()

        return self._prefer_local()

    def _prefer_local(self) -> str:
        for p in ["ollama", "llamacpp"]:
            if p in self.available_providers:
                return p
        if settings.privacy_mode or settings.offline_mode or self.policy == RoutingPolicy.PRIVACY:
            return ""
        return self._any()

    def _prefer_cloud_capable(self) -> str:
        # Preference order for complex tasks
        for p in ["anthropic", "claude", "openai", "grok", "gemini", "deepseek",
                  "mistral", "groq", "ollama"]:
            if p in self.available_providers:
                return p
        return self._prefer_local()

    def _any(self) -> str:
        if not self.available_providers:
            return ""
        return sorted(self.available_providers)[0]

    @classmethod
    def infer_task_type(cls, text: str) -> TaskType:
        """Heuristic classification of user input."""
        t = text.lower()
        if any(w in t for w in ["explain", "what is", "describe", "how does"]):
            return TaskType.SIMPLE_EXPLANATION
        if any(w in t for w in ["parse", "extract", "analyze output", "read this"]):
            return TaskType.OUTPUT_PARSING
        if any(w in t for w in ["report", "generate report", "write report"]):
            return TaskType.REPORT_GENERATION
        if any(w in t for w in ["plan", "assess", "evaluate", "strategy"]):
            return TaskType.PLANNING
        if any(w in t for w in ["correlate", "finding", "vulnerability", "cve"]):
            return TaskType.FINDING_CORRELATION
        if any(w in t for w in ["private", "sensitive", "confidential", "secret"]):
            return TaskType.SENSITIVE_ANALYSIS
        return TaskType.CHAT


    def select_for_role(self, role: str) -> str:
        """Multi-model role routing (planner / analyst / parser / reporter)."""
        role = (role or "").lower()
        role_map = {
            "planner": settings.planner_provider,
            "analyst": settings.analyst_provider,
            "parser": settings.parser_provider,
            "reporter": settings.reporter_provider,
        }
        preferred = role_map.get(role)
        if preferred and preferred in self.available_providers:
            return preferred
        # Fallbacks by role
        if role == "parser":
            return self._prefer_local()
        if role in ("planner", "analyst"):
            return self._prefer_cloud_capable()
        if role == "reporter":
            return self._prefer_cloud_capable()
        return self._any()

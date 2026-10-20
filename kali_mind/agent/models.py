"""Shared agent models (no heavy imports)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PlanStep(BaseModel):
    step: int
    description: str
    tool: Optional[str] = None
    operation: Optional[str] = None
    target: Optional[str] = None
    options: Dict[str, Any] = Field(default_factory=dict)
    depends_on: Optional[int] = None
    parallel: bool = False


class ExecutionPlan(BaseModel):
    objective: str
    steps: List[PlanStep]
    requires_approval: bool = True

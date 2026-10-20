"""Shared AI request/response schemas."""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Role(str, Enum):
    system = "system"
    user = "user"
    assistant = "assistant"


class Message(BaseModel):
    role: Role
    content: str


class AIRequest(BaseModel):
    messages: List[Message]
    system: Optional[str] = None
    max_tokens: int = Field(default=4096, ge=1, le=131072)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    stream: bool = False
    provider: Optional[str] = None  # override
    model: Optional[str] = None
    session_id: Optional[str] = None


class AIResponse(BaseModel):
    content: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    cost_estimate: float = 0.0


class ProviderHealth(BaseModel):
    name: str
    available: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class TokenUsage(BaseModel):
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    requests: int = 0
    cost_estimate: float = 0.0
    total_latency_ms: float = 0.0

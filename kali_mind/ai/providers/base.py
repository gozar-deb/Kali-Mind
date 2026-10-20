"""Base AI provider interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator

from kali_mind.ai.schemas import AIRequest, AIResponse


class BaseProvider(ABC):
    name: str = "base"

    @abstractmethod
    async def complete(self, request: AIRequest) -> AIResponse:
        ...

    async def stream(self, request: AIRequest) -> AsyncIterator[str]:
        response = await self.complete(request)
        yield response.content

    # FIX #10: health_check uses HEAD or lightweight ping, not full LLM call
    async def health_check(self) -> bool:
        """Lightweight availability check. Override in each provider."""
        return False

    def _build_messages(self, request: AIRequest) -> list[dict]:
        msgs = []
        if request.system:
            msgs.append({"role": "system", "content": request.system})
        for m in request.messages:
            msgs.append({"role": m.role.value, "content": m.content})
        return msgs

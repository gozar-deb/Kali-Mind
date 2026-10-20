"""Miscellaneous providers: Groq, Mistral, Cohere."""
from __future__ import annotations

import time


import httpx

from kali_mind.ai.providers.base import BaseProvider
from kali_mind.ai.schemas import AIRequest, AIResponse


class GroqProvider(BaseProvider):
    """Groq Cloud — OpenAI-compatible but very fast."""
    name = "groq"

    def __init__(self, api_key: str, model: str = "llama-3.1-8b-instant") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, request: AIRequest) -> AIResponse:
        from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
        p = OpenAICompatProvider(
            name="groq",
            api_key=self.api_key,
            model=request.model or self.model,
            base_url="https://api.groq.com/openai/v1",
        )
        return await p.complete(request)

    async def stream(self, request: AIRequest):
        from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
        p = OpenAICompatProvider(
            name="groq", api_key=self.api_key, model=self.model,
            base_url="https://api.groq.com/openai/v1",
        )
        async for token in p.stream(request):
            yield token

    async def health_check(self) -> bool:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get("https://api.groq.com/openai/v1/models",
                                     headers={"Authorization": f"Bearer {self.api_key}"})
                return r.status_code == 200
        except Exception:
            return False


class MistralProvider(BaseProvider):
    name = "mistral"

    def __init__(self, api_key: str, model: str = "mistral-small-latest") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, request: AIRequest) -> AIResponse:
        from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
        p = OpenAICompatProvider(
            name="mistral",
            api_key=self.api_key,
            model=request.model or self.model,
            base_url="https://api.mistral.ai/v1",
        )
        return await p.complete(request)

    async def stream(self, request: AIRequest):
        from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
        p = OpenAICompatProvider(
            name="mistral", api_key=self.api_key, model=self.model,
            base_url="https://api.mistral.ai/v1",
        )
        async for token in p.stream(request):
            yield token

    async def health_check(self) -> bool:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get("https://api.mistral.ai/v1/models",
                                     headers={"Authorization": f"Bearer {self.api_key}"})
                return r.status_code == 200
        except Exception:
            return False


class CohereProvider(BaseProvider):
    name = "cohere"

    def __init__(self, api_key: str, model: str = "command-r") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, request: AIRequest) -> AIResponse:
        model = request.model or self.model
        chat_history = []
        system_parts = [request.system] if request.system else []
        user_message = None
        # Cohere v1/chat requires the current user turn in `message`; previous
        # turns become chat_history. System messages are represented by `preamble`.
        for m in request.messages:
            role = m.role.value
            if role == "system":
                system_parts.append(m.content)
            elif role == "user":
                if user_message is not None:
                    chat_history.append({"role": "USER", "message": user_message})
                user_message = m.content
            else:
                if user_message is not None:
                    chat_history.append({"role": "USER", "message": user_message})
                    user_message = None
                chat_history.append({"role": "CHATBOT", "message": m.content})
        if user_message is None:
            raise ValueError("Cohere requires the final conversation turn to be a user message")
        system_prompt = "\n\n".join(system_parts)

        t0 = time.monotonic()
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                "https://api.cohere.ai/v1/chat",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": model,
                    "message": user_message,
                    "chat_history": chat_history,
                    "preamble": system_prompt,
                    "max_tokens": request.max_tokens,
                    "temperature": request.temperature,
                },
            )
            resp.raise_for_status()
        latency = (time.monotonic() - t0) * 1000
        data = resp.json()
        content = data.get("text", "")
        usage = data.get("meta", {}).get("tokens", {})
        return AIResponse(
            content=content,
            provider="cohere",
            model=model,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            latency_ms=latency,
        )

    async def health_check(self) -> bool:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get("https://api.cohere.ai/v1/models",
                                     headers={"Authorization": f"Bearer {self.api_key}"})
                return r.status_code == 200
        except Exception:
            return False

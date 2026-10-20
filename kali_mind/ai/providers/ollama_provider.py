"""Ollama local model provider."""
from __future__ import annotations

import json
import time
from typing import AsyncIterator

import httpx

from kali_mind.ai.providers.base import BaseProvider
from kali_mind.ai.schemas import AIRequest, AIResponse


class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self, endpoint: str = "http://localhost:11434", model: str = "llama3") -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model

    async def complete(self, request: AIRequest) -> AIResponse:
        model = request.model or self.model
        messages = self._build_messages(request)
        t0 = time.monotonic()
        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(
                f"{self.endpoint}/api/chat",
                json={
                    "model": model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": request.temperature},
                },
            )
            resp.raise_for_status()
        latency = (time.monotonic() - t0) * 1000
        data = resp.json()
        content = data["message"]["content"]
        in_tok = data.get("prompt_eval_count", 0)
        out_tok = data.get("eval_count", 0)
        return AIResponse(
            content=content,
            provider="ollama",
            model=model,
            input_tokens=in_tok,
            output_tokens=out_tok,
            latency_ms=latency,
            cost_estimate=0.0,
        )

    async def stream(self, request: AIRequest) -> AsyncIterator[str]:
        model = request.model or self.model
        messages = self._build_messages(request)
        async with httpx.AsyncClient(timeout=180) as client:
            async with client.stream(
                "POST",
                f"{self.endpoint}/api/chat",
                json={
                    "model": model,
                    "messages": messages,
                    "stream": True,
                    "options": {"temperature": request.temperature},
                },
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line:
                        try:
                            d = json.loads(line)
                            token = d.get("message", {}).get("content", "")
                            if token:
                                yield token
                            if d.get("done"):
                                break
                        except json.JSONDecodeError as exc:
                            raise RuntimeError("Ollama returned malformed streaming JSON") from exc

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.endpoint}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{self.endpoint}/api/tags")
                r.raise_for_status()
                return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return []

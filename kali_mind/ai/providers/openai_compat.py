"""OpenAI-compatible provider with retry logic."""
from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncIterator

import httpx

from kali_mind.ai.providers.base import BaseProvider
from kali_mind.ai.schemas import AIRequest, AIResponse

_COST_TABLE: dict[str, tuple[float, float]] = {
    "gpt-4o": (5.0, 15.0),
    "gpt-4o-mini": (0.15, 0.6),
    "gpt-4-turbo": (10.0, 30.0),
    "gpt-3.5-turbo": (0.5, 1.5),
}

_MAX_RETRIES = 3
_RETRY_CODES = {429, 500, 502, 503, 504}


class OpenAICompatProvider(BaseProvider):
    def __init__(self, name: str, api_key: str, model: str,
                 base_url: str = "https://api.openai.com/v1") -> None:
        self.name = name
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    async def complete(self, request: AIRequest) -> AIResponse:
        model = request.model or self.model
        messages = self._build_messages(request)
        t0 = time.monotonic()

        # FIX #7: exponential backoff retry on 429/5xx
        for attempt in range(_MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=120) as client:
                    resp = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                        json={"model": model, "messages": messages,
                              "max_tokens": request.max_tokens, "temperature": request.temperature},
                    )
                    if resp.status_code in _RETRY_CODES and attempt < _MAX_RETRIES - 1:
                        wait = 2 ** attempt
                        await asyncio.sleep(wait)
                        continue
                    resp.raise_for_status()
            except httpx.TimeoutException:
                if attempt < _MAX_RETRIES - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise
            break

        latency = (time.monotonic() - t0) * 1000
        data = resp.json()
        usage = data.get("usage", {})
        in_tok = usage.get("prompt_tokens", 0)
        out_tok = usage.get("completion_tokens", 0)
        cost = _estimate_cost(model, in_tok, out_tok)
        choices = data.get("choices") or []
        message = choices[0].get("message", {}) if choices else {}
        content = message.get("content")
        if isinstance(content, list):
            content = "".join(
                part.get("text", "") for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )
        if not isinstance(content, str) or not content.strip():
            if message.get("tool_calls"):
                raise RuntimeError(f"{self.name} returned tool calls without text; tool-call handling is not implemented")
            raise RuntimeError(f"{self.name} returned no text content")
        return AIResponse(content=content, provider=self.name, model=model,
                          input_tokens=in_tok, output_tokens=out_tok,
                          latency_ms=latency, cost_estimate=cost)

    async def stream(self, request: AIRequest) -> AsyncIterator[str]:
        model = request.model or self.model
        messages = self._build_messages(request)
        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST", f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": messages,
                      "max_tokens": request.max_tokens, "temperature": request.temperature, "stream": True},
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        chunk = line[6:]
                        if chunk == "[DONE]":
                            break
                        try:
                            d = json.loads(chunk)
                        except json.JSONDecodeError as exc:
                            raise RuntimeError(f"{self.name} returned malformed streaming JSON") from exc
                        choices = d.get("choices") or []
                        if not choices:
                            # Usage-only chunks are legal with some compatible APIs.
                            continue
                        delta_obj = choices[0].get("delta", {})
                        delta = delta_obj.get("content", "")
                        if isinstance(delta, list):
                            delta = "".join(
                                part.get("text", "") for part in delta
                                if isinstance(part, dict) and part.get("type") == "text"
                            )
                        if delta:
                            yield delta

    async def health_check(self) -> bool:
        """HEAD request to base URL — no tokens consumed."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}/models",
                                     headers={"Authorization": f"Bearer {self.api_key}"})
                return r.status_code == 200
        except Exception:
            return False


def _estimate_cost(model: str, in_tok: int, out_tok: int) -> float:
    for key, (in_price, out_price) in _COST_TABLE.items():
        if key in model:
            return (in_tok * in_price + out_tok * out_price) / 1_000_000
    return 0.0

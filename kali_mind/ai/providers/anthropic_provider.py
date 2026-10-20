"""Anthropic Claude provider."""
from __future__ import annotations

import time


import httpx

from kali_mind.ai.providers.base import BaseProvider
from kali_mind.ai.schemas import AIRequest, AIResponse

_COST_TABLE = {
    "claude-3-5-sonnet": (3.0, 15.0),
    "claude-3-5-haiku": (0.8, 4.0),
    "claude-3-opus": (15.0, 75.0),
    "claude-3-haiku": (0.25, 1.25),
}


class AnthropicProvider(BaseProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-3-5-haiku-20241022") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, request: AIRequest) -> AIResponse:
        model = request.model or self.model
        # Anthropic accepts only user/assistant roles in messages; system prompts
        # belong in the top-level system field. Merge adjacent same-role messages.
        messages = []
        for message in request.messages:
            if message.role.value == "system":
                # Preserve system-role history as instruction text rather than sending
                # an invalid system role in the messages array.
                continue
            role = message.role.value
            if messages and messages[-1]["role"] == role:
                messages[-1]["content"].append({"type": "text", "text": message.content})
            else:
                messages.append({"role": role, "content": [{"type": "text", "text": message.content}]})
        system_parts = [request.system] if request.system else []
        system_parts.extend(m.content for m in request.messages if m.role.value == "system")
        if not messages:
            raise ValueError("Anthropic requires at least one user or assistant message")
        payload: dict = {
            "model": model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": messages,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)

        t0 = time.monotonic()
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json=payload,
            )
            resp.raise_for_status()
        latency = (time.monotonic() - t0) * 1000
        data = resp.json()
        content = "".join(
            block.get("text", "") for block in data.get("content", [])
            if isinstance(block, dict) and block.get("type") == "text"
        )
        if not content:
            raise RuntimeError("Anthropic returned no text content")
        usage = data.get("usage", {})
        in_tok = usage.get("input_tokens", 0)
        out_tok = usage.get("output_tokens", 0)
        cost = _estimate_cost(model, in_tok, out_tok)
        return AIResponse(
            content=content,
            provider="anthropic",
            model=model,
            input_tokens=in_tok,
            output_tokens=out_tok,
            latency_ms=latency,
            cost_estimate=cost,
        )


    async def health_check(self) -> bool:
        """HEAD request to Anthropic API — no tokens consumed."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    "https://api.anthropic.com/v1/models",
                    headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                )
                return r.status_code == 200
        except Exception:
            return False


def _estimate_cost(model: str, in_tok: int, out_tok: int) -> float:
    for key, (inp, outp) in _COST_TABLE.items():
        if key in model:
            return (in_tok * inp + out_tok * outp) / 1_000_000
    return 0.0

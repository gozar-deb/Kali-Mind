"""Google Gemini provider."""
from __future__ import annotations

import time


import httpx

from kali_mind.ai.providers.base import BaseProvider
from kali_mind.ai.schemas import AIRequest, AIResponse


class GeminiProvider(BaseProvider):
    name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash") -> None:
        self.api_key = api_key
        self.model = model

    async def complete(self, request: AIRequest) -> AIResponse:
        model = request.model or self.model
        contents = []
        for message in request.messages:
            role = message.role.value
            if role == "system":
                continue
            gemini_role = "model" if role == "assistant" else "user"
            if contents and contents[-1]["role"] == gemini_role:
                contents[-1]["parts"].append({"text": message.content})
            else:
                contents.append({"role": gemini_role, "parts": [{"text": message.content}]})
        system_parts = [request.system] if request.system else []
        system_parts.extend(m.content for m in request.messages if m.role.value == "system")
        if not contents:
            raise ValueError("Gemini requires at least one user or assistant message")
        payload = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": request.max_tokens,
                "temperature": request.temperature,
            },
        }
        if system_parts:
            payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_parts)}]}
        # Keep credentials out of URLs, which are frequently captured by HTTP logs.
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        t0 = time.monotonic()
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(url, headers={"x-goog-api-key": self.api_key}, json=payload)
            resp.raise_for_status()
        latency = (time.monotonic() - t0) * 1000
        data = resp.json()
        candidates = data.get("candidates") or []
        text = "".join(
            part.get("text", "")
            for part in (candidates[0].get("content", {}).get("parts", []) if candidates else [])
            if isinstance(part, dict)
        )
        if not text:
            prompt_feedback = data.get("promptFeedback", {})
            raise RuntimeError(f"Gemini returned no text content (feedback: {prompt_feedback.get('blockReason', 'unspecified')})")
        usage = data.get("usageMetadata", {})
        in_tok = usage.get("promptTokenCount", 0)
        out_tok = usage.get("candidatesTokenCount", 0)
        return AIResponse(
            content=text,
            provider="gemini",
            model=model,
            input_tokens=in_tok,
            output_tokens=out_tok,
            latency_ms=latency,
        )

    async def health_check(self) -> bool:
        """Lightweight ping — lists models without generating content."""
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    headers={"x-goog-api-key": self.api_key},
                )
                return r.status_code == 200
        except Exception:
            return False

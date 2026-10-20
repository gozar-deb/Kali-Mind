from __future__ import annotations

import asyncio

import pytest

from kali_mind.ai.gateway import AIGateway
from kali_mind.ai.schemas import AIRequest, AIResponse, Message, Role
from kali_mind.security.rate_limit import RateLimiter, RateLimitConfig


class FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, fail=False, chunks=None):
        self.fail = fail
        self.chunks = chunks or ["hello", " world"]
        self.called = False

    async def complete(self, request):
        self.called = True
        if self.fail:
            raise RuntimeError("simulated provider failure")
        return AIResponse(content="ok", provider=self.name, model=request.model or self.model)

    async def stream(self, request):
        self.called = True
        if self.fail:
            raise RuntimeError("simulated stream failure")
        for chunk in self.chunks:
            yield chunk


def gateway_with(provider_name="fake", provider=None):
    gateway = AIGateway.__new__(AIGateway)
    gateway._providers = {provider_name: provider or FakeProvider()}
    gateway._usage = {}
    gateway._health_cache = {}
    return gateway


def test_failed_completion_releases_cost_reservation(monkeypatch):
    import kali_mind.config as config
    import kali_mind.security.rate_limit as rate_module

    monkeypatch.setattr(config.settings, "privacy_mode", False)
    monkeypatch.setattr(config.settings, "offline_mode", False)
    monkeypatch.setattr(config.settings, "default_provider", "fake")
    limiter = RateLimiter(config=RateLimitConfig(max_ai_cost_usd_per_session=5))
    monkeypatch.setattr(rate_module, "_limiter", limiter)
    provider = FakeProvider(fail=True)
    gateway = gateway_with(provider=provider)
    request = AIRequest(messages=[Message(role=Role.user, content="hello")])

    with pytest.raises(RuntimeError, match="simulated provider failure"):
        asyncio.run(gateway.complete(request))
    assert limiter.summary()["session_ai_cost_usd"] == 0
    assert limiter.summary()["session_ai_requests"] == 1


def test_stream_settles_reservation_and_records_usage(monkeypatch):
    import kali_mind.config as config
    import kali_mind.security.rate_limit as rate_module

    monkeypatch.setattr(config.settings, "privacy_mode", False)
    monkeypatch.setattr(config.settings, "offline_mode", False)
    monkeypatch.setattr(config.settings, "default_provider", "fake")
    limiter = RateLimiter(config=RateLimitConfig(max_ai_cost_usd_per_session=5))
    monkeypatch.setattr(rate_module, "_limiter", limiter)
    gateway = gateway_with()
    request = AIRequest(messages=[Message(role=Role.user, content="hello")])

    async def collect():
        return [chunk async for chunk in gateway.stream(request)]

    assert asyncio.run(collect()) == ["hello", " world"]
    assert limiter.summary()["session_ai_cost_usd"] >= 0
    assert gateway.get_usage_summary()[0].requests == 1
    assert gateway.get_usage_summary()[0].output_tokens > 0


def test_stream_failure_releases_cost_reservation(monkeypatch):
    import kali_mind.config as config
    import kali_mind.security.rate_limit as rate_module

    monkeypatch.setattr(config.settings, "privacy_mode", False)
    monkeypatch.setattr(config.settings, "offline_mode", False)
    monkeypatch.setattr(config.settings, "default_provider", "fake")
    limiter = RateLimiter(config=RateLimitConfig(max_ai_cost_usd_per_session=5))
    monkeypatch.setattr(rate_module, "_limiter", limiter)
    gateway = gateway_with(provider=FakeProvider(fail=True))
    request = AIRequest(messages=[Message(role=Role.user, content="hello")])

    async def collect():
        return [chunk async for chunk in gateway.stream(request)]

    with pytest.raises(RuntimeError, match="simulated stream failure"):
        asyncio.run(collect())
    assert limiter.summary()["session_ai_cost_usd"] == 0


def test_debate_uses_each_provider_default_model(monkeypatch):
    import kali_mind.config as config
    import kali_mind.security.rate_limit as rate_module

    monkeypatch.setattr(config.settings, "privacy_mode", False)
    monkeypatch.setattr(config.settings, "offline_mode", False)
    limiter = RateLimiter(config=RateLimitConfig(max_ai_cost_usd_per_session=5))
    monkeypatch.setattr(rate_module, "_limiter", limiter)

    class ModelProvider(FakeProvider):
        def __init__(self, name, model):
            super().__init__()
            self.name = name
            self.model = model
            self.received_model = "unset"

        async def complete(self, request):
            self.received_model = request.model
            return AIResponse(content="ok", provider=self.name, model=self.model)

    a, b = ModelProvider("a", "model-a"), ModelProvider("b", "model-b")
    gateway = AIGateway.__new__(AIGateway)
    gateway._providers = {"a": a, "b": b}
    gateway._usage = {}
    gateway._health_cache = {}
    request = AIRequest(messages=[Message(role=Role.user, content="compare")], model="model-from-other-provider")
    results = asyncio.run(gateway.debate(request, ["a", "b"]))
    assert len(results) == 2
    assert a.received_model is None and b.received_model is None


def test_router_privacy_override_cannot_select_remote(monkeypatch):
    import kali_mind.config as config
    from kali_mind.ai.router import ModelRouter, TaskType

    monkeypatch.setattr(config.settings, "privacy_mode", True)
    monkeypatch.setattr(config.settings, "offline_mode", False)
    router = ModelRouter(["ollama", "openai"])
    with pytest.raises(ValueError, match="conflicts with privacy"):
        router.select_provider(TaskType.CHAT, override="openai")


def test_explicit_unknown_provider_does_not_silently_fallback(monkeypatch):
    import kali_mind.config as config

    monkeypatch.setattr(config.settings, "privacy_mode", False)
    monkeypatch.setattr(config.settings, "offline_mode", False)
    gateway = gateway_with()
    request = AIRequest(messages=[Message(role=Role.user, content="hello")])
    with pytest.raises(RuntimeError, match="not configured or available"):
        asyncio.run(gateway.complete(request, provider="missing-provider"))


def test_gemini_maps_roles_and_keeps_api_key_out_of_url(monkeypatch):
    import kali_mind.ai.providers.gemini_provider as module

    captured = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": "part one"}, {"text": " part two"}]}}]}

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def post(self, url, **kwargs):
            captured.update(url=url, **kwargs)
            return Response()

    monkeypatch.setattr(module.httpx, "AsyncClient", Client)
    request = AIRequest(
        system="be precise",
        messages=[Message(role=Role.user, content="hi"), Message(role=Role.assistant, content="hello"), Message(role=Role.user, content="again")],
    )
    response = asyncio.run(module.GeminiProvider(api_key="secret", model="gemini-test").complete(request))
    assert response.content == "part one part two"
    assert "secret" not in captured["url"]
    assert captured["headers"]["x-goog-api-key"] == "secret"
    assert [item["role"] for item in captured["json"]["contents"]] == ["user", "model", "user"]
    assert captured["json"]["systemInstruction"]["parts"][0]["text"] == "be precise"


def test_anthropic_maps_system_messages_and_extracts_multiple_text_blocks(monkeypatch):
    import kali_mind.ai.providers.anthropic_provider as module

    captured = {}

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"content": [{"type": "text", "text": "first"}, {"type": "tool_use", "id": "x"}, {"type": "text", "text": " second"}], "usage": {"input_tokens": 2, "output_tokens": 3}}

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def post(self, url, **kwargs):
            captured.update(url=url, **kwargs)
            return Response()

    monkeypatch.setattr(module.httpx, "AsyncClient", Client)
    request = AIRequest(messages=[
        Message(role=Role.system, content="system from history"),
        Message(role=Role.user, content="hi"),
        Message(role=Role.assistant, content="hello"),
    ])
    response = asyncio.run(module.AnthropicProvider(api_key="secret").complete(request))
    assert response.content == "first second"
    assert captured["json"]["system"] == "system from history"
    assert all(m["role"] in ("user", "assistant") for m in captured["json"]["messages"])


def test_cohere_rejects_non_user_final_turn_before_network_call():
    from kali_mind.ai.providers.misc_providers import CohereProvider

    request = AIRequest(messages=[
        Message(role=Role.user, content="hello"),
        Message(role=Role.assistant, content="hi"),
    ])
    with pytest.raises(ValueError, match="final conversation turn to be a user"):
        asyncio.run(CohereProvider(api_key="secret").complete(request))

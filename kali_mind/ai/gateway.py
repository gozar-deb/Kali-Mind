"""AI Gateway — unified interface for all AI providers."""
from __future__ import annotations

import asyncio
import time
from typing import AsyncIterator, Dict, List, Optional

from kali_mind.ai.providers.base import BaseProvider
from kali_mind.ai.schemas import AIRequest, AIResponse, ProviderHealth, TokenUsage
from kali_mind.config import ProvidersConfig, load_providers_config, settings


class AIGateway:
    def __init__(self, providers_config: Optional[ProvidersConfig] = None) -> None:
        self._cfg = providers_config or load_providers_config()
        self._providers: Dict[str, BaseProvider] = {}
        self._usage: Dict[str, TokenUsage] = {}
        self._health_cache: Dict[str, ProviderHealth] = {}
        self._build_providers()

    def _build_providers(self) -> None:
        cfg = self._cfg

        if cfg.ollama.enabled:
            from kali_mind.ai.providers.ollama_provider import OllamaProvider
            self._providers["ollama"] = OllamaProvider(
                endpoint=cfg.ollama.endpoint or "http://localhost:11434",
                model=cfg.ollama.model or "llama3")

        if cfg.openai.enabled and cfg.openai.api_key:
            from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
            self._providers["openai"] = OpenAICompatProvider(
                name="openai", api_key=cfg.openai.api_key, model=cfg.openai.model or "gpt-4o-mini")

        if cfg.anthropic.enabled and cfg.anthropic.api_key:
            from kali_mind.ai.providers.anthropic_provider import AnthropicProvider
            p = AnthropicProvider(api_key=cfg.anthropic.api_key, model=cfg.anthropic.model or "claude-3-5-haiku-20241022")
            self._providers["anthropic"] = p
            self._providers["claude"] = p

        if cfg.grok.enabled and cfg.grok.api_key:
            from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
            self._providers["grok"] = OpenAICompatProvider(
                name="grok", api_key=cfg.grok.api_key, model=cfg.grok.model or "grok-beta",
                base_url=cfg.grok.endpoint or "https://api.x.ai/v1")

        if cfg.gemini.enabled and cfg.gemini.api_key:
            from kali_mind.ai.providers.gemini_provider import GeminiProvider
            self._providers["gemini"] = GeminiProvider(api_key=cfg.gemini.api_key, model=cfg.gemini.model or "gemini-1.5-flash")

        if cfg.deepseek.enabled and cfg.deepseek.api_key:
            from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
            self._providers["deepseek"] = OpenAICompatProvider(
                name="deepseek", api_key=cfg.deepseek.api_key, model=cfg.deepseek.model or "deepseek-chat",
                base_url=cfg.deepseek.endpoint or "https://api.deepseek.com/v1")

        if cfg.nvidia.enabled and cfg.nvidia.api_key:
            from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
            self._providers["nvidia"] = OpenAICompatProvider(
                name="nvidia", api_key=cfg.nvidia.api_key, model=cfg.nvidia.model or "meta/llama-3.1-8b-instruct",
                base_url=cfg.nvidia.endpoint or "https://integrate.api.nvidia.com/v1")

        if cfg.groq.enabled and cfg.groq.api_key:
            from kali_mind.ai.providers.misc_providers import GroqProvider
            self._providers["groq"] = GroqProvider(api_key=cfg.groq.api_key, model=cfg.groq.model or "llama-3.1-8b-instant")

        if cfg.mistral.enabled and cfg.mistral.api_key:
            from kali_mind.ai.providers.misc_providers import MistralProvider
            self._providers["mistral"] = MistralProvider(api_key=cfg.mistral.api_key, model=cfg.mistral.model or "mistral-small-latest")

        if cfg.cohere.enabled and cfg.cohere.api_key:
            from kali_mind.ai.providers.misc_providers import CohereProvider
            self._providers["cohere"] = CohereProvider(api_key=cfg.cohere.api_key, model=cfg.cohere.model or "command-r")

        if cfg.kimi.enabled and cfg.kimi.api_key:
            from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
            self._providers["kimi"] = OpenAICompatProvider(
                name="kimi", api_key=cfg.kimi.api_key, model=cfg.kimi.model or "moonshot-v1-8k",
                base_url=cfg.kimi.endpoint or "https://api.moonshot.cn/v1")

        if cfg.openrouter.enabled and cfg.openrouter.api_key:
            from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
            self._providers["openrouter"] = OpenAICompatProvider(
                name="openrouter", api_key=cfg.openrouter.api_key, model=cfg.openrouter.model or "openai/gpt-4o-mini",
                base_url=cfg.openrouter.endpoint or "https://openrouter.ai/api/v1")

        if cfg.together.enabled and cfg.together.api_key:
            from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
            self._providers["together"] = OpenAICompatProvider(
                name="together", api_key=cfg.together.api_key, model=cfg.together.model or "meta-llama/Llama-3-8b-chat-hf",
                base_url=cfg.together.endpoint or "https://api.together.xyz/v1")

    @property
    def available_providers(self) -> List[str]:
        return list(self._providers.keys())

    def get_provider(self, name: str) -> Optional[BaseProvider]:
        return self._providers.get(name)

    @staticmethod
    def _estimate_request_cost(provider: BaseProvider, request: AIRequest) -> float:
        """Conservatively reserve budget before a model call starts.

        Known OpenAI-compatible model rates are used where available. Unknown cloud
        providers use a conservative ceiling; local Ollama calls reserve no dollar cost.
        """
        if provider.__class__.__name__ == "OllamaProvider":
            return 0.0
        model = request.model or getattr(provider, "model", "") or ""
        input_text = (request.system or "") + "\n" + "\n".join(
            message.content for message in request.messages
        )
        input_tokens = max(1, (len(input_text) + 3) // 4)
        output_tokens = max(1, int(request.max_tokens))
        try:
            from kali_mind.ai.providers.openai_compat import _estimate_cost
            known = _estimate_cost(model, input_tokens, output_tokens)
            if known > 0:
                return known
        except Exception:
            pass
        # $30/M input and $100/M output are deliberately conservative fallbacks for
        # providers/models without a trusted price table.
        return (input_tokens * 0.00003) + (output_tokens * 0.0001)

    def _resolve_provider(self, request: AIRequest, provider: Optional[str] = None) -> tuple[str, BaseProvider, bool]:
        """Resolve one provider consistently for complete, stream and debate.

        Explicit provider requests never silently fall back. Automatic routing is
        constrained by privacy/offline mode before any override is considered.
        """
        local_only = bool(settings.privacy_mode or settings.offline_mode)
        explicit = provider or request.provider
        if local_only:
            if explicit and explicit.strip().lower() != "ollama":
                raise RuntimeError("Explicit provider conflicts with privacy/offline mode; only Ollama is permitted")
            name = "ollama"
            if name not in self._providers:
                raise RuntimeError(
                    "Privacy/offline mode requires a configured local Ollama provider; "
                    "no remote fallback is permitted"
                )
            return name, self._providers[name], True
        if explicit:
            name = explicit.strip().lower()
            if name not in self._providers:
                raise RuntimeError(f"Requested AI provider '{name}' is not configured or available")
            return name, self._providers[name], False

        # An explicit model identifier is meaningful only in a provider context.
        # Preserve the configured default provider in that case instead of sending
        # a provider-specific model name to an automatically selected vendor.
        if request.model:
            default_name = (settings.default_provider or "").strip().lower()
            if default_name not in self._providers:
                raise RuntimeError(
                    f"Model '{request.model}' was specified, but default provider "
                    f"'{default_name}' is not configured"
                )
            return default_name, self._providers[default_name], False

        # Route automatically by task only when the caller did not explicitly
        # choose a provider. The router itself enforces privacy/offline constraints.
        from kali_mind.ai.router import ModelRouter
        text = "\n".join([request.system or ""] + [m.content for m in request.messages])
        router = ModelRouter(list(self._providers))
        name = router.select_provider(router.infer_task_type(text))
        if name not in self._providers:
            raise RuntimeError("No suitable configured AI provider is available for this request")
        return name, self._providers[name], False

    @staticmethod
    def _request_for_provider(request: AIRequest, provider_name: str, preserve_model: bool = True) -> AIRequest:
        # Pydantic v2 is a declared dependency. Copy rather than mutate caller state.
        model = request.model if preserve_model else None
        return request.model_copy(update={"provider": provider_name, "model": model})

    def _limiter(self):
        from kali_mind.security.rate_limit import get_rate_limiter
        return get_rate_limiter()

    async def complete(self, request: AIRequest, provider: Optional[str] = None) -> AIResponse:
        name, p, local_only = self._resolve_provider(request, provider)
        provider_request = self._request_for_provider(
            request, name, preserve_model=bool(provider or request.provider or request.model)
        )
        estimated_cost = self._estimate_request_cost(p, provider_request)
        session_id = request.session_id or "default"
        limiter = self._limiter()
        from kali_mind.exceptions import PolicyDenied
        try:
            allowed, reason = limiter.consume_ai(estimated_cost, session_id)
        except Exception as exc:
            raise RuntimeError("AI rate-limit enforcement unavailable; request denied") from exc
        if not allowed:
            raise PolicyDenied(reason)
        try:
            response = await p.complete(provider_request)
            actual_cost = float(getattr(response, "cost_estimate", 0) or 0)
            if actual_cost <= 0 and not local_only:
                actual_cost = estimated_cost
                response.cost_estimate = actual_cost
            self._track_usage(response)
            limiter.settle_ai_cost(estimated_cost, actual_cost, session_id)
            try:
                from kali_mind.observability.metrics import get_metrics
                get_metrics().incr("ai.complete")
            except Exception:
                pass
            return response
        except BaseException:
            # Includes cancellation: never strand a cost reservation. The request
            # still counts against the per-minute request rate limit.
            limiter.release_ai_reservation(estimated_cost, session_id)
            raise

    async def complete_with_role(self, request: AIRequest, role: str) -> AIResponse:
        """Complete using the provider assigned to a specific role (planner/analyst/parser/reporter)."""
        role_map = {
            "planner": settings.planner_provider,
            "analyst": settings.analyst_provider,
            "parser": settings.parser_provider,
            "reporter": settings.reporter_provider,
        }
        provider = role_map.get(role)
        return await self.complete(request, provider=provider)

    async def stream(self, request: AIRequest, provider: Optional[str] = None) -> AsyncIterator[str]:
        name, p, local_only = self._resolve_provider(request, provider)
        provider_request = self._request_for_provider(
            request, name, preserve_model=bool(provider or request.provider or request.model)
        )
        estimated_cost = self._estimate_request_cost(p, provider_request)
        session_id = request.session_id or "default"
        limiter = self._limiter()
        from kali_mind.exceptions import PolicyDenied
        try:
            allowed, reason = limiter.consume_ai(estimated_cost, session_id)
        except Exception as exc:
            raise RuntimeError("AI rate-limit enforcement unavailable; request denied") from exc
        if not allowed:
            raise PolicyDenied(reason)

        chunks: list[str] = []
        completed = False
        try:
            async for token in p.stream(provider_request):
                if token:
                    chunks.append(token)
                    yield token
            completed = True
        finally:
            if completed:
                content = "".join(chunks)
                # Streaming interfaces expose text only, so estimate usage from
                # text length when provider-native usage metadata is unavailable.
                input_text = (provider_request.system or "") + "\n" + "\n".join(
                    m.content for m in provider_request.messages
                )
                input_tokens = max(0, (len(input_text) + 3) // 4)
                output_tokens = max(0, (len(content) + 3) // 4)
                actual_cost = self._estimate_request_cost(p, provider_request)
                if output_tokens:
                    try:
                        from kali_mind.ai.providers.openai_compat import _estimate_cost
                        model_name = provider_request.model or getattr(p, "model", "") or ""
                        provider_cost = _estimate_cost(model_name, input_tokens, output_tokens)
                        if provider_cost > 0:
                            actual_cost = provider_cost
                    except Exception:
                        pass
                if local_only:
                    actual_cost = 0.0
                limiter.settle_ai_cost(estimated_cost, actual_cost, session_id)
                # Reuse the standard usage aggregation for parity with complete().
                self._track_usage(AIResponse(
                    content=content, provider=name,
                    model=provider_request.model or getattr(p, "model", "unknown"),
                    input_tokens=input_tokens, output_tokens=output_tokens,
                    cost_estimate=actual_cost,
                ))
                try:
                    from kali_mind.observability.metrics import get_metrics
                    get_metrics().incr("ai.stream")
                except Exception:
                    pass
            else:
                limiter.release_ai_reservation(estimated_cost, session_id)

    async def debate(self, request: AIRequest, providers: List[str]) -> List[AIResponse]:
        """Compare provider responses with isolated model selection and accounting."""
        local_only = bool(settings.privacy_mode or settings.offline_mode)
        selected = ["ollama"] if local_only else list(dict.fromkeys(p.strip().lower() for p in providers if p))
        if local_only and "ollama" not in self._providers:
            raise RuntimeError("Privacy/offline mode requires a configured local Ollama provider; remote debate is disabled")
        available = [name for name in selected if name in self._providers]
        if not available:
            raise RuntimeError("No valid providers for debate mode")
        limiter = self._limiter()
        from kali_mind.exceptions import PolicyDenied
        session_id = request.session_id or "default"
        reservations: list[tuple[str, BaseProvider, AIRequest, float]] = []
        try:
            # Reserve every call before launching any network request. If one fails
            # policy checks, release earlier reservations and do not start partial work.
            for name in available:
                p = self._providers[name]
                provider_request = self._request_for_provider(request, name, preserve_model=False)
                estimate = self._estimate_request_cost(p, provider_request)
                allowed, reason = limiter.consume_ai(estimate, session_id)
                if not allowed:
                    raise PolicyDenied(reason)
                reservations.append((name, p, provider_request, estimate))
        except BaseException:
            for _name, _p, _req, estimate in reservations:
                limiter.release_ai_reservation(estimate, session_id)
            raise

        tasks = [p.complete(req) for _name, p, req, _estimate in reservations]
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        except BaseException:
            # If the caller cancels the debate, gather propagates cancellation.
            # Release every outstanding cost reservation rather than exhausting
            # the session budget with calls that never produced usable results.
            for _name, _p, _req, estimate in reservations:
                limiter.release_ai_reservation(estimate, session_id)
            raise
        valid: list[AIResponse] = []
        for (name, _p, _req, reserved), result in zip(reservations, results):
            if not isinstance(result, AIResponse):
                limiter.release_ai_reservation(reserved, session_id)
                continue
            actual = float(getattr(result, "cost_estimate", 0) or 0)
            if actual <= 0 and not local_only:
                actual = reserved
                result.cost_estimate = actual
            self._track_usage(result)
            limiter.settle_ai_cost(reserved, actual, session_id)
            valid.append(result)
        if not valid:
            raise RuntimeError("All selected AI providers failed during debate")
        return valid

    async def health_check_all(self) -> List[ProviderHealth]:
        results = []
        for name, provider in self._providers.items():
            t0 = time.monotonic()
            try:
                ok = await asyncio.wait_for(provider.health_check(), timeout=5.0)
                latency = (time.monotonic() - t0) * 1000
                h = ProviderHealth(name=name, available=ok, latency_ms=latency)
            except Exception as e:
                h = ProviderHealth(name=name, available=False, error=str(e))
            self._health_cache[name] = h
            results.append(h)
        return results

    def get_usage_summary(self) -> List[TokenUsage]:
        return list(self._usage.values())

    def _track_usage(self, response: AIResponse) -> None:
        key = f"{response.provider}:{response.model}"
        if key not in self._usage:
            self._usage[key] = TokenUsage(provider=response.provider, model=response.model)
        u = self._usage[key]
        u.input_tokens += response.input_tokens
        u.output_tokens += response.output_tokens
        u.requests += 1
        u.cost_estimate += response.cost_estimate
        u.total_latency_ms += response.latency_ms


_gateway: Optional[AIGateway] = None


def get_gateway() -> AIGateway:
    global _gateway
    if _gateway is None:
        _gateway = AIGateway()
    return _gateway


def reset_gateway() -> None:
    """FIX #9: allow resetting singleton after config changes."""
    global _gateway
    _gateway = None

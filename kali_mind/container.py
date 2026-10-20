"""Lightweight dependency-injection container.

Replaces ad-hoc global singletons with explicit construction and optional
overrides for tests. Call ``get_container()`` from application code; tests can
``reset_container()`` and inject fakes via ``Container.override``.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional, TypeVar

T = TypeVar("T")


class Container:
    """Simple service locator + factory registry."""

    def __init__(self) -> None:
        self._factories: Dict[str, Callable[["Container"], Any]] = {}
        self._singletons: Dict[str, Any] = {}
        self._overrides: Dict[str, Any] = {}

    def register(self, name: str, factory: Callable[["Container"], Any], *, singleton: bool = True) -> None:
        self._factories[name] = factory
        if not singleton and name in self._singletons:
            del self._singletons[name]

    def override(self, name: str, instance: Any) -> None:
        """Inject a test double; takes precedence over factories."""
        self._overrides[name] = instance

    def get(self, name: str) -> Any:
        if name in self._overrides:
            return self._overrides[name]
        if name in self._singletons:
            return self._singletons[name]
        if name not in self._factories:
            raise KeyError(f"Service not registered: {name}")
        instance = self._factories[name](self)
        self._singletons[name] = instance
        return instance

    def reset(self) -> None:
        self._singletons.clear()
        self._overrides.clear()


_container: Optional[Container] = None


def _build_default() -> Container:
    c = Container()

    def _settings(_c: Container):
        from kali_mind.config import settings
        return settings

    def _scope(_c: Container):
        from kali_mind.security.scope import get_scope_manager
        return get_scope_manager()

    def _policy(_c: Container):
        from kali_mind.security.policy import get_policy_engine
        return get_policy_engine()

    def _registry(_c: Container):
        from kali_mind.tools.registry import get_registry
        return get_registry()

    def _store(_c: Container):
        from kali_mind.evidence.store import get_store
        return get_store()

    def _executor(_c: Container):
        from kali_mind.execution.executor import get_executor
        return get_executor()

    def _gateway(_c: Container):
        from kali_mind.ai.gateway import get_gateway
        return get_gateway()

    def _rate_limiter(_c: Container):
        from kali_mind.security.rate_limit import get_rate_limiter
        return get_rate_limiter()

    def _cache(_c: Container):
        from kali_mind.execution.cache import get_tool_cache
        return get_tool_cache()

    def _secrets(_c: Container):
        from kali_mind.security.secrets import get_secret_store
        return get_secret_store()

    c.register("settings", _settings)
    c.register("scope", _scope)
    c.register("policy", _policy)
    c.register("registry", _registry)
    c.register("store", _store)
    c.register("executor", _executor)
    c.register("gateway", _gateway)
    c.register("rate_limiter", _rate_limiter)
    c.register("cache", _cache)
    c.register("secrets", _secrets)
    return c


def get_container() -> Container:
    global _container
    if _container is None:
        _container = _build_default()
    return _container


def reset_container() -> None:
    global _container
    if _container is not None:
        _container.reset()
    _container = None

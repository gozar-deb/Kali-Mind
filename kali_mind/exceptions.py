"""Domain exceptions for Kali-Mind.

Use these instead of bare Exception so callers can handle failures precisely.
"""
from __future__ import annotations


class KaliMindError(Exception):
    """Base exception for all Kali-Mind errors."""


class ConfigError(KaliMindError):
    """Invalid or missing configuration."""


class ScopeError(KaliMindError):
    """Target is outside authorized engagement scope."""


class PolicyDenied(KaliMindError):
    """Policy engine denied or requires approval for the requested action."""

    def __init__(self, reason: str, requires_approval: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.requires_approval = requires_approval


class AdapterError(KaliMindError):
    """Tool adapter failed to build, validate, or parse a request."""


class ToolNotFoundError(AdapterError):
    """Requested tool has no registered adapter or is not installed."""


class ValidationError(AdapterError):
    """Tool request failed validation (bad target, options, or flags)."""


class ExecutionError(KaliMindError):
    """Tool process failed, timed out, or was cancelled."""


class ProviderError(KaliMindError):
    """AI provider request failed or returned an unusable response."""


class PlanValidationError(KaliMindError):
    """AI-generated plan failed structural or policy validation."""


class EvidenceError(KaliMindError):
    """Evidence store or filesystem write failed."""

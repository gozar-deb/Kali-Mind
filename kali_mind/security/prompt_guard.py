"""Prompt-injection and tool-call output defenses.

Defenses layered on top of system prompts:
1. Sanitize user input for common injection markers
2. Validate model-emitted tool requests against schema + scope
3. Strip attempts to override system rules from conversation history
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Patterns frequently used in prompt-injection attempts
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)", re.I),
    re.compile(r"disregard\s+(your|the)\s+(system|safety)", re.I),
    re.compile(r"you\s+are\s+now\s+(dan|jailbroken|unrestricted)", re.I),
    re.compile(r"new\s+system\s+prompt\s*:", re.I),
    re.compile(r"<\|?(system|endoftext)\|?>", re.I),
    re.compile(r"\[INST\]|\[/INST\]", re.I),
]

_PLACEHOLDER_TARGETS = {
    "<target>", "<ip>", "<host>", "<url>", "TARGET", "HOSTNAME",
    "ACTUAL_IP_OR_HOSTNAME", "example.com", "TODO",
}


def sanitize_user_message(text: str) -> Tuple[str, List[str]]:
    """Flag and lightly neutralize injection attempts. Returns (text, warnings)."""
    warnings: List[str] = []
    cleaned = text
    for pat in _INJECTION_PATTERNS:
        if pat.search(cleaned):
            warnings.append(f"Possible prompt-injection pattern: {pat.pattern[:40]}…")
            cleaned = pat.sub("[filtered]", cleaned)
    if warnings:
        logger.warning("Prompt guard flagged %d pattern(s) in user input", len(warnings))
    return cleaned, warnings


def validate_tool_call(
    tool: str,
    operation: str,
    target: Optional[str],
    options: Optional[Dict[str, Any]],
    *,
    allowed_tools: Optional[set] = None,
) -> Tuple[bool, str]:
    """Post-model validation of a structured tool call."""
    if not tool or not isinstance(tool, str):
        return False, "Missing or invalid tool name"
    if allowed_tools is not None and tool not in allowed_tools:
        return False, f"Tool '{tool}' is not in the allowed set"
    if not isinstance(target, str):
        return False, "Target must be a non-empty string"
    t = target.strip()
    if not t or t in _PLACEHOLDER_TARGETS:
        return False, f"Invalid or placeholder target: {target!r}"
    if re.search(r"[;`|&$<>\n\r]", t):
        return False, "Target contains unsafe shell characters"
    if options is not None and not isinstance(options, dict):
        return False, "Options must be a dict"
    return True, "ok"


def filter_history_messages(messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Strip injection-like content from historical user turns before resending."""
    out = []
    for m in messages:
        role = m.get("role", "")
        content = m.get("content", "")
        if role == "user":
            content, _ = sanitize_user_message(content)
        out.append({"role": role, "content": content})
    return out

"""Untrusted tool-call channel — separate from natural language.

Models should emit tool requests only inside TOOL_CALL fences. The planner
parses these into structured ToolRequest objects and validates them before
execution. Natural-language content outside fences never becomes a command.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from kali_mind.security.prompt_guard import validate_tool_call
from kali_mind.tools.adapters.base import ToolRequest

logger = logging.getLogger(__name__)

# Capture through the closing fence, not the first closing brace: tool-call JSON
# commonly contains nested option objects.
TOOL_CALL_RE = re.compile(
    r"<TOOL_CALL>\s*(.*?)\s*</TOOL_CALL>",
    re.DOTALL | re.IGNORECASE,
)

TOOL_CALL_INSTRUCTIONS = """
When you need to run a tool, emit ONE or more blocks exactly like:

<TOOL_CALL>
{"tool":"nmap","operation":"quick_scan","target":"192.168.56.10","options":{}}
</TOOL_CALL>

Rules:
- Never put shell commands in chat text.
- Only use tools from the available list.
- target must be a real in-scope host/IP/URL — never placeholders.
- options must be a JSON object with safe keys only.
"""


def extract_tool_calls(text: str) -> List[Dict[str, Any]]:
    calls = []
    for m in TOOL_CALL_RE.finditer(text or ""):
        try:
            data = json.loads(m.group(1))
            if isinstance(data, dict):
                calls.append(data)
        except json.JSONDecodeError as e:
            logger.warning("Invalid TOOL_CALL JSON: %s", e)
    return calls


def tool_calls_to_requests(
    calls: List[Dict[str, Any]],
    *,
    allowed_tools: Optional[set] = None,
) -> Tuple[List[ToolRequest], List[str]]:
    """Convert raw tool call dicts to ToolRequest list; collect errors."""
    requests: List[ToolRequest] = []
    errors: List[str] = []
    for c in calls:
        tool = c.get("tool", "")
        operation = c.get("operation", "default")
        target = c.get("target")
        options = c.get("options", {})
        if not isinstance(tool, str) or not isinstance(operation, str):
            errors.append("Tool and operation must be strings")
            continue
        if not isinstance(options, dict):
            errors.append("Options must be a dict")
            continue
        ok, msg = validate_tool_call(tool, operation, target, options, allowed_tools=allowed_tools)
        if not ok:
            errors.append(msg)
            continue
        try:
            timeout = int(c.get("timeout", 300))
        except (TypeError, ValueError):
            errors.append("Timeout must be an integer between 1 and 7200 seconds")
            continue
        if timeout < 1 or timeout > 7200:
            errors.append("Timeout must be an integer between 1 and 7200 seconds")
            continue
        requests.append(ToolRequest(
            tool=tool, operation=operation, target=str(target), options=options, timeout=timeout,
        ))
    return requests, errors


def strip_tool_calls(text: str) -> str:
    return TOOL_CALL_RE.sub("", text or "").strip()

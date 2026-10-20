"""Base tool adapter interface with validation and normalized results."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from kali_mind.tools.registry import RiskLevel

# Characters that should never appear in a target (command-injection / path tricks)
_UNSAFE_TARGET_RE = re.compile(r"[;`|&$<>\n\r]|\$\(|`")


class ToolRequest(BaseModel):
    """Structured tool invocation request from the AI agent."""
    tool: str
    operation: str
    target: str
    options: Dict[str, Any] = Field(default_factory=dict)
    output_format: str = "text"
    timeout: int = Field(default=300, ge=1, le=7200)


class ToolResult(BaseModel):
    """Result from tool execution."""
    tool: str
    operation: str
    target: str
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    success: bool = True
    parsed: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: float = 0.0


class ParsedResult(BaseModel):
    """Normalized structure that every adapter should aim to produce.

    Downstream findings correlation and reporting work best when tools
    converge on this shape instead of free-form dicts.
    """
    hosts: List[Dict[str, Any]] = Field(default_factory=list)
    ports: List[Dict[str, Any]] = Field(default_factory=list)
    urls: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    credentials: List[Dict[str, Any]] = Field(default_factory=list)
    raw_summary: str = ""
    extra: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class BaseAdapter(ABC):
    """All tool adapters must implement this interface.

    Subclasses should:
    - declare ALLOWED_OPTIONS (whitelist of option keys)
    - declare ALLOWED_FLAGS (whitelist of raw flag strings if any)
    - override validate_request for tool-specific checks
    - produce parse_output that preferably returns a dict compatible with ParsedResult
    """

    tool_name: str = "unknown"
    risk_level: RiskLevel = RiskLevel.MEDIUM

    # Whitelist of option keys the adapter understands. Empty = accept any
    # (legacy). Prefer explicit lists for new adapters.
    ALLOWED_OPTIONS: Set[str] = set()

    # Whitelist of flag strings that may appear in options["extra_flags"]
    ALLOWED_FLAGS: Set[str] = set()

    @abstractmethod
    def build_command(self, request: ToolRequest) -> List[str]:
        """Construct the argv list from a structured request. Never use shell=True."""
        ...

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        """Parse raw tool output into structured data (ideally ParsedResult-compatible)."""
        ...

    def validate_request(self, request: ToolRequest) -> Optional[str]:
        """Return an error string if request is invalid, None otherwise.

        Base checks:
        - non-empty target
        - no shell metacharacters in target
        - option keys in ALLOWED_OPTIONS (when the set is non-empty)
        - extra flags in ALLOWED_FLAGS (when present)
        - timeout bounds
        """
        if not request.target or not str(request.target).strip():
            return "Target is required"

        target = str(request.target).strip()
        if target.startswith("-"):
            return "Target must not begin with '-' (option injection is not allowed)"
        if len(target) > 2048:
            return "Target exceeds the 2048-character safety limit"
        if "\x00" in target:
            return "Target contains a null byte"
        try:
            parsed_target = urlsplit(target) if "://" in target else None
            if parsed_target and (parsed_target.username or parsed_target.password):
                return "Credentials embedded in target URLs are not allowed"
        except ValueError:
            return "Target URL is malformed"
        if _UNSAFE_TARGET_RE.search(target):
            return f"Target contains unsafe characters: {target[:60]}"

        # Path traversal / absolute path tricks for tools that take file targets
        if ".." in target.split("/") or target.startswith(("/etc/", "/proc/", "/sys/", "/dev/")):
            # Allow only if the tool explicitly needs local files and is low risk
            if self.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                return f"Suspicious path in target for high-risk tool: {target[:60]}"

        if request.timeout < 1 or request.timeout > 7200:
            return f"Timeout out of range (1-7200): {request.timeout}"

        if self.ALLOWED_OPTIONS and request.options:
            unknown = set(request.options.keys()) - self.ALLOWED_OPTIONS
            if unknown:
                return f"Unknown options for {self.tool_name}: {sorted(unknown)}"

        extra_flags = request.options.get("extra_flags")
        if extra_flags is not None:
            if not isinstance(extra_flags, (list, tuple)):
                return "extra_flags must be a list of strings"
            if self.ALLOWED_FLAGS:
                for flag in extra_flags:
                    flag_str = str(flag).strip()
                    # Allow only exact matches or known prefixes
                    if flag_str not in self.ALLOWED_FLAGS and not any(
                        flag_str.startswith(f + " ") or flag_str.startswith(f + "=")
                        for f in self.ALLOWED_FLAGS
                    ):
                        return f"Disallowed flag for {self.tool_name}: {flag_str}"

        return None

    def supported_operations(self) -> List[str]:
        return []

    def safe_options(self, request: ToolRequest) -> Dict[str, Any]:
        """Return only the options that are in ALLOWED_OPTIONS (or all if unset)."""
        if not self.ALLOWED_OPTIONS:
            return dict(request.options)
        return {k: v for k, v in request.options.items() if k in self.ALLOWED_OPTIONS}

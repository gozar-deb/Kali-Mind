"""Tool discovery engine — detects available security tools on the system."""
from __future__ import annotations

import asyncio
import shutil
from typing import List, Optional

from kali_mind.tools.registry import ToolManifest, ToolRegistry, get_registry


async def discover_tools(registry: Optional[ToolRegistry] = None) -> List[ToolManifest]:
    """Scan system for installed tools and update registry availability."""
    if registry is None:
        registry = get_registry()

    tasks = [_check_tool(tool) for tool in registry.all_tools()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    available = []
    for tool, result in zip(registry.all_tools(), results):
        if isinstance(result, Exception):
            tool.available = False
        else:
            tool.available, tool.version = result
            if tool.available:
                available.append(tool)

    return available


async def _check_tool(tool: ToolManifest) -> tuple[bool, Optional[str]]:
    """Check if a tool binary exists and get its version."""
    binary_path = shutil.which(tool.binary)
    if not binary_path:
        return False, None

    version = await _get_version(binary_path, tool.version_flag)
    return True, version


async def _get_version(binary: str, flag: str = "--version") -> Optional[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, flag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        from kali_mind.execution.process_utils import communicate_with_timeout
        stdout, stderr = await communicate_with_timeout(proc, timeout=5.0)
        out = (stdout or stderr or b"").decode(errors="ignore").strip()
        # Extract first line, first 80 chars
        return out.split("\n")[0][:80] if out else None
    except Exception:
        return None


def discover_tools_sync() -> List[ToolManifest]:
    """Synchronous wrapper for tool discovery."""
    return asyncio.run(discover_tools())

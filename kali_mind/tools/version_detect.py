"""Tool version detection and simple flag adaptation hints."""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_VERSION_CACHE: Dict[str, str] = {}


async def detect_version(binary: str, flag: str = "--version") -> Optional[str]:
    if binary in _VERSION_CACHE:
        return _VERSION_CACHE[binary]
    try:
        proc = await asyncio.create_subprocess_exec(
            binary, flag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        from kali_mind.execution.process_utils import communicate_with_timeout
        out, err = await communicate_with_timeout(proc, timeout=5)
        text = (out or err or b"").decode(errors="ignore")
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
        ver = m.group(1) if m else text.split("\n")[0][:40]
        _VERSION_CACHE[binary] = ver
        return ver
    except Exception as e:
        logger.debug("version detect failed for %s: %s", binary, e)
        return None


def adapt_flags(tool: str, version: Optional[str], flags: list) -> list:
    """Example adaptations for known tools across versions."""
    if not version:
        return flags
    try:
        major = int(version.split(".")[0])
    except ValueError:
        return flags
    # nuclei: older versions used -jsonl naming differences etc.
    if tool == "nuclei" and major < 3:
        return [("json" if f == "-json" else f) for f in flags]
    return flags

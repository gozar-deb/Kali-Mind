"""In-session cache for identical tool requests."""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ToolCache:
    def __init__(self, ttl_seconds: float = 600.0, max_entries: int = 128) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._store: Dict[str, tuple[float, Any]] = {}

    @staticmethod
    def make_key(tool: str, operation: str, target: str, options: Optional[dict] = None) -> str:
        payload = json.dumps(
            {"tool": tool, "op": operation, "target": target, "opts": options or {}},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:24]

    def get(self, key: str) -> Optional[Any]:
        entry = self._store.get(key)
        if not entry:
            return None
        ts, value = entry
        if time.monotonic() - ts > self.ttl:
            del self._store[key]
            return None
        logger.debug("tool cache hit %s", key)
        return value

    def put(self, key: str, value: Any) -> None:
        if len(self._store) >= self.max_entries:
            # drop oldest
            oldest = min(self._store.items(), key=lambda kv: kv[1][0])[0]
            del self._store[oldest]
        self._store[key] = (time.monotonic(), value)

    def clear(self) -> None:
        self._store.clear()


_cache: Optional[ToolCache] = None


def get_tool_cache() -> ToolCache:
    global _cache
    if _cache is None:
        _cache = ToolCache()
    return _cache

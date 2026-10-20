"""Cross-session disk cache for tool results (TTL-based)."""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

from kali_mind.execution.cache import ToolCache

logger = logging.getLogger(__name__)


class DiskToolCache(ToolCache):
    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_seconds: float = 3600.0,
        max_entries: int = 500,
    ) -> None:
        super().__init__(ttl_seconds=ttl_seconds, max_entries=max_entries)
        if cache_dir is None:
            from kali_mind.config import settings
            cache_dir = settings.home_dir / "tool_cache"
        self.cache_dir = Path(cache_dir)
        existed = self.cache_dir.exists()
        self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not existed:
            try:
                self.cache_dir.chmod(0o700)
            except OSError:
                pass

    def _path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def get(self, key: str) -> Optional[Any]:
        mem = super().get(key)
        if mem is not None:
            return mem
        path = self._path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if time.time() - data.get("ts", 0) > self.ttl:
                path.unlink(missing_ok=True)
                return None
            value = data.get("value")
            super().put(key, value)
            logger.debug("disk cache hit %s", key)
            return value
        except Exception as e:
            logger.debug("disk cache read failed: %s", e)
            return None

    def put(self, key: str, value: Any) -> None:
        super().put(key, value)
        try:
            payload = {"ts": time.time(), "value": value if not hasattr(value, "model_dump") else value.model_dump()}
            path = self._path(key)
            path.write_text(json.dumps(payload, default=str), encoding="utf-8")
            path.chmod(0o600)
        except Exception as e:
            logger.debug("disk cache write failed: %s", e)


_disk: Optional[DiskToolCache] = None


def get_disk_cache() -> DiskToolCache:
    global _disk
    if _disk is None:
        _disk = DiskToolCache()
    return _disk

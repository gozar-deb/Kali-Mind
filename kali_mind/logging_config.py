"""Structured logging setup for Kali-Mind."""
from __future__ import annotations

import logging
import sys
from typing import Optional


_CONFIGURED = False


def setup_logging(level: str = "INFO", json_format: bool = False) -> None:
    """Configure root logger once.

    Args:
        level: Log level name (DEBUG, INFO, WARNING, ERROR).
        json_format: If True, emit simple key=value style lines suitable for
                     later JSON conversion. Keeps dependency surface zero.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    root = logging.getLogger("kali_mind")
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stderr)
    if json_format:
        fmt = logging.Formatter(
            "ts=%(asctime)s level=%(levelname)s logger=%(name)s msg=%(message)s"
        )
    else:
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    handler.setFormatter(fmt)
    root.addHandler(handler)

    # Quiet noisy third-party loggers
    for name in ("httpx", "httpcore", "asyncio", "uvicorn", "fastapi"):
        logging.getLogger(name).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a child logger under the kali_mind namespace."""
    if name:
        return logging.getLogger(f"kali_mind.{name}" if not name.startswith("kali_mind") else name)
    return logging.getLogger("kali_mind")

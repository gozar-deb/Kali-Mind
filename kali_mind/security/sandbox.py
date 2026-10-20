"""Optional sandboxed tool execution helpers.

Provides best-effort isolation for high-risk tools:
- Drop ambient authority via restricted environment
- Optional ``firejail`` / ``bubblewrap`` wrapper when installed
- Never claims full seccomp isolation unless those tools are present

Enable with env ``KALI_MIND_SANDBOX=1`` or ``settings.sandbox_mode``.
"""
from __future__ import annotations

import logging
import os
import shutil
from typing import List, Optional

logger = logging.getLogger(__name__)


def sandbox_available() -> Optional[str]:
    """Return the name of an available sandbox wrapper, or None."""
    for binary in ("firejail", "bwrap"):
        if shutil.which(binary):
            return binary
    return None


def wrap_command(cmd: List[str], *, enabled: bool = False) -> List[str]:
    """Optionally wrap *cmd* with firejail/bwrap for stronger isolation."""
    if not enabled:
        return list(cmd)
    wrapper = sandbox_available()
    if wrapper is None:
        logger.error("Sandbox requested but neither firejail nor bubblewrap is installed")
        raise RuntimeError("Sandbox mode is enabled, but firejail/bwrap is not installed")

    if wrapper == "firejail":
        # Network stays available (scanners need it); private home/tmp reduce side effects
        return [
            "firejail",
            "--quiet",
            "--private-tmp",
            "--private-home",
            "--caps.drop=all",
            "--nonewprivs",
            "--",
            *cmd,
        ]
    # bubblewrap minimal profile
    return [
        "bwrap",
        "--ro-bind", "/", "/",
        "--tmpfs", "/tmp",
        "--dev", "/dev",
        "--proc", "/proc",
        "--die-with-parent",
        "--",
        *cmd,
    ]


def restricted_env() -> dict:
    """Environment for child processes: strip secrets, keep PATH/locale."""
    keep = {
        "PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM",
        "TMPDIR", "TMP", "TEMP",
    }
    # Do not pass the whole KALI_MIND_* namespace: it may contain API tokens,
    # provider keys, or other credentials. Tool children only need basic runtime vars.
    return {k: v for k, v in os.environ.items() if k in keep}

"""Shared bounded subprocess handling for auxiliary commands."""
from __future__ import annotations

import asyncio
import os
import signal

MAX_AUX_STDOUT_BYTES = 10_000_000
MAX_AUX_STDERR_BYTES = 1_000_000


async def communicate_with_timeout(
    proc: asyncio.subprocess.Process,
    timeout: float,
    *,
    max_stdout_bytes: int = MAX_AUX_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_AUX_STDERR_BYTES,
) -> tuple[bytes, bytes]:
    """Read bounded output and kill/reap a process group on timeout/cancellation.

    Callers should launch POSIX subprocesses with ``start_new_session=True`` so the
    process group can be terminated without affecting unrelated processes. Output is
    drained even after a capture limit is reached to avoid blocking the child process.
    """
    async def read_limited(stream, limit: int, label: bytes) -> bytes:
        if stream is None:
            return b""
        chunks: list[bytes] = []
        remaining = max(0, limit)
        truncated = False
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                break
            if remaining > 0:
                kept = chunk[:remaining]
                chunks.append(kept)
                remaining -= len(kept)
                if len(kept) < len(chunk):
                    truncated = True
            else:
                truncated = True
        if truncated:
            chunks.append(label)
        return b"".join(chunks)

    stdout_task = asyncio.create_task(read_limited(proc.stdout, max_stdout_bytes, b"\n[stdout truncated]"))
    stderr_task = asyncio.create_task(read_limited(proc.stderr, max_stderr_bytes, b"\n[stderr truncated]"))
    wait_task = asyncio.create_task(proc.wait())
    try:
        stdout, stderr, _ = await asyncio.wait_for(
            asyncio.gather(stdout_task, stderr_task, wait_task), timeout=timeout
        )
        return stdout or b"", stderr or b""
    except (asyncio.TimeoutError, asyncio.CancelledError):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except (ProcessLookupError, PermissionError, OSError):
                pass
        for task in (stdout_task, stderr_task, wait_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(stdout_task, stderr_task, wait_task, return_exceptions=True)
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except (asyncio.TimeoutError, ProcessLookupError):
            pass
        raise

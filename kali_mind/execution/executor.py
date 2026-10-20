"""Command execution engine — structured process management."""
from __future__ import annotations

import asyncio
import logging
import os
import shlex
import signal
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

from kali_mind.tools.adapters.base import ToolRequest, ToolResult
from kali_mind.tools.adapters.registry import get_adapter
from kali_mind.security.policy import PolicyDecision, get_policy_engine

logger = logging.getLogger(__name__)

MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB


class ExecutionEngine:
    """
    Safe, structured process execution subsystem.
    Never calls os.system() with AI-generated strings.
    """

    def __init__(
        self,
        log_dir: Optional[Path] = None,
        output_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.log_dir = log_dir
        self.output_callback = output_callback
        self._running_processes: dict[int, asyncio.subprocess.Process] = {}

    async def execute(
        self,
        request: ToolRequest,
        skip_policy: bool = False,
        session_id: Optional[str] = None,
    ) -> ToolResult:
        """Execute a tool request safely."""
        t0 = time.monotonic()

        # Policy is mandatory. Keep the legacy parameter for API compatibility, but
        # never allow callers to bypass scope/risk enforcement with skip_policy=True.
        if skip_policy:
            logger.warning("Ignoring deprecated skip_policy=True; policy enforcement cannot be bypassed")
        policy = get_policy_engine()
        result = policy.evaluate(request)
        if result.decision == PolicyDecision.DENY:
            return ToolResult(
                tool=request.tool, operation=request.operation, target=request.target,
                command="", success=False, error=f"Policy denied: {result.reason}",
            )
        if result.decision == PolicyDecision.REQUIRE_APPROVAL:
            return ToolResult(
                tool=request.tool, operation=request.operation, target=request.target,
                command="", success=False, error=f"Approval required: {result.reason}",
            )

        # Get adapter and build command
        adapter = get_adapter(request.tool)
        if adapter is None:
            return ToolResult(
                tool=request.tool,
                operation=request.operation,
                target=request.target,
                command="",
                success=False,
                error=f"No adapter found for tool: {request.tool}",
            )

        validation_error = adapter.validate_request(request)
        if validation_error:
            return ToolResult(
                tool=request.tool,
                operation=request.operation,
                target=request.target,
                command="",
                success=False,
                error=f"Validation error: {validation_error}",
            )

        # Cache lookup only after policy evaluation: a cached result must never
        # bypass current scope, mode, risk, or approval requirements.
        cache_key = None
        try:
            from kali_mind.execution.disk_cache import get_disk_cache as get_tool_cache
            cache = get_tool_cache()
            cache_key = cache.make_key(request.tool, request.operation, request.target, request.options)
            cached = cache.get(cache_key)
            if isinstance(cached, dict):
                # Disk cache serializes Pydantic models as dictionaries.
                try:
                    cached = ToolResult.model_validate(cached)
                except Exception:
                    cached = None
            if isinstance(cached, ToolResult):
                logger.info("Cache hit for %s on %s", request.tool, request.target)
                return cached
        except Exception as exc:
            logger.debug("Tool cache unavailable: %s", exc)

        try:
            cmd = adapter.build_command(request)
        except Exception as exc:
            logger.exception("Adapter command construction failed for %s", request.tool)
            return ToolResult(
                tool=request.tool, operation=request.operation, target=request.target,
                command="", success=False, error=f"Adapter failed to build command: {exc}",
            )
        try:
            from kali_mind.security.sandbox import wrap_command
            from kali_mind.config import settings
            sandbox_on = bool(getattr(settings, "sandbox_mode", False))
            cmd = wrap_command(cmd, enabled=sandbox_on)
        except Exception as exc:
            logger.error("Execution isolation setup failed; refusing to run tool: %s", exc)
            return ToolResult(
                tool=request.tool, operation=request.operation, target=request.target,
                command="", success=False, error=f"Execution isolation setup failed: {exc}",
            )

        # Consume the tool quota atomically immediately before launch, after cache,
        # policy and request validation. This avoids parallel tasks racing the cap.
        try:
            from kali_mind.security.rate_limit import get_rate_limiter
            allowed, reason = get_rate_limiter().consume_tool(session_id or "default")
            if not allowed:
                return ToolResult(
                    tool=request.tool, operation=request.operation, target=request.target,
                    command="", success=False, error=f"Rate limited: {reason}",
                )
        except Exception as exc:
            logger.error("Rate-limit enforcement failed; refusing to execute: %s", exc)
            return ToolResult(
                tool=request.tool, operation=request.operation, target=request.target,
                command="", success=False, error="Rate-limit enforcement unavailable; execution denied",
            )

        cmd_str = shlex.join(cmd)
        logger.info("Executing: %s", cmd_str)

        if self.output_callback:
            try:
                self.output_callback(f"$ {cmd_str}\n")
            except Exception:
                logger.exception("Output callback failed; continuing with audited execution")

        try:
            stdout, stderr, exit_code = await self._run_process(
                cmd, timeout=request.timeout
            )
        except asyncio.TimeoutError:
            return ToolResult(
                tool=request.tool,
                operation=request.operation,
                target=request.target,
                command=cmd_str,
                success=False,
                error=f"Tool timed out after {request.timeout}s",
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        except Exception as e:
            return ToolResult(
                tool=request.tool,
                operation=request.operation,
                target=request.target,
                command=cmd_str,
                success=False,
                error=str(e),
                duration_ms=(time.monotonic() - t0) * 1000,
            )

        # Parse output
        try:
            parsed = adapter.parse_output(stdout, stderr, exit_code)
        except Exception as exc:
            logger.exception("Output parser failed for tool %s", request.tool)
            parsed = {"parse_error": str(exc), "raw_summary": stdout[:1000]}
        duration = (time.monotonic() - t0) * 1000

        result = ToolResult(
            tool=request.tool,
            operation=request.operation,
            target=request.target,
            command=cmd_str,
            stdout=stdout[:MAX_OUTPUT_BYTES],
            stderr=stderr[:50_000],
            exit_code=exit_code,
            success=exit_code == 0,
            parsed=parsed,
            duration_ms=duration,
        )

        if exit_code != 0 and not stdout.strip():
            result.success = False
            result.error = f"Exit code {exit_code}: {stderr[:500]}"

        self._log_result(result)
        if cache_key and result.success:
            try:
                from kali_mind.execution.disk_cache import get_disk_cache as get_tool_cache
                get_tool_cache().put(cache_key, result)
            except Exception:
                pass
        return result

    async def _run_process(
        self,
        cmd: List[str],
        timeout: int = 300,
    ) -> tuple[str, str, int]:
        """Run a process with bounded output capture and process-tree cleanup."""
        from kali_mind.security.sandbox import restricted_env

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=restricted_env(),
            start_new_session=True,
        )
        pid = proc.pid
        self._running_processes[pid] = proc

        async def read_limited(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
            chunks: list[bytes] = []
            remaining = limit
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
            return b"".join(chunks), truncated

        stdout_task = asyncio.create_task(read_limited(proc.stdout, MAX_OUTPUT_BYTES))
        stderr_task = asyncio.create_task(read_limited(proc.stderr, 50_000))
        wait_task = asyncio.create_task(proc.wait())
        try:
            (stdout_bytes, stdout_truncated), (stderr_bytes, stderr_truncated), _ = await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task, wait_task), timeout=float(timeout)
            )
        except (asyncio.TimeoutError, asyncio.CancelledError):
            # Kill the whole process group, not just the direct child; scanners often
            # spawn helper processes which otherwise outlive a timeout or cancellation.
            try:
                os.killpg(pid, signal.SIGKILL)
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
                logger.warning("Stopped process %s could not be reaped promptly", pid)
            raise
        finally:
            self._running_processes.pop(pid, None)

        stdout = stdout_bytes.decode(errors="replace") if stdout_bytes else ""
        stderr = stderr_bytes.decode(errors="replace") if stderr_bytes else ""
        if stdout_truncated:
            stdout += "\n[stdout truncated at configured capture limit]"
        if stderr_truncated:
            stderr += "\n[stderr truncated at configured capture limit]"
        return stdout, stderr, proc.returncode or 0

    def cancel_all(self) -> None:
        for pid, proc in list(self._running_processes.items()):
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as e:
                logger.debug("Failed to kill process %s: %s", pid, e)
        self._running_processes.clear()

    def _log_result(self, result: ToolResult) -> None:
        status = "OK" if result.success else "FAIL"
        logger.info(
            "[%s] %s:%s on %s (exit=%s, %.0fms)",
            status, result.tool, result.operation, result.target,
            result.exit_code, result.duration_ms,
        )
        if self.log_dir:
            try:
                self.log_dir.mkdir(parents=True, exist_ok=True)
                import re
                safe_tool = re.sub(r"[^A-Za-z0-9_-]+", "_", str(result.tool)).strip("._-")[:40] or "tool"
                ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                log_file = self.log_dir / f"{safe_tool}_{ts}.log"
                log_file.write_text(
                    f"Command: {result.command}\n"
                    f"Exit: {result.exit_code}\n"
                    f"Duration: {result.duration_ms:.0f}ms\n\n"
                    f"STDOUT:\n{result.stdout}\n\n"
                    f"STDERR:\n{result.stderr}\n",
                    encoding="utf-8",
                )
                log_file.chmod(0o600)
            except Exception as e:
                logger.warning("Failed to write tool log for %s: %s", result.tool, e)


_engine: Optional[ExecutionEngine] = None


def get_executor() -> ExecutionEngine:
    global _engine
    if _engine is None:
        from kali_mind.config import settings
        _engine = ExecutionEngine(log_dir=settings.logs_dir)
    return _engine

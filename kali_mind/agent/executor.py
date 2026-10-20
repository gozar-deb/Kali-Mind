"""Agent executor — executes plans with parallel step support and wordlist validation."""
from __future__ import annotations

import asyncio
import os
from typing import Callable, Dict, List, Optional

from kali_mind.agent.memory import AgentMemory
from kali_mind.agent.models import ExecutionPlan, PlanStep
from kali_mind.evidence.store import EvidenceRecord, get_store
from kali_mind.execution.executor import ExecutionEngine
from kali_mind.tools.adapters.base import ToolRequest
from kali_mind.tools.adapters.registry import get_adapter

# FIX #11: Common wordlist fallback paths
WORDLIST_FALLBACKS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]


def find_wordlist() -> Optional[str]:
    for path in WORDLIST_FALLBACKS:
        if os.path.exists(path):
            return path
    return None


class StepResult:
    def __init__(self, step: PlanStep, success: bool, output: str, parsed: Optional[Dict] = None) -> None:
        self.step = step
        self.success = success
        self.output = output
        self.parsed = parsed or {}


class AgentExecutor:
    def __init__(self, execution_engine: ExecutionEngine, memory: AgentMemory,
                 session_id: str, progress_callback: Optional[Callable[[str], None]] = None) -> None:
        self.engine = execution_engine
        self.memory = memory
        self.session_id = session_id
        self.progress_callback = progress_callback or (lambda msg: None)
        self.store = get_store()

    async def execute_plan(self, plan: ExecutionPlan, *, skip_validation: bool = False) -> List[StepResult]:
        """Execute all steps, grouping parallel ones with asyncio.gather. Feature #17.

        Plans are validated (scope, tool availability, adapter checks) before any
        tool is launched unless skip_validation=True.
        """
        # Work on a copy so target inference does not mutate the caller's plan.
        plan = plan.model_copy(deep=True)
        for planned_step in plan.steps:
            if planned_step.tool and not planned_step.target:
                planned_step.target = self._infer_target()

        if not skip_validation:
            from kali_mind.agent.plan_validator import PlanValidator
            from kali_mind.exceptions import PlanValidationError
            ok, issues = PlanValidator().validate(plan)
            if not ok:
                self.progress_callback("Plan validation failed:")
                for issue in issues:
                    self.progress_callback(f"  ✗ {issue}")
                raise PlanValidationError("; ".join(issues))

        self.store.log_action(self.session_id, "plan_started", plan.objective)
        results: List[StepResult] = []

        # Group steps: sequential vs parallel
        i = 0
        steps = plan.steps
        while i < len(steps):
            step = steps[i]

            # Feature #17: collect a parallel batch
            if step.parallel:
                batch = [step]
                j = i + 1
                while j < len(steps) and steps[j].parallel:
                    batch.append(steps[j])
                    j += 1
                # Honor the configured concurrency cap rather than hard-coding it.
                try:
                    from kali_mind.security.rate_limit import get_rate_limiter
                    max_parallel = max(1, int(get_rate_limiter().config.max_parallel_tools))
                except Exception:
                    max_parallel = 1
                self.progress_callback(
                    f"[Parallel batch: {len(batch)} steps, max {max_parallel} concurrent]"
                )
                batch_results: List[StepResult] = []
                for chunk_start in range(0, len(batch), max_parallel):
                    chunk = batch[chunk_start:chunk_start + max_parallel]
                    chunk_results = await asyncio.gather(
                        *[self._execute_step(s, results + batch_results) for s in chunk]
                    )
                    batch_results.extend(chunk_results)
                results.extend(batch_results)
                for batch_result in batch_results:
                    status = "✓" if batch_result.success else "✗"
                    self.progress_callback(
                        f"  {status} Step {batch_result.step.step}: "
                        f"{batch_result.step.description[:60]}"
                    )
                    if batch_result.parsed:
                        self.memory.add_tool_result(
                            batch_result.step.tool or "unknown", batch_result.parsed
                        )
                i = j
            else:
                result = await self._execute_step(step, results)
                results.append(result)
                status = "✓" if result.success else "✗"
                self.progress_callback(f"  {status} Step {step.step}: {step.description[:60]}")
                if result.parsed:
                    self.memory.add_tool_result(step.tool or "unknown", result.parsed)
                i += 1
            await asyncio.sleep(0.05)

        succeeded = len([r for r in results if r.success])
        self.store.log_action(self.session_id, "plan_completed",
                              f"{succeeded}/{len(results)} steps succeeded")
        return results

    async def _execute_step(self, step: PlanStep, previous: List[StepResult]) -> StepResult:
        if step.depends_on is not None:
            dependency = next((r for r in previous if r.step.step == step.depends_on), None)
            if dependency is None:
                return StepResult(
                    step, False, f"Dependency step {step.depends_on} has not completed"
                )
            if not dependency.success:
                return StepResult(
                    step, False, f"Skipped because dependency step {step.depends_on} failed"
                )

        if not step.tool:
            return StepResult(step, True, step.description)

        adapter = get_adapter(step.tool)
        if not adapter:
            return StepResult(step, False, f"No adapter for '{step.tool}'. Is it installed?")

        target = step.target or self._infer_target()
        if not target:
            return StepResult(step, False, "No target available for this step")

        # FIX #11: inject valid wordlist if missing
        options = dict(step.options)
        if step.tool in ("ffuf", "gobuster", "feroxbuster", "dirsearch") and "wordlist" not in options:
            wl = find_wordlist()
            if wl:
                options["wordlist"] = wl
            else:
                return StepResult(step, False,
                    "No wordlist found. Install with: sudo apt install wordlists seclists")

        request = ToolRequest(tool=step.tool, operation=step.operation or "default",
                              target=target, options=options)
        tool_result = await self.engine.execute(request, session_id=self.session_id)

        ev = EvidenceRecord(
            session_id=self.session_id, tool=tool_result.tool,
            operation=tool_result.operation, target=tool_result.target,
            command=tool_result.command,
            # FIX #18: truncate stdout in evidence, full output to file
            stdout=tool_result.stdout[:50_000],
            stderr=tool_result.stderr[:10_000],
            exit_code=tool_result.exit_code, parsed=tool_result.parsed,
        )
        self._save_full_output(tool_result.tool, target, tool_result.stdout)
        self.store.store_evidence(ev)
        self.store.log_action(self.session_id,
                              f"tool:{step.tool}:{step.operation}",
                              f"target={target} exit={tool_result.exit_code}")

        return StepResult(step, tool_result.success,
                          tool_result.stdout or tool_result.error or "", tool_result.parsed)

    def _infer_target(self) -> Optional[str]:
        if self.memory.targets:
            return self.memory.targets[0]
        if self.memory.discovered_hosts:
            return self.memory.discovered_hosts[0]
        return None

    def _save_full_output(self, tool: str, target: str, stdout: str) -> None:
        """FIX #18: save full output to evidence dir (best-effort, fully exception-safe)."""
        if not stdout or len(stdout) <= 50_000:
            return
        try:
            from kali_mind.config import settings
            from datetime import datetime
            import logging
            import re
            safe_tool = re.sub(r"[^A-Za-z0-9_-]+", "_", str(tool)).strip("._-")[:40] or "tool"
            safe_target = re.sub(r"[^A-Za-z0-9_-]+", "_", str(target)).strip("._-")[:40] or "target"
            fname = f"{safe_tool}_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.txt"
            out_dir = settings.evidence_dir
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / fname
            out_path.write_text(stdout, errors="replace", encoding="utf-8")
            out_path.chmod(0o600)
        except Exception as e:
            logging.getLogger(__name__).debug(
                "Best-effort evidence save failed for %s: %s", tool, e
            )

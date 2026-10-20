"""Security policy engine with audit logging."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from kali_mind.security.scope import get_scope_manager
from kali_mind.tools.adapters.base import ToolRequest
from kali_mind.tools.registry import RiskLevel, ToolCategory, get_registry

logger = logging.getLogger(__name__)


class ExecutionMode(str, Enum):
    MANUAL = "manual"
    ASSISTED = "assisted"
    AUTONOMOUS = "autonomous"
    DRY_RUN = "dry_run"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class PolicyResult:
    def __init__(
        self,
        decision: PolicyDecision,
        reason: str,
        risk_level: RiskLevel = RiskLevel.LOW,
    ) -> None:
        self.decision = decision
        self.reason = reason
        self.risk_level = risk_level

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "risk_level": self.risk_level.value,
        }


class PolicyEngine:
    """Evaluates tool requests against scope, risk, and execution mode.

    Every decision is appended to an audit log for later review.
    """

    def __init__(
        self,
        mode: ExecutionMode = ExecutionMode.ASSISTED,
        require_approval_above: RiskLevel = RiskLevel.MEDIUM,
        audit_log_path: Optional[Path] = None,
    ) -> None:
        self.mode = mode
        self.require_approval_above = require_approval_above
        self._risk_order = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }
        self._approval_threshold = self._risk_order[require_approval_above]
        self._audit_log_path = audit_log_path
        self._audit_buffer: List[Dict[str, Any]] = []

    def evaluate(self, request: ToolRequest) -> PolicyResult:
        result = self._evaluate_internal(request)
        self._audit(request, result)
        return result

    def _evaluate_internal(self, request: ToolRequest) -> PolicyResult:
        scope_mgr = get_scope_manager()
        in_scope, scope_reason = scope_mgr.is_in_scope(request.target)
        if not in_scope:
            return PolicyResult(
                PolicyDecision.DENY,
                f"Scope violation: {scope_reason}",
                RiskLevel.CRITICAL,
            )

        if self.mode == ExecutionMode.DRY_RUN:
            return PolicyResult(
                PolicyDecision.DENY,
                "Dry-run mode: execution disabled. Plan only.",
                RiskLevel.LOW,
            )

        registry = get_registry()
        tool_manifest = registry.get(request.tool)
        from kali_mind.tools.adapters.registry import get_adapter
        adapter = get_adapter(request.tool)

        # Use the more restrictive of registry and adapter metadata. Several built-in
        # aliases/adapters are not yet represented in the registry; never treat them as
        # low-risk merely because the manifest is missing.
        risk_candidates = []
        if tool_manifest is not None:
            risk_candidates.append(tool_manifest.risk_level)
        if adapter is not None:
            risk_candidates.append(getattr(adapter, "risk_level", RiskLevel.HIGH))
        risk = (
            max(risk_candidates, key=lambda item: self._risk_order.get(item, 2))
            if risk_candidates else RiskLevel.HIGH
        )
        risk_val = self._risk_order.get(risk, 2)

        category = tool_manifest.category.value if tool_manifest else ToolCategory.CUSTOM.value
        if not scope_mgr.is_category_allowed(category):
            return PolicyResult(
                PolicyDecision.DENY,
                f"Category '{category}' not in allowed scope categories.",
                risk,
            )

        if self.mode == ExecutionMode.MANUAL:
            return PolicyResult(
                PolicyDecision.DENY,
                "Manual mode: AI suggests commands only.",
                risk,
            )

        if risk == RiskLevel.CRITICAL:
            return PolicyResult(
                PolicyDecision.REQUIRE_APPROVAL,
                "Critical-risk operation requires explicit approval.",
                risk,
            )

        if risk_val >= self._approval_threshold and self.mode == ExecutionMode.ASSISTED:
            return PolicyResult(
                PolicyDecision.REQUIRE_APPROVAL,
                f"Risk level [{risk.value}] meets approval threshold.",
                risk,
            )

        return PolicyResult(
            PolicyDecision.ALLOW,
            "Request approved by policy engine.",
            risk,
        )

    def _audit(self, request: ToolRequest, result: PolicyResult) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "tool": request.tool,
            "operation": request.operation,
            "target": request.target,
            "options_keys": sorted(request.options.keys()) if request.options else [],
            "decision": result.decision.value,
            "reason": result.reason,
            "risk": result.risk_level.value,
            "mode": self.mode.value,
        }
        self._audit_buffer.append(entry)
        logger.info(
            "policy decision=%s tool=%s target=%s reason=%s",
            result.decision.value,
            request.tool,
            request.target,
            result.reason,
        )
        if self._audit_log_path:
            try:
                self._audit_log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._audit_log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except OSError as e:
                logger.warning("Failed to write policy audit log: %s", e)

    def recent_audit(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self._audit_buffer[-limit:])

    def set_mode(self, mode: ExecutionMode) -> None:
        if not isinstance(mode, ExecutionMode):
            raise ValueError(f"Invalid mode: {mode}. Must be one of {list(ExecutionMode)}")
        self.mode = mode
        logger.info("Execution mode set to %s", mode.value)

    def set_approval_threshold(self, level: RiskLevel) -> None:
        self.require_approval_above = level
        self._approval_threshold = self._risk_order[level]
        logger.info("Approval threshold set to %s", level.value)


_policy_engine: Optional[PolicyEngine] = None


def get_policy_engine() -> PolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        from kali_mind.config import settings
        audit_path = settings.logs_dir / "policy_audit.jsonl"
        _policy_engine = PolicyEngine(audit_log_path=audit_path)
    return _policy_engine


def reset_policy_engine() -> None:
    """Clear the singleton (useful for tests)."""
    global _policy_engine
    _policy_engine = None

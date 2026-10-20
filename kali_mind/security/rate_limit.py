"""Hard rate limits and API cost caps."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    max_tools_per_minute: int = 30
    max_tools_per_session: int = 200
    max_ai_requests_per_minute: int = 40
    max_ai_cost_usd_per_session: float = 5.0
    max_parallel_tools: int = 5


@dataclass
class RateLimiter:
    config: RateLimitConfig = field(default_factory=RateLimitConfig)
    _tool_timestamps: list = field(default_factory=list)
    _ai_timestamps: list = field(default_factory=list)
    _session_tool_counts: Dict[str, int] = field(default_factory=dict)
    _session_ai_costs: Dict[str, float] = field(default_factory=dict)
    _session_ai_counts: Dict[str, int] = field(default_factory=dict)

    def _prune(self, timestamps: list, window_s: float = 60.0) -> list:
        cutoff = time.monotonic() - window_s
        return [t for t in timestamps if t >= cutoff]

    def check_tool(self, session_id: str = "default") -> tuple[bool, str]:
        self._tool_timestamps = self._prune(self._tool_timestamps)
        if self._session_tool_counts.get(session_id, 0) >= self.config.max_tools_per_session:
            return False, f"Session tool cap reached ({self.config.max_tools_per_session})"
        if len(self._tool_timestamps) >= self.config.max_tools_per_minute:
            return False, f"Tool rate limit: {self.config.max_tools_per_minute}/min"
        return True, "ok"

    def consume_tool(self, session_id: str = "default") -> tuple[bool, str]:
        """Atomically check and reserve one tool execution for a session."""
        allowed, reason = self.check_tool(session_id)
        if not allowed:
            return False, reason
        self.record_tool(session_id)
        return True, "ok"

    def record_tool(self, session_id: str = "default") -> None:
        self._tool_timestamps.append(time.monotonic())
        self._session_tool_counts[session_id] = self._session_tool_counts.get(session_id, 0) + 1

    def check_ai(self, estimated_cost: float = 0.0, session_id: str = "default") -> tuple[bool, str]:
        self._ai_timestamps = self._prune(self._ai_timestamps)
        estimated_cost = max(0.0, float(estimated_cost))
        if self._session_ai_costs.get(session_id, 0.0) + estimated_cost > self.config.max_ai_cost_usd_per_session:
            return False, (
                f"Session AI cost cap ${self.config.max_ai_cost_usd_per_session:.2f} would be exceeded"
            )
        if len(self._ai_timestamps) >= self.config.max_ai_requests_per_minute:
            return False, f"AI rate limit: {self.config.max_ai_requests_per_minute}/min"
        return True, "ok"

    def consume_ai(self, estimated_cost: float = 0.0, session_id: str = "default") -> tuple[bool, str]:
        """Atomically reserve request count and estimated cost for a session."""
        estimated_cost = max(0.0, float(estimated_cost))
        allowed, reason = self.check_ai(estimated_cost, session_id)
        if not allowed:
            return False, reason
        self._ai_timestamps.append(time.monotonic())
        self._session_ai_counts[session_id] = self._session_ai_counts.get(session_id, 0) + 1
        self._session_ai_costs[session_id] = self._session_ai_costs.get(session_id, 0.0) + estimated_cost
        return True, "ok"

    def record_ai(self, cost: float = 0.0, session_id: str = "default") -> None:
        """Record a completed request (legacy API; also counts the request)."""
        self._ai_timestamps.append(time.monotonic())
        self._session_ai_counts[session_id] = self._session_ai_counts.get(session_id, 0) + 1
        self._session_ai_costs[session_id] = self._session_ai_costs.get(session_id, 0.0) + max(0.0, cost)

    def record_ai_cost(self, cost: float = 0.0, session_id: str = "default") -> None:
        """Add a cost adjustment for a request already counted by consume_ai()."""
        self._session_ai_costs[session_id] = self._session_ai_costs.get(session_id, 0.0) + max(0.0, cost)

    def settle_ai_cost(
        self, reserved_cost: float, actual_cost: float, session_id: str = "default"
    ) -> None:
        """Replace a request's conservative reservation with its known actual cost."""
        self._session_ai_costs[session_id] = max(
            0.0, self._session_ai_costs.get(session_id, 0.0)
            - max(0.0, reserved_cost) + max(0.0, actual_cost)
        )

    def release_ai_reservation(self, reserved_cost: float, session_id: str = "default") -> None:
        """Release a cost reservation when a request fails before cost is known.

        Request-count rate limiting is intentionally not rolled back: an attempted
        request still consumes rate-limit capacity even if the remote call fails.
        """
        self._session_ai_costs[session_id] = max(
            0.0,
            self._session_ai_costs.get(session_id, 0.0) - max(0.0, float(reserved_cost)),
        )

    def summary(self, session_id: str = "default") -> Dict[str, float]:
        return {
            "session_tools": float(self._session_tool_counts.get(session_id, 0)),
            "session_ai_requests": float(self._session_ai_counts.get(session_id, 0)),
            "session_ai_cost_usd": round(self._session_ai_costs.get(session_id, 0.0), 4),
            "tools_last_minute": float(len(self._prune(self._tool_timestamps))),
            "ai_last_minute": float(len(self._prune(self._ai_timestamps))),
        }

    def reset_session(self, session_id: str = "default") -> None:
        self._session_tool_counts.pop(session_id, None)
        self._session_ai_costs.pop(session_id, None)
        self._session_ai_counts.pop(session_id, None)


_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter

"""Feature #24: Real-time token and cost tracking dashboard."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from kali_mind.ai.schemas import TokenUsage

console = Console()
logger = logging.getLogger(__name__)


class CostTracker:
    """Tracks per-provider token usage and cost across a session."""

    def __init__(self) -> None:
        self._usage: Dict[str, TokenUsage] = {}
        self._gateway_seen: Dict[str, TokenUsage] = {}
        self._session_start = datetime.now()

    def record(self, usage: TokenUsage) -> None:
        key = f"{usage.provider}:{usage.model}"
        if key not in self._usage:
            self._usage[key] = TokenUsage(provider=usage.provider, model=usage.model)
        u = self._usage[key]
        u.input_tokens += usage.input_tokens
        u.output_tokens += usage.output_tokens
        u.requests += usage.requests
        u.cost_estimate += usage.cost_estimate
        u.total_latency_ms += usage.total_latency_ms

    def sync_from_gateway(self) -> None:
        """Pull latest usage from the gateway singleton."""
        try:
            from kali_mind.ai.gateway import get_gateway
            for current in get_gateway().get_usage_summary():
                key = f"{current.provider}:{current.model}"
                previous = self._gateway_seen.get(key)
                if previous is None:
                    delta = current.model_copy(deep=True)
                else:
                    # Gateway counters are cumulative snapshots. Record only their
                    # delta; adding the whole snapshot on every refresh double-counts.
                    fields = ("input_tokens", "output_tokens", "requests",
                              "cost_estimate", "total_latency_ms")
                    values = {}
                    for field_name in fields:
                        now_value = getattr(current, field_name)
                        old_value = getattr(previous, field_name)
                        values[field_name] = now_value - old_value if now_value >= old_value else now_value
                    delta = TokenUsage(
                        provider=current.provider, model=current.model, **values
                    )
                if any((delta.input_tokens, delta.output_tokens, delta.requests,
                        delta.cost_estimate, delta.total_latency_ms)):
                    self.record(delta)
                self._gateway_seen[key] = current.model_copy(deep=True)
        except Exception as e:
            logger.debug("Could not sync usage from gateway: %s", e)

    def render_table(self) -> Table:
        self.sync_from_gateway()
        table = Table(
            title=f"AI Usage — Session started {self._session_start.strftime('%H:%M:%S')}",
            box=box.ROUNDED, border_style="bright_blue", show_lines=True,
        )
        table.add_column("Provider", style="cyan")
        table.add_column("Model", style="white")
        table.add_column("Requests", justify="right")
        table.add_column("In Tokens", justify="right")
        table.add_column("Out Tokens", justify="right")
        table.add_column("Est. Cost", justify="right", style="yellow")
        table.add_column("Avg Latency", justify="right")

        total_cost = 0.0
        total_requests = 0
        for u in self._usage.values():
            avg_lat = f"{u.total_latency_ms / u.requests:.0f}ms" if u.requests else "—"
            cost_str = f"${u.cost_estimate:.4f}" if u.cost_estimate > 0 else "$0.00"
            table.add_row(u.provider, u.model[:30], str(u.requests),
                          f"{u.input_tokens:,}", f"{u.output_tokens:,}", cost_str, avg_lat)
            total_cost += u.cost_estimate
            total_requests += u.requests

        if not self._usage:
            table.add_row("[dim]No AI calls yet[/]", "—", "0", "0", "0", "$0.00", "—")
        else:
            table.add_row("", "[bold]TOTAL[/]", f"[bold]{total_requests}[/]",
                          "", "", f"[bold yellow]${total_cost:.4f}[/]", "")
        return table

    def render(self) -> None:
        console.print(Panel(self.render_table(), border_style="bright_blue"))

    def summary_line(self) -> str:
        self.sync_from_gateway()
        total_cost = sum(u.cost_estimate for u in self._usage.values())
        total_req = sum(u.requests for u in self._usage.values())
        total_tok = sum(u.input_tokens + u.output_tokens for u in self._usage.values())
        return f"AI: {total_req} calls | {total_tok:,} tokens | ${total_cost:.4f}"


_tracker: Optional[CostTracker] = None


def get_cost_tracker() -> CostTracker:
    global _tracker
    if _tracker is None:
        _tracker = CostTracker()
    return _tracker

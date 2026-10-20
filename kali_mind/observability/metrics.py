"""Lightweight metrics + optional OpenTelemetry hooks."""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class MetricsRegistry:
    counters: Dict[str, float] = field(default_factory=lambda: defaultdict(float))
    timers: Dict[str, list] = field(default_factory=lambda: defaultdict(list))

    def incr(self, name: str, value: float = 1.0) -> None:
        self.counters[name] += value
        self._otel_counter(name, value)

    def timing(self, name: str, duration_ms: float) -> None:
        self.timers[name].append(duration_ms)
        self._otel_histogram(name, duration_ms)

    def snapshot(self) -> dict:
        out = {"counters": dict(self.counters), "timers_ms": {}}
        for k, vals in self.timers.items():
            if vals:
                out["timers_ms"][k] = {
                    "count": len(vals),
                    "avg": sum(vals) / len(vals),
                    "max": max(vals),
                }
        return out

    def _otel_counter(self, name: str, value: float) -> None:
        try:
            from opentelemetry import metrics
            meter = metrics.get_meter("kali-mind")
            counter = meter.create_counter(name)
            counter.add(value)
        except Exception:
            pass

    def _otel_histogram(self, name: str, value: float) -> None:
        try:
            from opentelemetry import metrics
            meter = metrics.get_meter("kali-mind")
            hist = meter.create_histogram(name)
            hist.record(value)
        except Exception:
            pass


class Timer:
    def __init__(self, registry: MetricsRegistry, name: str) -> None:
        self.registry = registry
        self.name = name
        self._t0 = 0.0

    def __enter__(self):
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, *args):
        ms = (time.perf_counter() - self._t0) * 1000
        self.registry.timing(self.name, ms)


_metrics: Optional[MetricsRegistry] = None


def get_metrics() -> MetricsRegistry:
    global _metrics
    if _metrics is None:
        _metrics = MetricsRegistry()
    return _metrics

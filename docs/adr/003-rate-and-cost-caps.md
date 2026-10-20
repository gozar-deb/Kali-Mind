# ADR 003: Hard rate and cost caps

## Status
Accepted

## Decision
Every AI completion goes through RateLimiter.check_ai / record_ai. Tool runs go through check_tool / record_tool. Caps are session and per-minute based.

## Consequences
- Prevents runaway loops
- Operators can tune RateLimitConfig

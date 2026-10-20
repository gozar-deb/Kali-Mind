# ADR 001: Enforce scope at the execution layer

## Status
Accepted

## Context
AI models can hallucinate targets or follow injected instructions. Prompt-only controls are insufficient for a tool that launches real scanners.

## Decision
Every tool invocation is evaluated by `PolicyEngine` against `ScopeManager` **after** plan generation and **before** `asyncio.create_subprocess_exec`. Denials are audited to `policy_audit.jsonl`.

## Consequences
- Unauthorized targets cannot run even if the model requests them
- Operators must configure scope before testing
- Slight latency; clearer security properties

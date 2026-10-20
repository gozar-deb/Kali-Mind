# ADR 002: Untrusted tool-call channel

## Status
Accepted

## Decision
Tool invocations from models must appear only inside `<TOOL_CALL>{json}</TOOL_CALL>` fences (or structured provider tool APIs). Free-form chat text is never executed as a shell command.

## Consequences
- Clear separation between narration and actions
- Validation applied to JSON only

# Kali Mind v0.5.1 — Code Audit and Fix Report

## Scope and verification

This report documents the issues identified and corrected during the v0.5.0 audit pass. The review covered the Python source tree, security-critical execution and policy paths, AI provider routing, plugin loading, scope validation, reporting, persistence, API startup, and auxiliary subprocess helpers. All Python modules and tests compile, and an AST scan found no syntax errors or likely unused imports.

**Verification result:** `165 passed` with `pytest -q`; `python -m compileall -q kali_mind tests` passes. The measured test coverage is approximately **47%** across the package, so untested branches remain. The Ruff and Bandit commands could not be run because those tools are not installed in the execution environment.

## Issues fixed

### 1. Execution policy, scope, and tool validation

- Moved policy evaluation ahead of tool-cache lookup so cached output cannot bypass current scope, execution mode, risk, or approval rules.
- Made policy enforcement mandatory. The legacy `skip_policy=True` argument is retained for compatibility but no longer bypasses checks.
- Ensured adapter request validation happens before a cached result can be returned.
- Made tool rate-limit reservations atomic before process launch, and made per-session tool limits use the actual agent session ID.
- Made configured `max_parallel_tools` control parallel batches instead of hard-coding five workers.
- Made sandbox setup fail closed: if sandbox mode is requested but Firejail/Bubblewrap is unavailable or setup fails, the tool is not launched.
- Rejected option-like targets, null bytes, excessively long targets, URL-embedded credentials, unsafe shell metacharacters, and invalid timeout values.
- Made adapter command-construction and output-parser failures return controlled error results instead of crashing the execution flow.
- Made output callbacks best-effort so a UI callback exception does not unexpectedly abort a security task.
- Made the plan validator reject missing/forward dependencies and unsafe parallel dependencies; dependent steps are skipped when prerequisites fail.
- Aligned target inference between the orchestrator and executor.
- Updated sequential and parallel execution to consistently record results in agent memory and report parallel-step progress.

### 2. Subprocess safety and resource control

- Fixed timeout handling so the main executor kills and reaps the complete process group rather than leaving scanner child processes running.
- Added equivalent timeout/cancellation cleanup for auxiliary subprocesses used by screenshots, repository scanners, notifications, plugin installation, and tool discovery/version checks.
- Bounded captured stdout/stderr in the main executor and auxiliary subprocess helper to prevent unbounded output accumulation in memory.
- Restricted the environment passed to child tools to a minimal allowlist; API keys and arbitrary `KALI_MIND_*` secrets are no longer forwarded.
- Added unique, sanitized filenames for tool logs and full-output evidence to prevent path traversal and same-second overwrites.
- Restricted permissions on newly created managed directories and sensitive output files where supported.

### 3. AI privacy, rate limits, and cost accounting

- Removed remote-provider fallback from privacy/offline mode in complete, stream, and debate paths. If a local Ollama provider is unavailable, the request fails instead of sending content to a cloud provider.
- Reserved estimated AI cost before cloud calls so concurrent requests cannot all pass the cost check before any costs are recorded.
- Added conservative cost estimates for providers/models without known pricing, rather than treating unknown cloud usage as free.
- Scoped session tool counts and AI cost budgets by session ID while keeping per-minute request limits process-wide.
- Added validation bounds for model token limits and temperature.
- Removed duplicate AI request accounting from the orchestrator; the gateway is now the single request-accounting layer.
- Fixed the cost tracker so repeatedly syncing cumulative gateway snapshots records only deltas rather than repeatedly adding the same usage.

### 4. Plugin trust and Metasploit safeguards

- Required plugin signatures by default and removed the insecure built-in HMAC signing-key fallback.
- Rejected symlinked plugin directories/files, symlinked signature/checksum files, and checksum paths escaping the plugin directory.
- Validated plugin-template names to prevent path traversal.
- Made remote marketplace installs opt-in with `--allow-remote` in addition to command validation and interactive confirmation.
- Removed the implicit default Metasploit RPC password, enabled TLS certificate verification when TLS is used, enforced active scope, and required `approved=True` for exploit-capable module execution.
- Raised effective risk to the more restrictive level reported by the registry or adapter; critical adapters cannot be treated as lower risk merely because a registry manifest is missing. Unregistered tools require the explicit `custom` scope category.

### 5. Scope matching, reports, and user-controlled paths

- Fixed scope matching for authorized URLs and CIDR networks while preserving domain-label boundaries.
- Escaped untrusted finding/session/evidence fields in HTML and PDF reports and Telegram HTML notifications.
- Sanitized session export and report filenames; included session IDs to avoid same-name report collisions.
- Validated engagement IDs before using them as filesystem paths and ignored symlinked engagement files.
- Moved GitLeaks report output to a unique temporary directory instead of a predictable shared `/tmp` filename.

### 6. API, persistence, and reliability

- Fixed API token permission handling for both existing and newly created token files, rejected token-file symlinks, and used exclusive creation to avoid startup races.
- Stopped printing the API token to startup logs and used constant-time token comparison.
- Required TLS certificate and key files for non-loopback API binds; local loopback HTTP remains available for development.
- Replaced detailed internal report/export exception messages sent to API clients with generic errors while preserving server-side logs.
- Closed SQLite connections deterministically with commit/rollback handling, eliminating connection leaks and `ResourceWarning`s.
- Restricted permissions on evidence databases, disk-cache entries, reports, scope files, engagement files, session exports, logs, and full-output evidence where supported.
- Replaced mutable list defaults in affected Pydantic models with `default_factory`.
- Fixed mapping/model access in finding deduplication so empty fields do not cause `.get()` calls on model objects.
- Removed unused imports and duplicate pytest configuration that caused avoidable lint/config noise.

## Regression tests added

The new `tests/test_audit_regressions.py` suite covers URL/CIDR scope matching, nested tool-call JSON, malformed targets/timeouts, secret environment filtering, fail-closed sandboxing, signed plugin requirements and symlink rejection, mandatory policy enforcement, subprocess timeout and output limits, privacy-mode provider fallback, Metasploit approval/scope, HTML/PDF escaping, cost snapshot accounting, TLS binding requirements, path traversal protections, session-specific budgets, and pre-request AI cost reservation.

## Remaining limitations / items not certified

- This is a code audit and regression pass, **not a mathematical guarantee that no bugs remain**. Overall test coverage is approximately 47%, and some CLI/TUI, provider, adapter, and optional-feature branches remain lightly tested.
- Ruff and Bandit were not run because their executables were unavailable in this environment. CI should run both before release.
- No live cloud provider calls, Metasploit RPC service, real browser navigation, or scans against a real target were performed. External integrations should be tested in an authorized lab before deployment.
- Cost reservations for unknown cloud models are conservative estimates, not guaranteed representations of provider invoices. Configure limits appropriately and monitor actual provider usage.
- HMAC plugin signatures require a secret shared with the verifier; Ed25519 with a trusted public key is preferable for distributing plugins to other users.
- The API currently uses a single bearer token for access, not a complete per-user role/ownership authorization system. Do not expose it beyond a trusted environment without reviewing authentication, authorization, TLS, and reverse-proxy configuration.
- Sandbox mode depends on the local availability and correct configuration of Firejail or Bubblewrap; it now refuses to run unsandboxed when the mode is enabled.

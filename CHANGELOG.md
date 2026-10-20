## [0.5.2] - 2026-10-20

### Fixed — AI communication consistency
- Unified provider resolution for completion and streaming; explicit invalid providers now fail clearly.
- Enforced privacy/offline constraints before provider overrides and routing decisions.
- Integrated task-aware model routing when callers have not specified a provider or model.
- Kept provider-specific model identifiers from leaking across multi-provider debate requests.
- Released cost reservations on failed/cancelled completions and streams; settled streaming usage and metrics.
- Ensured debate requests reserve budgets before dispatch and clean up reservations on failures/cancellation.
- Corrected Anthropic system-role mapping and multi-block response extraction.
- Corrected Gemini conversation role mapping, system instructions, response parsing, and API-key header handling.
- Corrected Cohere message ordering and validation for a final user turn.
- Improved OpenAI-compatible response/stream parsing and made health checks distinguish authentication failures.
- Added native OpenAI-compatible streaming delegation for Groq and Mistral adapters.
- Added AI communication regression tests.

### Verification
- Automated test suite: 171 passed.
- Python compilation: passed.
- Live provider API smoke tests were not run; provider credentials and external service access were not available in this audit environment.

# Kali-Mind Changelog

## v0.5.1 — Security and reliability audit

- Enforced current scope/risk policy before cache lookup; deprecated `skip_policy=True` no longer bypasses policy.
- Made rate-limit and sandbox enforcement fail closed; tool quota reservation is atomic before process launch.
- Fixed subprocess timeout cleanup to kill/reap process groups, and bounded captured output in the main execution engine.
- Hardened privacy/offline mode so complete, streaming, and debate paths cannot fall back to remote providers.
- Enforced adapter risk levels in policy decisions; critical adapters still require approval in autonomous mode, and unregistered tools require the explicit `custom` scope category.
- Required explicit approval and active scope for Metasploit module execution; removed disabled TLS certificate verification and the implicit default RPC password.
- Required signed plugins by default, removed the insecure development HMAC key fallback, rejected symlinked plugin trees/path traversal, and hardened checksum validation.
- Fixed nested JSON tool-call parsing, missing-target validation, and malformed/out-of-range timeout handling.
- Unified sequential/parallel agent memory updates, target inference before plan validation, dependency ordering checks, and dependent-step failure propagation.
- Fixed URL/CIDR scope matching and rejected option-like targets.
- Escaped untrusted fields in HTML/PDF reports and Telegram notifications.
- Sanitized report/session/engagement/output filenames; prevented report and session export path traversal and log-name collisions.
- Isolated GitLeaks report files in private temporary directories.
- Fixed cumulative gateway usage being double-counted by the cost tracker and duplicate request counting in the orchestrator.
- Closed SQLite connections deterministically and restricted permissions on managed directories, evidence databases, cache files, reports, logs, scope, engagement, and export files where supported.
- Required TLS for non-loopback API binds, stopped printing the API token to startup logs, used constant-time token comparison, and stopped returning internal exception details from report/export endpoints.
- Added regression tests covering the audited security and correctness issues.
- Added per-session rate/cost accounting, conservative pre-request AI cost reservations, bounded auxiliary subprocess output, cancellation cleanup, API token race/symlink protections, and sensitive-file permissions.
- Fixed SQLite connection leaks, report filename traversal/collisions, Telegram HTML injection, engagement ID path traversal, and malformed finding model handling.
- Added `AUDIT_REPORT.md` with the fix inventory, test results, and remaining limitations.

## v0.5.0 — Full roadmap foundations

### Completed / substantially advanced
- Service orchestrator + multi-step reflection loop
- DI container expansion; disk tool cache; metrics (+ optional OTel)
- Plugin checksums + HMAC/Ed25519 signatures; entry-point section
- AI gateway hard rate/cost caps; tool_channel untrusted JSON channel
- Retrieval memory (lexical + optional embeddings)
- Family-specific local prompts; playbook runner CLI
- Offensive/cloud adapters (CME, Responder, Evil-WinRM, Impacket, AWS/Azure)
- Version detection helpers; multi-pane TUI; approval UI helper
- Multi-user token map (`users.json`); offline bundle helper
- Finding dedup in analysis path; lab walkthrough; Debian control; hard CI; mkdocs

---

## v0.4.0 — Architecture, Security & Roadmap Foundations

### Architecture
- Dependency-injection `container.py` for services (settings, scope, policy, gateway, rate limiter, cache, secrets)
- `services/orchestrator.py` shared plan→validate→critique→execute flow
- `cli_helpers.py` start of CLI monolith split
- Formal plugin protocol + checksum verification (`plugins/protocol.py`)

### Security
- Rate limits & AI cost caps (`security/rate_limit.py`)
- OS keyring-backed secret store (`security/secrets.py`)
- Optional firejail/bwrap sandbox wrapper (`security/sandbox.py`)
- Prompt-injection filters + tool-call validation (`security/prompt_guard.py`)
- ALLOWED_OPTIONS on recon adapters; new hardened extra adapters
- Restricted env strips API keys from child tool processes

### AI / agent
- Token-budgeted memory with history summarization
- Plan critique/revise loop in orchestrator
- Local-model system prompts (`ai/prompts.py`)
- Role-based provider routing (`ModelRouter.select_for_role`)
- Prompt guard wired into planner

### Adapters
- BloodHound, NetExec, Trivy, Semgrep, Impacket secretsdump adapters
- Tool result cache (`execution/cache.py`)

### Product / docs / ops
- Finding dedup + severity helpers
- Engagement playbooks (external_recon, web_app)
- Threat model, adapter authoring guide, ADR-001
- Dockerfile, GitHub Actions CI
- Expanded tests for v0.4 modules

### Not full product yet
- Multi-user multi-tenant mode (single-operator design remains)
- Full Textual multi-pane TUI rewrite
- Native provider tool-calling API across all vendors (schema validation is in place)
- 80% coverage (foundations + new tests added)

---

## v0.3.1 — Adapter Hardening, Bugfixes & Safety

### Bug fixes
- **Nikto parser**: fixed operator-precedence bug that treated any line containing "CVE" as a finding
- Report generators and API now use dynamic `__version__` (no more hardcoded stale versions)
- Findings analyzer logs parse failures instead of silent empty returns

### Security / safety
- Web adapters (httpx, ffuf, nikto, whatweb, nuclei) now use `ALLOWED_OPTIONS` / `ALLOWED_FLAGS`
- Ffuf wordlist path and match_codes sanitized; nuclei template paths reject `..`
- Parallel plan execution capped at 5 concurrent tools per batch

### Consistency
- Package version **0.3.1** across CLI, API, reports, and session export

---

## v0.3.0 — Security Hardening, Validation & Architecture

### Domain exceptions
- New `kali_mind.exceptions` module: `ScopeError`, `PolicyDenied`, `AdapterError`,
  `ValidationError`, `PlanValidationError`, `ExecutionError`, `ProviderError`, etc.

### Policy audit logging
- Every policy decision is logged to `~/.kali-mind/logs/policy_audit.jsonl`
- In-memory recent audit buffer for inspection

### Adapter validation
- Base adapter rejects targets with shell metacharacters
- Option key whitelist (`ALLOWED_OPTIONS`) and flag whitelist (`ALLOWED_FLAGS`)
- Timeout bounds and path-traversal heuristics for high-risk tools
- Nmap adapter updated with safe option/flag handling

### Plan validation
- New `agent/plan_validator.py` checks tool availability, scope, and adapter rules
  *before* any tool is executed
- Wired into `AgentExecutor.execute_plan()`

### Normalized results
- `ParsedResult` schema (hosts, ports, urls, findings, credentials, raw_summary)

### Logging
- `logging_config.setup_logging()` + `bootstrap()` called at CLI startup

### Tests
- New `tests/test_improvements.py` covering exceptions, scope, adapters,
  policy audit, plan validator, and logging

### Version
- Package version **0.3.0**

---

## v0.2.1 — Codebase Cleanup & Hardening

### Packaging & Structure
- Removed corrupted brace-named directories left by a bad archive (`{plugins,tests,...}`, `{ai`, etc.)
- Fixed `pyproject.toml` build-backend (`setuptools.build_meta`), added classifiers, keywords, URLs, and pytest/ruff config
- Improved `.gitignore` (secrets, caches, runtime artifacts)

### Consistency
- Unified all version strings to **0.2.0** (API, reports, session export previously still said 0.1.0)

### Reliability
- Replaced silent `except: pass` with proper logging in:
  - `security/scope.py` (load/save/clear)
  - `execution/executor.py` (process kill + log writes)
  - `agent/executor.py` (evidence file save)
  - `agent/planner.py` (JSON plan parse)
  - `features/notifications.py`, `cost_tracker.py`, `engagements.py`, `screenshot.py`, `plugin_marketplace.py`
- Scope matching improved (case-insensitive, cleaner domain/CIDR logic, better error messages)

### Safety notes
- Confirmed no `shell=True` or `os.system()` on AI-controlled input
- Process execution remains `asyncio.create_subprocess_exec` with argv lists

---

## v0.2.0 — Audit, Bug Fixes & 34 New Features

### Bug Fixes
- **FIX #1** `cli.py`: `Panel` import moved to top — was at line 872, after first usage
- **FIX #2** `scope.py`: Scope now persists to `~/.kali-mind/scope.yaml` on every mutation and loads at startup
- **FIX #3** `policy.py`: `set_mode()` now validates against `ExecutionMode` enum and raises `ValueError` on invalid input
- **FIX #4** `planner.py`: `_resolve_targets()` replaces `<target>` / `None` placeholders with real IPs from session memory
- **FIX #5** `analyzer.py`: `_parse_findings()` handles both bare arrays and wrapped dicts (`{"findings":[...]}`, `{"results":[...]}`)
- **FIX #6** Adapters: 17 new tool adapters added — masscan, subfinder, amass, gobuster, feroxbuster, wpscan, sqlmap, dirsearch, theHarvester, wafw00f, tshark, sherlock, naabu, strings, hydra, binwalk, exiftool
- **FIX #7** `openai_compat.py`: Exponential backoff retry on HTTP 429 / 5xx (up to 3 retries)
- **FIX #8** `gateway.py`: `offline_mode` and `privacy_mode` enforced directly in `AIGateway.complete()`, not just the router
- **FIX #9** `gateway.py`: `reset_gateway()` function added to clear singleton after config changes
- **FIX #10** `base.py`: `health_check()` defaults to lightweight HEAD/ping rather than a full LLM call
- **FIX #11** `executor.py`: Wordlist fallback chain with clear user error message if no wordlists found
- **FIX #12** `server.py`: FastAPI server generates a secure random token at startup, requires `Authorization: Bearer <token>` on all non-health endpoints; token printed to terminal on `kali-mind serve`
- **FIX #13** `config.py`: Migrated from deprecated Pydantic v1 `class Config` to `model_config = SettingsConfigDict(...)`
- **FIX #14** Tests: All evidence store tests use isolated temp DBs; API token generation tested

### New Features

| # | Feature | Module | Command |
|---|---------|--------|---------|
| 21 | Attack Surface Map — rich tree of hosts/ports/findings | `features/attack_surface.py` | `/map`, `kali-mind map <session>` |
| 22 | Multi-Model Collaboration — assign providers to roles | `gateway.py` + `config.py` | `.env` role assignments |
| 23 | AI Debate/Verification Mode | `findings/analyzer.py` | `/debate` |
| 24 | Real-Time Cost & Token Dashboard | `features/cost_tracker.py` | `/cost`, shown in prompt |
| 25 | Session Export/Import (JSON bundles) | `features/session_transfer.py` | `kali-mind sessions export/import` |
| 26 | Wordlist Manager | `features/wordlist_manager.py` | `kali-mind wordlists`, `/wordlists` |
| 27 | CVE Enrichment via NVD API | `features/cve_enrichment.py` | `/enrich` |
| 28 | Full Textual TUI | `features/tui_app.py` | `kali-mind tui`, `/tui` |
| 29 | Git/Secret Scanning (gitleaks/trufflehog) | `features/git_scanner.py` | `kali-mind git-scan`, `/git` |
| 30 | Metasploit RPC Integration | `features/msf_client.py` | Python API |
| 31 | Named Engagement Profiles | `features/engagements.py` | `kali-mind engagement new/activate` |
| 32 | Automatic Screenshot Capture | `features/screenshot.py` | `/screenshot <url>` |
| 33 | Notifications (desktop/Telegram/Slack) | `features/notifications.py` | Auto on high/critical findings |
| 34 | Plugin Marketplace | `features/plugin_marketplace.py` | `kali-mind plugins search/install/marketplace` |

### Architecture
- Streaming AI responses wired to interactive REPL via `gateway.stream()` (FIX #16 / Feature #16)
- Parallel plan step execution via `asyncio.gather()` for steps with `parallel: true` (Feature #17)
- Full evidence output truncated at 50KB in DB; full output saved to `~/.kali-mind/evidence/` (FIX #18)
- Copilot mode uses dedicated `COPILOT_SYSTEM` prompt via `planner.copilot_chat()` (FIX #19)
- AI logging unified (FIX #20)

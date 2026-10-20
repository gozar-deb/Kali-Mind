# Kali Mind AI Communication Audit — v0.5.2

Date: 2026-10-20

## Scope

Reviewed and updated the AI gateway, task router, provider adapters, AI cost/rate-limit lifecycle, and regression coverage. No live provider API calls were made; validation used local tests and mocked HTTP responses.

## Issues fixed

1. **Cost reservations leaked on failed completion calls.** Failed or cancelled completions now release estimated cost reservations while retaining the attempted request in the rate-limit counter.
2. **Streaming accounting differed from completion accounting.** Stream calls now settle reservations, record approximate token usage, aggregate usage, and increment stream metrics. Since the common streaming interface yields text chunks only, usage is estimated from character counts unless a future provider-specific usage channel is added.
3. **Debate requests could leak reservations on partial reservation failures or cancellation.** All provider budgets are reserved before dispatch; failed reservations are rolled back, failed provider results release their reservation, and cancellation releases outstanding reservations.
4. **Debate reused a model identifier across unrelated providers.** Each debate participant now uses its own configured model unless a provider-specific override is added in a future API.
5. **Provider selection differed between streaming and completion.** Both now use one resolution function. Explicit unknown providers fail clearly rather than silently falling back.
6. **Task-aware routing was not connected to the gateway.** Requests without an explicit provider or model now use `ModelRouter` task classification. Requests with an explicit model use the configured default provider so model IDs are not sent to an unrelated vendor.
7. **Privacy/offline routing could be overridden in the standalone router.** Privacy/offline policy is checked before overrides. The gateway refuses explicit non-local provider requests in privacy/offline mode and requires Ollama.
8. **Anthropic message conversion was invalid for system roles.** System instructions are moved into the top-level `system` field; only user/assistant roles are sent in `messages`; multiple text blocks are collected and empty text responses are reported clearly.
9. **Gemini message conversion lost conversation roles.** User and assistant turns are represented as `user` and `model` content entries; system instructions use `systemInstruction`; adjacent same-role messages are merged; response blocks are parsed robustly.
10. **Gemini API keys appeared in request URLs.** The key is now sent through the `x-goog-api-key` header for generation and health checks.
11. **Cohere could reference an undefined current user message.** The adapter now handles system messages as preamble, constructs chat history consistently, and rejects requests that do not end in a user turn before making a network call.
12. **OpenAI-compatible responses assumed a non-empty text field.** Response parsing now handles content-block lists, empty choices, and tool-call-only responses explicitly.
13. **OpenAI-compatible stream parsing silently swallowed malformed JSON.** Malformed streaming chunks now raise a clear error; usage-only chunks are ignored safely.
14. **Ollama stream parsing silently swallowed malformed JSON.** Invalid chunks now produce a clear error rather than silently returning partial output.
15. **Health checks treated authentication errors as healthy.** Anthropic, Gemini, Cohere, Groq, Mistral, and OpenAI-compatible health checks now require HTTP 200, distinguishing a reachable endpoint with invalid credentials from a usable integration.
16. **Groq and Mistral adapters did not delegate to native streaming support.** Both now delegate streaming to their OpenAI-compatible API adapter.
17. **Rate limiter lacked a reservation-release primitive.** Added `release_ai_reservation()` while deliberately retaining rate-limit counts for attempted calls.
18. **Version and changelog were stale.** Bumped package version to 0.5.2 and documented the changes.

## Regression tests added

- Failed completion reservation cleanup.
- Streaming usage accounting and reservation cleanup on failure.
- Provider-specific model selection in debate mode.
- Privacy router override enforcement.
- Explicit unknown-provider behavior.
- Gemini role/system instruction mapping and API-key header handling.
- Anthropic system-role conversion and multi-block response parsing.
- Cohere invalid final-turn rejection.

## Verification

- `pytest -q`: **174 passed**.
- `python -m compileall -q kali_mind tests`: passed.
- Ruff was not installed in this environment; Ruff checks were not run.
- No real provider requests were sent. Credentials, endpoint reachability, provider-specific quotas, model availability, and live streaming compatibility remain unverified.

## Remaining limitations

- Streaming usage is estimated from text length because the common provider interface currently exposes only text chunks, not standardized final usage metadata.
- Provider pricing tables and estimated costs are approximate and must not be interpreted as billing statements.
- Provider model names and API behavior can change; live smoke tests should be run with each configured credential before production use.
- Some OpenAI-compatible vendors have API-specific request differences despite sharing the chat-completions format; the new regression tests do not establish live compatibility for every vendor/model.

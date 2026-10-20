# Kali-Mind Threat Model

## Assets
- Engagement scope configuration
- Tool execution capability (can probe networks)
- AI API keys and session evidence
- Generated reports and findings

## Trust boundaries
1. **User → CLI/API**: Operator is trusted to set scope correctly.
2. **AI model → Tool requests**: Model output is **untrusted**. All tool calls pass through policy, scope, adapter validation, and prompt-guard checks.
3. **Plugins → Process**: Plugin adapters must use argv lists; install commands are prefix-whitelisted; optional SHA-256 checksums.
4. **Child tools → Host**: Optional firejail/bwrap sandbox; secrets stripped from tool environment.

## Threats and mitigations

| Threat | Mitigation |
|--------|------------|
| AI invents out-of-scope target | Scope gate at policy + plan validator + prompt guard |
| Prompt injection | Pattern filter + system prompt rules + tool-call schema validation |
| Command injection via options | ALLOWED_OPTIONS/FLAGS, no shell=True, metacharacter checks |
| Runaway autonomous loops | Rate limits (tools/min, session caps, AI cost caps) |
| Secret leakage to tools | `restricted_env()` strips API keys from child processes |
| Malicious plugin | Checksums, trusted install prefixes, risk levels |
| Unauthorized use | Legal notice; scope required before execution |

## Out of scope
- Protecting against a malicious local operator with root
- Full multi-tenant isolation (single-operator design)
- Guaranteeing model non-hallucination (mitigated, not eliminated)

## Residual risk
Model quality and adapter completeness remain residual risks. Prefer assisted mode and review plans before execution on sensitive networks.

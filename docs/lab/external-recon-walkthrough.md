# Lab walkthrough: External recon (expected flow)

## Setup
1. Scope a lab target only:
   ```bash
   kali-mind scope add 192.168.56.0/24
   kali-mind scope add 192.168.56.10
   ```
2. Ensure tools: `subfinder`, `httpx`, `whatweb`, `nuclei` (or use playbook with available tools).

## Run playbook
```bash
kali-mind playbook run external_recon --target 192.168.56.10
```

## Expected progression
1. Subdomain/host discovery (may be empty on pure IP labs)
2. HTTP probe → URLs/status codes in session memory
3. WhatWeb technologies listed
4. Nuclei findings (if templates present); severity medium+

## Expected artifacts
- Session under `~/.kali-mind/`
- Policy audit lines in `~/.kali-mind/logs/policy_audit.jsonl`
- Report via `kali-mind report SESSION-…`

## Failure cases
- No scope → all tools denied
- Offline without Ollama → AI plan fails; tools can still run via playbook steps without AI if invoked directly

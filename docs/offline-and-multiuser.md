# Offline / air-gapped and multi-user notes

## Full air-gapped offline story
1. Install with Ollama (or another local runtime) only — `KALI_MIND_DEFAULT_PROVIDER=ollama`
2. Enable `--offline` / `offline_mode` so the gateway never calls cloud APIs
3. Pre-load wordlists (SecLists) and nuclei templates onto local disk
4. Optional: offline CVE data via local NVD mirror; set no `NVD_API_KEY`
5. Plugin marketplace remote fetch will fail closed and use the built-in catalog

## Multi-user / shared engagements
Kali-Mind v0.4 remains a **single-operator** tool. Shared engagements would require:
- Authentication on the API (today: single bearer token)
- Per-user scopes and audit partitions
- Concurrent session isolation in the evidence DB

Until then, do not expose `kali-mind serve` beyond localhost without an authenticating reverse proxy, and treat the API token as a root credential for the local engagement.

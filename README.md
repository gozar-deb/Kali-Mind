# ⚔ Kali-Mind

**AI-Powered Kali Linux Security Orchestration Platform**

Kali-Mind is an advanced, extensible AI security orchestration platform that runs natively on Kali Linux. It allows security professionals to interact with Kali's security ecosystem through natural language.

Kali-Mind functions as an AI security copilot and agent runtime capable of:
- Understanding security objectives
- Selecting appropriate tools
- Constructing execution plans
- Running authorized security tools
- Analyzing and correlating output
- Maintaining engagement context
- Generating professional security reports

---

## ⚠️ Legal Notice

**Kali-Mind is designed for authorized security testing only.**

All active security testing must be performed only against systems you are explicitly authorized to test. Unauthorized scanning or testing is illegal in most jurisdictions. Always obtain written authorization before testing.

---

## Features

| Feature | Description |
|---|---|
| **Multi-Provider AI** | OpenAI, Claude, Grok, Gemini, Groq, Mistral, DeepSeek, Ollama, and more |
| **Smart Model Router** | Auto-selects best AI provider based on task complexity and privacy needs |
| **Tool Discovery** | Auto-detects 30+ Kali security tools at runtime |
| **Tool Adapters** | Structured adapters for Nmap, FFUF, HTTPx, Nikto, Nuclei, WhatWeb, and more |
| **AI Agent Runtime** | Plans, executes, and chains tools autonomously |
| **Human Approval System** | Manual / Assisted / Autonomous / Dry-run modes |
| **Scope Enforcement** | Policy engine enforces authorized targets at the execution layer |
| **Evidence Database** | SQLite-backed evidence store with full provenance |
| **Finding Correlation** | AI correlates evidence across tools into structured findings |
| **Multi-Format Reports** | Markdown, HTML, PDF, JSON, and SARIF reports |
| **Plugin System** | Extensible with custom tool plugins |
| **Privacy Mode** | `--privacy` flag forces local-only models |
| **Offline Mode** | `--offline` for air-gapped environments |
| **API Server** | Optional FastAPI backend for web dashboards and integrations |
| **Self-Diagnostics** | `kali-mind doctor` checks all dependencies |

---

## Installation

### Requirements

- Python 3.10+
- Kali Linux (or compatible Linux distribution)
- At least one AI provider configured (Ollama recommended for offline use)

### Install

```bash
git clone https://github.com/your-org/kali-mind
cd kali-mind

# Install with pip
pip install -e .

# Or with development dependencies
pip install -e ".[dev]"
```

### Configure

```bash
# Copy the environment template
cp .env.example .env

# Edit .env and add your API keys
nano .env
```

### Verify installation

```bash
kali-mind doctor
```

---

## Quick Start

### Interactive mode

```bash
kali-mind
```

### Configure scope (required before testing)

```bash
kali-mind scope add 192.168.56.0/24
kali-mind scope add 192.168.56.10
```

### Run the AI agent

```bash
kali-mind agent "Assess my authorized lab target 192.168.56.10"
```

### Command copilot

```bash
kali-mind copilot
```

### Generate a report

```bash
kali-mind report SESSION-XXXXX
```

---

## CLI Reference

```
kali-mind                        # Interactive AI session
kali-mind chat                   # Start chat session
kali-mind agent [objective]      # Run AI agent
kali-mind copilot                # Command copilot mode
kali-mind doctor                 # System diagnostics
kali-mind status                 # System status
kali-mind config                 # Show configuration
kali-mind serve                  # Start API server

kali-mind tools                  # List all tools
kali-mind tools search <query>   # Search tools
kali-mind tools discover         # Detect installed tools
kali-mind tools show <name>      # Show tool details

kali-mind sessions               # List sessions
kali-mind sessions show <id>     # Show session details
kali-mind sessions replay <id>   # Replay session timeline
kali-mind report <session_id>    # Generate reports

kali-mind scope                  # Show scope
kali-mind scope add <target>     # Add authorized target
kali-mind scope exclude <target> # Exclude target
kali-mind scope clear            # Clear scope

kali-mind plugins                # List plugins
kali-mind plugins add <name>     # Create plugin template

kali-mind models                 # List AI providers
```

### In-session slash commands

```
/agent <objective>    Run agent for objective
/scope add <target>   Add target to scope
/scope                Show scope
/tools                List available tools
/findings             Show findings
/report               Generate report
/status               Session status
/openai               Switch to OpenAI
/claude               Switch to Anthropic Claude
/grok                 Switch to xAI Grok
/gemini               Switch to Google Gemini
/groq                 Switch to Groq
/ollama               Switch to Ollama (local)
/auto                 Auto-select provider
```

---

## AI Providers

| Provider | Command | Environment Variable |
|---|---|---|
| Ollama (local) | `/ollama` | `OLLAMA_HOST` |
| OpenAI | `/openai` | `OPENAI_API_KEY` |
| Anthropic Claude | `/claude` | `ANTHROPIC_API_KEY` |
| xAI Grok | `/grok` | `XAI_API_KEY` |
| Google Gemini | `/gemini` | `GEMINI_API_KEY` |
| DeepSeek | `/deepseek` | `DEEPSEEK_API_KEY` |
| Groq | `/groq` | `GROQ_API_KEY` |
| Mistral | `/mistral` | `MISTRAL_API_KEY` |
| Moonshot / Kimi | `/kimi` | `KIMI_API_KEY` |
| NVIDIA NIM | `/nvidia` | `NVIDIA_API_KEY` |
| OpenRouter | — | `OPENROUTER_API_KEY` |
| Together AI | — | `TOGETHER_API_KEY` |
| Cohere | — | `COHERE_API_KEY` |

---

## Execution Modes

| Mode | Description |
|---|---|
| **Manual** | AI suggests commands only. User executes them manually. |
| **Assisted** | AI proposes each action. User approves before execution. |
| **Autonomous** | AI executes approved tool categories automatically in scope. |
| **Dry-Run** | No execution. AI generates plan only. |

---

## Supported Security Tools

### Reconnaissance
nmap, masscan, amass, subfinder, httpx, whatweb, wafw00f, naabu, theharvester

### Web Security
ffuf, gobuster, nikto, sqlmap, nuclei, feroxbuster, wpscan, dirsearch

### Network Analysis
tshark, tcpdump, netcat, socat, wireshark

### OSINT
theHarvester, sherlock, spiderfoot, recon-ng

### Password Testing (authorized lab use)
john, hashcat, hydra

### Exploitation Framework (authorized environments)
Metasploit Framework

### Reverse Engineering
ghidra, radare2, binwalk, strings, objdump, gdb

### Forensics
volatility3, exiftool, file

---

## Plugin System

Create custom plugins for any CLI security tool:

```bash
kali-mind plugins add my-scanner
```

This creates `~/.kali-mind/plugins/my-scanner/` with:
- `plugin.yaml` — tool metadata
- `adapter.py` — command builder and output parser
- `README.md` — documentation

---

## Privacy and Security

- **Privacy mode** (`--privacy`): forces local AI models only, disables cloud providers
- **Offline mode** (`--offline`): disables internet-dependent features
- **Scope enforcement**: policy engine validates all targets before execution
- **No arbitrary shell execution**: all tool invocations go through structured adapters
- **Fail-closed execution controls**: scope/risk policy, rate limiting, and requested sandboxing are enforced before launch
- **Signed plugins**: plugin signatures are required by default; unsigned plugins need an explicit local-development override
- **Audit logging**: all actions logged to session evidence store
- **Secret protection**: API keys only in `.env`, never committed

---

## API Server

Start the optional FastAPI backend:

```bash
kali-mind serve --host 127.0.0.1 --port 8765
```

API documentation available at: `http://localhost:8765/docs`. The API token is stored in
`~/.kali-mind/.api_token` and is not printed to logs. Non-loopback binds require TLS, e.g.
`kali-mind serve --host 0.0.0.0 --ssl-certfile cert.pem --ssl-keyfile key.pem`.

---

## Testing

```bash
pytest tests/ -v
```

---

## Project Structure

```
kali-mind/
├── kali_mind/
│   ├── ai/
│   │   ├── gateway.py         # Unified AI provider gateway
│   │   ├── router.py          # Intelligent model router
│   │   ├── schemas.py         # AI request/response models
│   │   └── providers/         # Per-provider implementations
│   ├── agent/
│   │   ├── planner.py         # AI planning engine
│   │   ├── executor.py        # Plan execution and tool chaining
│   │   └── memory.py          # Session context and memory
│   ├── tools/
│   │   ├── registry.py        # Universal tool registry
│   │   ├── discovery.py       # Runtime tool detection
│   │   └── adapters/          # Per-tool adapters
│   ├── security/
│   │   ├── policy.py          # Policy engine
│   │   └── scope.py           # Engagement scope management
│   ├── execution/
│   │   └── executor.py        # Process execution engine
│   ├── evidence/
│   │   └── store.py           # SQLite evidence database
│   ├── findings/
│   │   └── analyzer.py        # AI finding correlation
│   ├── reporting/             # Report generators
│   ├── tui/                   # Terminal UI components
│   ├── api/                   # FastAPI server
│   ├── plugins/               # Plugin loader
│   └── cli.py                 # Main CLI
├── plugins/                   # Built-in plugins
├── tests/                     # Test suite
├── examples/                  # Example configurations
├── .env.example
└── pyproject.toml
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

*Built for security professionals, students, researchers, and CTF enthusiasts.*
*Always test only against systems you are authorized to assess.*

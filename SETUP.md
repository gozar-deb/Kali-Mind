# Kali-Mind Setup & Usage Guide

> **Legal Notice:** Kali-Mind is designed exclusively for authorized security testing. You must have explicit written permission before scanning or testing any system. Unauthorized use is illegal.

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Installation](#2-installation)
3. [AI Provider Setup](#3-ai-provider-setup)
4. [First Run & Diagnostics](#4-first-run--diagnostics)
5. [Core Concepts](#5-core-concepts)
6. [Scope Configuration](#6-scope-configuration)
7. [Interactive Session](#7-interactive-session)
8. [Running the AI Agent](#8-running-the-ai-agent)
9. [Command Copilot](#9-command-copilot)
10. [Session & Evidence Management](#10-session--evidence-management)
11. [Generating Reports](#11-generating-reports)
12. [All CLI Commands](#12-all-cli-commands)
13. [In-Session Slash Commands](#13-in-session-slash-commands)
14. [Advanced Features](#14-advanced-features)
15. [Plugin System](#15-plugin-system)
16. [API Server](#16-api-server)
17. [Configuration Reference](#17-configuration-reference)
18. [Troubleshooting](#18-troubleshooting)

---

## 1. Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| OS | Kali Linux 2023.1+ | Ubuntu 22.04+ also works |
| Python | 3.10+ | 3.11 or 3.12 recommended |
| RAM | 2 GB | 4 GB+ for local AI models |
| Disk | 500 MB | More for local models and wordlists |
| AI Provider | At least one | Ollama (local) or any cloud API key |

Check your Python version:

```bash
python3 --version
```

---

## 2. Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/your-org/kali-mind.git
cd kali-mind
```

### Step 2 — Install Python dependencies

```bash
pip install -e . --break-system-packages
```

Or in a virtual environment (recommended for non-Kali systems):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Step 3 — Copy the environment template

```bash
cp .env.example .env
```

### Step 4 — Verify the install

```bash
kali-mind --version
```

You should see:

```
Kali-Mind v0.2.0
```

---

## 3. AI Provider Setup

Kali-Mind requires at least one AI provider. You can use a local model (no internet needed) or a cloud API.

### Option A — Ollama (Recommended, Free, Local)

Ollama runs models entirely on your machine. No API key needed. Best for privacy-sensitive engagements.

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (choose one)
ollama pull llama3          # 4.7 GB — good general purpose
ollama pull mistral         # 4.1 GB — fast and capable
ollama pull codellama       # 3.8 GB — good for technical analysis
ollama pull phi3            # 2.3 GB — small and fast
```

Edit your `.env`:

```env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3
KALI_MIND_DEFAULT_PROVIDER=ollama
```

Verify Ollama is running:

```bash
ollama list
```

### Option B — Cloud AI Providers

Add your API key(s) to `.env`. You only need one, but you can configure multiple to switch between them.

```env
# Pick one or more:
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
XAI_API_KEY=xai-...
GEMINI_API_KEY=AIza...
GROQ_API_KEY=gsk_...
DEEPSEEK_API_KEY=sk-...
MISTRAL_API_KEY=...
```

Set the default:

```env
KALI_MIND_DEFAULT_PROVIDER=openai   # or anthropic, groq, gemini, etc.
```

**Provider cost comparison (approximate, check provider sites for current pricing):**

| Provider | Speed | Cost | Privacy | Best For |
|----------|-------|------|---------|----------|
| Ollama | Medium | Free | 100% local | All sensitive work |
| Groq | Very fast | Low | Cloud | Quick analysis |
| Anthropic Claude | Slow | Medium | Cloud | Complex reasoning |
| OpenAI GPT-4o | Medium | Medium | Cloud | Reports, planning |
| Google Gemini | Fast | Low | Cloud | General use |
| DeepSeek | Fast | Very low | Cloud | Budget option |

### Option C — Multi-Model (Advanced)

Assign different providers to different roles for best results:

```env
KALI_MIND_PLANNER_PROVIDER=openai       # planning assessment workflow
KALI_MIND_ANALYST_PROVIDER=anthropic    # correlating findings
KALI_MIND_PARSER_PROVIDER=ollama        # parsing raw tool output (local)
KALI_MIND_REPORTER_PROVIDER=openai      # writing the final report
```

---

## 4. First Run & Diagnostics

Run the doctor to check everything is configured correctly:

```bash
kali-mind doctor
```

Expected output (on a full Kali install):

```
⚕ Kali-Mind Doctor

┌─────────────────────────────┬────────┬──────────────────────────┐
│ Check                       │ Status │ Details                  │
├─────────────────────────────┼────────┼──────────────────────────┤
│ Python 3.10+                │ ✓ OK   │ 3.12.0                   │
│ Database                    │ ✓ OK   │ ~/.kali-mind/kali_mind.db│
│ Config dir (~/.kali-mind)   │ ✓ OK   │ /home/user/.kali-mind    │
│ Wordlists installed         │ ✓ OK   │ /usr/share/wordlists/... │
│ nmap                        │ ✓ OK   │ /usr/bin/nmap            │
│ ffuf                        │ ✓ OK   │ /usr/bin/ffuf            │
│ httpx                       │ ✓ OK   │ /usr/bin/httpx           │
│ ...                         │ ...    │ ...                      │
│ AI providers configured     │ ✓ OK   │ ollama                   │
│ Ollama                      │ ✓ OK   │ http://localhost:11434   │
└─────────────────────────────┴────────┴──────────────────────────┘
```

If wordlists are missing:

```bash
sudo apt install wordlists seclists
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

If a tool is missing:

```bash
sudo apt install nmap ffuf httpx-toolkit nikto gobuster nuclei
```

---

## 5. Core Concepts

### Scope
Before doing anything, you must define which targets you are authorized to test. Kali-Mind enforces scope at the execution layer — the AI cannot instruct tools to run outside it.

### Sessions
Every time you run Kali-Mind, a session is created. Sessions store all commands, evidence, and findings. You can replay, export, and report on any session later.

### Execution Modes
| Mode | What happens |
|------|-------------|
| **Manual** | AI suggests commands; you run them yourself |
| **Assisted** (default) | AI proposes each action; you approve before it runs |
| **Autonomous** | AI executes approved tool categories automatically within scope |
| **Dry-run** | AI generates the full plan but nothing executes |

### Evidence & Findings
Every tool execution is recorded as evidence. The AI analyzes this evidence to produce structured findings (title, severity, affected asset, remediation). Findings are clearly labeled as either **Observed** (directly from tool output) or **AI Inference** (reasoned from evidence).

---

## 6. Scope Configuration

You must configure scope before running any active tests. Scope is persisted to `~/.kali-mind/scope.yaml` and reloads automatically.

### Add authorized targets

```bash
# Single IP
kali-mind scope add 192.168.56.10

# CIDR range
kali-mind scope add 192.168.56.0/24

# Hostname
kali-mind scope add lab.example.com

# Wildcard subdomain
kali-mind scope add "*.lab.example.com"
```

### Exclude specific targets

```bash
# Exclude the gateway from testing
kali-mind scope exclude 192.168.56.1
```

### View current scope

```bash
kali-mind scope
```

Output:

```
Scope: default
  Authorized: 192.168.56.0/24
  Excluded:   192.168.56.1
  Categories: reconnaissance, enumeration, vulnerability_assessment
```

### Clear scope

```bash
kali-mind scope clear
```

### Using named engagement profiles (recommended for real engagements)

```bash
# Create an engagement profile
kali-mind engagement new "Client XYZ Q3 2026" --client "ACME Corp" --target 10.10.10.0/24

# Activate it (loads scope automatically)
kali-mind engagement activate <engagement-id>

# List all profiles
kali-mind engagement
```

---

## 7. Interactive Session

Start the main interactive session:

```bash
kali-mind
```

Or with a specific provider:

```bash
kali-mind --provider groq
kali-mind --provider ollama
kali-mind --privacy          # force local models only
kali-mind --offline          # disable all internet-dependent features
```

The session starts with a banner showing your current provider, session ID, and scope:

```
╭──────────────────────────────────────────╮
│  ⚔  KALI-MIND  ⚔                         │
│  AI Security Orchestration Engine        │
│                                          │
│  AI:      OLLAMA / llama3                │
│  Session: SESSION-A1B2C3D4               │
│  Mode:    Assisted                       │
│  Scope:   Not configured                 │
╰──────────────────────────────────────────╯
```

From here, you can:
- Type naturally to chat with the AI
- Use `/commands` for specific actions
- Ask questions about Kali tools and techniques
- Have the AI plan and execute a security assessment

### Example conversations

```
You > What tools can I use to enumerate web directories?

Kali-Mind > For web directory enumeration, you have several strong options...
            - ffuf: fastest, highly configurable, supports multiple modes
            - gobuster: reliable, good for dir/dns/vhost scanning  
            - feroxbuster: recursive by default, good for deep scans
            ...

You > /scope add 192.168.56.10

You > /agent Perform a web application assessment on my authorized target 192.168.56.10
```

---

## 8. Running the AI Agent

The agent takes a natural-language objective, plans a multi-step workflow, proposes it for your approval, then executes it.

### From the interactive session

```
You > /agent Assess my authorized lab server at 192.168.56.10
```

### From the command line

```bash
kali-mind agent "Perform a full assessment of my authorized lab target 192.168.56.10"
```

### What happens

**1. Planning phase** — The AI reads your scope, available tools, and session context, then produces a structured plan:

```
Execution Plan
┌────┬────────────────────────────┬────────────┬──────────────┬───────────────┐
│ #  │ Step                       │ Tool       │ Operation    │ Target        │
├────┼────────────────────────────┼────────────┼──────────────┼───────────────┤
│ 1  │ Host discovery             │ nmap       │ ping_scan    │ 192.168.56.10 │
│ 2  │ Port enumeration           │ nmap       │ port_scan    │ 192.168.56.10 │
│ 3  │ Service detection          │ nmap       │ service_scan │ 192.168.56.10 │
│ 4  │ HTTP probe                 │ httpx      │ probe        │ 192.168.56.10 │
│ 5  │ Technology fingerprinting  │ whatweb    │ fingerprint  │ 192.168.56.10 │
│ 6  │ Directory enumeration      │ ffuf       │ directory    │ 192.168.56.10 │
│ 7  │ Vulnerability scan         │ nuclei     │ scan         │ 192.168.56.10 │
└────┴────────────────────────────┴────────────┴──────────────┴───────────────┘

Execute? [Y] Yes  [N] No  [D] Dry-run
>
```

**2. Execution phase** — Each step runs sequentially (or in parallel if marked). Output is captured and parsed.

**3. Analysis phase** — The AI correlates all evidence into structured findings:

```
Security Findings
┌───┬──────────┬────────────────────────────────┬──────────────────┬────────────┐
│ # │ Severity │ Title                          │ Asset            │ Confidence │
├───┼──────────┼────────────────────────────────┼──────────────────┼────────────┤
│ 1 │ MEDIUM   │ Exposed Admin Panel            │ 192.168.56.10:80 │ High       │
│ 2 │ LOW      │ Outdated Apache Version        │ 192.168.56.10:80 │ High       │
│ 3 │ INFO     │ SSH Service Exposed            │ 192.168.56.10:22 │ High       │
└───┴──────────┴────────────────────────────────┴──────────────────┴────────────┘
```

**4. Attack surface map** — A visual tree of everything discovered:

```
⚔ Attack Surface — SESSION-A1B2C3D4
└── 🖥  192.168.56.10
    ├── 22/tcp  ssh  OpenSSH 8.9p1
    └── 80/tcp  http  Apache 2.4.54
        ├── http://192.168.56.10/
        ├── http://192.168.56.10/admin
        └── ⚠ MEDIUM: Exposed Admin Panel
```

**5. Reports** — HTML, PDF, Markdown, JSON, and SARIF reports saved automatically.

---

## 9. Command Copilot

The copilot mode explains commands before you run them — useful for learning Kali tools or planning manual steps.

```bash
kali-mind copilot
```

```
Copilot > How do I enumerate subdomains for a target domain?

Kali-Mind >
  Recommended tool: subfinder (passive) + amass (active)

  Command:
    subfinder -d target.com -silent

  Arguments:
    -d target.com    The target domain to enumerate
    -silent          Suppress banner, output subdomains only

  Why this tool:
    subfinder uses passive DNS sources and APIs — no direct contact
    with the target, making it safe and stealthy for recon.

  Expected output:
    sub1.target.com
    sub2.target.com
    mail.target.com

  Risks:
    Low — purely passive, queries third-party databases

  Next step:
    Pipe results to httpx to check which subdomains are live:
    subfinder -d target.com -silent | httpx -silent
```

---

## 10. Session & Evidence Management

### List all sessions

```bash
kali-mind sessions
```

### View session details and findings

```bash
kali-mind sessions show SESSION-A1B2C3D4
```

### Replay the timeline of a session

```bash
kali-mind replay SESSION-A1B2C3D4
```

Output:

```
10:31:02  plan_started        Assess authorized lab server
10:31:05  tool:nmap:ping_scan target=192.168.56.10 exit=0
10:31:14  tool:nmap:port_scan target=192.168.56.10 exit=0
10:31:20  tool:httpx:probe    target=192.168.56.10 exit=0
10:32:01  plan_completed      7/7 steps succeeded
```

### Export a session (for sharing or archiving)

```bash
kali-mind sessions export SESSION-A1B2C3D4
kali-mind sessions export SESSION-A1B2C3D4 --output /tmp/session-export.json
```

### Import a session on another machine

```bash
kali-mind sessions import /tmp/session-export.json
```

### View attack surface map

```bash
kali-mind map SESSION-A1B2C3D4
```

---

## 11. Generating Reports

Generate all report formats for a session:

```bash
kali-mind report SESSION-A1B2C3D4
```

Reports are saved to `~/.kali-mind/reports/` in these formats:

| Format | File | Use case |
|--------|------|----------|
| HTML | `session.html` | Client-ready, dark cybersecurity theme |
| PDF | `session.pdf` | Formal deliverable |
| Markdown | `session.md` | Documentation, GitHub, wikis |
| JSON | `session.json` | Integration with other tools |
| SARIF | `session.sarif` | GitHub Advanced Security, VS Code |

Generate a specific format only:

```bash
kali-mind report SESSION-A1B2C3D4 --format html
kali-mind report SESSION-A1B2C3D4 --format pdf
```

---

## 12. All CLI Commands

### Top-level commands

```bash
kali-mind                          # Start interactive session
kali-mind --privacy                # Force local AI only
kali-mind --offline                # No internet
kali-mind --provider groq          # Use specific provider
kali-mind --version                # Show version

kali-mind chat                     # Alias for interactive session
kali-mind agent "objective"        # Run agent non-interactively
kali-mind copilot                  # Command copilot mode
kali-mind tui                      # Full-screen Textual TUI
kali-mind doctor                   # System diagnostics
kali-mind status                   # Show system/provider status
kali-mind config                   # Show current configuration
kali-mind report <session-id>      # Generate reports
kali-mind replay <session-id>      # Replay session timeline
kali-mind map <session-id>         # Attack surface map
kali-mind serve                    # Start API server
kali-mind git-scan <path|url>      # Scan git repo for secrets
```

### Tools subcommands

```bash
kali-mind tools                    # List all tools in registry
kali-mind tools discover           # Detect installed tools on system
kali-mind tools search <query>     # Search by name, category, capability
kali-mind tools show <name>        # Detailed info about a tool
```

### Sessions subcommands

```bash
kali-mind sessions                 # List all sessions
kali-mind sessions show <id>       # Session details + findings
kali-mind sessions replay <id>     # Action timeline
kali-mind sessions export <id>     # Export as JSON bundle
kali-mind sessions import <file>   # Import a JSON bundle
```

### Scope subcommands

```bash
kali-mind scope                    # Show current scope
kali-mind scope add <target>       # Add IP, CIDR, hostname, or *.domain
kali-mind scope exclude <target>   # Add to exclusion list
kali-mind scope clear              # Remove all scope configuration
```

### Engagement subcommands

```bash
kali-mind engagement               # List all engagement profiles
kali-mind engagement new <name>    # Create new profile
kali-mind engagement new "Client" --client "ACME" --target 10.0.0.0/24
kali-mind engagement activate <id> # Load profile scope as active scope
kali-mind engagement add-target <id> <target>
```

### Plugins subcommands

```bash
kali-mind plugins                  # List loaded plugins
kali-mind plugins add <name>       # Create a new plugin template
kali-mind plugins marketplace      # Browse available plugins
kali-mind plugins search <query>   # Search plugin catalog
kali-mind plugins install <name>   # Install a plugin
```

### Models subcommands

```bash
kali-mind models                   # List providers + health + usage stats
```

### Wordlists subcommands

```bash
kali-mind wordlists                # List all available wordlists by category
kali-mind wordlists find directory # Find best wordlist for a category
kali-mind wordlists find password
kali-mind wordlists find dns
```

---

## 13. In-Session Slash Commands

Inside an interactive session, use these shortcuts:

### AI & Provider

```
/openai          Switch to OpenAI
/claude          Switch to Anthropic Claude
/grok            Switch to xAI Grok
/gemini          Switch to Google Gemini
/groq            Switch to Groq
/ollama          Switch to Ollama (local)
/deepseek        Switch to DeepSeek
/mistral         Switch to Mistral
/auto            Auto-select best available provider
```

### Assessment Control

```
/agent <objective>     Run the AI agent for an objective
/scope                 Show current scope
/scope add <target>    Add target to scope
/scope exclude <t>     Exclude target from scope
/tools                 List available installed tools
/wordlists             Show available wordlists
```

### Analysis & Reporting

```
/findings              Show findings for this session
/map                   Show attack surface map
/report                Generate all report formats
/cost                  Show AI token/cost usage dashboard
/debate                Have multiple AI models verify the last finding
/enrich                Enrich findings with CVE data from NVD API
/export                Export session as JSON bundle
/status                Show session statistics
```

### Special Features

```
/screenshot <url>      Capture a screenshot of a URL
/git <path|url>        Scan a git repository for secrets
/tui                   Launch full-screen Textual TUI
```

---

## 14. Advanced Features

### AI Debate Mode — verify high-severity findings

When a critical or high finding is produced, you can have multiple AI models independently analyze the same evidence. If they disagree, confidence is automatically reduced and the finding is flagged for review.

```
You > /debate
```

Output:

```
Debating last finding with: openai, anthropic, groq
Result: medium confidence — [DEBATED] Exposed Admin Panel

AI Debate: 2/3 models confirmed this finding.
```

### CVE Enrichment — attach real vulnerability data

After an assessment, enrich your findings with CVSS scores, descriptions, and links from the National Vulnerability Database:

```
You > /enrich
✓ Enriched 4 findings with CVE data
```

Optionally configure an NVD API key for higher rate limits (free at nvd.nist.gov):

```env
# Not currently in .env.example — add manually if needed
NVD_API_KEY=your-nvd-key
```

### Privacy Mode — keep everything local

```bash
kali-mind --privacy
```

In privacy mode:
- Only Ollama/local models are used
- No data is sent to cloud providers
- Scope and evidence stay on your machine

### Offline Mode — air-gapped environments

```bash
kali-mind --offline
```

In offline mode:
- Cloud AI providers are disabled
- Only local tools and models are used
- No internet calls at all

### Streaming Responses

By default, AI responses stream token-by-token so you see output immediately. To disable:

```env
KALI_MIND_ENABLE_STREAMING=false
```

### Notifications — get alerted on critical findings

Configure Telegram or Slack to receive a message when a high or critical finding is discovered:

```env
KALI_MIND_TELEGRAM_TOKEN=your-bot-token
KALI_MIND_TELEGRAM_CHAT_ID=your-chat-id
KALI_MIND_SLACK_WEBHOOK=https://hooks.slack.com/...
KALI_MIND_NOTIFY_SEVERITY=high     # notify on high and critical
```

Desktop notifications via `notify-send` are automatic if it is installed.

### Full-Screen TUI

Launch a split-pane terminal interface with AI chat on the right and status/findings on the left:

```bash
kali-mind tui
```

Keyboard shortcuts:
- `Ctrl+C` — Quit
- `Ctrl+P` — Cycle through AI providers
- `Ctrl+R` — Refresh findings panel
- `F1` — Show help

### Git Secret Scanning

Scan a local repository or remote GitHub URL for exposed credentials, API keys, and secrets:

```bash
# Local directory
kali-mind git-scan /path/to/repo

# Remote GitHub repository
kali-mind git-scan https://github.com/org/repo

# From inside a session
/git /path/to/repo
```

Requires `gitleaks` or `trufflehog`:

```bash
# gitleaks
sudo apt install gitleaks

# trufflehog
pip install trufflehog
```

### Metasploit Integration

For authorized lab environments with Metasploit RPC running:

```bash
# Start msfrpcd first
msfrpcd -P yourpassword -S -a 127.0.0.1

# Use in Python
from kali_mind.features.msf_client import MetasploitClient
import asyncio

async def main():
    client = MetasploitClient(host="127.0.0.1", password="yourpassword")
    await client.authenticate()
    modules = await client.list_modules("exploit")
    results = await client.run_module(
        "exploit", "unix/ftp/vsftpd_234_backdoor",
        options={"RPORT": 21},
        authorized_target="192.168.56.10",  # must be in configured scope
        approved=True,  # explicit confirmation for exploit-capable module execution
    )

asyncio.run(main())
```

---

## 15. Plugin System

### Create a custom plugin

```bash
kali-mind plugins add my-scanner
```

This creates `~/.kali-mind/plugins/my-scanner/` with three files:

**`plugin.yaml`** — tool metadata:

```yaml
name: my-scanner
binary: my-scanner
category: reconnaissance
description: My custom security scanner
capabilities:
  - port_scanning
  - service_detection
input_types:
  - hostname
  - ip
output_formats:
  - text
  - json
risk_level: low
tags:
  - custom
```

**`adapter.py`** — command builder and output parser:

```python
from kali_mind.tools.adapters.base import BaseAdapter, ToolRequest
from typing import Any, Dict, List

class Adapter(BaseAdapter):
    tool_name = "my-scanner"

    def build_command(self, request: ToolRequest) -> List[str]:
        return ["my-scanner", "--target", request.target, "--format", "json"]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        import json
        try:
            return json.loads(stdout)
        except Exception:
            return {"raw": stdout, "errors": [stderr] if stderr else []}
```

Plugins are loaded automatically at startup only after signature verification. Signed plugins are required by default. For HMAC signing, set a strong persistent `KALI_MIND_PLUGIN_SIGNING_KEY` in the environment, then sign a plugin directory with `sign_plugin_hmac(Path("~/.kali-mind/plugins/my-scanner").expanduser())` from Python. Do not use a development/default signing key. For isolated local development only, unsigned plugins can be enabled with `KALI_MIND_REQUIRE_SIGNED_PLUGINS=false`; do not use this setting for untrusted plugins.

### Browse and install community plugins

```bash
kali-mind plugins marketplace
kali-mind plugins search nuclei
kali-mind plugins install nuclei-templates --allow-remote
```

---

## 16. API Server

Start the API server locally (recommended):

```bash
kali-mind serve --host 127.0.0.1 --port 8765
```

Non-loopback binds are rejected unless both TLS certificate and key paths are provided:

```bash
kali-mind serve --host 0.0.0.0 --port 8765 --ssl-certfile cert.pem --ssl-keyfile key.pem
```

Startup output shows the URL and token-file path, never the token itself. The token is stored in `~/.kali-mind/.api_token` with owner-only permissions. Use a trusted certificate or a properly configured TLS reverse proxy for remote access.

### Authentication

Every request (except `GET /health`) requires a Bearer token:

```bash
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8765/tools
```

The token is stored at `~/.kali-mind/.api_token` (permissions: `600`).

### Key endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Public health check |
| `GET` | `/providers` | Provider health status |
| `GET` | `/providers/usage` | Token and cost usage |
| `POST` | `/chat` | Send a message to the AI |
| `GET` | `/tools` | List all tools |
| `GET` | `/tools/search?q=web` | Search tools |
| `POST` | `/tools/discover` | Detect installed tools |
| `GET` | `/sessions` | List sessions |
| `POST` | `/sessions` | Create a session |
| `GET` | `/sessions/{id}` | Session details |
| `GET` | `/sessions/{id}/findings` | Session findings |
| `GET` | `/sessions/{id}/evidence` | Session evidence |
| `POST` | `/sessions/{id}/report` | Generate reports |
| `POST` | `/sessions/{id}/export` | Export session bundle |
| `GET` | `/scope` | Current scope |
| `POST` | `/scope` | Set scope |
| `POST` | `/scope/target` | Add a target |
| `GET` | `/wordlists` | List wordlists |
| `GET` | `/cost` | AI usage stats |
| `GET` | `/engagements` | List engagements |

Interactive API documentation: `http://localhost:8765/docs`

---

## 17. Configuration Reference

### `.env` file (secrets)

Never commit this file. All fields are optional — configure only what you need.

```env
# AI Providers (add the key for any you want to use)
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
XAI_API_KEY=
KIMI_API_KEY=
GEMINI_API_KEY=
DEEPSEEK_API_KEY=
NVIDIA_API_KEY=
OPENROUTER_API_KEY=
GROQ_API_KEY=
COHERE_API_KEY=
MISTRAL_API_KEY=
TOGETHER_API_KEY=

# Ollama local server
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3

# Default provider
KALI_MIND_DEFAULT_PROVIDER=ollama

# Custom database path (default: ~/.kali-mind/kali_mind.db)
KALI_MIND_DB_PATH=

# Logging level
LOG_LEVEL=INFO

# Notifications
KALI_MIND_TELEGRAM_TOKEN=
KALI_MIND_TELEGRAM_CHAT_ID=
KALI_MIND_SLACK_WEBHOOK=
KALI_MIND_NOTIFY_SEVERITY=high

# Multi-model role assignments
KALI_MIND_PLANNER_PROVIDER=
KALI_MIND_ANALYST_PROVIDER=
KALI_MIND_PARSER_PROVIDER=
KALI_MIND_REPORTER_PROVIDER=
```

### `~/.kali-mind/` directory

```
~/.kali-mind/
├── config.yaml          # Advanced config (rarely needed)
├── providers.yaml       # Provider model/endpoint overrides
├── scope.yaml           # Persisted scope (auto-managed)
├── kali_mind.db         # SQLite database (sessions, evidence, findings)
├── .api_token           # API server token (permissions: 600)
├── tools/               # Custom tool definitions
├── plugins/             # Installed plugins
├── sessions/            # Exported session bundles
├── evidence/            # Full tool output files (>50KB)
├── reports/             # Generated reports (HTML, PDF, MD, JSON, SARIF)
├── logs/                # Execution logs
└── models/              # Downloaded model files
```

### `~/.kali-mind/providers.yaml` (optional)

Override models and endpoints without touching `.env`:

```yaml
openai:
  enabled: true
  model: gpt-4o            # override default model

anthropic:
  enabled: true
  model: claude-opus-4-5

ollama:
  enabled: true
  endpoint: http://localhost:11434
  model: mistral
```

---

## 18. Troubleshooting

### "No AI provider available"

```
RuntimeError: No AI provider available. Configure at least one in .env
```

**Fix:** Make sure you have either Ollama running (`ollama serve`) or at least one API key in `.env` with the corresponding provider variable set. Run `kali-mind doctor` to check.

---

### "No scope configured"

```
⚠ No scope configured. Use /scope add <target> first.
```

**Fix:** Add a target before running the agent:

```bash
kali-mind scope add 192.168.56.10
# or inside the session:
/scope add 192.168.56.10
```

---

### "No wordlist found" when running ffuf/gobuster

```
No wordlist found. Install with: sudo apt install wordlists seclists
```

**Fix:**

```bash
sudo apt install wordlists seclists
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```

Or point to a custom wordlist in the agent's options.

---

### Ollama is not reachable

```
Ollama: ○ Offline
```

**Fix:**

```bash
# Start Ollama
ollama serve

# Verify a model is downloaded
ollama list

# Pull one if empty
ollama pull llama3
```

---

### Provider rate limit errors (429)

Kali-Mind retries automatically with exponential backoff (up to 3 attempts). If errors persist, switch providers:

```
/groq      # Groq has a generous free tier and is very fast
/ollama    # Completely free, no rate limits
```

---

### "Policy denied: Scope violation"

The target you specified is not in your authorized scope.

**Fix:** Either add the target to scope, or verify you typed the IP correctly:

```bash
kali-mind scope add 192.168.1.100
kali-mind scope
```

---

### Reports not generating (PDF issues)

PDF generation requires `reportlab`. If missing:

```bash
pip install reportlab --break-system-packages
```

If reportlab fails, HTML, Markdown, and JSON reports still generate successfully.

---

### Plugin adapter fails to load

If a plugin's `adapter.py` crashes on import, Kali-Mind logs a warning and continues — the plugin's tool is still registered in the registry, just without a command builder. Check logs:

```bash
tail -f ~/.kali-mind/logs/*.log
```

---

### Textual TUI shows layout errors

Ensure you have a recent version of Textual:

```bash
pip install "textual>=0.60" --break-system-packages
```

The TUI requires a terminal with at least 80×24 characters and true color support.

---

### Running tests

```bash
cd kali-mind
pip install -e ".[dev]" --break-system-packages
pytest tests/ -v
```

All 118 tests should pass.

---

## Quick Reference Card

```
# Install
pip install -e . --break-system-packages

# Check everything
kali-mind doctor

# Set scope (required before testing)
kali-mind scope add 192.168.56.0/24

# Start interactive session
kali-mind

# Run agent directly
kali-mind agent "Assess 192.168.56.10"

# Generate report
kali-mind report <session-id>

# Key session commands
/agent <objective>    run the AI agent
/scope add <target>   add a target
/map                  show attack surface
/findings             show findings
/report               generate reports
/cost                 AI usage stats
/debate               verify findings
/tui                  full-screen UI
exit                  quit
```

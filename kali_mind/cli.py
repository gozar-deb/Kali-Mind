"""Kali-Mind CLI — full command-line interface with all features."""
from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table

from kali_mind import __version__
from kali_mind.config import settings
from kali_mind.tui.components import (
    console, print_banner, print_error, print_findings,
    print_info, print_plan, print_success, print_warning, print_ai_response,
)

app = typer.Typer(name="kali-mind",
                  help="⚔ Kali-Mind — AI-Powered Security Orchestration Platform",
                  no_args_is_help=False, rich_markup_mode="rich")

tools_app = typer.Typer(help="Tool registry management")
sessions_app = typer.Typer(help="Session management")
scope_app = typer.Typer(help="Engagement scope management")
plugins_app = typer.Typer(help="Plugin management")
models_app = typer.Typer(help="AI model/provider management")
engagement_app = typer.Typer(help="Engagement profile management")
wordlists_app = typer.Typer(help="Wordlist management")
playbook_app = typer.Typer(help="Engagement playbooks")

app.add_typer(tools_app, name="tools")
app.add_typer(sessions_app, name="sessions")
app.add_typer(scope_app, name="scope")
app.add_typer(plugins_app, name="plugins")
app.add_typer(models_app, name="models")
app.add_typer(engagement_app, name="engagement")
app.add_typer(wordlists_app, name="wordlists")
app.add_typer(playbook_app, name="playbook")


def _startup() -> None:
    from kali_mind.config import bootstrap
    bootstrap(settings)
    from kali_mind.plugins.loader import get_plugin_loader
    get_plugin_loader().load_all()


# ─── Default callback ────────────────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    privacy: bool = typer.Option(False, "--privacy", help="Privacy mode: local models only"),
    offline: bool = typer.Option(False, "--offline", help="Offline mode"),
    provider: Optional[str] = typer.Option(None, "--provider", "-p"),
    version: bool = typer.Option(False, "--version", "-v"),
) -> None:
    if version:
        console.print(f"Kali-Mind v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is not None:
        return
    if privacy:
        settings.privacy_mode = True
    if offline:
        settings.offline_mode = True
    if provider:
        settings.default_provider = provider
    _startup()
    asyncio.run(_interactive_session())


# ─── Interactive session ─────────────────────────────────────────────────────

async def _interactive_session() -> None:
    from kali_mind.ai.gateway import get_gateway
    from kali_mind.agent.memory import AgentMemory
    from kali_mind.agent.planner import Planner
    from kali_mind.evidence.store import Session, get_store
    from kali_mind.security.scope import get_scope_manager
    from kali_mind.tools.discovery import discover_tools
    from kali_mind.features.cost_tracker import get_cost_tracker

    print_info("Discovering installed security tools...")
    available = await discover_tools()

    store = get_store()
    session_id = f"SESSION-{uuid.uuid4().hex[:8].upper()}"
    session = Session(id=session_id, name=session_id)
    store.create_session(session)

    gateway = get_gateway()
    memory = AgentMemory(session_id)
    planner = Planner(gateway, memory)
    cost_tracker = get_cost_tracker()

    scope_mgr = get_scope_manager()
    scope_str = scope_mgr.get_scope().name if scope_mgr.get_scope() else "Not configured"
    print_banner(
        provider=settings.default_provider.upper(),
        model=", ".join(gateway.available_providers[:3]),
        session=session_id, scope=scope_str,
    )
    console.print(f"[dim]Found {len(available)} security tools. Type 'help' or your objective.[/]\n")

    while True:
        # Show cost summary in prompt
        cost_line = cost_tracker.summary_line()
        try:
            user_input = console.input(f"[dim]{cost_line}[/]\n[bold bright_cyan]You > [/]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye.[/]")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            console.print("[dim]Session saved. Goodbye.[/]")
            break
        elif user_input.lower() == "help":
            _print_help()
            continue
        elif user_input.startswith("/"):
            await _handle_slash_command(user_input, gateway, memory, planner, session_id)
            continue

        # Feature #16: streaming response
        if settings.enable_streaming:
            await _stream_response(gateway, planner, memory, user_input)
        else:
            try:
                response = await planner.chat(user_input)
                print_ai_response(response, provider=settings.default_provider)
            except Exception as e:
                print_error(f"AI error: {e}")


async def _stream_response(gateway, planner, memory, user_input: str) -> None:
    """Feature #16: stream tokens as they arrive using Rich Live."""
    from kali_mind.ai.schemas import AIRequest
    memory.add_user_message(user_input)
    context = memory.get_context_summary()
    from kali_mind.agent.planner import PLANNER_SYSTEM
    system = PLANNER_SYSTEM + f"\n\nSession context:\n{context}"
    request = AIRequest(
        system=system, messages=memory.get_recent_messages(8),
        max_tokens=1024, temperature=0.3,
    )
    collected = []
    try:
        console.print(f"[bold bright_blue]Kali-Mind[/] [dim]({settings.default_provider})[/]")
        async for token in gateway.stream(request):
            console.print(token, end="")
            collected.append(token)
        console.print()
        full_response = "".join(collected)
        memory.add_assistant_message(full_response)
    except Exception as e:
        print_error(f"Streaming error: {e}")


async def _handle_slash_command(cmd: str, gateway, memory, planner, session_id: str) -> None:
    parts = cmd.split()
    base = parts[0].lower()

    if base == "/agent":
        objective = " ".join(parts[1:]) or console.input("[bold cyan]Objective > [/]").strip()
        await _run_agent(objective, gateway, memory, planner, session_id)

    elif base == "/scope":
        from kali_mind.security.scope import get_scope_manager
        mgr = get_scope_manager()
        if len(parts) >= 3 and parts[1] == "add":
            mgr.add_target(parts[2])
            memory.targets.append(parts[2])
            print_success(f"Target added to scope: {parts[2]}")
        elif len(parts) >= 3 and parts[1] == "exclude":
            mgr.exclude_target(parts[2])
            print_success(f"Excluded: {parts[2]}")
        else:
            console.print(mgr.summary())

    elif base in ("/local", "/openai", "/claude", "/anthropic", "/grok",
                  "/kimi", "/gemini", "/deepseek", "/nvidia", "/ollama",
                  "/groq", "/mistral", "/auto"):
        provider = base[1:]
        if provider == "auto":
            from kali_mind.ai.gateway import get_gateway
            p = get_gateway().available_providers
            provider = p[0] if p else "ollama"
        elif provider == "claude":
            provider = "anthropic"
        settings.default_provider = provider
        print_success(f"Switched to: {provider}")

    elif base == "/report":
        from kali_mind.reporting.manager import ReportManager
        try:
            paths = ReportManager().generate_all(session_id)
            print_success("Reports generated:")
            for fmt, path in paths.items():
                console.print(f"  [cyan]{fmt}[/]: {path}")
        except Exception as e:
            print_error(str(e))

    elif base == "/findings":
        from kali_mind.evidence.store import get_store
        findings = get_store().get_findings(session_id)
        print_findings(findings)

    elif base == "/map":
        # Feature #21: attack surface map
        from kali_mind.features.attack_surface import AttackSurfaceMap
        asm = AttackSurfaceMap(session_id)
        asm.render({
            "hosts": memory.discovered_hosts,
            "ports": memory.discovered_ports,
            "technologies": memory.discovered_technologies,
            "urls": memory.discovered_urls,
        })

    elif base == "/cost":
        # Feature #24: cost dashboard
        from kali_mind.features.cost_tracker import get_cost_tracker
        get_cost_tracker().render()

    elif base == "/debate":
        # Feature #23: debate mode on last finding
        from kali_mind.evidence.store import get_store
        findings = get_store().get_findings(session_id)
        if not findings:
            print_info("No findings to debate.")
        else:
            from kali_mind.findings.analyzer import FindingAnalyzer
            analyzer = FindingAnalyzer(gateway, memory, session_id)
            providers = [p for p in gateway.available_providers if p != "ollama"][:3]
            if len(providers) < 2:
                providers = gateway.available_providers[:3]
            print_info(f"Debating last finding with: {', '.join(providers)}")
            result = await analyzer.debate_finding(findings[-1], providers)
            console.print(f"Result: [yellow]{result.confidence}[/] confidence — {result.title}")

    elif base == "/enrich":
        # Feature #27: CVE enrichment
        from kali_mind.evidence.store import get_store
        from kali_mind.features.cve_enrichment import CVEEnricher
        findings = get_store().get_findings(session_id)
        enricher = CVEEnricher()
        enriched = await enricher.enrich_findings(findings)
        print_success(f"Enriched {len(enriched)} findings with CVE data")

    elif base == "/export":
        # Feature #25: session export
        from kali_mind.features.session_transfer import SessionTransfer
        path = SessionTransfer().export_session(session_id)
        print_success(f"Session exported to: {path}")

    elif base == "/tools":
        from kali_mind.tools.registry import get_registry
        _print_tools_table(get_registry().available_tools())

    elif base == "/status":
        from kali_mind.evidence.store import get_store
        store = get_store()
        ev = store.get_evidence(session_id)
        fi = store.get_findings(session_id)
        console.print(f"[cyan]{session_id}[/]: {len(ev)} commands, {len(fi)} findings")
        console.print(f"Scope: {get_scope_manager().summary()}")

    elif base == "/wordlists":
        from kali_mind.features.wordlist_manager import get_wordlist_manager
        get_wordlist_manager().render_table()

    elif base == "/screenshot":
        if len(parts) < 2:
            print_warning("Usage: /screenshot <url>")
        else:
            from kali_mind.features.screenshot import ScreenshotCapture
            sc = ScreenshotCapture()
            path = await sc.capture(parts[1])
            if path:
                print_success(f"Screenshot saved: {path}")
            else:
                print_warning("No headless browser found. Install chromium or cutycapt.")

    elif base == "/tui":
        # Feature #28: launch full TUI
        from kali_mind.features.tui_app import launch_tui
        launch_tui(session_id=session_id, provider=settings.default_provider)

    elif base == "/git":
        if len(parts) < 2:
            print_warning("Usage: /git <repo_path_or_url>")
        else:
            from kali_mind.features.git_scanner import GitScanner
            scanner = GitScanner()
            target = parts[1]
            if target.startswith("http"):
                result = await scanner.scan_github_repo(target)
            else:
                result = await scanner.scan_repo(target)
            if result["findings"]:
                print_error(f"Found {len(result['findings'])} secrets in {target}!")
                for f in result["findings"][:5]:
                    console.print(f"  [red]•[/] {f.get('rule', '?')}: {f.get('file', '?')}")
            elif result["errors"]:
                print_warning(result["errors"][0])
            else:
                print_success("No secrets found.")

    else:
        print_warning(f"Unknown command: {base}. Type 'help' for help.")


async def _run_agent(objective: str, gateway, memory, planner, session_id: str) -> None:
    from kali_mind.agent.executor import AgentExecutor
    from kali_mind.execution.executor import get_executor
    from kali_mind.findings.analyzer import FindingAnalyzer
    from kali_mind.security.scope import get_scope_manager
    from kali_mind.evidence.store import get_store
    from kali_mind.features.notifications import get_notification_service
    from kali_mind.features.cost_tracker import get_cost_tracker

    scope_mgr = get_scope_manager()
    if not scope_mgr.get_scope():
        print_warning("No scope configured. Use /scope add <target> first.")
        return

    console.print(f"\n[bold bright_blue]Planning:[/] {objective}\n")
    try:
        plan = await planner.plan(objective)
    except Exception as e:
        print_error(f"Planning failed: {e}")
        return

    if not plan.steps:
        print_warning("No executable steps generated.")
        return

    print_plan([s.model_dump() for s in plan.steps])
    console.print("\n[bold]Execute?[/] [dim]\\[Y][/] Yes  [dim]\\[N][/] No  [dim]\\[D][/] Dry-run")
    choice = console.input("[bold bright_cyan]> [/]").strip().upper()

    if choice == "N":
        print_info("Cancelled.")
        return
    if choice == "D":
        from kali_mind.security.policy import ExecutionMode, get_policy_engine
        get_policy_engine().set_mode(ExecutionMode.DRY_RUN)
        print_info("Dry-run mode.")

    executor = get_executor()
    agent_exec = AgentExecutor(
        execution_engine=executor, memory=memory, session_id=session_id,
        progress_callback=lambda msg: console.print(f"  {msg}"),
    )
    results = await agent_exec.execute_plan(plan)
    ok = len([r for r in results if r.success])
    console.print(f"\n[bold]Plan completed:[/] {ok}/{len(results)} steps succeeded\n")

    # Analyze findings
    print_info("Analyzing evidence...")
    store = get_store()
    evidence = store.get_evidence(session_id)
    if evidence:
        analyzer = FindingAnalyzer(gateway, memory, session_id)
        findings = await analyzer.analyze_evidence(evidence)
        if findings:
            print_findings(findings)
            # Feature #33: notify on high/critical
            notifier = get_notification_service()
            for f in findings:
                await notifier.notify_finding(f)
            # Feature #21: show attack surface map
            from kali_mind.features.attack_surface import AttackSurfaceMap
            AttackSurfaceMap(session_id).render({
                "hosts": memory.discovered_hosts,
                "ports": memory.discovered_ports,
                "technologies": memory.discovered_technologies,
                "urls": memory.discovered_urls,
            })
        else:
            print_info("No significant findings detected.")
    # Feature #24: show cost
    get_cost_tracker().render()


def _print_help() -> None:
    table = Table(title="Kali-Mind Commands", box=box.ROUNDED, border_style="bright_blue")
    table.add_column("Command", style="cyan")
    table.add_column("Description")
    cmds = [
        ("/agent <objective>", "Run the AI security agent"),
        ("/scope add <target>", "Add authorized target"),
        ("/scope exclude <target>", "Exclude target from scope"),
        ("/scope", "Show scope"),
        ("/tools", "List available tools"),
        ("/findings", "Show findings"),
        ("/map", "Show attack surface map (Feature #21)"),
        ("/cost", "Show AI cost/token usage (Feature #24)"),
        ("/debate", "AI debate last finding (Feature #23)"),
        ("/enrich", "Enrich findings with CVE data (Feature #27)"),
        ("/export", "Export session bundle (Feature #25)"),
        ("/screenshot <url>", "Capture screenshot (Feature #32)"),
        ("/git <path|url>", "Scan git repo for secrets (Feature #29)"),
        ("/tui", "Launch full-screen TUI (Feature #28)"),
        ("/wordlists", "List available wordlists (Feature #26)"),
        ("/report", "Generate reports"),
        ("/status", "Session status"),
        ("/openai /claude /groq /ollama ...", "Switch AI provider"),
        ("exit / quit", "Exit Kali-Mind"),
    ]
    for cmd, desc in cmds:
        table.add_row(cmd, desc)
    console.print(table)


def _print_tools_table(tools: list) -> None:
    table = Table(title="Available Tools", box=box.ROUNDED, border_style="bright_blue")
    table.add_column("Tool", style="cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Risk")
    table.add_column("Description")
    for t in tools:
        table.add_row(t.name, t.category.value, t.risk_level.value, t.description)
    console.print(table)


# ─── Subcommands ─────────────────────────────────────────────────────────────

@app.command("chat")
def cmd_chat(provider: Optional[str] = typer.Option(None, "--provider", "-p")) -> None:
    """Start interactive AI chat."""
    if provider:
        settings.default_provider = provider
    _startup()
    asyncio.run(_interactive_session())


@app.command("agent")
def cmd_agent(
    objective: Optional[str] = typer.Argument(None),
    session: Optional[str] = typer.Option(None, "--session", "-s"),
) -> None:
    """Run AI agent for a security objective."""
    _startup()
    asyncio.run(_run_agent_standalone(objective, session))


async def _run_agent_standalone(objective: Optional[str], session_id: Optional[str]) -> None:
    from kali_mind.ai.gateway import get_gateway
    from kali_mind.agent.memory import AgentMemory
    from kali_mind.agent.planner import Planner
    from kali_mind.evidence.store import Session, get_store
    from kali_mind.tools.discovery import discover_tools

    if not objective:
        objective = console.input("[bold cyan]Objective > [/]").strip()
    if not objective:
        print_error("No objective specified.")
        return
    store = get_store()
    if not session_id:
        session_id = f"SESSION-{uuid.uuid4().hex[:8].upper()}"
        store.create_session(Session(id=session_id, name=session_id))
    gateway = get_gateway()
    memory = AgentMemory(session_id)
    planner = Planner(gateway, memory)
    await discover_tools()
    print_banner(provider=settings.default_provider.upper(), session=session_id)
    await _run_agent(objective, gateway, memory, planner, session_id)


@app.command("copilot")
def cmd_copilot() -> None:
    """Command copilot — explains and guides security commands."""
    _startup()
    console.print(Panel(
        "[bright_blue]Kali-Mind Copilot[/]\n"
        "Describe what you want to do. I'll recommend the right tool, command, and explain everything.\n"
        "Type 'exit' to quit.",
        border_style="bright_blue",
    ))
    asyncio.run(_copilot_loop())


async def _copilot_loop() -> None:
    from kali_mind.ai.gateway import get_gateway
    from kali_mind.agent.memory import AgentMemory
    from kali_mind.agent.planner import Planner

    gateway = get_gateway()
    memory = AgentMemory("copilot")
    planner = Planner(gateway, memory)

    while True:
        try:
            query = console.input("[bold bright_cyan]Copilot > [/]").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if query.lower() in ("exit", "quit"):
            break
        try:
            # Feature #19: use dedicated copilot_chat method
            response = await planner.copilot_chat(query)
            print_ai_response(response, provider=settings.default_provider)
        except Exception as e:
            print_error(str(e))


@app.command("tui")
def cmd_tui(
    session: Optional[str] = typer.Option(None, "--session", "-s"),
) -> None:
    """Launch the full-screen Textual TUI. (Feature #28)"""
    _startup()
    from kali_mind.features.tui_app import launch_tui
    sid = session or f"SESSION-{uuid.uuid4().hex[:8].upper()}"
    launch_tui(session_id=sid, provider=settings.default_provider)


@app.command("doctor")
def cmd_doctor() -> None:
    """System self-diagnostics."""
    _startup()
    asyncio.run(_doctor())


async def _doctor() -> None:
    import shutil as sh
    from kali_mind.ai.gateway import get_gateway
    from kali_mind.tools.discovery import discover_tools
    from kali_mind.tools.registry import get_registry
    from kali_mind.features.wordlist_manager import get_wordlist_manager

    console.print("\n[bold bright_blue]⚕ Kali-Mind Doctor[/]\n")
    checks = []

    v = sys.version_info
    checks.append(("Python 3.10+", v >= (3, 10), f"{v.major}.{v.minor}.{v.micro}"))

    try:
        from kali_mind.evidence.store import get_store
        get_store()
        checks.append(("Database", True, str(settings.db_path)))
    except Exception as e:
        checks.append(("Database", False, str(e)))

    checks.append(("Config dir", settings.home_dir.exists(), str(settings.home_dir)))

    # Wordlists (Feature #26)
    wm = get_wordlist_manager()
    checks.append(("Wordlists installed", wm.is_installed(), wm.best_directory_wordlist() or "none found"))

    common_tools = ["nmap", "ffuf", "httpx", "whatweb", "nikto", "nuclei",
                    "gobuster", "sqlmap", "tshark", "amass", "subfinder",
                    "theharvester", "hydra", "john", "hashcat", "ghidra",
                    "radare2", "binwalk", "git", "docker", "notify-send"]
    await discover_tools()
    registry = get_registry()
    for t in common_tools:
        ok = sh.which(t) is not None or (registry.get(t) and registry.get(t).available)
        checks.append((t, ok, sh.which(t) or "not found"))

    gateway = get_gateway()
    checks.append(("AI providers", len(gateway.available_providers) > 0,
                   ", ".join(gateway.available_providers) or "none"))

    try:
        from kali_mind.ai.providers.ollama_provider import OllamaProvider
        ok2 = await asyncio.wait_for(OllamaProvider().health_check(), timeout=3)
        checks.append(("Ollama", ok2, "http://localhost:11434"))
    except Exception:
        checks.append(("Ollama", False, "not reachable"))

    # Git secret scanners (Feature #29)
    from kali_mind.features.git_scanner import GitScanner
    gs_tools = GitScanner().detect_tools()
    checks.append(("Git secret scanners", bool(gs_tools), ", ".join(gs_tools) or "none — install gitleaks/trufflehog"))

    # Screenshot tools (Feature #32)
    from kali_mind.features.screenshot import ScreenshotCapture
    sc_tool = ScreenshotCapture().detect_tool()
    checks.append(("Screenshot tool", bool(sc_tool), sc_tool or "none — install chromium"))

    table = Table(box=box.ROUNDED, border_style="bright_blue")
    table.add_column("Check", style="white")
    table.add_column("Status", width=8)
    table.add_column("Details", style="dim white")
    for name, ok, detail in checks:
        status = "[green]✓ OK[/]" if ok else "[red]✗ FAIL[/]"
        table.add_row(name, status, str(detail))
    console.print(table)
    ok_count = sum(1 for _, ok, _ in checks if ok)
    console.print(f"\n[dim]{ok_count}/{len(checks)} checks passed[/]")


@app.command("status")
def cmd_status() -> None:
    """Show system status."""
    _startup()
    asyncio.run(_print_status())


async def _print_status() -> None:
    from kali_mind.ai.gateway import get_gateway
    from kali_mind.security.scope import get_scope_manager
    from kali_mind.evidence.store import get_store
    from kali_mind.tools.registry import get_registry

    gateway = get_gateway()
    scope_mgr = get_scope_manager()
    store = get_store()
    registry = get_registry()

    table = Table(title="Kali-Mind Status", box=box.ROUNDED, border_style="bright_blue")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="bright_white")
    table.add_row("Version", f"v{__version__}")
    table.add_row("Provider", settings.default_provider)
    table.add_row("Available providers", ", ".join(gateway.available_providers) or "none")
    table.add_row("Privacy mode", "ON" if settings.privacy_mode else "off")
    table.add_row("Offline mode", "ON" if settings.offline_mode else "off")
    table.add_row("Streaming", "ON" if settings.enable_streaming else "off")
    scope = scope_mgr.get_scope()
    table.add_row("Scope", scope.name if scope else "not configured")
    avail = len(registry.available_tools())
    table.add_row("Tools available", f"{avail}/{len(registry.all_tools())}")
    table.add_row("Sessions", str(len(store.list_sessions())))
    table.add_row("Config dir", str(settings.home_dir))
    console.print(table)

    health = await gateway.health_check_all()
    htable = Table(title="Provider Health", box=box.ROUNDED, border_style="dim")
    htable.add_column("Provider", style="cyan")
    htable.add_column("Status", width=12)
    htable.add_column("Latency")
    for h in health:
        status = "[green]● Online[/]" if h.available else "[red]○ Offline[/]"
        latency = f"{h.latency_ms:.0f}ms" if h.latency_ms else "—"
        htable.add_row(h.name, status, latency)
    console.print(htable)


# ─── Tools ──────────────────────────────────────────────────────────────────

@tools_app.callback(invoke_without_command=True)
def tools_default(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        _startup()
        from kali_mind.tools.registry import get_registry
        _print_tools_table(get_registry().all_tools())


@tools_app.command("search")
def tools_search(query: str) -> None:
    """Search tools."""
    _startup()
    results = get_registry_search(query)
    if results:
        _print_tools_table(results)
    else:
        print_warning(f"No tools found: {query}")


def get_registry_search(q):
    from kali_mind.tools.registry import get_registry
    return get_registry().search(q)


@tools_app.command("discover")
def tools_discover() -> None:
    """Detect installed tools."""
    _startup()
    available = asyncio.run(_discover_async())
    print_success(f"Found {len(available)} installed tool(s):")
    for t in available:
        console.print(f"  [green]✓[/] [cyan]{t.name}[/] — {t.version or '?'}")


async def _discover_async():
    from kali_mind.tools.discovery import discover_tools
    return await discover_tools()


@tools_app.command("show")
def tools_show(name: str) -> None:
    """Show tool details."""
    _startup()
    from kali_mind.tools.registry import get_registry
    t = get_registry().get(name)
    if not t:
        print_error(f"Tool not found: {name}")
        raise typer.Exit(1)
    table = Table(title=f"Tool: {t.name}", box=box.ROUNDED, border_style="bright_blue")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Binary", t.binary)
    table.add_row("Category", t.category.value)
    table.add_row("Risk Level", t.risk_level.value)
    table.add_row("Available", "[green]yes[/]" if t.available else "[red]no[/]")
    table.add_row("Description", t.description)
    table.add_row("Capabilities", ", ".join(t.capabilities))
    table.add_row("Tags", ", ".join(t.tags))
    console.print(table)


# ─── Sessions ────────────────────────────────────────────────────────────────

@sessions_app.callback(invoke_without_command=True)
def sessions_default(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        _startup()
        from kali_mind.evidence.store import get_store
        sessions = get_store().list_sessions()
        if not sessions:
            print_info("No sessions found.")
            return
        table = Table(title="Sessions", box=box.ROUNDED, border_style="bright_blue")
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Status")
        table.add_column("Created")
        for s in sessions:
            table.add_row(s.id, s.name, s.status, s.created_at[:19] if s.created_at else "—")
        console.print(table)


@sessions_app.command("show")
def sessions_show(session_id: str) -> None:
    _startup()
    from kali_mind.evidence.store import get_store
    store = get_store()
    session = store.get_session(session_id)
    if not session:
        print_error(f"Session not found: {session_id}")
        raise typer.Exit(1)
    findings = store.get_findings(session_id)
    console.print(f"[bold]{session.name}[/] ({session.id}) — {session.status}")
    print_findings(findings)


@sessions_app.command("replay")
def sessions_replay(session_id: str) -> None:
    _startup()
    from kali_mind.evidence.store import get_store
    for entry in get_store().get_replay_log(session_id):
        ts = entry.get("timestamp", "")[:19]
        console.print(f"[dim]{ts}[/]  [cyan]{entry.get('action','')}[/]  {entry.get('details','')}")


@sessions_app.command("export")
def sessions_export(session_id: str, output: Optional[str] = typer.Option(None, "--output", "-o")) -> None:
    """Export session as JSON bundle. (Feature #25)"""
    _startup()
    from kali_mind.features.session_transfer import SessionTransfer
    try:
        path = SessionTransfer().export_session(session_id, Path(output) if output else None)
        print_success(f"Exported to: {path}")
    except Exception as e:
        print_error(str(e))


@sessions_app.command("import")
def sessions_import(bundle_path: str) -> None:
    """Import a session bundle. (Feature #25)"""
    _startup()
    from kali_mind.features.session_transfer import SessionTransfer
    try:
        new_id = SessionTransfer().import_session(Path(bundle_path))
        print_success(f"Imported session: {new_id}")
    except Exception as e:
        print_error(str(e))


# ─── Scope ──────────────────────────────────────────────────────────────────

@scope_app.callback(invoke_without_command=True)
def scope_default(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        _startup()
        from kali_mind.security.scope import get_scope_manager
        console.print(get_scope_manager().summary())


@scope_app.command("add")
def scope_add(target: str) -> None:
    _startup()
    from kali_mind.security.scope import get_scope_manager
    get_scope_manager().add_target(target)
    print_success(f"Added: {target}")


@scope_app.command("exclude")
def scope_exclude(target: str) -> None:
    _startup()
    from kali_mind.security.scope import get_scope_manager
    get_scope_manager().exclude_target(target)
    print_success(f"Excluded: {target}")


@scope_app.command("clear")
def scope_clear() -> None:
    _startup()
    from kali_mind.security.scope import get_scope_manager
    get_scope_manager().clear_scope()
    print_success("Scope cleared.")


# ─── Wordlists (Feature #26) ─────────────────────────────────────────────────

@wordlists_app.callback(invoke_without_command=True)
def wordlists_default(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        _startup()
        from kali_mind.features.wordlist_manager import get_wordlist_manager
        get_wordlist_manager().render_table()


@wordlists_app.command("find")
def wordlists_find(category: str = typer.Argument("directory")) -> None:
    """Find best wordlist for a category."""
    _startup()
    from kali_mind.features.wordlist_manager import get_wordlist_manager
    path = get_wordlist_manager().best_for(category)
    if path:
        print_success(f"Best {category} wordlist: {path}")
    else:
        print_warning(f"No {category} wordlists found.")
        from kali_mind.features.wordlist_manager import get_wordlist_manager
        console.print(get_wordlist_manager().install_instructions())


# ─── Engagement profiles (Feature #31) ──────────────────────────────────────

@engagement_app.callback(invoke_without_command=True)
def engagement_default(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        _startup()
        from kali_mind.features.engagements import get_engagement_manager
        profiles = get_engagement_manager().list_all()
        if not profiles:
            print_info("No engagement profiles. Create one: kali-mind engagement new <name>")
            return
        table = Table(title="Engagement Profiles", box=box.ROUNDED, border_style="bright_blue")
        table.add_column("ID", style="cyan")
        table.add_column("Name")
        table.add_column("Client")
        table.add_column("Targets")
        table.add_column("Sessions")
        for p in profiles:
            table.add_row(p.id, p.name, p.client, str(len(p.authorized_targets)), str(len(p.sessions)))
        console.print(table)


@engagement_app.command("new")
def engagement_new(
    name: str,
    client: str = typer.Option("", "--client", "-c"),
    target: Optional[str] = typer.Option(None, "--target", "-t"),
) -> None:
    """Create a new engagement profile."""
    _startup()
    from kali_mind.features.engagements import get_engagement_manager
    targets = [target] if target else []
    profile = get_engagement_manager().create(name=name, client=client, authorized_targets=targets)
    print_success(f"Created engagement: {profile.name} (ID: {profile.id})")


@engagement_app.command("activate")
def engagement_activate(engagement_id: str) -> None:
    """Load engagement scope as active scope."""
    _startup()
    from kali_mind.features.engagements import get_engagement_manager
    ok = get_engagement_manager().activate(engagement_id)
    if ok:
        print_success(f"Activated engagement: {engagement_id}")
    else:
        print_error(f"Engagement not found: {engagement_id}")


@engagement_app.command("add-target")
def engagement_add_target(engagement_id: str, target: str) -> None:
    _startup()
    from kali_mind.features.engagements import get_engagement_manager
    ok = get_engagement_manager().add_target(engagement_id, target)
    if ok:
        print_success(f"Added {target} to {engagement_id}")
    else:
        print_error(f"Engagement not found: {engagement_id}")


# ─── Plugins ─────────────────────────────────────────────────────────────────

@plugins_app.callback(invoke_without_command=True)
def plugins_default(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        _startup()
        from kali_mind.plugins.loader import get_plugin_loader
        plugins = get_plugin_loader().list_plugins()
        if not plugins:
            print_info("No plugins loaded.")
        for p in plugins:
            console.print(f"  [cyan]{p.name}[/] — {p.path}")


@plugins_app.command("add")
def plugins_add(name: str) -> None:
    """Create plugin template."""
    _startup()
    from kali_mind.plugins.loader import get_plugin_loader
    path = get_plugin_loader().create_plugin_template(name)
    print_success(f"Plugin template: {path}")


@plugins_app.command("search")
def plugins_search(query: str) -> None:
    """Search plugin marketplace. (Feature #34)"""
    _startup()
    asyncio.run(_plugins_search(query))


async def _plugins_search(query: str) -> None:
    from kali_mind.features.plugin_marketplace import PluginMarketplace
    await PluginMarketplace().render_catalog(query)


@plugins_app.command("install")
def plugins_install(
    name: str,
    allow_remote: bool = typer.Option(
        False, "--allow-remote", help="Allow remote install after reviewing the source and command"
    ),
) -> None:
    """Install a marketplace plugin (remote execution requires explicit opt-in)."""
    _startup()
    asyncio.run(_plugins_install(name, allow_remote=allow_remote))


async def _plugins_install(name: str, *, allow_remote: bool = False) -> None:
    from kali_mind.features.plugin_marketplace import PluginMarketplace
    await PluginMarketplace().install(name, allow_remote=allow_remote)


@plugins_app.command("marketplace")
def plugins_marketplace() -> None:
    """Browse the plugin marketplace. (Feature #34)"""
    _startup()
    asyncio.run(_plugins_marketplace())


async def _plugins_marketplace() -> None:
    from kali_mind.features.plugin_marketplace import PluginMarketplace
    await PluginMarketplace().render_catalog()


# ─── Models ──────────────────────────────────────────────────────────────────

@models_app.callback(invoke_without_command=True)
def models_default(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        _startup()
        asyncio.run(_list_models())


async def _list_models() -> None:
    from kali_mind.ai.gateway import get_gateway
    gateway = get_gateway()
    health = await gateway.health_check_all()
    htable = Table(title="AI Providers", box=box.ROUNDED, border_style="bright_blue")
    htable.add_column("Provider", style="cyan")
    htable.add_column("Status")
    htable.add_column("Latency")
    for h in health:
        status = "[green]● Online[/]" if h.available else "[red]○ Offline[/]"
        latency = f"{h.latency_ms:.0f}ms" if h.latency_ms else "—"
        htable.add_row(h.name, status, latency)
    console.print(htable)

    from kali_mind.features.cost_tracker import get_cost_tracker
    tracker = get_cost_tracker()
    tracker.sync_from_gateway()
    if tracker._usage:
        console.print(tracker.render_table())


# ─── Report & Replay ─────────────────────────────────────────────────────────

@app.command("report")
def cmd_report(session_id: str = typer.Argument(...),
               format: Optional[str] = typer.Option(None, "--format", "-f")) -> None:
    """Generate reports for a session."""
    _startup()
    from kali_mind.reporting.manager import ReportManager
    try:
        paths = ReportManager().generate_all(session_id)
        print_success("Reports generated:")
        for fmt, path in paths.items():
            if not format or format == fmt:
                console.print(f"  [cyan]{fmt}[/]: {path}")
    except Exception as e:
        print_error(str(e))


@app.command("replay")
def cmd_replay(session_id: str) -> None:
    """Replay action timeline for a session."""
    _startup()
    from kali_mind.evidence.store import get_store
    log = get_store().get_replay_log(session_id)
    if not log:
        print_info("No replay data.")
        return
    console.print(f"\n[bold bright_blue]Replay: {session_id}[/]\n")
    for entry in log:
        ts = entry.get("timestamp", "")[:19]
        console.print(f"[dim]{ts}[/]  [cyan]{entry.get('action','')}[/]  {entry.get('details','')}")


@app.command("map")
def cmd_map(session_id: str = typer.Argument(...)) -> None:
    """Show attack surface map for a session. (Feature #21)"""
    _startup()
    from kali_mind.evidence.store import get_store
    from kali_mind.features.attack_surface import AttackSurfaceMap
    store = get_store()
    ev = store.get_evidence(session_id)

    hosts, ports = [], []
    for e in ev:
        if e.parsed:
            hosts.extend(e.parsed.get("hosts", []))
            ports.extend(e.parsed.get("ports", []))

    AttackSurfaceMap(session_id).render({"hosts": list(set(hosts)), "ports": ports})


@app.command("config")
def cmd_config() -> None:
    """Show configuration."""
    _startup()
    table = Table(title="Configuration", box=box.ROUNDED, border_style="bright_blue")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="bright_white")
    table.add_row("Home dir", str(settings.home_dir))
    table.add_row("DB path", str(settings.db_path))
    table.add_row("Default provider", settings.default_provider)
    table.add_row("Privacy mode", str(settings.privacy_mode))
    table.add_row("Offline mode", str(settings.offline_mode))
    table.add_row("Streaming", str(settings.enable_streaming))
    table.add_row("Log level", settings.log_level)
    console.print(table)


@app.command("serve")
def cmd_serve(
    host: str = typer.Option("127.0.0.1", "--host", "-H"),
    port: int = typer.Option(8765, "--port", "-p"),
    ssl_certfile: Optional[str] = typer.Option(None, "--ssl-certfile", help="TLS certificate for non-loopback binding"),
    ssl_keyfile: Optional[str] = typer.Option(None, "--ssl-keyfile", help="TLS private key for non-loopback binding"),
) -> None:
    """Start the API server; remote binds require TLS."""
    _startup()
    from kali_mind.api.server import start_server
    try:
        start_server(host=host, port=port, ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)
    except ValueError as exc:
        print_error(str(exc))
        raise typer.Exit(code=2)


@app.command("git-scan")
def cmd_git_scan(target: str = typer.Argument(..., help="Local path or GitHub URL")) -> None:
    """Scan a git repository for exposed secrets. (Feature #29)"""
    _startup()
    asyncio.run(_git_scan(target))


async def _git_scan(target: str) -> None:
    from kali_mind.features.git_scanner import GitScanner
    scanner = GitScanner()
    if not scanner.detect_tools():
        print_error("No secret scanning tools found. Install: pip install trufflehog  or: apt install gitleaks")
        return
    print_info(f"Scanning: {target}")
    if target.startswith("http"):
        result = await scanner.scan_github_repo(target)
    else:
        result = await scanner.scan_repo(target)
    if result.get("errors"):
        print_error(result["errors"][0])
    elif result["findings"]:
        print_error(f"Found {len(result['findings'])} potential secrets!")
        for f in result["findings"][:10]:
            console.print(f"  [red]•[/] [{f.get('rule','?')}] {f.get('file','')}")
    else:
        print_success("No secrets found.")


if __name__ == "__main__":
    app()


@playbook_app.callback(invoke_without_command=True)
def playbook_default(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is not None:
        return
    from kali_mind.features.playbook_runner import find_playbooks
    for p in find_playbooks():
        console.print(f"  [cyan]{p.stem}[/] — {p}")


@playbook_app.command("run")
def playbook_run(
    name: str = typer.Argument(..., help="Playbook name or path"),
    target: str = typer.Option(..., "--target", "-t", help="Target host/URL"),
) -> None:
    """Run a YAML engagement playbook against an in-scope target."""
    _startup()
    async def _run():
        from kali_mind.ai.gateway import get_gateway
        from kali_mind.agent.memory import AgentMemory
        from kali_mind.services.orchestrator import Orchestrator
        from kali_mind.features.playbook_runner import run_playbook
        import uuid
        sid = f"SESSION-{uuid.uuid4().hex[:8].upper()}"
        mem = AgentMemory(sid)
        mem.targets.append(target)
        orch = Orchestrator(get_gateway(), mem, sid, progress=lambda m: console.print(f"[dim]{m}[/]"))
        await run_playbook(name, target, orch)
        print_success(f"Playbook finished — session {sid}")
    asyncio.run(_run())


@playbook_app.command("list")
def playbook_list() -> None:
    from kali_mind.features.playbook_runner import find_playbooks
    for p in find_playbooks():
        console.print(f"  [cyan]{p.stem}[/] — {p}")

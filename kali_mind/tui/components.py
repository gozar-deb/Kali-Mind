"""Rich-based terminal UI components for Kali-Mind."""
from __future__ import annotations

from typing import Any, Dict, List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

_THEME = Theme({
    "info": "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "critical": "bold red on black",
    "high": "bold dark_orange",
    "medium": "bold yellow",
    "low": "bold cyan",
    "informational": "dim white",
    "accent": "bold bright_blue",
    "dim_text": "dim white",
    "prompt": "bold bright_cyan",
})

console = Console(theme=_THEME)


def print_banner(
    provider: str = "Ollama",
    model: str = "Local",
    mode: str = "Assisted",
    scope: str = "None",
    session: str = "—",
) -> None:
    """Print the Kali-Mind welcome banner."""
    banner = Panel(
        Text.assemble(
            Text("  ⚔  KALI-MIND  ⚔\n", style="bold bright_blue"),
            Text("  AI Security Orchestration Engine\n", style="dim white"),
            Text("\n"),
            Text(f"  AI:      ", style="dim white"), Text(f"{provider} / {model}\n", style="cyan"),
            Text(f"  Session: ", style="dim white"), Text(f"{session}\n", style="bright_white"),
            Text(f"  Mode:    ", style="dim white"), Text(f"{mode}\n", style="yellow"),
            Text(f"  Scope:   ", style="dim white"), Text(f"{scope}\n", style="green"),
        ),
        border_style="bright_blue",
        expand=False,
    )
    console.print(banner)


def print_plan(steps: list[dict]) -> None:
    """Display an execution plan."""
    table = Table(
        title="Execution Plan",
        box=box.ROUNDED,
        border_style="bright_blue",
        show_lines=True,
    )
    table.add_column("#", style="dim white", width=4)
    table.add_column("Step", style="bright_white")
    table.add_column("Tool", style="cyan")
    table.add_column("Operation", style="yellow")
    table.add_column("Target", style="green")

    for s in steps:
        table.add_row(
            str(s.get("step", "?")),
            s.get("description", ""),
            s.get("tool") or "—",
            s.get("operation") or "—",
            s.get("target") or "—",
        )
    console.print(table)


def print_findings(findings: list) -> None:
    """Display a findings summary table."""
    if not findings:
        console.print("[dim_text]No findings recorded.[/]")
        return

    sev_style = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "informational",
    }

    table = Table(
        title="Security Findings",
        box=box.ROUNDED,
        border_style="bright_blue",
        show_lines=True,
    )
    table.add_column("#", width=4, style="dim white")
    table.add_column("Severity", width=14)
    table.add_column("Title")
    table.add_column("Asset", style="cyan")
    table.add_column("Confidence", width=10)

    for i, f in enumerate(findings, 1):
        sev = f.severity if hasattr(f, "severity") else f.get("severity", "info")
        title = f.title if hasattr(f, "title") else f.get("title", "")
        asset = f.affected_asset if hasattr(f, "affected_asset") else f.get("affected_asset", "")
        conf = f.confidence if hasattr(f, "confidence") else f.get("confidence", "")
        table.add_row(
            str(i),
            Text(sev.upper(), style=sev_style.get(sev, "")),
            title,
            asset,
            conf,
        )
    console.print(table)


def print_tool_status(
    tool: str,
    operation: str,
    target: str,
    status: str = "running",
) -> None:
    icon = {"running": "◉", "done": "✓", "fail": "✗"}.get(status, "○")
    style = {"running": "yellow", "done": "green", "fail": "red"}.get(status, "white")
    console.print(f"  [{style}]{icon}[/] [cyan]{tool}[/]:[yellow]{operation}[/] → [green]{target}[/]")


def print_status_panel(
    steps_status: List[Dict[str, Any]],
    findings_count: Dict[str, int],
) -> None:
    """Print a rich status panel like the spec example."""
    status_lines = []
    icons = {"done": "✓", "running": "◉", "pending": "○", "fail": "✗"}
    styles = {"done": "green", "running": "yellow", "pending": "dim white", "fail": "red"}

    for s in steps_status:
        icon = icons.get(s["status"], "○")
        style = styles.get(s["status"], "white")
        status_lines.append(f"[{style}]{icon}[/] {s['name']}")

    status_text = "\n".join(status_lines) if status_lines else "(no steps)"
    crit = findings_count.get("critical", 0)
    high = findings_count.get("high", 0)
    med = findings_count.get("medium", 0)
    low = findings_count.get("low", 0)
    info = findings_count.get("informational", 0)
    total = sum(findings_count.values())

    findings_text = (
        f"Total: [bright_white]{total}[/]\n"
        f"[critical]Critical: {crit}[/]  [high]High: {high}[/]  "
        f"[medium]Medium: {med}[/]  [low]Low: {low}[/]  [dim]Info: {info}[/]"
    )

    panel = Panel(
        f"{status_text}\n\n{findings_text}",
        title="STATUS",
        border_style="bright_blue",
    )
    console.print(panel)


def ask_approval(prompt: str) -> str:
    """Prompt user for Y/N/E approval."""
    console.print(f"\n[prompt]{prompt}[/]")
    console.print("[dim]\\[Y][/] Yes  [dim]\\[N][/] No  [dim]\\[E][/] Edit")
    return console.input("[prompt]> [/]").strip().upper()


def print_ai_response(content: str, provider: str = "") -> None:
    provider_label = f" [dim]({provider})[/]" if provider else ""
    console.print(Panel(content, title=f"[accent]Kali-Mind{provider_label}[/]", border_style="bright_blue"))


def print_error(message: str) -> None:
    console.print(f"[error]✗ {message}[/]")


def print_success(message: str) -> None:
    console.print(f"[success]✓ {message}[/]")


def print_warning(message: str) -> None:
    console.print(f"[warning]⚠ {message}[/]")


def print_info(message: str) -> None:
    console.print(f"[info]ℹ {message}[/]")

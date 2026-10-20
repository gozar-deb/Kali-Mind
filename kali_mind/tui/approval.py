"""First-class approval UI — show command, allow edit, Y/N/edit."""
from __future__ import annotations

from typing import Optional, Tuple

from rich.console import Console
from rich.panel import Panel

console = Console()


def request_approval(
    tool: str,
    command: str,
    risk: str = "medium",
    reason: str = "",
) -> Tuple[bool, Optional[str]]:
    """
    Returns (approved, edited_command_or_None).
    If user chooses edit, returns the new command string (still executed via argv split carefully by caller).
    """
    body = f"[bold]Tool:[/] {tool}\n[bold]Risk:[/] {risk}\n"
    if reason:
        body += f"[bold]Reason:[/] {reason}\n"
    body += f"\n[cyan]{command}[/]"
    console.print(Panel(body, title="Approval required", border_style="yellow"))
    console.print("[y]es / [n]o / [e]dit command")
    try:
        choice = console.input("> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False, None
    if choice in ("y", "yes"):
        return True, None
    if choice in ("e", "edit"):
        try:
            edited = console.input("New command> ").strip()
        except (EOFError, KeyboardInterrupt):
            return False, None
        if edited:
            return True, edited
        return False, None
    return False, None

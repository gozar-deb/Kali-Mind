"""CLI helper utilities extracted from the monolith for maintainability."""
from __future__ import annotations

from rich.table import Table
from rich import box

from kali_mind.tui.components import console


def print_help() -> None:
    """Show interactive slash-command help."""
    table = Table(title="Slash commands", box=box.ROUNDED, border_style="cyan")
    table.add_column("Command", style="bold")
    table.add_column("Description")
    rows = [
        ("/agent <objective>", "Run AI agent plan+execute"),
        ("/scope [add|exclude] <t>", "Manage engagement scope"),
        ("/tools", "List tools"),
        ("/findings", "Show findings"),
        ("/report", "Generate reports"),
        ("/map", "Attack surface map"),
        ("/cost", "Token/cost dashboard"),
        ("/debate", "Multi-model finding debate"),
        ("/openai|/claude|/grok|/ollama", "Switch AI provider"),
        ("/status", "Session status"),
        ("help", "This help"),
        ("exit", "Quit"),
    ]
    for a, b in rows:
        table.add_row(a, b)
    console.print(table)


def print_tools_table(tools: list) -> None:
    table = Table(title="Tools", box=box.ROUNDED)
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Risk")
    table.add_column("Available")
    for t in tools:
        table.add_row(
            getattr(t, "name", "?"),
            str(getattr(t, "category", "")),
            str(getattr(getattr(t, "risk_level", None), "value", "")),
            "yes" if getattr(t, "available", False) else "no",
        )
    console.print(table)

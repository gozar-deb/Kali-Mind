"""Feature #34: Plugin marketplace — browse, search, and install community plugins."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()
logger = logging.getLogger(__name__)

# Community plugin registry URL (GitHub-hosted)
REGISTRY_URL = "https://raw.githubusercontent.com/kali-mind/plugins/main/registry.json"

# Fallback built-in catalog (used when registry is unreachable)
BUILTIN_CATALOG: List[Dict[str, Any]] = [
    {
        "name": "nuclei-templates",
        "description": "Extended Nuclei templates for web vulnerability scanning",
        "author": "ProjectDiscovery",
        "category": "web_security",
        "repo": "https://github.com/projectdiscovery/nuclei-templates",
        "install": "git clone https://github.com/projectdiscovery/nuclei-templates ~/.kali-mind/plugins/nuclei-templates",
        "tags": ["nuclei", "templates", "cve"],
    },
    {
        "name": "custom-wordlists",
        "description": "Custom wordlists for directory and DNS enumeration",
        "author": "Community",
        "category": "utility",
        "repo": "https://github.com/danielmiessler/SecLists",
        "install": "git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists",
        "tags": ["wordlists", "seclists"],
    },
    {
        "name": "log4shell-scanner",
        "description": "Log4Shell (CVE-2021-44228) detection plugin",
        "author": "Community",
        "category": "web_security",
        "repo": "https://github.com/fullhunt/log4j-scan",
        "install": "pip install log4j-scan --break-system-packages",
        "tags": ["log4j", "cve", "rce"],
    },
    {
        "name": "cloud-enum",
        "description": "Cloud resource enumeration for AWS, Azure, GCP",
        "author": "Community",
        "category": "reconnaissance",
        "repo": "https://github.com/initstring/cloud_enum",
        "install": "pip install cloud-enum --break-system-packages",
        "tags": ["cloud", "aws", "azure", "gcp"],
    },
]


class PluginMarketplace:
    def __init__(self, plugins_dir: Optional[Path] = None) -> None:
        if plugins_dir is None:
            from kali_mind.config import settings
            plugins_dir = settings.plugins_dir
        self.plugins_dir = plugins_dir

    async def fetch_catalog(self) -> List[Dict[str, Any]]:
        """Fetch the remote plugin catalog, fall back to built-in."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(REGISTRY_URL)
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            logger.debug("Failed to fetch remote plugin catalog: %s", e)
        return BUILTIN_CATALOG

    async def search(self, query: str) -> List[Dict[str, Any]]:
        catalog = await self.fetch_catalog()
        q = query.lower()
        return [
            p for p in catalog
            if q in p.get("name", "").lower()
            or q in p.get("description", "").lower()
            or any(q in t for t in p.get("tags", []))
            or q in p.get("category", "").lower()
        ]

    async def install(self, name: str, *, allow_remote: bool = False) -> bool:
        """Install a plugin by name.

        Security: install commands are executed without shell=True and must
        start with a whitelisted binary. Remote registry installs are blocked
        unless --allow-remote is explicitly passed.
        """
        if not allow_remote:
            console.print(
                "[yellow]Remote plugin installation is disabled by default. "
                "Re-run with --allow-remote only after reviewing the source and command.[/]"
            )
            return False
        catalog = await self.fetch_catalog()
        plugin = next((p for p in catalog if p.get("name") == name), None)
        if not plugin:
            console.print(f"[red]Plugin not found: {name}[/]")
            return False

        install_cmd = plugin.get("install", "")
        if not install_cmd:
            console.print(f"[yellow]No install command for: {name}[/]")
            return False

        # Security: validate install command starts with a trusted binary
        allowed_prefixes = ("git clone", "pip install", "pip3 install", "apt install",
                            "apt-get install", "sudo apt", "sudo pip", "cargo install")
        if not any(install_cmd.strip().startswith(p) for p in allowed_prefixes):
            console.print(f"[red]✗ Install command rejected — must start with a trusted tool (git, pip, apt)[/]")
            console.print(f"[dim]  Rejected: {install_cmd[:80]}[/]")
            return False

        console.print(f"[dim]Installing {name}...[/]")
        console.print(f"[dim]Command: {install_cmd}[/]")
        console.print("[yellow]This will run the above command. Proceed? [Y/N][/]")
        try:
            choice = input("> ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            return False
        if choice != "Y":
            console.print("[dim]Cancelled.[/]")
            return False

        # BUG FIX: use shlex.split instead of shell=True to prevent injection
        try:
            import shlex
            import asyncio
            cmd_parts = shlex.split(install_cmd)
            proc = await asyncio.create_subprocess_exec(
                *cmd_parts,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            from kali_mind.execution.process_utils import communicate_with_timeout
            stdout, stderr = await communicate_with_timeout(proc, timeout=120)
            if proc.returncode == 0:
                console.print(f"[green]✓ Installed: {name}[/]")
                return True
            else:
                console.print(f"[red]✗ Install failed: {stderr.decode(errors='replace')[:200]}[/]")
                return False
        except asyncio.TimeoutError:
            console.print("[red]✗ Install timed out after 120s[/]")
            return False
        except Exception as e:
            console.print(f"[red]✗ Install error: {e}[/]")
            return False

    def list_installed(self) -> List[str]:
        """List locally installed plugins."""
        if not self.plugins_dir.exists():
            return []
        return [d.name for d in self.plugins_dir.iterdir() if d.is_dir()]

    async def render_catalog(self, query: Optional[str] = None) -> None:
        catalog = await self.search(query) if query else await self.fetch_catalog()
        installed = set(self.list_installed())

        table = Table(
            title=f"Plugin Marketplace{f' — \"{query}\"' if query else ''}",
            box=box.ROUNDED, border_style="bright_blue",
        )
        table.add_column("Name", style="cyan")
        table.add_column("Category", style="yellow")
        table.add_column("Description")
        table.add_column("Status", width=10)

        for p in catalog:
            status = "[green]Installed[/]" if p["name"] in installed else "[dim]Available[/]"
            table.add_row(p["name"], p.get("category", ""), p.get("description", "")[:60], status)

        console.print(table)
        console.print(f"\nInstall: [cyan]kali-mind plugins install <name>[/]")

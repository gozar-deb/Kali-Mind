"""Feature #26: Wordlist manager — discover, categorize, and select wordlists."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

KNOWN_WORDLIST_DIRS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster",
    "/usr/share/metasploit-framework/data/wordlists",
    "/opt/SecLists",
]

CATEGORIES: Dict[str, List[str]] = {
    "directory": ["common", "directory", "web-content", "dirbuster", "dirb"],
    "dns": ["dns", "subdomain", "subdomains"],
    "password": ["password", "rockyou", "unix_passwords", "darkweb"],
    "username": ["username", "users", "unix_users"],
    "fuzzing": ["fuzz", "lfi", "sqli", "xss", "bypass"],
}


class WordlistManager:
    def __init__(self) -> None:
        self._cache: Optional[List[Tuple[str, str, int]]] = None  # (category, path, size_kb)

    def scan(self) -> List[Tuple[str, str, int]]:
        """Scan known dirs for wordlist files."""
        if self._cache is not None:
            return self._cache
        results = []
        for base in KNOWN_WORDLIST_DIRS:
            base_path = Path(base)
            if not base_path.exists():
                continue
            for f in base_path.rglob("*.txt"):
                category = self._categorize(f.name.lower())
                size_kb = f.stat().st_size // 1024
                results.append((category, str(f), size_kb))
        self._cache = sorted(results, key=lambda x: x[0])
        return self._cache

    def _categorize(self, name: str) -> str:
        for cat, keywords in CATEGORIES.items():
            if any(kw in name for kw in keywords):
                return cat
        return "other"

    def best_for(self, category: str) -> Optional[str]:
        """Return the best available wordlist for a category."""
        wls = self.scan()
        matches = [(cat, path, size) for cat, path, size in wls if cat == category]
        if not matches:
            return None
        # Prefer medium-sized wordlists (not too small, not huge)
        ideal = sorted(matches, key=lambda x: abs(x[2] - 500))
        return ideal[0][1]

    def best_directory_wordlist(self) -> Optional[str]:
        return self.best_for("directory")

    def best_password_wordlist(self) -> Optional[str]:
        return self.best_for("password")

    def best_dns_wordlist(self) -> Optional[str]:
        return self.best_for("dns")

    def render_table(self) -> None:
        wls = self.scan()
        table = Table(title="Available Wordlists", box=box.ROUNDED, border_style="bright_blue")
        table.add_column("Category", style="cyan", width=12)
        table.add_column("Path", style="white")
        table.add_column("Size (KB)", justify="right", style="yellow")
        for cat, path, size in wls[:50]:
            table.add_row(cat, path, f"{size:,}")
        if not wls:
            table.add_row("[dim]No wordlists found[/]",
                          "Install: sudo apt install wordlists seclists", "—")
        console.print(table)

    def is_installed(self) -> bool:
        return bool(self.scan())

    def install_instructions(self) -> str:
        return (
            "Wordlists not found. Install them:\n"
            "  sudo apt install wordlists seclists\n"
            "  sudo gzip -d /usr/share/wordlists/rockyou.txt.gz\n\n"
            "Or clone SecLists:\n"
            "  git clone https://github.com/danielmiessler/SecLists /opt/SecLists"
        )


_manager: Optional[WordlistManager] = None


def get_wordlist_manager() -> WordlistManager:
    global _manager
    if _manager is None:
        _manager = WordlistManager()
    return _manager

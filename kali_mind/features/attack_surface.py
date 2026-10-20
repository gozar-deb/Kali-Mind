"""Feature #21: Attack Surface Map — rich tree visualization of discovered assets."""
from __future__ import annotations
from typing import Any, Dict, List
from rich.tree import Tree
from rich.console import Console
from rich.panel import Panel

console = Console()


class AttackSurfaceMap:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id

    def build_tree(self, memory_data: Dict[str, Any]) -> Tree:
        hosts = memory_data.get("hosts", [])
        ports = memory_data.get("ports", [])
        technologies = memory_data.get("technologies", [])
        urls = memory_data.get("urls", [])
        findings = memory_data.get("findings", [])

        root = Tree(f"[bold bright_blue]⚔ Attack Surface — {self.session_id}[/]")
        if not hosts:
            root.add("[dim]No hosts discovered yet[/]")
            return root

        ports_by_host: Dict[str, List[Dict]] = {}
        for p in ports:
            ports_by_host.setdefault(p.get("host", "?"), []).append(p)

        urls_by_host: Dict[str, List[str]] = {}
        for u in urls:
            try:
                from urllib.parse import urlparse
                h = urlparse(u).netloc or "unknown"
                urls_by_host.setdefault(h, []).append(u)
            except Exception:
                urls_by_host.setdefault("unknown", []).append(u)

        findings_by_asset: Dict[str, List] = {}
        for f in findings:
            asset = f.get("affected_asset", "?") if isinstance(f, dict) else getattr(f, "affected_asset", "?")
            findings_by_asset.setdefault(asset, []).append(f)

        for host in hosts:
            host_node = root.add(f"[bold green]🖥  {host}[/]")
            for p in ports_by_host.get(host, []):
                pn = p.get("port", "?")
                proto = p.get("protocol", "tcp")
                svc = p.get("service", "unknown")
                ver = p.get("version", "")
                port_node = host_node.add(
                    f"[cyan]{pn}/{proto}[/]  [yellow]{svc}[/]"
                    + (f"  [dim]{ver[:40]}[/]" if ver else "")
                )
                for u in urls_by_host.get(host, [])[:5]:
                    port_node.add(f"[blue]{u}[/]")
                for f in findings_by_asset.get(f"{host}:{pn}", []):
                    sev = f.get("severity", "info") if isinstance(f, dict) else getattr(f, "severity", "info")
                    title = f.get("title", "") if isinstance(f, dict) else getattr(f, "title", "")
                    color = {"critical": "red", "high": "dark_orange", "medium": "yellow",
                             "low": "cyan"}.get(sev, "dim")
                    port_node.add(f"[{color}]⚠ {sev.upper()}: {title}[/]")
            if technologies:
                tn = host_node.add("[dim]Technologies[/]")
                for t in technologies[:10]:
                    tn.add(f"[magenta]{t}[/]")
        return root

    def render(self, memory_data: Dict[str, Any]) -> None:
        tree = self.build_tree(memory_data)
        console.print(Panel(tree, border_style="bright_blue", title="Attack Surface Map"))

    def to_text(self, memory_data: Dict[str, Any]) -> str:
        hosts = memory_data.get("hosts", [])
        ports = memory_data.get("ports", [])
        ports_by_host: Dict[str, List[Dict]] = {}
        for p in ports:
            ports_by_host.setdefault(p.get("host", "?"), []).append(p)
        lines = [f"Attack Surface — {self.session_id}", ""]
        for host in hosts:
            lines.append(f"{host}")
            hp = ports_by_host.get(host, [])
            for i, p in enumerate(hp):
                prefix = "└──" if i == len(hp) - 1 else "├──"
                lines.append(f"  {prefix} {p.get('port')}/{p.get('protocol','tcp')} {p.get('service','')}")
            lines.append("")
        return "\n".join(lines)

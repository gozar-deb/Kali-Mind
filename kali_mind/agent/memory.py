"""Agent memory — conversation history, assets, and token-budgeted context."""
from __future__ import annotations

from typing import Any, Dict, List

from kali_mind.ai.schemas import Message, Role


def _estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token)."""
    return max(1, len(text) // 4)


class AgentMemory:
    """Tracks conversation history, discovered assets, and session state."""

    def __init__(self, session_id: str, max_context_tokens: int = 6000) -> None:
        self.session_id = session_id
        self.max_context_tokens = max_context_tokens
        self.messages: List[Message] = []
        self.targets: List[str] = []
        self.discovered_hosts: List[str] = []
        self.discovered_ports: List[Dict[str, Any]] = []
        self.discovered_services: List[str] = []
        self.discovered_technologies: List[str] = []
        self.discovered_urls: List[str] = []
        self.tool_results: List[Dict[str, Any]] = []
        self.context: Dict[str, Any] = {}
        self._summary: str = ""

    def add_user_message(self, content: str) -> None:
        self.messages.append(Message(role=Role.user, content=content))
        self._maybe_summarize()

    def add_assistant_message(self, content: str) -> None:
        self.messages.append(Message(role=Role.assistant, content=content))
        self._maybe_summarize()

    def add_tool_result(self, tool: str, result: Dict[str, Any]) -> None:
        # Keep tool results compact
        compact = {k: result[k] for k in result if k in (
            "hosts", "ports", "services", "technologies", "urls", "findings", "paths",
        ) or k == "raw_summary"}
        self.tool_results.append({"tool": tool, "result": compact})
        if "hosts" in result:
            for h in result["hosts"]:
                host = h if isinstance(h, str) else str(h.get("host", h))
                if host and host not in self.discovered_hosts:
                    self.discovered_hosts.append(host)
        if "ports" in result:
            for p in result["ports"]:
                if p not in self.discovered_ports:
                    self.discovered_ports.append(p)
        if "services" in result:
            self.discovered_services.extend(
                s for s in result["services"] if s not in self.discovered_services
            )
        if "technologies" in result:
            self.discovered_technologies.extend(
                t for t in result["technologies"] if t not in self.discovered_technologies
            )
        if "urls" in result:
            for u in result["urls"]:
                url = u if isinstance(u, str) else str(u.get("url", u))
                if url and url not in self.discovered_urls:
                    self.discovered_urls.append(url)

    def get_context_summary(self) -> str:
        lines = [f"Session: {self.session_id}"]
        if self._summary:
            lines.append(f"History summary: {self._summary}")
        if self.targets:
            lines.append(f"Targets: {', '.join(self.targets)}")
        if self.discovered_hosts:
            lines.append(f"Discovered hosts: {', '.join(self.discovered_hosts[:30])}")
        if self.discovered_ports:
            port_strs = [
                f"{p.get('port', '?')}/{p.get('protocol', 'tcp')} ({p.get('service', '')})"
                for p in self.discovered_ports[:20]
            ]
            lines.append(f"Open ports: {', '.join(port_strs)}")
        if self.discovered_technologies:
            lines.append(f"Technologies: {', '.join(self.discovered_technologies[:15])}")
        if self.discovered_urls:
            lines.append(f"URLs: {', '.join(self.discovered_urls[:15])}")
        if self.tool_results:
            lines.append(f"Tools run: {len(self.tool_results)}")
        return "\n".join(lines)

    def get_recent_messages(self, n: int = 10) -> List[Message]:
        """Return recent messages that fit under the token budget."""
        selected: List[Message] = []
        budget = self.max_context_tokens
        for msg in reversed(self.messages):
            cost = _estimate_tokens(msg.content)
            if cost > budget and selected:
                break
            selected.append(msg)
            budget -= cost
            if len(selected) >= n:
                break
        return list(reversed(selected))

    def _maybe_summarize(self) -> None:
        """When history is long, collapse older turns into a short summary."""
        if len(self.messages) < 20:
            return
        older = self.messages[:-12]
        if not older:
            return
        bits = []
        for m in older[-10:]:
            prefix = "User" if m.role == Role.user else "Assistant"
            bits.append(f"{prefix}: {m.content[:120]}")
        self._summary = " | ".join(bits)[:800]
        # Keep only recent messages in full fidelity
        self.messages = self.messages[-12:]

    def clear(self) -> None:
        self.messages.clear()
        self.tool_results.clear()
        self._summary = ""

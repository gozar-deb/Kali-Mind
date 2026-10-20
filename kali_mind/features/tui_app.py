"""Feature #28: Full Textual-based TUI with split panes."""
from __future__ import annotations


try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import (
        Footer, Header, Input, Label, Log, RichLog
    )
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


if TEXTUAL_AVAILABLE:
    CSS = """
    Screen { background: #0d1117; }
    Header { background: #21262d; color: #58a6ff; }
    Footer { background: #21262d; }
    .sidebar { width: 30%; border: solid #30363d; }
    .main-pane { width: 70%; border: solid #30363d; }
    .chat-log { height: 1fr; overflow-y: auto; }
    .input-row { height: 3; }
    Input { background: #161b22; border: solid #30363d; color: #c9d1d9; }
    Label { color: #58a6ff; padding: 0 1; }
    Log { background: #0d1117; color: #8b949e; }
    RichLog { background: #0d1117; }
    .status-good { color: #3fb950; }
    .status-bad { color: #ff2d2d; }
    .severity-critical { color: #ff2d2d; }
    .severity-high { color: #ff6b35; }
    .severity-medium { color: #ffd700; }
    .severity-low { color: #4fc3f7; }
    """

    class KaliMindTUI(App):
        """Full-screen TUI for Kali-Mind."""
        CSS = CSS
        BINDINGS = [
            Binding("ctrl+c", "quit", "Quit"),
            Binding("ctrl+p", "switch_provider", "Provider"),
            Binding("ctrl+r", "refresh", "Refresh"),
            Binding("f1", "show_help", "Help"),
        ]

        session_id: str = ""
        provider: str = "ollama"

        def __init__(self, session_id: str = "", provider: str = "ollama") -> None:
            super().__init__()
            self.session_id = session_id
            self.provider = provider

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal():
                with Vertical(classes="sidebar"):
                    yield Label("⚔ STATUS")
                    yield Log(id="status_log", highlight=True)
                    yield Label("🔍 FINDINGS")
                    yield Log(id="findings_log", highlight=True)
                    yield Label("🛠 TOOLS")
                    yield Log(id="tools_log", highlight=True)
                with Vertical(classes="main-pane"):
                    yield Label("💬 AI CHAT")
                    yield RichLog(id="chat_log", highlight=True, markup=True)
                    with Horizontal(classes="input-row"):
                        yield Input(placeholder="Type objective or /command...", id="chat_input")
            yield Footer()

        def on_mount(self) -> None:
            self.query_one("#status_log", Log).write_line(f"Session: {self.session_id}")
            self.query_one("#status_log", Log).write_line(f"Provider: {self.provider}")
            self.query_one("#chat_log", RichLog).write(
                "[bold bright_blue]⚔ Kali-Mind TUI[/]\n"
                "Type your security objective or use /commands\n"
                "Press Ctrl+C to exit\n"
            )

        async def on_input_submitted(self, event: Input.Submitted) -> None:
            text = event.value.strip()
            if not text:
                return
            event.input.value = ""
            chat_log = self.query_one("#chat_log", RichLog)
            chat_log.write(f"\n[bold bright_cyan]You:[/] {text}")

            try:
                from kali_mind.ai.gateway import get_gateway
                from kali_mind.ai.schemas import AIRequest, Message, Role

                gateway = get_gateway()
                req = AIRequest(
                    system="You are Kali-Mind, an AI security orchestration assistant.",
                    messages=[Message(role=Role.user, content=text)],
                    max_tokens=800,
                )
                response = await gateway.complete(req, provider=self.provider)
                chat_log.write(f"\n[bold bright_blue]Kali-Mind:[/]\n{response.content}\n")

                status_log = self.query_one("#status_log", Log)
                status_log.write_line(f"AI: {response.provider} ({response.output_tokens} tokens)")
            except Exception as e:
                chat_log.write(f"\n[red]Error: {e}[/]\n")

        def action_refresh(self) -> None:
            self._refresh_findings()

        def _refresh_findings(self) -> None:
            if not self.session_id:
                return
            try:
                from kali_mind.evidence.store import get_store
                findings = get_store().get_findings(self.session_id)
                log = self.query_one("#findings_log", Log)
                log.clear()
                for f in findings[-10:]:
                    sev = f.severity.upper()
                    log.write_line(f"[{sev}] {f.title[:30]}")
            except Exception:
                pass

        def action_show_help(self) -> None:
            log = self.query_one("#chat_log", RichLog)
            log.write(
                "\n[bold]Commands:[/]\n"
                "/agent <objective> — run agent\n"
                "/scope add <target> — add scope\n"
                "/findings — show findings\n"
                "/report — generate report\n"
                "/tools — list tools\n"
                "Ctrl+R — refresh findings\n"
                "Ctrl+P — switch provider\n"
            )

        def action_switch_provider(self) -> None:
            providers = ["ollama", "openai", "anthropic", "groq", "gemini"]
            idx = providers.index(self.provider) if self.provider in providers else 0
            self.provider = providers[(idx + 1) % len(providers)]
            self.query_one("#status_log", Log).write_line(f"Provider: {self.provider}")


def launch_tui(session_id: str = "", provider: str = "ollama") -> None:
    """Launch the full-screen TUI."""
    if not TEXTUAL_AVAILABLE:
        from rich.console import Console
        Console().print("[red]Textual not installed. Run: pip install textual[/]")
        return
    app = KaliMindTUI(session_id=session_id, provider=provider)
    app.run()

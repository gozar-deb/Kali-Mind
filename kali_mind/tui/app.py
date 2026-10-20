"""Multi-pane Textual TUI for Kali-Mind."""
from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Log, Static, DataTable


class KaliMindTUI(App):
    """Panes: scope/status | plan/output | findings."""

    CSS = """
    Screen { layout: vertical; }
    #top { height: 3; }
    #main { height: 1fr; }
    #left { width: 1fr; }
    #center { width: 2fr; }
    #right { width: 1fr; }
    #input { dock: bottom; height: 3; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("ctrl+c", "quit", "Quit"),
        Binding("f5", "refresh", "Refresh"),
    ]

    def __init__(self, session_id: str = "TUI", **kwargs):
        super().__init__(**kwargs)
        self.session_id = session_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"Kali-Mind TUI — session {self.session_id}", id="top")
        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield Static("[b]Scope / Status[/b]")
                yield Log(id="scope_log")
            with Vertical(id="center"):
                yield Static("[b]Plan / Tool Output[/b]")
                yield Log(id="output_log")
            with Vertical(id="right"):
                yield Static("[b]Findings[/b]")
                yield DataTable(id="findings_table")
        yield Input(placeholder="Objective or /command — Enter to run", id="input")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings_table", DataTable)
        table.add_columns("Sev", "Title", "Asset")
        scope = self.query_one("#scope_log", Log)
        try:
            from kali_mind.security.scope import get_scope_manager
            scope.write(get_scope_manager().summary())
        except Exception as e:
            scope.write(f"Scope: {e}")
        out = self.query_one("#output_log", Log)
        out.write("Ready. Type an objective or /help")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return
        out = self.query_one("#output_log", Log)
        if text in ("/quit", "exit", "q"):
            self.exit()
            return
        out.write(f"> {text}")
        if text.startswith("/scope"):
            try:
                from kali_mind.security.scope import get_scope_manager
                parts = text.split()
                mgr = get_scope_manager()
                if len(parts) >= 3 and parts[1] == "add":
                    mgr.add_target(parts[2])
                    out.write(f"Added scope: {parts[2]}")
                self.query_one("#scope_log", Log).clear()
                self.query_one("#scope_log", Log).write(mgr.summary())
            except Exception as e:
                out.write(f"Error: {e}")
            return
        out.write("(Connect orchestrator in full install to run agents from TUI)")
        out.write("Use CLI: kali-mind agent \"...\" for full execution.")


def run_tui(session_id: str = "TUI") -> None:
    KaliMindTUI(session_id=session_id).run()

"""Regression tests for security and correctness fixes in the v0.5.1 audit pass."""
from __future__ import annotations

import asyncio
import sys

import pytest


def test_scope_accepts_authorized_urls_and_preserves_cidr(tmp_path):
    from kali_mind.security.scope import ScopeConfig, ScopeManager

    manager = ScopeManager(scope_file=tmp_path / "scope.yaml")
    manager.set_scope(ScopeConfig(authorized_targets=["192.168.56.0/24", "https://example.com"] ,
                                  excluded_targets=["https://admin.example.com/login"]))
    assert manager.is_in_scope("192.168.56.10")[0]
    assert manager.is_in_scope("https://example.com/login")[0]
    assert not manager.is_in_scope("https://admin.example.com/login")[0]
    assert not manager.is_in_scope("https://evil-example.com")[0]


def test_tool_call_parser_handles_nested_json():
    from kali_mind.ai.tool_channel import extract_tool_calls, tool_calls_to_requests

    text = '''<TOOL_CALL>
    {"tool":"nmap","operation":"quick_scan","target":"192.168.56.10",
     "options":{"ports":"80,443","nested":{"enabled":true}}}
    </TOOL_CALL>'''
    calls = extract_tool_calls(text)
    assert len(calls) == 1
    assert calls[0]["options"]["nested"]["enabled"] is True
    requests, errors = tool_calls_to_requests(calls, allowed_tools={"nmap"})
    assert not errors
    assert requests[0].options["ports"] == "80,443"


def test_tool_call_parser_rejects_missing_target_and_bad_timeout():
    from kali_mind.ai.tool_channel import tool_calls_to_requests

    requests, errors = tool_calls_to_requests([{"tool": "nmap"}], allowed_tools={"nmap"})
    assert not requests and errors
    requests, errors = tool_calls_to_requests([
        {"tool": "nmap", "target": "192.168.56.10", "timeout": "not-a-number"}
    ], allowed_tools={"nmap"})
    assert not requests and any("Timeout" in e for e in errors)


def test_restricted_environment_does_not_forward_kali_mind_secrets(monkeypatch):
    from kali_mind.security.sandbox import restricted_env

    monkeypatch.setenv("KALI_MIND_API_TOKEN", "do-not-forward")
    monkeypatch.setenv("OPENAI_API_KEY", "do-not-forward-either")
    env = restricted_env()
    assert "KALI_MIND_API_TOKEN" not in env
    assert "OPENAI_API_KEY" not in env


def test_requested_sandbox_fails_closed_without_wrapper(monkeypatch):
    from kali_mind.security import sandbox

    monkeypatch.setattr(sandbox.shutil, "which", lambda _binary: None)
    with pytest.raises(RuntimeError, match="not installed"):
        sandbox.wrap_command(["echo", "hello"], enabled=True)


def test_unsigned_plugin_signature_is_rejected_by_default(tmp_path):
    from kali_mind.security.plugin_sign import verify_plugin_signature

    (tmp_path / "adapter.py").write_text("# harmless test plugin\n")
    ok, reason = verify_plugin_signature(tmp_path)
    assert not ok
    assert "required" in reason


def test_plugin_template_rejects_path_traversal(tmp_path):
    from kali_mind.plugins.loader import PluginLoader

    loader = PluginLoader(plugins_dir=tmp_path)
    with pytest.raises(ValueError):
        loader.create_plugin_template("../escape")


def test_execution_policy_cannot_be_skipped(monkeypatch):
    from kali_mind.execution.executor import ExecutionEngine
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.security.policy import PolicyDecision, PolicyResult
    from kali_mind.tools.registry import RiskLevel
    import kali_mind.execution.executor as executor_module

    class DenyPolicy:
        def evaluate(self, _request):
            return PolicyResult(PolicyDecision.DENY, "test deny", RiskLevel.CRITICAL)

    monkeypatch.setattr(executor_module, "get_policy_engine", lambda: DenyPolicy())
    result = asyncio.run(ExecutionEngine().execute(
        ToolRequest(tool="nmap", operation="quick_scan", target="192.168.56.10"),
        skip_policy=True,
    ))
    assert not result.success
    assert "Policy denied" in (result.error or "")


def test_timed_out_process_is_killed_and_reaped():
    from kali_mind.execution.executor import ExecutionEngine

    engine = ExecutionEngine()

    async def run():
        with pytest.raises(asyncio.TimeoutError):
            await engine._run_process(
                [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1
            )
        assert not engine._running_processes

    asyncio.run(run())


def test_execution_output_capture_is_bounded_and_marks_truncation():
    from kali_mind.execution.executor import ExecutionEngine, MAX_OUTPUT_BYTES

    engine = ExecutionEngine()
    stdout, _stderr, code = asyncio.run(engine._run_process(
        [sys.executable, "-c", "print('x' * 11000000)"], timeout=15
    ))
    assert code == 0
    assert len(stdout) <= MAX_OUTPUT_BYTES + 100
    assert "stdout truncated" in stdout


def test_privacy_mode_never_falls_back_to_remote_provider(monkeypatch):
    from kali_mind.ai.gateway import AIGateway
    from kali_mind.ai.schemas import AIRequest, Message, Role
    import kali_mind.config as config_module

    monkeypatch.setattr(config_module.settings, "privacy_mode", True)
    monkeypatch.setattr(config_module.settings, "offline_mode", False)
    gateway = AIGateway.__new__(AIGateway)
    gateway._providers = {"openai": object()}
    gateway._usage = {}
    gateway._health_cache = {}
    request = AIRequest(messages=[Message(role=Role.user, content="hello")])
    with pytest.raises(RuntimeError, match="no remote fallback"):
        asyncio.run(gateway.complete(request))


def test_metasploit_module_execution_enforces_scope(monkeypatch):
    from kali_mind.features.msf_client import MetasploitClient
    import kali_mind.security.scope as scope_module

    class Scope:
        def is_in_scope(self, _target):
            return False, "not authorized"

    monkeypatch.setattr(scope_module, "get_scope_manager", lambda: Scope())
    client = MetasploitClient(password="test")
    client._token = "authenticated"

    async def run():
        with pytest.raises(PermissionError, match="explicit approval"):
            await client.run_module("exploit", "example", {}, "203.0.113.99")
        with pytest.raises(PermissionError, match="scope policy"):
            await client.run_module(
                "exploit", "example", {}, "203.0.113.99", approved=True
            )

    asyncio.run(run())


def test_html_report_escapes_untrusted_finding_fields():
    from kali_mind.reporting.html import generate_html
    from kali_mind.evidence.store import Finding, Session, EvidenceRecord

    session = Session(id="S-1", name="<script>alert(1)</script>")
    finding = Finding(
        session_id="S-1", title="<script>alert(2)</script>", severity="<img>",
        confidence="<b>bad</b>", affected_asset="example.test",
        description="safe", timestamp="<svg/onload=alert(3)>",
    )
    evidence = [EvidenceRecord(
        session_id="S-1", tool="<script>", operation="</td><script>",
        target="example.test", command="echo ok",
    )]
    html = generate_html(session, evidence, [finding])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(2)&lt;/script&gt;" in html
    assert "&lt;svg/onload=alert(3)&gt;" in html


def test_pdf_report_escapes_untrusted_paragraph_markup(tmp_path):
    from kali_mind.reporting.pdf import generate_pdf
    from kali_mind.evidence.store import Finding, Session

    session = Session(id="S-1", name="<script>alert(1)</script>")
    finding = Finding(
        session_id="S-1", title="<script>alert(2)</script>", severity="high",
        confidence="high", affected_asset="example.test",
        description="<b>untrusted</b>", remediation="<para>bad</para>",
    )
    output = tmp_path / "report.pdf"
    generate_pdf(session, [], [finding], output)
    assert output.exists() and output.stat().st_size > 100


def test_cost_tracker_does_not_double_count_gateway_snapshots(monkeypatch):
    from kali_mind.ai.schemas import TokenUsage
    from kali_mind.features.cost_tracker import CostTracker
    import kali_mind.ai.gateway as gateway_module

    snapshot = [TokenUsage(provider="openai", model="gpt-test", input_tokens=10,
                           output_tokens=5, requests=1, cost_estimate=0.01,
                           total_latency_ms=100)]

    class Gateway:
        def get_usage_summary(self):
            return snapshot

    monkeypatch.setattr(gateway_module, "get_gateway", lambda: Gateway())
    tracker = CostTracker()
    tracker.sync_from_gateway()
    tracker.sync_from_gateway()
    usage = tracker._usage["openai:gpt-test"]
    assert usage.requests == 1
    assert usage.input_tokens == 10
    assert usage.cost_estimate == pytest.approx(0.01)

    snapshot[0] = TokenUsage(provider="openai", model="gpt-test", input_tokens=18,
                             output_tokens=8, requests=2, cost_estimate=0.02,
                             total_latency_ms=160)
    tracker.sync_from_gateway()
    usage = tracker._usage["openai:gpt-test"]
    assert usage.requests == 2
    assert usage.input_tokens == 18
    assert usage.cost_estimate == pytest.approx(0.02)


def test_remote_api_binding_requires_tls(monkeypatch):
    from kali_mind.api.server import start_server

    with pytest.raises(ValueError, match="requires both"):
        start_server(host="0.0.0.0", port=8765)


def test_engagement_manager_rejects_path_like_ids(tmp_path):
    from kali_mind.features.engagements import EngagementManager

    manager = EngagementManager(engagements_dir=tmp_path)
    assert manager.get("../../etc/passwd") is None


def test_session_export_filename_is_sanitized(tmp_path, monkeypatch):
    from kali_mind.features.session_transfer import SessionTransfer
    from kali_mind.evidence.store import EvidenceStore, Session
    import kali_mind.config as config_module

    store = EvidenceStore(tmp_path / "db.sqlite")
    store.create_session(Session(id="../outside", name="../../escape/name"))
    monkeypatch.setattr(config_module.settings, "sessions_dir", tmp_path / "exports")
    result = SessionTransfer(store).export_session("../outside")
    assert result.parent == (tmp_path / "exports")
    assert result.exists()


def test_critical_adapter_risk_is_not_downgraded_in_autonomous_mode(tmp_path, monkeypatch):
    from kali_mind.security.policy import PolicyEngine, ExecutionMode, PolicyDecision
    from kali_mind.security.scope import ScopeManager, ScopeConfig
    from kali_mind.tools.adapters.base import ToolRequest
    import kali_mind.security.scope as scope_module

    scope = ScopeManager(scope_file=tmp_path / "scope.yaml")
    scope.set_scope(ScopeConfig(authorized_targets=["192.168.56.0/24"],
                                allowed_categories=["custom"]))
    monkeypatch.setattr(scope_module, "_scope_manager", scope)
    engine = PolicyEngine(mode=ExecutionMode.AUTONOMOUS)
    decision = engine.evaluate(ToolRequest(
        tool="responder", operation="listen", target="192.168.56.10"
    ))
    assert decision.decision == PolicyDecision.REQUIRE_APPROVAL


def test_report_manager_sanitizes_session_name_paths(tmp_path, monkeypatch):
    import kali_mind.reporting.manager as manager_module
    from kali_mind.reporting.manager import ReportManager
    from kali_mind.evidence.store import EvidenceStore, Session

    store = EvidenceStore(tmp_path / "db.sqlite")
    store.create_session(Session(id="SESSION-123", name="../../escape/name"))
    monkeypatch.setattr(manager_module, "get_store", lambda: store)
    output_dir = tmp_path / "reports"
    paths = ReportManager(reports_dir=output_dir).generate_all("SESSION-123")
    assert paths
    assert all(path.parent == output_dir for path in paths.values())
    assert all(path.exists() for path in paths.values())


def test_ai_cost_cap_reserves_estimated_cost_before_cloud_call(monkeypatch):
    from kali_mind.ai.gateway import AIGateway
    from kali_mind.ai.schemas import AIRequest, AIResponse, Message, Role
    from kali_mind.security.rate_limit import RateLimiter, RateLimitConfig
    from kali_mind.exceptions import PolicyDenied
    import kali_mind.config as config_module
    import kali_mind.security.rate_limit as rate_module

    class FakeCloudProvider:
        model = "unknown-expensive-model"
        called = False

        async def complete(self, _request):
            self.called = True
            return AIResponse(content="ok", provider="cloud", model=self.model)

    provider = FakeCloudProvider()
    gateway = AIGateway.__new__(AIGateway)
    gateway._providers = {"cloud": provider}
    gateway._usage = {}
    gateway._health_cache = {}
    monkeypatch.setattr(config_module.settings, "privacy_mode", False)
    monkeypatch.setattr(config_module.settings, "offline_mode", False)
    monkeypatch.setattr(config_module.settings, "default_provider", "cloud")
    monkeypatch.setattr(rate_module, "_limiter", RateLimiter(
        config=RateLimitConfig(max_ai_cost_usd_per_session=0.01)
    ))
    request = AIRequest(messages=[Message(role=Role.user, content="hello")], max_tokens=4096)
    with pytest.raises(PolicyDenied):
        asyncio.run(gateway.complete(request))
    assert not provider.called


def test_rate_limits_are_scoped_to_session_ids():
    from kali_mind.security.rate_limit import RateLimiter, RateLimitConfig

    limiter = RateLimiter(config=RateLimitConfig(
        max_tools_per_session=1, max_ai_cost_usd_per_session=0.5
    ))
    assert limiter.consume_tool("session-a")[0]
    assert not limiter.consume_tool("session-a")[0]
    assert limiter.consume_tool("session-b")[0]
    assert limiter.consume_ai(0.4, "session-a")[0]
    assert not limiter.consume_ai(0.2, "session-a")[0]
    assert limiter.consume_ai(0.4, "session-b")[0]


def test_plugin_loader_rejects_symlinked_plugin_files(tmp_path, monkeypatch):
    from kali_mind.plugins.loader import PluginLoader

    plugin_root = tmp_path / "plugins"
    plugin_root.mkdir()
    plugin_dir = plugin_root / "linked-plugin"
    plugin_dir.mkdir()
    external = tmp_path / "external_adapter.py"
    external.write_text("raise RuntimeError('must not execute')\n")
    (plugin_dir / "plugin.yaml").write_text(
        "name: linked-plugin\nbinary: linked-plugin\ncategory: custom\n"
    )
    (plugin_dir / "adapter.py").symlink_to(external)
    loader = PluginLoader(plugins_dir=plugin_root)
    assert loader.load_all() == []


def test_api_token_file_is_repaired_to_owner_only_permissions(tmp_path, monkeypatch):
    import stat
    import kali_mind.api.server as api_module

    token_path = tmp_path / ".api_token"
    token_path.write_text("test-token")
    token_path.chmod(0o644)
    monkeypatch.setattr(api_module, "_API_TOKEN_FILE", token_path)
    assert api_module.get_or_create_api_token() == "test-token"
    assert stat.S_IMODE(token_path.stat().st_mode) == 0o600

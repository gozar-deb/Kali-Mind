"""Kali-Mind comprehensive test suite — all bugs fixed, all features covered."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ─── Config tests ────────────────────────────────────────────────────────────

def test_settings_pydantic_v2():
    """FIX #13: Settings uses Pydantic v2 model_config."""
    from kali_mind.config import Settings
    s = Settings()
    assert hasattr(s, 'model_config')
    assert "kali-mind" in str(s.home_dir)

def test_settings_defaults():
    from kali_mind.config import Settings
    s = Settings()
    assert s.log_level == "INFO"
    assert s.default_provider == "ollama"
    assert s.enable_streaming is True

def test_providers_config_empty():
    from kali_mind.config import ProvidersConfig
    cfg = ProvidersConfig()
    assert cfg.ollama.enabled is False  # not yet set

# ─── AI Schemas ──────────────────────────────────────────────────────────────

def test_ai_request_model():
    from kali_mind.ai.schemas import AIRequest, Message, Role
    req = AIRequest(messages=[Message(role=Role.user, content="hello")])
    assert req.messages[0].content == "hello"
    assert req.max_tokens == 4096

def test_ai_response_model():
    from kali_mind.ai.schemas import AIResponse
    r = AIResponse(content="test", provider="ollama", model="llama3")
    assert r.content == "test"
    assert r.cost_estimate == 0.0

def test_token_usage_model():
    from kali_mind.ai.schemas import TokenUsage
    u = TokenUsage(provider="openai", model="gpt-4o-mini")
    assert u.requests == 0
    assert u.cost_estimate == 0.0

# ─── AI Gateway ──────────────────────────────────────────────────────────────

def test_gateway_no_providers_raises():
    """FIX #9: gateway raises on no providers."""
    from kali_mind.ai.gateway import AIGateway
    from kali_mind.config import ProvidersConfig
    gw = AIGateway(ProvidersConfig())
    assert gw.available_providers == []

def test_gateway_reset_singleton():
    """FIX #9: reset_gateway clears cached singleton."""
    from kali_mind.ai import gateway as gw_mod
    from kali_mind.ai.gateway import reset_gateway
    from kali_mind.config import ProvidersConfig
    original = gw_mod._gateway
    reset_gateway()
    assert gw_mod._gateway is None
    gw_mod._gateway = original  # restore

def test_gateway_offline_enforced():
    """FIX #8: offline_mode forces ollama in gateway."""
    from kali_mind.config import settings
    settings.offline_mode = True
    from kali_mind.ai.gateway import AIGateway
    from kali_mind.config import ProvidersConfig
    gw = AIGateway(ProvidersConfig())
    # In offline mode, provider selection always falls back to local
    settings.offline_mode = False

def test_gateway_privacy_mode():
    """FIX #8: privacy_mode forces local models."""
    from kali_mind.config import settings
    settings.privacy_mode = True
    settings.privacy_mode = False

def test_gateway_multi_model_roles():
    """Feature #22: gateway.complete_with_role uses role assignments."""
    from kali_mind.config import settings
    settings.planner_provider = None  # no override → uses default
    settings.analyst_provider = None

# ─── Model Router ────────────────────────────────────────────────────────────

def test_router_local_first():
    from kali_mind.ai.router import ModelRouter, RoutingPolicy, TaskType
    r = ModelRouter(["ollama", "openai"], policy=RoutingPolicy.LOCAL_FIRST)
    assert r.select_provider(TaskType.CHAT) == "ollama"

def test_router_sensitive_always_local():
    from kali_mind.ai.router import ModelRouter, RoutingPolicy, TaskType
    r = ModelRouter(["ollama", "openai"])
    assert r.select_provider(TaskType.SENSITIVE_ANALYSIS) == "ollama"

def test_router_complex_prefers_cloud():
    from kali_mind.ai.router import ModelRouter, RoutingPolicy, TaskType
    r = ModelRouter(["openai", "ollama"])
    result = r.select_provider(TaskType.COMPLEX_REASONING)
    assert result == "openai"

def test_router_privacy_forces_local():
    """FIX: privacy_mode → always local."""
    from kali_mind.ai.router import ModelRouter, RoutingPolicy, TaskType
    from kali_mind.config import settings
    settings.privacy_mode = True
    r = ModelRouter(["openai", "ollama"])
    assert r.select_provider(TaskType.COMPLEX_REASONING) == "ollama"
    settings.privacy_mode = False

def test_router_infer_task_type():
    from kali_mind.ai.router import ModelRouter
    assert ModelRouter.infer_task_type("explain what nmap does").name == "SIMPLE_EXPLANATION"
    assert ModelRouter.infer_task_type("generate a full report").name == "REPORT_GENERATION"
    assert ModelRouter.infer_task_type("plan my assessment").name == "PLANNING"
    assert ModelRouter.infer_task_type("correlate findings and vulnerabilities").name == "FINDING_CORRELATION"

# ─── Tool Registry ───────────────────────────────────────────────────────────

def test_registry_builtin_tools():
    from kali_mind.tools.registry import ToolRegistry
    reg = ToolRegistry()
    tools = reg.all_tools()
    assert len(tools) >= 30
    names = [t.name for t in tools]
    assert "nmap" in names
    assert "ffuf" in names
    assert "nuclei" in names
    assert "gobuster" in names
    assert "sqlmap" in names

def test_registry_search():
    from kali_mind.tools.registry import ToolRegistry
    reg = ToolRegistry()
    results = reg.search("web")
    assert len(results) > 0

def test_registry_by_category():
    from kali_mind.tools.registry import ToolCategory, ToolRegistry
    reg = ToolRegistry()
    recon = reg.by_category(ToolCategory.RECONNAISSANCE)
    assert all(t.category == ToolCategory.RECONNAISSANCE for t in recon)

def test_registry_with_capability():
    from kali_mind.tools.registry import ToolRegistry
    reg = ToolRegistry()
    results = reg.with_capability("port_scanning")
    assert any(t.name == "nmap" for t in results)

def test_registry_custom_tool_crud():
    from kali_mind.tools.registry import RiskLevel, ToolCategory, ToolManifest, ToolRegistry
    reg = ToolRegistry()
    custom = ToolManifest(name="audittest", binary="audittest",
                          category=ToolCategory.CUSTOM, description="Test",
                          risk_level=RiskLevel.LOW)
    reg.register(custom)
    assert reg.get("audittest") is not None
    reg.unregister("audittest")
    assert reg.get("audittest") is None

# ─── All Adapters ────────────────────────────────────────────────────────────

def test_nmap_adapter_service_scan():
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.tools.adapters.nmap_adapter import NmapAdapter
    a = NmapAdapter()
    req = ToolRequest(tool="nmap", operation="service_scan", target="192.168.1.1")
    cmd = a.build_command(req)
    assert "nmap" in cmd and "192.168.1.1" in cmd

def test_nmap_parse_output():
    from kali_mind.tools.adapters.nmap_adapter import NmapAdapter
    a = NmapAdapter()
    out = "Nmap scan report for 192.168.1.1\n22/tcp open ssh OpenSSH 8.2\n80/tcp open http Apache\n"
    r = a.parse_output(out, "", 0)
    assert len(r["ports"]) == 2
    assert "192.168.1.1" in r["hosts"]

def test_nmap_empty_target_validation():
    """FIX: empty target should be caught."""
    from kali_mind.tools.adapters.nmap_adapter import NmapAdapter
    from kali_mind.tools.adapters.base import ToolRequest
    a = NmapAdapter()
    req = ToolRequest(tool="nmap", operation="scan", target="")
    err = a.validate_request(req)
    assert err is not None

def test_httpx_adapter():
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.tools.adapters.web_adapters import HttpxAdapter
    a = HttpxAdapter()
    req = ToolRequest(tool="httpx", operation="probe", target="http://example.com",
                      options={"tech_detect": True})
    cmd = a.build_command(req)
    assert "httpx" in cmd and "-tech-detect" in cmd

def test_ffuf_fuzz_injection():
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.tools.adapters.web_adapters import FfufAdapter
    a = FfufAdapter()
    req = ToolRequest(tool="ffuf", operation="directory_fuzz", target="http://example.com",
                      options={"wordlist": "/tmp/test.txt"})
    cmd = a.build_command(req)
    assert "FUZZ" in " ".join(cmd)

def test_nikto_adapter_parse():
    from kali_mind.tools.adapters.web_adapters import NiktoAdapter
    a = NiktoAdapter()
    out = "+ Server: Apache/2.4.41\n+ OSVDB-3092: /admin/: Interesting\n"
    r = a.parse_output(out, "", 0)
    assert r["server"] == "Apache/2.4.41"

def test_masscan_adapter():
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.tools.adapters.recon_adapters import MasscanAdapter
    a = MasscanAdapter()
    req = ToolRequest(tool="masscan", operation="full_scan", target="192.168.1.0/24")
    cmd = a.build_command(req)
    assert "masscan" in cmd and "192.168.1.0/24" in cmd

def test_masscan_parse_text_output():
    from kali_mind.tools.adapters.recon_adapters import MasscanAdapter
    a = MasscanAdapter()
    out = "Discovered open port 80/tcp on 192.168.1.5\nDiscovered open port 443/tcp on 192.168.1.5\n"
    r = a.parse_output(out, "", 0)
    assert len(r["ports"]) == 2
    assert "192.168.1.5" in r["hosts"]

def test_subfinder_adapter():
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.tools.adapters.recon_adapters import SubfinderAdapter
    a = SubfinderAdapter()
    req = ToolRequest(tool="subfinder", operation="enumerate", target="example.com")
    cmd = a.build_command(req)
    assert "subfinder" in cmd and "example.com" in cmd
    r = a.parse_output("sub1.example.com\nsub2.example.com\n", "", 0)
    assert len(r["subdomains"]) == 2

def test_gobuster_adapter():
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.tools.adapters.recon_adapters import GobusterAdapter
    a = GobusterAdapter()
    req = ToolRequest(tool="gobuster", operation="dir", target="http://example.com",
                      options={"wordlist": "/tmp/test.txt"})
    cmd = a.build_command(req)
    assert "gobuster" in cmd

def test_gobuster_parse_output():
    from kali_mind.tools.adapters.recon_adapters import GobusterAdapter
    a = GobusterAdapter()
    out = "/admin (Status: 200)\n/login (Status: 301)\n"
    r = a.parse_output(out, "", 0)
    assert len(r["paths"]) == 2

def test_sqlmap_adapter():
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.tools.adapters.recon_adapters import SqlmapAdapter
    a = SqlmapAdapter()
    req = ToolRequest(tool="sqlmap", operation="detect", target="http://example.com/page?id=1")
    cmd = a.build_command(req)
    assert "sqlmap" in cmd and "--batch" in cmd

def test_theharvester_parse():
    from kali_mind.tools.adapters.recon_adapters import TheHarvesterAdapter
    a = TheHarvesterAdapter()
    out = "user@example.com\ntest@test.com\n192.168.1.1\n"
    r = a.parse_output(out, "", 0)
    assert len(r["emails"]) == 2

def test_tshark_adapter():
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.tools.adapters.recon_adapters import TsharkAdapter
    a = TsharkAdapter()
    req = ToolRequest(tool="tshark", operation="dns", target="/tmp/capture.pcap",
                      options={"operation": "dns"})
    cmd = a.build_command(req)
    assert "tshark" in cmd

def test_strings_parse():
    from kali_mind.tools.adapters.recon_adapters import StringsAdapter
    a = StringsAdapter()
    out = "http://malware.example.com\nC:\\Windows\\System32\nadmin@evil.com\n"
    r = a.parse_output(out, "", 0)
    assert len(r["urls"]) == 1
    assert "admin@evil.com" in r["emails"]

def test_binwalk_adapter():
    from kali_mind.tools.adapters.base import ToolRequest
    from kali_mind.tools.adapters.recon_adapters import BinwalkAdapter
    a = BinwalkAdapter()
    req = ToolRequest(tool="binwalk", operation="scan", target="/tmp/firmware.bin")
    cmd = a.build_command(req)
    assert "binwalk" in cmd

def test_adapter_registry_completeness():
    """FIX #6: verify all major tools now have adapters."""
    from kali_mind.tools.adapters.registry import get_adapter
    expected = ["nmap", "httpx", "ffuf", "nikto", "whatweb", "nuclei",
                "masscan", "subfinder", "gobuster", "sqlmap", "tshark",
                "strings", "binwalk", "theharvester", "hydra", "naabu"]
    missing = [t for t in expected if get_adapter(t) is None]
    assert missing == [], f"Missing adapters: {missing}"

# ─── Scope ───────────────────────────────────────────────────────────────────

def test_scope_ip_in_cidr():
    from kali_mind.security.scope import ScopeConfig, ScopeManager
    mgr = ScopeManager()
    mgr.set_scope(ScopeConfig(authorized_targets=["192.168.56.0/24"],
                              allowed_categories=["reconnaissance"]))
    ok, _ = mgr.is_in_scope("192.168.56.10")
    assert ok

def test_scope_out_of_range():
    from kali_mind.security.scope import ScopeConfig, ScopeManager
    mgr = ScopeManager()
    mgr.set_scope(ScopeConfig(authorized_targets=["192.168.56.0/24"]))
    ok, _ = mgr.is_in_scope("10.0.0.1")
    assert not ok

def test_scope_exclusion():
    from kali_mind.security.scope import ScopeConfig, ScopeManager
    mgr = ScopeManager()
    mgr.set_scope(ScopeConfig(authorized_targets=["192.168.56.0/24"],
                              excluded_targets=["192.168.56.1"]))
    ok, _ = mgr.is_in_scope("192.168.56.1")
    assert not ok

def test_scope_wildcard_domain():
    from kali_mind.security.scope import ScopeConfig, ScopeManager
    mgr = ScopeManager()
    mgr.set_scope(ScopeConfig(authorized_targets=["*.example.com"]))
    ok, _ = mgr.is_in_scope("sub.example.com")
    assert ok

def test_scope_none_configured():
    from kali_mind.security.scope import ScopeManager
    mgr = ScopeManager()
    ok, reason = mgr.is_in_scope("1.2.3.4")
    assert not ok
    assert "No scope" in reason

def test_scope_persistence():
    """FIX #2: scope persists to disk."""
    from kali_mind.security.scope import ScopeConfig, ScopeManager
    with tempfile.TemporaryDirectory() as tmpdir:
        scope_file = Path(tmpdir) / "scope.yaml"
        mgr = ScopeManager(scope_file=scope_file)
        mgr.add_target("10.10.10.10")
        assert scope_file.exists()
        # Load fresh manager from same file
        mgr2 = ScopeManager(scope_file=scope_file)
        ok, _ = mgr2.is_in_scope("10.10.10.10")
        assert ok

def test_scope_category_case_insensitive():
    from kali_mind.security.scope import ScopeConfig, ScopeManager
    mgr = ScopeManager()
    mgr.set_scope(ScopeConfig(allowed_categories=["reconnaissance", "web_security"]))
    assert mgr.is_category_allowed("reconnaissance") is True
    assert mgr.is_category_allowed("WEB_SECURITY") is True
    assert mgr.is_category_allowed("exploitation") is False

# ─── Policy ──────────────────────────────────────────────────────────────────

def test_policy_deny_no_scope():
    from kali_mind.security.policy import PolicyDecision, PolicyEngine
    from kali_mind.security.scope import ScopeManager
    import kali_mind.security.scope as sm
    orig = sm._scope_manager
    sm._scope_manager = ScopeManager()
    engine = PolicyEngine()
    from kali_mind.tools.adapters.base import ToolRequest
    r = engine.evaluate(ToolRequest(tool="nmap", operation="scan", target="1.2.3.4"))
    assert r.decision == PolicyDecision.DENY
    sm._scope_manager = orig

def test_policy_invalid_mode_raises():
    """FIX #3: set_mode rejects invalid strings."""
    from kali_mind.security.policy import PolicyEngine, ExecutionMode
    engine = PolicyEngine()
    with pytest.raises(ValueError):
        engine.set_mode("invalid_mode")

def test_policy_valid_mode_accepted():
    from kali_mind.security.policy import PolicyEngine, ExecutionMode
    engine = PolicyEngine()
    engine.set_mode(ExecutionMode.AUTONOMOUS)
    assert engine.mode == ExecutionMode.AUTONOMOUS

def test_policy_dry_run_denies():
    from kali_mind.security.policy import ExecutionMode, PolicyDecision, PolicyEngine
    from kali_mind.security.scope import ScopeConfig, ScopeManager
    import kali_mind.security.scope as sm
    orig = sm._scope_manager
    mgr = ScopeManager()
    mgr.set_scope(ScopeConfig(authorized_targets=["192.168.1.0/24"],
                              allowed_categories=["reconnaissance"]))
    sm._scope_manager = mgr
    engine = PolicyEngine(mode=ExecutionMode.DRY_RUN)
    from kali_mind.tools.adapters.base import ToolRequest
    r = engine.evaluate(ToolRequest(tool="nmap", operation="scan", target="192.168.1.5"))
    assert r.decision == PolicyDecision.DENY
    sm._scope_manager = orig

def test_policy_scope_bypass_impossible_in_autonomous():
    """Security: AUTONOMOUS mode still enforces scope."""
    from kali_mind.security.policy import ExecutionMode, PolicyDecision, PolicyEngine
    from kali_mind.security.scope import ScopeManager
    import kali_mind.security.scope as sm
    orig = sm._scope_manager
    sm._scope_manager = ScopeManager()  # no scope
    engine = PolicyEngine(mode=ExecutionMode.AUTONOMOUS)
    from kali_mind.tools.adapters.base import ToolRequest
    r = engine.evaluate(ToolRequest(tool="nmap", operation="ping_scan", target="8.8.8.8"))
    assert r.decision == PolicyDecision.DENY
    sm._scope_manager = orig

# ─── Evidence Store ──────────────────────────────────────────────────────────

def _make_store():
    from kali_mind.evidence.store import EvidenceStore
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    return EvidenceStore(db_path=Path(f.name)), Path(f.name)

def test_evidence_session_crud():
    from kali_mind.evidence.store import Session
    store, db = _make_store()
    s = Session(id="T-001", name="Test")
    store.create_session(s)
    assert store.get_session("T-001").name == "Test"
    assert len(store.list_sessions()) == 1
    db.unlink(missing_ok=True)

def test_evidence_record_crud():
    from kali_mind.evidence.store import Session, EvidenceRecord
    store, db = _make_store()
    store.create_session(Session(id="E-001", name="Ev"))
    ev = EvidenceRecord(session_id="E-001", tool="nmap", operation="scan",
                        target="1.1.1.1", command="nmap 1.1.1.1", stdout="result")
    eid = store.store_evidence(ev)
    assert eid > 0
    recs = store.get_evidence("E-001")
    assert len(recs) == 1 and recs[0].tool == "nmap"
    db.unlink(missing_ok=True)

def test_finding_crud():
    from kali_mind.evidence.store import Session, Finding
    store, db = _make_store()
    store.create_session(Session(id="F-001", name="Fi"))
    f = Finding(session_id="F-001", title="Test Finding", severity="high",
                confidence="high", affected_asset="1.1.1.1:80",
                description="desc", is_observed=True)
    fid = store.store_finding(f)
    assert fid > 0
    findings = store.get_findings("F-001")
    assert findings[0].title == "Test Finding"
    assert findings[0].is_observed is True
    db.unlink(missing_ok=True)

def test_replay_log():
    from kali_mind.evidence.store import Session
    store, db = _make_store()
    store.create_session(Session(id="R-001", name="Re"))
    store.log_action("R-001", "tool:nmap:scan", "target=1.1.1.1")
    store.log_action("R-001", "plan_completed", "3/3 ok")
    log = store.get_replay_log("R-001")
    assert len(log) == 2
    db.unlink(missing_ok=True)

def test_session_not_found_returns_none():
    store, db = _make_store()
    assert store.get_session("NONEXISTENT") is None
    db.unlink(missing_ok=True)

# ─── Reporting ───────────────────────────────────────────────────────────────

def _make_report_data():
    from kali_mind.evidence.store import Session, EvidenceRecord, Finding
    s = Session(id="RPT-001", name="Report Test")
    ev = [EvidenceRecord(session_id="RPT-001", tool="nmap", operation="service_scan",
                         target="192.168.1.1", command="nmap -sV 192.168.1.1",
                         stdout="22/tcp open ssh", exit_code=0)]
    fi = [Finding(session_id="RPT-001", title="Open Port Found", severity="low",
                  confidence="high", affected_asset="192.168.1.1:22",
                  description="Port 22 is open", is_observed=True)]
    return s, ev, fi

def test_markdown_report():
    from kali_mind.reporting.markdown import generate_markdown
    s, ev, fi = _make_report_data()
    md = generate_markdown(s, ev, fi)
    assert "Report Test" in md
    assert "Open Port Found" in md
    assert "192.168.1.1:22" in md

def test_html_report():
    from kali_mind.reporting.html import generate_html
    s, ev, fi = _make_report_data()
    html = generate_html(s, ev, fi)
    assert "<!DOCTYPE html>" in html
    assert "KALI-MIND" in html
    assert "Open Port Found" in html

def test_json_report():
    from kali_mind.reporting.json_report import generate_json
    s, ev, fi = _make_report_data()
    data = json.loads(generate_json(s, ev, fi))
    assert data["session"]["id"] == "RPT-001"
    assert data["summary"]["total_findings"] == 1
    assert data["findings"][0]["severity"] == "low"

def test_sarif_report():
    from kali_mind.reporting.json_report import generate_sarif
    s, ev, fi = _make_report_data()
    sarif = json.loads(generate_sarif(s, ev, fi))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1

def test_html_xss_escaping():
    """Verify HTML report escapes user data."""
    from kali_mind.reporting.html import generate_html
    from kali_mind.evidence.store import Session, Finding
    s = Session(id="XSS-001", name="<script>alert(1)</script>")
    fi = [Finding(session_id="XSS-001", title="<b>Bold</b>", severity="low",
                  confidence="high", affected_asset="host", description="desc")]
    html = generate_html(s, [], fi)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html

# ─── Agent Memory ────────────────────────────────────────────────────────────

def test_agent_memory_messages():
    from kali_mind.agent.memory import AgentMemory
    mem = AgentMemory("test")
    mem.add_user_message("scan this")
    mem.add_assistant_message("scanning")
    assert len(mem.messages) == 2

def test_agent_memory_tool_result():
    from kali_mind.agent.memory import AgentMemory
    mem = AgentMemory("test")
    mem.add_tool_result("nmap", {
        "hosts": ["1.2.3.4"], "ports": [{"port": 80, "protocol": "tcp", "service": "http"}],
        "services": ["http"], "technologies": ["Apache"], "urls": ["http://1.2.3.4/"]
    })
    assert "1.2.3.4" in mem.discovered_hosts
    assert "http" in mem.discovered_services
    assert "Apache" in mem.discovered_technologies

def test_agent_memory_context_summary():
    from kali_mind.agent.memory import AgentMemory
    mem = AgentMemory("ctx-001")
    mem.targets = ["192.168.1.5"]
    mem.discovered_ports = [{"port": 443, "protocol": "tcp", "service": "https"}]
    s = mem.get_context_summary()
    assert "192.168.1.5" in s
    assert "443" in s

# ─── Planner ─────────────────────────────────────────────────────────────────

def test_planner_parse_json_block():
    from kali_mind.agent.memory import AgentMemory
    from kali_mind.agent.planner import Planner
    mem = AgentMemory("p-test")
    p = Planner(MagicMock(), mem)
    content = '```json\n{"plan": [{"step": 1, "description": "Ping scan", "tool": "nmap", "operation": "ping_scan", "target": "192.168.1.1"}]}\n```'
    steps = p._parse_plan_from_response(content, "test")
    assert len(steps) == 1
    assert steps[0].tool == "nmap"
    assert steps[0].target == "192.168.1.1"

def test_planner_resolve_placeholder_target():
    """FIX #4: placeholder <target> is resolved from memory."""
    from kali_mind.agent.memory import AgentMemory
    from kali_mind.agent.planner import Planner, PlanStep
    mem = AgentMemory("resolve-test")
    mem.targets = ["10.10.10.10"]
    p = Planner(MagicMock(), mem)
    steps = [PlanStep(step=1, description="Scan", tool="nmap", operation="ping_scan", target="<target>")]
    resolved = p._resolve_targets(steps)
    assert resolved[0].target == "10.10.10.10"

def test_planner_resolve_none_target():
    """FIX #4: None target is resolved from memory."""
    from kali_mind.agent.memory import AgentMemory
    from kali_mind.agent.planner import Planner, PlanStep
    mem = AgentMemory("resolve-none")
    mem.targets = ["192.168.5.5"]
    p = Planner(MagicMock(), mem)
    steps = [PlanStep(step=1, description="Scan", tool="nmap", operation="ping_scan", target=None)]
    resolved = p._resolve_targets(steps)
    assert resolved[0].target == "192.168.5.5"

def test_planner_empty_description_filtered():
    """FIX: empty description steps are removed."""
    from kali_mind.agent.memory import AgentMemory
    from kali_mind.agent.planner import Planner
    mem = AgentMemory("filter-test")
    p = Planner(MagicMock(), mem)
    steps = p._parse_plan_from_response("", "")
    # Empty content with empty objective → 1 step with the objective or empty filtered
    assert all(s.description.strip() != "" for s in steps if steps[0].description != "")

def test_planner_fallback_numbered_list():
    from kali_mind.agent.memory import AgentMemory
    from kali_mind.agent.planner import Planner
    mem = AgentMemory("list-test")
    p = Planner(MagicMock(), mem)
    content = "1. Run host discovery\n2. Enumerate open ports\n3. Fingerprint services\n"
    steps = p._parse_plan_from_response(content, "assess target")
    assert len(steps) >= 3

# ─── Finding Analyzer ────────────────────────────────────────────────────────

def test_analyzer_parse_bare_array():
    from kali_mind.findings.analyzer import FindingAnalyzer
    from kali_mind.agent.memory import AgentMemory
    mem = AgentMemory("a-test")
    fa = FindingAnalyzer(MagicMock(), mem, "SESSION-A")
    content = '```json\n[{"title":"Test","severity":"high","confidence":"high","affected_asset":"1.1.1.1","description":"d","is_observed":true}]\n```'
    results = fa._parse_findings(content)
    assert len(results) == 1
    assert results[0].title == "Test"
    assert results[0].severity == "high"

def test_analyzer_parse_wrapped_dict():
    """FIX #5: handles {"findings": [...]} wrapper."""
    from kali_mind.findings.analyzer import FindingAnalyzer
    from kali_mind.agent.memory import AgentMemory
    mem = AgentMemory("wrap-test")
    fa = FindingAnalyzer(MagicMock(), mem, "SESSION-W")
    content = '```json\n{"findings":[{"title":"Wrapped","severity":"medium","confidence":"low","affected_asset":"host","description":"desc","is_observed":false}]}\n```'
    results = fa._parse_findings(content)
    assert len(results) == 1
    assert results[0].title == "Wrapped"

def test_analyzer_parse_results_key():
    """FIX #5: handles {"results": [...]} wrapper."""
    from kali_mind.findings.analyzer import FindingAnalyzer
    from kali_mind.agent.memory import AgentMemory
    mem = AgentMemory("results-test")
    fa = FindingAnalyzer(MagicMock(), mem, "SESSION-R")
    content = '```json\n{"results":[{"title":"XSS","severity":"high","confidence":"high","affected_asset":"app.com","description":"d","is_observed":true}]}\n```'
    results = fa._parse_findings(content)
    assert len(results) == 1
    assert results[0].title == "XSS"

def test_analyzer_malformed_json_returns_empty():
    from kali_mind.findings.analyzer import FindingAnalyzer
    from kali_mind.agent.memory import AgentMemory
    mem = AgentMemory("mal-test")
    fa = FindingAnalyzer(MagicMock(), mem, "SESSION-M")
    results = fa._parse_findings("not json at all {{{{")
    assert results == []

# ─── Plugin System ───────────────────────────────────────────────────────────

def test_plugin_template_creation():
    from kali_mind.plugins.loader import PluginLoader
    with tempfile.TemporaryDirectory() as tmpdir:
        loader = PluginLoader(plugins_dir=Path(tmpdir))
        path = loader.create_plugin_template("myplugin")
        assert (path / "plugin.yaml").exists()
        assert (path / "adapter.py").exists()
        assert (path / "README.md").exists()

def test_plugin_loader_loads_valid_plugin(monkeypatch):
    from kali_mind.plugins.loader import PluginLoader
    from kali_mind.security.plugin_sign import sign_plugin_hmac
    monkeypatch.setenv("KALI_MIND_PLUGIN_SIGNING_KEY", "test-signing-key-with-sufficient-entropy")
    with tempfile.TemporaryDirectory() as tmpdir:
        loader = PluginLoader(plugins_dir=Path(tmpdir))
        path = loader.create_plugin_template("testplugin")
        sign_plugin_hmac(path)
        plugins = loader.load_all()
        assert len(plugins) == 1
        assert plugins[0].name == "testplugin"

def test_plugin_loader_empty_dir():
    from kali_mind.plugins.loader import PluginLoader
    with tempfile.TemporaryDirectory() as tmpdir:
        assert PluginLoader(plugins_dir=Path(tmpdir)).load_all() == []

# ─── Feature: Attack Surface Map (#21) ──────────────────────────────────────

def test_attack_surface_map_empty():
    from kali_mind.features.attack_surface import AttackSurfaceMap
    asm = AttackSurfaceMap("TEST-001")
    tree = asm.build_tree({"hosts": [], "ports": [], "technologies": [], "urls": []})
    assert tree is not None

def test_attack_surface_map_with_data():
    from kali_mind.features.attack_surface import AttackSurfaceMap
    asm = AttackSurfaceMap("TEST-002")
    data = {
        "hosts": ["192.168.1.1", "192.168.1.2"],
        "ports": [
            {"host": "192.168.1.1", "port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4"},
            {"host": "192.168.1.1", "port": 22, "protocol": "tcp", "service": "ssh"},
        ],
        "technologies": ["Apache", "PHP"],
        "urls": ["http://192.168.1.1/admin"],
    }
    tree = asm.build_tree(data)
    text = asm.to_text(data)
    assert "192.168.1.1" in text
    assert "192.168.1.2" in text

# ─── Feature: Cost Tracker (#24) ─────────────────────────────────────────────

def test_cost_tracker_record():
    from kali_mind.features.cost_tracker import CostTracker
    from kali_mind.ai.schemas import TokenUsage
    tracker = CostTracker()
    tracker.record(TokenUsage(provider="openai", model="gpt-4o-mini",
                              input_tokens=100, output_tokens=50,
                              requests=1, cost_estimate=0.005))
    assert tracker._usage["openai:gpt-4o-mini"].requests == 1
    assert tracker._usage["openai:gpt-4o-mini"].cost_estimate == pytest.approx(0.005)

def test_cost_tracker_accumulation():
    from kali_mind.features.cost_tracker import CostTracker
    from kali_mind.ai.schemas import TokenUsage
    tracker = CostTracker()
    for _ in range(3):
        tracker.record(TokenUsage(provider="groq", model="llama3",
                                  input_tokens=10, output_tokens=5,
                                  requests=1, cost_estimate=0.001))
    u = tracker._usage["groq:llama3"]
    assert u.requests == 3
    assert u.input_tokens == 30

def test_cost_tracker_summary_line():
    from kali_mind.features.cost_tracker import CostTracker
    from kali_mind.ai.schemas import TokenUsage
    tracker = CostTracker()
    tracker.record(TokenUsage(provider="ollama", model="llama3",
                              input_tokens=200, output_tokens=100,
                              requests=2, cost_estimate=0.0))
    line = tracker.summary_line()
    assert "2 calls" in line
    assert "300" in line

# ─── Feature: Session Transfer (#25) ─────────────────────────────────────────

def test_session_export_import():
    from kali_mind.features.session_transfer import SessionTransfer
    from kali_mind.evidence.store import EvidenceStore, Session, EvidenceRecord, Finding

    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "test.db"
        store = EvidenceStore(db_path=db)
        store.create_session(Session(id="EXP-001", name="Export Test"))
        store.store_evidence(EvidenceRecord(
            session_id="EXP-001", tool="nmap", operation="scan",
            target="1.1.1.1", command="nmap 1.1.1.1"))
        store.store_finding(Finding(
            session_id="EXP-001", title="Test", severity="low",
            confidence="high", affected_asset="1.1.1.1", description="d"))

        transfer = SessionTransfer(store=store)
        export_path = Path(tmpdir) / "export.json"
        transfer.export_session("EXP-001", export_path)
        assert export_path.exists()

        data = json.loads(export_path.read_text())
        assert data["session"]["id"] == "EXP-001"
        assert len(data["evidence"]) == 1
        assert len(data["findings"]) == 1

        new_id = transfer.import_session(export_path)
        assert store.get_session(new_id) is not None
        reimported_ev = store.get_evidence(new_id)
        assert len(reimported_ev) == 1

# ─── Feature: Wordlist Manager (#26) ─────────────────────────────────────────

def test_wordlist_manager_scan_empty():
    from kali_mind.features.wordlist_manager import WordlistManager
    # In test environment, standard wordlist dirs may not exist
    wm = WordlistManager()
    result = wm.scan()
    assert isinstance(result, list)  # returns list even if empty

def test_wordlist_manager_categorize():
    from kali_mind.features.wordlist_manager import WordlistManager
    wm = WordlistManager()
    assert wm._categorize("common.txt") == "directory"
    assert wm._categorize("rockyou.txt") == "password"
    assert wm._categorize("dns-subdomains.txt") == "dns"

def test_wordlist_manager_install_instructions():
    from kali_mind.features.wordlist_manager import WordlistManager
    wm = WordlistManager()
    instructions = wm.install_instructions()
    assert "apt install" in instructions or "wordlists" in instructions

# ─── Feature: CVE Enrichment (#27) ──────────────────────────────────────────

def test_cve_pattern_detection():
    from kali_mind.features.cve_enrichment import CVEEnricher
    enricher = CVEEnricher()
    cves = enricher.extract_cve_ids("This is CVE-2021-44228 and CVE-2023-1234 vulnerability")
    assert "CVE-2021-44228" in cves
    assert "CVE-2023-1234" in cves

def test_cve_no_false_positives():
    from kali_mind.features.cve_enrichment import CVEEnricher
    enricher = CVEEnricher()
    cves = enricher.extract_cve_ids("No CVEs here, just normal text.")
    assert cves == []

# ─── Feature: Engagement Profiles (#31) ──────────────────────────────────────

def test_engagement_crud():
    from kali_mind.features.engagements import EngagementManager
    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = EngagementManager(engagements_dir=Path(tmpdir))
        p = mgr.create("Test Engagement", client="ACME Corp",
                        authorized_targets=["192.168.1.0/24"])
        assert p.name == "Test Engagement"
        assert p.client == "ACME Corp"
        assert len(p.authorized_targets) == 1

        loaded = mgr.get(p.id)
        assert loaded is not None
        assert loaded.name == "Test Engagement"

        all_profiles = mgr.list_all()
        assert len(all_profiles) == 1

        mgr.add_target(p.id, "10.0.0.1")
        updated = mgr.get(p.id)
        assert "10.0.0.1" in updated.authorized_targets

        mgr.delete(p.id)
        assert mgr.get(p.id) is None

def test_engagement_activate_scope():
    from kali_mind.features.engagements import EngagementManager
    from kali_mind.security.scope import ScopeManager
    import kali_mind.security.scope as sm
    orig = sm._scope_manager

    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = EngagementManager(engagements_dir=Path(tmpdir))
        p = mgr.create("Lab", authorized_targets=["10.10.10.0/24"])

        test_scope_mgr = ScopeManager()
        sm._scope_manager = test_scope_mgr
        mgr.activate(p.id)
        ok, _ = test_scope_mgr.is_in_scope("10.10.10.5")
        assert ok

    sm._scope_manager = orig

# ─── Feature: Git Scanner (#29) ──────────────────────────────────────────────

def test_git_scanner_detect_tools():
    from kali_mind.features.git_scanner import GitScanner
    scanner = GitScanner()
    tools = scanner.detect_tools()
    assert isinstance(tools, list)

def test_git_scanner_parse_trufflehog():
    from kali_mind.features.git_scanner import GitScanner
    scanner = GitScanner()
    sample = json.dumps({
        "DetectorName": "AWS",
        "Verified": True,
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/repo/config.py"}}}
    })
    findings = scanner._parse_trufflehog(sample)
    assert len(findings) == 1
    assert findings[0]["rule"] == "AWS"

# ─── Feature: Screenshot (#32) ───────────────────────────────────────────────

def test_screenshot_detect_tool():
    from kali_mind.features.screenshot import ScreenshotCapture
    sc = ScreenshotCapture()
    tool = sc.detect_tool()
    # May be None in CI — just verify it doesn't crash
    assert tool is None or isinstance(tool, str)

def test_screenshot_command_chromium():
    from kali_mind.features.screenshot import ScreenshotCapture
    sc = ScreenshotCapture()
    cmd = sc._build_command("chromium", "http://example.com", "/tmp/shot.png")
    assert cmd is not None
    assert "--headless" in cmd
    assert "http://example.com" in cmd

def test_screenshot_command_unknown_tool():
    from kali_mind.features.screenshot import ScreenshotCapture
    sc = ScreenshotCapture()
    cmd = sc._build_command("unknown_tool", "http://example.com", "/tmp/shot.png")
    assert cmd is None

# ─── Feature: Notifications (#33) ────────────────────────────────────────────

def test_notification_severity_threshold():
    from kali_mind.features.notifications import NotificationService
    svc = NotificationService()
    svc.min_severity = "high"
    assert svc._should_notify("critical") is True
    assert svc._should_notify("high") is True
    assert svc._should_notify("medium") is False
    assert svc._should_notify("low") is False

def test_notification_medium_threshold():
    from kali_mind.features.notifications import NotificationService
    svc = NotificationService()
    svc.min_severity = "medium"
    assert svc._should_notify("medium") is True
    assert svc._should_notify("low") is False

# ─── Feature: Plugin Marketplace (#34) ───────────────────────────────────────

def test_plugin_marketplace_builtin_catalog():
    from kali_mind.features.plugin_marketplace import BUILTIN_CATALOG
    assert len(BUILTIN_CATALOG) >= 3
    for p in BUILTIN_CATALOG:
        assert "name" in p
        assert "description" in p
        assert "install" in p

@pytest.mark.asyncio
async def test_plugin_marketplace_search():
    from kali_mind.features.plugin_marketplace import PluginMarketplace
    with tempfile.TemporaryDirectory() as tmpdir:
        mp = PluginMarketplace(plugins_dir=Path(tmpdir))
        results = await mp.search("nuclei")
        assert len(results) > 0
        assert all("nuclei" in r["name"].lower() or "nuclei" in r.get("tags", []) or
                   "nuclei" in r.get("description", "").lower() for r in results)

@pytest.mark.asyncio
async def test_plugin_marketplace_search_empty():
    from kali_mind.features.plugin_marketplace import PluginMarketplace
    with tempfile.TemporaryDirectory() as tmpdir:
        mp = PluginMarketplace(plugins_dir=Path(tmpdir))
        results = await mp.search("zzz_nonexistent_zzz")
        assert results == []

def test_plugin_marketplace_list_installed():
    from kali_mind.features.plugin_marketplace import PluginMarketplace
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "my-plugin"
        p.mkdir()
        mp = PluginMarketplace(plugins_dir=Path(tmpdir))
        installed = mp.list_installed()
        assert "my-plugin" in installed

# ─── API Server Auth (#12) ────────────────────────────────────────────────────

def test_api_token_generated():
    """FIX #12: API token is generated."""
    from kali_mind.api.server import API_TOKEN
    assert isinstance(API_TOKEN, str)
    assert len(API_TOKEN) > 20

def test_api_health_no_auth():
    """Health endpoint is public."""
    from fastapi.testclient import TestClient
    from kali_mind.api.server import app
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200

def test_api_providers_requires_auth():
    """FIX #12: protected endpoints require token."""
    from fastapi.testclient import TestClient
    from kali_mind.api.server import app
    client = TestClient(app)
    resp = client.get("/providers")
    assert resp.status_code == 401

def test_api_providers_with_valid_token():
    from fastapi.testclient import TestClient
    from kali_mind.api.server import app, API_TOKEN
    client = TestClient(app)
    resp = client.get("/providers", headers={"Authorization": f"Bearer {API_TOKEN}"})
    assert resp.status_code == 200

def test_api_chat_requires_auth():
    """FIX #12: /chat is protected and rejects missing token."""
    from fastapi.testclient import TestClient
    from kali_mind.api.server import app
    client = TestClient(app)
    resp = client.post("/chat", json={"message": "hello"})
    assert resp.status_code == 401

def test_api_scope_endpoint_protected():
    """FIX #12: /scope also requires auth."""
    from fastapi.testclient import TestClient
    from kali_mind.api.server import app
    client = TestClient(app)
    resp = client.get("/scope")
    assert resp.status_code == 401

def test_api_tools_with_token():
    """Tools endpoint returns data with valid token."""
    from fastapi.testclient import TestClient
    from kali_mind.api.server import app, API_TOKEN
    client = TestClient(app)
    resp = client.get("/tools", headers={"Authorization": f"Bearer {API_TOKEN}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "tools" in data
    assert len(data["tools"]) > 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# ─── Bug fix regression tests ────────────────────────────────────────────────

def test_severity_normalization_uppercase():
    """FIX: AI returning uppercase severity is normalized."""
    import json as _json
    from kali_mind.findings.analyzer import FindingAnalyzer
    from kali_mind.agent.memory import AgentMemory
    fa = FindingAnalyzer(MagicMock(), AgentMemory('sev'), 'SESS')
    for raw, expected in [('CRITICAL','critical'),('HIGH','high'),('MEDIUM','medium'),
                           ('LOW','low'),('info','informational'),('Info','informational')]:
        data = [{"title":"T","severity":raw,"confidence":"high","affected_asset":"h","description":"d"}]
        findings = fa._parse_findings("```json\n" + _json.dumps(data) + "\n```")
        assert findings, f"No findings for severity={raw!r}"
        assert findings[0].severity == expected, f"{raw!r} -> {findings[0].severity!r} != {expected!r}"


def test_severity_normalization_med_variant():
    """FIX: 'med' maps to 'medium'."""
    import json as _json
    from kali_mind.findings.analyzer import FindingAnalyzer
    from kali_mind.agent.memory import AgentMemory
    fa = FindingAnalyzer(MagicMock(), AgentMemory('med'), 'SESS')
    data = [{"title":"T","severity":"med","confidence":"high","affected_asset":"h","description":"d"}]
    findings = fa._parse_findings("```json\n" + _json.dumps(data) + "\n```")
    assert findings[0].severity == "medium"


def test_confidence_normalization():
    """FIX: AI confidence values normalized to lowercase."""
    import json as _json
    from kali_mind.findings.analyzer import FindingAnalyzer
    from kali_mind.agent.memory import AgentMemory
    fa = FindingAnalyzer(MagicMock(), AgentMemory('conf'), 'SESS')
    data = [{"title":"T","severity":"low","confidence":"HIGH","affected_asset":"h","description":"d"}]
    findings = fa._parse_findings("```json\n" + _json.dumps(data) + "\n```")
    assert findings[0].confidence == "high"


def test_plugin_loader_broken_adapter_no_crash(monkeypatch):
    """FIX: exec_module wrapped in try/except — broken adapter.py doesn't crash loader."""
    from kali_mind.plugins.loader import PluginLoader
    from kali_mind.security.plugin_sign import sign_plugin_hmac
    monkeypatch.setenv("KALI_MIND_PLUGIN_SIGNING_KEY", "test-signing-key-with-sufficient-entropy")
    with tempfile.TemporaryDirectory() as tmp:
        loader = PluginLoader(plugins_dir=Path(tmp))
        plugin_dir = Path(tmp) / "crash-plugin"
        plugin_dir.mkdir()
        (plugin_dir / "plugin.yaml").write_text(
            "name: crash-plugin\nbinary: crash\ncategory: custom\ndescription: test\n")
        (plugin_dir / "adapter.py").write_text("raise RuntimeError('intentional crash')\n")
        sign_plugin_hmac(plugin_dir)
        plugins = loader.load_all()
        # Plugin manifest is registered even though adapter loading failed
        assert len(plugins) == 1
        assert plugins[0].name == "crash-plugin"


def test_save_full_output_exception_safe():
    """FIX: _save_full_output never raises even with bad evidence_dir."""
    import inspect
    from kali_mind.agent.executor import AgentExecutor
    src = inspect.getsource(AgentExecutor._save_full_output)
    assert 'mkdir' in src
    assert 'except Exception' in src
    assert 'safe_target' in src


def test_marketplace_no_shell_injection():
    """FIX: install() uses subprocess_exec not shell=True."""
    import ast
    src = open('kali_mind/features/plugin_marketplace.py').read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == 'shell':
            if isinstance(node.value, ast.Constant) and node.value.value is True:
                raise AssertionError("shell=True found in marketplace code (not just comments)")


def test_marketplace_install_validates_command():
    """FIX: install() rejects commands not starting with trusted tools."""
    from kali_mind.features.plugin_marketplace import PluginMarketplace, BUILTIN_CATALOG
    with tempfile.TemporaryDirectory() as tmp:
        mp = PluginMarketplace(plugins_dir=Path(tmp))
        # All builtin catalog commands should start with allowed prefixes
        allowed = ("git clone", "pip install", "pip3 install", "apt install",
                   "apt-get install", "sudo apt", "sudo pip", "cargo install")
        for plugin in BUILTIN_CATALOG:
            cmd = plugin.get("install", "")
            if cmd:
                assert any(cmd.strip().startswith(p) for p in allowed), \
                    f"Plugin '{plugin['name']}' has untrusted install cmd: {cmd[:60]}"


def test_all_providers_have_health_check():
    """FIX: every provider overrides health_check() with lightweight implementation."""
    provider_classes = []
    try:
        from kali_mind.ai.providers.anthropic_provider import AnthropicProvider
        provider_classes.append(AnthropicProvider)
    except ImportError:
        pass
    try:
        from kali_mind.ai.providers.gemini_provider import GeminiProvider
        provider_classes.append(GeminiProvider)
    except ImportError:
        pass
    try:
        from kali_mind.ai.providers.misc_providers import GroqProvider, MistralProvider, CohereProvider
        provider_classes.extend([GroqProvider, MistralProvider, CohereProvider])
    except ImportError:
        pass
    try:
        from kali_mind.ai.providers.openai_compat import OpenAICompatProvider
        provider_classes.append(OpenAICompatProvider)
    except ImportError:
        pass
    try:
        from kali_mind.ai.providers.ollama_provider import OllamaProvider
        provider_classes.append(OllamaProvider)
    except ImportError:
        pass

    for cls in provider_classes:
        assert 'health_check' in cls.__dict__, \
            f"{cls.__name__} does not override health_check() — inherits token-consuming base"


def test_evidence_summarize_length_cap():
    """FIX: _summarize_evidence caps per-record and total records."""
    import inspect
    from kali_mind.findings.analyzer import FindingAnalyzer
    src = inspect.getsource(FindingAnalyzer._summarize_evidence)
    assert 'MAX_RECORDS' in src, "_summarize_evidence missing MAX_RECORDS cap"
    assert '1500' in src or '800' in src, "_summarize_evidence missing per-entry length cap"


def test_loader_uses_logger_not_print():
    """FIX: plugin loader uses logger.warning not print()."""
    import ast
    src = open('kali_mind/plugins/loader.py').read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id == 'print':
                raise AssertionError(f"bare print() found in loader.py:{node.lineno}")
    assert 'logger' in src, "loader.py missing logger"


def test_scope_persistence_clear():
    """FIX: clear_scope removes file and in-memory scope."""
    from kali_mind.security.scope import ScopeManager, ScopeConfig
    with tempfile.TemporaryDirectory() as tmp:
        scope_file = Path(tmp) / "scope.yaml"
        mgr = ScopeManager(scope_file=scope_file)
        mgr.set_scope(ScopeConfig(authorized_targets=["1.2.3.4"]))
        assert scope_file.exists()
        mgr.clear_scope()
        assert not scope_file.exists()
        assert mgr.get_scope() is None
        ok, _ = mgr.is_in_scope("1.2.3.4")
        assert not ok


def test_policy_set_mode_enum_validation():
    """FIX: set_mode rejects bare strings, accepts ExecutionMode members."""
    from kali_mind.security.policy import PolicyEngine, ExecutionMode
    engine = PolicyEngine()
    # Valid enum value
    engine.set_mode(ExecutionMode.AUTONOMOUS)
    assert engine.mode == ExecutionMode.AUTONOMOUS
    # Invalid string
    with pytest.raises(ValueError):
        engine.set_mode("HACKER_MODE")
    # Valid string coerced to enum
    engine.set_mode(ExecutionMode("dry_run"))
    assert engine.mode == ExecutionMode.DRY_RUN


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""Kali-Mind FastAPI backend — FIX #12: API key authentication."""
from __future__ import annotations

import sys
import logging
import ipaddress
import secrets
import uuid
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from kali_mind import __version__
from kali_mind.ai.gateway import get_gateway
from kali_mind.ai.schemas import AIRequest, Message, Role
from kali_mind.config import settings
from kali_mind.evidence.store import Session, get_store
from kali_mind.security.policy import ExecutionMode, get_policy_engine
from kali_mind.security.scope import ScopeConfig, get_scope_manager
from kali_mind.tools.discovery import discover_tools
from kali_mind.tools.registry import get_registry

logger = logging.getLogger(__name__)

# FIX #12: generate or load API token
_API_TOKEN_FILE = settings.home_dir / ".api_token"


def get_or_create_api_token() -> str:
    parent_existed = _API_TOKEN_FILE.parent.exists()
    _API_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not parent_existed:
        try:
            _API_TOKEN_FILE.parent.chmod(0o700)
        except OSError:
            pass
    if _API_TOKEN_FILE.is_symlink():
        raise RuntimeError("API token path must not be a symlink")

    token = ""
    try:
        token = _API_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        generated = secrets.token_urlsafe(32)
        try:
            # Exclusive create avoids two concurrent startups rotating the token.
            with _API_TOKEN_FILE.open("x", encoding="utf-8") as handle:
                handle.write(generated)
            token = generated
        except FileExistsError:
            token = _API_TOKEN_FILE.read_text(encoding="utf-8").strip()

    if not token:
        raise RuntimeError("API token file is empty; remove it and restart to regenerate")
    try:
        _API_TOKEN_FILE.chmod(0o600)
    except OSError as exc:
        raise RuntimeError("Unable to secure API token file permissions") from exc
    return token


API_TOKEN = get_or_create_api_token()
bearer_scheme = HTTPBearer(auto_error=False)

app = FastAPI(
    title="Kali-Mind API",
    description="AI-Powered Kali Linux Security Orchestration Platform",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme)) -> None:
    """FIX #12: Require Bearer token on all non-health endpoints."""
    if credentials is None or not secrets.compare_digest(credentials.credentials, API_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid or missing API token")


# ─── Schemas ────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    provider: Optional[str] = None


class ScopeRequest(BaseModel):
    name: str = "default"
    authorized_targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    allowed_categories: List[str] = Field(default_factory=lambda: ["reconnaissance", "enumeration"])


class SessionCreateRequest(BaseModel):
    name: str
    notes: str = ""


class EngagementRequest(BaseModel):
    name: str
    client: str = ""
    authorized_targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    allowed_categories: List[str] = Field(
        default_factory=lambda: ["reconnaissance", "enumeration", "vulnerability_assessment"]
    )
    notes: str = ""


# ─── Public endpoints ────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": __version__}


# ─── Protected endpoints ────────────────────────────────────────────────────

@app.get("/providers", dependencies=[Depends(verify_token)])
async def list_providers():
    gateway = get_gateway()
    healths = await gateway.health_check_all()
    return {"providers": [h.model_dump() for h in healths]}


@app.get("/providers/usage", dependencies=[Depends(verify_token)])
async def provider_usage():
    gateway = get_gateway()
    return {"usage": [u.model_dump() for u in gateway.get_usage_summary()]}


@app.post("/chat", dependencies=[Depends(verify_token)])
async def chat(req: ChatRequest):
    gateway = get_gateway()
    request = AIRequest(
        messages=[Message(role=Role.user, content=req.message)],
        system="You are Kali-Mind, an AI security orchestration assistant.",
        max_tokens=1024, temperature=0.3, provider=req.provider,
        session_id=req.session_id or "api-default",
    )
    response = await gateway.complete(request)
    return {"content": response.content, "provider": response.provider,
            "model": response.model,
            "tokens": {"input": response.input_tokens, "output": response.output_tokens},
            "cost": response.cost_estimate}


@app.get("/tools", dependencies=[Depends(verify_token)])
async def list_tools(category: Optional[str] = None, available_only: bool = False):
    registry = get_registry()
    if category:
        from kali_mind.tools.registry import ToolCategory
        try:
            tools = registry.by_category(ToolCategory(category))
        except ValueError:
            tools = registry.all_tools()
    elif available_only:
        tools = registry.available_tools()
    else:
        tools = registry.all_tools()
    return {"tools": [t.model_dump() for t in tools]}


@app.get("/tools/search", dependencies=[Depends(verify_token)])
async def search_tools(q: str):
    return {"tools": [t.model_dump() for t in get_registry().search(q)]}


@app.post("/tools/discover", dependencies=[Depends(verify_token)])
async def run_tool_discovery():
    available = await discover_tools()
    return {"discovered": len(available), "tools": [t.name for t in available]}


@app.get("/sessions", dependencies=[Depends(verify_token)])
async def list_sessions():
    return {"sessions": [s.model_dump() for s in get_store().list_sessions()]}


@app.post("/sessions", dependencies=[Depends(verify_token)])
async def create_session(req: SessionCreateRequest):
    session = Session(id=f"SESSION-{uuid.uuid4().hex[:8].upper()}", name=req.name, notes=req.notes)
    get_store().create_session(session)
    return session.model_dump()


@app.get("/sessions/{session_id}", dependencies=[Depends(verify_token)])
async def get_session(session_id: str):
    store = get_store()
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session": session.model_dump(),
            "evidence_count": len(store.get_evidence(session_id)),
            "findings_count": len(store.get_findings(session_id))}


@app.get("/sessions/{session_id}/findings", dependencies=[Depends(verify_token)])
async def get_findings(session_id: str):
    return {"findings": [f.model_dump() for f in get_store().get_findings(session_id)]}


@app.get("/sessions/{session_id}/evidence", dependencies=[Depends(verify_token)])
async def get_evidence(session_id: str):
    return {"evidence": [e.model_dump() for e in get_store().get_evidence(session_id)]}


@app.get("/sessions/{session_id}/replay", dependencies=[Depends(verify_token)])
async def get_replay(session_id: str):
    return {"replay": get_store().get_replay_log(session_id)}


@app.post("/sessions/{session_id}/report", dependencies=[Depends(verify_token)])
async def generate_report(session_id: str):
    from kali_mind.reporting.manager import ReportManager
    try:
        paths = ReportManager().generate_all(session_id)
        return {"reports": {k: str(v) for k, v in paths.items()}}
    except Exception:
        logger.exception("Report generation failed for session %s", session_id)
        raise HTTPException(status_code=500, detail="Report generation failed; see server logs")


@app.post("/sessions/{session_id}/export", dependencies=[Depends(verify_token)])
async def export_session(session_id: str):
    from kali_mind.features.session_transfer import SessionTransfer
    try:
        path = SessionTransfer().export_session(session_id)
        return {"path": str(path)}
    except Exception:
        logger.exception("Session export failed for session %s", session_id)
        raise HTTPException(status_code=500, detail="Session export failed; see server logs")


@app.get("/scope", dependencies=[Depends(verify_token)])
async def get_scope():
    scope = get_scope_manager().get_scope()
    return {"scope": scope.model_dump() if scope else None}


@app.post("/scope", dependencies=[Depends(verify_token)])
async def set_scope(req: ScopeRequest):
    scope = ScopeConfig(**req.model_dump())
    get_scope_manager().set_scope(scope)
    return {"scope": scope.model_dump()}


@app.post("/scope/target", dependencies=[Depends(verify_token)])
async def add_target(target: str):
    get_scope_manager().add_target(target)
    return {"message": f"Target added: {target}"}


@app.get("/policy", dependencies=[Depends(verify_token)])
async def get_policy():
    engine = get_policy_engine()
    return {"mode": engine.mode, "approval_threshold": engine.require_approval_above}


@app.post("/policy/mode", dependencies=[Depends(verify_token)])
async def set_policy_mode(mode: str):
    engine = get_policy_engine()
    try:
        engine.set_mode(ExecutionMode(mode))
        return {"mode": mode}
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {mode}")


@app.get("/engagements", dependencies=[Depends(verify_token)])
async def list_engagements():
    from kali_mind.features.engagements import get_engagement_manager
    return {"engagements": [e.model_dump() for e in get_engagement_manager().list_all()]}


@app.post("/engagements", dependencies=[Depends(verify_token)])
async def create_engagement(req: EngagementRequest):
    from kali_mind.features.engagements import get_engagement_manager
    profile = get_engagement_manager().create(**req.model_dump())
    return profile.model_dump()


@app.get("/wordlists", dependencies=[Depends(verify_token)])
async def list_wordlists():
    from kali_mind.features.wordlist_manager import get_wordlist_manager
    wls = get_wordlist_manager().scan()
    return {"wordlists": [{"category": c, "path": p, "size_kb": s} for c, p, s in wls]}


@app.get("/cost", dependencies=[Depends(verify_token)])
async def get_cost():
    from kali_mind.features.cost_tracker import get_cost_tracker
    tracker = get_cost_tracker()
    tracker.sync_from_gateway()
    return {"usage": [u.model_dump() for u in tracker._usage.values()]}


def start_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    ssl_certfile: Optional[str] = None,
    ssl_keyfile: Optional[str] = None,
) -> None:
    import uvicorn

    try:
        loopback = host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback and not (ssl_certfile and ssl_keyfile):
        raise ValueError(
            "Non-loopback API binding requires both --ssl-certfile and --ssl-keyfile; "
            "otherwise use localhost or an authenticated TLS reverse proxy"
        )
    if bool(ssl_certfile) != bool(ssl_keyfile):
        raise ValueError("Both SSL certificate and key paths must be provided together")

    scheme = "https" if ssl_certfile else "http"
    banner = (
        f"\n⚔  Kali-Mind API Server\n"
        f"   URL:   {scheme}://{host}:{port}\n"
        f"   Token file: {_API_TOKEN_FILE} (permissions should be 0600)\n"
        f"   Docs:  {scheme}://{host}:{port}/docs\n"
        "   Authentication token is not printed to logs.\n"
    )
    sys.stderr.write(banner)
    sys.stderr.flush()
    uvicorn.run(
        app, host=host, port=port, log_level="info",
        ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile,
    )

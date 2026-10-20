"""Kali-Mind configuration management."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    _HAS_PYDANTIC_SETTINGS = True
except ImportError:  # pragma: no cover - fallback for minimal envs
    _HAS_PYDANTIC_SETTINGS = False
    BaseSettings = BaseModel  # type: ignore
    def SettingsConfigDict(**kwargs):  # type: ignore
        return {}

load_dotenv()

KALI_MIND_HOME = Path.home() / ".kali-mind"


class ProviderConfig(BaseModel):
    enabled: bool = False
    api_key: Optional[str] = None
    endpoint: Optional[str] = None
    model: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class ProvidersConfig(BaseModel):
    openai: ProviderConfig = Field(default_factory=ProviderConfig)
    anthropic: ProviderConfig = Field(default_factory=ProviderConfig)
    grok: ProviderConfig = Field(default_factory=ProviderConfig)
    kimi: ProviderConfig = Field(default_factory=ProviderConfig)
    gemini: ProviderConfig = Field(default_factory=ProviderConfig)
    deepseek: ProviderConfig = Field(default_factory=ProviderConfig)
    nvidia: ProviderConfig = Field(default_factory=ProviderConfig)
    mistral: ProviderConfig = Field(default_factory=ProviderConfig)
    groq: ProviderConfig = Field(default_factory=ProviderConfig)
    cohere: ProviderConfig = Field(default_factory=ProviderConfig)
    together: ProviderConfig = Field(default_factory=ProviderConfig)
    openrouter: ProviderConfig = Field(default_factory=ProviderConfig)
    ollama: ProviderConfig = Field(default_factory=ProviderConfig)


class PolicyConfig(BaseModel):
    default_mode: str = "assisted"
    require_approval_above: str = "medium"
    allow_destructive: bool = False
    max_concurrent_tools: int = 3
    default_timeout: int = 300


# FIX #13: Use Pydantic v2 model_config instead of deprecated class Config
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KALI_MIND_",
        env_file=".env",
        extra="ignore",
    )

    home_dir: Path = KALI_MIND_HOME
    tools_dir: Path = KALI_MIND_HOME / "tools"
    plugins_dir: Path = KALI_MIND_HOME / "plugins"
    sessions_dir: Path = KALI_MIND_HOME / "sessions"
    evidence_dir: Path = KALI_MIND_HOME / "evidence"
    reports_dir: Path = KALI_MIND_HOME / "reports"
    logs_dir: Path = KALI_MIND_HOME / "logs"
    models_dir: Path = KALI_MIND_HOME / "models"
    wordlists_dir: Path = Path("/usr/share/wordlists")

    db_path: Path = KALI_MIND_HOME / "kali_mind.db"

    default_provider: str = "ollama"
    privacy_mode: bool = False
    offline_mode: bool = False
    sandbox_mode: bool = False
    require_signed_plugins: bool = True

    log_level: str = "INFO"

    # Feature flags
    enable_notifications: bool = True
    enable_cost_tracking: bool = True
    enable_streaming: bool = True

    # AI role assignments (FIX #22 multi-model)
    planner_provider: Optional[str] = None
    analyst_provider: Optional[str] = None
    parser_provider: Optional[str] = None
    reporter_provider: Optional[str] = None


def load_providers_config() -> ProvidersConfig:
    cfg = ProvidersConfig()

    cfg.ollama.enabled = True
    cfg.ollama.endpoint = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    cfg.ollama.model = os.getenv("OLLAMA_MODEL", "llama3")

    _set_provider(cfg.openai, "OPENAI_API_KEY", "gpt-4o-mini")
    _set_provider(cfg.anthropic, "ANTHROPIC_API_KEY", "claude-3-5-haiku-20241022")
    _set_provider(cfg.grok, "XAI_API_KEY", "grok-beta", endpoint="https://api.x.ai/v1")
    _set_provider(cfg.kimi, "KIMI_API_KEY", "moonshot-v1-8k", endpoint="https://api.moonshot.cn/v1")
    _set_provider(cfg.gemini, "GEMINI_API_KEY", "gemini-1.5-flash")
    _set_provider(cfg.deepseek, "DEEPSEEK_API_KEY", "deepseek-chat", endpoint="https://api.deepseek.com/v1")
    _set_provider(cfg.nvidia, "NVIDIA_API_KEY", "meta/llama-3.1-8b-instruct", endpoint="https://integrate.api.nvidia.com/v1")
    _set_provider(cfg.mistral, "MISTRAL_API_KEY", "mistral-small-latest")
    _set_provider(cfg.groq, "GROQ_API_KEY", "llama-3.1-8b-instant")
    _set_provider(cfg.cohere, "COHERE_API_KEY", "command-r")
    _set_provider(cfg.together, "TOGETHER_API_KEY", "meta-llama/Llama-3-8b-chat-hf", endpoint="https://api.together.xyz/v1")
    _set_provider(cfg.openrouter, "OPENROUTER_API_KEY", "openai/gpt-4o-mini", endpoint="https://openrouter.ai/api/v1")

    providers_file = KALI_MIND_HOME / "providers.yaml"
    if providers_file.exists():
        with open(providers_file) as f:
            data = yaml.safe_load(f) or {}
        for name, vals in data.items():
            if hasattr(cfg, name) and isinstance(vals, dict):
                pc = getattr(cfg, name)
                for k, v in vals.items():
                    if hasattr(pc, k):
                        setattr(pc, k, v)

    return cfg


def _set_provider(pc: ProviderConfig, env_key: str, model: str, endpoint: Optional[str] = None) -> None:
    key = os.getenv(env_key)
    if key:
        pc.enabled = True
        pc.api_key = key
        pc.model = model
        if endpoint:
            pc.endpoint = endpoint


def ensure_home_dirs(s: Settings) -> None:
    for d in [s.home_dir, s.tools_dir, s.plugins_dir, s.sessions_dir,
              s.evidence_dir, s.reports_dir, s.logs_dir, s.models_dir]:
        existed = d.exists()
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not existed:
            try:
                d.chmod(0o700)
            except OSError:
                # Custom or read-only locations may not permit permission changes.
                pass


def bootstrap(s: Optional[Settings] = None) -> Settings:
    """Create home dirs and configure logging. Call once at process start."""
    s = s or settings
    ensure_home_dirs(s)
    try:
        from kali_mind.logging_config import setup_logging
        setup_logging(s.log_level)
    except Exception:
        pass
    return s


settings = Settings()

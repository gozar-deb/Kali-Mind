"""Feature #31: Named engagement profiles with persistent scope and session linkage."""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class EngagementProfile(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8].upper())
    name: str
    client: str = ""
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    authorized_targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    allowed_categories: List[str] = Field(
        default_factory=lambda: ["reconnaissance", "enumeration", "vulnerability_assessment"]
    )
    sessions: List[str] = Field(default_factory=list)
    notes: str = ""
    tester: str = ""
    scope_document: str = ""  # path or reference to auth doc

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Fa-f0-9]{8}", value):
            raise ValueError("Engagement id must be exactly 8 hexadecimal characters")
        return value.upper()


class EngagementManager:
    def __init__(self, engagements_dir: Optional[Path] = None) -> None:
        if engagements_dir is None:
            from kali_mind.config import settings
            engagements_dir = settings.home_dir / "engagements"
        self.dir = engagements_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    def create(self, name: str, **kwargs) -> EngagementProfile:
        profile = EngagementProfile(name=name, **kwargs)
        self._save(profile)
        return profile

    def list_all(self) -> List[EngagementProfile]:
        profiles = []
        for f in self.dir.glob("*.yaml"):
            if f.is_symlink() or not f.is_file():
                continue
            try:
                profiles.append(self._load(f))
            except Exception as e:
                logger.warning("Failed to load engagement profile %s: %s", f, e)
        return sorted(profiles, key=lambda p: p.created_at, reverse=True)

    def get(self, engagement_id: str) -> Optional[EngagementProfile]:
        if re.fullmatch(r"[A-Fa-f0-9]{8}", engagement_id):
            path = self.dir / f"{engagement_id.upper()}.yaml"
            if path.is_file() and not path.is_symlink():
                return self._load(path)
        # Search by name
        for p in self.list_all():
            if p.name.lower() == engagement_id.lower() or p.id == engagement_id:
                return p
        return None

    def add_target(self, engagement_id: str, target: str) -> bool:
        p = self.get(engagement_id)
        if not p:
            return False
        if target not in p.authorized_targets:
            p.authorized_targets.append(target)
        self._save(p)
        return True

    def add_session(self, engagement_id: str, session_id: str) -> bool:
        p = self.get(engagement_id)
        if not p:
            return False
        if session_id not in p.sessions:
            p.sessions.append(session_id)
        self._save(p)
        return True

    def activate(self, engagement_id: str) -> bool:
        """Load engagement scope into the active scope manager."""
        p = self.get(engagement_id)
        if not p:
            return False
        from kali_mind.security.scope import ScopeConfig, get_scope_manager
        scope = ScopeConfig(
            name=p.name,
            authorized_targets=p.authorized_targets,
            excluded_targets=p.excluded_targets,
            allowed_categories=p.allowed_categories,
            notes=p.notes,
        )
        get_scope_manager().set_scope(scope)
        return True

    def delete(self, engagement_id: str) -> bool:
        p = self.get(engagement_id)
        if not p:
            return False
        path = self.dir / f"{p.id}.yaml"
        if path.exists():
            path.unlink()
        return True

    def _save(self, profile: EngagementProfile) -> None:
        # Revalidate IDs at the filesystem boundary.
        if not re.fullmatch(r"[A-Fa-f0-9]{8}", profile.id):
            raise ValueError("Invalid engagement ID")
        path = self.dir / f"{profile.id}.yaml"
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(profile.model_dump(), f, default_flow_style=False)
        path.chmod(0o600)

    def _load(self, path: Path) -> EngagementProfile:
        with open(path) as f:
            data = yaml.safe_load(f)
        return EngagementProfile(**data)


_manager: Optional[EngagementManager] = None


def get_engagement_manager() -> EngagementManager:
    global _manager
    if _manager is None:
        _manager = EngagementManager()
    return _manager

"""Multi-user API auth — simple token → user map (local single-node).

Users file: ``~/.kali-mind/users.json``
{
  "alice": {"token": "...", "scopes": ["192.168.56.0/24"], "role": "operator"},
  "bob":   {"token": "...", "scopes": ["10.0.0.0/8"], "role": "operator"}
}

This is intentionally minimal — not a full IdP.
"""
from __future__ import annotations

import json
import logging
import secrets
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class UserRecord(BaseModel):
    token: str
    scopes: List[str] = Field(default_factory=list)
    role: str = "operator"


class UserStore:
    def __init__(self, path: Optional[Path] = None) -> None:
        if path is None:
            from kali_mind.config import settings
            path = settings.home_dir / "users.json"
        self.path = path
        self._users: Dict[str, UserRecord] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                self._users = {k: UserRecord(**v) for k, v in raw.items()}
            except Exception as e:
                logger.warning("Failed to load users.json: %s", e)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v.model_dump() for k, v in self._users.items()}
        self.path.write_text(json.dumps(data, indent=2))
        self.path.chmod(0o600)

    def create_user(self, username: str, scopes: Optional[List[str]] = None) -> UserRecord:
        token = secrets.token_urlsafe(32)
        rec = UserRecord(token=token, scopes=scopes or [], role="operator")
        self._users[username] = rec
        self.save()
        return rec

    def authenticate(self, token: str) -> Optional[str]:
        """Return username if token matches."""
        for name, rec in self._users.items():
            if secrets.compare_digest(rec.token, token):
                return name
        return None

    def scopes_for(self, username: str) -> List[str]:
        rec = self._users.get(username)
        return list(rec.scopes) if rec else []


_store: Optional[UserStore] = None


def get_user_store() -> UserStore:
    global _store
    if _store is None:
        _store = UserStore()
    return _store

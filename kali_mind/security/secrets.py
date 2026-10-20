"""Secret store: environment variables with optional OS keyring backend.

Usage:
    store = get_secret_store()
    key = store.get("OPENAI_API_KEY")
    store.set("OPENAI_API_KEY", "sk-...")  # prefers keyring when available
"""
from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

SERVICE_NAME = "kali-mind"


class SecretStore:
    def __init__(self) -> None:
        self._keyring = None
        try:
            import keyring  # type: ignore
            self._keyring = keyring
            logger.debug("OS keyring backend available")
        except ImportError:
            logger.debug("keyring not installed; using environment variables only")

    def get(self, name: str) -> Optional[str]:
        """Resolve secret: keyring → environment → None."""
        if self._keyring is not None:
            try:
                val = self._keyring.get_password(SERVICE_NAME, name)
                if val:
                    return val
            except Exception as e:
                logger.debug("keyring get failed for %s: %s", name, e)
        return os.getenv(name) or None

    def set(self, name: str, value: str) -> bool:
        """Store in keyring when available; always also set process env for current run."""
        os.environ[name] = value
        if self._keyring is not None:
            try:
                self._keyring.set_password(SERVICE_NAME, name, value)
                return True
            except Exception as e:
                logger.warning("keyring set failed for %s: %s", name, e)
                return False
        return True

    def delete(self, name: str) -> None:
        os.environ.pop(name, None)
        if self._keyring is not None:
            try:
                self._keyring.delete_password(SERVICE_NAME, name)
            except Exception:
                pass


_store: Optional[SecretStore] = None


def get_secret_store() -> SecretStore:
    global _store
    if _store is None:
        _store = SecretStore()
    return _store

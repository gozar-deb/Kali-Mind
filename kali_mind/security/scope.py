"""Engagement scope management with persistence."""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ScopeConfig(BaseModel):
    name: str = "default"
    authorized_targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    allowed_categories: List[str] = Field(
        default_factory=lambda: ["reconnaissance", "enumeration", "vulnerability_assessment"]
    )
    notes: str = ""


class ScopeManager:
    """Validates targets against engagement scope. Scope is persisted to disk."""

    def __init__(self, scope_file: Optional[Path] = None) -> None:
        self._scope: Optional[ScopeConfig] = None
        self._scope_file = scope_file
        self._load_from_file()

    def _load_from_file(self) -> None:
        if self._scope_file and self._scope_file.exists():
            try:
                with open(self._scope_file) as f:
                    data = yaml.safe_load(f) or {}
                self._scope = ScopeConfig(**data)
                logger.debug("Loaded scope from %s", self._scope_file)
            except Exception as e:
                logger.warning("Failed to load scope from %s: %s", self._scope_file, e)

    def _save_to_file(self) -> None:
        if self._scope_file and self._scope:
            try:
                self._scope_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self._scope_file, "w", encoding="utf-8") as f:
                    yaml.safe_dump(self._scope.model_dump(), f, default_flow_style=False)
                self._scope_file.chmod(0o600)
            except Exception as e:
                logger.error("Failed to save scope to %s: %s", self._scope_file, e)

    def set_scope(self, scope: ScopeConfig) -> None:
        self._scope = scope
        self._save_to_file()

    def get_scope(self) -> Optional[ScopeConfig]:
        return self._scope

    def clear_scope(self) -> None:
        self._scope = None
        if self._scope_file and self._scope_file.exists():
            try:
                self._scope_file.unlink()
            except OSError as e:
                logger.warning("Failed to remove scope file %s: %s", self._scope_file, e)

    def add_target(self, target: str) -> None:
        if self._scope is None:
            self._scope = ScopeConfig()
        if target not in self._scope.authorized_targets:
            self._scope.authorized_targets.append(target)
        self._save_to_file()

    def exclude_target(self, target: str) -> None:
        if self._scope is None:
            self._scope = ScopeConfig()
        if target not in self._scope.excluded_targets:
            self._scope.excluded_targets.append(target)
        self._save_to_file()

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        if self._scope is None:
            return False, "No scope configured. Use 'kali-mind scope add <target>' first."
        if self._is_excluded(target):
            return False, f"Target '{target}' is in the exclusion list."
        if not self._scope.authorized_targets:
            return False, "No authorized targets configured."
        for auth_target in self._scope.authorized_targets:
            if self._target_matches(target, auth_target):
                return True, f"Target is within authorized scope: {auth_target}"
        return False, f"Target '{target}' is NOT in authorized scope."

    def _is_excluded(self, target: str) -> bool:
        return any(self._target_matches(target, exc) for exc in self._scope.excluded_targets)

    def _target_matches(self, target: str, scope_entry: str) -> bool:
        """Return True if target is covered by the scope entry (exact, CIDR, or domain)."""
        target = self._normalize_host(target)
        scope_entry = scope_entry.strip().lower()
        if not target or not scope_entry:
            return False
        # Scope entries may be entered as URLs; compare host identity, not URL path.
        if "://" in scope_entry:
            scope_host = self._normalize_host(scope_entry)
            if scope_host:
                scope_entry = scope_host
        elif "/" not in scope_entry and not scope_entry.startswith("*."):
            # Normalize optional host:port notation but preserve CIDR entries.
            try:
                ipaddress.ip_network(scope_entry, strict=False)
            except ValueError:
                scope_host = self._normalize_host(scope_entry)
                if scope_host:
                    scope_entry = scope_host
        if target == scope_entry:
            return True
        # CIDR / IP network match
        try:
            target_ip = ipaddress.ip_address(target)
            network = ipaddress.ip_network(scope_entry, strict=False)
            if target_ip in network:
                return True
        except ValueError:
            # Not an IP/CIDR pair — fall through to domain matching
            pass
        # Wildcard domain: *.example.com
        if scope_entry.startswith("*."):
            domain = scope_entry[2:]
            if target == domain or target.endswith(f".{domain}"):
                return True
        # Subdomain of a bare domain entry; label boundary prevents evil-example.com.
        if target.endswith(f".{scope_entry}"):
            return True
        return False

    @staticmethod
    def _normalize_host(value: str) -> str:
        """Normalize host-like targets and URLs without weakening domain boundaries."""
        value = value.strip().lower()
        if not value:
            return ""
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
        try:
            parsed = urlsplit(value if "://" in value else f"//{value}")
            host = parsed.hostname
            if host:
                return host.rstrip(".").lower()
        except ValueError:
            return ""
        return value.rstrip(".")

    def is_category_allowed(self, category: str) -> bool:
        if self._scope is None:
            return False
        return category.lower() in [c.lower() for c in self._scope.allowed_categories]

    def summary(self) -> str:
        if not self._scope:
            return "No scope configured"
        targets = ", ".join(self._scope.authorized_targets) or "none"
        excluded = ", ".join(self._scope.excluded_targets) or "none"
        return (
            f"Scope: {self._scope.name}\n"
            f"  Authorized: {targets}\n"
            f"  Excluded:   {excluded}\n"
            f"  Categories: {', '.join(self._scope.allowed_categories)}"
        )


_scope_manager: Optional[ScopeManager] = None


def get_scope_manager() -> ScopeManager:
    global _scope_manager
    if _scope_manager is None:
        from kali_mind.config import settings
        scope_file = settings.home_dir / "scope.yaml"
        _scope_manager = ScopeManager(scope_file=scope_file)
    return _scope_manager

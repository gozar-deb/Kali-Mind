"""Formal plugin protocol for Kali-Mind.

A plugin is a directory containing:
  plugin.yaml   — manifest
  adapter.py    — implements BaseAdapter (or registers via entry point)

Optional:
  checksums.sha256 — signed integrity file
  README.md

See docs/adapter-authoring.md for the full guide.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, List, Optional, Protocol, runtime_checkable

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class PluginManifest(BaseModel):
    name: str
    binary: str = ""
    category: str = "custom"
    description: str = ""
    version: str = "0.1.0"
    author: str = ""
    capabilities: List[str] = Field(default_factory=list)
    risk_level: str = "medium"
    entry: str = "adapter:Adapter"  # module:Class
    requires_checksum: bool = False
    tags: List[str] = Field(default_factory=list)


@runtime_checkable
class Plugin(Protocol):
    """Structural protocol — any object with these attributes is a plugin."""

    name: str
    manifest: PluginManifest

    def load_adapter(self) -> Any:
        ...


def load_manifest(path: Path) -> PluginManifest:
    data = yaml.safe_load(path.read_text()) or {}
    return PluginManifest(**data)


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_plugin_checksums(plugin_dir: Path) -> tuple[bool, str]:
    """Verify checksums.sha256 if present. Returns (ok, message)."""
    if plugin_dir.is_symlink():
        return False, "plugin directory must not be a symlink"
    checksum_file = plugin_dir / "checksums.sha256"
    if checksum_file.is_symlink():
        return False, "checksum file must not be a symlink"
    if not checksum_file.exists():
        return True, "no checksum file (optional)"
    try:
        lines = checksum_file.read_text().strip().splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                return False, f"malformed checksum entry: {line[:120]}"
            expected, rel = parts[0], parts[1].strip().lstrip("*")
            candidate = plugin_dir / rel
            if any(parent.is_symlink() for parent in candidate.parents if parent != plugin_dir.parent):
                return False, f"symlinked checksum path is not allowed: {rel}"
            if candidate.is_symlink():
                return False, f"symlinked checksum target is not allowed: {rel}"
            target = candidate.resolve()
            try:
                target.relative_to(plugin_dir.resolve())
            except ValueError:
                return False, f"checksum path escapes plugin directory: {rel}"
            if not target.is_file():
                return False, f"missing or unsafe file listed in checksums: {rel}"
            if len(expected) != 64 or any(c not in "0123456789abcdefABCDEF" for c in expected):
                return False, f"invalid SHA-256 digest for {rel}"
            actual = compute_file_sha256(target)
            if actual != expected.lower():
                return False, f"checksum mismatch for {rel}"
        return True, "checksums verified"
    except Exception as e:
        return False, f"checksum verification error: {e}"


def write_checksums(plugin_dir: Path, files: Optional[List[str]] = None) -> Path:
    """Generate checksums.sha256 for plugin files (helper for authors)."""
    if files is None:
        files = [p.name for p in plugin_dir.iterdir() if p.is_file() and p.name != "checksums.sha256"]
    lines = []
    for name in sorted(files):
        path = plugin_dir / name
        if path.exists():
            lines.append(f"{compute_file_sha256(path)}  {name}")
    out = plugin_dir / "checksums.sha256"
    out.write_text("\n".join(lines) + "\n")
    return out

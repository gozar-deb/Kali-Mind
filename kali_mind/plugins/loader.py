"""Plugin loader — dynamic loading of security tool plugins."""
from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from kali_mind.config import settings
from kali_mind.tools.adapters.registry import register_adapter
from kali_mind.tools.registry import (
    RiskLevel, ToolCategory, ToolManifest, get_registry
)

logger = logging.getLogger(__name__)


class PluginManifest:
    """Represents a loaded plugin."""
    def __init__(self, name: str, path: Path, manifest: Dict[str, Any]) -> None:
        self.name = name
        self.path = path
        self.manifest = manifest

    def __repr__(self) -> str:
        return f"Plugin({self.name})"


class PluginLoader:
    """Loads tool plugins from the plugins directory."""

    def __init__(self, plugins_dir: Optional[Path] = None) -> None:
        self.plugins_dir = plugins_dir or settings.plugins_dir
        self._loaded: List[PluginManifest] = []

    def load_all(self) -> List[PluginManifest]:
        """Load all plugins from the plugins directory."""
        if not self.plugins_dir.exists():
            return []

        loaded = []
        for plugin_dir in self.plugins_dir.iterdir():
            if plugin_dir.is_symlink() or not plugin_dir.is_dir():
                logger.warning("Skipping symlink or non-directory plugin entry: %s", plugin_dir)
                continue
            manifest_file = plugin_dir / "plugin.yaml"
            if not manifest_file.is_file() or manifest_file.is_symlink():
                continue
            # Signature calculation intentionally ignores symlinks; therefore reject
            # them entirely so Python cannot execute unsigned linked helper files.
            if any(child.is_symlink() for child in plugin_dir.rglob("*")):
                logger.warning("Plugin %s contains symlinks and was rejected", plugin_dir.name)
                continue
            try:
                from kali_mind.security.plugin_sign import verify_plugin_signature
                from kali_mind.plugins.protocol import verify_plugin_checksums
                ok_c, msg_c = verify_plugin_checksums(plugin_dir)
                if not ok_c:
                    logger.warning("Plugin %s checksum failed: %s", plugin_dir.name, msg_c)
                    continue
                require_signature = bool(getattr(settings, "require_signed_plugins", True))
                ok_s, msg_s = verify_plugin_signature(plugin_dir, require=require_signature)
                if not ok_s:
                    logger.warning("Plugin %s signature failed: %s", plugin_dir.name, msg_s)
                    continue
                pm = self._load_plugin(plugin_dir, manifest_file)
                if pm:
                    loaded.append(pm)
                    self._loaded.append(pm)
            except Exception as e:
                logger.warning("Failed to load plugin from %s: %s", plugin_dir, e)

        return loaded

    def _load_plugin(self, plugin_dir: Path, manifest_file: Path) -> Optional[PluginManifest]:
        with open(manifest_file) as f:
            data = yaml.safe_load(f)

        if not data or "name" not in data:
            return None

        pm = PluginManifest(name=data["name"], path=plugin_dir, manifest=data)

        # Register in tool registry
        registry = get_registry()
        tool = ToolManifest(
            name=data["name"],
            binary=data.get("binary", data["name"]),
            category=ToolCategory(data.get("category", "custom")),
            description=data.get("description", ""),
            capabilities=data.get("capabilities", []),
            input_types=data.get("input_types", []),
            output_formats=data.get("output_formats", ["text"]),
            risk_level=RiskLevel(data.get("risk_level", "medium")),
            tags=data.get("tags", []),
        )
        registry.register(tool)

        # Load Python adapter if present
        adapter_file = plugin_dir / "adapter.py"
        if adapter_file.exists():
            try:
                spec = importlib.util.spec_from_file_location(
                    f"kali_mind_plugin_{data['name']}", adapter_file
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    if hasattr(module, "Adapter"):
                        adapter = module.Adapter()
                        register_adapter(data["name"], adapter)
            except Exception as adapter_err:
                logger.warning("Failed to load adapter for plugin '%s': %s", data['name'], adapter_err)

        return pm

    def list_plugins(self) -> List[PluginManifest]:
        return self._loaded.copy()

    def create_plugin_template(self, name: str) -> Path:
        """Create a new plugin directory with template files."""
        if not name or name in {".", ".."} or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in name):
            raise ValueError("Plugin name must contain only letters, numbers, underscores, or hyphens")
        plugin_dir = self.plugins_dir / name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        manifest_content = f"""\
name: {name}
binary: {name}
category: custom
description: Custom security tool plugin
capabilities: []
input_types: [hostname, ip]
output_formats: [text]
risk_level: medium
tags: [custom]
version_flag: --version
"""
        (plugin_dir / "plugin.yaml").write_text(manifest_content)

        adapter_content = '''\
"""Custom adapter for this plugin."""
from kali_mind.tools.adapters.base import BaseAdapter, ToolRequest
from typing import Any, Dict, List


class Adapter(BaseAdapter):
    tool_name = "custom"

    def build_command(self, request: ToolRequest) -> List[str]:
        return [self.tool_name, request.target]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {"raw": stdout, "errors": [stderr] if stderr else []}
'''
        (plugin_dir / "adapter.py").write_text(adapter_content)
        (plugin_dir / "README.md").write_text(f"# {name} Plugin\n\nCustom Kali-Mind plugin.\n")

        return plugin_dir


_loader: Optional[PluginLoader] = None


def get_plugin_loader() -> PluginLoader:
    global _loader
    if _loader is None:
        _loader = PluginLoader()
    return _loader

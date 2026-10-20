"""Air-gapped offline bundle helper — document + create local asset packs."""
from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

MANIFEST_NAME = "offline_manifest.json"


def create_offline_bundle(dest: Path, include_dirs: List[Path] | None = None) -> Path:
    """Create a directory layout for offline use.

    Layout:
      dest/
        offline_manifest.json
        wordlists/
        nuclei-templates/
        cve/   (placeholder for NVD mirror)
        playbooks/
        models/  (ollama export notes)
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    for sub in ("wordlists", "nuclei-templates", "cve", "playbooks", "models"):
        (dest / sub).mkdir(exist_ok=True)

    # Copy bundled playbooks
    src_playbooks = Path(__file__).resolve().parents[2] / "examples" / "playbooks"
    if src_playbooks.exists():
        for f in src_playbooks.glob("*.yaml"):
            shutil.copy2(f, dest / "playbooks" / f.name)

    if include_dirs:
        for d in include_dirs:
            d = Path(d)
            if d.exists():
                target = dest / d.name
                if d.is_dir():
                    shutil.copytree(d, target, dirs_exist_ok=True)

    manifest = {
        "version": 1,
        "description": "Kali-Mind offline pack",
        "components": {
            "wordlists": "Place SecLists or custom lists here",
            "nuclei-templates": "Clone projectdiscovery/nuclei-templates offline",
            "cve": "Optional NVD JSON mirror for offline CVE enrichment",
            "playbooks": "Engagement playbooks",
            "models": "Export Ollama models: ollama create / ollama save",
        },
        "env": {
            "KALI_MIND_DEFAULT_PROVIDER": "ollama",
            "KALI_MIND_OFFLINE_MODE": "true",
            "OLLAMA_HOST": "http://127.0.0.1:11434",
        },
    }
    (dest / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2))
    logger.info("Offline bundle created at %s", dest)
    return dest

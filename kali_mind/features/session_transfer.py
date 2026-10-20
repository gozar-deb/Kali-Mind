"""Feature #25: Session export and import as self-contained JSON bundles."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from kali_mind import __version__
from kali_mind.evidence.store import (
    EvidenceRecord, EvidenceStore, Finding, Session, get_store
)


class SessionTransfer:
    def __init__(self, store: Optional[EvidenceStore] = None) -> None:
        self.store = store or get_store()

    def export_session(self, session_id: str, output_path: Optional[Path] = None) -> Path:
        """Export session to a self-contained JSON bundle."""
        session = self.store.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")

        evidence = self.store.get_evidence(session_id)
        findings = self.store.get_findings(session_id)
        replay = self.store.get_replay_log(session_id)

        bundle: Dict[str, Any] = {
            "kali_mind_version": __version__,
            "export_date": datetime.now().isoformat(),
            "session": session.model_dump(),
            "evidence": [e.model_dump() for e in evidence],
            "findings": [f.model_dump() for f in findings],
            "replay_log": replay,
        }

        if output_path is None:
            from kali_mind.config import settings
            # Session names/IDs can originate in imported bundles; keep them from
            # escaping the managed export directory via path separators or dot segments.
            slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", session.name).strip("_-").lower()[:60]
            safe_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", session_id).strip("_-")[:80]
            slug = slug or "session"
            safe_id = safe_id or "unknown"
            output_path = settings.sessions_dir / f"{slug}_{safe_id}.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        try:
            output_path.chmod(0o600)
        except OSError:
            pass
        return output_path

    def import_session(self, bundle_path: Path) -> str:
        """Import a session bundle. Returns the new session_id."""
        data = json.loads(bundle_path.read_text())

        raw_session = data.get("session", {})
        session = Session(**raw_session)
        # Avoid ID collision by appending suffix if session already exists
        if self.store.get_session(session.id):
            import uuid
            session.id = f"{session.id}-{uuid.uuid4().hex[:6].upper()}"

        self.store.create_session(session)

        for raw_ev in data.get("evidence", []):
            raw_ev["session_id"] = session.id
            raw_ev.pop("id", None)
            ev = EvidenceRecord(**raw_ev)
            self.store.store_evidence(ev)

        for raw_f in data.get("findings", []):
            raw_f["session_id"] = session.id
            raw_f.pop("id", None)
            f = Finding(**raw_f)
            self.store.store_finding(f)

        for entry in data.get("replay_log", []):
            self.store.log_action(session.id, entry.get("action", ""), entry.get("details", ""))

        return session.id

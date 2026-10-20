"""Evidence database — SQLite-backed persistent storage for sessions, findings, and evidence."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from kali_mind.config import settings


class EvidenceRecord(BaseModel):
    id: Optional[int] = None
    session_id: str
    timestamp: str = ""
    tool: str
    operation: str
    target: str
    command: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    parsed: Optional[Dict[str, Any]] = None
    notes: str = ""

    def model_post_init(self, *args: Any) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class Finding(BaseModel):
    id: Optional[int] = None
    session_id: str
    timestamp: str = ""
    title: str
    severity: str  # informational, low, medium, high, critical
    confidence: str  # low, medium, high
    affected_asset: str
    description: str
    evidence: str = ""
    potential_impact: str = ""
    remediation: str = ""
    references: List[str] = []
    detection_source: str = ""
    is_observed: bool = True  # False = AI inference

    def model_post_init(self, *args: Any) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class Session(BaseModel):
    id: str
    name: str
    created_at: str = ""
    updated_at: str = ""
    scope: Optional[Dict[str, Any]] = None
    status: str = "active"
    notes: str = ""

    def model_post_init(self, *args: Any) -> None:
        now = datetime.now().isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


class EvidenceStore:
    """SQLite-backed evidence and session store."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or settings.db_path
        self._init_db()
        # Evidence may contain sensitive scan output; tighten permissions on disk.
        try:
            self.db_path.chmod(0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connection(self):
        """Commit or roll back, and always close SQLite connections."""
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT,
                    updated_at TEXT,
                    scope TEXT,
                    status TEXT DEFAULT 'active',
                    notes TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT,
                    tool TEXT,
                    operation TEXT,
                    target TEXT,
                    command TEXT,
                    stdout TEXT DEFAULT '',
                    stderr TEXT DEFAULT '',
                    exit_code INTEGER DEFAULT 0,
                    parsed TEXT,
                    notes TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT,
                    title TEXT,
                    severity TEXT,
                    confidence TEXT,
                    affected_asset TEXT,
                    description TEXT,
                    evidence TEXT DEFAULT '',
                    potential_impact TEXT DEFAULT '',
                    remediation TEXT DEFAULT '',
                    finding_refs TEXT DEFAULT '[]',
                    detection_source TEXT DEFAULT '',
                    is_observed INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS replay_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT,
                    action TEXT,
                    details TEXT
                );
            """)

    # Sessions
    def create_session(self, session: Session) -> Session:
        with self._connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?,?)",
                (
                    session.id, session.name, session.created_at, session.updated_at,
                    json.dumps(session.scope) if session.scope else None,
                    session.status, session.notes,
                ),
            )
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if row:
            return Session(
                id=row["id"], name=row["name"],
                created_at=row["created_at"], updated_at=row["updated_at"],
                scope=json.loads(row["scope"]) if row["scope"] else None,
                status=row["status"], notes=row["notes"],
            )
        return None

    def list_sessions(self) -> List[Session]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM sessions ORDER BY updated_at DESC").fetchall()
        return [
            Session(
                id=r["id"], name=r["name"],
                created_at=r["created_at"], updated_at=r["updated_at"],
                scope=json.loads(r["scope"]) if r["scope"] else None,
                status=r["status"], notes=r["notes"],
            )
            for r in rows
        ]

    # Evidence
    def store_evidence(self, ev: EvidenceRecord) -> int:
        with self._connection() as conn:
            cur = conn.execute(
                """INSERT INTO evidence
                   (session_id, timestamp, tool, operation, target, command,
                    stdout, stderr, exit_code, parsed, notes)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ev.session_id, ev.timestamp, ev.tool, ev.operation,
                    ev.target, ev.command, ev.stdout, ev.stderr, ev.exit_code,
                    json.dumps(ev.parsed) if ev.parsed else None, ev.notes,
                ),
            )
            return cur.lastrowid or 0

    def get_evidence(self, session_id: str) -> List[EvidenceRecord]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE session_id=? ORDER BY timestamp",
                (session_id,),
            ).fetchall()
        return [
            EvidenceRecord(
                id=r["id"], session_id=r["session_id"], timestamp=r["timestamp"],
                tool=r["tool"], operation=r["operation"], target=r["target"],
                command=r["command"], stdout=r["stdout"], stderr=r["stderr"],
                exit_code=r["exit_code"],
                parsed=json.loads(r["parsed"]) if r["parsed"] else None,
                notes=r["notes"],
            )
            for r in rows
        ]

    # Findings
    def store_finding(self, finding: Finding) -> int:
        with self._connection() as conn:
            cur = conn.execute(
                """INSERT INTO findings
                   (session_id, timestamp, title, severity, confidence, affected_asset,
                    description, evidence, potential_impact, remediation, finding_refs,
                    detection_source, is_observed)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    finding.session_id, finding.timestamp, finding.title,
                    finding.severity, finding.confidence, finding.affected_asset,
                    finding.description, finding.evidence, finding.potential_impact,
                    finding.remediation, json.dumps(finding.references),
                    finding.detection_source, int(finding.is_observed),
                ),
            )
            return cur.lastrowid or 0

    def get_findings(self, session_id: str) -> List[Finding]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id=? ORDER BY severity DESC, timestamp",
                (session_id,),
            ).fetchall()
        return [
            Finding(
                id=r["id"], session_id=r["session_id"], timestamp=r["timestamp"],
                title=r["title"], severity=r["severity"], confidence=r["confidence"],
                affected_asset=r["affected_asset"], description=r["description"],
                evidence=r["evidence"], potential_impact=r["potential_impact"],
                remediation=r["remediation"],
                references=json.loads(r["finding_refs"]) if r["finding_refs"] else [],
                detection_source=r["detection_source"],
                is_observed=bool(r["is_observed"]),
            )
            for r in rows
        ]

    # Replay log
    def log_action(self, session_id: str, action: str, details: str = "") -> None:
        ts = datetime.now().isoformat()
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO replay_log (session_id, timestamp, action, details) VALUES (?,?,?,?)",
                (session_id, ts, action, details),
            )

    def get_replay_log(self, session_id: str) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM replay_log WHERE session_id=? ORDER BY timestamp",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]


_store: Optional[EvidenceStore] = None


def get_store() -> EvidenceStore:
    global _store
    if _store is None:
        _store = EvidenceStore()
    return _store

"""Report manager — coordinates all report formats."""
from __future__ import annotations

from pathlib import Path
import re
from typing import Optional

from kali_mind.config import settings
from kali_mind.evidence.store import get_store


class ReportManager:
    def __init__(self, reports_dir: Optional[Path] = None) -> None:
        self.reports_dir = reports_dir or settings.reports_dir
        existed = self.reports_dir.exists()
        self.reports_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not existed:
            try:
                self.reports_dir.chmod(0o700)
            except OSError:
                pass
        self.store = get_store()

    def generate_all(self, session_id: str) -> dict[str, Path]:
        session = self.store.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")

        evidence = self.store.get_evidence(session_id)
        findings = self.store.get_findings(session_id)
        # Session names can be imported from external bundles; sanitize the name and
        # include the session ID to prevent path traversal and accidental overwrites.
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", session.name).strip("_-").lower()[:60] or "session"
        safe_id = re.sub(r"[^a-zA-Z0-9_-]+", "_", session_id).strip("_-")[:80] or "unknown"
        basename = f"{slug}_{safe_id}"

        generated = {}

        # Markdown
        md_path = self.reports_dir / f"{basename}.md"
        from kali_mind.reporting.markdown import generate_markdown
        md_path.write_text(generate_markdown(session, evidence, findings))
        md_path.chmod(0o600)
        generated["markdown"] = md_path

        # HTML
        html_path = self.reports_dir / f"{basename}.html"
        from kali_mind.reporting.html import generate_html
        html_path.write_text(generate_html(session, evidence, findings))
        html_path.chmod(0o600)
        generated["html"] = html_path

        # JSON
        json_path = self.reports_dir / f"{basename}.json"
        from kali_mind.reporting.json_report import generate_json
        json_path.write_text(generate_json(session, evidence, findings))
        json_path.chmod(0o600)
        generated["json"] = json_path

        # SARIF
        sarif_path = self.reports_dir / f"{basename}.sarif"
        from kali_mind.reporting.json_report import generate_sarif
        sarif_path.write_text(generate_sarif(session, evidence, findings))
        sarif_path.chmod(0o600)
        generated["sarif"] = sarif_path

        # PDF
        pdf_path = self.reports_dir / f"{basename}.pdf"
        from kali_mind.reporting.pdf import generate_pdf
        generate_pdf(session, evidence, findings, pdf_path)
        if pdf_path.exists():
            pdf_path.chmod(0o600)
        generated["pdf"] = pdf_path

        return generated

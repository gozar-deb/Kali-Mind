"""PDF report generator using ReportLab."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import List
from xml.sax.saxutils import escape as _xml_escape

from kali_mind import __version__
from kali_mind.evidence.store import EvidenceRecord, Finding, Session

_SEVERITY_COLORS = {
    "critical": (0.9, 0.1, 0.1),
    "high": (1.0, 0.4, 0.2),
    "medium": (1.0, 0.85, 0.0),
    "low": (0.3, 0.76, 0.97),
    "informational": (0.6, 0.6, 0.6),
}

_BG = (0.05, 0.067, 0.09)
_SURFACE = (0.086, 0.106, 0.133)
_TEXT = (0.788, 0.820, 0.851)
_ACCENT = (0.345, 0.651, 1.0)


def generate_pdf(
    session: Session,
    evidence: List[EvidenceRecord],
    findings: List[Finding],
    output_path: Path,
) -> None:
    """Generate a PDF security report."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )

        styles = getSampleStyleSheet()
        style_normal = ParagraphStyle(
            "normal",
            fontName="Courier",
            fontSize=9,
            textColor=colors.HexColor("#c9d1d9"),
            leading=14,
        )
        style_h1 = ParagraphStyle(
            "h1",
            fontName="Courier-Bold",
            fontSize=20,
            textColor=colors.HexColor("#58a6ff"),
        )
        style_h2 = ParagraphStyle(
            "h2",
            fontName="Courier-Bold",
            fontSize=13,
            textColor=colors.HexColor("#58a6ff"),
            spaceBefore=12,
        )
        style_h3 = ParagraphStyle(
            "h3",
            fontName="Courier-Bold",
            fontSize=11,
            textColor=colors.HexColor("#c9d1d9"),
            spaceBefore=8,
        )
        style_code = ParagraphStyle(
            "code",
            fontName="Courier",
            fontSize=8,
            textColor=colors.HexColor("#8b949e"),
            backColor=colors.HexColor("#161b22"),
            leftIndent=10,
        )

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))
        counts = {s: len([f for f in findings if f.severity == s]) for s in severity_order}

        story = []

        # Header
        story.append(Paragraph("⚔ KALI-MIND SECURITY REPORT", style_h1))
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph(f"Session: {_xml_escape(str(session.name))} | {now}", style_normal))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#30363d")))
        story.append(Spacer(1, 6 * mm))

        # Summary table
        story.append(Paragraph("Executive Summary", style_h2))
        sum_data = [["Severity", "Count"]]
        for sev, count in counts.items():
            sum_data.append([sev.upper(), str(count)])

        sum_table = Table(sum_data, colWidths=[80 * mm, 40 * mm])
        sum_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#21262d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#58a6ff")),
            ("FONTNAME", (0, 0), (-1, -1), "Courier"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#c9d1d9")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0d1117"), colors.HexColor("#161b22")]),
        ]))
        story.append(sum_table)
        story.append(Spacer(1, 6 * mm))

        # Findings
        story.append(Paragraph("Findings", style_h2))
        if not findings_sorted:
            story.append(Paragraph("No findings recorded for this session.", style_normal))
        else:
            for i, f in enumerate(findings_sorted, 1):
                sev_color = colors.Color(*_SEVERITY_COLORS.get(f.severity, (0.6, 0.6, 0.6)))
                src = "OBSERVED" if f.is_observed else "AI INFERENCE"

                story.append(Paragraph(f"#{i:03d} — {_xml_escape(str(f.title))}", style_h3))
                detail_data = [
                    ["Severity", f.severity.upper()],
                    ["Confidence", f.confidence.capitalize()],
                    ["Asset", f.affected_asset],
                    ["Source", src],
                    ["Timestamp", f.timestamp],
                ]
                dt = Table(detail_data, colWidths=[50 * mm, 120 * mm])
                dt.setStyle(TableStyle([
                    ("FONTNAME", (0, 0), (-1, -1), "Courier"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#8b949e")),
                    ("TEXTCOLOR", (1, 0), (1, 0), sev_color),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#0d1117"), colors.HexColor("#161b22")]),
                ]))
                story.append(dt)
                story.append(Spacer(1, 2 * mm))
                if f.description:
                    story.append(Paragraph(_xml_escape(str(f.description)), style_normal))
                if f.remediation:
                    story.append(Paragraph(f"Remediation: {_xml_escape(str(f.remediation))}", style_normal))
                story.append(Spacer(1, 4 * mm))

        # Command history
        story.append(Paragraph("Command History", style_h2))
        if evidence:
            cmd_data = [["#", "Tool", "Operation", "Target", "Exit"]]
            for i, ev in enumerate(evidence, 1):
                cmd_data.append([str(i), ev.tool, ev.operation, ev.target[:40], str(ev.exit_code)])
            cmd_table = Table(cmd_data, colWidths=[10 * mm, 30 * mm, 35 * mm, 70 * mm, 15 * mm])
            cmd_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#21262d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#58a6ff")),
                ("FONTNAME", (0, 0), (-1, -1), "Courier"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#c9d1d9")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#0d1117"), colors.HexColor("#161b22")]),
            ]))
            story.append(cmd_table)
        else:
            story.append(Paragraph("No commands recorded.", style_normal))

        # Footer
        story.append(Spacer(1, 10 * mm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))
        story.append(Paragraph(f"Generated by Kali-Mind v{__version__} — {now}", style_code))

        doc.build(story)

    except ImportError:
        # Fallback: write plaintext
        output_path.write_text(
            f"Kali-Mind Report — {session.name}\n"
            f"Generated: {datetime.now().isoformat()}\n\n"
            f"Findings: {len(findings)}\n"
            f"Evidence: {len(evidence)}\n\n"
            "(Install reportlab for full PDF output)"
        )

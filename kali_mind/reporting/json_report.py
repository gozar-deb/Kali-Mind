"""JSON and SARIF report generators."""
from __future__ import annotations

import json
from datetime import datetime
from typing import List

from kali_mind import __version__
from kali_mind.evidence.store import EvidenceRecord, Finding, Session


def generate_json(
    session: Session,
    evidence: List[EvidenceRecord],
    findings: List[Finding],
) -> str:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    counts = {s: len([f for f in findings if f.severity == s]) for s in severity_order}

    data = {
        "report_version": "1.0",
        "generated": datetime.now().isoformat(),
        "generator": f"Kali-Mind v{__version__}",
        "session": {
            "id": session.id,
            "name": session.name,
            "created_at": session.created_at,
            "status": session.status,
            "scope": session.scope,
            "notes": session.notes,
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": counts,
            "total_commands": len(evidence),
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "affected_asset": f.affected_asset,
                "description": f.description,
                "evidence": f.evidence,
                "potential_impact": f.potential_impact,
                "remediation": f.remediation,
                "references": f.references,
                "detection_source": f.detection_source,
                "is_observed": f.is_observed,
                "timestamp": f.timestamp,
            }
            for f in findings
        ],
        "evidence": [
            {
                "id": ev.id,
                "tool": ev.tool,
                "operation": ev.operation,
                "target": ev.target,
                "command": ev.command,
                "exit_code": ev.exit_code,
                "timestamp": ev.timestamp,
                "parsed": ev.parsed,
            }
            for ev in evidence
        ],
    }
    return json.dumps(data, indent=2)


def generate_sarif(
    session: Session,
    evidence: List[EvidenceRecord],
    findings: List[Finding],
) -> str:
    """Generate SARIF 2.1.0 format report."""
    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "informational": "none",
    }

    results = []
    for f in findings:
        results.append({
            "ruleId": f.title.lower().replace(" ", "-"),
            "level": severity_map.get(f.severity, "none"),
            "message": {
                "text": f.description
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.affected_asset
                        }
                    }
                }
            ],
            "properties": {
                "confidence": f.confidence,
                "remediation": f.remediation,
                "is_observed": f.is_observed,
            }
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Kali-Mind",
                        "version": __version__,
                        "informationUri": "https://github.com/kali-mind/kali-mind",
                        "rules": []
                    }
                },
                "results": results,
                "properties": {
                    "session_id": session.id,
                    "session_name": session.name,
                    "generated": datetime.now().isoformat(),
                }
            }
        ]
    }
    return json.dumps(sarif, indent=2)

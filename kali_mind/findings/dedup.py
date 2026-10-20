"""Finding deduplication and severity calibration."""
from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from typing import Dict

logger = logging.getLogger(__name__)

SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}


def _value(finding, name: str, default=None):
    """Read a field from either a mapping or a model without assuming both APIs."""
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _fingerprint(finding) -> str:
    """Stable id from title + asset."""
    title = str(_value(finding, "title", "") or "").lower().strip()
    asset = str(_value(finding, "affected_asset", "") or "").lower().strip()
    key = f"{title}|{asset}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def deduplicate_findings(findings: list) -> list:
    """Merge findings with the same fingerprint; keep highest severity and merge evidence."""
    groups: Dict[str, list] = defaultdict(list)
    for f in findings:
        groups[_fingerprint(f)].append(f)

    merged = []
    for fp, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue
        # Prefer highest severity
        def sev(f):
            severity = _value(f, "severity", "informational") or "informational"
            return SEVERITY_RANK.get(str(severity).lower(), 0)

        best = max(group, key=sev)
        # Merge evidence strings if attributes exist
        evidences = []
        for f in group:
            ev = _value(f, "evidence", "")
            if ev and ev not in evidences:
                evidences.append(str(ev))
        if hasattr(best, "evidence") and evidences:
            best.evidence = "\n---\n".join(evidences)[:5000]
        elif isinstance(best, dict) and evidences:
            best["evidence"] = "\n---\n".join(evidences)[:5000]
        merged.append(best)
        logger.debug("Deduped %d findings into one (fp=%s)", len(group), fp)
    return merged


def calibrate_severity(finding, *, boost_if_observed: bool = True) -> str:
    """Adjust severity based on confidence and observation status."""
    sev = str(_value(finding, "severity", "informational") or "informational").lower()
    conf = str(_value(finding, "confidence", "low") or "low").lower()
    observed = _value(finding, "is_observed", False)

    rank = SEVERITY_RANK.get(sev, 1)
    if conf == "low" and rank > 2:
        rank -= 1  # dampen low-confidence high severity
    if boost_if_observed and observed and rank < 5:
        rank = min(5, rank + 0)  # keep as-is for observed; room for future boost rules
    inv = {v: k for k, v in SEVERITY_RANK.items() if k != "info"}
    return inv.get(rank, sev)

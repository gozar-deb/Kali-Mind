"""Finding analyzer — correlates evidence with AI debate support."""
from __future__ import annotations

import json
import logging
import re
from typing import List

from kali_mind.ai.gateway import AIGateway
from kali_mind.ai.schemas import AIRequest, Message, Role
from kali_mind.agent.memory import AgentMemory
from kali_mind.evidence.store import EvidenceRecord, Finding

logger = logging.getLogger(__name__)

ANALYST_SYSTEM = """You are a security analyst reviewing evidence from an authorized penetration test.

Analyze the evidence and produce structured findings. Rules:
- Distinguish OBSERVED facts from AI INFERENCE (mark is_observed accordingly)
- Never hallucinate findings without evidence
- Be conservative: low confidence when evidence is ambiguous

Return a JSON array (NOT wrapped in an object):
```json
[
  {
    "title": "Short title",
    "severity": "critical|high|medium|low|informational",
    "confidence": "high|medium|low",
    "affected_asset": "host:port or URL",
    "description": "What was found",
    "evidence": "Evidence reference",
    "potential_impact": "What could happen",
    "remediation": "How to fix",
    "references": [],
    "is_observed": true
  }
]
```"""


class FindingAnalyzer:
    def __init__(self, gateway: AIGateway, memory: AgentMemory, session_id: str) -> None:
        self.gateway = gateway
        self.memory = memory
        self.session_id = session_id

    def _get_store(self):
        from kali_mind.evidence.store import get_store
        return get_store()

    async def analyze_evidence(self, evidence_records: List[EvidenceRecord]) -> List[Finding]:
        if not evidence_records:
            return []
        evidence_text = self._summarize_evidence(evidence_records)
        context = self.memory.get_context_summary()
        request = AIRequest(
            system=ANALYST_SYSTEM,
            messages=[Message(role=Role.user, content=(
                f"Session context:\n{context}\n\n"
                f"Evidence:\n{evidence_text}\n\n"
                "Return a JSON array of findings."
            ))],
            max_tokens=3000, temperature=0.1, session_id=self.session_id,
        )
        response = await self.gateway.complete_with_role(request, "analyst")
        findings = self._parse_findings(response.content)
        try:
            from kali_mind.findings.dedup import deduplicate_findings, calibrate_severity
            findings = deduplicate_findings(findings)
            for f in findings:
                f.severity = calibrate_severity(f)
        except Exception:
            pass
        store = self._get_store()
        for f in findings:
            f.session_id = self.session_id
            store.store_finding(f)
        return findings

    async def debate_finding(self, finding: Finding, providers: List[str]) -> Finding:
        """Feature #23: have multiple models verify a finding and adjust confidence."""
        request = AIRequest(
            system="You are a security expert reviewing a potential finding. "
                   "Respond with CONFIRM, REJECT, or UNCERTAIN and a one-sentence reason.",
            messages=[Message(role=Role.user, content=(
                f"Finding: {finding.title}\n"
                f"Severity: {finding.severity}\n"
                f"Description: {finding.description}\n"
                f"Evidence: {finding.evidence}\n\n"
                "Is this a valid security finding?"
            ))],
            max_tokens=200, temperature=0.1,
        )
        responses = await self.gateway.debate(request, providers)
        confirms = sum(1 for r in responses if "CONFIRM" in r.content.upper())
        rejects = sum(1 for r in responses if "REJECT" in r.content.upper())
        total = len(responses)

        if total == 0:
            return finding
        ratio = confirms / total
        if ratio >= 0.7:
            finding.confidence = "high"
        elif ratio >= 0.4:
            finding.confidence = "medium"
            finding.title = f"[DEBATED] {finding.title}"
        else:
            finding.confidence = "low"
            finding.severity = "informational"
            finding.title = f"[LIKELY FALSE POSITIVE] {finding.title}"

        finding.description += f"\n\nAI Debate: {confirms}/{total} models confirmed this finding."
        return finding

    async def correlate_all(self) -> List[Finding]:
        store = self._get_store()
        evidence = store.get_evidence(self.session_id)
        return await self.analyze_evidence(evidence)

    def _summarize_evidence(self, records: List[EvidenceRecord]) -> str:
        # Cap number of evidence records to prevent context overflow
        MAX_RECORDS = 20
        if len(records) > MAX_RECORDS:
            records = records[-MAX_RECORDS:]  # use most recent
        lines = []
        for ev in records:
            lines.append(f"\n--- {ev.tool.upper()} ({ev.operation}) → {ev.target} ---")
            lines.append(f"Command: {ev.command}")
            if ev.parsed:
                # Cap each evidence entry to prevent context overflow
                parsed_str = json.dumps(ev.parsed, indent=2)
                lines.append(f"Parsed: {parsed_str[:1500]}")
            elif ev.stdout:
                lines.append(f"Output:\n{ev.stdout[:800]}")
            if ev.exit_code != 0:
                lines.append(f"Exit code: {ev.exit_code}")
        return "\n".join(lines)

    def _parse_findings(self, content: str) -> List[Finding]:
        """FIX #5: handle both bare arrays and wrapped dicts."""
        # Try ```json ... ``` block first
        json_pattern = re.compile(r"```(?:json)?\s*(\[.*?\]|\{.*?\})\s*```", re.DOTALL)
        match = json_pattern.search(content)
        raw_json = match.group(1) if match else None

        # Fallback: find any array or object
        if not raw_json:
            arr = re.search(r"\[.*\]", content, re.DOTALL)
            obj = re.search(r"\{.*\}", content, re.DOTALL)
            raw_json = (arr.group(0) if arr else None) or (obj.group(0) if obj else None)

        if not raw_json:
            return []

        try:
            data = json.loads(raw_json)
            # FIX #5: unwrap dict wrappers like {"findings": [...]}
            if isinstance(data, dict):
                for key in ("findings", "results", "vulnerabilities", "issues"):
                    if key in data and isinstance(data[key], list):
                        data = data[key]
                        break
                else:
                    return []

            findings = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                # Normalize severity/confidence to lowercase (AI may return uppercase)
                raw_sev = str(item.get("severity", "informational")).lower().strip()
                raw_conf = str(item.get("confidence", "low")).lower().strip()
                # Map common variants
                sev_map = {"info": "informational", "critical": "critical", "high": "high",
                           "medium": "medium", "med": "medium", "low": "low",
                           "informational": "informational", "none": "informational"}
                conf_map = {"high": "high", "medium": "medium", "med": "medium",
                            "low": "low", "certain": "high", "likely": "medium"}
                f = Finding(
                    session_id=self.session_id,
                    title=item.get("title", "Unnamed Finding"),
                    severity=sev_map.get(raw_sev, "informational"),
                    confidence=conf_map.get(raw_conf, "low"),
                    affected_asset=item.get("affected_asset", "unknown"),
                    description=item.get("description", ""),
                    evidence=item.get("evidence", ""),
                    potential_impact=item.get("potential_impact", ""),
                    remediation=item.get("remediation", ""),
                    references=item.get("references", []),
                    detection_source="AI correlation",
                    is_observed=item.get("is_observed", False),
                )
                findings.append(f)
            return findings
        except Exception as e:
            logger.warning("Failed to parse AI findings JSON: %s", e)
            return []

"""Feature #27: CVE enrichment — attach CVE data to findings via NVD API."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import httpx

from kali_mind.evidence.store import Finding

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class CVEEnricher:
    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = api_key  # NVD API key is optional (higher rate limits with key)

    async def enrich_finding(self, finding: Finding) -> Finding:
        """Detect CVE mentions in a finding and attach NVD metadata."""
        text = f"{finding.title} {finding.description} {finding.evidence}"
        cve_ids = list(set(CVE_PATTERN.findall(text.upper())))
        if not cve_ids:
            return finding

        enriched_refs = list(finding.references)
        summaries = []

        for cve_id in cve_ids[:3]:  # limit to 3 CVEs per finding
            cve_data = await self._fetch_cve(cve_id)
            if cve_data:
                cvss = cve_data.get("cvss_score")
                summary = cve_data.get("description", "")[:200]
                summaries.append(f"{cve_id} (CVSS: {cvss}): {summary}")
                if cve_data.get("url") and cve_data["url"] not in enriched_refs:
                    enriched_refs.append(cve_data["url"])

        if summaries:
            finding.description += "\n\nCVE Details:\n" + "\n".join(summaries)
            finding.references = enriched_refs

        return finding

    async def enrich_findings(self, findings: List[Finding]) -> List[Finding]:
        """Enrich all findings in a list."""
        enriched = []
        for f in findings:
            enriched.append(await self.enrich_finding(f))
        return enriched

    async def _fetch_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        try:
            params = {"cveId": cve_id}
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(NVD_API, params=params, headers=headers)
                if resp.status_code != 200:
                    return None
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return None
                cve = vulns[0].get("cve", {})
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                cvss_score = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cvss_data = metrics[key][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        break
                return {
                    "id": cve_id,
                    "description": desc,
                    "cvss_score": cvss_score,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
        except Exception:
            return None

    def extract_cve_ids(self, text: str) -> List[str]:
        return list(set(CVE_PATTERN.findall(text.upper())))

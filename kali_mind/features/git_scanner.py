"""Feature #29: Git/GitHub secret scanning using trufflehog and gitleaks."""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List


class GitScanner:
    """Scans git repositories for exposed secrets and credentials."""

    TOOLS = ["trufflehog", "gitleaks", "git-secrets"]

    def detect_tools(self) -> List[str]:
        return [t for t in self.TOOLS if shutil.which(t)]

    async def scan_repo(self, repo_path: str) -> Dict[str, Any]:
        """Scan a local repo for secrets using available tools."""
        available = self.detect_tools()
        results: Dict[str, Any] = {"tool": None, "findings": [], "errors": [], "repo": repo_path}

        if "gitleaks" in available:
            r = await self._run_gitleaks(repo_path)
            results["tool"] = "gitleaks"
            results.update(r)
        elif "trufflehog" in available:
            r = await self._run_trufflehog(repo_path)
            results["tool"] = "trufflehog"
            results.update(r)
        else:
            results["errors"].append(
                "No secret scanning tools found. Install: pip install trufflehog "
                "or: sudo apt install gitleaks"
            )
        return results

    async def scan_github_repo(self, repo_url: str) -> Dict[str, Any]:
        """Scan a remote GitHub repo URL."""
        available = self.detect_tools()
        results: Dict[str, Any] = {"tool": None, "findings": [], "errors": [], "repo": repo_url}

        if "trufflehog" in available:
            proc = await asyncio.create_subprocess_exec(
                "trufflehog", "github", "--repo", repo_url, "--json",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            from kali_mind.execution.process_utils import communicate_with_timeout
            stdout, stderr = await communicate_with_timeout(proc, timeout=120)
            results["tool"] = "trufflehog"
            results["findings"] = self._parse_trufflehog(stdout.decode(errors="replace"))
        else:
            results["errors"].append("trufflehog not found. Install: pip install trufflehog")
        return results

    async def _run_gitleaks(self, path: str) -> Dict[str, Any]:
        findings = []
        # Unique private temporary directory avoids cross-run collisions and /tmp
        # symlink attacks against a predictable report filename.
        with tempfile.TemporaryDirectory(prefix="kali-mind-gitleaks-") as tmpdir:
            report = Path(tmpdir) / "report.json"
            proc = await asyncio.create_subprocess_exec(
                "gitleaks", "detect", "--source", path, "--report-format", "json",
                "--report-path", str(report), "--no-git",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            from kali_mind.execution.process_utils import communicate_with_timeout
            stdout, stderr = await communicate_with_timeout(proc, timeout=60)
            try:
                if report.exists():
                    data = json.loads(report.read_text())
                    for item in (data or []):
                        findings.append({
                            "rule": item.get("RuleID", "unknown"),
                            "file": item.get("File", ""),
                            "line": item.get("StartLine", 0),
                            "match": item.get("Match", "")[:100],
                            "secret": item.get("Secret", "")[:20] + "...",
                        })
            except (OSError, json.JSONDecodeError, TypeError, AttributeError) as exc:
                return {"findings": [], "errors": [str(exc)]}
        return {"findings": findings}

    async def _run_trufflehog(self, path: str) -> Dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            "trufflehog", "filesystem", path, "--json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        from kali_mind.execution.process_utils import communicate_with_timeout
        stdout, stderr = await communicate_with_timeout(proc, timeout=60)
        findings = self._parse_trufflehog(stdout.decode(errors="replace"))
        return {"findings": findings}

    def _parse_trufflehog(self, stdout: str) -> List[Dict[str, Any]]:
        findings = []
        for line in stdout.strip().split("\n"):
            if not line:
                continue
            try:
                d = json.loads(line)
                findings.append({
                    "rule": d.get("DetectorName", "unknown"),
                    "file": d.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                    "verified": d.get("Verified", False),
                    "raw": str(d.get("Raw", ""))[:50] + "...",
                })
            except Exception:
                pass
        return findings

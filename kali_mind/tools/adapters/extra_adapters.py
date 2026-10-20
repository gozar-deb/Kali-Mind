"""Additional tool adapters: BloodHound, NetExec, Impacket helpers, Trivy, Semgrep."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from kali_mind.tools.adapters.base import BaseAdapter, ToolRequest
from kali_mind.tools.registry import RiskLevel


class BloodHoundAdapter(BaseAdapter):
    tool_name = "bloodhound-python"
    risk_level = RiskLevel.HIGH
    ALLOWED_OPTIONS = {"domain", "username", "collection", "nameserver", "extra_flags"}
    ALLOWED_FLAGS = {"-c", "--collectionmethod", "-d", "-u", "-ns", "--zip"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        cmd = ["bloodhound-python", "-c", str(opts.get("collection", "All"))]
        if opts.get("domain"):
            d = str(opts["domain"])
            if re.match(r"^[a-zA-Z0-9.-]+$", d):
                cmd.extend(["-d", d])
        if opts.get("username"):
            u = str(opts["username"])
            if re.match(r"^[a-zA-Z0-9._\\-]+$", u):
                cmd.extend(["-u", u])
        if opts.get("nameserver"):
            ns = str(opts["nameserver"])
            if re.match(r"^[0-9a-fA-F.:]+$", ns):
                cmd.extend(["-ns", ns])
        cmd.append("--zip")
        # Target is DC / domain controller host
        if request.target:
            cmd.extend(["-dc", request.target])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {
            "raw_summary": (stdout or stderr or "")[:2000],
            "success": exit_code == 0,
            "findings": [],
        }

    def supported_operations(self) -> List[str]:
        return ["collect", "all"]


class NetExecAdapter(BaseAdapter):
    tool_name = "netexec"
    risk_level = RiskLevel.HIGH
    ALLOWED_OPTIONS = {"protocol", "module", "username", "extra_flags"}
    ALLOWED_FLAGS = {"-u", "-p", "-M", "--shares", "--users", "--sessions"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        proto = str(opts.get("protocol", "smb"))
        if proto not in {"smb", "ssh", "winrm", "ldap", "rdp", "ftp", "wmi"}:
            proto = "smb"
        cmd = ["netexec", proto, request.target]
        if opts.get("module"):
            mod = str(opts["module"])
            if re.match(r"^[a-zA-Z0-9_-]+$", mod):
                cmd.extend(["-M", mod])
        if opts.get("username"):
            u = str(opts["username"])
            if re.match(r"^[a-zA-Z0-9._\\$-]+$", u):
                cmd.extend(["-u", u])
        for flag in opts.get("extra_flags") or []:
            if str(flag) in self.ALLOWED_FLAGS:
                cmd.append(str(flag))
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        hosts = []
        for line in (stdout or "").splitlines():
            if "SMB" in line or "SSH" in line or "WINRM" in line:
                hosts.append(line.strip())
        return {"hosts": hosts, "raw_summary": (stdout or "")[:3000], "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["enum", "module", "shares"]


class TrivyAdapter(BaseAdapter):
    tool_name = "trivy"
    risk_level = RiskLevel.LOW
    ALLOWED_OPTIONS = {"scan_type", "severity", "format", "extra_flags"}
    ALLOWED_FLAGS = {"--quiet", "--severity", "--format", "image", "fs", "repo", "config"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        scan_type = str(opts.get("scan_type", "fs"))
        if scan_type not in {"image", "fs", "repo", "config"}:
            scan_type = "fs"
        cmd = ["trivy", scan_type, "--quiet"]
        if request.output_format == "json" or opts.get("format") == "json":
            cmd.extend(["--format", "json"])
        if opts.get("severity"):
            sev = str(opts["severity"])
            if re.match(r"^[A-Z,]+$", sev):
                cmd.extend(["--severity", sev])
        cmd.append(request.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        findings = []
        try:
            data = json.loads(stdout or "{}")
            for result in data.get("Results", []) if isinstance(data, dict) else []:
                for vuln in result.get("Vulnerabilities") or []:
                    findings.append({
                        "title": vuln.get("VulnerabilityID", "vuln"),
                        "severity": (vuln.get("Severity") or "unknown").lower(),
                        "description": vuln.get("Title") or vuln.get("Description", ""),
                        "package": vuln.get("PkgName"),
                    })
        except (json.JSONDecodeError, TypeError, ValueError):
            if stdout:
                findings.append({"raw": stdout[:500]})
        return {"findings": findings, "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["image", "fs", "repo", "config"]


class SemgrepAdapter(BaseAdapter):
    tool_name = "semgrep"
    risk_level = RiskLevel.LOW
    ALLOWED_OPTIONS = {"config", "extra_flags"}
    ALLOWED_FLAGS = {"--config", "--json", "--quiet"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        cmd = ["semgrep", "--quiet"]
        if request.output_format == "json":
            cmd.append("--json")
        cfg = str(opts.get("config", "auto"))
        if re.match(r"^[a-zA-Z0-9_./:@-]+$", cfg) and ".." not in cfg:
            cmd.extend(["--config", cfg])
        cmd.append(request.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        findings = []
        try:
            data = json.loads(stdout or "{}")
            for r in data.get("results", []):
                findings.append({
                    "title": r.get("check_id", "finding"),
                    "severity": str(r.get("extra", {}).get("severity", "medium")).lower(),
                    "path": r.get("path"),
                    "description": r.get("extra", {}).get("message", ""),
                })
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        return {"findings": findings, "success": exit_code in (0, 1)}

    def supported_operations(self) -> List[str]:
        return ["scan"]


class ImpacketSecretsdumpAdapter(BaseAdapter):
    """Authorized-lab only — high risk credential dumping helper."""
    tool_name = "secretsdump.py"
    risk_level = RiskLevel.CRITICAL
    ALLOWED_OPTIONS = {"just_dc_ntlm", "extra_flags"}
    ALLOWED_FLAGS = {"-just-dc-ntlm", "-outputfile"}

    def build_command(self, request: ToolRequest) -> List[str]:
        # target format expected: domain/user@host — still validated by base unsafe-char check
        cmd = ["secretsdump.py", request.target]
        opts = self.safe_options(request)
        if opts.get("just_dc_ntlm"):
            cmd.append("-just-dc-ntlm")
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        creds = []
        for line in (stdout or "").splitlines():
            if ":::" in line and not line.startswith("["):
                creds.append({"raw": line.strip()})
        return {"credentials": creds, "raw_summary": (stdout or "")[:2000], "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["dump", "just_dc_ntlm"]

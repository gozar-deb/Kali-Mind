"""Additional offensive / specialized adapters (authorized lab use only)."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from kali_mind.tools.adapters.base import BaseAdapter, ToolRequest
from kali_mind.tools.registry import RiskLevel


class CrackMapExecAdapter(BaseAdapter):
    """Alias-compatible CME / netexec style."""
    tool_name = "crackmapexec"
    risk_level = RiskLevel.HIGH
    ALLOWED_OPTIONS = {"protocol", "module", "username", "extra_flags"}
    ALLOWED_FLAGS = {"-u", "-p", "-M", "--shares"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        proto = str(opts.get("protocol", "smb"))
        if proto not in {"smb", "ssh", "winrm", "ldap", "rdp"}:
            proto = "smb"
        # Prefer netexec binary if present conceptually; argv still says crackmapexec
        cmd = ["crackmapexec", proto, request.target]
        if opts.get("module"):
            mod = str(opts["module"])
            if re.match(r"^[a-zA-Z0-9_-]+$", mod):
                cmd.extend(["-M", mod])
        if opts.get("username"):
            u = str(opts["username"])
            if re.match(r"^[a-zA-Z0-9._\\$-]+$", u):
                cmd.extend(["-u", u])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {"raw_summary": (stdout or "")[:3000], "hosts": [request_target_safe(stdout)], "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["enum", "module"]


def request_target_safe(stdout: str) -> str:
    for line in (stdout or "").splitlines():
        if line.strip():
            return line.strip()[:80]
    return ""


class ResponderAdapter(BaseAdapter):
    tool_name = "responder"
    risk_level = RiskLevel.CRITICAL
    ALLOWED_OPTIONS = {"interface", "extra_flags"}
    ALLOWED_FLAGS = {"-I", "-w", "-f", "-v"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        iface = str(opts.get("interface", request.target or "eth0"))
        if not re.match(r"^[a-zA-Z0-9._-]+$", iface):
            iface = "eth0"
        return ["responder", "-I", iface, "-w"]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {"raw_summary": (stdout or stderr or "")[:2000], "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["listen"]


class EvilWinrmAdapter(BaseAdapter):
    tool_name = "evil-winrm"
    risk_level = RiskLevel.CRITICAL
    ALLOWED_OPTIONS = {"user", "extra_flags"}
    ALLOWED_FLAGS = {"-i", "-u", "-p"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        cmd = ["evil-winrm", "-i", request.target]
        if opts.get("user"):
            u = str(opts["user"])
            if re.match(r"^[a-zA-Z0-9._\\$-]+$", u):
                cmd.extend(["-u", u])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {"raw_summary": (stdout or "")[:2000], "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["shell"]


class ImpacketWmiexecAdapter(BaseAdapter):
    tool_name = "wmiexec.py"
    risk_level = RiskLevel.CRITICAL
    ALLOWED_OPTIONS = {"extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        return ["wmiexec.py", request.target]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {"raw_summary": (stdout or "")[:2000], "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["exec"]


class ImpacketPsexecAdapter(BaseAdapter):
    tool_name = "psexec.py"
    risk_level = RiskLevel.CRITICAL
    ALLOWED_OPTIONS = {"extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        return ["psexec.py", request.target]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {"raw_summary": (stdout or "")[:2000], "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["exec"]


class AwsCliAdapter(BaseAdapter):
    tool_name = "aws"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {"service", "operation", "extra_flags"}
    ALLOWED_FLAGS = {"--output", "--region"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        svc = str(opts.get("service", "sts"))
        op = str(opts.get("operation", "get-caller-identity"))
        if not re.match(r"^[a-z0-9-]+$", svc) or not re.match(r"^[a-z0-9-]+$", op):
            svc, op = "sts", "get-caller-identity"
        return ["aws", svc, op, "--output", "json"]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {"raw_summary": (stdout or "")[:3000], "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["sts", "s3", "ec2"]


class AzureCliAdapter(BaseAdapter):
    tool_name = "az"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {"command", "extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        # Restrict to account show by default
        return ["az", "account", "show", "-o", "json"]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {"raw_summary": (stdout or "")[:3000], "success": exit_code == 0}

    def supported_operations(self) -> List[str]:
        return ["account"]

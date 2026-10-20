"""Nmap tool adapter."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from kali_mind.tools.adapters.base import BaseAdapter, ToolRequest
from kali_mind.tools.registry import RiskLevel


class NmapAdapter(BaseAdapter):
    tool_name = "nmap"
    risk_level = RiskLevel.MEDIUM

    ALLOWED_OPTIONS = {"ports", "timing", "scripts", "top_ports", "extra_flags"}
    ALLOWED_FLAGS = {
        "-Pn", "-n", "-v", "-vv", "--open", "-A", "-sV", "-sC", "-sS", "-sU",
        "-O", "-F", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    }

    OPERATIONS = {
        "ping_scan": ["-sn"],
        "port_scan": ["-p-", "--open"],
        "service_scan": ["-sV", "-sC"],
        "os_detection": ["-O"],
        "quick_scan": ["-T4", "-F"],
        "full_scan": ["-T4", "-A", "-v"],
        "stealth_scan": ["-sS"],
        "udp_scan": ["-sU"],
        "version_scan": ["-sV"],
        "script_scan": ["-sC"],
        "top_ports": ["--top-ports", "1000"],
        "aggressive": ["-A"],
    }

    def build_command(self, request: ToolRequest) -> List[str]:
        cmd = ["nmap"]
        ops = self.OPERATIONS.get(request.operation, ["-sV"])
        cmd.extend(ops)

        opts = self.safe_options(request)

        if request.output_format == "xml":
            cmd.extend(["-oX", "-"])
        elif request.output_format == "json":
            cmd.extend(["-oX", "-"])

        if "ports" in opts:
            cmd.extend(["-p", str(opts["ports"])])
        if "timing" in opts:
            timing = str(opts["timing"]).strip()
            if timing.isdigit() and 0 <= int(timing) <= 5:
                cmd.append(f"-T{timing}")
        if "scripts" in opts:
            # Only allow safe script names (alphanumeric, underscore, comma, slash)
            scripts = str(opts["scripts"])
            if re.match(r"^[a-zA-Z0-9_,/\-]+$", scripts):
                cmd.extend([f"--script={scripts}"])
        if "top_ports" in opts:
            top = str(opts["top_ports"])
            if top.isdigit():
                cmd.extend(["--top-ports", top])

        extra = opts.get("extra_flags") or []
        for flag in extra:
            flag_str = str(flag).strip()
            if flag_str in self.ALLOWED_FLAGS:
                cmd.append(flag_str)

        cmd.append(request.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "hosts": [],
            "ports": [],
            "services": [],
            "os": [],
            "errors": [],
        }
        if exit_code != 0 and stderr:
            result["errors"].append(stderr)
            return result

        # Parse open ports
        port_pattern = re.compile(
            r"(\d+)/(\w+)\s+(\w+)\s+(\S+)\s*(.*)"
        )
        host_pattern = re.compile(r"Nmap scan report for (.+)")
        os_pattern = re.compile(r"OS details: (.+)")

        current_host = None
        for line in stdout.split("\n"):
            hm = host_pattern.search(line)
            if hm:
                current_host = hm.group(1).strip()
                result["hosts"].append(current_host)

            pm = port_pattern.search(line)
            if pm and pm.group(3) == "open":
                port_info = {
                    "host": current_host,
                    "port": int(pm.group(1)),
                    "protocol": pm.group(2),
                    "state": pm.group(3),
                    "service": pm.group(4),
                    "version": pm.group(5).strip(),
                }
                result["ports"].append(port_info)
                if port_info["service"] not in result["services"]:
                    result["services"].append(port_info["service"])

            om = os_pattern.search(line)
            if om:
                result["os"].append(om.group(1))

        return result

    def supported_operations(self) -> List[str]:
        return list(self.OPERATIONS.keys())

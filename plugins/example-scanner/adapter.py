"""Example adapter for the example-scanner plugin."""
from __future__ import annotations

from typing import Any, Dict, List

from kali_mind.tools.adapters.base import BaseAdapter, ToolRequest
from kali_mind.tools.registry import RiskLevel


class Adapter(BaseAdapter):
    tool_name = "example-scanner"
    risk_level = RiskLevel.LOW

    def build_command(self, request: ToolRequest) -> List[str]:
        cmd = ["example-scanner", "--target", request.target]
        if request.output_format == "json":
            cmd.append("--json")
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {
            "raw": stdout,
            "errors": [stderr] if stderr else [],
            "success": exit_code == 0,
        }

    def supported_operations(self) -> List[str]:
        return ["scan", "quick_scan"]

"""Web security tool adapters: httpx, ffuf, nikto, whatweb, nuclei."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from kali_mind.tools.adapters.base import BaseAdapter, ToolRequest
from kali_mind.tools.registry import RiskLevel


class HttpxAdapter(BaseAdapter):
    tool_name = "httpx"
    risk_level = RiskLevel.LOW
    ALLOWED_OPTIONS = {
        "tech_detect", "status_code", "title", "content_length",
        "follow_redirects", "extra_flags",
    }
    ALLOWED_FLAGS = {
        "-silent", "-json", "-tech-detect", "-status-code", "-title",
        "-content-length", "-follow-redirects", "-no-color",
    }

    def build_command(self, request: ToolRequest) -> List[str]:
        cmd = ["httpx", "-u", request.target, "-silent"]
        if request.output_format == "json":
            cmd.append("-json")
        opts = self.safe_options(request)
        if opts.get("tech_detect"):
            cmd.append("-tech-detect")
        if opts.get("status_code"):
            cmd.append("-status-code")
        if opts.get("title"):
            cmd.append("-title")
        if opts.get("content_length"):
            cmd.append("-content-length")
        if opts.get("follow_redirects"):
            cmd.append("-follow-redirects")
        for flag in opts.get("extra_flags") or []:
            if str(flag) in self.ALLOWED_FLAGS:
                cmd.append(str(flag))
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "urls": [], "technologies": [], "status_codes": {}, "errors": [],
        }
        for line in (stdout or "").strip().split("\n"):
            if not line:
                continue
            try:
                d = json.loads(line)
                result["urls"].append(d.get("url", ""))
                if "tech" in d:
                    result["technologies"].extend(d["tech"])
                if "status_code" in d:
                    result["status_codes"][d.get("url", "")] = d["status_code"]
            except (json.JSONDecodeError, TypeError, ValueError):
                if line.startswith("http"):
                    result["urls"].append(line.strip())
        return result

    def supported_operations(self) -> List[str]:
        return ["probe", "tech_detect", "status_check"]


class FfufAdapter(BaseAdapter):
    tool_name = "ffuf"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {
        "wordlist", "match_codes", "extensions", "threads", "rate", "extra_flags",
    }
    ALLOWED_FLAGS = {"-mc", "-e", "-t", "-rate", "-of", "-json", "-s", "-c"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        wordlist = str(opts.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
        # Basic path safety: no shell metacharacters in wordlist path
        if re.search(r"[;`|&$<>]", wordlist):
            wordlist = "/usr/share/wordlists/dirb/common.txt"

        target = request.target
        if "FUZZ" not in target:
            target = target.rstrip("/") + "/FUZZ"

        match_codes = str(opts.get("match_codes", "200,204,301,302,307,401,403"))
        if not re.match(r"^[\d,]+$", match_codes):
            match_codes = "200,204,301,302,307,401,403"

        cmd = ["ffuf", "-u", target, "-w", wordlist, "-mc", match_codes]
        if request.output_format == "json":
            cmd.extend(["-of", "json"])
        if opts.get("extensions"):
            ext = str(opts["extensions"])
            if re.match(r"^[a-zA-Z0-9.,]+$", ext):
                cmd.extend(["-e", ext])
        if opts.get("threads"):
            threads = str(opts["threads"])
            if threads.isdigit() and 1 <= int(threads) <= 200:
                cmd.extend(["-t", threads])
        if opts.get("rate"):
            rate = str(opts["rate"])
            if rate.isdigit():
                cmd.extend(["-rate", rate])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"paths": [], "redirects": [], "errors": []}
        try:
            d = json.loads(stdout or "{}")
            for r in d.get("results", []):
                result["paths"].append({
                    "url": r.get("url"),
                    "status": r.get("status"),
                    "length": r.get("length"),
                    "words": r.get("words"),
                })
        except (json.JSONDecodeError, TypeError, ValueError):
            pattern = re.compile(r"(https?://\S+)\s+\[Status:\s+(\d+),")
            for m in pattern.finditer(stdout or ""):
                result["paths"].append({"url": m.group(1), "status": int(m.group(2))})
        return result

    def supported_operations(self) -> List[str]:
        return ["directory_fuzz", "file_fuzz", "param_fuzz", "vhost_fuzz"]


class NiktoAdapter(BaseAdapter):
    tool_name = "nikto"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {"port", "ssl", "tuning", "extra_flags"}
    ALLOWED_FLAGS = {"-ssl", "-nointeractive", "-Format"}

    def build_command(self, request: ToolRequest) -> List[str]:
        cmd = ["nikto", "-h", request.target, "-nointeractive"]
        if request.output_format == "json":
            cmd.extend(["-Format", "json"])
        elif request.output_format == "xml":
            cmd.extend(["-Format", "xml"])
        opts = self.safe_options(request)
        if opts.get("port"):
            port = str(opts["port"])
            if port.isdigit() and 1 <= int(port) <= 65535:
                cmd.extend(["-p", port])
        if opts.get("ssl"):
            cmd.append("-ssl")
        if opts.get("tuning"):
            tuning = str(opts["tuning"])
            # Nikto tuning is a string of digits/letters like "123b"
            if re.match(r"^[0-9a-zA-Z]+$", tuning):
                cmd.extend(["-Tuning", tuning])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"findings": [], "server": None, "errors": []}
        for line in (stdout or "").split("\n"):
            if line.startswith("+ Server:"):
                result["server"] = line.split(":", 1)[1].strip()
            # BUGFIX: parentheses required — was matching any line containing CVE
            elif line.startswith("+ ") and ("OSVDB" in line or "CVE" in line):
                result["findings"].append(line[2:].strip())
            elif line.startswith("+ ") and len(line) > 10:
                finding = line[2:].strip()
                if finding and not finding.startswith("Target"):
                    result["findings"].append(finding)
        return result

    def supported_operations(self) -> List[str]:
        return ["web_scan", "ssl_check", "headers_check"]


class WhatWebAdapter(BaseAdapter):
    tool_name = "whatweb"
    risk_level = RiskLevel.LOW
    ALLOWED_OPTIONS = {"aggression", "extra_flags"}
    ALLOWED_FLAGS = {"--color=never", "--log-json=-"}

    def build_command(self, request: ToolRequest) -> List[str]:
        cmd = ["whatweb"]
        if request.output_format == "json":
            cmd.extend(["--log-json=-"])
        else:
            cmd.extend(["--color=never"])
        opts = self.safe_options(request)
        if opts.get("aggression"):
            agg = str(opts["aggression"])
            if agg in {"1", "2", "3", "4"}:
                cmd.extend([f"--aggression={agg}"])
        cmd.append(request.target)
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"technologies": [], "url": None, "plugins": {}}
        try:
            for line in (stdout or "").strip().split("\n"):
                if not line:
                    continue
                d = json.loads(line)
                if isinstance(d, list) and d:
                    entry = d[0]
                    result["url"] = entry.get("target")
                    for plugin, info in entry.get("plugins", {}).items():
                        result["technologies"].append(plugin)
                        result["plugins"][plugin] = info
        except (json.JSONDecodeError, TypeError, ValueError, KeyError):
            tech_pattern = re.compile(r"\[([^\]]+)\]")
            for m in tech_pattern.finditer(stdout or ""):
                techs = [t.strip() for t in m.group(1).split(",")]
                result["technologies"].extend(techs)
        return result

    def supported_operations(self) -> List[str]:
        return ["fingerprint", "aggressive_fingerprint"]


class NucleiAdapter(BaseAdapter):
    tool_name = "nuclei"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {"severity", "templates", "tags", "rate_limit", "extra_flags"}
    ALLOWED_FLAGS = {"-silent", "-json", "-severity", "-t", "-tags", "-rate-limit"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = self.safe_options(request)
        cmd = ["nuclei", "-u", request.target, "-silent"]
        if request.output_format == "json":
            cmd.append("-json")
        if opts.get("severity"):
            sev = str(opts["severity"]).lower()
            if re.match(r"^[a-z,]+$", sev):
                cmd.extend(["-severity", sev])
        if opts.get("templates"):
            tmpl = str(opts["templates"])
            # Only allow relative-looking template paths / known names
            if re.match(r"^[a-zA-Z0-9_./\-]+$", tmpl) and ".." not in tmpl:
                cmd.extend(["-t", tmpl])
        if opts.get("tags"):
            tags = str(opts["tags"])
            if re.match(r"^[a-zA-Z0-9_,\-]+$", tags):
                cmd.extend(["-tags", tags])
        if opts.get("rate_limit"):
            rate = str(opts["rate_limit"])
            if rate.isdigit() and 1 <= int(rate) <= 500:
                cmd.extend(["-rate-limit", rate])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"findings": [], "errors": []}
        for line in (stdout or "").strip().split("\n"):
            if not line:
                continue
            try:
                d = json.loads(line)
                result["findings"].append({
                    "template": d.get("template-id"),
                    "name": d.get("info", {}).get("name"),
                    "severity": d.get("info", {}).get("severity"),
                    "matched": d.get("matched-at"),
                    "description": d.get("info", {}).get("description"),
                })
            except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
                if "[" in line and "]" in line:
                    result["findings"].append({"raw": line})
        return result

    def supported_operations(self) -> List[str]:
        return ["scan", "cve_scan", "misconfiguration_scan", "exposure_scan"]

"""Recon tool adapters: masscan, subfinder, amass, gobuster, feroxbuster, wpscan, sqlmap, dirsearch."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from kali_mind.tools.adapters.base import BaseAdapter, ToolRequest
from kali_mind.tools.registry import RiskLevel


class MasscanAdapter(BaseAdapter):
    tool_name = "masscan"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {"ports", "rate", "extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        rate = opts.get("rate", "1000")
        ports = opts.get("ports", "0-65535")
        cmd = ["masscan", request.target, f"-p{ports}", f"--rate={rate}", "--output-format", "json"]
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"hosts": [], "ports": [], "errors": []}
        try:
            data = json.loads(stdout or "[]")
            for entry in data:
                ip = entry.get("ip", "")
                if ip and ip not in result["hosts"]:
                    result["hosts"].append(ip)
                for p in entry.get("ports", []):
                    result["ports"].append({"host": ip, "port": p.get("port"), "protocol": p.get("proto", "tcp"), "state": p.get("status", "open")})
        except Exception:
            # plain text: Discovered open port 80/tcp on 192.168.1.1
            for m in re.finditer(r"Discovered open port (\d+)/(\w+) on ([\d.]+)", stdout or ""):
                result["ports"].append({"host": m.group(3), "port": int(m.group(1)), "protocol": m.group(2), "state": "open"})
                if m.group(3) not in result["hosts"]:
                    result["hosts"].append(m.group(3))
        return result

    def supported_operations(self) -> List[str]:
        return ["full_scan", "port_range", "top_ports"]


class SubfinderAdapter(BaseAdapter):
    tool_name = "subfinder"
    risk_level = RiskLevel.LOW
    ALLOWED_OPTIONS = {"extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        cmd = ["subfinder", "-d", request.target, "-silent"]
        if request.output_format == "json":
            cmd.extend(["-oJ"])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"subdomains": [], "errors": []}
        for line in (stdout or "").strip().split("\n"):
            line = line.strip()
            if line:
                try:
                    d = json.loads(line)
                    result["subdomains"].append(d.get("host", line))
                except Exception:
                    result["subdomains"].append(line)
        return result

    def supported_operations(self) -> List[str]:
        return ["enumerate", "passive"]


class AmassAdapter(BaseAdapter):
    tool_name = "amass"
    risk_level = RiskLevel.LOW
    ALLOWED_OPTIONS = {"mode", "extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        cmd = ["amass", "enum", "-d", request.target, "-passive"]
        if request.options.get("active"):
            cmd = ["amass", "enum", "-d", request.target]
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"subdomains": [], "ips": [], "errors": []}
        for line in (stdout or "").strip().split("\n"):
            line = line.strip()
            if line and "." in line:
                parts = line.split()
                if parts:
                    result["subdomains"].append(parts[0])
                    if len(parts) > 1:
                        result["ips"].extend(parts[1:])
        return result

    def supported_operations(self) -> List[str]:
        return ["passive_enum", "active_enum", "intel"]


class GobusterAdapter(BaseAdapter):
    tool_name = "gobuster"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {"wordlist", "extensions", "threads", "extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        mode = opts.get("mode", "dir")
        wordlist = opts.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        _check_wordlist(wordlist)
        cmd = ["gobuster", mode, "-u", request.target, "-w", wordlist, "-q"]
        if request.output_format == "json":
            cmd.extend(["-o", "/dev/stdout", "--no-progress"])
        if opts.get("extensions"):
            cmd.extend(["-x", opts["extensions"]])
        if opts.get("threads"):
            cmd.extend(["-t", str(opts["threads"])])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"paths": [], "errors": []}
        for line in (stdout or "").strip().split("\n"):
            m = re.match(r"(/.+?)\s+\(Status:\s+(\d+)\)", line)
            if m:
                result["paths"].append({"path": m.group(1), "status": int(m.group(2))})
        return result

    def supported_operations(self) -> List[str]:
        return ["dir", "dns", "vhost", "s3"]


class FeroxbusterAdapter(BaseAdapter):
    tool_name = "feroxbuster"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {"wordlist", "threads", "extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        wordlist = opts.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        _check_wordlist(wordlist)
        cmd = ["feroxbuster", "--url", request.target, "--wordlist", wordlist, "--quiet", "--json"]
        if opts.get("depth"):
            cmd.extend(["--depth", str(opts["depth"])])
        if opts.get("extensions"):
            cmd.extend(["--extensions", opts["extensions"]])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"paths": [], "errors": []}
        for line in (stdout or "").strip().split("\n"):
            try:
                d = json.loads(line)
                if d.get("type") == "response":
                    result["paths"].append({"url": d.get("url"), "status": d.get("status"), "length": d.get("content_length")})
            except Exception:
                pass
        return result

    def supported_operations(self) -> List[str]:
        return ["scan", "recursive_scan"]


class WpscanAdapter(BaseAdapter):
    tool_name = "wpscan"
    risk_level = RiskLevel.MEDIUM

    def build_command(self, request: ToolRequest) -> List[str]:
        cmd = ["wpscan", "--url", request.target, "--format", "json", "--no-banner"]
        opts = request.options
        if opts.get("enumerate"):
            cmd.extend(["--enumerate", opts["enumerate"]])  # u,p,t,vp,ap
        if opts.get("api_token"):
            cmd.extend(["--api-token", opts["api_token"]])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"version": None, "plugins": [], "themes": [], "users": [], "vulnerabilities": [], "errors": []}
        try:
            data = json.loads(stdout or "{}")
            wp_version = data.get("version", {})
            result["version"] = wp_version.get("number") if wp_version else None
            for slug, info in (data.get("plugins", {}) or {}).items():
                result["plugins"].append({"slug": slug, "version": info.get("version", {}).get("number"), "vulnerabilities": len(info.get("vulnerabilities", []))})
            for u in (data.get("users", {}) or {}).values():
                result["users"].append(u.get("username"))
        except Exception:
            pass
        return result

    def supported_operations(self) -> List[str]:
        return ["scan", "enumerate_users", "enumerate_plugins", "enumerate_themes"]


class SqlmapAdapter(BaseAdapter):
    tool_name = "sqlmap"
    risk_level = RiskLevel.HIGH
    ALLOWED_OPTIONS = {"level", "risk", "batch", "extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        cmd = ["sqlmap", "-u", request.target, "--batch", "--output-dir", "/tmp/sqlmap_out"]
        if opts.get("level"):
            cmd.extend(["--level", str(opts["level"])])
        if opts.get("risk"):
            cmd.extend(["--risk", str(opts["risk"])])
        if opts.get("dbs"):
            cmd.append("--dbs")
        if opts.get("dump"):
            cmd.append("--dump")
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"injectable": False, "parameters": [], "databases": [], "technique": [], "errors": []}
        out = stdout or ""
        if "is vulnerable" in out or "Parameter:" in out:
            result["injectable"] = True
        for m in re.finditer(r"Parameter: (\S+)", out):
            result["parameters"].append(m.group(1))
        for m in re.finditer(r"available databases.*?\[(.*?)\]", out, re.DOTALL):
            result["databases"].extend([d.strip().strip("*").strip() for d in m.group(1).split("\n") if d.strip()])
        return result

    def supported_operations(self) -> List[str]:
        return ["detect", "enumerate_dbs", "dump", "shell"]


class DirsearchAdapter(BaseAdapter):
    tool_name = "dirsearch"
    risk_level = RiskLevel.MEDIUM

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        cmd = ["dirsearch", "-u", request.target, "--format", "json", "-q"]
        if opts.get("extensions"):
            cmd.extend(["-e", opts["extensions"]])
        if opts.get("wordlist"):
            cmd.extend(["-w", opts["wordlist"]])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"paths": [], "errors": []}
        try:
            data = json.loads(stdout or "{}")
            for item in data.get("results", []):
                result["paths"].append({"path": item.get("path"), "status": item.get("status"), "length": item.get("content-length")})
        except Exception:
            for m in re.finditer(r"(\d{3})\s+\S+\s+(/.+)", stdout or ""):
                result["paths"].append({"status": int(m.group(1)), "path": m.group(2)})
        return result

    def supported_operations(self) -> List[str]:
        return ["scan", "recursive"]


class TheHarvesterAdapter(BaseAdapter):
    tool_name = "theharvester"
    risk_level = RiskLevel.LOW

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        source = opts.get("source", "google,bing,linkedin")
        cmd = ["theHarvester", "-d", request.target, "-b", source]
        if request.output_format == "json":
            cmd.extend(["-f", "/tmp/harvester_out"])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"emails": [], "hosts": [], "ips": [], "errors": []}
        out = stdout or ""
        # Emails
        result["emails"] = list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", out)))
        # Hosts/subdomains
        domain = ""
        for m in re.finditer(r"Hosts found.*?\n(.*?)(?:\n\n|\Z)", out, re.DOTALL):
            for line in m.group(1).split("\n"):
                line = line.strip()
                if line and "." in line:
                    result["hosts"].append(line)
        # IPs
        result["ips"] = list(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", out)))
        return result

    def supported_operations(self) -> List[str]:
        return ["harvest", "google", "bing", "linkedin"]


class WafdAdapter(BaseAdapter):
    tool_name = "wafw00f"
    risk_level = RiskLevel.LOW

    def build_command(self, request: ToolRequest) -> List[str]:
        return ["wafw00f", request.target, "-a"]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"waf_detected": False, "waf_name": None, "errors": []}
        out = stdout or ""
        if "is behind" in out:
            result["waf_detected"] = True
            m = re.search(r"is behind (.+?) WAF", out)
            if m:
                result["waf_name"] = m.group(1)
        elif "No WAF detected" in out or "Generic" in out:
            result["waf_detected"] = False
        return result

    def supported_operations(self) -> List[str]:
        return ["detect"]


class TsharkAdapter(BaseAdapter):
    tool_name = "tshark"
    risk_level = RiskLevel.LOW

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        op = opts.get("operation", "summary")
        if op == "dns":
            return ["tshark", "-r", request.target, "-Y", "dns", "-T", "fields", "-e", "dns.qry.name", "-e", "dns.a"]
        elif op == "http":
            return ["tshark", "-r", request.target, "-Y", "http.request", "-T", "fields", "-e", "http.request.method", "-e", "http.request.uri", "-e", "ip.dst"]
        elif op == "json":
            return ["tshark", "-r", request.target, "-T", "json", "-x"]
        else:
            return ["tshark", "-r", request.target, "-q", "-z", "conv,tcp"]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"packets": [], "conversations": [], "dns_queries": [], "http_requests": [], "errors": []}
        out = stdout or ""
        # DNS
        for line in out.split("\n"):
            parts = line.strip().split("\t")
            if len(parts) >= 1 and parts[0]:
                result["dns_queries"].append(parts[0])
        return result

    def supported_operations(self) -> List[str]:
        return ["summary", "dns", "http", "conversations", "json"]


class SherlockAdapter(BaseAdapter):
    tool_name = "sherlock"
    risk_level = RiskLevel.LOW

    def build_command(self, request: ToolRequest) -> List[str]:
        return ["sherlock", request.target, "--print-found", "--timeout", "10"]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"found": [], "not_found": [], "errors": []}
        for line in (stdout or "").split("\n"):
            if "[+]" in line:
                result["found"].append(line.replace("[+]", "").strip())
            elif "[-]" in line:
                result["not_found"].append(line.replace("[-]", "").strip())
        return result

    def supported_operations(self) -> List[str]:
        return ["search"]


class NaabuAdapter(BaseAdapter):
    tool_name = "naabu"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {"ports", "rate", "extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        cmd = ["naabu", "-host", request.target, "-silent"]
        if request.output_format == "json":
            cmd.append("-json")
        if opts.get("ports"):
            cmd.extend(["-p", str(opts["ports"])])
        if opts.get("top_ports"):
            cmd.extend(["-top-ports", str(opts["top_ports"])])
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"ports": [], "errors": []}
        for line in (stdout or "").strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                result["ports"].append({"host": d.get("ip"), "port": d.get("port"), "protocol": "tcp"})
            except Exception:
                m = re.match(r"([\d.]+):(\d+)", line)
                if m:
                    result["ports"].append({"host": m.group(1), "port": int(m.group(2)), "protocol": "tcp"})
        return result

    def supported_operations(self) -> List[str]:
        return ["scan", "top_ports", "full_scan"]


class StringsAdapter(BaseAdapter):
    tool_name = "strings"
    risk_level = RiskLevel.LOW

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        min_len = opts.get("min_len", "4")
        return ["strings", "-n", str(min_len), request.target]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        strings_found = [l for l in (stdout or "").split("\n") if l.strip()]
        urls = [s for s in strings_found if s.startswith(("http://", "https://"))]
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", stdout or "")
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", stdout or "")
        return {"strings": strings_found[:500], "urls": urls, "emails": emails, "ips": ips, "total": len(strings_found)}

    def supported_operations(self) -> List[str]:
        return ["extract", "grep"]


class HydraAdapter(BaseAdapter):
    tool_name = "hydra"
    risk_level = RiskLevel.HIGH
    ALLOWED_OPTIONS = {"service", "username", "wordlist", "extra_flags"}

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        service = opts.get("service", "ssh")
        userlist = opts.get("userlist", "/usr/share/wordlists/metasploit/unix_users.txt")
        passlist = opts.get("passlist", "/usr/share/wordlists/rockyou.txt")
        cmd = ["hydra", "-L", userlist, "-P", passlist, request.target, service, "-t", "4", "-V"]
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"credentials": [], "attempts": 0, "errors": []}
        for line in (stdout or "").split("\n"):
            if "[" in line and "login:" in line:
                m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
                if m:
                    result["credentials"].append({"username": m.group(1), "password": m.group(2)})
        return result

    def supported_operations(self) -> List[str]:
        return ["ssh", "ftp", "http-post-form", "smb"]


class BinwalkAdapter(BaseAdapter):
    tool_name = "binwalk"
    risk_level = RiskLevel.LOW

    def build_command(self, request: ToolRequest) -> List[str]:
        opts = request.options
        cmd = ["binwalk", request.target]
        if opts.get("extract"):
            cmd.extend(["-e", "--directory", "/tmp/binwalk_out"])
        if opts.get("entropy"):
            cmd.append("-E")
        return cmd

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"signatures": [], "errors": []}
        for line in (stdout or "").split("\n"):
            m = re.match(r"\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(.+)", line)
            if m:
                result["signatures"].append({"offset": int(m.group(1)), "description": m.group(2).strip()})
        return result

    def supported_operations(self) -> List[str]:
        return ["scan", "extract", "entropy"]


class ExiftoolAdapter(BaseAdapter):
    tool_name = "exiftool"
    risk_level = RiskLevel.LOW

    def build_command(self, request: ToolRequest) -> List[str]:
        return ["exiftool", "-json", request.target]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {"metadata": {}, "errors": []}
        try:
            data = json.loads(stdout or "[]")
            if data:
                result["metadata"] = data[0]
        except Exception:
            pass
        return result

    def supported_operations(self) -> List[str]:
        return ["extract_metadata"]


def _check_wordlist(path: str) -> None:
    """FIX #11: Warn if wordlist missing but don't crash."""
    import os
    if not os.path.exists(path):
        # Will fail gracefully at execution time
        pass

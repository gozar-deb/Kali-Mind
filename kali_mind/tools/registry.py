"""Universal Tool Registry — centralized metadata for all security tools."""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolCategory(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    WEB_SECURITY = "web_security"
    NETWORK_ANALYSIS = "network_analysis"
    OSINT = "osint"
    PASSWORD_TESTING = "password_testing"
    EXPLOITATION = "exploitation"
    WIRELESS = "wireless"
    FORENSICS = "forensics"
    REVERSE_ENGINEERING = "reverse_engineering"
    REPORTING = "reporting"
    UTILITY = "utility"
    CUSTOM = "custom"


class ToolArgument(BaseModel):
    name: str
    type: str = "string"
    required: bool = False
    description: str = ""
    default: Optional[Any] = None
    choices: Optional[List[str]] = None


class ToolManifest(BaseModel):
    name: str
    binary: str
    category: ToolCategory
    description: str
    capabilities: List[str] = Field(default_factory=list)
    input_types: List[str] = Field(default_factory=list)
    output_formats: List[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    arguments: List[ToolArgument] = Field(default_factory=list)
    documentation_url: Optional[str] = None
    version_flag: str = "--version"
    available: bool = False
    version: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


# ─── Built-in tool definitions ─────────────────────────────────────────────

BUILTIN_TOOLS: List[ToolManifest] = [
    # Reconnaissance
    ToolManifest(
        name="nmap",
        binary="nmap",
        category=ToolCategory.RECONNAISSANCE,
        description="Network discovery and service enumeration",
        capabilities=["host_discovery", "port_scanning", "service_detection", "os_detection", "script_scanning"],
        input_types=["hostname", "ip", "cidr"],
        output_formats=["text", "xml", "json"],
        risk_level=RiskLevel.MEDIUM,
        tags=["network", "scanner", "ports"],
    ),
    ToolManifest(
        name="masscan",
        binary="masscan",
        category=ToolCategory.RECONNAISSANCE,
        description="High-speed TCP port scanner",
        capabilities=["port_scanning", "host_discovery"],
        input_types=["ip", "cidr"],
        output_formats=["text", "xml", "json"],
        risk_level=RiskLevel.MEDIUM,
        tags=["network", "scanner", "fast"],
    ),
    ToolManifest(
        name="amass",
        binary="amass",
        category=ToolCategory.RECONNAISSANCE,
        description="Attack surface mapping and asset discovery",
        capabilities=["subdomain_enumeration", "dns_brute", "certificate_transparency"],
        input_types=["domain"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.LOW,
        tags=["subdomain", "osint", "dns"],
    ),
    ToolManifest(
        name="subfinder",
        binary="subfinder",
        category=ToolCategory.RECONNAISSANCE,
        description="Fast passive subdomain enumeration tool",
        capabilities=["subdomain_enumeration"],
        input_types=["domain"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.LOW,
        tags=["subdomain", "passive"],
    ),
    ToolManifest(
        name="httpx",
        binary="httpx",
        category=ToolCategory.RECONNAISSANCE,
        description="Fast HTTP toolkit for probing web servers",
        capabilities=["http_probing", "technology_detection", "status_codes"],
        input_types=["url", "hostname", "ip"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.LOW,
        tags=["http", "probe", "web"],
    ),
    ToolManifest(
        name="whatweb",
        binary="whatweb",
        category=ToolCategory.RECONNAISSANCE,
        description="Web technology fingerprinting",
        capabilities=["technology_detection", "cms_detection", "framework_detection"],
        input_types=["url"],
        output_formats=["text", "json", "xml"],
        risk_level=RiskLevel.LOW,
        tags=["web", "fingerprint"],
    ),
    ToolManifest(
        name="theharvester",
        binary="theHarvester",
        category=ToolCategory.OSINT,
        description="Email, subdomain, and name harvesting from public sources",
        capabilities=["email_harvesting", "subdomain_enum", "osint"],
        input_types=["domain"],
        output_formats=["text", "xml", "json"],
        risk_level=RiskLevel.LOW,
        tags=["osint", "email", "passive"],
    ),
    ToolManifest(
        name="wafw00f",
        binary="wafw00f",
        category=ToolCategory.RECONNAISSANCE,
        description="Web Application Firewall detection tool",
        capabilities=["waf_detection"],
        input_types=["url"],
        output_formats=["text"],
        risk_level=RiskLevel.LOW,
        tags=["waf", "web"],
    ),
    ToolManifest(
        name="naabu",
        binary="naabu",
        category=ToolCategory.RECONNAISSANCE,
        description="Fast port scanner with SYN/CONNECT probing",
        capabilities=["port_scanning"],
        input_types=["ip", "hostname", "cidr"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.MEDIUM,
        tags=["ports", "scanner"],
    ),
    # Web Security
    ToolManifest(
        name="ffuf",
        binary="ffuf",
        category=ToolCategory.WEB_SECURITY,
        description="Fast web fuzzer and directory/file discovery",
        capabilities=["directory_fuzzing", "file_discovery", "parameter_fuzzing", "vhost_fuzzing"],
        input_types=["url"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.MEDIUM,
        tags=["fuzzer", "directory", "web"],
    ),
    ToolManifest(
        name="gobuster",
        binary="gobuster",
        category=ToolCategory.WEB_SECURITY,
        description="Directory/file and DNS brute-force tool",
        capabilities=["directory_brute", "dns_brute", "vhost_discovery"],
        input_types=["url", "domain"],
        output_formats=["text"],
        risk_level=RiskLevel.MEDIUM,
        tags=["directory", "brute", "web"],
    ),
    ToolManifest(
        name="nikto",
        binary="nikto",
        category=ToolCategory.WEB_SECURITY,
        description="Web server scanner for misconfigurations and vulnerabilities",
        capabilities=["web_vulnerability_scan", "misconfiguration_check"],
        input_types=["url", "hostname"],
        output_formats=["text", "xml", "json", "html"],
        risk_level=RiskLevel.MEDIUM,
        tags=["scanner", "web", "vuln"],
    ),
    ToolManifest(
        name="sqlmap",
        binary="sqlmap",
        category=ToolCategory.WEB_SECURITY,
        description="Automatic SQL injection detection and exploitation tool",
        capabilities=["sqli_detection", "sqli_exploitation", "db_enumeration"],
        input_types=["url"],
        output_formats=["text"],
        risk_level=RiskLevel.HIGH,
        tags=["sqli", "database", "web"],
    ),
    ToolManifest(
        name="nuclei",
        binary="nuclei",
        category=ToolCategory.WEB_SECURITY,
        description="Template-based vulnerability scanner",
        capabilities=["vulnerability_scanning", "cve_detection", "misconfiguration"],
        input_types=["url", "hostname", "ip"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.MEDIUM,
        tags=["scanner", "templates", "cve"],
    ),
    ToolManifest(
        name="feroxbuster",
        binary="feroxbuster",
        category=ToolCategory.WEB_SECURITY,
        description="Recursive content discovery tool",
        capabilities=["directory_discovery", "recursive_scan"],
        input_types=["url"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.MEDIUM,
        tags=["directory", "recursive", "web"],
    ),
    ToolManifest(
        name="wpscan",
        binary="wpscan",
        category=ToolCategory.WEB_SECURITY,
        description="WordPress security scanner",
        capabilities=["cms_scan", "plugin_enum", "user_enum", "vuln_check"],
        input_types=["url"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.MEDIUM,
        tags=["wordpress", "cms", "web"],
    ),
    ToolManifest(
        name="dirsearch",
        binary="dirsearch",
        category=ToolCategory.WEB_SECURITY,
        description="Web path scanner",
        capabilities=["directory_discovery", "path_scanning"],
        input_types=["url"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.MEDIUM,
        tags=["directory", "web"],
    ),
    # Network Analysis
    ToolManifest(
        name="tshark",
        binary="tshark",
        category=ToolCategory.NETWORK_ANALYSIS,
        description="Terminal-based Wireshark packet analyzer",
        capabilities=["packet_capture", "pcap_analysis", "protocol_analysis", "dns_analysis"],
        input_types=["pcap", "interface"],
        output_formats=["text", "json", "xml"],
        risk_level=RiskLevel.LOW,
        tags=["pcap", "network", "packets"],
    ),
    ToolManifest(
        name="tcpdump",
        binary="tcpdump",
        category=ToolCategory.NETWORK_ANALYSIS,
        description="Command-line packet analyzer",
        capabilities=["packet_capture", "pcap_analysis"],
        input_types=["pcap", "interface"],
        output_formats=["text", "pcap"],
        risk_level=RiskLevel.LOW,
        tags=["pcap", "network", "capture"],
    ),
    ToolManifest(
        name="netcat",
        binary="nc",
        category=ToolCategory.NETWORK_ANALYSIS,
        description="Networking utility for reading/writing data across connections",
        capabilities=["port_scan", "banner_grab", "file_transfer", "reverse_shell"],
        input_types=["hostname", "ip"],
        output_formats=["text"],
        risk_level=RiskLevel.HIGH,
        tags=["network", "utility"],
    ),
    # OSINT
    ToolManifest(
        name="sherlock",
        binary="sherlock",
        category=ToolCategory.OSINT,
        description="Hunt down social media accounts by username",
        capabilities=["username_search", "social_media_enum"],
        input_types=["username"],
        output_formats=["text"],
        risk_level=RiskLevel.LOW,
        tags=["osint", "social", "username"],
    ),
    ToolManifest(
        name="spiderfoot",
        binary="spiderfoot",
        category=ToolCategory.OSINT,
        description="Automated OSINT platform",
        capabilities=["osint", "target_recon", "threat_intel"],
        input_types=["domain", "ip", "email"],
        output_formats=["text", "json", "html"],
        risk_level=RiskLevel.LOW,
        tags=["osint", "recon"],
    ),
    ToolManifest(
        name="recon-ng",
        binary="recon-ng",
        category=ToolCategory.OSINT,
        description="Full-featured reconnaissance framework",
        capabilities=["osint", "domain_recon", "network_recon"],
        input_types=["domain", "ip"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.LOW,
        tags=["osint", "framework"],
    ),
    # Password Testing (authorized lab use)
    ToolManifest(
        name="john",
        binary="john",
        category=ToolCategory.PASSWORD_TESTING,
        description="Password cracker for authorized lab use",
        capabilities=["hash_cracking", "password_recovery"],
        input_types=["hash_file"],
        output_formats=["text"],
        risk_level=RiskLevel.HIGH,
        tags=["password", "hash", "crack"],
    ),
    ToolManifest(
        name="hashcat",
        binary="hashcat",
        category=ToolCategory.PASSWORD_TESTING,
        description="Advanced GPU-based password recovery",
        capabilities=["hash_cracking", "password_recovery"],
        input_types=["hash_file"],
        output_formats=["text"],
        risk_level=RiskLevel.HIGH,
        tags=["password", "gpu", "crack"],
    ),
    ToolManifest(
        name="hydra",
        binary="hydra",
        category=ToolCategory.PASSWORD_TESTING,
        description="Online password brute-force tool (authorized testing only)",
        capabilities=["credential_brute", "login_testing"],
        input_types=["hostname", "ip"],
        output_formats=["text"],
        risk_level=RiskLevel.HIGH,
        tags=["password", "brute", "credential"],
    ),
    # Exploitation Framework (authorized environments)
    ToolManifest(
        name="msfconsole",
        binary="msfconsole",
        category=ToolCategory.EXPLOITATION,
        description="Metasploit Framework console (authorized environments only)",
        capabilities=["exploitation", "post_exploitation", "payload_generation"],
        input_types=["hostname", "ip"],
        output_formats=["text"],
        risk_level=RiskLevel.CRITICAL,
        tags=["metasploit", "exploit", "framework"],
    ),
    # Reverse Engineering
    ToolManifest(
        name="ghidra",
        binary="ghidra",
        category=ToolCategory.REVERSE_ENGINEERING,
        description="NSA reverse engineering framework",
        capabilities=["disassembly", "decompilation", "binary_analysis"],
        input_types=["binary"],
        output_formats=["text"],
        risk_level=RiskLevel.LOW,
        tags=["reversing", "binary", "decompile"],
    ),
    ToolManifest(
        name="radare2",
        binary="r2",
        category=ToolCategory.REVERSE_ENGINEERING,
        description="Open-source reverse engineering framework",
        capabilities=["disassembly", "debugging", "binary_analysis"],
        input_types=["binary"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.LOW,
        tags=["reversing", "binary"],
    ),
    ToolManifest(
        name="binwalk",
        binary="binwalk",
        category=ToolCategory.REVERSE_ENGINEERING,
        description="Firmware analysis and extraction tool",
        capabilities=["firmware_analysis", "binary_extraction", "entropy_analysis"],
        input_types=["binary", "firmware"],
        output_formats=["text"],
        risk_level=RiskLevel.LOW,
        tags=["firmware", "extraction"],
    ),
    ToolManifest(
        name="strings",
        binary="strings",
        category=ToolCategory.REVERSE_ENGINEERING,
        description="Extract printable strings from binary files",
        capabilities=["string_extraction"],
        input_types=["binary"],
        output_formats=["text"],
        risk_level=RiskLevel.LOW,
        tags=["strings", "binary"],
    ),
    ToolManifest(
        name="objdump",
        binary="objdump",
        category=ToolCategory.REVERSE_ENGINEERING,
        description="Display information from object files",
        capabilities=["disassembly", "symbol_inspection"],
        input_types=["binary"],
        output_formats=["text"],
        risk_level=RiskLevel.LOW,
        tags=["disassembly", "binary"],
    ),
    ToolManifest(
        name="gdb",
        binary="gdb",
        category=ToolCategory.REVERSE_ENGINEERING,
        description="GNU Debugger",
        capabilities=["debugging", "binary_analysis"],
        input_types=["binary"],
        output_formats=["text"],
        risk_level=RiskLevel.LOW,
        tags=["debug", "binary"],
    ),
    # Forensics
    ToolManifest(
        name="volatility3",
        binary="vol",
        category=ToolCategory.FORENSICS,
        description="Memory forensics framework",
        capabilities=["memory_analysis", "process_list", "network_connections"],
        input_types=["memory_dump"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.LOW,
        tags=["forensics", "memory"],
    ),
    ToolManifest(
        name="exiftool",
        binary="exiftool",
        category=ToolCategory.FORENSICS,
        description="Metadata extraction from files",
        capabilities=["metadata_extraction"],
        input_types=["file"],
        output_formats=["text", "json"],
        risk_level=RiskLevel.LOW,
        tags=["metadata", "forensics"],
    ),
    ToolManifest(
        name="file",
        binary="file",
        category=ToolCategory.FORENSICS,
        description="Determine file type",
        capabilities=["file_type_detection"],
        input_types=["file"],
        output_formats=["text"],
        risk_level=RiskLevel.LOW,
        tags=["file", "forensics"],
    ),
]


class ToolRegistry:
    """Central registry for all security tools."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolManifest] = {}
        for t in BUILTIN_TOOLS:
            self._tools[t.name] = t

    def register(self, tool: ToolManifest) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolManifest]:
        return self._tools.get(name)

    def all_tools(self) -> List[ToolManifest]:
        return list(self._tools.values())

    def available_tools(self) -> List[ToolManifest]:
        return [t for t in self._tools.values() if t.available]

    def by_category(self, category: ToolCategory) -> List[ToolManifest]:
        return [t for t in self._tools.values() if t.category == category]

    def search(self, query: str) -> List[ToolManifest]:
        q = query.lower()
        results = []
        for t in self._tools.values():
            if (
                q in t.name.lower()
                or q in t.description.lower()
                or any(q in cap for cap in t.capabilities)
                or any(q in tag for tag in t.tags)
                or q == t.category.value
            ):
                results.append(t)
        return results

    def with_capability(self, capability: str) -> List[ToolManifest]:
        cap = capability.lower()
        return [t for t in self._tools.values() if any(cap in c for c in t.capabilities)]

    def unregister(self, name: str) -> bool:
        if name in self._tools:
            del self._tools[name]
            return True
        return False


# Singleton
_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry

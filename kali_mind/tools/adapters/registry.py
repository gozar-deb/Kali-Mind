"""Adapter registry — maps tool names to their adapters."""
from __future__ import annotations
from typing import Dict, Optional
from kali_mind.tools.adapters.base import BaseAdapter

_adapters: Optional[Dict[str, BaseAdapter]] = None


def _load_adapters() -> Dict[str, BaseAdapter]:
    adapters: Dict[str, BaseAdapter] = {}

    try:
        from kali_mind.tools.adapters.nmap_adapter import NmapAdapter
        adapters["nmap"] = NmapAdapter()
    except ImportError:
        pass

    try:
        from kali_mind.tools.adapters.web_adapters import (
            FfufAdapter, HttpxAdapter, NiktoAdapter, NucleiAdapter, WhatWebAdapter)
        adapters["httpx"] = HttpxAdapter()
        adapters["ffuf"] = FfufAdapter()
        adapters["nikto"] = NiktoAdapter()
        adapters["whatweb"] = WhatWebAdapter()
        adapters["nuclei"] = NucleiAdapter()
    except ImportError:
        pass

    try:
        from kali_mind.tools.adapters.recon_adapters import (
            MasscanAdapter, SubfinderAdapter, AmassAdapter, GobusterAdapter,
            FeroxbusterAdapter, WpscanAdapter, SqlmapAdapter, DirsearchAdapter,
            TheHarvesterAdapter, WafdAdapter, TsharkAdapter, SherlockAdapter,
            NaabuAdapter, StringsAdapter, HydraAdapter, BinwalkAdapter, ExiftoolAdapter)
        adapters["masscan"] = MasscanAdapter()
        adapters["subfinder"] = SubfinderAdapter()
        adapters["amass"] = AmassAdapter()
        adapters["gobuster"] = GobusterAdapter()
        adapters["feroxbuster"] = FeroxbusterAdapter()
        adapters["wpscan"] = WpscanAdapter()
        adapters["sqlmap"] = SqlmapAdapter()
        adapters["dirsearch"] = DirsearchAdapter()
        adapters["theharvester"] = TheHarvesterAdapter()
        adapters["wafw00f"] = WafdAdapter()
        adapters["tshark"] = TsharkAdapter()
        adapters["sherlock"] = SherlockAdapter()
        adapters["naabu"] = NaabuAdapter()
        adapters["strings"] = StringsAdapter()
        adapters["hydra"] = HydraAdapter()
        adapters["binwalk"] = BinwalkAdapter()
        adapters["exiftool"] = ExiftoolAdapter()
    except ImportError:
        pass

    try:
        from kali_mind.tools.adapters.extra_adapters import (
            BloodHoundAdapter, NetExecAdapter, TrivyAdapter,
            SemgrepAdapter, ImpacketSecretsdumpAdapter,
        )
        adapters["bloodhound-python"] = BloodHoundAdapter()
        adapters["netexec"] = NetExecAdapter()
        adapters["nxc"] = NetExecAdapter()  # alias
        adapters["trivy"] = TrivyAdapter()
        adapters["semgrep"] = SemgrepAdapter()
        adapters["secretsdump.py"] = ImpacketSecretsdumpAdapter()
        adapters["secretsdump"] = ImpacketSecretsdumpAdapter()
    except ImportError:
        pass


    try:
        from kali_mind.tools.adapters.offensive_adapters import (
            CrackMapExecAdapter, ResponderAdapter, EvilWinrmAdapter,
            ImpacketWmiexecAdapter, ImpacketPsexecAdapter,
            AwsCliAdapter, AzureCliAdapter,
        )
        adapters["crackmapexec"] = CrackMapExecAdapter()
        adapters["cme"] = CrackMapExecAdapter()
        adapters["responder"] = ResponderAdapter()
        adapters["evil-winrm"] = EvilWinrmAdapter()
        adapters["wmiexec.py"] = ImpacketWmiexecAdapter()
        adapters["psexec.py"] = ImpacketPsexecAdapter()
        adapters["aws"] = AwsCliAdapter()
        adapters["az"] = AzureCliAdapter()
    except ImportError:
        pass

    return adapters


def get_adapter(tool_name: str) -> Optional[BaseAdapter]:
    global _adapters
    if _adapters is None:
        _adapters = _load_adapters()
    return _adapters.get(tool_name)


def register_adapter(name: str, adapter: BaseAdapter) -> None:
    global _adapters
    if _adapters is None:
        _adapters = _load_adapters()
    _adapters[name] = adapter

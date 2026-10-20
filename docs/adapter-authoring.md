# Adapter Authoring Guide

## Minimal adapter

```python
from kali_mind.tools.adapters.base import BaseAdapter, ToolRequest
from kali_mind.tools.registry import RiskLevel

class MyAdapter(BaseAdapter):
    tool_name = "mytool"
    risk_level = RiskLevel.MEDIUM
    ALLOWED_OPTIONS = {"threads", "extra_flags"}
    ALLOWED_FLAGS = {"-v", "--json"}

    def build_command(self, request: ToolRequest) -> list[str]:
        # ALWAYS return argv list — never a shell string
        cmd = ["mytool", request.target]
        opts = self.safe_options(request)
        if opts.get("threads"):
            cmd.extend(["-t", str(opts["threads"])])
        return cmd

    def parse_output(self, stdout, stderr, exit_code) -> dict:
        return {
            "hosts": [],
            "ports": [],
            "urls": [],
            "findings": [],
            "raw_summary": stdout[:2000],
        }

    def supported_operations(self) -> list[str]:
        return ["scan"]
```

## Register

In a plugin `adapter.py` export the class, and list it in `plugin.yaml`:

```yaml
name: mytool
binary: mytool
category: reconnaissance
entry: adapter:MyAdapter
risk_level: medium
```

Generate checksums:

```bash
python -c "from pathlib import Path; from kali_mind.plugins.protocol import write_checksums; write_checksums(Path('.'))"
```

## Rules
1. Never use `shell=True` or `os.system`.
2. Validate options; use `ALLOWED_OPTIONS`.
3. Prefer `ParsedResult`-compatible keys: hosts, ports, urls, findings, credentials.
4. Set an honest `risk_level`.

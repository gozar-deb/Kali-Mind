"""Feature #32: Automatic screenshot capture of web findings."""
from __future__ import annotations

import asyncio
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


class ScreenshotCapture:
    """Captures screenshots of web targets using available headless browser tools."""

    TOOLS = ["chromium", "chromium-browser", "google-chrome", "cutycapt", "wkhtmltoimage"]

    def detect_tool(self) -> Optional[str]:
        for t in self.TOOLS:
            if shutil.which(t):
                return t
        return None

    async def capture(self, url: str, output_dir: Optional[Path] = None) -> Optional[Path]:
        """Capture a screenshot of the given URL."""
        # Screenshots trigger a real browser navigation; reject local-file schemes and
        # out-of-scope hosts before any request is made.
        try:
            parsed = urlsplit(url)
        except ValueError:
            return None
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            logger.warning("Refusing screenshot URL with unsupported scheme or missing host")
            return None
        from kali_mind.security.scope import get_scope_manager
        in_scope, reason = get_scope_manager().is_in_scope(url)
        if not in_scope:
            logger.warning("Refusing screenshot for out-of-scope URL: %s", reason)
            return None

        tool = self.detect_tool()
        if not tool:
            return None

        if output_dir is None:
            from kali_mind.config import settings
            output_dir = settings.evidence_dir / "screenshots"
        output_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = url.replace("://", "_").replace("/", "_").replace(":", "_")[:50]
        output_file = output_dir / f"{safe_url}_{ts}.png"

        cmd = self._build_command(tool, url, str(output_file))
        if not cmd:
            return None

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            from kali_mind.execution.process_utils import communicate_with_timeout
            await communicate_with_timeout(proc, timeout=30)
            if output_file.exists() and output_file.stat().st_size > 0:
                return output_file
        except asyncio.TimeoutError:
            logger.debug("Screenshot timed out for %s", url)
        except Exception as e:
            logger.debug("Screenshot capture failed for %s: %s", url, e)
        return None

    def _build_command(self, tool: str, url: str, output: str) -> Optional[list]:
        if "chrom" in tool:
            return [
                tool, "--headless", "--disable-gpu",
                "--screenshot=" + output, "--window-size=1280,900",
                "--disable-extensions", url,
            ]
        elif tool == "cutycapt":
            return ["cutycapt", f"--url={url}", f"--out={output}",
                    "--delay=2000", "--max-wait=10000"]
        elif tool == "wkhtmltoimage":
            return ["wkhtmltoimage", "--quiet", url, output]
        return None

    async def capture_finding_urls(self, urls: list[str], output_dir: Optional[Path] = None) -> dict[str, Optional[Path]]:
        """Capture screenshots for a list of URLs concurrently."""
        tasks = {url: self.capture(url, output_dir) for url in urls}
        results = {}
        for url, coro in tasks.items():
            results[url] = await coro
        return results

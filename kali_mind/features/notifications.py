"""Feature #33: Desktop and messaging notifications for high-severity findings."""
from __future__ import annotations

import asyncio
import html
import logging
import os
import shutil
from typing import Optional

import httpx

from kali_mind.evidence.store import Finding

logger = logging.getLogger(__name__)


class NotificationService:
    """Sends notifications via notify-send, Telegram, or Slack."""

    def __init__(self) -> None:
        self.telegram_token = os.getenv("KALI_MIND_TELEGRAM_TOKEN")
        self.telegram_chat_id = os.getenv("KALI_MIND_TELEGRAM_CHAT_ID")
        self.slack_webhook = os.getenv("KALI_MIND_SLACK_WEBHOOK")
        self.min_severity = os.getenv("KALI_MIND_NOTIFY_SEVERITY", "high")

    def _should_notify(self, severity: str) -> bool:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        return order.get(severity, 0) >= order.get(self.min_severity, 3)

    async def notify_finding(self, finding: Finding) -> None:
        if not self._should_notify(finding.severity):
            return
        message = (
            f"⚠️ [{html.escape(str(finding.severity).upper())}] "
            f"{html.escape(str(finding.title))}\n"
            f"Asset: {html.escape(str(finding.affected_asset))}\n"
            f"Confidence: {html.escape(str(finding.confidence))}"
        )
        await asyncio.gather(
            self._desktop_notify(finding.severity, finding.title, message),
            self._telegram_notify(message),
            self._slack_notify(message),
            return_exceptions=True,
        )

    async def notify_session_complete(self, session_id: str, counts: dict) -> None:
        msg = (
            f"✅ Kali-Mind Assessment Complete\n"
            f"Session: {html.escape(str(session_id))}\n"
            f"Critical: {html.escape(str(counts.get('critical', 0)))} | "
            f"High: {html.escape(str(counts.get('high', 0)))} | "
            f"Medium: {html.escape(str(counts.get('medium', 0)))} | "
            f"Low: {html.escape(str(counts.get('low', 0)))}"
        )
        await asyncio.gather(
            self._desktop_notify("info", "Assessment Complete", msg),
            self._telegram_notify(msg),
            self._slack_notify(msg),
            return_exceptions=True,
        )

    async def _desktop_notify(self, severity: str, title: str, body: str) -> None:
        if not shutil.which("notify-send"):
            return
        urgency = "critical" if severity == "critical" else "normal"
        try:
            proc = await asyncio.create_subprocess_exec(
                "notify-send", f"Kali-Mind: {title}", body,
                f"--urgency={urgency}", "--app-name=Kali-Mind",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True,
            )
            from kali_mind.execution.process_utils import communicate_with_timeout
            await communicate_with_timeout(proc, timeout=5)
        except Exception as e:
            logger.debug("Desktop notification failed: %s", e)

    async def _telegram_notify(self, message: str) -> None:
        if not self.telegram_token or not self.telegram_chat_id:
            return
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                    json={"chat_id": self.telegram_chat_id, "text": message, "parse_mode": "HTML"},
                )
        except Exception as e:
            logger.debug("Telegram notification failed: %s", e)

    async def _slack_notify(self, message: str) -> None:
        if not self.slack_webhook:
            return
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(self.slack_webhook, json={"text": message})
        except Exception as e:
            logger.debug("Slack notification failed: %s", e)


_service: Optional[NotificationService] = None


def get_notification_service() -> NotificationService:
    global _service
    if _service is None:
        _service = NotificationService()
    return _service

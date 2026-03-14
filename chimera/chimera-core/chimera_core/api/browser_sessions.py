from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import quote

from chimera_core.capabilities.browser.automation import BrowserAutomation
from chimera_core.capabilities.browser.browser_task import ActionType, BrowserAction, BrowserTask


@dataclass
class PersistentBrowserSession:
    target: str
    headless: bool = True
    auth_cookies: Dict[str, str] = field(default_factory=dict)
    playwright_factory: Optional[Any] = None

    def __post_init__(self) -> None:
        self._automation: Optional[BrowserAutomation] = None
        self._lock = asyncio.Lock()
        self._current_url = self.target

    async def analyze(self, url: Optional[str] = None) -> Dict[str, Any]:
        task = BrowserTask(
            actions=[
                BrowserAction(type=ActionType.NAVIGATE, url=url or self._current_url),
                BrowserAction(type=ActionType.WAIT_FOR_NAVIGATION),
            ],
            context={"auth_cookies": dict(self.auth_cookies)},
        )
        return await self.execute(task, url=url)

    async def execute(self, task: BrowserTask, *, url: Optional[str] = None) -> Dict[str, Any]:
        async with self._lock:
            automation = await self._ensure_started(url=url)
            task_to_run = self._normalized_task(task, url=url)
            artifacts = await automation.execute_task(task_to_run)
            self._current_url = artifacts.get("url") or url or self._current_url
            return artifacts

    async def trace_xss(self, *, url: Optional[str], parameter: str, payload: str) -> Dict[str, Any]:
        target = url or self._current_url
        encoded = quote(payload, safe="")
        joiner = "&" if "?" in target else "?"
        trace_url = f"{target}{joiner}{parameter}={encoded}"
        capture = await self.execute(
            BrowserTask(
                actions=[
                    BrowserAction(type=ActionType.NAVIGATE, url=trace_url),
                    BrowserAction(type=ActionType.WAIT_FOR_NAVIGATION),
                ],
                context={"trace_parameter": parameter, "trace_payload": payload},
            ),
            url=trace_url,
        )
        dom = str(capture.get("page_source") or "")
        console_blob = "\n".join(item.get("text", "") for item in capture.get("console", []) or [])
        sinks = list(capture.get("dom_sinks") or [])
        confirmed = bool(sinks) and (payload in trace_url or payload in dom or parameter in trace_url)
        explanation = (
            f"Payload reached a detectable DOM sink for parameter {parameter}."
            if confirmed
            else f"Payload did not produce a confirmed DOM-XSS signal for parameter {parameter}."
        )
        return {
            "status": "confirmed" if confirmed else "false_positive",
            "confidence": 0.95 if confirmed else 0.25,
            "proof_artifacts": [
                {"type": "browser_capture", "ref": capture.get("url")},
                {"type": "console", "ref": console_blob[:400]},
            ],
            "replay_steps": [
                {
                    "action": "navigate",
                    "request": {"url": trace_url},
                    "expected_diff": "Observe DOM sink execution or reflected client-side flow.",
                }
            ],
            "explanation": explanation,
            "capture": capture,
        }

    async def close(self) -> None:
        async with self._lock:
            if self._automation is not None:
                await self._automation.close()
                self._automation = None

    async def _ensure_started(self, *, url: Optional[str] = None) -> BrowserAutomation:
        if self._automation is None:
            self._automation = BrowserAutomation(
                headless=self.headless,
                browser_factory=self.playwright_factory,
            )
            await self._automation.start()
            if self.auth_cookies and getattr(self._automation.context, "add_cookies", None):
                target = url or self.target
                cookies = [{"name": key, "value": value, "url": target} for key, value in self.auth_cookies.items()]
                await self._automation.context.add_cookies(cookies)
        return self._automation

    def _normalized_task(self, task: BrowserTask, *, url: Optional[str] = None) -> BrowserTask:
        actions = list(task.actions)
        target = url or self._current_url or self.target
        if not any(action.type == ActionType.NAVIGATE for action in actions):
            actions.insert(0, BrowserAction(type=ActionType.NAVIGATE, url=target))
            actions.insert(1, BrowserAction(type=ActionType.WAIT_FOR_NAVIGATION))
        return BrowserTask(
            actions=actions,
            capture_har=task.capture_har,
            capture_screenshots=task.capture_screenshots,
            extract_console=task.extract_console,
            context=dict(task.context),
        )

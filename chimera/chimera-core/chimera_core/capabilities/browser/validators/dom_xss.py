from __future__ import annotations

from typing import Any, Dict, Optional

from chimera_core.capabilities.browser.automation import BrowserAutomation
from chimera_core.capabilities.browser.browser_task import ActionType, BrowserAction, BrowserTask
from chimera_core.validators.types import ValidationResult


class DOMXSSValidator:
    def __init__(self, *, browser_factory=None, headless: bool = True) -> None:
        self.browser_factory = browser_factory
        self.headless = headless

    async def validate(self, url: str, injection_point: str, payload: str) -> ValidationResult:
        task = BrowserTask(
            actions=[
                BrowserAction(type=ActionType.NAVIGATE, url=url),
                BrowserAction(type=ActionType.FILL, selector=injection_point, value=payload),
                BrowserAction(type=ActionType.EXTRACT_CONSOLE),
            ],
            capture_screenshots=True,
            extract_console=True,
        )
        browser = BrowserAutomation(headless=self.headless, browser_factory=self.browser_factory)
        await browser.start()
        try:
            artifacts = await browser.execute_task(task)
        finally:
            await browser.close()

        dom = artifacts.get("page_source", "")
        console = artifacts.get("console", [])
        hit = payload in dom or payload in str(console)
        return ValidationResult(
            status="confirmed" if hit else "false_positive",
            confidence=0.95 if hit else 0.35,
            proof_artifacts=[
                {"type": "browser_capture", "ref": artifacts.get("url")},
                {"type": "screenshot", "ref": "inline" if artifacts.get("screenshot") else ""},
            ],
            replay_steps=[
                {
                    "action": "navigate_and_fill",
                    "request": {"url": url, "selector": injection_point, "payload": payload},
                    "expected_diff": "Payload reaches a DOM sink or appears in console output.",
                }
            ],
            explanation="Payload reached a DOM sink." if hit else "Payload did not reach a DOM sink.",
        )

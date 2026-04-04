from __future__ import annotations

from typing import Any, Dict, List, Optional

from chimera_core.capabilities.browser.browser_task import ActionType, BrowserAction, BrowserTask


class BrowserAutomation:
    def __init__(self, *, headless: bool = True, browser_factory=None) -> None:
        self.headless = headless
        self.browser_factory = browser_factory
        self._playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.console_logs: List[Dict[str, str]] = []
        self.network: List[Dict[str, Any]] = []

    async def start(self) -> None:
        if self.browser_factory is not None:
            self.browser, self.context, self.page = await self.browser_factory(self.headless)
            return
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed") from exc

        self._playwright = await async_playwright().start()
        self.browser = await self._playwright.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context()
        self.page = await self.context.new_page()
        self._attach_observers()

    async def execute_task(self, task: BrowserTask) -> Dict[str, Any]:
        if self.page is None or self.context is None:
            raise RuntimeError("BrowserAutomation.start() must be called before execute_task()")
        self.console_logs = []
        self.network = []
        self._attach_observers()

        if task.capture_har:
            await self.context.tracing.start(screenshots=task.capture_screenshots, snapshots=True)
        js_results: List[Dict[str, Any]] = []
        try:
            for action in task.actions:
                result = await self._execute_action(action)
                if result is not None:
                    js_results.append({"action": action.type.value, "result": result})
            artifacts = await self._collect_artifacts(task)
            artifacts["js_results"] = js_results
            return artifacts
        finally:
            if task.capture_har:
                await self.context.tracing.stop()

    async def close(self) -> None:
        if self.browser is not None:
            await self.browser.close()
        if self._playwright is not None:
            await self._playwright.stop()

    async def _execute_action(self, action: BrowserAction):
        if self.page is None:
            raise RuntimeError("Browser page is not initialized")
        if action.type == ActionType.NAVIGATE:
            resp = await self.page.goto(action.url, timeout=action.timeout)
            if resp is not None:
                return {"status": resp.status, "url": resp.url}
            return None
        if action.type == ActionType.CLICK:
            await self.page.click(action.selector, timeout=action.timeout)
            return None
        if action.type == ActionType.FILL:
            await self.page.fill(action.selector, action.value or "", timeout=action.timeout)
            return None
        if action.type == ActionType.WAIT_FOR_SELECTOR:
            await self.page.wait_for_selector(action.selector, timeout=action.timeout)
            return None
        if action.type == ActionType.WAIT_FOR_NAVIGATION:
            await self.page.wait_for_load_state("networkidle", timeout=action.timeout)
            return None
        if action.type == ActionType.EXECUTE_JS:
            return await self.page.evaluate(action.js_code or "() => null")
        if action.type in {ActionType.EXTRACT_DOM, ActionType.EXTRACT_CONSOLE, ActionType.SCREENSHOT}:
            return None
        raise ValueError(f"Unsupported browser action: {action.type}")

    async def _collect_artifacts(self, task: BrowserTask) -> Dict[str, Any]:
        if self.page is None:
            raise RuntimeError("Browser page is not initialized")
        script_srcs = await self.page.eval_on_selector_all("script[src]", "els => els.map(el => el.src)")
        postmessage_listeners = await self.page.evaluate(
            """
            () => {
              const scripts = Array.from(document.scripts).map(s => s.textContent || "");
              return scripts.filter(text => text.includes("postMessage") || text.includes("addEventListener('message'") || text.includes('addEventListener(\"message\"')).slice(0, 20);
            }
            """
        )
        page_source = await self.page.content()
        artifacts: Dict[str, Any] = {
            "url": self.page.url,
            "network": list(self.network),
            "console": list(self.console_logs) if task.extract_console else [],
            "page_source": page_source,
            "script_srcs": script_srcs,
            "postmessage_listeners": postmessage_listeners,
            "dom_sinks": _detect_dom_sinks(page_source),
        }
        if task.capture_screenshots:
            screenshot = await self.page.screenshot()
            artifacts["screenshot"] = screenshot.hex()
        return artifacts

    def _attach_observers(self) -> None:
        if self.page is None:
            return
        self.page.on("console", lambda msg: self.console_logs.append({"type": msg.type, "text": msg.text}))
        self.page.on("request", lambda req: self.network.append({"event": "request", "method": req.method, "url": req.url}))
        self.page.on("response", lambda resp: self.network.append({"event": "response", "status": resp.status, "url": resp.url}))


def _detect_dom_sinks(content: str) -> List[Dict[str, str]]:
    import re

    patterns = {
        "innerHTML": r"innerHTML\s*=",
        "document.write": r"document\.write\s*\(",
        "eval": r"eval\s*\(",
        "location": r"window\.location|location\.href",
    }
    findings = []
    for sink_type, pattern in patterns.items():
        for match in re.finditer(pattern, content, flags=re.IGNORECASE):
            start = max(match.start() - 40, 0)
            end = min(match.end() + 80, len(content))
            findings.append({"type": sink_type, "evidence": content[start:end], "parameter": None})
    return findings

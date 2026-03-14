import pytest

from chimera_core.capabilities.browser.automation import BrowserAutomation
from chimera_core.capabilities.browser.browser_task import ActionType, BrowserAction, BrowserTask
from chimera_core.capabilities.browser.llm_interface import suggest_browser_task
from chimera_core.capabilities.browser.validators.dom_xss import DOMXSSValidator


class FakePage:
    def __init__(self) -> None:
        self.url = ""
        self._handlers = {}
        self._content = "<script>node.innerHTML = location.search; window.addEventListener('message', handler)</script>"

    def on(self, event: str, handler) -> None:
        self._handlers[event] = handler

    async def goto(self, url: str, timeout: int = 0):
        self.url = url
        return None

    async def click(self, selector: str, timeout: int = 0):
        return None

    async def fill(self, selector: str, value: str, timeout: int = 0):
        return None

    async def wait_for_selector(self, selector: str, timeout: int = 0):
        return None

    async def wait_for_load_state(self, state: str, timeout: int = 0):
        return None

    async def evaluate(self, js_code: str):
        if "document.scripts" in js_code:
            return ["window.addEventListener('message', handler)"]
        return {"ok": True}

    async def eval_on_selector_all(self, selector: str, script: str):
        return ["https://cdn.example.com/app.js"]

    async def content(self) -> str:
        return self._content

    async def screenshot(self) -> bytes:
        return b"fake"


class FakeContext:
    def __init__(self) -> None:
        self.tracing = self

    async def new_page(self):
        return FakePage()

    async def add_cookies(self, cookies):
        return None

    async def start(self, screenshots: bool = True, snapshots: bool = True):
        return None

    async def stop(self):
        return None


class FakeBrowser:
    async def new_context(self):
        return FakeContext()

    async def close(self):
        return None


async def fake_browser_factory(headless: bool):
    browser = FakeBrowser()
    context = await browser.new_context()
    page = await context.new_page()
    return browser, context, page


@pytest.mark.asyncio
async def test_browser_automation_executes_task() -> None:
    automation = BrowserAutomation(browser_factory=fake_browser_factory)
    await automation.start()
    try:
        artifacts = await automation.execute_task(
            BrowserTask(actions=[BrowserAction(type=ActionType.NAVIGATE, url="https://www.example.com")])
        )
    finally:
        await automation.close()

    assert artifacts["url"] == "https://www.example.com"
    assert artifacts["script_srcs"]
    assert artifacts["dom_sinks"]


@pytest.mark.asyncio
async def test_suggest_browser_task_parses_llm_json() -> None:
    async def fake_llm(prompt: str) -> str:
        return '{"actions":[{"type":"navigate","url":"https://www.example.com"}],"capture_screenshots":true}'

    task = await suggest_browser_task({"dom_snapshot": "<form></form>"}, "test a form", llm_callable=fake_llm)

    assert task.actions[0].type == ActionType.NAVIGATE


@pytest.mark.asyncio
async def test_dom_xss_validator_uses_deterministic_artifacts() -> None:
    validator = DOMXSSValidator(browser_factory=fake_browser_factory)
    result = await validator.validate("https://www.example.com/search?q=<svg>", "input[name='q']", "<svg>")

    assert result.status == "confirmed"
    assert result.confidence >= 0.95

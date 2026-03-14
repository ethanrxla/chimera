from chimera_core.capabilities.browser.automation import BrowserAutomation
from chimera_core.capabilities.browser.browser_task import ActionType, BrowserAction, BrowserTask
from chimera_core.capabilities.browser.llm_interface import suggest_browser_task

__all__ = [
    "ActionType",
    "BrowserAction",
    "BrowserAutomation",
    "BrowserTask",
    "suggest_browser_task",
]

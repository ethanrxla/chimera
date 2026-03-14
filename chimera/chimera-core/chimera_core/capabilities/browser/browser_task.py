from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    NAVIGATE = "navigate"
    CLICK = "click"
    FILL = "fill"
    SCREENSHOT = "screenshot"
    EXTRACT_DOM = "extract_dom"
    EXTRACT_CONSOLE = "extract_console"
    WAIT_FOR_NAVIGATION = "wait_for_navigation"
    WAIT_FOR_SELECTOR = "wait_for_selector"
    EXECUTE_JS = "execute_js"


class BrowserAction(BaseModel):
    type: ActionType
    selector: Optional[str] = None
    value: Optional[str] = None
    url: Optional[str] = None
    js_code: Optional[str] = None
    timeout: int = 30000


class BrowserTask(BaseModel):
    actions: List[BrowserAction] = Field(default_factory=list)
    capture_har: bool = True
    capture_screenshots: bool = True
    extract_console: bool = True
    context: Dict[str, Any] = Field(default_factory=dict)

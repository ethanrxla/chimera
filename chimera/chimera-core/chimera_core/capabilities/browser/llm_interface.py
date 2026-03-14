from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, Optional

from chimera_core.capabilities.browser.browser_task import BrowserTask


async def suggest_browser_task(
    context: Dict[str, Any],
    hypothesis: str,
    *,
    llm_callable: Optional[Callable[[str], Awaitable[str]]] = None,
) -> BrowserTask:
    if llm_callable is None:
        return BrowserTask(actions=[], context={"reason": "llm_unavailable", "hypothesis": hypothesis})

    dom_snapshot = str(context.get("dom_snapshot") or "")[:2000]
    prompt = (
        "You are guiding browser automation for security testing.\n"
        f"Hypothesis: {hypothesis}\n"
        f"DOM snapshot excerpt:\n{dom_snapshot}\n\n"
        "Return ONLY JSON matching BrowserTask with actions using these types: "
        "navigate, click, fill, wait_for_selector, wait_for_navigation, execute_js.\n"
        "Do not include secrets or arbitrary unbounded scripts."
    )
    try:
        response = await llm_callable(prompt)
        payload = json.loads(response)
        task = BrowserTask(**payload)
        if task.context is None:
            task.context = {}
        task.context.setdefault("hypothesis", hypothesis)
        return task
    except Exception:
        return BrowserTask(actions=[], context={"reason": "llm_parse_failed", "hypothesis": hypothesis})

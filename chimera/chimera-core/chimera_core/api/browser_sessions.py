from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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
    session_id: str = ""
    artifacts_dir: Optional[str] = None
    observable: bool = False

    def __post_init__(self) -> None:
        self._automation: Optional[BrowserAutomation] = None
        self._lock = asyncio.Lock()
        self._current_url = self.target
        self._capture_index = 0
        self._last_capture: Dict[str, Any] = {}
        self._artifacts_path = Path(self.artifacts_dir) if self.artifacts_dir else None
        if self._artifacts_path is not None:
            self._artifacts_path.mkdir(parents=True, exist_ok=True)

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
            artifacts = self._persist_capture(artifacts, task_to_run)
            self._current_url = artifacts.get("url") or url or self._current_url
            self._last_capture = artifacts
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
            self._append_session_event({"event": "close"})

    async def get_console(self, *, limit: int = 200) -> Dict[str, Any]:
        async with self._lock:
            console = list(self._last_capture.get("console") or [])
            if limit > 0:
                console = console[-limit:]
            return {
                "session_id": self.session_id,
                "count": len(console),
                "console": console,
                "artifact_ref": self._last_capture.get("console_artifact_ref"),
                "capture_artifact_ref": self._last_capture.get("capture_artifact_ref"),
            }

    async def get_network(self, *, limit: int = 200) -> Dict[str, Any]:
        async with self._lock:
            network = list(self._last_capture.get("network") or [])
            if limit > 0:
                network = network[-limit:]
            return {
                "session_id": self.session_id,
                "count": len(network),
                "network": network,
                "artifact_ref": self._last_capture.get("network_artifact_ref"),
                "capture_artifact_ref": self._last_capture.get("capture_artifact_ref"),
            }

    async def get_latest_capture(self) -> Dict[str, Any]:
        async with self._lock:
            return dict(self._last_capture)

    async def get_screenshot_bytes(self) -> bytes | None:
        async with self._lock:
            screenshot_ref = str(self._last_capture.get("screenshot_artifact_ref") or "")
            if not screenshot_ref or self._artifacts_path is None:
                return None
            screenshot_path = self._artifacts_path / Path(screenshot_ref).name
            if not screenshot_path.exists():
                return None
            return screenshot_path.read_bytes()

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

    def _persist_capture(self, artifacts: Dict[str, Any], task: BrowserTask) -> Dict[str, Any]:
        self._capture_index += 1
        capture = dict(artifacts)
        capture.setdefault("browser_session_id", self.session_id or None)
        capture.setdefault("observable", self.observable)

        if self._artifacts_path is None:
            return capture

        capture_stem = f"capture_{self._capture_index:04d}"

        page_source = str(capture.get("page_source") or "")
        if page_source:
            page_source_name = f"{capture_stem}.html"
            (self._artifacts_path / page_source_name).write_text(page_source, encoding="utf-8")
            capture["page_source_artifact_ref"] = page_source_name

        console = capture.get("console")
        if isinstance(console, list):
            console_name = f"{capture_stem}_console.json"
            (self._artifacts_path / console_name).write_text(json.dumps(console, indent=2), encoding="utf-8")
            capture["console_artifact_ref"] = console_name

        network = capture.get("network")
        if isinstance(network, list):
            network_name = f"{capture_stem}_network.json"
            (self._artifacts_path / network_name).write_text(json.dumps(network, indent=2), encoding="utf-8")
            capture["network_artifact_ref"] = network_name

        screenshot_hex = str(capture.get("screenshot") or "")
        if screenshot_hex:
            screenshot_name = f"{capture_stem}.png"
            try:
                (self._artifacts_path / screenshot_name).write_bytes(bytes.fromhex(screenshot_hex))
                capture["screenshot_artifact_ref"] = screenshot_name
            except ValueError:
                pass

        capture_payload = {
            "schema": "chimera.browser_capture.v1",
            "session_id": self.session_id,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "observable": self.observable,
            "headless": self.headless,
            "task": task.model_dump() if hasattr(task, "model_dump") else dict(task),
            "capture": capture,
        }
        capture_name = f"{capture_stem}.json"
        (self._artifacts_path / capture_name).write_text(json.dumps(capture_payload, indent=2), encoding="utf-8")
        capture["capture_artifact_ref"] = capture_name
        self._append_session_event(
            {
                "event": "capture",
                "capture_artifact_ref": capture_name,
                "url": capture.get("url"),
                "status_code": capture.get("status_code"),
                "screenshot_artifact_ref": capture.get("screenshot_artifact_ref"),
            }
        )
        return capture

    def _append_session_event(self, payload: Dict[str, Any]) -> None:
        if self._artifacts_path is None:
            return
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            **payload,
        }
        events_path = self._artifacts_path / "session_events.jsonl"
        with events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event))
            handle.write("\n")

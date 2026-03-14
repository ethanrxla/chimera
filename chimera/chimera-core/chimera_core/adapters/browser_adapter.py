from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from chimera_core.adapters.base import AdapterBase
from chimera_core.capabilities.browser import BrowserAutomation
from chimera_core.capabilities.browser.browser_task import ActionType, BrowserAction, BrowserTask
from chimera_core.capabilities.browser.llm_interface import suggest_browser_task
from chimera_core.capabilities.browser.validators.dom_xss import DOMXSSValidator
from chimera_core.findings import Finding


class BrowserAdapter(AdapterBase):
    id = "browser"
    capabilities = ["dom-analysis", "network-capture"]

    def __init__(
        self,
        runtime,
        options: Optional[Dict[str, object]] = None,
        run_id: str = "mock_run_id",
        task_id: str = "mock_task_id",
        scope_hash: str = "mock_scope_hash",
        artifacts_root: Optional[Path] = None,
    ) -> None:
        self.runtime = runtime
        self.scope_graph = runtime.scope_graph
        self.scope_policy = runtime.scope_policy
        self.options = options or {}
        self.run_id = run_id
        self.task_id = task_id
        self.scope_hash = scope_hash
        self.artifacts_root = artifacts_root or runtime.artifacts_root
        self.headless = bool(self.options.get("headless", True))

    def _artifact_dir(self) -> Path:
        return Path(self.artifacts_root) / self.run_id / self.id / self.task_id

    def run(self, targets: List[str], *args, **kwargs) -> dict:
        if not targets:
            raise ValueError("Browser adapter requires a target URL")
        target = targets[0]
        if not self.scope_graph.is_in_scope(target):
            raise ValueError(f"Target out of scope: {target}")
        mode = str(self.options.get("mode") or "analyze")
        capture = self.options.get("capture_override")
        findings: List[Finding]
        extra_artifacts: List[Dict[str, str]] = []
        if mode == "trace_xss":
            trace_result = asyncio.run(self.trace_xss_sink(target, parameter=str(self.options.get("parameter") or "q"), payload=str(self.options.get("payload") or "<svg/onload=alert(1)>")))
            capture = trace_result
            findings = self._findings_from_trace_result(target, trace_result)
            extra_artifacts.append({"path": str(self._artifact_dir() / "trace_result.json"), "artifact_type": "xss_trace", "tool": self.id})
        else:
            if capture is None:
                capture = asyncio.run(self.analyze_page(target, auth_cookies=self.options.get("auth_cookies")))
            findings = self.normalize(capture)
        artifact_dir = self._artifact_dir()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        capture_name = "trace_result.json" if mode == "trace_xss" else "browser_capture.json"
        capture_path = artifact_dir / capture_name
        capture_path.write_text(json.dumps(capture, indent=2), encoding="utf-8")
        findings_path = artifact_dir / "findings.json"
        findings_path.write_text(json.dumps([finding.to_dict() for finding in findings], indent=2), encoding="utf-8")
        return {
            "events": [{"level": "info", "message": f"{self.id} completed", "targets": targets}],
            "artifacts": [
                {"path": str(capture_path), "artifact_type": "browser_capture", "tool": self.id},
                {"path": str(findings_path), "artifact_type": "findings", "tool": self.id},
            ] + extra_artifacts,
            "raw_output_refs": [json.dumps(capture)],
            "findings": findings,
            "command": None,
        }

    async def analyze_page(self, url: str, auth_cookies: Optional[dict] = None) -> Dict[str, Any]:
        browser_factory = self.options.get("browser_factory")
        if browser_factory is not None:
            return await browser_factory(url, auth_cookies)
        task = BrowserTask(
            actions=[
                BrowserAction(type=ActionType.NAVIGATE, url=url),
                BrowserAction(type=ActionType.WAIT_FOR_NAVIGATION),
            ],
            context={"auth_cookies": auth_cookies or {}},
        )
        browser = BrowserAutomation(headless=self.headless, browser_factory=self.options.get("playwright_factory"))
        await browser.start()
        try:
            if auth_cookies and getattr(browser.context, "add_cookies", None):
                await browser.context.add_cookies([{"name": key, "value": value, "url": url} for key, value in auth_cookies.items()])
            return await browser.execute_task(task)
        finally:
            await browser.close()

    async def suggest_task(self, context: Dict[str, Any], hypothesis: str) -> BrowserTask:
        return await suggest_browser_task(context, hypothesis, llm_callable=self.options.get("llm_callable"))

    async def trace_xss_sink(self, url: str, parameter: str, payload: str) -> Dict[str, Any]:
        validator = DOMXSSValidator(browser_factory=self.options.get("playwright_factory"), headless=self.headless)
        result = await validator.validate(url=f"{url}?{parameter}={payload}", injection_point=f"input[name='{parameter}']", payload=payload)
        return {
            "status": result.status,
            "confidence": result.confidence,
            "proof_artifacts": result.proof_artifacts,
            "replay_steps": result.replay_steps,
            "explanation": result.explanation,
        }

    def normalize(self, raw_output: Any) -> List[Finding]:
        if isinstance(raw_output, str):
            data = json.loads(raw_output)
        else:
            data = raw_output
        findings: List[Finding] = []
        for sink in data.get("dom_sinks", []):
            findings.append(
                Finding(
                    finding_id=f"browser:{data.get('url')}:{sink['type']}",
                    severity="medium",
                    title=f"Potential DOM sink: {sink['type']}",
                    description=sink["evidence"],
                    affected_target=data.get("url", "unknown"),
                    tool_source=self.id,
                    tool_version="playwright",
                    run_id=self.run_id,
                    scope_hash=self.scope_hash,
                    finding_type="DOM_XSS",
                    asset={"host": _host(data.get("url", "")), "endpoint": _path(data.get("url", "")), "method": "GET", "parameter": sink.get("parameter")},
                    confidence=0.68,
                    sink=sink["type"],
                )
            )
        if data.get("console"):
            findings.append(
                Finding(
                    finding_id=f"browser:{data.get('url')}:console",
                    severity="info",
                    title="Browser console activity captured",
                    description="\n".join(item.get("text", "") for item in data.get("console", [])[:10]),
                    affected_target=data.get("url", "unknown"),
                    tool_source=self.id,
                    tool_version="playwright",
                    run_id=self.run_id,
                    scope_hash=self.scope_hash,
                    finding_type="BROWSER_TELEMETRY",
                    asset={"host": _host(data.get("url", "")), "endpoint": _path(data.get("url", "")), "method": "GET", "parameter": None},
                    confidence=0.4,
                )
            )
        if data.get("postmessage_listeners"):
            findings.append(
                Finding(
                    finding_id=f"browser:{data.get('url')}:postmessage",
                    severity="low",
                    title="postMessage listener surface detected",
                    description="\n".join(data.get("postmessage_listeners", [])[:5]),
                    affected_target=data.get("url", "unknown"),
                    tool_source=self.id,
                    tool_version="playwright",
                    run_id=self.run_id,
                    scope_hash=self.scope_hash,
                    finding_type="POSTMESSAGE_SURFACE",
                    asset={"host": _host(data.get("url", "")), "endpoint": _path(data.get("url", "")), "method": "GET", "parameter": None},
                    confidence=0.55,
                )
            )
        return findings

    def _findings_from_trace_result(self, target: str, trace_result: Dict[str, Any]) -> List[Finding]:
        status = str(trace_result.get("status") or "needs_replay")
        explanation = str(trace_result.get("explanation") or "")
        severity = "high" if status == "confirmed" else "info"
        finding = Finding(
            finding_id=f"browser-trace:{target}",
            severity=severity,
            title="DOM XSS sink validation",
            description=explanation,
            affected_target=target,
            tool_source=self.id,
            tool_version="playwright",
            run_id=self.run_id,
            scope_hash=self.scope_hash,
            finding_type="DOM_XSS",
            validation_status="confirmed" if status == "confirmed" else "false_positive" if status == "false_positive" else "needs_replay",
            validation_reason=explanation,
            confidence=float(trace_result.get("confidence") or 0.5),
            proof_artifacts=list(trace_result.get("proof_artifacts") or []),
            replay_steps=list(trace_result.get("replay_steps") or []),
            asset={"host": _host(target), "endpoint": _path(target), "method": "GET", "parameter": self.options.get("parameter")},
            sink="innerHTML",
        )
        return [finding]

def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url


def _path(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).path or "/"

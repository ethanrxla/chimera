"""
Tool executor for Chimera autonomous agents.

This is the security boundary between LLM tool calls and actual system
interaction.  Every tool invocation passes through scope checking, rate
limiting, and output truncation before results are returned to the LLM.
"""
from __future__ import annotations

import fnmatch
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from chimera_core.agents.llm_provider import ToolCall
from chimera_core.scope import ScopeGraph, ScopePolicy


# Maximum characters returned to the LLM from a single tool call.
# Prevents a large HTTP response from filling the entire context window.
MAX_RESULT_CHARS = 8_000


@dataclass
class ToolResult:
    """Result of executing a tool call."""
    tool_use_id: str
    output: str
    is_error: bool = False
    artifact_path: Optional[str] = None  # path to full saved artifact
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_use_id": self.tool_use_id,
            "output": self.output,
            "is_error": self.is_error,
            "artifact_path": self.artifact_path,
        }


@dataclass
class ReportedFinding:
    """A vulnerability reported by the agent via the report_finding tool."""
    title: str
    severity: str
    vuln_type: str
    affected_endpoint: str
    description: str
    poc_steps: List[str]
    evidence: str
    curl_command: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "title": self.title,
            "severity": self.severity,
            "vuln_type": self.vuln_type,
            "affected_endpoint": self.affected_endpoint,
            "description": self.description,
            "poc_steps": self.poc_steps,
            "evidence": self.evidence,
        }
        if self.curl_command:
            result["curl_command"] = self.curl_command
        return result


class ToolExecutor:
    """
    Executes tool calls from LLM agents within scope and budget constraints.

    Security model:
    - All HTTP requests are scope-checked against ScopeGraph before execution
    - Rate limiting is enforced via ScopePolicy
    - Tool output is truncated to MAX_RESULT_CHARS to prevent context bloat
    - Source code tools only work if a repo_path is configured
    - All raw results are saved to artifacts for replay
    """

    def __init__(
        self,
        scope_graph: ScopeGraph,
        scope_policy: ScopePolicy,
        artifacts_dir: Path,
        run_id: str,
        task_id: str = "agent",
        repo_path: Optional[Path] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        artifact_namespace: Optional[str] = None,
    ):
        self.scope_graph = scope_graph
        self.scope_policy = scope_policy
        self.artifacts_dir = Path(artifacts_dir)
        self.run_id = run_id
        self.task_id = task_id
        self.repo_path = repo_path
        self._http_client = http_client
        self.artifact_namespace = artifact_namespace
        self._request_count = 0
        self._last_request_time = 0.0
        self._playwright_browser = None
        self._playwright_context = None

        # Findings collected during execution
        self.reported_findings: List[ReportedFinding] = []

        # Tool call log for artifact saving
        self._call_log: List[Dict[str, Any]] = []

        # Ensure artifacts directory exists
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

    async def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=10),
            )
        return self._http_client

    # ── Public API ────────────────────────────────────────────────────────

    async def execute(self, tool_call: ToolCall) -> ToolResult:
        """
        Execute a tool call from the LLM.

        1. Validate tool name is registered
        2. Scope-check target URLs against ScopeGraph
        3. Rate-limit check
        4. Execute the tool
        5. Save raw result as artifact
        6. Return truncated result to LLM
        """
        handlers = {
            "http_request": self._exec_http_request,
            "browser_navigate": self._exec_browser_navigate,
            "browser_interact": self._exec_browser_interact,
            "browser_fill_submit": self._exec_browser_fill_submit,
            "read_source_file": self._exec_read_source_file,
            "search_source_code": self._exec_search_source_code,
            "list_source_files": self._exec_list_source_files,
            "report_finding": self._exec_report_finding,
        }

        handler = handlers.get(tool_call.name)
        if handler is None:
            return ToolResult(
                tool_use_id=tool_call.id,
                output=f"Error: Unknown tool '{tool_call.name}'.  Available: {', '.join(handlers.keys())}",
                is_error=True,
            )

        try:
            result = await handler(tool_call.arguments)
            # Truncate output to prevent context bloat
            if len(result.output) > MAX_RESULT_CHARS:
                truncated = result.output[:MAX_RESULT_CHARS]
                result.output = truncated + f"\n\n[TRUNCATED — full output saved to {result.artifact_path}]"
            result.tool_use_id = tool_call.id

            # Log the call
            self._call_log.append({
                "call_id": tool_call.id,
                "tool": tool_call.name,
                "args": tool_call.arguments,
                "output_length": len(result.output),
                "is_error": result.is_error,
                "timestamp": time.time(),
            })

            return result
        except Exception as exc:
            return ToolResult(
                tool_use_id=tool_call.id,
                output=f"Error executing {tool_call.name}: {exc}",
                is_error=True,
            )

    # ── Tool implementations ─────────────────────────────────────────────

    async def _exec_http_request(self, params: Dict[str, Any]) -> ToolResult:
        """Send an HTTP request within scope."""
        method = str(params.get("method", "GET")).upper()
        url = str(params.get("url", ""))
        headers = dict(params.get("headers") or {})
        body = params.get("body")
        follow = bool(params.get("follow_redirects", True))

        # Scope check
        if not self.scope_graph.is_in_scope(url):
            return ToolResult(
                tool_use_id="",
                output=f"SCOPE VIOLATION: {url} is not in the allowed scope.  In-scope targets: {self.scope_graph.allowed_domains}",
                is_error=True,
            )

        # Rate limiting
        self._enforce_rate_limit()

        # Execute
        client = await self._get_http_client()
        try:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode("utf-8") if body else None,
                follow_redirects=follow,
            )
        except httpx.ConnectError as exc:
            return ToolResult(tool_use_id="", output=f"Connection error: {exc}", is_error=True)
        except httpx.ReadTimeout:
            return ToolResult(tool_use_id="", output="Request timed out after 30 seconds", is_error=True)

        self._request_count += 1

        # Format response
        resp_headers = dict(response.headers)
        body_text = response.text

        # Save full response as artifact
        artifact_path = self._save_artifact(
            f"http_{self._request_count}",
            json.dumps({
                "request": {"method": method, "url": url, "headers": headers, "body": body},
                "response": {
                    "status_code": response.status_code,
                    "headers": resp_headers,
                    "body": body_text,
                },
            }, indent=2),
        )

        # Format for LLM (compact)
        output = f"HTTP {response.status_code} {method} {url}\n"
        output += f"Content-Type: {resp_headers.get('content-type', 'unknown')}\n"
        output += f"Content-Length: {len(body_text)}\n\n"
        output += body_text

        return ToolResult(tool_use_id="", output=output, artifact_path=str(artifact_path))

    async def _exec_browser_navigate(self, params: Dict[str, Any]) -> ToolResult:
        """Navigate headless browser to URL."""
        url = str(params.get("url", ""))
        wait_for = str(params.get("wait_for", "networkidle"))
        extract_selectors = list(params.get("extract_selectors") or [])

        if not self.scope_graph.is_in_scope(url):
            return ToolResult(
                tool_use_id="",
                output=f"SCOPE VIOLATION: {url} is not in scope.",
                is_error=True,
            )

        self._enforce_rate_limit()

        try:
            page = await self._get_browser_page()
            network_log: List[str] = []

            # Capture network requests
            def on_request(request):
                network_log.append(f"{request.method} {request.url}")

            page.on("request", on_request)

            await page.goto(url, wait_until=wait_for, timeout=30000)

            # Get page content
            title = await page.title()
            content = await page.content()

            # Extract text from selectors
            extracted = {}
            for selector in extract_selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    texts = []
                    for el in elements:
                        text = await el.inner_text()
                        texts.append(text.strip())
                    extracted[selector] = texts
                except Exception:
                    extracted[selector] = ["(selector not found)"]

            # Save full content as artifact
            artifact_path = self._save_artifact(
                f"browser_{self._request_count}",
                json.dumps({
                    "url": url,
                    "title": title,
                    "html_length": len(content),
                    "network_log": network_log[:50],
                    "extracted": extracted,
                }, indent=2),
            )
            self._request_count += 1

            # Format for LLM
            output = f"Page: {title}\nURL: {url}\n"
            output += f"HTML length: {len(content)} chars\n\n"
            if network_log:
                output += "Network requests:\n"
                for req in network_log[:20]:
                    output += f"  {req}\n"
                output += "\n"
            if extracted:
                output += "Extracted content:\n"
                for sel, texts in extracted.items():
                    output += f"  {sel}: {texts}\n"
                output += "\n"
            # Include a snippet of the HTML body
            output += "Page content (first 4000 chars):\n"
            output += content[:4000]

            return ToolResult(tool_use_id="", output=output, artifact_path=str(artifact_path))

        except Exception as exc:
            return ToolResult(tool_use_id="", output=f"Browser error: {exc}", is_error=True)

    async def _exec_browser_interact(self, params: Dict[str, Any]) -> ToolResult:
        """Interact with a page: fill forms, click buttons."""
        url = str(params.get("url", ""))
        actions = list(params.get("actions") or [])

        if not self.scope_graph.is_in_scope(url):
            return ToolResult(
                tool_use_id="",
                output=f"SCOPE VIOLATION: {url} is not in scope.",
                is_error=True,
            )

        self._enforce_rate_limit()

        try:
            page = await self._get_browser_page()
            network_log: List[str] = []

            def on_request(request):
                network_log.append(f"{request.method} {request.url}")

            def on_response(response):
                network_log.append(f"  → {response.status} {response.url}")

            page.on("request", on_request)
            page.on("response", on_response)

            await page.goto(url, wait_until="networkidle", timeout=30000)

            results = []
            for action in actions:
                act = str(action.get("action", ""))
                selector = str(action.get("selector", ""))

                if act == "fill" and selector:
                    value = str(action.get("value", ""))
                    await page.fill(selector, value)
                    results.append(f"Filled '{selector}' with '{value}'")

                elif act == "click" and selector:
                    await page.click(selector)
                    results.append(f"Clicked '{selector}'")
                    # Wait for network activity after click
                    try:
                        await page.wait_for_load_state("networkidle", timeout=10000)
                    except Exception:
                        pass

                elif act == "wait":
                    wait_ms = int(action.get("wait_ms", 1000))
                    await page.wait_for_timeout(wait_ms)
                    results.append(f"Waited {wait_ms}ms")

            self._request_count += 1

            # Capture final page state
            final_content = await page.content()
            final_url = page.url

            artifact_path = self._save_artifact(
                f"browser_interact_{self._request_count}",
                json.dumps({
                    "initial_url": url,
                    "final_url": final_url,
                    "actions": actions,
                    "results": results,
                    "network_log": network_log[:50],
                    "final_html_length": len(final_content),
                }, indent=2),
            )

            output = f"Performed {len(actions)} actions on {url}\n"
            output += f"Final URL: {final_url}\n\n"
            for r in results:
                output += f"  ✓ {r}\n"
            output += f"\nNetwork activity ({len(network_log)} requests):\n"
            for entry in network_log[:20]:
                output += f"  {entry}\n"
            output += f"\nFinal page content (first 3000 chars):\n"
            output += final_content[:3000]

            return ToolResult(tool_use_id="", output=output, artifact_path=str(artifact_path))

        except Exception as exc:
            return ToolResult(tool_use_id="", output=f"Browser interaction error: {exc}", is_error=True)

    async def _exec_browser_fill_submit(self, params: Dict[str, Any]) -> ToolResult:
        """Convenience wrapper for simple form fill + submit workflows."""
        fields = dict(params.get("fields") or {})
        actions: List[Dict[str, Any]] = []
        for selector, value in fields.items():
            actions.append({"action": "fill", "selector": str(selector), "value": str(value)})
        actions.append({"action": "click", "selector": str(params.get("submit_selector") or "")})
        return await self._exec_browser_interact({"url": params.get("url"), "actions": actions})

    async def _exec_read_source_file(self, params: Dict[str, Any]) -> ToolResult:
        """Read a source file from the target repo."""
        if self.repo_path is None:
            return ToolResult(
                tool_use_id="",
                output="Source code not available.  No repo_path configured (black-box mode).",
                is_error=True,
            )

        rel_path = str(params.get("path", ""))
        start_line = params.get("start_line")
        end_line = params.get("end_line")

        # Sanitize path to prevent traversal
        resolved = (self.repo_path / rel_path).resolve()
        if not str(resolved).startswith(str(self.repo_path.resolve())):
            return ToolResult(
                tool_use_id="",
                output=f"Path traversal blocked: {rel_path}",
                is_error=True,
            )

        if not resolved.exists():
            return ToolResult(tool_use_id="", output=f"File not found: {rel_path}", is_error=True)

        if not resolved.is_file():
            return ToolResult(tool_use_id="", output=f"Not a file: {rel_path}", is_error=True)

        try:
            content = resolved.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return ToolResult(tool_use_id="", output=f"Error reading file: {exc}", is_error=True)

        lines = content.splitlines()

        # Apply line range
        if start_line is not None or end_line is not None:
            s = max((start_line or 1) - 1, 0)
            e = min(end_line or len(lines), len(lines))
            # Cap at 200 lines
            if e - s > 200:
                e = s + 200
            lines = lines[s:e]
            line_info = f" (lines {s + 1}-{e})"
        else:
            if len(lines) > 200:
                lines = lines[:200]
                line_info = " (first 200 lines)"
            else:
                line_info = ""

        numbered = "\n".join(f"{i + 1}: {line}" for i, line in enumerate(lines))
        output = f"File: {rel_path}{line_info}\n{len(lines)} lines\n\n{numbered}"

        return ToolResult(tool_use_id="", output=output)

    async def _exec_search_source_code(self, params: Dict[str, Any]) -> ToolResult:
        """Search source code for a pattern."""
        if self.repo_path is None:
            return ToolResult(
                tool_use_id="",
                output="Source code not available.  No repo_path configured (black-box mode).",
                is_error=True,
            )

        pattern = str(params.get("pattern", ""))
        file_glob = str(params.get("file_glob", "**/*"))
        is_regex = bool(params.get("is_regex", False))
        max_results = min(int(params.get("max_results", 20)), 50)

        if not pattern:
            return ToolResult(tool_use_id="", output="Error: pattern is required", is_error=True)

        # Use grep for speed
        try:
            cmd = ["grep", "-rn", "--include", file_glob, "-m", str(max_results)]
            if not is_regex:
                cmd.append("-F")
            cmd.extend([pattern, str(self.repo_path)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                cwd=self.repo_path,
            )
            raw = result.stdout

            if not raw.strip():
                return ToolResult(tool_use_id="", output=f"No matches found for: {pattern}")

            # Format output — strip repo path prefix for readability
            repo_prefix = str(self.repo_path) + "/"
            lines = []
            for line in raw.strip().splitlines()[:max_results]:
                cleaned = line.replace(repo_prefix, "")
                lines.append(cleaned)

            output = f"Search results for '{pattern}':\n\n" + "\n".join(lines)
            return ToolResult(tool_use_id="", output=output)

        except subprocess.TimeoutExpired:
            return ToolResult(tool_use_id="", output="Search timed out after 15 seconds", is_error=True)
        except Exception as exc:
            return ToolResult(tool_use_id="", output=f"Search error: {exc}", is_error=True)

    async def _exec_list_source_files(self, params: Dict[str, Any]) -> ToolResult:
        """List files in the source repo."""
        if self.repo_path is None:
            return ToolResult(
                tool_use_id="",
                output="Source code not available.  No repo_path configured (black-box mode).",
                is_error=True,
            )

        directory = str(params.get("directory", "."))
        glob_pattern = str(params.get("glob", "*"))
        max_depth = min(int(params.get("max_depth", 3)), 5)

        target_dir = (self.repo_path / directory).resolve()
        if not str(target_dir).startswith(str(self.repo_path.resolve())):
            return ToolResult(tool_use_id="", output="Path traversal blocked", is_error=True)

        if not target_dir.is_dir():
            return ToolResult(tool_use_id="", output=f"Not a directory: {directory}", is_error=True)

        entries: List[str] = []
        for path in sorted(target_dir.rglob(glob_pattern)):
            # Enforce depth limit
            rel = path.relative_to(target_dir)
            if len(rel.parts) > max_depth:
                continue
            # Skip hidden and common noise
            if any(part.startswith(".") for part in rel.parts):
                continue
            if any(part in ("node_modules", "__pycache__", ".git", "dist", "build") for part in rel.parts):
                continue

            kind = "dir" if path.is_dir() else "file"
            size = f" ({path.stat().st_size}B)" if path.is_file() else ""
            entries.append(f"  [{kind}] {rel}{size}")

            if len(entries) >= 100:
                entries.append("  ... (truncated at 100 entries)")
                break

        output = f"Contents of {directory}/ ({len(entries)} entries):\n\n" + "\n".join(entries)
        return ToolResult(tool_use_id="", output=output)

    async def _exec_report_finding(self, params: Dict[str, Any]) -> ToolResult:
        """Record a confirmed vulnerability finding."""
        finding = ReportedFinding(
            title=str(params.get("title", "Untitled")),
            severity=str(params.get("severity", "medium")),
            vuln_type=str(params.get("vuln_type", "unknown")),
            affected_endpoint=str(params.get("affected_endpoint", "")),
            description=str(params.get("description", "")),
            poc_steps=list(params.get("poc_steps") or []),
            evidence=str(params.get("evidence", "")),
            curl_command=params.get("curl_command"),
        )

        self.reported_findings.append(finding)

        # Save as artifact
        artifact_path = self._save_artifact(
            f"finding_{len(self.reported_findings)}",
            json.dumps(finding.to_dict(), indent=2),
        )

        return ToolResult(
            tool_use_id="",
            output=f"Finding recorded: [{finding.severity.upper()}] {finding.title}\nSaved to: {artifact_path}",
            artifact_path=str(artifact_path),
            metadata={"finding_index": len(self.reported_findings) - 1},
        )

    # ── Helpers ───────────────────────────────────────────────────────────

    def _enforce_rate_limit(self) -> None:
        """Simple rate limiter: enforce scope policy's max RPS."""
        min_interval = 1.0 / max(self.scope_policy.max_rps, 1)
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.monotonic()

    def _save_artifact(self, name: str, content: str) -> Path:
        """Save tool output to an artifact file."""
        artifact_dir = self._artifact_dir()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        path = artifact_dir / f"{name}.json"
        path.write_text(content, encoding="utf-8")
        return path

    def _artifact_dir(self) -> Path:
        if self.artifact_namespace:
            return self.artifacts_dir / self.run_id / self.artifact_namespace / self.task_id
        return self.artifacts_dir / self.run_id / "agent" / self.task_id

    async def _get_browser_page(self):
        """Get or create a Playwright browser page."""
        if self._playwright_browser is None:
            from playwright.async_api import async_playwright
            pw = await async_playwright().start()
            self._playwright_browser = await pw.chromium.launch(headless=True)
            self._playwright_context = await self._playwright_browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (X11; Linux x86_64) Chimera/1.0",
            )
        return await self._playwright_context.new_page()

    async def close(self) -> None:
        """Clean up resources."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
        if self._playwright_browser:
            await self._playwright_browser.close()

    def save_call_log(self) -> Path:
        """Save the complete tool call log as an artifact."""
        return self._save_artifact("tool_call_log", json.dumps(self._call_log, indent=2))

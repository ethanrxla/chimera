"""
Multi-turn autonomous agent loop for Chimera.

This is the core execution engine that replaces Shannon's claude-executor.ts.
It manages the conversation between the LLM and the tool executor, handling:
- Turn budgeting and token budget enforcement
- Context compaction to prevent context window overflow
- Finding collection via the report_finding tool
- Event emission for the TUI to display progress

Each agent runs one of these loops with a specialist system prompt and
a subset of the available tools.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from chimera_core.agents.llm_provider import LLMProvider, LLMResponse, TokenUsage, ToolCall
from chimera_core.agents.tool_executor import ToolExecutor, ToolResult, ReportedFinding
from chimera_core.agents.tools import AGENT_TOOLS, get_tools_for_role
from chimera_core.findings import Finding, stable_finding_id


@dataclass
class AgentResult:
    """Complete result of an agent run."""
    findings: List[Finding]
    reported: List[ReportedFinding]
    usage: TokenUsage
    turns: int
    duration_seconds: float
    stop_reason: str  # "budget_exhausted" | "agent_done" | "no_tool_calls" | "error"
    artifact_paths: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings_count": len(self.findings),
            "reported_count": len(self.reported),
            "usage": self.usage.to_dict(),
            "turns": self.turns,
            "duration_seconds": round(self.duration_seconds, 2),
            "stop_reason": self.stop_reason,
            "errors": self.errors,
        }


class AgentLoop:
    """
    Multi-turn autonomous agent loop.

    The agent receives a system prompt (specialist role), has access to tools,
    and runs until it either:
    - Reports findings via report_finding tool and signals completion
    - Exhausts its turn budget
    - Exhausts its token budget
    - Returns end_turn without pending tool calls (done exploring)

    Context compaction:
        Every ``compact_interval`` turns, older tool results are summarised to
        prevent context window overflow.  The last ``keep_recent_turns`` turns
        are kept verbatim; everything else is compressed.
    """

    def __init__(
        self,
        llm: LLMProvider,
        tool_executor: ToolExecutor,
        system_prompt: str,
        *,
        agent_role: str = "analysis",
        analysis_domain: str = "",
        max_turns: int = 200,
        max_input_tokens: int = 5_000_000,
        max_output_tokens: int = 500_000,
        compact_interval: int = 50,
        keep_recent_turns: int = 10,
        run_id: str = "",
        task_id: str = "",
        event_emitter: Optional[Callable] = None,
    ):
        self.llm = llm
        self.tool_executor = tool_executor
        self.system_prompt = system_prompt
        self.agent_role = agent_role
        self.analysis_domain = analysis_domain
        self.max_turns = max_turns
        self.max_input_tokens = max_input_tokens
        self.max_output_tokens = max_output_tokens
        self.compact_interval = compact_interval
        self.keep_recent_turns = keep_recent_turns
        self.run_id = run_id
        self.task_id = task_id
        self.event_emitter = event_emitter

        # Determine which tools to expose
        has_source = tool_executor.repo_path is not None
        self.tools = get_tools_for_role(agent_role, has_source_code=has_source)

    async def run(self, initial_context: str) -> AgentResult:
        """
        Execute the full agent loop.

        Args:
            initial_context: Initial user message describing the target,
                prior findings, and what to look for.

        Returns:
            AgentResult with collected findings, usage stats, and artifacts.
        """
        start_time = time.monotonic()
        total_usage = TokenUsage()
        errors: List[str] = []
        turn = 0
        stop_reason = "agent_done"
        # Count consecutive turns with no progress to detect stuck agents
        no_progress_turns = 0

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": initial_context},
        ]

        self._emit("agent_started", {
            "agent_role": self.agent_role,
            "analysis_domain": self.analysis_domain,
            "max_turns": self.max_turns,
            "tool_count": len(self.tools),
        })

        for turn in range(1, self.max_turns + 1):
            # Budget check — total input tokens
            if total_usage.input_tokens >= self.max_input_tokens:
                stop_reason = "input_budget_exhausted"
                self._emit("agent_budget_exhausted", {
                    "reason": "input_tokens",
                    "current": total_usage.input_tokens,
                    "limit": self.max_input_tokens,
                })
                break

            if total_usage.output_tokens >= self.max_output_tokens:
                stop_reason = "output_budget_exhausted"
                break

            # Context compaction
            if turn > 1 and turn % self.compact_interval == 0:
                messages = self._compact_context(messages)
                self._emit("agent_context_compacted", {"turn": turn, "message_count": len(messages)})

            # Call LLM
            self._emit("agent_turn_started", {"turn": turn})

            try:
                response = await self.llm.chat(
                    messages=messages,
                    tools=self.tools if self.tools else None,
                    temperature=0.0,
                    max_tokens=4096,
                )
            except Exception as exc:
                error_msg = f"LLM error on turn {turn}: {exc}"
                errors.append(error_msg)
                self._emit("agent_error", {"turn": turn, "error": error_msg})
                # Retry once after a pause
                if turn < self.max_turns:
                    time.sleep(2)
                    continue
                stop_reason = "error"
                break

            total_usage += response.usage

            # No tool calls — agent is done
            if not response.has_tool_calls:
                # Add assistant's final message
                messages.append({"role": "assistant", "content": response.content})
                self._emit("agent_turn_completed", {
                    "turn": turn,
                    "tool_calls": 0,
                    "content_length": len(response.content),
                })
                no_progress_turns += 1

                if no_progress_turns >= 3:
                    # Agent has returned text-only responses 3 times in a row — it's done
                    stop_reason = "agent_done"
                    break
                # Give the agent one more chance
                continue

            no_progress_turns = 0

            # Process tool calls
            tool_results: List[ToolResult] = []
            for tc in response.tool_calls:
                result = await self.tool_executor.execute(tc)
                tool_results.append(result)

                self._emit("agent_tool_called", {
                    "turn": turn,
                    "tool": tc.name,
                    "args_summary": _summarise_args(tc.arguments),
                    "output_length": len(result.output),
                    "is_error": result.is_error,
                })

            # Append assistant message with tool calls
            messages.append({
                "role": "assistant",
                "content": response.content,
                "tool_calls": response.tool_calls,
            })

            # Append tool results
            messages.append({
                "role": "tool",
                "results": [
                    {
                        "tool_use_id": r.tool_use_id,
                        "output": r.output,
                        "is_error": r.is_error,
                    }
                    for r in tool_results
                ],
            })

            self._emit("agent_turn_completed", {
                "turn": turn,
                "tool_calls": len(response.tool_calls),
                "findings_so_far": len(self.tool_executor.reported_findings),
                "input_tokens_total": total_usage.input_tokens,
            })

        else:
            stop_reason = "max_turns_reached"

        duration = time.monotonic() - start_time

        # Collect findings from the tool executor
        findings = self._convert_findings()

        # Save the tool call log
        call_log_path = self.tool_executor.save_call_log()

        # Save conversation trace
        trace_path = self._save_trace(messages, total_usage, turn, stop_reason)

        self._emit("agent_finished", {
            "turns": turn,
            "findings": len(findings),
            "stop_reason": stop_reason,
            "duration_seconds": round(duration, 2),
            "usage": total_usage.to_dict(),
        })

        # Clean up
        await self.tool_executor.close()

        return AgentResult(
            findings=findings,
            reported=list(self.tool_executor.reported_findings),
            usage=total_usage,
            turns=turn,
            duration_seconds=duration,
            stop_reason=stop_reason,
            artifact_paths=[str(call_log_path), str(trace_path)],
            errors=errors,
        )

    # ── Context management ────────────────────────────────────────────────

    def _compact_context(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Compress older messages to prevent context window overflow.

        Strategy:
        - Keep system message and initial user message intact
        - Keep the last ``keep_recent_turns`` turn pairs verbatim
        - Compress everything in between into a summary message
        """
        if len(messages) <= 4 + (self.keep_recent_turns * 2):
            return messages  # Not enough messages to compact

        # messages[0] = system, messages[1] = initial user context
        prefix = messages[:2]
        # Each "turn" is 2 messages: assistant + tool result
        # Keep recent turns
        keep_count = self.keep_recent_turns * 2
        middle = messages[2:-keep_count] if keep_count > 0 else messages[2:]
        recent = messages[-keep_count:] if keep_count > 0 else []

        # Summarise the middle section
        summary_parts = []
        findings_mentioned = 0
        tools_called = 0
        for msg in middle:
            if msg.get("role") == "assistant":
                tool_calls = msg.get("tool_calls", [])
                tools_called += len(tool_calls) if isinstance(tool_calls, list) else 0
            if msg.get("role") == "tool":
                results = msg.get("results", [])
                for r in results:
                    output = str(r.get("output", ""))
                    if "Finding recorded" in output:
                        findings_mentioned += 1

        summary = (
            f"[CONTEXT SUMMARY: {len(middle)} messages compacted.  "
            f"{tools_called} tool calls made, {findings_mentioned} findings recorded.  "
            f"See earlier artifacts for full details.]"
        )

        compacted = prefix + [{"role": "user", "content": summary}] + recent
        return compacted

    # ── Finding conversion ────────────────────────────────────────────────

    def _convert_findings(self) -> List[Finding]:
        """Convert ReportedFindings from tool executor into Chimera Finding objects."""
        findings = []
        for rf in self.tool_executor.reported_findings:
            finding_id = stable_finding_id(
                title=rf.title,
                affected_target=rf.affected_endpoint,
                tool_source="chimera-agent",
                signature=rf.vuln_type,
            )

            # Build replay steps from PoC
            replay_steps = []
            for i, step in enumerate(rf.poc_steps):
                replay_steps.append({
                    "step": i + 1,
                    "description": step,
                })
            if rf.curl_command:
                replay_steps.append({
                    "step": len(rf.poc_steps) + 1,
                    "description": f"Reproduce with: {rf.curl_command}",
                    "type": "curl",
                    "command": rf.curl_command,
                })

            findings.append(Finding(
                finding_id=finding_id,
                severity=rf.severity,
                title=rf.title,
                description=rf.description,
                affected_target=rf.affected_endpoint,
                tool_source="chimera-agent",
                tool_version=f"agent/{self.agent_role}/{self.analysis_domain}",
                run_id=self.run_id,
                scope_hash="agent-scope",
                evidence_refs=[rf.evidence[:500]] if rf.evidence else [],
                repro_guidance=rf.curl_command or "\n".join(rf.poc_steps),
                finding_type=rf.vuln_type.upper() if rf.vuln_type else None,
                confidence=0.95,  # Agent-confirmed with PoC
                replay_steps=replay_steps,
                exploit_status="exploited",
                asset={
                    "host": _host_from_url(rf.affected_endpoint),
                    "endpoint": _path_from_url(rf.affected_endpoint),
                    "method": None,
                    "parameter": None,
                },
            ))

        return findings

    # ── Tracing ───────────────────────────────────────────────────────────

    def _save_trace(
        self,
        messages: List[Dict[str, Any]],
        usage: TokenUsage,
        turns: int,
        stop_reason: str,
    ) -> Path:
        """Save the full conversation trace as an artifact."""
        # Strip large content from messages for the trace
        trace_messages = []
        for msg in messages:
            entry: Dict[str, Any] = {"role": msg.get("role", "")}
            content = msg.get("content", "")
            if isinstance(content, str) and len(content) > 2000:
                entry["content"] = content[:2000] + f"... [{len(content)} chars total]"
            else:
                entry["content"] = content

            if msg.get("tool_calls"):
                tcs = msg["tool_calls"]
                entry["tool_calls"] = [
                    {"name": tc.name if isinstance(tc, ToolCall) else tc.get("name"), "id": tc.id if isinstance(tc, ToolCall) else tc.get("id")}
                    for tc in tcs
                ]
            if msg.get("results"):
                entry["results_count"] = len(msg["results"])

            trace_messages.append(entry)

        trace = {
            "agent_role": self.agent_role,
            "analysis_domain": self.analysis_domain,
            "turns": turns,
            "stop_reason": stop_reason,
            "usage": usage.to_dict(),
            "findings_count": len(self.tool_executor.reported_findings),
            "messages": trace_messages,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        artifacts_dir = self.tool_executor._artifact_dir()
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        trace_path = artifacts_dir / "agent_trace.json"
        trace_path.write_text(json.dumps(trace, indent=2, default=str), encoding="utf-8")
        return trace_path

    # ── Events ────────────────────────────────────────────────────────────

    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Emit an event for the TUI/event stream."""
        if self.event_emitter is None:
            return
        full_payload = {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "agent_role": self.agent_role,
            "analysis_domain": self.analysis_domain,
            **payload,
        }
        try:
            self.event_emitter(event_type, full_payload)
        except Exception:
            pass  # Don't let event emission errors crash the agent


# ── Utilities ─────────────────────────────────────────────────────────────────

def _summarise_args(args: Dict[str, Any], max_len: int = 120) -> str:
    """Create a one-line summary of tool arguments for logging."""
    parts = []
    for key, value in args.items():
        val = str(value)
        if len(val) > 60:
            val = val[:57] + "..."
        parts.append(f"{key}={val}")
    summary = ", ".join(parts)
    if len(summary) > max_len:
        summary = summary[:max_len - 3] + "..."
    return summary


def _host_from_url(url: str) -> str:
    """Extract hostname from a URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def _path_from_url(url: str) -> str:
    """Extract path from a URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.path or "/"
    except Exception:
        return "/"

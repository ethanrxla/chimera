"""
LLM provider abstraction for Chimera autonomous agents.

Supports:
    - Anthropic API  (Claude Sonnet 4 / Opus 4)  → best agentic quality
    - OpenAI-compat  (GPT-4o, NVIDIA NIM, Ollama) → same interface, different base_url

All providers expose the same async ``chat()`` method so the AgentLoop
doesn't know or care which backend is running.

Tool calling is handled via the provider-native format and normalised into
a list of ``ToolCall`` objects.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

import httpx


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class TokenUsage:
    """Tracks token consumption for budget enforcement."""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    def __iadd__(self, other: "TokenUsage") -> "TokenUsage":
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        return self

    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def estimated_cost_usd(self, input_rate: float, output_rate: float) -> float:
        """Estimate cost in USD given per-million-token rates."""
        return (self.input_tokens * input_rate + self.output_tokens * output_rate) / 1_000_000

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "total_tokens": self.total_tokens(),
        }


@dataclass
class ToolCall:
    """A single tool invocation requested by the LLM."""
    id: str
    name: str
    arguments: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "name": self.name, "arguments": self.arguments}


@dataclass
class LLMResponse:
    """Normalised response from any LLM provider."""
    content: str
    tool_calls: List[ToolCall] = field(default_factory=list)
    usage: TokenUsage = field(default_factory=TokenUsage)
    stop_reason: str = "end_turn"

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


# ── Provider protocol ────────────────────────────────────────────────────────

class LLMProvider(Protocol):
    """Interface that all LLM backends must implement."""

    async def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        ...


# ── Anthropic (Claude) ───────────────────────────────────────────────────────

class AnthropicProvider:
    """
    Claude API via httpx (no SDK dependency).

    Supports tool use and prompt caching via Anthropic's native format.
    """

    API_URL = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        api_key: Optional[str] = None,
        prompt_caching: bool = True,
        max_retries: int = 3,
    ):
        self.model = model
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.prompt_caching = prompt_caching
        self.max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=300.0)
        return self._client

    async def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a chat completion request to the Anthropic API."""
        client = await self._get_client()

        # Separate system message from conversation
        system_content = None
        conversation = []
        for msg in messages:
            if msg.get("role") == "system":
                system_content = msg["content"]
            else:
                conversation.append(self._format_message(msg))

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
            "content-type": "application/json",
        }
        if self.prompt_caching:
            headers["anthropic-beta"] = "prompt-caching-2024-07-31"

        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": conversation,
        }

        if system_content:
            if self.prompt_caching:
                # Cache the system prompt for reuse across turns
                payload["system"] = [
                    {"type": "text", "text": system_content, "cache_control": {"type": "ephemeral"}}
                ]
            else:
                payload["system"] = system_content

        if tools:
            payload["tools"] = self._format_tools_anthropic(tools)

        # Retry loop with exponential backoff
        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                response = await client.post(self.API_URL, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return self._parse_anthropic_response(data)
            except httpx.HTTPStatusError as exc:
                last_error = exc
                if exc.response.status_code == 429:
                    # Rate limited — back off
                    wait = min(2 ** attempt * 2, 30)
                    await asyncio.sleep(wait)
                    continue
                if exc.response.status_code >= 500:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise
            except (httpx.ConnectError, httpx.ReadTimeout) as exc:
                last_error = exc
                await asyncio.sleep(2 ** attempt)
                continue

        raise RuntimeError(f"Anthropic API failed after {self.max_retries} retries: {last_error}")

    def _format_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Convert internal message format to Anthropic format."""
        role = msg["role"]
        content = msg.get("content", "")

        # Tool result messages
        if role == "tool":
            results = msg.get("results", [])
            content_blocks = []
            for result in results:
                content_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": result.get("tool_use_id", "unknown"),
                    "content": str(result.get("output", "")),
                    "is_error": result.get("is_error", False),
                })
            return {"role": "user", "content": content_blocks}

        # Assistant messages with tool calls
        if role == "assistant" and msg.get("tool_calls"):
            content_blocks = []
            if content:
                content_blocks.append({"type": "text", "text": content})
            for tc in msg["tool_calls"]:
                content_blocks.append({
                    "type": "tool_use",
                    "id": tc.id if isinstance(tc, ToolCall) else tc.get("id", ""),
                    "name": tc.name if isinstance(tc, ToolCall) else tc.get("name", ""),
                    "input": tc.arguments if isinstance(tc, ToolCall) else tc.get("arguments", {}),
                })
            return {"role": "assistant", "content": content_blocks}

        # Plain text messages
        return {"role": role, "content": content}

    def _format_tools_anthropic(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert generic tool definitions to Anthropic tool format."""
        formatted = []
        for tool in tools:
            entry: Dict[str, Any] = {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "input_schema": tool.get("parameters", {"type": "object", "properties": {}}),
            }
            # Cache tool definitions to save on input tokens
            if self.prompt_caching and tool == tools[-1]:
                entry["cache_control"] = {"type": "ephemeral"}
            formatted.append(entry)
        return formatted

    def _parse_anthropic_response(self, data: Dict[str, Any]) -> LLMResponse:
        """Parse Anthropic API response into normalised LLMResponse."""
        content_parts = []
        tool_calls = []
        stop_reason = data.get("stop_reason", "end_turn")

        for block in data.get("content", []):
            if block.get("type") == "text":
                content_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.get("id", ""),
                    name=block.get("name", ""),
                    arguments=block.get("input", {}),
                ))

        usage_data = data.get("usage", {})
        usage = TokenUsage(
            input_tokens=usage_data.get("input_tokens", 0),
            output_tokens=usage_data.get("output_tokens", 0),
            cache_read_tokens=usage_data.get("cache_read_input_tokens", 0),
            cache_write_tokens=usage_data.get("cache_creation_input_tokens", 0),
        )

        # Anthropic uses "tool_use" as stop_reason when tool calls are present
        if stop_reason == "tool_use":
            stop_reason = "tool_use"

        return LLMResponse(
            content="\n".join(content_parts),
            tool_calls=tool_calls,
            usage=usage,
            stop_reason=stop_reason,
        )

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# ── OpenAI-compatible (GPT-4o, NVIDIA NIM, Ollama) ───────────────────────────

class OpenAIProvider:
    """
    OpenAI-compatible chat completion endpoint.

    Works with:
    - OpenAI API          (base_url=https://api.openai.com/v1)
    - NVIDIA NIM          (base_url=https://integrate.api.nvidia.com/v1)
    - Ollama              (base_url=http://ollama:11434/v1)
    - Any OpenAI-compat   (vLLM, Together, Fireworks, etc.)
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
        api_key: Optional[str] = None,
        max_retries: int = 3,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=300.0)
        return self._client

    async def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a chat completion request to an OpenAI-compatible endpoint."""
        client = await self._get_client()

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # Format messages for OpenAI
        formatted_messages: List[Dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") == "tool":
                results = msg.get("results", [])
                if results:
                    for result in results:
                        formatted_messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": result.get("tool_use_id", "unknown"),
                                "content": str(result.get("output", "")),
                            }
                        )
                    continue
            formatted = self._format_message(msg)
            if formatted is not None:
                formatted_messages.append(formatted)

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": formatted_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            payload["tools"] = self._format_tools_openai(tools)
            payload["tool_choice"] = "auto"

        url = f"{self.base_url}/chat/completions"

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return self._parse_openai_response(data)
            except httpx.HTTPStatusError as exc:
                last_error = exc
                if exc.response.status_code == 429:
                    wait = min(2 ** attempt * 2, 30)
                    await asyncio.sleep(wait)
                    continue
                if exc.response.status_code >= 500:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise
            except (httpx.ConnectError, httpx.ReadTimeout) as exc:
                last_error = exc
                await asyncio.sleep(2 ** attempt)
                continue

        raise RuntimeError(f"OpenAI-compat API failed after {self.max_retries} retries: {last_error}")

    def _format_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Convert internal message format to OpenAI format."""
        role = msg["role"]

        # Tool result messages are expanded in chat() because OpenAI expects
        # one message per tool result.
        if role == "tool":
            return None

        # Assistant with tool calls
        if role == "assistant" and msg.get("tool_calls"):
            openai_tool_calls = []
            for tc in msg["tool_calls"]:
                tc_id = tc.id if isinstance(tc, ToolCall) else tc.get("id", "")
                tc_name = tc.name if isinstance(tc, ToolCall) else tc.get("name", "")
                tc_args = tc.arguments if isinstance(tc, ToolCall) else tc.get("arguments", {})
                openai_tool_calls.append({
                    "id": tc_id,
                    "type": "function",
                    "function": {
                        "name": tc_name,
                        "arguments": json.dumps(tc_args) if isinstance(tc_args, dict) else str(tc_args),
                    },
                })
            result: Dict[str, Any] = {
                "role": "assistant",
                "content": msg.get("content") or None,
                "tool_calls": openai_tool_calls,
            }
            return result

        # Plain messages
        return {"role": role, "content": msg.get("content", "")}

    def _format_tools_openai(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert to OpenAI function-calling format."""
        formatted = []
        for tool in tools:
            formatted.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters", {"type": "object", "properties": {}}),
                },
            })
        return formatted

    def _parse_openai_response(self, data: Dict[str, Any]) -> LLMResponse:
        """Parse OpenAI-compatible response into normalised LLMResponse."""
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})

        content = message.get("content") or ""
        finish_reason = choice.get("finish_reason", "stop")

        tool_calls = []
        for tc in message.get("tool_calls") or []:
            func = tc.get("function", {})
            args_raw = func.get("arguments", "{}")
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
            except json.JSONDecodeError:
                args = {"raw": args_raw}
            tool_calls.append(ToolCall(
                id=tc.get("id", ""),
                name=func.get("name", ""),
                arguments=args,
            ))

        usage_data = data.get("usage", {})
        usage = TokenUsage(
            input_tokens=usage_data.get("prompt_tokens", 0),
            output_tokens=usage_data.get("completion_tokens", 0),
        )

        stop_reason = "tool_use" if finish_reason == "tool_calls" else "end_turn"

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            usage=usage,
            stop_reason=stop_reason,
        )

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# ── Factory ───────────────────────────────────────────────────────────────────

def create_provider(
    provider_name: str,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    **kwargs: Any,
) -> LLMProvider:
    """
    Factory for creating an LLM provider from config.

    Examples:
        create_provider("anthropic")
        create_provider("nvidia_nim", model="meta/llama-4-maverick-17b-128e-instruct")
        create_provider("ollama", model="qwen2.5-coder:7b")
        create_provider("openai", model="gpt-4o")
    """
    if provider_name == "anthropic":
        return AnthropicProvider(
            model=model or "claude-sonnet-4-20250514",
            api_key=api_key or os.getenv("ANTHROPIC_API_KEY"),
            **kwargs,
        )

    if provider_name == "nvidia_nim":
        return OpenAIProvider(
            model=model or "meta/llama-4-maverick-17b-128e-instruct",
            base_url=base_url or "https://integrate.api.nvidia.com/v1",
            api_key=api_key or os.getenv("NVIDIA_API_KEY"),
            **kwargs,
        )

    if provider_name == "ollama":
        return OpenAIProvider(
            model=model or "qwen2.5-coder:7b",
            base_url=base_url or "http://ollama:11434/v1",
            api_key=api_key or "ollama",
            **kwargs,
        )

    if provider_name in ("openai", "openai_compatible"):
        return OpenAIProvider(
            model=model or "gpt-4o",
            base_url=base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            api_key=api_key or os.getenv("OPENAI_API_KEY"),
            **kwargs,
        )

    raise ValueError(
        f"Unknown provider: {provider_name!r}.  "
        f"Supported: anthropic, nvidia_nim, ollama, openai, openai_compatible"
    )

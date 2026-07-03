from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, List

_MAX_TOOL_OUTPUT_CHARS = 12000
_MAX_TOOL_OUTPUT_STRING = 1500
_MAX_TOOL_OUTPUT_LIST_ITEMS = 12
_MAX_TOOL_OUTPUT_DICT_KEYS = 24
_MAX_TOOL_OUTPUT_DEPTH = 4
_MAX_COMPACTION_ASSISTANT_TEXT = 400
_MAX_COMPACTION_TOOL_RESULT = 320
_USAGE_NUMERIC_KEYS = (
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _usage_breakdown(value: Any) -> Dict[str, int]:
    if value is None:
        return {}
    if isinstance(value, dict):
        items = value.items()
    else:
        items = vars(value).items() if hasattr(value, "__dict__") else []
    breakdown: Dict[str, int] = {}
    for key, item in items:
        if key.startswith("_"):
            continue
        parsed = _as_int(item)
        if parsed:
            breakdown[str(key)] = parsed
    return breakdown


def extract_output_text(response: Any) -> str:
    output = getattr(response, "output", None) or []
    parts: List[str] = []
    for item in output:
        item_type = getattr(item, "type", None) or (item.get("type") if isinstance(item, dict) else None)
        if item_type == "output_text":
            text = getattr(item, "text", None) or (item.get("text") if isinstance(item, dict) else None)
            if text:
                parts.append(str(text))
    if parts:
        return "\n".join(parts).strip()
    text = getattr(response, "output_text", None)
    if isinstance(text, str):
        return text.strip()
    return ""


def _usage_dict(response: Any) -> Dict[str, int]:
    usage = getattr(response, "usage", None)
    if usage is None:
        return {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
        }

    prompt_tokens = _as_int(
        getattr(usage, "input_tokens", None)
        or getattr(usage, "prompt_tokens", None)
        or 0
    )
    completion_tokens = _as_int(
        getattr(usage, "output_tokens", None)
        or getattr(usage, "completion_tokens", None)
        or 0
    )
    prompt_details = getattr(usage, "prompt_tokens_details", None)
    cache_creation = _usage_breakdown(getattr(usage, "cache_creation", None))
    cache_read = _usage_breakdown(getattr(usage, "cache_read", None))
    cache_creation_input_tokens = _as_int(
        getattr(usage, "cache_creation_input_tokens", None)
        or sum(cache_creation.values())
    )
    cache_read_input_tokens = _as_int(
        getattr(usage, "cache_read_input_tokens", None)
        or getattr(usage, "cached_input_tokens", None)
        or getattr(prompt_details, "cached_tokens", None)
        or sum(cache_read.values())
    )
    payload = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": _as_int(getattr(usage, "total_tokens", None) or (prompt_tokens + completion_tokens)),
        "cache_creation_input_tokens": cache_creation_input_tokens,
        "cache_read_input_tokens": cache_read_input_tokens,
    }
    if cache_creation:
        payload["cache_creation"] = cache_creation
    if cache_read:
        payload["cache_read"] = cache_read
    return payload


def _merge_usage(total: Dict[str, Any], delta: Dict[str, Any]) -> None:
    for key in _USAGE_NUMERIC_KEYS:
        total[key] = _as_int(total.get(key)) + _as_int(delta.get(key))
    for nested_key in ("cache_creation", "cache_read"):
        delta_nested = delta.get(nested_key)
        if not isinstance(delta_nested, dict):
            continue
        current = dict(total.get(nested_key) or {})
        for name, value in delta_nested.items():
            current[str(name)] = _as_int(current.get(name)) + _as_int(value)
        total[nested_key] = current


def _anthropic_cache_control(*, enabled: bool, ttl: str | None) -> Dict[str, str] | None:
    if not enabled:
        return None
    payload: Dict[str, str] = {"type": "ephemeral"}
    normalized_ttl = str(ttl or "").strip().lower()
    if normalized_ttl == "1h":
        payload["ttl"] = "1h"
    return payload


def _anthropic_system_content(
    *,
    system_prompt: str,
    system_prompt_blocks: List[Dict[str, Any]] | None,
    enable_prompt_caching: bool,
    prompt_cache_ttl: str | None,
) -> Any:
    if not system_prompt_blocks:
        return system_prompt

    cache_control = _anthropic_cache_control(enabled=enable_prompt_caching, ttl=prompt_cache_ttl)
    last_cacheable_index = -1
    for index, block in enumerate(system_prompt_blocks):
        if block.get("cacheable"):
            last_cacheable_index = index

    content: List[Dict[str, Any]] = []
    for index, block in enumerate(system_prompt_blocks):
        text = str(block.get("text") or "").strip()
        if not text:
            continue
        payload: Dict[str, Any] = {"type": "text", "text": text}
        if cache_control and index == last_cacheable_index:
            payload["cache_control"] = dict(cache_control)
        content.append(payload)
    return content or system_prompt


def _compact_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= _MAX_TOOL_OUTPUT_DEPTH:
        if isinstance(value, (dict, list)):
            return f"<truncated:{type(value).__name__}>"
        if isinstance(value, str):
            return value[:_MAX_TOOL_OUTPUT_STRING]
        return value

    if isinstance(value, str):
        if len(value) <= _MAX_TOOL_OUTPUT_STRING:
            return value
        return value[:_MAX_TOOL_OUTPUT_STRING] + "...[truncated]"

    if isinstance(value, list):
        items = [
            _compact_value(item, depth=depth + 1)
            for item in value[:_MAX_TOOL_OUTPUT_LIST_ITEMS]
        ]
        if len(value) > _MAX_TOOL_OUTPUT_LIST_ITEMS:
            items.append(f"<truncated:{len(value) - _MAX_TOOL_OUTPUT_LIST_ITEMS} more items>")
        return items

    if isinstance(value, dict):
        compacted: Dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_TOOL_OUTPUT_DICT_KEYS:
                compacted["_truncated_keys"] = len(value) - _MAX_TOOL_OUTPUT_DICT_KEYS
                break
            compacted[str(key)] = _compact_value(item, depth=depth + 1)
        return compacted

    return value


def _serialize_tool_output(result: Any) -> str:
    compacted = _compact_value(result)
    payload = json.dumps(compacted)
    if len(payload) <= _MAX_TOOL_OUTPUT_CHARS:
        return payload
    overflow = len(payload) - _MAX_TOOL_OUTPUT_CHARS
    fallback = {
        "truncated": True,
        "overflow_chars": overflow,
        "summary": _compact_value(compacted, depth=_MAX_TOOL_OUTPUT_DEPTH - 1),
    }
    serialized = json.dumps(fallback)
    return serialized[:_MAX_TOOL_OUTPUT_CHARS]


def _provider_family(provider_preset: str | None) -> str:
    preset = (provider_preset or "openai").strip().lower().replace("-", "_")
    if preset == "anthropic":
        return "anthropic"
    return "openai_compatible"


def _normalize_tool_spec(tool: Dict[str, Any]) -> Dict[str, Any]:
    if tool.get("type") == "function" and isinstance(tool.get("function"), dict):
        return dict(tool["function"])
    return dict(tool)


def _openai_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for tool in tools:
        spec = _normalize_tool_spec(tool)
        normalized.append({"type": "function", "function": spec})
    return normalized


def _anthropic_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for tool in tools:
        spec = _normalize_tool_spec(tool)
        normalized.append(
            {
                "name": spec["name"],
                "description": spec.get("description", ""),
                "input_schema": spec.get("parameters") or {"type": "object", "properties": {}},
            }
        )
    return normalized


def _stringify_openai_content(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(part.strip() for part in parts if part).strip()
    return ""


def _extract_openai_response(response: Any) -> Dict[str, Any]:
    choice = response.choices[0]
    message = choice.message
    assistant_text = _stringify_openai_content(getattr(message, "content", None))
    raw_tool_calls = getattr(message, "tool_calls", None) or []
    tool_calls = []
    for item in raw_tool_calls:
        function = getattr(item, "function", None) or {}
        call_id = getattr(item, "id", None) or getattr(item, "call_id", None)
        if isinstance(function, dict):
            name = function.get("name")
            arguments_raw = function.get("arguments") or "{}"
        else:
            name = getattr(function, "name", None)
            arguments_raw = getattr(function, "arguments", None) or "{}"
        tool_calls.append(
            {
                "call_id": call_id,
                "name": name,
                "arguments_raw": arguments_raw,
                "openai_call": item,
            }
        )
    return {
        "assistant_text": assistant_text,
        "tool_calls": tool_calls,
        "usage": _usage_dict(response),
    }


def _extract_anthropic_response(message: Any) -> Dict[str, Any]:
    assistant_text_parts: List[str] = []
    tool_calls = []
    for block in getattr(message, "content", None) or []:
        block_type = getattr(block, "type", None) or (block.get("type") if isinstance(block, dict) else None)
        if block_type == "text":
            text = getattr(block, "text", None) or (block.get("text") if isinstance(block, dict) else None)
            if text:
                assistant_text_parts.append(str(text))
            continue
        if block_type == "tool_use":
            call_id = getattr(block, "id", None) or (block.get("id") if isinstance(block, dict) else None)
            name = getattr(block, "name", None) or (block.get("name") if isinstance(block, dict) else None)
            arguments = getattr(block, "input", None) or (block.get("input") if isinstance(block, dict) else None) or {}
            tool_calls.append(
                {
                    "call_id": call_id,
                    "name": name,
                    "arguments_dict": dict(arguments),
                }
            )
    return {
        "assistant_text": "\n".join(part.strip() for part in assistant_text_parts if part).strip(),
        "tool_calls": tool_calls,
        "usage": _usage_dict(message),
    }


def _tool_result_excerpt(result: Any) -> str:
    serialized = _serialize_tool_output(result)
    if len(serialized) <= _MAX_COMPACTION_TOOL_RESULT:
        return serialized
    return serialized[:_MAX_COMPACTION_TOOL_RESULT] + "...[truncated]"


def _summarize_turns(turns: List[Dict[str, Any]], *, start_index: int) -> str:
    lines: List[str] = []
    for offset, turn in enumerate(turns):
        turn_index = start_index + offset
        assistant_text = str(turn.get("assistant_text") or "").strip()
        if assistant_text:
            lines.append(f"Turn {turn_index} assistant: {assistant_text[:_MAX_COMPACTION_ASSISTANT_TEXT]}")
        for tool_call in turn.get("tool_calls", []):
            lines.append(
                f"Turn {turn_index} tool call: {tool_call['name']} args={json.dumps(_compact_value(tool_call['arguments']), sort_keys=True)}"
            )
        for tool_result in turn.get("tool_results", []):
            lines.append(
                f"Turn {turn_index} tool result: {tool_result['tool_name']} -> {_tool_result_excerpt(tool_result['result'])}"
            )
    return "\n".join(lines).strip()


def _compaction_context(compactions: List[Dict[str, Any]]) -> str:
    if not compactions:
        return ""
    lines = ["Compacted prior turns:"]
    for index, item in enumerate(compactions, start=1):
        header = f"- Compaction {index}: turns {item['start_turn']}-{item['end_turn']}"
        if item.get("artifact_ref"):
            header += f" | artifact_ref={item['artifact_ref']}"
        lines.append(header)
        lines.append(item["summary"])
    return "\n".join(lines).strip()


def _maybe_compact_turns(
    turns: List[Dict[str, Any]],
    compactions: List[Dict[str, Any]],
    *,
    compaction_threshold: int | None,
    keep_recent_turns: int,
    persist_compaction: Callable[[Dict[str, Any]], str] | None,
) -> List[Dict[str, Any]]:
    threshold = int(compaction_threshold or 0)
    keep_count = max(int(keep_recent_turns or 0), 0)
    if threshold <= 0 or len(turns) <= threshold:
        return turns

    compact_count = max(1, len(turns) - keep_count)
    if compact_count >= len(turns):
        compact_count = max(1, len(turns) - 1)
    to_compact = turns[:compact_count]
    if not to_compact:
        return turns

    start_turn = sum(item["turn_count"] for item in compactions) + 1
    summary = _summarize_turns(to_compact, start_index=start_turn)
    payload = {
        "type": "context_compaction",
        "start_turn": start_turn,
        "end_turn": start_turn + len(to_compact) - 1,
        "turn_count": len(to_compact),
        "summary": summary,
        "kept_recent_turns": keep_count,
    }
    artifact_ref = persist_compaction(payload) if persist_compaction else None
    compactions.append({**payload, "artifact_ref": artifact_ref})
    return turns[compact_count:]


def _openai_messages(
    *,
    system_prompt: str,
    user_input: str,
    turns: List[Dict[str, Any]],
    compactions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_input},
    ]
    compacted_context = _compaction_context(compactions)
    if compacted_context:
        messages.append({"role": "user", "content": compacted_context})

    for turn in turns:
        assistant_message: Dict[str, Any] = {
            "role": "assistant",
            "content": turn.get("assistant_text") or "",
        }
        if turn.get("tool_calls"):
            assistant_message["tool_calls"] = [
                {
                    "id": item["call_id"],
                    "type": "function",
                    "function": {
                        "name": item["name"],
                        "arguments": json.dumps(item["arguments"]),
                    },
                }
                for item in turn["tool_calls"]
            ]
        messages.append(assistant_message)
        for tool_result in turn.get("tool_results", []):
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_result["call_id"],
                    "content": tool_result["output"],
                }
            )
    return messages


def _anthropic_messages(
    *,
    user_input: str,
    turns: List[Dict[str, Any]],
    compactions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    initial_text = user_input
    compacted_context = _compaction_context(compactions)
    if compacted_context:
        initial_text = f"{user_input}\n\n{compacted_context}"

    messages: List[Dict[str, Any]] = [{"role": "user", "content": initial_text}]
    for turn in turns:
        assistant_content: List[Dict[str, Any]] = []
        if turn.get("assistant_text"):
            assistant_content.append({"type": "text", "text": turn["assistant_text"]})
        assistant_content.extend(
            {
                "type": "tool_use",
                "id": item["call_id"],
                "name": item["name"],
                "input": item["arguments"],
            }
            for item in turn.get("tool_calls", [])
        )
        messages.append({"role": "assistant", "content": assistant_content})
        user_content = [
            {
                "type": "tool_result",
                "tool_use_id": tool_result["call_id"],
                "content": tool_result["output"],
            }
            for tool_result in turn.get("tool_results", [])
        ]
        if user_content:
            messages.append({"role": "user", "content": user_content})
    return messages


async def _call_openai_compatible(
    *,
    client: Any,
    model: str,
    system_prompt: str,
    user_input: str,
    turns: List[Dict[str, Any]],
    compactions: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
) -> Dict[str, Any]:
    response = await client.chat.completions.create(
        model=model,
        messages=_openai_messages(
            system_prompt=system_prompt,
            user_input=user_input,
            turns=turns,
            compactions=compactions,
        ),
        tools=_openai_tools(tools),
        tool_choice="auto",
    )
    return _extract_openai_response(response)


async def _call_anthropic(
    *,
    client: Any,
    model: str,
    system_prompt: str,
    system_prompt_blocks: List[Dict[str, Any]] | None,
    user_input: str,
    turns: List[Dict[str, Any]],
    compactions: List[Dict[str, Any]],
    tools: List[Dict[str, Any]],
    enable_prompt_caching: bool = False,
    prompt_cache_ttl: str | None = None,
) -> Dict[str, Any]:
    system_content = _anthropic_system_content(
        system_prompt=system_prompt,
        system_prompt_blocks=system_prompt_blocks,
        enable_prompt_caching=enable_prompt_caching,
        prompt_cache_ttl=prompt_cache_ttl,
    )
    kwargs: Dict[str, Any] = dict(
        model=model,
        system=system_content,
        messages=_anthropic_messages(
            user_input=user_input,
            turns=turns,
            compactions=compactions,
        ),
        tools=_anthropic_tools(tools),
        max_tokens=4096,
    )
    cache_control = _anthropic_cache_control(enabled=enable_prompt_caching, ttl=prompt_cache_ttl)
    if cache_control and not isinstance(system_content, list):
        kwargs["cache_control"] = cache_control
    message = await client.messages.create(**kwargs)
    return _extract_anthropic_response(message)


async def run_responses_tool_loop(
    *,
    client: Any,
    provider_preset: str = "openai",
    model: str,
    system_prompt: str,
    system_prompt_blocks: List[Dict[str, Any]] | None = None,
    user_input: str,
    tools: List[Dict[str, Any]],
    tool_handlers: Dict[str, Callable[[Dict[str, Any]], Awaitable[Any]]],
    max_turns: int,
    max_tool_calls: int | None = None,
    reasoning_effort: str | None = None,
    compaction_threshold: int | None = None,
    keep_recent_turns: int = 2,
    persist_compaction: Callable[[Dict[str, Any]], str] | None = None,
    initial_turns: List[Dict[str, Any]] | None = None,
    initial_compactions: List[Dict[str, Any]] | None = None,
    initial_tool_results: List[Dict[str, Any]] | None = None,
    initial_usage: Dict[str, Any] | None = None,
    persist_checkpoint: Callable[[Dict[str, Any]], None] | None = None,
    enable_prompt_caching: bool = False,
    prompt_cache_ttl: str | None = None,
) -> Dict[str, Any]:
    del reasoning_effort

    family = _provider_family(provider_preset)
    usage: Dict[str, Any] = dict(
        initial_usage
        or {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
        }
    )
    tool_results: List[Dict[str, Any]] = list(initial_tool_results or [])
    turns: List[Dict[str, Any]] = list(initial_turns or [])
    compactions: List[Dict[str, Any]] = list(initial_compactions or [])
    last_assistant_text = ""

    def _checkpoint_payload(*, status: str) -> Dict[str, Any]:
        return {
            "status": status,
            "turn_count": len(turns),
            "tool_result_count": len(tool_results),
            "turns": turns,
            "compactions": compactions,
            "tool_results": tool_results,
            "usage": usage,
            "last_output_text": last_assistant_text,
        }

    for _turn in range(max_turns):
        turns = _maybe_compact_turns(
            turns,
            compactions,
            compaction_threshold=compaction_threshold,
            keep_recent_turns=keep_recent_turns,
            persist_compaction=persist_compaction,
        )

        if family == "anthropic":
            response = await _call_anthropic(
                client=client,
                model=model,
                system_prompt=system_prompt,
                system_prompt_blocks=system_prompt_blocks,
                user_input=user_input,
                turns=turns,
                compactions=compactions,
                tools=tools,
                enable_prompt_caching=enable_prompt_caching,
                prompt_cache_ttl=prompt_cache_ttl,
            )
        else:
            response = await _call_openai_compatible(
                client=client,
                model=model,
                system_prompt=system_prompt,
                user_input=user_input,
                turns=turns,
                compactions=compactions,
                tools=tools,
            )

        _merge_usage(usage, response["usage"])

        last_assistant_text = response["assistant_text"]
        if not response["tool_calls"]:
            if persist_checkpoint:
                persist_checkpoint(_checkpoint_payload(status="completed"))
            return {
                "output_text": last_assistant_text,
                "tool_results": tool_results,
                "turns": turns,
                "compactions": compactions,
                "usage": usage,
            }

        remaining_tool_calls = None if max_tool_calls is None else max(0, int(max_tool_calls) - len(tool_results))
        if remaining_tool_calls == 0:
            if persist_checkpoint:
                persist_checkpoint(_checkpoint_payload(status="tool_budget_exhausted"))
            return {
                "output_text": last_assistant_text,
                "tool_results": tool_results,
                "turns": turns,
                "compactions": compactions,
                "usage": usage,
            }

        tool_calls = response["tool_calls"][:remaining_tool_calls] if remaining_tool_calls is not None else response["tool_calls"]
        turn_record = {
            "assistant_text": last_assistant_text,
            "tool_calls": [],
            "tool_results": [],
        }
        for call_index, call in enumerate(tool_calls, start=1):
            tool_name = call["name"]
            if "arguments_dict" in call:
                arguments = dict(call["arguments_dict"])
            else:
                arguments = json.loads(call.get("arguments_raw") or "{}")
            call_id = call.get("call_id") or f"tool-call-{len(tool_results) + call_index}"
            handler = tool_handlers[tool_name]
            result = await handler(arguments)
            serialized = _serialize_tool_output(result)

            tool_result = {
                "tool_name": tool_name,
                "arguments": arguments,
                "result": result,
                "call_id": call_id,
                "output": serialized,
            }
            tool_results.append({"tool_name": tool_name, "arguments": arguments, "result": result})
            turn_record["tool_calls"].append(
                {
                    "call_id": call_id,
                    "name": tool_name,
                    "arguments": arguments,
                }
            )
            turn_record["tool_results"].append(tool_result)

        turns.append(turn_record)
        if persist_checkpoint:
            persist_checkpoint(_checkpoint_payload(status="running"))

    if persist_checkpoint:
        persist_checkpoint(_checkpoint_payload(status="turn_budget_exhausted"))
    return {
        "output_text": last_assistant_text,
        "tool_results": tool_results,
        "turns": turns,
        "compactions": compactions,
        "usage": usage,
    }

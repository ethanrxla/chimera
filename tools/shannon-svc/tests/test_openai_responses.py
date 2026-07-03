import asyncio
from types import SimpleNamespace

from test_shannon_robustness import _reload_main


def test_extract_output_text_prefers_output_text_items() -> None:
    module = _reload_main({"SHANNON_PROVIDER": "openai_compatible"})
    responses_module = __import__("openai_responses")
    response = SimpleNamespace(
        output=[
            SimpleNamespace(type="reasoning", summary=[]),
            SimpleNamespace(type="output_text", text="final answer"),
        ]
    )

    assert responses_module.extract_output_text(response) == "final answer"


def test_run_responses_tool_loop_executes_tool_then_returns_final_text() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible"})
    responses_module = __import__("openai_responses")

    tool_call = SimpleNamespace(
        id="call-1",
        function=SimpleNamespace(
            name="hexstrike_probe",
            arguments='{"endpoint":"https://example.com/login","method":"GET"}',
        ),
    )
    first = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[tool_call]))],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
    )
    second = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='{"status":"completed"}', tool_calls=[]))],
        usage=SimpleNamespace(prompt_tokens=4, completion_tokens=3, total_tokens=7),
    )

    class FakeCompletions:
        def __init__(self) -> None:
            self.calls = []
            self._responses = [first, second]

        async def create(self, **kwargs):
            self.calls.append(kwargs)
            return self._responses.pop(0)

    class FakeChat:
        def __init__(self) -> None:
            self.completions = FakeCompletions()

    class FakeClient:
        def __init__(self) -> None:
            self.chat = FakeChat()

    tool_calls = []

    async def fake_tool(arguments):
        tool_calls.append(arguments)
        return {"status_code": 200, "headers": {}, "body_excerpt": "ok"}

    result = asyncio.run(
        responses_module.run_responses_tool_loop(
            client=FakeClient(),
            provider_preset="openai",
            model="gpt-5.4-mini",
            system_prompt="system",
            user_input="investigate",
            tools=[{"name": "hexstrike_probe", "description": "probe", "parameters": {"type": "object", "properties": {}}}],
            tool_handlers={"hexstrike_probe": fake_tool},
            max_turns=3,
            reasoning_effort="medium",
        )
    )

    assert result["output_text"] == '{"status":"completed"}'
    assert tool_calls == [{"endpoint": "https://example.com/login", "method": "GET"}]
    assert result["tool_results"][0]["tool_name"] == "hexstrike_probe"
    assert result["usage"]["total_tokens"] == 22


def test_run_responses_tool_loop_compacts_older_turns_and_persists_summary() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible"})
    responses_module = __import__("openai_responses")

    def _response(tool_name: str, call_id: str):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=f"calling {tool_name}",
                        tool_calls=[
                            SimpleNamespace(
                                id=call_id,
                                function=SimpleNamespace(name=tool_name, arguments='{"endpoint":"https://example.com"}'),
                            )
                        ],
                    )
                )
            ],
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=2, total_tokens=12),
        )

    final = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="done", tool_calls=[]))],
        usage=SimpleNamespace(prompt_tokens=4, completion_tokens=1, total_tokens=5),
    )

    class FakeCompletions:
        def __init__(self) -> None:
            self._responses = [
                _response("hexstrike_endpoints", "call-1"),
                _response("hexstrike_probe", "call-2"),
                _response("browser_capture_dom", "call-3"),
                final,
            ]

        async def create(self, **kwargs):
            return self._responses.pop(0)

    class FakeChat:
        def __init__(self) -> None:
            self.completions = FakeCompletions()

    class FakeClient:
        def __init__(self) -> None:
            self.chat = FakeChat()

    compactions = []

    async def fake_tool(arguments):
        return {"status": "ok", "echo": arguments["endpoint"]}

    result = asyncio.run(
        responses_module.run_responses_tool_loop(
            client=FakeClient(),
            provider_preset="ollama",
            model="qwen2.5-coder:7b",
            system_prompt="system",
            user_input="investigate",
            tools=[{"name": "hexstrike_probe", "description": "probe", "parameters": {"type": "object", "properties": {}}}],
            tool_handlers={
                "hexstrike_endpoints": fake_tool,
                "hexstrike_probe": fake_tool,
                "browser_capture_dom": fake_tool,
            },
            max_turns=4,
            compaction_threshold=2,
            keep_recent_turns=1,
            persist_compaction=lambda payload: compactions.append(payload) or f"artifact-{len(compactions)}",
        )
    )

    assert result["output_text"] == "done"
    assert len(compactions) == 1
    assert compactions[0]["type"] == "context_compaction"
    assert "hexstrike_endpoints" in compactions[0]["summary"]
    assert compactions[0]["kept_recent_turns"] == 1


def test_run_responses_tool_loop_resumes_from_checkpoint_state() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible"})
    responses_module = __import__("openai_responses")

    final = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="resumed-done", tool_calls=[]))],
        usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2, total_tokens=5),
    )

    class FakeCompletions:
        def __init__(self) -> None:
            self.calls = []

        async def create(self, **kwargs):
            self.calls.append(kwargs)
            return final

    class FakeChat:
        def __init__(self) -> None:
            self.completions = FakeCompletions()

    class FakeClient:
        def __init__(self) -> None:
            self.chat = FakeChat()

    checkpoints = []
    existing_turns = [
        {
            "assistant_text": "calling hexstrike_probe",
            "tool_calls": [{"call_id": "call-1", "name": "hexstrike_probe", "arguments": {"endpoint": "https://example.com/login"}}],
            "tool_results": [{"tool_name": "hexstrike_probe", "call_id": "call-1", "output": "{\"status\":200}", "result": {"status": 200}}],
        }
    ]
    existing_compactions = [{"start_turn": 1, "end_turn": 1, "turn_count": 1, "summary": "Turn 1 tool call: hexstrike_probe", "artifact_ref": "artifact-1"}]
    existing_tool_results = [{"tool_name": "hexstrike_probe", "arguments": {"endpoint": "https://example.com/login"}, "result": {"status": 200}}]

    result = asyncio.run(
        responses_module.run_responses_tool_loop(
            client=FakeClient(),
            provider_preset="openai",
            model="gpt-5.4-mini",
            system_prompt="system",
            user_input="investigate",
            tools=[],
            tool_handlers={},
            max_turns=3,
            initial_turns=existing_turns,
            initial_compactions=existing_compactions,
            initial_tool_results=existing_tool_results,
            initial_usage={"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
            persist_checkpoint=lambda payload: checkpoints.append(payload),
        )
    )

    assert result["output_text"] == "resumed-done"
    assert result["usage"]["total_tokens"] == 19
    assert len(result["turns"]) == 1
    assert result["compactions"][0]["artifact_ref"] == "artifact-1"
    assert result["tool_results"][0]["tool_name"] == "hexstrike_probe"
    assert checkpoints[-1]["status"] == "completed"
    assert checkpoints[-1]["turn_count"] == 1


def test_serialize_tool_output_compacts_large_browser_payloads() -> None:
    _reload_main({"SHANNON_PROVIDER": "openai_compatible"})
    responses_module = __import__("openai_responses")

    payload = {
        "url": "http://juice-shop:3000/",
        "dom_excerpt": "A" * 20000,
        "console": [{"text": "B" * 5000} for _ in range(30)],
        "headers": {f"h{index}": "x" * 500 for index in range(40)},
    }

    serialized = responses_module._serialize_tool_output(payload)

    assert len(serialized) <= 12000
    assert "truncated" in serialized or "...[truncated]" in serialized


def test_run_responses_tool_loop_passes_anthropic_prompt_caching_settings() -> None:
    _reload_main({"SHANNON_PROVIDER": "anthropic"})
    responses_module = __import__("openai_responses")

    usage = SimpleNamespace(
        input_tokens=20,
        output_tokens=5,
        total_tokens=25,
        cache_creation_input_tokens=40,
        cache_read_input_tokens=10,
        cache_creation=SimpleNamespace(ephemeral_1h_input_tokens=40),
    )
    final = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="done")],
        usage=usage,
    )

    class FakeMessages:
        def __init__(self) -> None:
            self.calls = []

        async def create(self, **kwargs):
            self.calls.append(kwargs)
            return final

    class FakeClient:
        def __init__(self) -> None:
            self.messages = FakeMessages()

    client = FakeClient()

    result = asyncio.run(
        responses_module.run_responses_tool_loop(
            client=client,
            provider_preset="anthropic",
            model="claude-sonnet-4-20250514",
            system_prompt="system",
            user_input="investigate",
            tools=[],
            tool_handlers={},
            max_turns=1,
            enable_prompt_caching=True,
            prompt_cache_ttl="1h",
        )
    )

    assert result["output_text"] == "done"
    assert client.messages.calls[0]["cache_control"] == {"type": "ephemeral", "ttl": "1h"}
    assert result["usage"]["cache_creation_input_tokens"] == 40
    assert result["usage"]["cache_read_input_tokens"] == 10


def test_run_responses_tool_loop_uses_structured_system_blocks_for_anthropic_cache_breakpoint() -> None:
    _reload_main({"SHANNON_PROVIDER": "anthropic"})
    responses_module = __import__("openai_responses")

    final = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="done")],
        usage=SimpleNamespace(input_tokens=10, output_tokens=5, total_tokens=15),
    )

    class FakeMessages:
        def __init__(self) -> None:
            self.calls = []

        async def create(self, **kwargs):
            self.calls.append(kwargs)
            return final

    class FakeClient:
        def __init__(self) -> None:
            self.messages = FakeMessages()

    client = FakeClient()

    result = asyncio.run(
        responses_module.run_responses_tool_loop(
            client=client,
            provider_preset="anthropic",
            model="claude-sonnet-4-20250514",
            system_prompt="fallback system",
            system_prompt_blocks=[
                {"name": "identity", "text": "Stable identity block", "cacheable": True},
                {"name": "role", "text": "Stable role block", "cacheable": True},
                {"name": "scope", "text": "Dynamic scope block", "cacheable": False},
            ],
            user_input="investigate",
            tools=[],
            tool_handlers={},
            max_turns=1,
            enable_prompt_caching=True,
            prompt_cache_ttl="1h",
        )
    )

    assert result["output_text"] == "done"
    call = client.messages.calls[0]
    assert "cache_control" not in call
    assert isinstance(call["system"], list)
    assert call["system"][1]["cache_control"] == {"type": "ephemeral", "ttl": "1h"}
    assert call["system"][2] == {"type": "text", "text": "Dynamic scope block"}

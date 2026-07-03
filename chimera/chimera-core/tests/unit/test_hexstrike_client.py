import asyncio

import httpx
import pytest

from chimera_core.hexstrike.client import HexStrikeClient


def test_client_routes_unified_launcher_tools() -> None:
    seen_urls = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, json={"ok": True}, request=request)

    transport = httpx.MockTransport(handler)
    client = HexStrikeClient(base_url="http://hexstrike:8888", transport=transport)

    async def run() -> None:
        await client.call_tool("nuclei", {"target": "https://example.com"})
        await client.call_tool("probe", {"endpoint": "https://example.com/login"})

    asyncio.run(run())

    assert "http://hexstrike:8888/api/tools/nuclei" in seen_urls
    assert "http://hexstrike:8888/api/probe" in seen_urls


def test_client_rejects_unknown_tool() -> None:
    client = HexStrikeClient(base_url="http://hexstrike:8888")

    async def run() -> None:
        with pytest.raises(ValueError):
            await client.call_tool("unknown_tool", {})

    asyncio.run(run())

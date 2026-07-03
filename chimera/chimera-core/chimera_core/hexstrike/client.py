from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

from chimera_core.hexstrike.catalog import get_tool_spec


class HexStrikeClient:
    def __init__(
        self,
        *,
        base_url: str,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        timeout_s: int = 300,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.transport = transport
        self.timeout_s = timeout_s

    async def call_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        spec = get_tool_spec(tool_name)
        url = f"{self.base_url}{spec.route}"
        async with httpx.AsyncClient(timeout=self.timeout_s, transport=self.transport) as client:
            response = await client.post(url, json=params)
            response.raise_for_status()
            return response.json()

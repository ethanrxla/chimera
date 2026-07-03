from __future__ import annotations

from typing import Any, Dict, Optional

import httpx


class ChimeraBrowserMediator:
    """Bridge Shannon browser tool calls to Chimera persistent browser sessions."""

    def __init__(self, *, session_id: str, chimera_base_url: str, timeout_s: float = 60.0) -> None:
        self.session_id = session_id
        self.chimera_base_url = chimera_base_url.rstrip("/")
        self.timeout_s = timeout_s

    async def execute(self, task: Dict[str, Any], *, url: Optional[str] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"task": task}
        if url is not None:
            payload["url"] = url

        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            response = await client.post(
                f"{self.chimera_base_url}/v1/browser/sessions/{self.session_id}/execute",
                json=payload,
            )
            response.raise_for_status()
            result = response.json()

        capture = result.get("capture")
        if isinstance(capture, dict):
            capture.setdefault("mediated_by", "chimera")
            capture.setdefault("browser_session_id", self.session_id)
            return capture
        return {
            "mediated_by": "chimera",
            "browser_session_id": self.session_id,
            "raw_result": result,
        }

    async def get_console(self, *, limit: int = 200) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            response = await client.get(
                f"{self.chimera_base_url}/v1/browser/sessions/{self.session_id}/console",
                params={"limit": limit},
            )
            response.raise_for_status()
            return response.json()

    async def get_network(self, *, limit: int = 200) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            response = await client.get(
                f"{self.chimera_base_url}/v1/browser/sessions/{self.session_id}/network",
                params={"limit": limit},
            )
            response.raise_for_status()
            return response.json()

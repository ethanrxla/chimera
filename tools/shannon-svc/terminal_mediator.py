from __future__ import annotations

from typing import Any, Dict, Optional

import httpx


class ChimeraTerminalMediator:
    """Bridge Shannon terminal tool calls to Chimera persistent terminal sessions."""

    def __init__(self, *, chimera_base_url: str, timeout_s: float = 60.0) -> None:
        self.chimera_base_url = chimera_base_url.rstrip("/")
        self.timeout_s = timeout_s

    async def start(
        self,
        *,
        command: list[str],
        run_id: str,
        target: Optional[str],
        scope_summary: Dict[str, Any],
        cwd: Optional[str] = None,
        cols: int = 120,
        rows: int = 36,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "command": command,
            "run_id": run_id,
            "target": target,
            "scope_summary": scope_summary,
            "cols": cols,
            "rows": rows,
        }
        if cwd:
            payload["cwd"] = cwd
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            response = await client.post(
                f"{self.chimera_base_url}/v1/terminal/sessions",
                json=payload,
            )
            response.raise_for_status()
            return response.json()

    async def write(self, session_id: str, *, data: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            response = await client.post(
                f"{self.chimera_base_url}/v1/terminal/sessions/{session_id}/write",
                json={"data": data},
            )
            response.raise_for_status()
            return response.json()

    async def read(self, session_id: str, *, max_bytes: int = 8192, timeout_ms: int = 50) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            response = await client.post(
                f"{self.chimera_base_url}/v1/terminal/sessions/{session_id}/read",
                json={"max_bytes": max_bytes, "timeout_ms": timeout_ms},
            )
            response.raise_for_status()
            return response.json()

    async def resize(self, session_id: str, *, cols: int, rows: int) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            response = await client.post(
                f"{self.chimera_base_url}/v1/terminal/sessions/{session_id}/resize",
                json={"cols": cols, "rows": rows},
            )
            response.raise_for_status()
            return response.json()

    async def close(self, session_id: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            response = await client.delete(
                f"{self.chimera_base_url}/v1/terminal/sessions/{session_id}",
            )
            response.raise_for_status()
            return response.json()

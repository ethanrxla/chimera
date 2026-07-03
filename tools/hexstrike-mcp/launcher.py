"""
HexStrike unified launcher.

Starts two servers:
  - Upstream hexstrike_upstream.py (Flask) on port 8888 — 150+ tool execution endpoints
  - Our FastAPI analysis server (server.py) on port 8889 — LLM-powered analysis endpoints

A thin reverse proxy on port 8888 routes:
  /api/tools/* and /api/command, /api/bugbounty, etc. → Flask upstream (port 8887)
  /api/recon, /api/endpoints, /api/attack-surface, /api/exploit, /api/probe → FastAPI (port 8889)
  /health → combined health from both

This keeps the existing chimera-core integration on port 8888 working while adding 150+ tools.
"""
import os
import subprocess
import sys
import threading
import time
import logging

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("hexstrike.launcher")

FLASK_PORT = int(os.getenv("HEXSTRIKE_FLASK_PORT", "8887"))
FASTAPI_PORT = int(os.getenv("HEXSTRIKE_FASTAPI_PORT", "8889"))
PROXY_PORT = int(os.getenv("HEXSTRIKE_PORT", "8888"))

# Routes that belong to the upstream Flask tool-execution server
_FLASK_PREFIXES = (
    "/api/tools/",
    "/api/command",
    "/api/bugbounty",
    "/api/ctf",
    "/api/intelligence",
    "/api/ai/",
    "/api/python/",
)

# Routes that belong to our FastAPI LLM-analysis server
_FASTAPI_PREFIXES = (
    "/api/recon",
    "/api/endpoints",
    "/api/attack-surface",
    "/api/exploit",
    "/api/probe",
)

# Specific tool overrides: our FastAPI implementation takes precedence over Flask upstream.
# Used when the upstream implementation has bugs or missing functionality.
_FASTAPI_TOOL_OVERRIDES = (
    "/api/tools/httpx",   # upstream doesn't pipe targets via stdin correctly
)


def _start_flask():
    """Launch upstream hexstrike_upstream.py (Flask) on FLASK_PORT."""
    env = os.environ.copy()
    env["HEXSTRIKE_PORT"] = str(FLASK_PORT)
    env["PORT"] = str(FLASK_PORT)
    proc = subprocess.Popen(
        [sys.executable, "/app/hexstrike_upstream.py", "--port", str(FLASK_PORT)],
        env=env,
    )
    log.info("Flask upstream started on port %d (pid=%d)", FLASK_PORT, proc.pid)
    proc.wait()
    log.warning("Flask upstream exited with code %d", proc.returncode)


def _start_fastapi():
    """Launch our FastAPI analysis server on FASTAPI_PORT."""
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=FASTAPI_PORT,
        log_level="info",
    )


# ── Proxy FastAPI app ─────────────────────────────────────────────────────

proxy_app = FastAPI(title="HexStrike Unified Proxy", version="2.0.0")


async def _proxy(request: Request, target_port: int) -> Response:
    url = f"http://127.0.0.1:{target_port}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"
    body = await request.body()
    async with httpx.AsyncClient(timeout=300) as client:
        resp = await client.request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            content=body,
        )
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=dict(resp.headers),
        media_type=resp.headers.get("content-type"),
    )


@proxy_app.get("/health")
async def health():
    results = {}
    async with httpx.AsyncClient(timeout=5) as client:
        for name, port in [("upstream_tools", FLASK_PORT), ("llm_analysis", FASTAPI_PORT)]:
            try:
                r = await client.get(f"http://127.0.0.1:{port}/health")
                results[name] = r.json() if r.status_code == 200 else {"status": "error", "code": r.status_code}
            except Exception as exc:
                results[name] = {"status": "unreachable", "error": str(exc)}
    return JSONResponse({"status": "ok", "service": "hexstrike-unified", "backends": results})


@proxy_app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def catch_all(request: Request, path: str):
    full_path = f"/{path}"
    # Check specific FastAPI overrides first (more specific than Flask prefix catch-all)
    if any(full_path == p or full_path.startswith(p + "/") for p in _FASTAPI_TOOL_OVERRIDES):
        return await _proxy(request, FASTAPI_PORT)
    if any(full_path.startswith(p) for p in _FLASK_PREFIXES):
        return await _proxy(request, FLASK_PORT)
    if any(full_path.startswith(p) for p in _FASTAPI_PREFIXES):
        return await _proxy(request, FASTAPI_PORT)
    # Default: try Flask first, then FastAPI
    return await _proxy(request, FLASK_PORT)


def _wait_for_port(port: int, timeout: float = 60.0) -> bool:
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(1)
    return False


if __name__ == "__main__":
    log.info("Starting HexStrike unified launcher...")

    # Start Flask upstream in background thread
    t_flask = threading.Thread(target=_start_flask, daemon=True)
    t_flask.start()

    # Start our FastAPI analysis server in background thread
    t_fastapi = threading.Thread(target=_start_fastapi, daemon=True)
    t_fastapi.start()

    # Wait for both backends to come up
    log.info("Waiting for Flask upstream on port %d...", FLASK_PORT)
    if not _wait_for_port(FLASK_PORT, timeout=90):
        log.warning("Flask upstream did not start in time — proxy will retry on demand")

    log.info("Waiting for FastAPI analysis server on port %d...", FASTAPI_PORT)
    if not _wait_for_port(FASTAPI_PORT, timeout=30):
        log.warning("FastAPI server did not start in time")

    log.info("Starting proxy on port %d", PROXY_PORT)
    uvicorn.run(proxy_app, host="0.0.0.0", port=PROXY_PORT, log_level="info")

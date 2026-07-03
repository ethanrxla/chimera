"""
HexStrike Security API Server — runs as Docker service `hexstrike` on port 8888.

The hexstrike_mcp.py stdio bridge calls this server.  All endpoints use the
API keys passed via environment variables.
"""
import asyncio
import json
import os
import re
import time
from typing import Any, List
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="HexStrike Security API", version="1.0.0")

_LINK_RE = re.compile(r'href=["\']([^"\'#?][^"\']*)["\']', re.IGNORECASE)
_COMMON_PATHS = [
    "/", "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html",
    "/openapi.json", "/docs", "/redoc", "/graphql", "/health", "/status",
    "/admin", "/login", "/register", "/user", "/users", "/products",
    "/rest/user/whoami",
]


async def _direct_crawl(base_url: str, max_links: int = 30) -> list[str]:
    """Crawl base_url with httpx and extract hrefs. Used when Firecrawl is unavailable
    or the target is on a private network."""
    found: set[str] = set()
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        # Probe common paths first
        for path in _COMMON_PATHS:
            url = f"{origin}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code < 400:
                    found.add(url)
                    for href in _LINK_RE.findall(resp.text)[:50]:
                        abs_url = href if href.startswith("http") else urljoin(origin, href)
                        if abs_url.startswith(origin):
                            found.add(abs_url)
            except Exception:
                pass
            if len(found) >= max_links:
                break

        # Fetch the root page and extract more links
        if len(found) < max_links:
            try:
                resp = await client.get(base_url)
                for href in _LINK_RE.findall(resp.text)[:100]:
                    abs_url = href if href.startswith("http") else urljoin(origin, href)
                    if abs_url.startswith(origin):
                        found.add(abs_url)
            except Exception:
                pass

    return sorted(found)[:max_links]

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
FIRECRAWL_API_KEY = os.getenv("FIRECRAWL_API_KEY", "")
SERPAPI_API_KEY = os.getenv("SERPAPI_API_KEY", "")
LLM_API_BASE = os.getenv("LLM_API_BASE", "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "dummy")
LLM_MODEL = os.getenv("LLM_MODEL", "qwen2.5:7b")


async def _llm_complete(prompt: str, max_tokens: int = 2048) -> str:
    if LLM_API_BASE:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{LLM_API_BASE}/chat/completions",
                headers={"Authorization": f"Bearer {LLM_API_KEY}"},
                json={"model": LLM_MODEL, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens},
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
    if ANTHROPIC_API_KEY:
        import anthropic  # noqa: PLC0415
        client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
        msg = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text.strip()
    raise RuntimeError("No LLM backend configured: set LLM_API_BASE or ANTHROPIC_API_KEY")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ReconRequest(BaseModel):
    target: str
    passive_only: bool = True


class EndpointsRequest(BaseModel):
    target: str


class AttackSurfaceRequest(BaseModel):
    target: str
    findings: List[Any] = []


class ExploitRequest(BaseModel):
    vuln_type: str
    target: str
    context: str = ""


class ProbeRequest(BaseModel):
    endpoint: str
    method: str = "GET"
    token: str = ""
    headers: dict[str, str] = {}
    query: dict[str, Any] = {}
    body: Any = None
    follow_redirects: bool = True


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "hexstrike-api",
        "capabilities": ["recon", "endpoints", "attack-surface", "exploit", "probe"],
        "backends": {
            "llm": LLM_API_BASE or ("anthropic" if ANTHROPIC_API_KEY else None),
            "firecrawl": bool(FIRECRAWL_API_KEY),
            "serpapi": bool(SERPAPI_API_KEY),
        },
    }


# ---------------------------------------------------------------------------
# Recon
# ---------------------------------------------------------------------------

@app.post("/api/recon")
async def recon(req: ReconRequest):
    url = req.target if req.target.startswith("http") else f"https://{req.target}"
    domain = url.split("//")[-1].split("/")[0]
    results: dict = {
        "target": req.target,
        "source": "hexstrike-api",
        "endpoints": [],
        "search_results": [],
        "errors": {},
    }

    async with httpx.AsyncClient(timeout=30) as client:
        if FIRECRAWL_API_KEY:
            try:
                resp = await client.post(
                    "https://api.firecrawl.dev/v1/map",
                    headers={"Authorization": f"Bearer {FIRECRAWL_API_KEY}"},
                    json={"url": url, "limit": 50},
                )
                if resp.status_code == 200:
                    results["endpoints"] = resp.json().get("links", [])[:30]
            except Exception as exc:
                results["errors"]["firecrawl"] = str(exc)

        if SERPAPI_API_KEY:
            try:
                resp = await client.get(
                    "https://serpapi.com/search",
                    params={"q": f"site:{domain}", "api_key": SERPAPI_API_KEY, "num": 20},
                    timeout=15,
                )
                if resp.status_code == 200:
                    results["search_results"] = [
                        r.get("link", "") for r in resp.json().get("organic_results", []) if r.get("link")
                    ]
            except Exception as exc:
                results["errors"]["serpapi"] = str(exc)

    # Fallback: direct HTTP crawl when external APIs return nothing
    if not results["endpoints"] and not results["search_results"]:
        try:
            crawled = await _direct_crawl(url)
            results["endpoints"] = crawled
            results["source"] = "direct-crawl-fallback"
        except Exception as exc:
            results["errors"]["direct_crawl"] = str(exc)

    return results


# ---------------------------------------------------------------------------
# Endpoint discovery
# ---------------------------------------------------------------------------

@app.post("/api/endpoints")
async def endpoints(req: EndpointsRequest):
    results: dict = {"target": req.target, "source": "hexstrike-api", "endpoints": [], "errors": {}}

    if FIRECRAWL_API_KEY:
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.post(
                    "https://api.firecrawl.dev/v1/crawl",
                    headers={"Authorization": f"Bearer {FIRECRAWL_API_KEY}"},
                    json={"url": req.target, "limit": 50, "scrapeOptions": {"formats": ["links"]}},
                )
                if resp.status_code == 200:
                    results["endpoints"] = resp.json().get("data", [])[:30]
            except Exception as exc:
                results["errors"]["firecrawl"] = str(exc)
    else:
        results["errors"]["firecrawl"] = "FIRECRAWL_API_KEY not configured"

    # Fallback: direct HTTP crawl when Firecrawl is unavailable or returned nothing
    if not results["endpoints"]:
        try:
            crawled = await _direct_crawl(req.target)
            results["endpoints"] = crawled
            results["source"] = "direct-crawl-fallback"
        except Exception as exc:
            results["errors"]["direct_crawl"] = str(exc)

    return results


# ---------------------------------------------------------------------------
# Attack surface analysis
# ---------------------------------------------------------------------------

@app.post("/api/attack-surface")
async def attack_surface(req: AttackSurfaceRequest):
    prompt = (
        f"You are an expert penetration tester. Analyze the full attack surface for: {req.target}\n\n"
        f"Prior recon findings:\n{json.dumps(req.findings, indent=2)}\n\n"
        "Return valid JSON only (no markdown fences):\n"
        '{"attack_vectors":[{"name":str,"description":str,"severity":"critical|high|medium|low",'
        '"confidence":0.0}],'
        '"entry_points":[str],'
        '"recommended_tests":[str],'
        '"priority_order":[str]}'
    )
    try:
        text = await _llm_complete(prompt)
    except Exception as exc:
        return {"error": str(exc), "target": req.target}
    try:
        return json.loads(text)
    except Exception:
        return {"analysis": text, "target": req.target, "parse_failed": True}


# ---------------------------------------------------------------------------
# Exploit guidance
# ---------------------------------------------------------------------------

@app.post("/api/exploit")
async def exploit(req: ExploitRequest):
    prompt = (
        f"Expert penetration tester. Provide concrete exploit guidance for:\n"
        f"Vulnerability type: {req.vuln_type}\n"
        f"Target: {req.target}\n"
        f"Context: {req.context}\n\n"
        "Return valid JSON only (no markdown fences):\n"
        '{"repro_steps":[str],"payload_examples":[str],"tools_needed":[str],'
        '"severity":"critical|high|medium|low","mitigation":str}'
    )
    try:
        text = await _llm_complete(prompt)
    except Exception as exc:
        return {"error": str(exc)}
    try:
        return json.loads(text)
    except Exception:
        return {"guidance": text, "parse_failed": True}


# ---------------------------------------------------------------------------
# API security probe
# ---------------------------------------------------------------------------

@app.post("/api/tools/httpx")
async def tools_httpx(req: dict):
    """Override upstream httpx endpoint — upstream doesn't pipe targets via stdin correctly."""
    # Accept both 'target' (upstream singular) and 'targets' (our wrapper's field)
    targets_raw: str = req.get("targets") or req.get("target") or ""
    if not targets_raw:
        return {"error": "Target parameter is required"}
    additional_args: str = req.get("additional_args", "-title -tech-detect -status-code -content-length")
    # Build stdin input: one URL per line
    urls = [u.strip() for u in targets_raw.replace(",", "\n").splitlines() if u.strip()]
    stdin_data = "\n".join(urls) + "\n"
    cmd = ["httpx"] + additional_args.split()
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(input=stdin_data.encode()), timeout=120)
        return {
            "success": proc.returncode == 0,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace")[:1000],
            "return_code": proc.returncode,
            "execution_time": round(time.monotonic() - t0, 2),
        }
    except asyncio.TimeoutError:
        return {"error": "httpx timed out", "execution_time": 120}
    except FileNotFoundError:
        return {"error": "httpx binary not found"}
    except Exception as exc:
        return {"error": str(exc)}


@app.post("/api/probe")
async def probe(req: ProbeRequest):
    out: dict = {"endpoint": req.endpoint, "method": req.method, "source": "hexstrike-api", "checks": {}}
    headers = dict(req.headers or {})
    if req.token:
        headers.setdefault("Authorization", f"Bearer {req.token}")

    async with httpx.AsyncClient(timeout=10, follow_redirects=bool(req.follow_redirects)) as client:
        try:
            fn = getattr(client, req.method.lower(), client.get)
            request_kwargs = {"headers": headers}
            if req.query:
                request_kwargs["params"] = dict(req.query)
            if req.body is not None:
                if isinstance(req.body, (dict, list)):
                    request_kwargs["json"] = req.body
                else:
                    request_kwargs["content"] = str(req.body)
            resp = await fn(req.endpoint, **request_kwargs)
            out["status_code"] = resp.status_code
            out["checks"]["auth_required"] = resp.status_code in (401, 403)
            out["checks"]["server"] = resp.headers.get("server", "")
            out["checks"]["content_type"] = resp.headers.get("content-type", "")
            out["checks"]["cors"] = resp.headers.get("access-control-allow-origin", "")
            out["checks"]["x_frame"] = resp.headers.get("x-frame-options", "")
            out["checks"]["csp"] = bool(resp.headers.get("content-security-policy"))
            out["checks"]["hsts"] = bool(resp.headers.get("strict-transport-security"))
            out["checks"]["rate_limit_headers"] = {
                k: v for k, v in resp.headers.items()
                if "rate" in k.lower() or "retry" in k.lower() or "limit" in k.lower()
            }
            out["headers"] = dict(resp.headers)
            out["body_excerpt"] = resp.text[:2048]
        except Exception as exc:
            out["error"] = str(exc)

    return out

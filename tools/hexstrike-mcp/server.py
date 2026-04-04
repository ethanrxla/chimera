"""
HexStrike Security API Server — runs as Docker service `hexstrike` on port 8888.

The hexstrike_mcp.py stdio bridge calls this server.  All endpoints use the
API keys passed via environment variables.
"""
import json
import os
from typing import Any, List

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="HexStrike Security API", version="1.0.0")

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
FIRECRAWL_API_KEY = os.getenv("FIRECRAWL_API_KEY", "")
SERPAPI_API_KEY = os.getenv("SERPAPI_API_KEY", "")


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
            "anthropic": bool(ANTHROPIC_API_KEY),
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

    return results


# ---------------------------------------------------------------------------
# Attack surface analysis
# ---------------------------------------------------------------------------

@app.post("/api/attack-surface")
async def attack_surface(req: AttackSurfaceRequest):
    if not ANTHROPIC_API_KEY:
        return {"error": "ANTHROPIC_API_KEY not configured", "target": req.target}

    import anthropic  # noqa: PLC0415

    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
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
    msg = await client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}],
    )
    text = msg.content[0].text.strip()
    try:
        return json.loads(text)
    except Exception:
        return {"analysis": text, "target": req.target, "parse_failed": True}


# ---------------------------------------------------------------------------
# Exploit guidance
# ---------------------------------------------------------------------------

@app.post("/api/exploit")
async def exploit(req: ExploitRequest):
    if not ANTHROPIC_API_KEY:
        return {"error": "ANTHROPIC_API_KEY not configured"}

    import anthropic  # noqa: PLC0415

    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    prompt = (
        f"Expert penetration tester. Provide concrete exploit guidance for:\n"
        f"Vulnerability type: {req.vuln_type}\n"
        f"Target: {req.target}\n"
        f"Context: {req.context}\n\n"
        "Return valid JSON only (no markdown fences):\n"
        '{"repro_steps":[str],"payload_examples":[str],"tools_needed":[str],'
        '"severity":"critical|high|medium|low","mitigation":str}'
    )
    msg = await client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}],
    )
    text = msg.content[0].text.strip()
    try:
        return json.loads(text)
    except Exception:
        return {"guidance": text, "parse_failed": True}


# ---------------------------------------------------------------------------
# API security probe
# ---------------------------------------------------------------------------

@app.post("/api/probe")
async def probe(req: ProbeRequest):
    out: dict = {"endpoint": req.endpoint, "method": req.method, "source": "hexstrike-api", "checks": {}}
    headers = {"Authorization": f"Bearer {req.token}"} if req.token else {}

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        try:
            fn = getattr(client, req.method.lower(), client.get)
            resp = await fn(req.endpoint, headers=headers)
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
        except Exception as exc:
            out["error"] = str(exc)

    return out

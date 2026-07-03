"""
HexStrike MCP Bridge — stdio transport.

Spawned as a subprocess by Decepticon's MultiServerMCPClient when
HEXSTRIKE_ENABLED=true.  Exposes high-level analysis tools plus direct
HexStrike tool wrappers that proxy to the HexStrike API server
(http://hexstrike:8888 by default).

Each tool falls back to direct API usage (Firecrawl, SerpAPI, Anthropic)
when the HexStrike server is unreachable.
"""
import argparse
import json
import os
import sys

import httpx
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Bootstrap — parse --server before FastMCP takes over argv
# ---------------------------------------------------------------------------
_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--server", default=os.getenv("HEXSTRIKE_SERVER_URL", "http://hexstrike:8888"))
_args, _remaining = _parser.parse_known_args()
sys.argv = [sys.argv[0]] + _remaining  # strip --server so FastMCP doesn't choke

SERVER_URL: str = _args.server.rstrip("/")
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
FIRECRAWL_API_KEY: str = os.getenv("FIRECRAWL_API_KEY", "")
SERPAPI_API_KEY: str = os.getenv("SERPAPI_API_KEY", "")
LLM_API_BASE: str = os.getenv("LLM_API_BASE", "").rstrip("/")
LLM_API_KEY: str = os.getenv("LLM_API_KEY", "dummy")
LLM_MODEL: str = os.getenv("LLM_MODEL", "qwen2.5:7b")

mcp = FastMCP("hexstrike")

_DIRECT_TOOL_ROUTES = {
    "httpx": "/api/tools/httpx",
    "nmap": "/api/tools/nmap",
    "nuclei": "/api/tools/nuclei",
    "nikto": "/api/tools/nikto",
    "gobuster": "/api/tools/gobuster",
    "ffuf": "/api/tools/ffuf",
    "dalfox": "/api/tools/dalfox",
    "subfinder": "/api/tools/subfinder",
    "waybackurls": "/api/tools/waybackurls",
    "gau": "/api/tools/gau",
    "masscan": "/api/tools/masscan",
    "sqlmap": "/api/tools/sqlmap",
    "curl": "/api/tools/curl",
    "checksec": "/api/tools/checksec",
    "anew": "/api/tools/anew",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _server_post(path: str, payload: dict, timeout: int = 60) -> dict:
    """Call HexStrike server; return parsed response or fallback sentinel."""
    try:
        resp = httpx.post(f"{SERVER_URL}{path}", json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        return {"_fallback": True, "_error": str(exc)}


def _server_tool(tool_name: str, payload: dict, timeout: int = 300) -> str:
    route = _DIRECT_TOOL_ROUTES.get(tool_name)
    if not route:
        return json.dumps({"error": f"Unsupported HexStrike tool: {tool_name}"}, indent=2)
    result = _server_post(route, payload, timeout=timeout)
    return json.dumps(result, indent=2)


def _claude_complete(prompt: str, max_tokens: int = 2048) -> str:
    """LLM call used as local fallback — prefers Ollama, falls back to Anthropic."""
    if LLM_API_BASE:
        try:
            resp = httpx.post(
                f"{LLM_API_BASE}/chat/completions",
                headers={"Authorization": f"Bearer {LLM_API_KEY}"},
                json={"model": LLM_MODEL, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens},
                timeout=120,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
        except Exception as exc:
            return json.dumps({"error": str(exc)})
    if not ANTHROPIC_API_KEY:
        return json.dumps({"error": "No LLM backend: set LLM_API_BASE or ANTHROPIC_API_KEY"})
    import anthropic  # lazy import; present in chimera/decepticon venvs
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text.strip()


def _firecrawl_map(url: str) -> list[str]:
    """Return up to 30 links from Firecrawl /map."""
    if not FIRECRAWL_API_KEY:
        return []
    try:
        resp = httpx.post(
            "https://api.firecrawl.dev/v1/map",
            headers={"Authorization": f"Bearer {FIRECRAWL_API_KEY}"},
            json={"url": url, "limit": 30},
            timeout=30,
        )
        if resp.status_code == 200:
            return resp.json().get("links", [])[:30]
    except Exception:
        pass
    return []


def _serpapi_site(domain: str) -> list[str]:
    """Return up to 20 URLs from site: query via SerpAPI."""
    if not SERPAPI_API_KEY:
        return []
    try:
        resp = httpx.get(
            "https://serpapi.com/search",
            params={"q": f"site:{domain}", "api_key": SERPAPI_API_KEY, "num": 20},
            timeout=15,
        )
        if resp.status_code == 200:
            return [r.get("link", "") for r in resp.json().get("organic_results", []) if r.get("link")]
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool(
    description=(
        "Passive reconnaissance: subdomain discovery, technology fingerprinting, "
        "and endpoint enumeration for a target domain or URL."
    )
)
def recon_target(target: str, passive_only: bool = True) -> str:
    result = _server_post("/api/recon", {"target": target, "passive_only": passive_only})
    if not result.get("_fallback"):
        return json.dumps(result, indent=2)

    # Fallback: Firecrawl + SerpAPI
    url = target if target.startswith("http") else f"https://{target}"
    links = _firecrawl_map(url)
    search_hits = _serpapi_site(target.split("//")[-1].split("/")[0])
    return json.dumps({
        "target": target,
        "source": "hexstrike-mcp-fallback",
        "endpoints": links,
        "search_results": search_hits,
        "note": f"HexStrike server unreachable ({result.get('_error')}); used Firecrawl + SerpAPI",
    }, indent=2)


@mcp.tool(
    description=(
        "Enumerate API endpoints, parameters, and HTTP methods for a target URL. "
        "Returns discovered paths useful for BOLA/IDOR and auth testing."
    )
)
def discover_endpoints(target_url: str) -> str:
    result = _server_post("/api/endpoints", {"target": target_url})
    if not result.get("_fallback"):
        return json.dumps(result, indent=2)

    links = _firecrawl_map(target_url)
    return json.dumps({
        "target": target_url,
        "source": "hexstrike-mcp-fallback",
        "endpoints": links,
        "note": f"HexStrike server unreachable ({result.get('_error')}); used Firecrawl",
    }, indent=2)


@mcp.tool(
    description=(
        "Analyze the attack surface given prior recon findings. "
        "Returns prioritized attack vectors, entry points, and recommended tests."
    )
)
def analyze_attack_surface(target: str, findings_json: str) -> str:
    try:
        findings = json.loads(findings_json)
    except Exception:
        findings = []

    result = _server_post("/api/attack-surface", {"target": target, "findings": findings})
    if not result.get("_fallback"):
        return json.dumps(result, indent=2)

    # Fallback: direct Claude call
    prompt = (
        f"Expert penetration tester. Analyze the attack surface for {target}.\n\n"
        f"Prior recon findings:\n{json.dumps(findings, indent=2)}\n\n"
        "Return JSON only (no markdown):\n"
        '{"attack_vectors":[{"name":str,"description":str,"severity":"critical|high|medium|low",'
        '"confidence":0.0-1.0}],'
        '"entry_points":[str],'
        '"recommended_tests":[str],'
        '"priority_order":[str]}'
    )
    text = _claude_complete(prompt)
    try:
        return text if text.startswith("{") else json.dumps({"analysis": text, "source": "anthropic-fallback"})
    except Exception:
        return json.dumps({"analysis": text, "source": "anthropic-fallback"})


@mcp.tool(
    description=(
        "Generate step-by-step exploit guidance for a confirmed vulnerability. "
        "Includes payload examples, tools needed, and mitigation advice."
    )
)
def exploit_guidance(vuln_type: str, target: str, context: str = "") -> str:
    result = _server_post("/api/exploit", {"vuln_type": vuln_type, "target": target, "context": context})
    if not result.get("_fallback"):
        return json.dumps(result, indent=2)

    prompt = (
        f"Expert pentester. Step-by-step exploit for:\n"
        f"Vulnerability: {vuln_type}\nTarget: {target}\nContext: {context}\n\n"
        "Return JSON only (no markdown):\n"
        '{"repro_steps":[str],"payload_examples":[str],"tools_needed":[str],'
        '"severity":"critical|high|medium|low","mitigation":str}'
    )
    text = _claude_complete(prompt)
    try:
        return text if text.startswith("{") else json.dumps({"guidance": text, "source": "anthropic-fallback"})
    except Exception:
        return json.dumps({"guidance": text})


@mcp.tool(
    description=(
        "Probe an API endpoint for security issues: authentication requirements, "
        "CORS headers, server fingerprinting, and basic response analysis."
    )
)
def api_security_probe(endpoint: str, method: str = "GET", token: str = "") -> str:
    result = _server_post("/api/probe", {"endpoint": endpoint, "method": method, "token": token})
    if not result.get("_fallback"):
        return json.dumps(result, indent=2)

    # Fallback: direct probe
    out: dict = {"endpoint": endpoint, "method": method, "source": "hexstrike-mcp-fallback", "checks": {}}
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        with httpx.Client(timeout=10, follow_redirects=True) as client:
            fn = getattr(client, method.lower(), client.get)
            resp = fn(endpoint, headers=headers)
            out["status_code"] = resp.status_code
            out["checks"]["auth_required"] = resp.status_code in (401, 403)
            out["checks"]["server"] = resp.headers.get("server", "")
            out["checks"]["content_type"] = resp.headers.get("content-type", "")
            out["checks"]["cors"] = resp.headers.get("access-control-allow-origin", "")
            out["checks"]["x_frame"] = resp.headers.get("x-frame-options", "")
            out["checks"]["csp"] = bool(resp.headers.get("content-security-policy"))
    except Exception as exc:
        out["error"] = str(exc)
    return json.dumps(out, indent=2)


@mcp.tool(
    description=(
        "Direct pass-through to a named HexStrike upstream tool route. "
        "Use when you need one of the lower-level HexStrike tools that does not have a convenience wrapper."
    )
)
def run_hexstrike_tool(tool_name: str, payload_json: str = "{}") -> str:
    try:
        payload = json.loads(payload_json) if payload_json.strip() else {}
    except Exception as exc:
        return json.dumps({"error": f"Invalid payload_json: {exc}"}, indent=2)
    return _server_tool(tool_name, payload)


@mcp.tool(description="Run httpx against one or more URLs or hosts.")
def run_httpx(targets: str, additional_args: str = "-title -tech-detect -status-code") -> str:
    return _server_tool("httpx", {"targets": targets, "additional_args": additional_args})


@mcp.tool(description="Run nmap service fingerprinting against a host.")
def run_nmap(target: str, scan_type: str = "-sCV", ports: str = "80,443,8080") -> str:
    return _server_tool("nmap", {"target": target, "scan_type": scan_type, "ports": ports})


@mcp.tool(description="Run masscan for fast port discovery against a host.")
def run_masscan(target: str, ports: str = "80,443,8080", rate: str = "1000") -> str:
    return _server_tool("masscan", {"target": target, "ports": ports, "rate": rate})


@mcp.tool(description="Run nuclei templates against a target URL.")
def run_nuclei(target: str, severity: str = "critical,high,medium", tags: str = "") -> str:
    payload = {"target": target, "severity": severity}
    if tags:
        payload["tags"] = tags
    return _server_tool("nuclei", payload)


@mcp.tool(description="Run nikto against a target URL.")
def run_nikto(target: str) -> str:
    return _server_tool("nikto", {"target": target})


@mcp.tool(description="Run gobuster for directory or file brute forcing.")
def run_gobuster(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    return _server_tool("gobuster", {"url": url, "mode": mode, "wordlist": wordlist})


@mcp.tool(description="Run ffuf against a fuzzable URL pattern.")
def run_ffuf(url: str, additional_args: str = "-mc 200,301,302 -t 40") -> str:
    return _server_tool("ffuf", {"url": url, "additional_args": additional_args})


@mcp.tool(description="Run dalfox against a URL for XSS testing.")
def run_dalfox(url: str, additional_args: str = "--silence --no-color") -> str:
    return _server_tool("dalfox", {"url": url, "additional_args": additional_args})


@mcp.tool(description="Run subfinder against a domain.")
def run_subfinder(domain: str) -> str:
    return _server_tool("subfinder", {"domain": domain})


@mcp.tool(description="Collect historical URLs from Wayback Machine.")
def run_waybackurls(domain: str) -> str:
    return _server_tool("waybackurls", {"domain": domain})


@mcp.tool(description="Gather archived URLs from multiple providers.")
def run_gau(domain: str) -> str:
    return _server_tool("gau", {"domain": domain})


@mcp.tool(description="Run sqlmap against a target URL. Use only with explicit authorization.")
def run_sqlmap(url: str, data: str = "", additional_args: str = "--batch --level=2") -> str:
    payload = {"url": url, "additional_args": additional_args}
    if data:
        payload["data"] = data
    return _server_tool("sqlmap", payload)


@mcp.tool(description="Replay a curl request through HexStrike.")
def run_curl(url: str, additional_args: str = "-i -s") -> str:
    return _server_tool("curl", {"url": url, "additional_args": additional_args})


@mcp.tool(description="Run checksec against a local file path inside the HexStrike environment.")
def run_checksec(file_path: str, additional_args: str = "--format=json") -> str:
    return _server_tool("checksec", {"file_path": file_path, "additional_args": additional_args})


@mcp.tool(description="Append unique lines with anew semantics.")
def run_anew(input_lines: str, output_file: str = "") -> str:
    payload = {"input_lines": input_lines}
    if output_file:
        payload["output_file"] = output_file
    return _server_tool("anew", payload)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="stdio")

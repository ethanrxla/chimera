from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class HexStrikeToolSpec:
    tool_name: str
    route: str
    risk_tier: str
    target_fields: Tuple[str, ...]
    allowed_agents: Tuple[str, ...]
    description: str = ""
    example: str = ""
    timeout_s: int = 300


_CATALOG: Dict[str, HexStrikeToolSpec] = {
    "nuclei": HexStrikeToolSpec(
        tool_name="nuclei",
        route="/api/tools/nuclei",
        risk_tier="bounded_active",
        target_fields=("target",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Template-based scanning for well-known web vulnerabilities.",
        example='{"tool":"nuclei","target":"https://example.com","severity":"critical,high,medium","tags":"xss,sqli"}',
    ),
    "gobuster": HexStrikeToolSpec(
        tool_name="gobuster",
        route="/api/tools/gobuster",
        risk_tier="bounded_active",
        target_fields=("url",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Directory and path brute forcing.",
        example='{"tool":"gobuster","url":"https://example.com","mode":"dir","wordlist":"/usr/share/wordlists/dirb/common.txt"}',
    ),
    "ffuf": HexStrikeToolSpec(
        tool_name="ffuf",
        route="/api/tools/ffuf",
        risk_tier="bounded_active",
        target_fields=("url",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Fast fuzzing for files, params, or vhosts.",
        example='{"tool":"ffuf","url":"https://example.com/FUZZ","additional_args":"-mc 200,301,302 -t 40"}',
    ),
    "sqlmap": HexStrikeToolSpec(
        tool_name="sqlmap",
        route="/api/tools/sqlmap",
        risk_tier="dangerous",
        target_fields=("url",),
        allowed_agents=("strix", "shannon_executor"),
        description="SQL injection verification and exploitation guidance.",
        example='{"tool":"sqlmap","url":"https://example.com/login","data":"username=test&password=test","additional_args":"--batch --level=2"}',
    ),
    "dalfox": HexStrikeToolSpec(
        tool_name="dalfox",
        route="/api/tools/dalfox",
        risk_tier="bounded_active",
        target_fields=("url",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Focused XSS scanning.",
        example='{"tool":"dalfox","url":"https://example.com/search?q=test","additional_args":""}',
    ),
    "nmap": HexStrikeToolSpec(
        tool_name="nmap",
        route="/api/tools/nmap",
        risk_tier="bounded_active",
        target_fields=("target",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Port and service fingerprinting.",
        example='{"tool":"nmap","target":"example.com","scan_type":"-sCV","ports":"80,443,8080"}',
    ),
    "masscan": HexStrikeToolSpec(
        tool_name="masscan",
        route="/api/tools/masscan",
        risk_tier="bounded_active",
        target_fields=("target",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Fast port scanning for exposed services.",
        example='{"tool":"masscan","target":"example.com","ports":"80,443,8080","rate":"1000"}',
    ),
    "httpx": HexStrikeToolSpec(
        tool_name="httpx",
        route="/api/tools/httpx",
        risk_tier="safe",
        target_fields=("targets",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="HTTP probing and lightweight web fingerprinting.",
        example='{"tool":"httpx","targets":"https://example.com,https://api.example.com","additional_args":"-title -tech-detect -status-code"}',
    ),
    "curl": HexStrikeToolSpec(
        tool_name="curl",
        route="/api/tools/curl",
        risk_tier="safe",
        target_fields=("url",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Flexible HTTP requests for precise request replay.",
        example='{"tool":"curl","url":"https://example.com/login","additional_args":"-i -s"}',
    ),
    "katana": HexStrikeToolSpec(
        tool_name="katana",
        route="/api/tools/katana",
        risk_tier="safe",
        target_fields=("url",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Crawling for URLs and application paths.",
        example='{"tool":"katana","url":"https://example.com","depth":3}',
    ),
    "nikto": HexStrikeToolSpec(
        tool_name="nikto",
        route="/api/tools/nikto",
        risk_tier="bounded_active",
        target_fields=("target",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Web server misconfiguration checks.",
        example='{"tool":"nikto","target":"https://example.com"}',
    ),
    "subfinder": HexStrikeToolSpec(
        tool_name="subfinder",
        route="/api/tools/subfinder",
        risk_tier="safe",
        target_fields=("domain",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Subdomain discovery.",
        example='{"tool":"subfinder","domain":"example.com"}',
    ),
    "waybackurls": HexStrikeToolSpec(
        tool_name="waybackurls",
        route="/api/tools/waybackurls",
        risk_tier="safe",
        target_fields=("domain",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Historical URL collection from archives.",
        example='{"tool":"waybackurls","domain":"example.com"}',
    ),
    "gau": HexStrikeToolSpec(
        tool_name="gau",
        route="/api/tools/gau",
        risk_tier="safe",
        target_fields=("domain",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Gather archived URLs from multiple sources.",
        example='{"tool":"gau","domain":"example.com"}',
    ),
    "jwt_analyzer": HexStrikeToolSpec(
        tool_name="jwt_analyzer",
        route="/api/tools/jwt_analyzer",
        risk_tier="safe",
        target_fields=(),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="JWT structure and algorithm inspection.",
        example='{"tool":"jwt_analyzer","token":"JWT_STRING"}',
    ),
    "checksec": HexStrikeToolSpec(
        tool_name="checksec",
        route="/api/tools/checksec",
        risk_tier="safe",
        target_fields=(),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Binary hardening inspection for a provided file path.",
        example='{"tool":"checksec","file_path":"/bin/ls","additional_args":"--format=json"}',
    ),
    "anew": HexStrikeToolSpec(
        tool_name="anew",
        route="/api/tools/anew",
        risk_tier="safe",
        target_fields=(),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Append unique lines to a file or de-duplicate a supplied list.",
        example='{"tool":"anew","output_file":"/tmp/targets.txt","input_lines":"https://example.com\\nhttps://api.example.com"}',
    ),
    "command": HexStrikeToolSpec(
        tool_name="command",
        route="/api/command",
        risk_tier="dangerous",
        target_fields=(),
        allowed_agents=("strix", "shannon_executor"),
        description="Generic command execution through HexStrike upstream.",
        example='{"tool":"command","command":"echo healthcheck"}',
    ),
    "recon": HexStrikeToolSpec(
        tool_name="recon",
        route="/api/recon",
        risk_tier="safe",
        target_fields=("target",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Passive reconnaissance: seed endpoints and surrounding surface.",
        example='{"tool":"recon","target":"https://example.com","passive_only":true}',
    ),
    "endpoints": HexStrikeToolSpec(
        tool_name="endpoints",
        route="/api/endpoints",
        risk_tier="safe",
        target_fields=("target",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Enumerate reachable endpoints for a target URL.",
        example='{"tool":"endpoints","target":"https://example.com"}',
    ),
    "attack_surface": HexStrikeToolSpec(
        tool_name="attack_surface",
        route="/api/attack-surface",
        risk_tier="safe",
        target_fields=("target",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Prioritize attack vectors from prior recon or findings.",
        example='{"tool":"attack_surface","target":"https://example.com","findings":[]}',
    ),
    "exploit": HexStrikeToolSpec(
        tool_name="exploit",
        route="/api/exploit",
        risk_tier="bounded_active",
        target_fields=("target",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Generate exploit guidance for a specific vulnerability hypothesis.",
        example='{"tool":"exploit","vuln_type":"XSS","target":"https://example.com/search","context":"search input reflects HTML"}',
    ),
    "probe": HexStrikeToolSpec(
        tool_name="probe",
        route="/api/probe",
        risk_tier="safe",
        target_fields=("endpoint",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="Probe one endpoint for auth, CORS, and header security signals.",
        example='{"tool":"probe","endpoint":"https://example.com/login","method":"GET","token":""}',
    ),
    "wpscan": HexStrikeToolSpec(
        tool_name="wpscan",
        route="/api/tools/wpscan",
        risk_tier="bounded_active",
        target_fields=("url",),
        allowed_agents=("strix", "shannon_executor", "deterministic_runner"),
        description="WordPress vulnerability and user enumeration checks.",
        example='{"tool":"wpscan","url":"https://example.com","additional_args":"--enumerate u,p,t --detection-mode aggressive"}',
    ),
}


def get_tool_catalog() -> Dict[str, HexStrikeToolSpec]:
    return dict(_CATALOG)


def get_tool_spec(tool_name: str) -> HexStrikeToolSpec:
    try:
        return _CATALOG[tool_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported HexStrike tool: {tool_name}") from exc


def get_agent_tool_catalog(agent: str) -> Dict[str, HexStrikeToolSpec]:
    return {
        name: spec
        for name, spec in _CATALOG.items()
        if agent in spec.allowed_agents
    }


def render_tool_prompt(agent: str) -> str:
    lines = [
        "You have access to HexStrike security tools. To call a tool, emit a JSON block wrapped in",
        "<hexstrike_call> tags BEFORE your findings JSON. You may call multiple tools in sequence.",
        "After receiving tool results, reason about them and produce your findings JSON.",
        "",
        "Available tools:",
    ]
    for spec in get_agent_tool_catalog(agent).values():
        example = spec.example or f'{{"tool":"{spec.tool_name}"}}'
        lines.append(f"- {spec.tool_name}: {example}")
    lines.extend(
        [
            "",
            "Example:",
            '<hexstrike_call>{"tool":"nuclei","target":"https://example.com","severity":"high","tags":"xss"}</hexstrike_call>',
            '<hexstrike_call>{"tool":"probe","endpoint":"https://example.com/login","method":"GET","token":""}</hexstrike_call>',
            '{"findings": [...]}',
            "",
            "Rules:",
            "- Only call tools that are relevant to the plan",
            "- Do NOT call tools for out-of-scope targets",
            "- After tool results are injected, produce the final findings JSON",
            "- If no tool is needed, emit findings JSON directly",
        ]
    )
    return "\n".join(lines)

from __future__ import annotations

from typing import Any, Dict, List, Set


_SAFE_HEXSTRIKE_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "hexstrike_recon",
        "description": "Run passive reconnaissance for a target host or URL.",
        "example": {"target": "https://example.com", "passive_only": True},
    },
    {
        "name": "hexstrike_endpoints",
        "description": "Enumerate likely endpoints for a target host or URL.",
        "example": {"target": "https://example.com"},
    },
    {
        "name": "hexstrike_attack_surface",
        "description": "Prioritize attack vectors from prior recon or findings.",
        "example": {"target": "https://example.com", "findings": []},
    },
    {
        "name": "hexstrike_exploit",
        "description": "Generate exploit guidance for a specific vulnerability hypothesis.",
        "example": {"vuln_type": "XSS", "target": "https://example.com/search", "context": "search input reflects HTML"},
    },
    {
        "name": "hexstrike_probe",
        "description": "Run a bounded HTTP security probe against one concrete endpoint.",
        "example": {"endpoint": "https://example.com/login", "method": "GET", "token": ""},
    },
    {
        "name": "hexstrike_httpx",
        "description": "Run lightweight HTTP probing for status, headers, and titles.",
        "example": {"targets": "https://example.com", "additional_args": "-title -tech-detect -status-code"},
    },
    {
        "name": "hexstrike_nmap",
        "description": "Port and service fingerprinting.",
        "example": {"target": "example.com", "scan_type": "-sCV", "ports": "80,443,8080"},
    },
    {
        "name": "hexstrike_masscan",
        "description": "Fast port scanning for exposed services.",
        "example": {"target": "example.com", "ports": "80,443,8080", "rate": "1000"},
    },
    {
        "name": "hexstrike_nuclei",
        "description": "Template-based scanning for well-known web vulnerabilities.",
        "example": {"target": "https://example.com", "severity": "critical,high,medium", "tags": "xss,sqli"},
    },
    {
        "name": "hexstrike_nikto",
        "description": "Web server misconfiguration checks.",
        "example": {"target": "https://example.com"},
    },
    {
        "name": "hexstrike_katana",
        "description": "Crawling for URLs and application paths.",
        "example": {"url": "https://example.com", "depth": 3},
    },
    {
        "name": "hexstrike_gobuster",
        "description": "Directory and path brute forcing.",
        "example": {"url": "https://example.com", "mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt"},
    },
    {
        "name": "hexstrike_ffuf",
        "description": "Fast fuzzing for files, params, or vhosts.",
        "example": {"url": "https://example.com/FUZZ", "additional_args": "-mc 200,301,302 -t 40"},
    },
    {
        "name": "hexstrike_dalfox",
        "description": "Focused XSS scanning.",
        "example": {"url": "https://example.com/search?q=test", "additional_args": "--silence --no-color"},
    },
    {
        "name": "hexstrike_subfinder",
        "description": "Subdomain discovery.",
        "example": {"domain": "example.com"},
    },
    {
        "name": "hexstrike_waybackurls",
        "description": "Historical URL collection from archives.",
        "example": {"domain": "example.com"},
    },
    {
        "name": "hexstrike_gau",
        "description": "Gather archived URLs from multiple sources.",
        "example": {"domain": "example.com"},
    },
    {
        "name": "hexstrike_curl",
        "description": "Flexible HTTP requests for precise request replay.",
        "example": {"url": "https://example.com/login", "additional_args": "-i -s"},
    },
    {
        "name": "hexstrike_sqlmap",
        "description": "SQL injection verification and exploitation guidance.",
        "example": {"url": "https://example.com/login", "data": "username=test&password=test", "additional_args": "--batch --level=2"},
    },
    {
        "name": "hexstrike_jwt_analyzer",
        "description": "JWT structure and algorithm inspection.",
        "example": {"token": "JWT_STRING"},
    },
    {
        "name": "hexstrike_checksec",
        "description": "Binary hardening inspection for a provided file path.",
        "example": {"file_path": "/bin/ls", "additional_args": "--format=json"},
    },
    {
        "name": "hexstrike_anew",
        "description": "Append unique lines to a file or de-duplicate supplied input.",
        "example": {"output_file": "/tmp/targets.txt", "input_lines": "https://example.com\nhttps://api.example.com"},
    },
    {
        "name": "hexstrike_wpscan",
        "description": "WordPress vulnerability and user enumeration checks.",
        "example": {"url": "https://example.com", "additional_args": "--enumerate u,p,t --detection-mode aggressive"},
    },
]

_NON_HEXSTRIKE_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "zap_get_sites",
        "description": "List the current ZAP sites tree for an in-scope target or the whole session.",
        "example": {"target": "https://example.com"},
    },
    {
        "name": "zap_spider",
        "description": "Start a bounded passive ZAP spider for an in-scope target.",
        "example": {"target": "https://example.com", "recurse": True, "max_children": 25},
    },
    {
        "name": "zap_list_alerts",
        "description": "List ZAP alerts for an in-scope target.",
        "example": {"target": "https://example.com", "count": 20},
    },
    {
        "name": "list_source_files",
        "description": "List repository files under the configured source root using a bounded glob.",
        "example": {"glob": "src/**/*.ts", "limit": 40},
    },
    {
        "name": "search_source_code",
        "description": "Search the configured source tree for a regex pattern and return bounded matches.",
        "example": {"pattern": "app\\.get\\(", "glob": "src/**/*.ts", "limit": 20},
    },
    {
        "name": "read_source_file",
        "description": "Read a source file from the configured repo root with optional line bounds.",
        "example": {"path": "src/routes/login.ts", "start_line": 1, "end_line": 80},
    },
    {
        "name": "browser_navigate",
        "description": "Navigate to a target URL and capture status, headers, and final URL.",
        "example": {"url": "https://example.com"},
    },
    {
        "name": "browser_click",
        "description": "Click an element in the attached browser session.",
        "example": {"selector": "button[type=submit]", "url": "https://example.com/login"},
    },
    {
        "name": "browser_fill",
        "description": "Fill one or more form fields in the attached browser session.",
        "example": {"fields": {"input[name=email]": "user@example.com"}, "url": "https://example.com/login"},
    },
    {
        "name": "browser_execute_js",
        "description": "Execute JavaScript in the attached browser session and capture the result.",
        "example": {"js_code": "() => document.title", "url": "https://example.com"},
    },
    {
        "name": "browser_capture_dom",
        "description": "Fetch a page and capture simple DOM/title/body metadata for analysis.",
        "example": {"url": "https://example.com"},
    },
    {
        "name": "browser_get_console",
        "description": "Read the latest console entries from the attached browser session.",
        "example": {"limit": 50},
    },
    {
        "name": "browser_get_network",
        "description": "Read the latest captured network events from the attached browser session.",
        "example": {"limit": 50},
    },
    {
        "name": "terminal_start",
        "description": "Start a mediated PTY terminal session in Chimera core.",
        "example": {"command": ["bash"], "cols": 120, "rows": 36},
    },
    {
        "name": "terminal_write",
        "description": "Write text to a mediated PTY terminal session.",
        "example": {"session_id": "terminal-session-1", "data": "pwd\n"},
    },
    {
        "name": "terminal_read",
        "description": "Read buffered output from a mediated PTY terminal session.",
        "example": {"session_id": "terminal-session-1", "max_bytes": 4096, "timeout_ms": 50},
    },
    {
        "name": "terminal_resize",
        "description": "Resize a mediated PTY terminal session.",
        "example": {"session_id": "terminal-session-1", "cols": 140, "rows": 42},
    },
    {
        "name": "terminal_close",
        "description": "Close a mediated PTY terminal session.",
        "example": {"session_id": "terminal-session-1"},
    },
    {
        "name": "shell_run_scoped",
        "description": "Run a bounded read-only terminal command against an in-scope target.",
        "example": {"command": ["curl", "-sI", "https://example.com"]},
    },
    {
        "name": "read_artifact",
        "description": "Read a persisted run artifact by ref and return a bounded excerpt or selected JSON field.",
        "example": {"artifact_ref": "hexstrike/ver-1/check-1/normalized.json", "json_path": "body_excerpt", "max_chars": 1200},
    },
    {
        "name": "zap_get_sites",
        "description": "List in-scope sites currently known to the attached ZAP daemon.",
        "example": {"limit": 50},
    },
    {
        "name": "zap_spider",
        "description": "Run a bounded traditional spider in ZAP for one in-scope target URL.",
        "example": {"url": "https://example.com", "recurse": True, "max_duration_seconds": 60},
    },
    {
        "name": "zap_list_alerts",
        "description": "Fetch bounded ZAP alerts for one in-scope base URL.",
        "example": {"baseurl": "https://example.com", "count": 20},
    },
]

_ALL_TOOLS: List[Dict[str, Any]] = _SAFE_HEXSTRIKE_TOOLS + _NON_HEXSTRIKE_TOOLS
_TOOLS_BY_NAME: Dict[str, Dict[str, Any]] = {tool["name"]: tool for tool in _ALL_TOOLS}

_RECON_TOOL_NAMES: Set[str] = {
    "hexstrike_recon",
    "hexstrike_endpoints",
    "hexstrike_attack_surface",
    "hexstrike_httpx",
    "hexstrike_curl",
    "hexstrike_masscan",
    "hexstrike_katana",
    "hexstrike_subfinder",
    "hexstrike_waybackurls",
    "hexstrike_gau",
    "zap_get_sites",
    "zap_spider",
    "zap_list_alerts",
    "list_source_files",
    "search_source_code",
    "read_source_file",
    "browser_navigate",
    "browser_click",
    "browser_fill",
    "browser_execute_js",
    "browser_capture_dom",
    "browser_get_console",
    "browser_get_network",
    "terminal_start",
    "terminal_write",
    "terminal_read",
    "terminal_resize",
    "terminal_close",
    "read_artifact",
    "zap_get_sites",
    "zap_spider",
    "zap_list_alerts",
}

_REPORT_TOOL_NAMES: Set[str] = {
    "read_artifact",
}

_ANALYSIS_BASE_TOOL_NAMES: Set[str] = {
    "hexstrike_endpoints",
    "hexstrike_attack_surface",
    "hexstrike_probe",
    "hexstrike_httpx",
    "hexstrike_curl",
    "hexstrike_masscan",
    "hexstrike_checksec",
    "hexstrike_anew",
    "zap_get_sites",
    "zap_spider",
    "zap_list_alerts",
    "list_source_files",
    "search_source_code",
    "read_source_file",
    "browser_navigate",
    "browser_click",
    "browser_fill",
    "browser_execute_js",
    "browser_capture_dom",
    "browser_get_console",
    "browser_get_network",
    "terminal_start",
    "terminal_write",
    "terminal_read",
    "terminal_resize",
    "terminal_close",
    "read_artifact",
    "shell_run_scoped",
    "zap_get_sites",
    "zap_spider",
    "zap_list_alerts",
}

_EXPLOIT_EXTRA_TOOL_NAMES: Set[str] = {
    "hexstrike_exploit",
    "hexstrike_nuclei",
    "hexstrike_ffuf",
    "hexstrike_gobuster",
    "hexstrike_nikto",
    "hexstrike_nmap",
    "hexstrike_masscan",
    "hexstrike_sqlmap",
    "hexstrike_checksec",
    "hexstrike_anew",
}

_ROLE_BASE_TOOL_NAMES: Dict[str, Set[str]] = {
    "report": _REPORT_TOOL_NAMES,
    "recon": _RECON_TOOL_NAMES,
    "analysis": _ANALYSIS_BASE_TOOL_NAMES,
    "exploit": _ANALYSIS_BASE_TOOL_NAMES | _EXPLOIT_EXTRA_TOOL_NAMES,
}

_DOMAIN_TOOL_NAMES: Dict[str, Set[str]] = {
    "injection": {"hexstrike_nuclei", "hexstrike_ffuf"},
    "xss": {"hexstrike_dalfox"},
    "auth": {"hexstrike_jwt_analyzer"},
    "authz": set(),
    "ssrf": {"hexstrike_nuclei"},
}


def _schema_value(value: Any) -> Dict[str, Any]:
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, list):
        return {"type": "array", "items": {"type": "string"}}
    return {"type": "string"}


def _tool_spec(name: str, description: str, example: Dict[str, Any]) -> Dict[str, Any]:
    properties = {key: _schema_value(value) for key, value in example.items()}
    required = [key for key, value in example.items() if value not in (None, "", [], {})]
    return {
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    }


def get_allowed_oracle_tool_names(*, agent_role: str = "analysis", analysis_domain: str | None = None) -> List[str]:
    role = str(agent_role or "analysis").strip().lower()
    domain = str(analysis_domain or "").strip().lower()
    if role not in _ROLE_BASE_TOOL_NAMES:
        role = "analysis"

    allowed = set(_ROLE_BASE_TOOL_NAMES[role])
    if role in {"analysis", "exploit"}:
        allowed.update(_DOMAIN_TOOL_NAMES.get(domain, set()))

    present = [name for name in _TOOLS_BY_NAME if name in allowed]
    return present


def get_oracle_tools(*, agent_role: str = "analysis", analysis_domain: str | None = None) -> List[Dict[str, Any]]:
    specs: List[Dict[str, Any]] = []
    for tool_name in get_allowed_oracle_tool_names(agent_role=agent_role, analysis_domain=analysis_domain):
        tool = _TOOLS_BY_NAME[tool_name]
        specs.append(_tool_spec(tool["name"], tool["description"], tool["example"]))
    return specs

"""
Tool definitions for Chimera autonomous agents.

Each tool is a dict conforming to the OpenAI/Anthropic function-calling schema.
The AgentLoop passes these to the LLM, and the ToolExecutor runs the selected
tool when the LLM invokes it.
"""
from __future__ import annotations

from typing import Any, Dict, List


# ── Tool Schema ──────────────────────────────────────────────────────────────
# These are the tools available to every agent.  The ToolExecutor is responsible
# for actually running them; these dicts are just the descriptions the LLM sees.

AGENT_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "http_request",
        "description": (
            "Send an HTTP request to a target URL within scope.  "
            "Returns the status code, response headers, and body (truncated to 8KB).  "
            "Use this for API probing, authentication testing, and exploit delivery."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
                    "description": "HTTP method",
                },
                "url": {
                    "type": "string",
                    "description": "Absolute URL to request (must be in scope)",
                },
                "headers": {
                    "type": "object",
                    "description": "Additional HTTP headers as key-value pairs",
                    "additionalProperties": {"type": "string"},
                },
                "body": {
                    "type": "string",
                    "description": "Request body (for POST/PUT/PATCH).  JSON string or form data.",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "description": "Whether to follow HTTP redirects (default: true)",
                },
            },
            "required": ["method", "url"],
        },
    },
    {
        "name": "browser_navigate",
        "description": (
            "Navigate a headless Chrome browser to a URL and return the rendered page content.  "
            "Useful for JavaScript-heavy applications, SPAs, and extracting client-side rendered data.  "
            "Also captures the network request log (API calls made by the page)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to navigate to (must be in scope)",
                },
                "wait_for": {
                    "type": "string",
                    "enum": ["load", "domcontentloaded", "networkidle"],
                    "description": "Wait condition before extracting content (default: networkidle)",
                },
                "extract_selectors": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "CSS selectors to extract text from (returns inner text of each match)",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "browser_interact",
        "description": (
            "Interact with a page in the headless browser: fill form fields, click buttons, "
            "and capture the resulting response.  Use for login flows, form submissions, and "
            "multi-step interactions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to navigate to first (must be in scope)",
                },
                "actions": {
                    "type": "array",
                    "description": "Sequence of actions to perform (fill, click, wait)",
                    "items": {
                        "type": "object",
                        "properties": {
                            "action": {
                                "type": "string",
                                "enum": ["fill", "click", "wait"],
                            },
                            "selector": {
                                "type": "string",
                                "description": "CSS selector for the target element",
                            },
                            "value": {
                                "type": "string",
                                "description": "Value to fill (for 'fill' action)",
                            },
                            "wait_ms": {
                                "type": "integer",
                                "description": "Milliseconds to wait (for 'wait' action)",
                            },
                        },
                        "required": ["action"],
                    },
                },
            },
            "required": ["url", "actions"],
        },
    },
    {
        "name": "browser_fill_submit",
        "description": (
            "Navigate to a page, fill a set of form fields, submit the form, and return the resulting response.  "
            "Use this for login flows and simple form-based workflows."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to navigate to first (must be in scope)",
                },
                "fields": {
                    "type": "object",
                    "description": "CSS selector to value map for fields to fill",
                    "additionalProperties": {"type": "string"},
                },
                "submit_selector": {
                    "type": "string",
                    "description": "CSS selector for the submit button or form submit control",
                },
            },
            "required": ["url", "fields", "submit_selector"],
        },
    },
    {
        "name": "read_source_file",
        "description": (
            "Read a file from the target application's source code repository.  "
            "Only available in white-box mode when a repo_path is configured.  "
            "Use to understand server-side logic, find SQL queries, identify auth middleware, etc."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path in the repository (e.g. 'routes/login.ts')",
                },
                "start_line": {
                    "type": "integer",
                    "description": "First line to read (1-indexed, inclusive).  Omit to read from start.",
                },
                "end_line": {
                    "type": "integer",
                    "description": "Last line to read (1-indexed, inclusive).  Omit to read to end.  Max 200 lines.",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_source_code",
        "description": (
            "Search the target source code for a text pattern or regex.  "
            "Returns matching file paths with line numbers and snippets.  "
            "Use to find SQL queries, dangerous functions, hardcoded secrets, route definitions, etc."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Search pattern (literal string or regex)",
                },
                "file_glob": {
                    "type": "string",
                    "description": "Glob pattern to filter files (default: '**/*')",
                },
                "is_regex": {
                    "type": "boolean",
                    "description": "Whether to treat pattern as regex (default: false)",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of matches to return (default: 20)",
                },
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "list_source_files",
        "description": (
            "List files and directories in the target source repository.  "
            "Use to understand the project structure before reading specific files."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "directory": {
                    "type": "string",
                    "description": "Directory to list (relative to repo root, default: '.')",
                },
                "glob": {
                    "type": "string",
                    "description": "Glob pattern to filter results (e.g. '*.ts', '**/*.py')",
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum directory depth to traverse (default: 3)",
                },
            },
        },
    },
    {
        "name": "report_finding",
        "description": (
            "Report a CONFIRMED vulnerability with proof-of-concept evidence.  "
            "Only call this when you have successfully exploited a vulnerability and can "
            "provide a working PoC.  Do NOT report theoretical issues or hypotheses — "
            "only proven vulnerabilities with concrete evidence.\n\n"
            "Your evidence should include the exact HTTP request/response or browser actions "
            "that demonstrate the vulnerability."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short, descriptive title (e.g. 'SQL Injection in /rest/user/login')",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "CVSS-aligned severity",
                },
                "vuln_type": {
                    "type": "string",
                    "description": "Vulnerability class (e.g. 'sqli', 'xss', 'idor', 'auth_bypass')",
                },
                "affected_endpoint": {
                    "type": "string",
                    "description": "The specific URL or endpoint affected",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the vulnerability and its impact",
                },
                "poc_steps": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Step-by-step reproduction instructions.  Each step should be a "
                        "concrete action (e.g. 'Send POST to /api/login with body: ...')."
                    ),
                },
                "evidence": {
                    "type": "string",
                    "description": (
                        "Raw evidence proving the vulnerability: HTTP response bodies, "
                        "extracted data, error messages, etc."
                    ),
                },
                "curl_command": {
                    "type": "string",
                    "description": "A curl command that reproduces the exploit (optional but preferred)",
                },
            },
            "required": ["title", "severity", "vuln_type", "affected_endpoint", "description", "poc_steps", "evidence"],
        },
    },
]


def get_tools_for_role(role: str, has_source_code: bool = False) -> List[Dict[str, Any]]:
    """
    Return the subset of tools appropriate for an agent role.

    - recon: http_request, browser_navigate, source tools, report_finding
    - analysis: all tools
    - exploit: all tools
    - report: report_finding only (consumes prior findings, doesn't probe)
    """
    source_tools = {"read_source_file", "search_source_code", "list_source_files"}
    browser_tools = {"browser_navigate", "browser_interact", "browser_fill_submit"}

    if role == "report":
        return [t for t in AGENT_TOOLS if t["name"] == "report_finding"]

    tools = list(AGENT_TOOLS)

    # Remove source code tools if no repo is mounted
    if not has_source_code:
        tools = [t for t in tools if t["name"] not in source_tools]

    return tools

"""
Shannon Security Gateway — minimal FastAPI service for AI-powered security
verification at the end of the Chimera pipeline.

It preserves the narrow Chimera contract while allowing multiple LLM backends:
- Anthropic Messages API
- OpenAI-compatible chat completion endpoints (vLLM, TGI gateways, Ollama, etc.)

For the openai_compatible provider, Shannon runs a sequential 3-model reasoning
chain: Planner (qwen2.5-coder:7b) → Executor (qwen2.5-coder:7b) → Validator (qwen2.5-coder:7b).
Models are loaded one at a time in Ollama (OLLAMA_KEEP_ALIVE=30s) so peak VRAM
stays at ~5.5 GB, well within the RTX 5070's 12 GB budget.

API contract (matches chimera_core/adapters/shannon_adapter.py):
  GET  /health
  POST /api/v1/tasks   {"query": "...", "session_id": "..."}  → {"task_id": "..."}
  GET  /api/v1/tasks/{task_id}                                → {"status": "...", "findings": [...]}
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import subprocess
import uuid
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import anthropic
import httpx as _httpx
from fastapi import FastAPI, HTTPException
from openai import AsyncOpenAI
from pydantic import BaseModel
from candidate_extractor import extract_candidates_from_tool_results
from browser_mediator import ChimeraBrowserMediator
from terminal_mediator import ChimeraTerminalMediator
from openai_responses import run_responses_tool_loop
from tool_registry import get_allowed_oracle_tool_names, get_oracle_tools

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Shannon Security Gateway")

AGENT_REQUEST_SCHEMA = "shannon.agent_request.v1"
AGENT_RESULT_SCHEMA = "shannon.agent_result.v1"

# In-memory task store (single-process, sufficient for the Chimera use case)
_tasks: Dict[str, Dict[str, Any]] = {}
BROWSER_TOOL_EXECUTOR = None


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"true", "1", "yes", "on"}


@dataclass(frozen=True)
class _LocalToolSpec:
    route: str
    description: str
    example: Dict[str, Any]


@dataclass(frozen=True)
class _LocalScopeGraph:
    allowed_domains: List[str]


@dataclass(frozen=True)
class _ProviderPreset:
    name: str
    family: str
    default_model: str
    default_base_url: str
    api_key_env: str
    default_api_key: str = ""


_LOCAL_HEXSTRIKE_CATALOG: Dict[str, _LocalToolSpec] = {
    "recon": _LocalToolSpec(
        route="/api/recon",
        description="Run lightweight reconnaissance for a target host or URL.",
        example={"target": "https://example.com", "passive_only": True},
    ),
    "endpoints": _LocalToolSpec(
        route="/api/endpoints",
        description="Discover likely endpoints for a target application.",
        example={"target": "https://example.com"},
    ),
    "attack_surface": _LocalToolSpec(
        route="/api/attack-surface",
        description="Summarize the attack surface for a target URL or host.",
        example={"target": "https://example.com", "findings": []},
    ),
    "exploit": _LocalToolSpec(
        route="/api/exploit",
        description="Return exploit guidance for a concrete vulnerability class.",
        example={"vuln_type": "open_redirect", "target": "https://example.com/login", "context": "redirect parameter reflects attacker URL"},
    ),
    "probe": _LocalToolSpec(
        route="/api/probe",
        description="Run a bounded probe against a specific target URL.",
        example={"endpoint": "https://example.com/login", "method": "GET", "token": ""},
    ),
    "httpx": _LocalToolSpec(
        route="/api/tools/httpx",
        description="HTTP probe for status, headers, and title collection.",
        example={"targets": "https://example.com", "additional_args": "-title -status-code"},
    ),
    "nmap": _LocalToolSpec(
        route="/api/tools/nmap",
        description="Port and service fingerprinting.",
        example={"target": "example.com", "scan_type": "-sCV", "ports": "80,443,8080"},
    ),
    "masscan": _LocalToolSpec(
        route="/api/tools/masscan",
        description="Fast port scanning for exposed services.",
        example={"target": "example.com", "ports": "80,443,8080", "rate": "1000"},
    ),
    "nuclei": _LocalToolSpec(
        route="/api/tools/nuclei",
        description="Run nuclei templates against a scoped target.",
        example={"target": "https://example.com", "tags": "sqli", "severity": "high,critical"},
    ),
    "nikto": _LocalToolSpec(
        route="/api/tools/nikto",
        description="Web server misconfiguration checks.",
        example={"target": "https://example.com"},
    ),
    "katana": _LocalToolSpec(
        route="/api/tools/katana",
        description="Crawl a target for URLs and application paths.",
        example={"url": "https://example.com", "depth": 3},
    ),
    "gobuster": _LocalToolSpec(
        route="/api/tools/gobuster",
        description="Directory and path brute forcing.",
        example={"url": "https://example.com", "mode": "dir", "wordlist": "/usr/share/wordlists/dirb/common.txt"},
    ),
    "ffuf": _LocalToolSpec(
        route="/api/tools/ffuf",
        description="Fast fuzzing for files, params, or vhosts.",
        example={"url": "https://example.com/FUZZ", "additional_args": "-mc 200,301,302 -t 40"},
    ),
    "dalfox": _LocalToolSpec(
        route="/api/tools/dalfox",
        description="Run Dalfox against a single target URL.",
        example={"url": "https://example.com/search?q=test", "additional_args": "--silence --no-color"},
    ),
    "subfinder": _LocalToolSpec(
        route="/api/tools/subfinder",
        description="Subdomain discovery.",
        example={"domain": "example.com"},
    ),
    "waybackurls": _LocalToolSpec(
        route="/api/tools/waybackurls",
        description="Historical URL collection from archives.",
        example={"domain": "example.com"},
    ),
    "gau": _LocalToolSpec(
        route="/api/tools/gau",
        description="Gather archived URLs from multiple sources.",
        example={"domain": "example.com"},
    ),
    "curl": _LocalToolSpec(
        route="/api/tools/curl",
        description="Flexible HTTP requests for precise request replay.",
        example={"url": "https://example.com/login", "additional_args": "-i -s"},
    ),
    "sqlmap": _LocalToolSpec(
        route="/api/tools/sqlmap",
        description="SQL injection verification and exploitation guidance.",
        example={"url": "https://example.com/login", "data": "username=test&password=test", "additional_args": "--batch --level=2"},
    ),
    "jwt_analyzer": _LocalToolSpec(
        route="/api/tools/jwt_analyzer",
        description="JWT structure and algorithm inspection.",
        example={"token": "JWT_STRING"},
    ),
    "checksec": _LocalToolSpec(
        route="/api/tools/checksec",
        description="Binary hardening inspection for a provided file path.",
        example={"file_path": "/bin/ls", "additional_args": "--format=json"},
    ),
    "anew": _LocalToolSpec(
        route="/api/tools/anew",
        description="Append unique lines to a file or de-duplicate supplied input.",
        example={"output_file": "/tmp/targets.txt", "input_lines": "https://example.com\nhttps://api.example.com"},
    ),
    "wpscan": _LocalToolSpec(
        route="/api/tools/wpscan",
        description="WordPress vulnerability and user enumeration checks.",
        example={"url": "https://example.com", "additional_args": "--enumerate u,p,t --detection-mode aggressive"},
    ),
}


def get_agent_tool_catalog(agent: str) -> Dict[str, _LocalToolSpec]:
    if agent != "shannon_executor":
        return {}
    return dict(_LOCAL_HEXSTRIKE_CATALOG)


def render_tool_prompt(agent: str) -> str:
    lines = [
        "Available HexStrike tools for this role:",
    ]
    for name, spec in get_agent_tool_catalog(agent).items():
        lines.append(
            f'- {name}: {spec.description} Example: <hexstrike_call>{json.dumps({"tool": name, **spec.example})}</hexstrike_call>'
        )
    return "\n".join(lines)


def extract_targets_from_text(text: str) -> List[str]:
    pattern = re.compile(r"https?://[^\s\"'<>]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
    seen: List[str] = []
    for match in pattern.findall(text or ""):
        normalized = match.rstrip(".,)")
        if normalized not in seen:
            seen.append(normalized)
    return seen


def extract_targets_from_command(command: List[str]) -> List[str]:
    seen: List[str] = []
    common_tlds = {"com", "org", "net", "edu", "gov", "io", "co", "us", "uk", "dev", "app", "xyz", "me"}
    for arg in command[1:]:
        if not isinstance(arg, str):
            continue
        stripped = arg.strip()
        candidates: List[str] = []
        if stripped.startswith(("http://", "https://")):
            candidates.append(stripped)
        else:
            try:
                ipaddress.ip_address(stripped)
                candidates.append(stripped)
            except ValueError:
                for target in extract_targets_from_text(arg):
                    lowered = target.lower()
                    if lowered.startswith(("http://", "https://")):
                        candidates.append(target)
                        continue
                    parts = lowered.split(".")
                    if len(parts) >= 2 and parts[-1] in common_tlds:
                        candidates.append(target)
        for target in candidates:
            if target not in seen:
                seen.append(target)
    return seen


class HexStrikePolicy:
    def __init__(self, allow_dangerous: bool = False) -> None:
        self.allow_dangerous = allow_dangerous
        self._dangerous_tools = {"sqlmap", "command"}

    def validate_call(
        self,
        *,
        agent: str,
        tool_name: str,
        params: Dict[str, Any],
        scope_graph: "_LocalScopeGraph",
    ) -> None:
        if agent != "shannon_executor":
            raise ValueError(f"unsupported agent: {agent}")
        if tool_name not in get_agent_tool_catalog(agent):
            raise ValueError(f"unsupported tool: {tool_name}")
        if not self.allow_dangerous and tool_name in self._dangerous_tools:
            raise ValueError(f"dangerous tool blocked: {tool_name}")
        allowed = {domain.lower() for domain in scope_graph.allowed_domains}
        targets = extract_targets_from_text(json.dumps(params))
        for target in targets:
            lowered = target.lower()
            if lowered.startswith("http://") or lowered.startswith("https://"):
                host = lowered.split("://", 1)[1].split("/", 1)[0]
            else:
                host = lowered
            if allowed and all(host != domain and not host.endswith(f".{domain}") for domain in allowed):
                raise ValueError(f"out of scope target: {target}")

PROVIDER = (os.getenv("SHANNON_PROVIDER") or "anthropic").strip().lower().replace("-", "_")
if PROVIDER == "openai":
    PROVIDER = "openai_compatible"

# Keep MODEL for Anthropic provider path
MODEL = (
    os.getenv("SHANNON_MODEL")
    or (
        "claude-sonnet-4-6"
        if PROVIDER == "anthropic"
        else "qwen2.5-coder:7b"
    )
).strip()

# 3-stage chain models (openai_compatible provider only)
PLANNER_MODEL   = os.getenv("SHANNON_PLANNER_MODEL",   "qwen2.5-coder:7b")
EXECUTOR_MODEL  = os.getenv("SHANNON_EXECUTOR_MODEL",  "qwen2.5-coder:7b")
VALIDATOR_MODEL = os.getenv("SHANNON_VALIDATOR_MODEL", "qwen2.5-coder:7b")

MAX_TOKENS = int(os.getenv("SHANNON_MAX_TOKENS") or "8096")
TEMPERATURE = float(os.getenv("SHANNON_TEMPERATURE") or "0.1")
PLANNER_TEMPERATURE   = float(os.getenv("SHANNON_PLANNER_TEMPERATURE",   "0.0"))
EXECUTOR_TEMPERATURE  = float(os.getenv("SHANNON_EXECUTOR_TEMPERATURE",  "0.1"))
VALIDATOR_TEMPERATURE = float(os.getenv("SHANNON_VALIDATOR_TEMPERATURE", "0.0"))
ORACLE_ENABLED = _env_bool("SHANNON_ORACLE_ENABLED", True)
ORACLE_PROVIDER = (os.getenv("SHANNON_ORACLE_PROVIDER") or "openai").strip().lower()
ORACLE_MODEL = (os.getenv("SHANNON_ORACLE_MODEL") or "gpt-5.4").strip()
ORACLE_REASONING = (os.getenv("SHANNON_ORACLE_REASONING") or "medium").strip().lower()
ORACLE_MAX_TURNS = int(os.getenv("SHANNON_ORACLE_MAX_TURNS", "6"))
ORACLE_MAX_TOOL_CALLS = int(os.getenv("SHANNON_ORACLE_MAX_TOOL_CALLS", "12"))
ORACLE_MAX_RETRIES = int(os.getenv("SHANNON_ORACLE_MAX_RETRIES", "2"))
AGENT_ARTIFACT_ROOT = Path(os.getenv("SHANNON_AGENT_ARTIFACT_ROOT", "/tmp/shannon_agent"))
AGENT_TASK_ROOT = AGENT_ARTIFACT_ROOT / "tasks"
CHIMERA_ARTIFACTS_ROOT = Path(os.getenv("CHIMERA_ARTIFACTS_ROOT", str(AGENT_ARTIFACT_ROOT)))
SOURCE_REPO_ROOT = os.getenv("SHANNON_SOURCE_REPO_ROOT")
ANTHROPIC_PROMPT_CACHING = _env_bool("SHANNON_ANTHROPIC_PROMPT_CACHING", True)
ANTHROPIC_PROMPT_CACHE_TTL = (os.getenv("SHANNON_ANTHROPIC_CACHE_TTL") or "5m").strip().lower()
LOCAL_LLM_MAX_TOKENS = int(os.getenv("LOCAL_LLM_MAX_MODEL_LEN", "8096"))
CONTEXT_HEADROOM = 512  # reserve chars for system prompt overhead
LOCAL_HYPOTHESIS_ENABLED = _env_bool("SHANNON_LOCAL_HYPOTHESIS_ENABLED", True)
LOCAL_HYPOTHESIS_MAX_FINDINGS = int(os.getenv("SHANNON_LOCAL_HYPOTHESIS_MAX_FINDINGS", "8"))
LOCAL_HYPOTHESIS_MAX_CHECKS = int(os.getenv("SHANNON_LOCAL_HYPOTHESIS_MAX_CHECKS", "6"))
LOCAL_HYPOTHESIS_ORACLE_LIMIT = int(os.getenv("SHANNON_LOCAL_HYPOTHESIS_ORACLE_LIMIT", "4"))
BROWSER_TOOL_HEADLESS = _env_bool("SHANNON_BROWSER_HEADLESS", True)
BROWSER_TOOL_DEVTOOLS = _env_bool("SHANNON_BROWSER_DEVTOOLS", False)
BROWSER_TOOL_SLOW_MO_MS = int(os.getenv("SHANNON_BROWSER_SLOW_MO_MS", "0"))
BROWSER_EXECUTOR_MODE = (os.getenv("SHANNON_BROWSER_EXECUTOR_MODE") or "direct").strip().lower()
CHIMERA_CORE_URL = (os.getenv("CHIMERA_CORE_URL") or "http://chimera-core:8000").rstrip("/")
OPENAI_BASE_URL = (os.getenv("SHANNON_OPENAI_BASE_URL") or "http://sec-llm:8000/v1").rstrip("/")
OPENAI_API_KEY = (
    os.getenv("SHANNON_OPENAI_API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or "dummy"
)
PROMPT_DIR = Path(os.getenv("SHANNON_PROMPT_DIR", str(Path(__file__).resolve().parent / "prompts")))
AGENT_COMPACTION_THRESHOLD = int(os.getenv("SHANNON_AGENT_COMPACTION_THRESHOLD", "6"))
AGENT_COMPACTION_KEEP_RECENT = int(os.getenv("SHANNON_AGENT_COMPACTION_KEEP_RECENT", "2"))

_PROVIDER_PRESETS: Dict[str, _ProviderPreset] = {
    "anthropic": _ProviderPreset(
        name="anthropic",
        family="anthropic",
        default_model="claude-sonnet-4-20250514",
        default_base_url="https://api.anthropic.com/v1",
        api_key_env="ANTHROPIC_API_KEY",
    ),
    "openai": _ProviderPreset(
        name="openai",
        family="openai_compatible",
        default_model="gpt-5.4",
        default_base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
    ),
    "openai_compatible": _ProviderPreset(
        name="openai_compatible",
        family="openai_compatible",
        default_model="qwen2.5-coder:7b",
        default_base_url=OPENAI_BASE_URL,
        api_key_env="SHANNON_OPENAI_API_KEY",
        default_api_key="dummy",
    ),
    "nvidia_nim": _ProviderPreset(
        name="nvidia_nim",
        family="openai_compatible",
        default_model="meta/llama-4-maverick-17b-128e-instruct",
        default_base_url="https://integrate.api.nvidia.com/v1",
        api_key_env="NVIDIA_API_KEY",
    ),
    "ollama": _ProviderPreset(
        name="ollama",
        family="openai_compatible",
        default_model="qwen2.5-coder:7b",
        default_base_url="http://ollama:11434/v1",
        api_key_env="SHANNON_OPENAI_API_KEY",
        default_api_key="ollama",
    ),
}


def _normalize_provider_preset(name: str) -> str:
    preset = (name or "openai").strip().lower().replace("-", "_")
    if preset not in _PROVIDER_PRESETS:
        if preset == "openai_compat":
            return "openai_compatible"
        if preset == "nim":
            return "nvidia_nim"
        raise ValueError(f"unsupported provider preset: {name}")
    return preset


def _resolve_provider_runtime(
    preset_name: str,
    *,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    max_turns: Optional[int] = None,
    prefer_preset_defaults: bool = False,
) -> Dict[str, Any]:
    preset = _PROVIDER_PRESETS[_normalize_provider_preset(preset_name)]
    if prefer_preset_defaults:
        resolved_base_url = (base_url or preset.default_base_url).rstrip("/")
        resolved_api_key = (
            api_key
            or os.getenv(preset.api_key_env)
            or preset.default_api_key
        )
        resolved_model = (model or preset.default_model).strip()
    else:
        resolved_base_url = (base_url or os.getenv("SHANNON_ORACLE_BASE_URL") or preset.default_base_url).rstrip("/")
        resolved_api_key = (
            api_key
            or os.getenv(preset.api_key_env)
            or os.getenv("SHANNON_ORACLE_API_KEY")
            or (OPENAI_API_KEY if preset.family == "openai_compatible" else "")
            or preset.default_api_key
        )
        resolved_model = (model or os.getenv("SHANNON_ORACLE_MODEL") or preset.default_model).strip()
    if preset.name == "ollama" and not resolved_api_key:
        resolved_api_key = "ollama"
    return {
        "preset": preset.name,
        "family": preset.family,
        "model": resolved_model,
        "base_url": resolved_base_url,
        "api_key": resolved_api_key,
        "max_turns": int(max_turns or os.getenv("SHANNON_ORACLE_MAX_TURNS") or ORACLE_MAX_TURNS),
        "prompt_caching": bool(ANTHROPIC_PROMPT_CACHING and preset.family == "anthropic"),
        "prompt_cache_ttl": ANTHROPIC_PROMPT_CACHE_TTL if preset.family == "anthropic" else None,
    }


ORACLE_PROVIDER_PRESET = _normalize_provider_preset(ORACLE_PROVIDER)
ORACLE_RUNTIME = _resolve_provider_runtime(ORACLE_PROVIDER_PRESET, max_turns=ORACLE_MAX_TURNS)
ORACLE_BASE_URL = ORACLE_RUNTIME["base_url"]
ORACLE_API_KEY = ORACLE_RUNTIME["api_key"]
ORACLE_MODEL = ORACLE_RUNTIME["model"]

# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

# Used for Anthropic provider (single-call path)
SYSTEM_PROMPT = """You are an expert penetration tester performing the final verification pass in an automated security pipeline.

You will receive:
- Target URL(s)
- Optionally: prior findings from automated tools (strix crawler, browser DOM analysis, etc.)
- Vulnerability categories to check

Your job:
1. Verify and enrich each prior finding — confirm severity, add precise repro steps
2. Look for exploit chains (e.g. IDOR + weak auth = full account takeover)
3. Identify high-value issues the automated tools typically miss (business logic, auth flow, privilege escalation)
4. Provide proof-of-exploit steps that a pentester can execute immediately

Return ONLY a valid JSON object — no markdown, no explanation, no code blocks:
{
  "findings": [
    {
      "title": "Short descriptive title",
      "description": "What the vulnerability is and why it matters",
      "severity": "critical|high|medium|low",
      "target": "affected URL",
      "method": "GET|POST|PUT|DELETE or null",
      "parameter": "vulnerable parameter name or null",
      "repro_guidance": "Step-by-step proof of exploit"
    }
  ]
}

If nothing actionable is found, return: {"findings": []}"""

PLANNER_SYSTEM_PROMPT = """You are a security assessment planner. Your ONLY job is to produce a MINIMAL, TARGETED list of checks grounded in prior tool findings or the target description.

CRITICAL RULES:
1. ONLY generate checks for endpoints, parameters, or behaviours explicitly mentioned in the prior findings or the target description.
2. If there are NO prior findings and NO concrete endpoints in the description, return exactly: {"attack_classes": [], "checks": [], "context_notes": "no prior evidence — no checks generated"}
3. DO NOT invent endpoints, parameters, or guessed paths (no /admin, /search, /user/profile unless they appear in evidence).
4. Generate at most 5 checks. Prioritise the highest-impact and most-specific ones.
5. Each check MUST include an "evidence_basis" field quoting the prior finding or description text that justifies it.

Return ONLY this JSON schema — no markdown, no explanation:
{
  "attack_classes": ["SQLi","XSS","IDOR","broken_auth"],
  "checks": [
    {
      "id": "c1",
      "class": "<attack_class>",
      "target": "<EXACT endpoint or component from evidence, e.g. https://example.com/login?redirect=>",
      "what_to_test": "<specific payload or condition to probe>",
      "expected_vulnerability": "<what a positive result looks like>",
      "evidence_basis": "<direct quote from prior findings that justifies this check>"
    }
  ],
  "context_notes": "<relevant app-specific context from the prior findings>"
}"""

EXECUTOR_SYSTEM_PROMPT = """You are a security analyst. You receive an attack plan, prior findings from automated tools, and active probe results collected by HexStrike.

Your job: analyse each probe result and determine whether it constitutes evidence of a real vulnerability.

STRICT RULES:
1. ONLY report a finding when the probe_results for that check contain concrete evidence (e.g. HTTP 200 on an auth-required endpoint, XSS payload reflected in response, SQL error message, etc.).
2. Every finding's "target" must be the exact URL that was probed — never "unknown".
3. "description" must quote specific evidence from the probe output (status code, snippet, header, etc.).
4. "repro_guidance" must be actionable steps a pentester can follow to reproduce what the probe showed.
5. If probe_results are empty, timed-out, or show no evidence: {"findings": []}

Return ONLY valid JSON — no markdown, no explanation:
{
  "findings": [
    {
      "title": "Short descriptive title",
      "description": "Concrete evidence from probe: <quote from probe output>",
      "severity": "critical|high|medium|low",
      "target": "<exact probed URL>",
      "method": "GET|POST|PUT|DELETE or null",
      "parameter": "vulnerable parameter name or null",
      "repro_guidance": "Numbered steps based on the probe evidence"
    }
  ]
}"""

VALIDATOR_SYSTEM_PROMPT = """You are a senior penetration testing lead. Review a set of raw findings and:
1. DEDUPLICATE: Merge findings describing the same vulnerability. Keep the more detailed version.
2. SEVERITY: Assign accurate severity — critical=RCE/full auth bypass, high=IDOR with data/stored XSS, medium=reflected XSS/partial IDOR, low=info disclosure.
3. CHAINS: If two findings together produce a higher-impact attack, add one combined finding with escalated severity (e.g. IDOR + weak session = account takeover → critical).
4. REMOVE any finding with vague or implausible repro steps.

Return the same findings JSON schema. No markdown. No explanation. Only valid JSON."""

REPAIR_PROMPT = (
    "Your previous response was not valid JSON. "
    "Return ONLY a JSON object matching this schema — no markdown, no explanation:\n"
    '{"findings": [{"title": "...", "severity": "critical|high|medium|low", '
    '"target": "...", "description": "...", "repro_guidance": "..."}]}\n'
    "If nothing was found, return exactly: {\"findings\": []}"
)


def _default_agent_role(req: "AgentRequest") -> str:
    if req.agent_role:
        return str(req.agent_role).lower()
    lowered_mode = str(req.mode or "").lower()
    if lowered_mode == "report":
        return "report"
    if lowered_mode == "exploit":
        return "exploit"
    if lowered_mode == "recon":
        return "recon"
    return "analysis"


def _prompt_filename_for_request(req: "AgentRequest") -> str:
    role = _default_agent_role(req)
    if role in {"analysis", "exploit"}:
        domain = str(req.analysis_domain or "").strip().lower()
        if domain:
            return f"{domain}.txt"
    if role == "report":
        return "report.txt"
    if role == "recon":
        return "recon.txt"
    return "recon.txt"


def _load_role_prompt(req: "AgentRequest") -> str:
    prompt_path = PROMPT_DIR / _prompt_filename_for_request(req)
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8").strip()
    role = _default_agent_role(req)
    if role == "report":
        return "You are Shannon's reporting agent. Produce concise, evidence-grounded summaries only."
    if role == "recon":
        return "You are Shannon's reconnaissance agent. Map reachable attack surface and prioritize likely security pivots."
    return "You are Shannon's specialist analysis agent. Verify hypotheses with tool evidence and avoid unsupported claims."


def _scope_summary_text(scope_summary: dict, targets: List[str]) -> str:
    allowlist = list(scope_summary.get("allowlist") or targets)
    denylist = list(scope_summary.get("denylist") or [])
    allowed_methods = list(scope_summary.get("allowed_methods") or [])
    lines = ["Scope Summary:"]
    if allowlist:
        lines.append("Allowlist:")
        lines.extend(f"- {entry}" for entry in allowlist)
    if denylist:
        lines.append("Denylist:")
        lines.extend(f"- {entry}" for entry in denylist)
    if allowed_methods:
        lines.append(f"Allowed methods: {', '.join(allowed_methods)}")
    return "\n".join(lines)


def _compact_record_lines(title: str, records: List[Dict[str, Any]], *, max_items: int = 6) -> List[str]:
    lines = [f"{title}:"]
    if not records:
        lines.append("- none")
        return lines
    for item in records[:max_items]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("title") or item.get("name") or item.get("claim_type") or "item")
        target = str(item.get("affected_target") or item.get("target") or item.get("endpoint") or "")
        severity = str(item.get("severity") or item.get("severity_claimed") or "").lower()
        snippet = str(item.get("description") or item.get("success_condition") or "")[:220]
        parts = [name]
        if severity:
            parts.append(f"severity={severity}")
        if target:
            parts.append(f"target={target}")
        if snippet:
            parts.append(f"note={snippet}")
        lines.append("- " + " | ".join(parts))
    if len(records) > max_items:
        lines.append(f"- ... {len(records) - max_items} more")
    return lines

# ── HexStrike tool integration ────────────────────────────────────────────

HEXSTRIKE_BASE_URL = os.getenv("HEXSTRIKE_BASE_URL", "http://hexstrike:8888").rstrip("/")
HEXSTRIKE_ENABLED = os.getenv("HEXSTRIKE_ENABLED", "true").lower() == "true"
HEXSTRIKE_MAX_TOOL_TURNS = int(os.getenv("HEXSTRIKE_MAX_TOOL_TURNS", "3"))

SUPPORTED_HEXSTRIKE_TOOLS: Dict[str, Dict[str, Any]] = {
    name: {
        "path": spec.route,
        "example": spec.example,
        "description": spec.description,
    }
    for name, spec in get_agent_tool_catalog("shannon_executor").items()
}

# Regex to extract <hexstrike_call>...</hexstrike_call> blocks from executor output
_HEXSTRIKE_CALL_RE = re.compile(
    r"<hexstrike_call>\s*(\{.*?\})\s*</hexstrike_call>",
    re.DOTALL,
)

HEXSTRIKE_TOOLS_PROMPT = render_tool_prompt("shannon_executor")

EXECUTOR_WITH_TOOLS_SYSTEM_PROMPT = EXECUTOR_SYSTEM_PROMPT.rstrip() + "\n" + HEXSTRIKE_TOOLS_PROMPT


def _scope_graph_for_executor_input(executor_input: str) -> _LocalScopeGraph:
    targets = extract_targets_from_text(executor_input)
    domains: List[str] = []
    for target in targets:
        lowered = target.lower()
        if lowered.startswith("http://") or lowered.startswith("https://"):
            host = lowered.split("://", 1)[1].split("/", 1)[0]
        else:
            host = lowered
        if host not in domains:
            domains.append(host)
    return _LocalScopeGraph(allowed_domains=domains)


def _validate_hexstrike_scope(tool_name: str, params: Dict[str, Any], executor_input: str) -> None:
    policy = HexStrikePolicy(allow_dangerous=False)
    scope_graph = _scope_graph_for_executor_input(executor_input)
    policy.validate_call(
        agent="shannon_executor",
        tool_name=tool_name,
        params=params,
        scope_graph=scope_graph,
    )


def _scope_allowlist_from_summary(scope_summary: dict) -> List[str]:
    allowlist = list(scope_summary.get("allowlist") or [])
    normalized: List[str] = []
    for item in allowlist:
        host = _normalize_scope_host(str(item))
        if host and host not in normalized:
            normalized.append(host)
    return normalized


def _normalize_scope_host(value: str) -> str:
    host = value.lower()
    if host.startswith("http://") or host.startswith("https://"):
        host = host.split("://", 1)[1].split("/", 1)[0]
    if host.startswith("[") and "]" in host:
        return host.split("]", 1)[0] + "]"
    return host.split(":", 1)[0]


def _normalize_target_value(value: str) -> str:
    lowered = value.lower().strip()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        parsed = urlparse(lowered)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return f"{host}:{port}" if host else lowered
    host = _normalize_scope_host(lowered)
    if ":" in lowered:
        suffix = lowered.split(":", 1)[1]
        if suffix.isdigit() and host:
            return f"{host}:{suffix}"
    return host


def _target_matches_scope(target: str, allowlist: List[str]) -> bool:
    normalized_target = _normalize_target_value(target)
    target_host = _normalize_scope_host(target)
    for item in allowlist:
        allowed = str(item)
        normalized_allowed = _normalize_target_value(allowed)
        allowed_host = _normalize_scope_host(allowed)
        if normalized_target and normalized_target == normalized_allowed:
            return True
        if target_host and allowed_host and (
            target_host == allowed_host or target_host.endswith(f".{allowed_host}")
        ):
            return True
    return False


def _load_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _compact_prior_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    asset = finding.get("asset") if isinstance(finding.get("asset"), dict) else {}
    return {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "description": str(finding.get("description") or "")[:2400],
        "tool_source": finding.get("tool_source"),
        "tool_version": finding.get("tool_version"),
        "affected_target": finding.get("affected_target"),
        "evidence_refs": list(finding.get("evidence_refs") or [])[:10],
        "repro_guidance": finding.get("repro_guidance"),
        "validation_status": finding.get("validation_status"),
        "validation_reason": finding.get("validation_reason"),
        "confidence": finding.get("confidence"),
        "finding_type": finding.get("finding_type"),
        "asset": {
            "host": asset.get("host"),
            "endpoint": asset.get("endpoint"),
            "method": asset.get("method"),
            "parameter": asset.get("parameter"),
        },
    }


def _load_findings_from_run_dir(run_dir: Path) -> List[Dict[str, Any]]:
    candidate_paths: List[Path] = []
    root_findings = run_dir / "findings.json"
    if root_findings.exists():
        candidate_paths.append(root_findings)
    candidate_paths.extend(sorted(run_dir.glob("strix/*/findings.json")))
    candidate_paths.extend(sorted(run_dir.glob("browser/*/findings.json")))
    candidate_paths.extend(sorted(run_dir.glob("shannon/*/findings.json")))
    candidate_paths.extend(sorted(run_dir.glob("shannon/agent/*/local_hypotheses.json")))
    seen_ids: set[str] = set()
    findings: List[Dict[str, Any]] = []
    for path in candidate_paths:
        try:
            payload = _load_json_file(path)
        except Exception:
            continue
        if not isinstance(payload, list):
            continue
        for finding in payload:
            if not isinstance(finding, dict):
                continue
            finding_id = str(finding.get("finding_id") or f"{path}:{len(findings)}")
            if finding_id in seen_ids:
                continue
            seen_ids.add(finding_id)
            findings.append(_compact_prior_finding(finding))
    findings.sort(
        key=lambda item: (
            0 if str(item.get("tool_source") or "") == "strix" else 1,
            str(item.get("severity") or ""),
            str(item.get("title") or ""),
        )
    )
    return findings


def _latest_matching_run_dir(targets: List[str]) -> Optional[Path]:
    if not CHIMERA_ARTIFACTS_ROOT.exists():
        return None
    target_list = [target for target in targets if target]
    candidates: List[tuple[int, float, Path]] = []
    for run_dir in CHIMERA_ARTIFACTS_ROOT.iterdir():
        run_file = run_dir / "run.json"
        if not run_file.exists():
            continue
        try:
            run_data = _load_json_file(run_file)
        except Exception:
            continue
        if str(run_data.get("status") or "") != "completed":
            continue
        scope = run_data.get("scope_normalized") if isinstance(run_data.get("scope_normalized"), dict) else {}
        allowlist = list(scope.get("allowlist") or [])
        if target_list and not any(_target_matches_scope(target, allowlist) for target in target_list):
            continue
        findings = _load_findings_from_run_dir(run_dir)
        if not findings:
            continue
        strix_count = sum(1 for finding in findings if str(finding.get("tool_source") or "") == "strix")
        candidates.append((strix_count, run_dir.stat().st_mtime, run_dir))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]


def _resolve_prior_context(req: "AgentRequest") -> Dict[str, Any]:
    if req.prior_findings:
        evidence_refs = list(dict.fromkeys(str(ref) for ref in req.prior_evidence_refs if ref))
        if not evidence_refs:
            for finding in req.prior_findings:
                if isinstance(finding, dict):
                    evidence_refs.extend(str(ref) for ref in finding.get("evidence_refs") or [])
            evidence_refs = list(dict.fromkeys(evidence_refs))
        return {
            "prior_findings": list(req.prior_findings),
            "prior_evidence_refs": evidence_refs,
            "context_run_id": req.run_id,
            "context_source": "request",
        }
    if not req.auto_context:
        return {
            "prior_findings": [],
            "prior_evidence_refs": [],
            "context_run_id": None,
            "context_source": "disabled",
        }
    run_dir = CHIMERA_ARTIFACTS_ROOT / req.run_id
    context_source = "run_id"
    findings = _load_findings_from_run_dir(run_dir) if run_dir.exists() else []
    if not findings:
        run_dir = _latest_matching_run_dir(list(req.targets or []))
        findings = _load_findings_from_run_dir(run_dir) if run_dir is not None else []
        context_source = "latest_target_match" if run_dir is not None else "none"
    evidence_refs = list(
        dict.fromkeys(
            str(ref)
            for finding in findings
            for ref in (finding.get("evidence_refs") or [])
            if ref
        )
    )
    return {
        "prior_findings": findings[:25],
        "prior_evidence_refs": evidence_refs[:50],
        "context_run_id": run_dir.name if run_dir is not None else None,
        "context_source": context_source,
    }


def _ensure_agent_scope(params: Dict[str, Any], scope_summary: dict) -> None:
    allowed = set(_scope_allowlist_from_summary(scope_summary))
    if not allowed:
        return
    for target in extract_targets_from_text(json.dumps(params)):
        host = _normalize_scope_host(target)
        if all(host != domain and not host.endswith(f".{domain}") for domain in allowed):
            raise ValueError(f"out of scope target: {target}")


def _scope_violation_result(exc: Exception, *, target: Any = None) -> dict:
    result = {"error": "scope_violation", "detail": str(exc)}
    if target is not None:
        result["target"] = target
    return result


def _policy_scope_summary(scope_summary: dict) -> dict:
    return {
        "allowlist": list(scope_summary.get("allowlist") or []),
        "denylist": list(scope_summary.get("denylist") or []),
        "allowed_methods": list(scope_summary.get("allowed_methods") or []),
    }


async def _evaluate_policy(
    *,
    tool: str,
    scope_summary: dict,
    target: Optional[str] = None,
    method: Optional[str] = None,
    action_class: str = "passive",
    risk_class: Optional[str] = None,
    command: Optional[List[str]] = None,
    browser_actions: Optional[List[str]] = None,
    has_env_vars: bool = False,
    file_upload: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
) -> dict:
    payload: Dict[str, Any] = {
        "tool": tool,
        "target": target,
        "method": method,
        "action_class": action_class,
        "risk_class": risk_class,
        "command": list(command or []),
        "browser_actions": list(browser_actions or []),
        "has_env_vars": has_env_vars,
        "file_upload": file_upload,
        "scope_summary": _policy_scope_summary(scope_summary),
        "metadata": dict(metadata or {}),
    }
    try:
        async with _httpx.AsyncClient(timeout=10) as client:
            response = await client.post(f"{CHIMERA_CORE_URL}/v1/policy/evaluate", json=payload)
            response.raise_for_status()
            data = response.json()
            decision = dict(data.get("decision") or {})
            if decision:
                return decision
    except Exception as exc:
        logger.warning("Policy evaluation failed for tool=%s target=%s: %s", tool, target, exc)
        return {
            "decision": "deny",
            "reason": f"Policy kernel unavailable: {exc}",
            "matched_rule": "policy_unavailable",
            "require_approval_if_deferred": False,
            "target_scope": "unknown",
        }
    return {
        "decision": "deny",
        "reason": "Policy kernel returned no decision.",
        "matched_rule": "policy_missing",
        "require_approval_if_deferred": False,
        "target_scope": "unknown",
    }


def _policy_block_result(decision: dict, *, target: Any = None) -> dict:
    error = "policy_deferred" if decision.get("decision") == "defer" else "policy_denied"
    result = {
        "error": error,
        "detail": str(decision.get("reason") or "Blocked by policy."),
        "matched_rule": decision.get("matched_rule"),
        "require_approval_if_deferred": bool(decision.get("require_approval_if_deferred", False)),
    }
    if target is not None:
        result["target"] = target
    return result


PROBE_TIMEOUT_S = int(os.getenv("SHANNON_PROBE_TIMEOUT_S", "90"))


async def _hexstrike_call(tool_name: str, params: Dict[str, Any], executor_input: str = "", timeout: int = 300) -> str:
    """Dispatch a single HexStrike tool call and return the result as a string."""
    spec = SUPPORTED_HEXSTRIKE_TOOLS.get(tool_name)
    if not spec:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    try:
        _validate_hexstrike_scope(tool_name, params, executor_input)
    except Exception as exc:
        logger.warning("Blocked out-of-scope or disallowed HexStrike call: tool=%s error=%s", tool_name, exc)
        return json.dumps({"error": "scope_violation", "detail": str(exc)})
    scope_summary = {}
    try:
        scope_summary = json.loads(executor_input) if executor_input else {}
    except Exception:
        scope_summary = {}
    extracted_targets = extract_targets_from_text(json.dumps(params))
    target = extracted_targets[0] if extracted_targets else None
    method = str(params.get("method") or "GET").upper() if isinstance(params, dict) else "GET"
    action_class = "state_changing" if method in {"POST", "PUT", "PATCH", "DELETE"} else "low_impact"
    decision = await _evaluate_policy(
        tool="hexstrike",
        scope_summary=scope_summary,
        target=target,
        method=method,
        action_class=action_class,
        risk_class=action_class,
        metadata={"tool_name": tool_name},
    )
    if decision.get("decision") != "allow":
        return json.dumps(_policy_block_result(decision, target=target))
    url = f"{HEXSTRIKE_BASE_URL}{spec['path']}"
    try:
        async with _httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=params)
            data = resp.json()
            # Surface stdout/stderr clearly for tool execution results
            if "stdout" in data:
                return f"[stdout]\n{(data.get('stdout') or '')[:6000]}\n[stderr]\n{(data.get('stderr') or '')[:1000]}"
            return json.dumps(data, indent=2)[:8000]
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Auto-probe: Chimera dispatches HexStrike per planner check, no LLM needed
# ---------------------------------------------------------------------------

# Maps planner attack class → (tool_name, param_builder(target_url))
_CLASS_TO_PROBE: Dict[str, tuple] = {
    "broken_auth": ("httpx",   lambda t: {"targets": t, "additional_args": "-title -status-code -tech-detect -follow-redirects"}),
    "IDOR":        ("httpx",   lambda t: {"targets": t, "additional_args": "-title -status-code -follow-redirects"}),
    "SSRF":        ("httpx",   lambda t: {"targets": t, "additional_args": "-title -status-code -follow-redirects"}),
    "XSS":         ("dalfox",  lambda t: {"url": t, "options": "--silence --no-color"}),
    "SQLi":        ("nuclei",  lambda t: {"target": t, "tags": "sqli", "severity": "high,critical"}),
    "injection":   ("nuclei",  lambda t: {"target": t, "tags": "injection", "severity": "medium,high,critical"}),
}
_DEFAULT_PROBE: tuple = ("httpx", lambda t: {"targets": t, "additional_args": "-title -status-code -tech-detect"})


def _probe_target_in_scope(target: str, query: str) -> bool:
    """True if the probe target's hostname appears in the query (scope section)."""
    try:
        from urllib.parse import urlparse
        host = urlparse(target).hostname or ""
        return bool(host) and host in query
    except Exception:
        return False


async def _auto_probe_checks(
    task_id: str,
    checks: List[Dict[str, Any]],
    query: str,
) -> List[Dict[str, Any]]:
    """Dispatch a HexStrike probe for each planner check and collect results."""
    results: List[Dict[str, Any]] = []
    for check in checks:
        cls      = check.get("class", "").lower().replace(" ", "_")
        target   = (check.get("target") or "").strip()
        check_id = check.get("id", "?")

        if not target:
            results.append({"check_id": check_id, "skipped": "no target"})
            continue

        if not _probe_target_in_scope(target, query):
            logger.warning("Task %s: auto-probe skipped out-of-scope target %s", task_id, target)
            results.append({"check_id": check_id, "target": target, "skipped": "out_of_scope"})
            continue

        tool_name, param_builder = _CLASS_TO_PROBE.get(cls, _DEFAULT_PROBE)
        params = param_builder(target)
        logger.info("Task %s: auto-probe check=%s cls=%s tool=%s target=%s (timeout=%ds)",
                    task_id, check_id, cls, tool_name, target[:80], PROBE_TIMEOUT_S)
        probe_result = await _hexstrike_call(tool_name, params, query, timeout=PROBE_TIMEOUT_S)
        results.append({
            "check_id": check_id,
            "class":    cls,
            "target":   target,
            "tool":     tool_name,
            "result":   probe_result,
        })
        _save_raw_llm_artifact(probe_result, f"{task_id}_probe_{check_id}_{tool_name}")
    return results


async def _executor_with_tools(task_id: str, executor_input: str) -> tuple[Dict[str, Any], dict]:
    """
    Run the executor stage with a HexStrike tool-call loop.

    The executor may emit <hexstrike_call>{"tool":"...","param":"..."}</hexstrike_call>
    blocks.  We dispatch each call to HexStrike, inject the results back as a user
    message, and re-run the executor (up to HEXSTRIKE_MAX_TOOL_TURNS times).
    """
    total_usage: dict = _base_usage_dict()
    context = executor_input

    for turn in range(HEXSTRIKE_MAX_TOOL_TURNS + 1):
        system = EXECUTOR_WITH_TOOLS_SYSTEM_PROMPT if turn == 0 else EXECUTOR_SYSTEM_PROMPT
        # Turn 0: free-text mode so model can emit <hexstrike_call> tags; subsequent turns: JSON mode
        if turn == 0 and HEXSTRIKE_ENABLED:
            raw, usage = await _call_model_text(EXECUTOR_MODEL, system, context)
        else:
            raw, usage = await _call_model(EXECUTOR_MODEL, system, context)
        _save_raw_llm_artifact(raw, f"{task_id}_s2_executor_turn{turn}")
        _accumulate_usage(total_usage, usage)

        calls = _HEXSTRIKE_CALL_RE.findall(raw)
        if not calls or turn >= HEXSTRIKE_MAX_TOOL_TURNS:
            # No (more) tool calls or hit iteration limit — extract findings
            clean = _HEXSTRIKE_CALL_RE.sub("", raw).strip()
            try:
                findings_data = _parse_stage("executor", clean)
            except RuntimeError:
                findings_data = _parse_stage("executor", raw)
            return findings_data, total_usage

        # Dispatch tool calls and build results context
        tool_results: List[str] = []
        for call_json in calls:
            try:
                call = json.loads(call_json)
                tool_name = call.pop("tool", "")
                logger.info("Task %s: hexstrike tool=%s params=%s", task_id, tool_name, list(call.keys()))
                result = await _hexstrike_call(tool_name, call, executor_input)
                tool_results.append(f"[{tool_name} result]\n{result}")
            except Exception as exc:
                tool_results.append(f"[tool_call error: {exc}]")

        # Inject results for next executor turn
        context = json.dumps({
            "original_input": executor_input,
            "tool_results": tool_results,
            "instruction": "Using the tool results above, produce your final findings JSON.",
        })

    # Fallback: return empty findings
    return {"findings": []}, total_usage


def _clip_to_budget(query: str, max_tokens: int = LOCAL_LLM_MAX_TOKENS) -> str:
    """Truncate query so system_prompt + query fits within context budget.
    Rough estimate: 1 token ≈ 4 chars.
    """
    budget_chars = (max_tokens - CONTEXT_HEADROOM) * 4
    if len(query) > budget_chars:
        query = query[:budget_chars] + "\n[truncated: context budget]"
    return query


class TaskRequest(BaseModel):
    query: str
    session_id: str = ""


class PlanRequest(BaseModel):
    run_id: str
    candidate: dict
    prior_evidence_refs: list[str] = []
    scope_summary: dict = {}


class ValidateRequest(BaseModel):
    run_id: str
    candidate: dict
    verification_results: list[dict]
    evidence_refs: list[str]
    prior_findings: list[dict] = []


class AgentRequest(BaseModel):
    run_id: str
    mode: str
    intent: str
    targets: list[str]
    resume_task_id: str | None = None
    agent_role: str | None = None
    analysis_domain: str | None = None
    provider_preset: str | None = None
    model: str | None = None
    base_url: str | None = None
    repo_path: str | None = None
    max_turns: int | None = None
    max_tool_calls: int | None = None
    max_retries: int | None = None
    reasoning_effort: str | None = None
    browser_session_id: str | None = None
    auto_create_browser_session: bool = True
    candidate: dict | None = None
    prior_findings: list[dict] = []
    prior_evidence_refs: list[str] = []
    auto_context: bool = True
    scope_summary: dict = {}
    budget: dict = {}


# ---------------------------------------------------------------------------
# Model availability checks
# ---------------------------------------------------------------------------

def _check_models_available() -> dict:
    """Return per-model availability for all chain models (openai_compatible) or anthropic status."""
    if PROVIDER != "openai_compatible":
        return {"anthropic": True}
    try:
        import httpx as _httpx
        resp = _httpx.get(f"{OPENAI_BASE_URL}/models", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            ids = {m.get("id", "").rstrip(":latest").lower() for m in data.get("data", [])}

            def _avail(name: str) -> bool:
                base = name.rstrip(":latest").lower()
                return any(m == base or m.startswith(base) for m in ids)

            return {
                "planner":   _avail(PLANNER_MODEL),
                "executor":  _avail(EXECUTOR_MODEL),
                "validator": _avail(VALIDATOR_MODEL),
            }
    except Exception:
        pass
    return {"planner": False, "executor": False, "validator": False}


def _check_model_available() -> bool:
    """Backward-compatible single bool: True only if all chain models are available."""
    avail = _check_models_available()
    return all(avail.values())


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    models_avail = _check_models_available()
    payload: Dict[str, Any] = {
        "status": "ok",
        "service": "shannon-gateway",
        "provider": PROVIDER,
        "model_available": all(models_avail.values()),
        "models": models_avail,
    }
    if PROVIDER == "openai_compatible":
        payload["base_url"] = OPENAI_BASE_URL
        payload["chain"] = {
            "planner":   PLANNER_MODEL,
            "executor":  EXECUTOR_MODEL,
            "validator": VALIDATOR_MODEL,
        }
    else:
        payload["model"] = MODEL
    payload["oracle"] = {
        "enabled": ORACLE_ENABLED,
        "provider": ORACLE_PROVIDER,
        "provider_preset": ORACLE_PROVIDER_PRESET,
        "provider_family": ORACLE_RUNTIME["family"],
        "model": ORACLE_MODEL,
        "reasoning": ORACLE_REASONING,
        "max_turns": ORACLE_MAX_TURNS,
        "max_tool_calls": ORACLE_MAX_TOOL_CALLS,
        "base_url": ORACLE_BASE_URL,
        "prompt_caching": {
            "enabled": bool(ORACLE_RUNTIME.get("prompt_caching")),
            "ttl": ORACLE_RUNTIME.get("prompt_cache_ttl"),
        },
    }
    payload["autonomous_agent"] = {
        "request_schema": AGENT_REQUEST_SCHEMA,
        "result_schema": AGENT_RESULT_SCHEMA,
        "defaults": {
            "agent_role": "analysis",
            "analysis_domain": None,
            "provider_preset": ORACLE_PROVIDER_PRESET,
            "max_turns": ORACLE_MAX_TURNS,
            "max_tool_calls": ORACLE_MAX_TOOL_CALLS,
            "max_retries": ORACLE_MAX_RETRIES,
            "reasoning_effort": ORACLE_REASONING,
        },
        "prompt_caching": {
            "enabled": bool(ORACLE_RUNTIME.get("prompt_caching")),
            "ttl": ORACLE_RUNTIME.get("prompt_cache_ttl"),
        },
    }
    payload["browser_tools"] = {
        "mediated_executor": BROWSER_TOOL_EXECUTOR is not None,
        "headless": BROWSER_TOOL_HEADLESS,
        "devtools": BROWSER_TOOL_DEVTOOLS,
        "slow_mo_ms": BROWSER_TOOL_SLOW_MO_MS,
        "mode": BROWSER_EXECUTOR_MODE,
    }
    payload["terminal_tools"] = {
        "mediated_executor": True,
        "core_url": CHIMERA_CORE_URL,
    }
    payload["source_tools"] = {
        "configured": bool(SOURCE_REPO_ROOT),
        "repo_root": SOURCE_REPO_ROOT,
    }
    payload["local_hypotheses"] = {
        "enabled": LOCAL_HYPOTHESIS_ENABLED,
        "max_findings": LOCAL_HYPOTHESIS_MAX_FINDINGS,
        "max_checks": LOCAL_HYPOTHESIS_MAX_CHECKS,
        "oracle_limit": LOCAL_HYPOTHESIS_ORACLE_LIMIT,
    }
    payload["agent_compaction"] = {
        "threshold": AGENT_COMPACTION_THRESHOLD,
        "keep_recent_turns": AGENT_COMPACTION_KEEP_RECENT,
    }
    return payload


@app.post("/api/v1/tasks")
async def submit_task(req: TaskRequest):
    task_id = str(uuid.uuid4())
    _tasks[task_id] = {
        "status": "running",
        "findings": [],
        "provider": PROVIDER,
        "model": MODEL if PROVIDER == "anthropic" else f"{PLANNER_MODEL}|{EXECUTOR_MODEL}|{VALIDATOR_MODEL}",
    }
    asyncio.create_task(_run_analysis(task_id, req.query))
    logger.info("Task %s submitted (session=%s)", task_id, req.session_id)
    return {"task_id": task_id, "status": "running"}


def _plan_verification(run_id: str, candidate: dict, prior_evidence_refs: list[str], scope_summary: dict) -> dict:
    return _fallback_plan_verification(run_id, candidate, prior_evidence_refs, scope_summary)


def _fallback_plan_verification(run_id: str, candidate: dict, prior_evidence_refs: list[str], scope_summary: dict) -> dict:
    target = candidate.get("target") or ""
    endpoint = candidate.get("endpoint") or ""
    probe_url = _candidate_probe_url(target, endpoint)
    claim_type = candidate.get("claim_type") or "unknown"
    verifier_hint = str((candidate.get("metadata") or {}).get("verifier_hint") or f"probe_{claim_type}")
    target_spec = dict(((candidate.get("metadata") or {}).get("target")) or {})
    candidate_params = list(candidate.get("params") or [])
    base_headers = dict(target_spec.get("headers") or {})
    base_query = dict(target_spec.get("params") or {})
    base_body = target_spec.get("body")
    verification_id = f"{candidate.get('candidate_id', 'cand')}-plan"
    checks = []
    if claim_type == "open_redirect":
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_redirect_check",
                "description": "verify redirect parameter reflection",
                "probe_input": {
                    "method": "GET",
                    "url": probe_url,
                    "headers": {},
                    "query": {"redirect": "https://attacker.example"},
                    "body": None,
                    "follow_redirects": False,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "open_redirect",
                    "rules": {
                        "expected_redirect_statuses": [301, 302, 303, 307, 308],
                        "location_equals": "https://attacker.example",
                    },
                },
            }
        )
    elif verifier_hint == "probe_idor" or claim_type == "idor":
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_idor_check",
                "description": "verify alternate object identifier access",
                "probe_input": {
                    "method": "GET",
                    "url": _increment_numeric_object_url(probe_url),
                    "headers": {},
                    "query": {},
                    "body": None,
                    "follow_redirects": True,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "idor",
                    "rules": {
                        "status_in": [200],
                        "require_numeric_object_id": True,
                    },
                },
            }
        )
    elif verifier_hint == "probe_admin_access" or claim_type == "admin_exposure":
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_admin_access_check",
                "description": "verify anonymous access to admin surface",
                "probe_input": {
                    "method": "GET",
                    "url": probe_url,
                    "headers": {},
                    "query": {},
                    "body": None,
                    "follow_redirects": True,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "admin_exposure",
                    "rules": {
                        "status_in": [200],
                        "endpoint_contains_any": ["/admin", "/rest/admin", "/manager", "/console"],
                        "body_contains_any": ["admin", "dashboard", "administration"],
                        "allow_path_only_match": True,
                    },
                },
            }
        )
    elif verifier_hint == "probe_api_surface" or claim_type in {"api_surface_exposure", "exposed_docs"}:
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_api_surface_check",
                "description": "verify exposed API schema or API surface",
                "probe_input": {
                    "method": "GET",
                    "url": probe_url,
                    "headers": {},
                    "query": {},
                    "body": None,
                    "follow_redirects": True,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "api_surface_exposure" if claim_type == "api_surface_exposure" else "exposed_docs",
                    "rules": {
                        "status_in": [200, 400],
                        "endpoint_contains_any": ["/openapi.json", "/graphql", "/swagger", "/swagger-ui.html"],
                        "body_contains_any": ["openapi", "swagger", "\"paths\"", "graphql", "__schema"],
                        "allow_endpoint_match": True,
                    },
                },
            }
        )
    elif verifier_hint == "probe_auth_missing" or claim_type == "auth_missing":
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_auth_missing_check",
                "description": "verify authenticated-context endpoint without auth",
                "probe_input": {
                    "method": "GET",
                    "url": probe_url,
                    "headers": {},
                    "query": {},
                    "body": None,
                    "follow_redirects": True,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "auth_missing",
                    "rules": {
                        "status_in": [200],
                        "body_contains_any": ["user", "email", "id", "authentication"],
                        "allow_non_error_200": True,
                    },
                },
            }
        )
    elif verifier_hint == "probe_xss" or claim_type in {"xss", "reflected_xss", "stored_xss", "dom_xss"}:
        xss_param = candidate_params[0] if candidate_params else "q"
        xss_payload = "<svg/onload=alert(1)>"
        query = dict(base_query)
        body = base_body
        if str(target_spec.get("method") or "GET").upper() == "GET":
            query[xss_param] = xss_payload
            body = None
        elif isinstance(body, dict):
            body = {**body, xss_param: xss_payload}
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_xss_check",
                "description": "verify payload reflection or execution markers",
                "probe_input": {
                    "method": str(target_spec.get("method") or "GET"),
                    "url": probe_url,
                    "headers": base_headers,
                    "query": query,
                    "body": body,
                    "follow_redirects": True,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "xss",
                    "rules": {
                        "status_in": [200],
                        "payload": xss_payload,
                        "body_contains_any": [xss_payload, "alert(1)", "<svg"],
                    },
                },
            }
        )
    elif verifier_hint == "probe_sqli" or claim_type in {"sqli", "sql_injection", "nosql_injection"}:
        sql_param = candidate_params[0] if candidate_params else "q"
        sql_payload = "'"
        query = dict(base_query)
        body = base_body
        if str(target_spec.get("method") or "GET").upper() == "GET":
            query[sql_param] = sql_payload
            body = None
        elif isinstance(body, dict):
            body = {**body, sql_param: sql_payload}
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_sqli_check",
                "description": "verify SQL error signatures or parser faults",
                "probe_input": {
                    "method": str(target_spec.get("method") or "GET"),
                    "url": probe_url,
                    "headers": base_headers,
                    "query": query,
                    "body": body,
                    "follow_redirects": True,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "sqli",
                    "rules": {
                        "status_in": [200, 400, 500],
                        "body_contains_any": ["sql", "sqlite", "syntax error", "unterminated", "query failed"],
                    },
                },
            }
        )
    elif verifier_hint == "probe_ssrf" or claim_type == "ssrf":
        ssrf_param = candidate_params[0] if candidate_params else "url"
        ssrf_payload = "http://127.0.0.1:80"
        query = dict(base_query)
        body = base_body
        if str(target_spec.get("method") or "GET").upper() == "GET":
            query[ssrf_param] = ssrf_payload
            body = None
        elif isinstance(body, dict):
            body = {**body, ssrf_param: ssrf_payload}
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_ssrf_check",
                "description": "verify server-side fetch behavior against an internal URL",
                "probe_input": {
                    "method": str(target_spec.get("method") or "GET"),
                    "url": probe_url,
                    "headers": base_headers,
                    "query": query,
                    "body": body,
                    "follow_redirects": True,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "ssrf",
                    "rules": {
                        "status_in": [200, 201, 202],
                        "body_contains_any": ["127.0.0.1", "localhost", "internal", "metadata", "success"],
                        "body_excludes_any": ["blocked", "forbidden", "invalid url"],
                    },
                },
            }
        )
    elif verifier_hint == "probe_upload_bug" or claim_type in {"upload_bug", "file_upload", "xxe", "yaml_injection"}:
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_upload_check",
                "description": "verify parser exposure or unsafe upload handling",
                "probe_input": {
                    "method": str(target_spec.get("method") or "POST"),
                    "url": probe_url,
                    "headers": {**base_headers, "Content-Type": "application/xml"},
                    "query": dict(base_query),
                    "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "follow_redirects": True,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "upload_bug",
                    "rules": {
                        "status_in": [200, 400, 500],
                        "body_contains_any": ["root:x:", "doctype", "entity", "yaml", "parser"],
                    },
                },
            }
        )
    elif verifier_hint == "probe_business_logic" or claim_type in {"business_logic", "payment_bypass", "workflow_bypass"}:
        checks.append(
            {
                "check_id": "check-1",
                "probe_type": "http_business_logic_check",
                "description": "verify workflow can complete without the expected authorization or payment state",
                "probe_input": {
                    "method": str(target_spec.get("method") or "POST"),
                    "url": probe_url,
                    "headers": base_headers,
                    "query": dict(base_query),
                    "body": base_body,
                    "follow_redirects": True,
                    "timeout_s": 30,
                },
                "success_condition": {
                    "type": "business_logic",
                    "rules": {
                        "status_in": [200],
                        "body_contains_any": ["success", "confirmation", "checkout", "order", "token", "deluxe"],
                        "body_excludes_any": ["unauthorized", "forbidden", "payment required"],
                    },
                },
            }
        )
    return {
        "verification_plan": {
            "verification_id": verification_id,
            "candidate_id": candidate.get("candidate_id"),
            "target": probe_url,
            "claim_type": claim_type,
            "checks": checks,
            "required_artifact_kinds": ["http_request", "http_response", "http_normalized"],
            "planner_notes": "Generated bounded verification plan from candidate finding.",
        },
        "usage": _base_usage_dict(),
    }


def _increment_numeric_object_url(url: str) -> str:
    match = re.search(r"(\d+)(?!.*\d)", url)
    if not match:
        return url
    original = int(match.group(1))
    start, end = match.span(1)
    return f"{url[:start]}{original + 1}{url[end:]}"


def _candidate_probe_url(target: str, endpoint: str) -> str:
    target = (target or "").strip()
    endpoint = (endpoint or "").strip()
    if not endpoint:
        return target
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return endpoint
    if not target:
        return endpoint
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return urljoin(base.rstrip("/") + "/", endpoint.lstrip("/"))
    return endpoint


def _validate_verification(
    run_id: str,
    candidate: dict,
    verification_results: list[dict],
    evidence_refs: list[str],
    prior_findings: list[dict],
) -> dict:
    return _fallback_validate_verification(run_id, candidate, verification_results, evidence_refs, prior_findings)


def _fallback_validate_verification(
    run_id: str,
    candidate: dict,
    verification_results: list[dict],
    evidence_refs: list[str],
    prior_findings: list[dict],
) -> dict:
    passed = [result for result in verification_results if str(result.get("outcome")) == "passed"]
    claim_type = candidate.get("claim_type") or "unknown"
    if claim_type == "broken_authentication" and any(result.get("claim_type") == "exposed_docs" for result in passed):
        decision = {
            "status": "downgraded",
            "final_claim_type": "exposed_docs",
            "severity": "medium",
            "rationale": "Evidence supports exposed docs rather than broken authentication.",
            "duplicate_of": None,
            "required_evidence_refs_present": bool(evidence_refs),
        }
    elif passed and evidence_refs:
        decision = {
            "status": "verified",
            "final_claim_type": passed[0].get("claim_type") or claim_type,
            "severity": candidate.get("severity_claimed") or "medium",
            "rationale": "Deterministic verifier passed.",
            "duplicate_of": None,
            "required_evidence_refs_present": True,
        }
    else:
        decision = {
            "status": "rejected",
            "final_claim_type": claim_type,
            "severity": candidate.get("severity_claimed") or "medium",
            "rationale": "Insufficient evidence for promotion.",
            "duplicate_of": None,
            "required_evidence_refs_present": False,
        }
    return {"decision": decision, "usage": _base_usage_dict()}


@app.post("/plan")
async def plan_verification(req: PlanRequest):
    prompt = json.dumps(
        {
            "run_id": req.run_id,
            "candidate": req.candidate,
            "prior_evidence_refs": req.prior_evidence_refs,
            "scope_summary": req.scope_summary,
            "instruction": "Return only a verification plan JSON grounded in the candidate finding and scope.",
        }
    )
    try:
        raw, usage = await _call_model(PLANNER_MODEL, PLANNER_SYSTEM_PROMPT, prompt)
        data = _parse_stage("typed_planner", raw)
        required = {"verification_id", "candidate_id", "target", "claim_type", "checks", "required_artifact_kinds", "planner_notes"}
        if not required.issubset(set(data.keys())):
            raise RuntimeError("planner missing required verification plan keys")
        return {"verification_plan": data, "usage": usage or _base_usage_dict()}
    except Exception:
        return _fallback_plan_verification(req.run_id, req.candidate, req.prior_evidence_refs, req.scope_summary)


@app.post("/validate")
async def validate_verification(req: ValidateRequest):
    prompt = json.dumps(
        {
            "run_id": req.run_id,
            "candidate": req.candidate,
            "verification_results": req.verification_results,
            "evidence_refs": req.evidence_refs,
            "prior_findings": req.prior_findings,
            "instruction": "Return only a validator decision JSON. Reject or downgrade unsupported claims.",
        }
    )
    try:
        raw, usage = await _call_model(VALIDATOR_MODEL, VALIDATOR_SYSTEM_PROMPT, prompt)
        data = _parse_stage("typed_validator", raw)
        required = {"status", "final_claim_type", "severity", "rationale", "duplicate_of", "required_evidence_refs_present"}
        if not required.issubset(set(data.keys())):
            raise RuntimeError("validator missing required decision keys")
        return {"decision": data, "usage": usage or _base_usage_dict()}
    except Exception:
        return _fallback_validate_verification(
            req.run_id,
            req.candidate,
            req.verification_results,
            req.evidence_refs,
            req.prior_findings,
        )


@app.post("/agent")
async def agent_mode(req: AgentRequest):
    response = dict(await _run_agent_mode(req))
    task_id = str(response.get("task_id") or f"agent-{uuid.uuid4()}")
    response["task_id"] = task_id
    existing = _tasks.get(task_id, {})
    runtime = _resolve_agent_runtime(req)
    request_view = response.get("request") if isinstance(response.get("request"), dict) else _agent_request_summary(
        req,
        limits=_resolve_agent_limits(req, runtime),
    )
    response["schema"] = str(response.get("schema") or AGENT_RESULT_SCHEMA)
    response["request"] = request_view
    response["runtime"] = response.get("runtime") or {}
    response["context"] = response.get("context") or {}
    response["summary"] = response.get("summary") or {}
    response["results"] = response.get("results") or {}
    response["artifacts"] = response.get("artifacts") or {}
    _record_task_state(task_id, {
        "schema": str(response.get("schema") or AGENT_RESULT_SCHEMA),
        "status": str(response.get("status") or existing.get("status") or "completed"),
        "run_id": str(response.get("run_id") or existing.get("run_id") or req.run_id),
        "mode": "agent",
        "findings": list(existing.get("findings") or []),
        "checkpoint": response.get("checkpoint") or existing.get("checkpoint") or {},
        "request": request_view,
        "runtime": response.get("runtime") or existing.get("runtime") or {},
        "context": response.get("context") or existing.get("context") or {},
        "summary": response.get("summary") or existing.get("summary") or {},
        "artifacts": response.get("artifacts") or existing.get("artifacts") or {},
        "provider": str(response.get("provider") or existing.get("provider") or runtime["family"]),
        "provider_preset": str(response.get("provider_preset") or existing.get("provider_preset") or runtime["preset"]),
        "model": str(response.get("model") or existing.get("model") or runtime["model"]),
        "browser_session_id": response.get("browser_session_id") or existing.get("browser_session_id"),
        "browser_session_created": bool(response.get("browser_session_created") or existing.get("browser_session_created") or False),
        "browser_session_error": response.get("browser_session_error") or existing.get("browser_session_error"),
        "context_run_id": response.get("context_run_id") or existing.get("context_run_id"),
        "context_source": response.get("context_source") or existing.get("context_source"),
        "local_hypotheses_count": int(response.get("local_hypotheses_count") or existing.get("local_hypotheses_count") or 0),
        "oracle_focus_hypotheses_count": int(response.get("oracle_focus_hypotheses_count") or existing.get("oracle_focus_hypotheses_count") or 0),
        "local_hypotheses_ref": response.get("local_hypotheses_ref") or existing.get("local_hypotheses_ref"),
        "local_hypothesis_status": response.get("local_hypothesis_status") or existing.get("local_hypothesis_status"),
        "local_hypothesis_error": response.get("local_hypothesis_error") or existing.get("local_hypothesis_error"),
        "agent_trace_ref": response.get("agent_trace_ref"),
        "tool_call_refs": list(response.get("tool_call_refs") or []),
        "compaction_refs": list(response.get("compaction_refs") or existing.get("compaction_refs") or []),
        "exploit_queue": list(response.get("exploit_queue") or []),
        "usage": response.get("usage") or existing.get("usage") or _base_usage_dict(),
    })
    response["task_state_ref"] = _tasks[task_id].get("task_state_ref")
    artifacts = dict(response.get("artifacts") or {})
    artifacts["task_state_ref"] = response["task_state_ref"]
    response["artifacts"] = artifacts
    task_state_artifacts = dict(_tasks[task_id].get("artifacts") or {})
    task_state_artifacts["task_state_ref"] = response["task_state_ref"]
    _tasks[task_id]["artifacts"] = task_state_artifacts
    _persist_agent_task_state(task_id, str(_tasks[task_id].get("run_id") or req.run_id), _tasks[task_id])
    return response


@app.get("/api/v1/tasks/{task_id}")
def get_task(task_id: str):
    task = _tasks.get(task_id) or _load_agent_task_state(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id": task_id, **task}


@app.get("/agent/tasks/{task_id}")
def get_agent_task(task_id: str):
    return get_task(task_id)


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _save_raw_llm_artifact(text: str, task_id: str) -> None:
    """Persist raw LLM text to /tmp/shannon_raw_<task_id>.txt for diagnostic use."""
    try:
        artifact_path = Path(f"/tmp/shannon_raw_{task_id}.txt")
        artifact_path.write_text(text, encoding="utf-8")
        logger.info("Task %s: raw LLM output saved to %s", task_id, artifact_path)
    except Exception as exc:
        logger.warning("Task %s: could not save raw LLM artifact: %s", task_id, exc)


def _parse_stage(stage_name: str, raw: str) -> dict:
    """Parse JSON from a stage response; raises RuntimeError with stage name on failure."""
    try:
        return json.loads(_coerce_json_object(raw))
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{stage_name} returned non-JSON: {exc}. First 200 chars: {raw[:200]!r}"
        ) from exc


def _accumulate_usage(total: dict, usage: "dict | None") -> None:
    if not usage:
        return
    for key in (
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    ):
        total[key] = int(total.get(key, 0) or 0) + int(usage.get(key, 0) or 0)
    for nested_key in ("cache_creation", "cache_read"):
        nested = usage.get(nested_key)
        if not isinstance(nested, dict):
            continue
        current = dict(total.get(nested_key) or {})
        for item_key, value in nested.items():
            current[str(item_key)] = int(current.get(item_key, 0) or 0) + int(value or 0)
        total[nested_key] = current


def _base_usage_dict() -> Dict[str, Any]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }


def _normalize_model_key(model: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(model or "").strip().lower()).strip("_")


def _normalized_cache_ttl(ttl: str | None) -> str | None:
    normalized = str(ttl or "").strip().lower()
    if normalized in {"", "5m", "default"}:
        return "5m"
    if normalized == "1h":
        return "1h"
    return None


def _response_usage_dict(response: Any) -> Dict[str, Any] | None:
    usage = getattr(response, "usage", None)
    if usage is None:
        return None
    prompt_details = getattr(usage, "prompt_tokens_details", None)
    cache_creation = getattr(usage, "cache_creation", None)
    cache_read = getattr(usage, "cache_read", None)
    if isinstance(cache_creation, dict):
        cache_creation_values = cache_creation
    elif hasattr(cache_creation, "__dict__"):
        cache_creation_values = vars(cache_creation)
    else:
        cache_creation_values = {}
    if isinstance(cache_read, dict):
        cache_read_values = cache_read
    elif hasattr(cache_read, "__dict__"):
        cache_read_values = vars(cache_read)
    else:
        cache_read_values = {}
    usage_dict: Dict[str, Any] = {
        "prompt_tokens": int(
            getattr(usage, "input_tokens", None)
            or getattr(usage, "prompt_tokens", None)
            or 0
        ),
        "completion_tokens": int(
            getattr(usage, "output_tokens", None)
            or getattr(usage, "completion_tokens", None)
            or 0
        ),
        "total_tokens": int(
            getattr(usage, "total_tokens", None)
            or (
                int(getattr(usage, "input_tokens", None) or getattr(usage, "prompt_tokens", None) or 0)
                + int(getattr(usage, "output_tokens", None) or getattr(usage, "completion_tokens", None) or 0)
            )
        ),
        "cache_creation_input_tokens": int(
            getattr(usage, "cache_creation_input_tokens", None)
            or sum(int(value or 0) for value in cache_creation_values.values())
            or 0
        ),
        "cache_read_input_tokens": int(
            getattr(usage, "cache_read_input_tokens", None)
            or getattr(usage, "cached_input_tokens", None)
            or getattr(prompt_details, "cached_tokens", None)
            or sum(int(value or 0) for value in cache_read_values.values())
            or 0
        ),
    }
    if cache_creation_values:
        creation = {str(key): int(value or 0) for key, value in cache_creation_values.items() if not str(key).startswith("_") and int(value or 0)}
        if creation:
            usage_dict["cache_creation"] = creation
    if cache_read_values:
        read = {str(key): int(value or 0) for key, value in cache_read_values.items() if not str(key).startswith("_") and int(value or 0)}
        if read:
            usage_dict["cache_read"] = read
    return usage_dict


def _builtin_pricing(provider_family: str, provider_preset: str, model: str) -> Dict[str, Any] | None:
    normalized = _normalize_model_key(model)
    if provider_preset == "ollama":
        return {
            "input_per_mtok": 0.0,
            "cached_input_per_mtok": 0.0,
            "output_per_mtok": 0.0,
            "cache_write_5m_per_mtok": 0.0,
            "cache_write_1h_per_mtok": 0.0,
            "source": "local_unmetered_estimate",
        }
    if provider_family == "anthropic":
        if normalized.startswith("claude_sonnet_4"):
            return {
                "input_per_mtok": 3.0,
                "cached_input_per_mtok": 0.30,
                "output_per_mtok": 15.0,
                "cache_write_5m_per_mtok": 3.75,
                "cache_write_1h_per_mtok": 6.0,
                "source": "builtin_official_anthropic_prompt_caching_2026_04_11",
            }
        if normalized.startswith("claude_haiku_4") or normalized.startswith("claude_haiku_4_5"):
            return {
                "input_per_mtok": 1.0,
                "cached_input_per_mtok": 0.10,
                "output_per_mtok": 5.0,
                "cache_write_5m_per_mtok": 1.25,
                "cache_write_1h_per_mtok": 2.0,
                "source": "builtin_official_anthropic_prompt_caching_2026_04_11",
            }
        if normalized.startswith("claude_opus_4"):
            return {
                "input_per_mtok": 5.0,
                "cached_input_per_mtok": 0.50,
                "output_per_mtok": 25.0,
                "cache_write_5m_per_mtok": 6.25,
                "cache_write_1h_per_mtok": 10.0,
                "source": "builtin_official_anthropic_prompt_caching_2026_04_11",
            }
    if provider_preset == "openai":
        if normalized == "gpt_5_4":
            return {
                "input_per_mtok": 2.50,
                "cached_input_per_mtok": 0.25,
                "output_per_mtok": 15.0,
                "source": "builtin_official_openai_pricing_2026_04_11",
            }
        if normalized in {"gpt_5_4_mini", "gpt_5_4mini"}:
            return {
                "input_per_mtok": 0.75,
                "cached_input_per_mtok": 0.075,
                "output_per_mtok": 4.50,
                "source": "builtin_official_openai_pricing_2026_04_11",
            }
        if normalized in {"gpt_5_4_nano", "gpt_5_4nano"}:
            return {
                "input_per_mtok": 0.20,
                "cached_input_per_mtok": 0.02,
                "output_per_mtok": 1.25,
                "source": "builtin_official_openai_pricing_2026_04_11",
            }
    return None


def _usage_with_metadata(
    usage: "dict | None",
    *,
    provider_family: str,
    provider_preset: str,
    model: str,
    prompt_caching_enabled: bool = False,
    prompt_cache_ttl: str | None = None,
) -> Dict[str, Any]:
    merged = dict(_base_usage_dict())
    _accumulate_usage(merged, usage or {})
    pricing = _builtin_pricing(provider_family, provider_preset, model)
    cache_read_tokens = int(merged.get("cache_read_input_tokens", 0) or 0)
    cache_write_tokens = int(merged.get("cache_creation_input_tokens", 0) or 0)
    if provider_family == "anthropic":
        uncached_prompt_tokens = int(merged.get("prompt_tokens", 0) or 0)
    else:
        uncached_prompt_tokens = max(int(merged.get("prompt_tokens", 0) or 0) - cache_read_tokens, 0)
    cost_estimate_usd: float | None = None
    pricing_source = "unpriced_provider"
    pricing_rates: Dict[str, float] | None = None
    if pricing:
        pricing_source = str(pricing["source"])
        pricing_rates = {
            key: float(pricing[key])
            for key in (
                "input_per_mtok",
                "cached_input_per_mtok",
                "output_per_mtok",
            )
            if key in pricing
        }
        if "cache_write_5m_per_mtok" in pricing:
            pricing_rates["cache_write_5m_per_mtok"] = float(pricing["cache_write_5m_per_mtok"])
        if "cache_write_1h_per_mtok" in pricing:
            pricing_rates["cache_write_1h_per_mtok"] = float(pricing["cache_write_1h_per_mtok"])
        cost_estimate_usd = (
            (uncached_prompt_tokens / 1_000_000.0) * float(pricing.get("input_per_mtok", 0.0))
            + (cache_read_tokens / 1_000_000.0) * float(pricing.get("cached_input_per_mtok", 0.0))
            + (int(merged.get("completion_tokens", 0) or 0) / 1_000_000.0) * float(pricing.get("output_per_mtok", 0.0))
        )
        if provider_family == "anthropic" and cache_write_tokens:
            cache_creation_breakdown = dict(merged.get("cache_creation") or {})
            cache_write_1h = int(cache_creation_breakdown.get("ephemeral_1h_input_tokens", 0) or 0)
            cache_write_5m = max(cache_write_tokens - cache_write_1h, 0)
            cost_estimate_usd += (
                (cache_write_5m / 1_000_000.0) * float(pricing.get("cache_write_5m_per_mtok", 0.0))
                + (cache_write_1h / 1_000_000.0) * float(pricing.get("cache_write_1h_per_mtok", 0.0))
            )

    enriched: Dict[str, Any] = {
        **merged,
        "provider": provider_family,
        "provider_preset": provider_preset,
        "model": model,
        "prompt_caching_enabled": bool(prompt_caching_enabled and provider_family == "anthropic"),
        "prompt_cache_ttl": _normalized_cache_ttl(prompt_cache_ttl) if prompt_caching_enabled and provider_family == "anthropic" else None,
        "cost_estimate_available": cost_estimate_usd is not None,
        "cost_estimate_usd": round(cost_estimate_usd, 6) if cost_estimate_usd is not None else None,
        "pricing_source": pricing_source,
    }
    if pricing_rates:
        enriched["pricing_rates_usd_per_mtok"] = pricing_rates
    return enriched


def _oracle_system_prompt(
    req: AgentRequest,
    *,
    prior_findings: List[Dict[str, Any]],
    local_hypotheses: List[Dict[str, Any]],
) -> str:
    return "\n\n".join(
        section["text"]
        for section in _oracle_prompt_blocks(
            req,
            prior_findings=prior_findings,
            local_hypotheses=local_hypotheses,
        )
        if section.get("text")
    )


def _oracle_prompt_blocks(
    req: AgentRequest,
    *,
    prior_findings: List[Dict[str, Any]],
    local_hypotheses: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    role_prompt = _load_role_prompt(req)
    sections: List[Dict[str, Any]] = [
        {
            "name": "system_identity",
            "stable": True,
            "cacheable": True,
            "text": "You are Shannon, an autonomous penetration testing agent. Use only the provided tools and stay strictly in scope.",
        },
        {
            "name": "agent_role",
            "stable": True,
            "cacheable": True,
            "text": f"Agent role: {_default_agent_role(req)}",
        },
    ]
    if req.analysis_domain:
        sections.append(
            {
                "name": "analysis_domain",
                "stable": True,
                "cacheable": True,
                "text": f"Analysis domain: {req.analysis_domain}",
            }
        )
    sections.append(
        {
            "name": "role_prompt",
            "stable": True,
            "cacheable": True,
            "text": role_prompt,
        }
    )
    sections.append(
        {
            "name": "scope_summary",
            "stable": False,
            "cacheable": False,
            "text": _scope_summary_text(req.scope_summary, req.targets),
        }
    )
    sections.extend(
        {
            "name": "prior_findings",
            "stable": False,
            "cacheable": False,
            "text": line,
        }
        for line in _compact_record_lines("Prior Findings", prior_findings)
    )
    sections.extend(
        {
            "name": "local_hypotheses",
            "stable": False,
            "cacheable": False,
            "text": line,
        }
        for line in _compact_record_lines("Local Hypotheses", local_hypotheses)
    )
    sections.append(
        {
            "name": "operating_rules",
            "stable": True,
            "cacheable": True,
            "text": (
                "Operating rules:\n"
                "- Treat prior findings and local hypotheses as leads, not ground truth.\n"
                "- Prefer mediated browser and bounded probe evidence over speculation.\n"
                "- Produce concrete candidate vulnerabilities with evidence refs only.\n"
                "- If evidence is weak or contradictory, say so through the tool path instead of inventing certainty."
            ),
        }
    )
    return [section for section in sections if section.get("text")]


def _oracle_prompt_bundle(
    req: AgentRequest,
    *,
    prior_findings: List[Dict[str, Any]],
    local_hypotheses: List[Dict[str, Any]],
    prompt_caching_enabled: bool,
    prompt_cache_ttl: str | None,
) -> Dict[str, Any]:
    sections = _oracle_prompt_blocks(
        req,
        prior_findings=prior_findings,
        local_hypotheses=local_hypotheses,
    )
    system_prompt = "\n\n".join(section["text"] for section in sections if section.get("text"))
    cacheable_count = sum(1 for section in sections if section.get("cacheable"))
    stable_count = sum(1 for section in sections if section.get("stable"))
    return {
        "schema": "shannon.prompt_bundle.v1",
        "provider_preset": req.provider_preset or ORACLE_PROVIDER_PRESET,
        "agent_role": _default_agent_role(req),
        "analysis_domain": str(req.analysis_domain or "").strip().lower() or None,
        "system_prompt": system_prompt,
        "system_prompt_blocks": sections,
        "cache": {
            "enabled": bool(prompt_caching_enabled),
            "ttl": _normalized_cache_ttl(prompt_cache_ttl) if prompt_caching_enabled else None,
            "stable_block_count": stable_count,
            "cacheable_block_count": cacheable_count,
        },
    }


def _agent_run_dir(run_id: str, task_id: str) -> Path:
    return AGENT_ARTIFACT_ROOT / run_id / "shannon" / "agent" / task_id


def _persist_agent_trace(task_id: str, run_id: str, payload: dict) -> str:
    path = _agent_run_dir(run_id, task_id) / "agent_trace.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _persist_agent_task_state(task_id: str, run_id: str, payload: dict) -> str:
    path = _agent_run_dir(run_id, task_id) / "task_state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _persist_agent_payload(task_id: str, run_id: str, filename: str, payload: Any) -> str:
    path = _agent_run_dir(run_id, task_id) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def _persist_agent_compaction(task_id: str, run_id: str, *, index: int, payload: dict) -> str:
    return _persist_agent_payload(task_id, run_id, f"compaction_{index:02d}.json", payload)


def _agent_payload_from_ref(ref: str) -> Any:
    path = Path(str(ref))
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _resume_checkpoint_state(task_state: Dict[str, Any] | None) -> Dict[str, Any]:
    if not isinstance(task_state, dict):
        return {}
    checkpoint = task_state.get("checkpoint")
    return dict(checkpoint) if isinstance(checkpoint, dict) else {}


def _resume_local_hypotheses(task_state: Dict[str, Any] | None) -> List[Dict[str, Any]]:
    if not isinstance(task_state, dict):
        return []
    local_ref = str(task_state.get("local_hypotheses_ref") or "").strip()
    payload = _agent_payload_from_ref(local_ref)
    return list(payload) if isinstance(payload, list) else []


def _resume_task_state(req: "AgentRequest") -> Dict[str, Any] | None:
    resume_task_id = str(req.resume_task_id or "").strip()
    if not resume_task_id:
        return None
    state = _load_agent_task_state(resume_task_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"Resume task not found: {resume_task_id}")
    return state


def _resolve_agent_runtime(req: "AgentRequest") -> Dict[str, Any]:
    return _resolve_provider_runtime(
        req.provider_preset or ORACLE_PROVIDER_PRESET,
        model=req.model,
        base_url=req.base_url,
        max_turns=int(req.max_turns or req.budget.get("max_turns") or ORACLE_RUNTIME["max_turns"]),
        prefer_preset_defaults=bool(req.provider_preset),
    )


def _resolve_agent_limits(req: "AgentRequest", runtime: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "max_turns": min(int(req.max_turns or req.budget.get("max_turns") or runtime["max_turns"]), int(runtime["max_turns"])),
        "max_tool_calls": max(1, int(req.max_tool_calls or req.budget.get("max_tool_calls") or ORACLE_MAX_TOOL_CALLS)),
        "max_retries": min(int(req.max_retries or req.budget.get("max_retries") or ORACLE_MAX_RETRIES), ORACLE_MAX_RETRIES),
        "reasoning_effort": str(req.reasoning_effort or ORACLE_REASONING).strip().lower(),
    }


def _agent_request_summary(req: "AgentRequest", *, limits: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": AGENT_REQUEST_SCHEMA,
        "mode": str(req.mode or "").lower(),
        "intent": req.intent,
        "targets": list(req.targets or []),
        "resume_task_id": str(req.resume_task_id or "").strip() or None,
        "agent_role": _default_agent_role(req),
        "analysis_domain": str(req.analysis_domain or "").strip().lower() or None,
        "provider_preset": req.provider_preset or ORACLE_PROVIDER_PRESET,
        "model": req.model,
        "base_url": req.base_url,
        "repo_path": req.repo_path,
        "browser_session_id": req.browser_session_id,
        "auto_create_browser_session": bool(req.auto_create_browser_session),
        "auto_context": bool(req.auto_context),
        "scope_summary": dict(req.scope_summary or {}),
        "budget": {
            "max_turns": limits["max_turns"],
            "max_tool_calls": limits["max_tool_calls"],
            "max_retries": limits["max_retries"],
            "reasoning_effort": limits["reasoning_effort"],
        },
        # Legacy request mirrors preserved for existing readers.
        "max_turns": limits["max_turns"],
        "max_tool_calls": limits["max_tool_calls"],
        "max_retries": limits["max_retries"],
        "reasoning_effort": limits["reasoning_effort"],
    }


def _severity_score(value: str) -> int:
    ranking = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return ranking.get(str(value or "").lower(), 0)


def _yield_score(item: Dict[str, Any], *, intent: str, targets: List[str]) -> int:
    title = str(item.get("title") or item.get("name") or "")
    description = str(item.get("description") or "")
    target = str(item.get("affected_target") or item.get("target") or "")
    asset = item.get("asset") if isinstance(item.get("asset"), dict) else {}
    endpoint = str(asset.get("endpoint") or item.get("endpoint") or "")
    text = " ".join([title, description, target, endpoint]).lower()

    score = _severity_score(str(item.get("severity") or item.get("severity_claimed") or ""))
    if target:
        score += 2
    if endpoint:
        score += 2
    if item.get("evidence_refs"):
        score += 2
    if str(item.get("tool_source") or "").lower() == "strix":
        score += 2
    if "graphql" in text or "swagger" in text or "openapi" in text:
        score += 2
    if any(keyword in text for keyword in ("admin", "auth", "login", "token", "password")):
        score += 2
    if any(keyword in text for keyword in ("xss", "sql", "sqli", "ssrf", "idor", "upload", "redirect")):
        score += 2

    lowered_intent = str(intent or "").lower()
    if lowered_intent and any(keyword in text for keyword in lowered_intent.split()):
        score += 1
    for candidate_target in targets:
        normalized = str(candidate_target or "").lower()
        if normalized and normalized in text:
            score += 2
    return score


def _prioritize_records(records: List[Dict[str, Any]], *, intent: str, targets: List[str], limit: int) -> List[Dict[str, Any]]:
    if limit <= 0:
        return []
    ranked = sorted(
        [item for item in records if isinstance(item, dict)],
        key=lambda item: (
            _yield_score(item, intent=intent, targets=targets),
            _severity_score(str(item.get("severity") or item.get("severity_claimed") or "")),
        ),
        reverse=True,
    )
    return ranked[:limit]


def _json_path_value(payload: Any, selector: str) -> Any:
    selector_text = str(selector or "").strip()
    if selector_text in {"", "$"}:
        return payload
    if selector_text.startswith("$."):
        selector_text = selector_text[2:]
    elif selector_text.startswith("$"):
        selector_text = selector_text[1:]

    current: Any = payload
    for raw_part in [part for part in selector_text.split(".") if part]:
        part = raw_part
        index_match = re.fullmatch(r"([^\[]+)\[(\d+)\]", part)
        if index_match:
            part = index_match.group(1)
            index = int(index_match.group(2))
            if not isinstance(current, dict) or part not in current:
                raise KeyError(raw_part)
            current = current[part]
            if not isinstance(current, list) or index >= len(current):
                raise KeyError(raw_part)
            current = current[index]
            continue
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                raise KeyError(raw_part)
            current = current[index]
            continue
        if not isinstance(current, dict) or part not in current:
            raise KeyError(raw_part)
        current = current[part]
    return current


def _serialize_artifact_excerpt(value: Any, *, max_chars: int) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, indent=2, ensure_ascii=True)
    return text[:max_chars]


def _artifact_json_path_aliases(payload: Any, selector: str) -> List[str]:
    selector_text = str(selector or "").strip()
    if selector_text not in {"body", "$.body", "response.body", "$.response.body"}:
        return []
    if not isinstance(payload, dict):
        return []
    if str(payload.get("schema") or "") != "shannon.oracle_tool_result.v1":
        return []
    tool_name = str(payload.get("tool_name") or "")
    if tool_name not in {"browser_navigate", "browser_capture_dom"}:
        return []
    return [
        "$.result.page_source",
        "$.result.body_excerpt",
        "$.summary.page_excerpt",
        "$.summary.body_excerpt",
    ]


def _artifact_roots(req: AgentRequest, task_id: str) -> List[Path]:
    roots = [
        _agent_run_dir(req.run_id, task_id),
        CHIMERA_ARTIFACTS_ROOT / req.run_id,
    ]
    deduped: List[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = str(root.resolve()) if root.exists() else str(root)
        if key not in seen:
            seen.add(key)
            deduped.append(root)
    return deduped


def _resolve_readable_artifact(req: AgentRequest, task_id: str, artifact_ref: str) -> Path:
    candidate = Path(str(artifact_ref or "")).expanduser()
    if not str(candidate):
        raise ValueError("artifact_ref is required")

    roots = [root.resolve() for root in _artifact_roots(req, task_id)]
    if candidate.is_absolute():
        resolved = candidate.resolve()
        if any(root == resolved or root in resolved.parents for root in roots):
            return resolved
        raise ValueError(f"artifact_ref outside readable roots: {artifact_ref}")

    for root in roots:
        resolved = (root / candidate).resolve()
        if root == resolved or root in resolved.parents:
            if resolved.exists():
                return resolved
    raise FileNotFoundError(f"artifact not found: {artifact_ref}")


def _resolve_source_repo_root(req: AgentRequest) -> Path:
    configured = str(req.repo_path or SOURCE_REPO_ROOT or "").strip()
    if not configured:
        raise ValueError("source repo root is not configured")

    root = Path(configured).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"source repo root not found: {root}")

    if SOURCE_REPO_ROOT and req.repo_path:
        allowed_root = Path(SOURCE_REPO_ROOT).expanduser().resolve()
        try:
            root.relative_to(allowed_root)
        except ValueError as exc:
            raise ValueError(f"repo_path outside configured source root: {root}") from exc
    return root


def _resolve_source_file_path(req: AgentRequest, relative_path: str) -> tuple[Path, Path]:
    repo_root = _resolve_source_repo_root(req)
    if not relative_path:
        raise ValueError("path is required")
    candidate = (repo_root / relative_path).resolve()
    try:
        candidate.relative_to(repo_root)
    except ValueError as exc:
        raise ValueError(f"path escapes source repo root: {relative_path}") from exc
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(f"source file not found: {relative_path}")
    return repo_root, candidate


async def _list_source_files(arguments: Dict[str, Any], req: AgentRequest) -> Dict[str, Any]:
    repo_root = _resolve_source_repo_root(req)
    pattern = str(arguments.get("glob") or "**/*")
    limit = max(1, min(int(arguments.get("limit") or 40), 200))

    try:
        proc = await asyncio.create_subprocess_exec(
            "rg",
            "--files",
            "--glob",
            pattern,
            str(repo_root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode not in {0, 1}:
            raise RuntimeError(stderr.decode("utf-8", errors="replace") or "rg --files failed")
        raw_lines = [line for line in stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]
    except FileNotFoundError:
        raw_lines = [str(path) for path in repo_root.glob(pattern) if path.is_file()]

    rel_paths: List[str] = []
    for raw_line in raw_lines:
        path = Path(raw_line).resolve()
        try:
            rel_paths.append(str(path.relative_to(repo_root)))
        except ValueError:
            continue
        if len(rel_paths) >= limit:
            break

    return {
        "repo_root": str(repo_root),
        "glob": pattern,
        "count": len(rel_paths),
        "files": rel_paths,
    }


async def _search_source_code(arguments: Dict[str, Any], req: AgentRequest) -> Dict[str, Any]:
    repo_root = _resolve_source_repo_root(req)
    pattern = str(arguments.get("pattern") or "").strip()
    glob = str(arguments.get("glob") or "**/*")
    limit = max(1, min(int(arguments.get("limit") or 20), 200))
    if not pattern:
        raise ValueError("pattern is required")

    try:
        proc = await asyncio.create_subprocess_exec(
            "rg",
            "-n",
            "--no-heading",
            "--glob",
            glob,
            "-m",
            str(limit),
            pattern,
            str(repo_root),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode not in {0, 1}:
            raise RuntimeError(stderr.decode("utf-8", errors="replace") or "rg search failed")
        raw_lines = [line for line in stdout.decode("utf-8", errors="replace").splitlines() if line.strip()]
    except FileNotFoundError:
        regex = re.compile(pattern)
        raw_lines = []
        for path in repo_root.rglob("*"):
            if not path.is_file():
                continue
            relative_path = str(path.relative_to(repo_root))
            if not fnmatch(relative_path, glob):
                continue
            for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                if regex.search(line):
                    raw_lines.append(f"{path}:{line_number}:{line}")
                    if len(raw_lines) >= limit:
                        break
            if len(raw_lines) >= limit:
                break

    matches: List[Dict[str, Any]] = []
    for line in raw_lines[:limit]:
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        raw_path, line_number, excerpt = parts
        path = Path(raw_path).resolve()
        try:
            relative_path = str(path.relative_to(repo_root))
        except ValueError:
            continue
        matches.append(
            {
                "path": relative_path,
                "line": int(line_number),
                "excerpt": excerpt[:400],
            }
        )

    return {
        "repo_root": str(repo_root),
        "pattern": pattern,
        "glob": glob,
        "count": len(matches),
        "matches": matches,
    }


async def _read_source_file(arguments: Dict[str, Any], req: AgentRequest) -> Dict[str, Any]:
    relative_path = str(arguments.get("path") or "").strip()
    repo_root, file_path = _resolve_source_file_path(req, relative_path)
    start_line = max(1, int(arguments.get("start_line") or 1))
    end_line = int(arguments.get("end_line") or 0)

    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if end_line <= 0:
        end_line = min(len(lines), start_line + 199)
    end_line = max(start_line, min(end_line, len(lines)))
    excerpt_lines = lines[start_line - 1:end_line]
    excerpt = "\n".join(f"{index}: {line}" for index, line in enumerate(excerpt_lines, start=start_line))

    return {
        "repo_root": str(repo_root),
        "path": str(file_path.relative_to(repo_root)),
        "start_line": start_line,
        "end_line": end_line,
        "excerpt": excerpt[:8000],
    }


async def _call_core_json(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    async with _httpx.AsyncClient(timeout=30) as client:
        response = await client.post(f"{CHIMERA_CORE_URL}/v1{path}", json=payload)
        response.raise_for_status()
        return dict(response.json() or {})


async def _zap_get_sites(arguments: Dict[str, Any], req: AgentRequest) -> Dict[str, Any]:
    target = str(arguments.get("target") or (req.targets[0] if req.targets else "")).strip()
    if target:
        try:
            _ensure_agent_scope({"url": target}, req.scope_summary)
        except ValueError as exc:
            return _scope_violation_result(exc, target=target)
    decision = await _evaluate_policy(
        tool="zap",
        scope_summary=req.scope_summary,
        target=target or None,
        action_class="passive",
        risk_class="passive",
        metadata={"zap_action": "get_sites"},
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=target or None)
    try:
        return await _call_core_json("/zap/sites", {"target": target, "scope_summary": _policy_scope_summary(req.scope_summary)})
    except Exception as exc:
        return {"error": "zap_request_failed", "detail": str(exc), "target": target or None}


async def _zap_spider(arguments: Dict[str, Any], req: AgentRequest) -> Dict[str, Any]:
    target = str(arguments.get("target") or (req.targets[0] if req.targets else "")).strip()
    if not target:
        return {"error": "missing_target", "detail": "target is required"}
    try:
        _ensure_agent_scope({"url": target}, req.scope_summary)
    except ValueError as exc:
        return _scope_violation_result(exc, target=target)
    recurse = bool(arguments.get("recurse", True))
    max_children = max(1, min(int(arguments.get("max_children") or 25), 500))
    decision = await _evaluate_policy(
        tool="zap",
        scope_summary=req.scope_summary,
        target=target,
        action_class="low_impact",
        risk_class="passive",
        metadata={"zap_action": "spider", "recurse": recurse, "max_children": max_children},
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=target)
    try:
        return await _call_core_json(
            "/zap/spider",
            {
                "target": target,
                "recurse": recurse,
                "max_children": max_children,
                "scope_summary": _policy_scope_summary(req.scope_summary),
            },
        )
    except Exception as exc:
        return {"error": "zap_request_failed", "detail": str(exc), "target": target}


async def _zap_list_alerts(arguments: Dict[str, Any], req: AgentRequest) -> Dict[str, Any]:
    target = str(arguments.get("target") or (req.targets[0] if req.targets else "")).strip()
    if target:
        try:
            _ensure_agent_scope({"url": target}, req.scope_summary)
        except ValueError as exc:
            return _scope_violation_result(exc, target=target)
    count = max(1, min(int(arguments.get("count") or 20), 500))
    decision = await _evaluate_policy(
        tool="zap",
        scope_summary=req.scope_summary,
        target=target or None,
        action_class="passive",
        risk_class="passive",
        metadata={"zap_action": "list_alerts", "count": count},
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=target or None)
    try:
        return await _call_core_json(
            "/zap/alerts",
            {
                "target": target,
                "count": count,
                "scope_summary": _policy_scope_summary(req.scope_summary),
            },
        )
    except Exception as exc:
        return {"error": "zap_request_failed", "detail": str(exc), "target": target or None}


async def _read_artifact(arguments: Dict[str, Any], req: AgentRequest, *, task_id: str) -> Dict[str, Any]:
    artifact_ref = str(arguments.get("artifact_ref") or "")
    json_path = str(arguments.get("json_path") or "")
    max_chars = min(max(int(arguments.get("max_chars") or 1200), 200), 8000)
    try:
        path = _resolve_readable_artifact(req, task_id, artifact_ref)
        raw_text = path.read_text(encoding="utf-8")
        payload: Any
        kind = "text"
        try:
            payload = json.loads(raw_text)
            kind = "json"
        except json.JSONDecodeError:
            payload = raw_text
        selected = _json_path_value(payload, json_path) if json_path else payload
        excerpt = _serialize_artifact_excerpt(selected, max_chars=max_chars)
        return {
            "artifact_ref": artifact_ref,
            "resolved_path": str(path),
            "kind": kind,
            "json_path": json_path or None,
            "excerpt": excerpt,
            "size_bytes": len(raw_text.encode("utf-8")),
        }
    except Exception as exc:
        if kind == "json" and json_path:
            for alias_selector in _artifact_json_path_aliases(payload, json_path):
                try:
                    selected = _json_path_value(payload, alias_selector)
                    excerpt = _serialize_artifact_excerpt(selected, max_chars=max_chars)
                    return {
                        "artifact_ref": artifact_ref,
                        "resolved_path": str(path),
                        "kind": kind,
                        "json_path": json_path or None,
                        "resolved_json_path": alias_selector,
                        "excerpt": excerpt,
                        "size_bytes": len(raw_text.encode("utf-8")),
                    }
                except Exception:
                    continue
        return {
            "artifact_ref": artifact_ref,
            "error": "artifact_read_failed",
            "detail": str(exc),
            "json_path": json_path or None,
        }


def _load_agent_task_state(task_id: str) -> dict | None:
    legacy_path = AGENT_TASK_ROOT / f"{task_id}.json"
    candidate_paths = []
    if legacy_path.exists():
        candidate_paths.append(legacy_path)
    candidate_paths.extend(AGENT_ARTIFACT_ROOT.glob(f"*/shannon/agent/{task_id}/task_state.json"))
    for path in candidate_paths:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
    return None


def _record_task_state(task_id: str, payload: dict) -> dict:
    _tasks[task_id] = dict(payload)
    run_id = str(_tasks[task_id].get("run_id") or "unknown-run")
    task_state_ref = _persist_agent_task_state(task_id, run_id, _tasks[task_id])
    _tasks[task_id]["task_state_ref"] = task_state_ref
    _persist_agent_task_state(task_id, run_id, _tasks[task_id])
    return _tasks[task_id]


def _update_agent_checkpoint(task_id: str, *, run_id: str, checkpoint: Dict[str, Any]) -> dict:
    existing = dict(_tasks.get(task_id) or _load_agent_task_state(task_id) or {})
    existing["run_id"] = str(existing.get("run_id") or run_id)
    existing["checkpoint"] = checkpoint
    return _record_task_state(task_id, existing)


def _local_hypothesis_query(req: "AgentRequest", prior_context: Dict[str, Any]) -> str:
    return _clip_to_budget(
        json.dumps(
            {
                "intent": req.intent,
                "targets": req.targets,
                "candidate": req.candidate,
                "scope_summary": req.scope_summary,
                "prior_findings": prior_context["prior_findings"],
                "prior_evidence_refs": prior_context["prior_evidence_refs"],
                "instruction": (
                    "Generate a bounded, evidence-grounded pentest idea list for the Oracle. "
                    "Use only concrete endpoints or behaviors present in the target description, "
                    "the prior findings, or the candidate."
                ),
            }
        )
    )


def _finding_asset_from_target(target: str, method: Optional[str], parameter: Optional[str]) -> Dict[str, Any]:
    parsed = urlparse(str(target or ""))
    host = parsed.hostname or _normalize_scope_host(str(target or ""))
    endpoint = parsed.path or "/"
    return {
        "host": host or None,
        "endpoint": endpoint or "/",
        "method": method,
        "parameter": parameter,
    }


def _normalize_local_hypotheses(task_id: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for index, finding in enumerate(findings[:LOCAL_HYPOTHESIS_MAX_FINDINGS], start=1):
        if not isinstance(finding, dict):
            continue
        target = str(finding.get("target") or "")
        method = finding.get("method")
        parameter = finding.get("parameter")
        normalized.append(
            {
                "finding_id": f"{task_id}-local-hypothesis-{index}",
                "title": str(finding.get("title") or f"Local Hypothesis {index}"),
                "severity": str(finding.get("severity") or "medium"),
                "description": str(finding.get("description") or "")[:2400],
                "affected_target": target,
                "tool_source": "shannon_local",
                "tool_version": f"{PLANNER_MODEL}|{EXECUTOR_MODEL}|{VALIDATOR_MODEL}",
                "repro_guidance": finding.get("repro_guidance"),
                "evidence_refs": [f"agent_local_hypothesis:{task_id}:{index}"],
                "validation_status": "hypothesis",
                "validation_reason": "Generated by the local Shannon planner/executor/validator chain for Oracle prioritization.",
                "confidence": 0.35,
                "finding_type": "AGENT_HYPOTHESIS",
                "asset": _finding_asset_from_target(target, method, parameter),
            }
        )
    return normalized


async def _generate_local_hypotheses(req: "AgentRequest", prior_context: Dict[str, Any], *, task_id: str) -> Dict[str, Any]:
    if not LOCAL_HYPOTHESIS_ENABLED:
        return {
            "status": "disabled",
            "local_hypotheses": [],
            "plan": {},
            "probe_results": [],
            "usage": _base_usage_dict(),
            "error": None,
        }
    if PROVIDER != "openai_compatible":
        return {
            "status": "skipped",
            "local_hypotheses": [],
            "plan": {},
            "probe_results": [],
            "usage": _base_usage_dict(),
            "error": f"unsupported provider for local hypotheses: {PROVIDER}",
        }

    usage: Dict[str, Any] = _base_usage_dict()
    prompt = _local_hypothesis_query(req, prior_context)
    probe_results: List[Dict[str, Any]] = []
    plan_data: Dict[str, Any] = {}
    try:
        raw_plan, plan_usage = await _call_model(
            PLANNER_MODEL,
            PLANNER_SYSTEM_PROMPT,
            prompt,
            temperature=PLANNER_TEMPERATURE,
        )
        _accumulate_usage(usage, plan_usage)
        _save_raw_llm_artifact(raw_plan, f"{task_id}_local_hypothesis_plan")
        plan_data = _parse_stage("oracle_local_planner", raw_plan)
        checks = list(plan_data.get("checks") or [])[:LOCAL_HYPOTHESIS_MAX_CHECKS]
        if HEXSTRIKE_ENABLED and checks:
            probe_results = await _auto_probe_checks(f"{task_id}_local_hypothesis", checks, prompt)
        executor_input = json.dumps(
            {
                "query": prompt,
                "plan": plan_data,
                "probe_results": probe_results,
                "instruction": "Produce grounded pentest hypotheses for Oracle prioritization.",
            }
        )
        findings_data, executor_usage = await _executor_with_tools(f"{task_id}_local_hypothesis", executor_input)
        _accumulate_usage(usage, executor_usage)
        findings = list(findings_data.get("findings") or [])
        if findings:
            validator_input = json.dumps(
                {
                    "query": prompt,
                    "findings": findings,
                    "instruction": "Deduplicate and rank these as bounded hypotheses for Oracle follow-up.",
                }
            )
            raw_final, validator_usage = await _call_model(
                VALIDATOR_MODEL,
                VALIDATOR_SYSTEM_PROMPT,
                validator_input,
                temperature=VALIDATOR_TEMPERATURE,
            )
            _accumulate_usage(usage, validator_usage)
            _save_raw_llm_artifact(raw_final, f"{task_id}_local_hypothesis_validator")
            final_data = _parse_stage("oracle_local_validator", raw_final)
            findings = list(final_data.get("findings") or [])
        local_hypotheses = _normalize_local_hypotheses(task_id, findings)
        return {
            "status": "completed",
            "local_hypotheses": local_hypotheses,
            "plan": plan_data,
            "probe_results": probe_results,
            "usage": usage,
            "error": None,
        }
    except Exception as exc:
        logger.warning("Agent %s local hypothesis generation failed: %s", task_id, exc)
        return {
            "status": "failed",
            "local_hypotheses": [],
            "plan": plan_data,
            "probe_results": probe_results,
            "usage": usage,
            "error": str(exc),
        }


async def _ensure_browser_session(req: "AgentRequest") -> tuple[Optional[str], bool, Optional[str]]:
    if BROWSER_EXECUTOR_MODE != "mediated":
        return req.browser_session_id, False, None
    if req.browser_session_id:
        return req.browser_session_id, False, None
    if not req.auto_create_browser_session or not req.targets:
        return None, False, None

    payload: Dict[str, Any] = {
        "target": req.targets[0],
        "run_id": req.run_id,
        "headless": BROWSER_TOOL_HEADLESS,
    }
    if req.scope_summary:
        scope_summary = {
            "allowlist": list(req.scope_summary.get("allowlist") or req.targets),
            "denylist": list(req.scope_summary.get("denylist") or []),
        }
        payload["scope_text"] = json.dumps(scope_summary)

    try:
        async with _httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{CHIMERA_CORE_URL}/v1/browser/sessions",
                json=payload,
            )
            response.raise_for_status()
            session = response.json()
        return str(session.get("session_id") or ""), True, None
    except Exception as exc:
        return None, False, str(exc)


def _decode_hexstrike_result(raw: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw_output": raw}


def _interesting_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    keep = {
        "content-type",
        "location",
        "set-cookie",
        "server",
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "x-recruiting",
    }
    return {
        str(key): value
        for key, value in headers.items()
        if str(key).lower() in keep
    }


def _mediated_status(result: Dict[str, Any]) -> Optional[int]:
    js_results = result.get("js_results") if isinstance(result.get("js_results"), list) else []
    for item in js_results:
        payload = item.get("result") if isinstance(item, dict) and isinstance(item.get("result"), dict) else {}
        status = payload.get("status")
        if isinstance(status, int):
            return status
    network = result.get("network") if isinstance(result.get("network"), list) else []
    for item in network:
        if isinstance(item, dict) and item.get("event") == "response" and isinstance(item.get("status"), int):
            return int(item["status"])
    return None


def _page_title_from_html(html: str) -> str:
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""


def _tool_result_summary(tool_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    if tool_name in {"browser_navigate", "browser_capture_dom", "browser_click", "browser_fill", "browser_execute_js"}:
        headers = result.get("headers") if isinstance(result.get("headers"), dict) else {}
        page_source = str(result.get("page_source") or "")
        status_code = result.get("status_code")
        if not isinstance(status_code, int):
            status_code = _mediated_status(result)
        title = result.get("title")
        if not isinstance(title, str) or not title:
            title = _page_title_from_html(page_source)
        summary = {
            "url": result.get("url"),
            "final_url": result.get("final_url"),
            "status_code": status_code,
            "title": title,
            "interesting_headers": _interesting_headers(headers),
            "browser_session_id": result.get("browser_session_id"),
            "mediated_by": result.get("mediated_by"),
            "browser_fallback": result.get("browser_fallback"),
        }
        if tool_name == "browser_capture_dom":
            console = result.get("console") if isinstance(result.get("console"), list) else []
            summary["console"] = console[:5]
            if page_source:
                summary["page_excerpt"] = page_source[:800]
        if tool_name == "browser_execute_js":
            summary["js_results"] = list(result.get("js_results") or [])[:3]
    elif tool_name == "browser_get_console":
        summary = {
            "browser_session_id": result.get("browser_session_id"),
            "count": result.get("count"),
            "console": list(result.get("console") or [])[:10],
            "artifact_ref": result.get("artifact_ref"),
            "capture_artifact_ref": result.get("capture_artifact_ref"),
        }
    elif tool_name == "browser_get_network":
        summary = {
            "browser_session_id": result.get("browser_session_id"),
            "count": result.get("count"),
            "network": list(result.get("network") or [])[:12],
            "artifact_ref": result.get("artifact_ref"),
            "capture_artifact_ref": result.get("capture_artifact_ref"),
        }
    elif tool_name in {"hexstrike_recon", "hexstrike_endpoints"}:
        endpoints = result.get("endpoints") if isinstance(result.get("endpoints"), list) else []
        summary = {
            "target": result.get("target"),
            "source": result.get("source"),
            "endpoints": endpoints[:20],
            "endpoint_count": len(endpoints),
        }
    elif tool_name == "hexstrike_probe":
        summary = {
            "endpoint": result.get("endpoint"),
            "status_code": result.get("status_code"),
            "checks": result.get("checks"),
            "headers": _interesting_headers(result.get("headers") if isinstance(result.get("headers"), dict) else {}),
            "body_excerpt": str(result.get("body_excerpt") or "")[:1200],
        }
    elif tool_name == "hexstrike_httpx":
        raw_output = str(result.get("raw_output") or "")
        summary = {
            "raw_output_excerpt": raw_output[:1200],
        }
    elif tool_name in {"hexstrike_nuclei", "hexstrike_dalfox", "hexstrike_attack_surface", "hexstrike_exploit", "hexstrike_nikto", "hexstrike_gobuster", "hexstrike_ffuf"}:
        summary = {
            "target": result.get("target") or result.get("url"),
            "raw_output_excerpt": str(result.get("raw_output") or result.get("stdout") or result.get("body") or "")[:1600],
        }
    elif tool_name == "shell_run_scoped":
        summary = {
            "command": result.get("command"),
            "returncode": result.get("returncode"),
            "stdout": str(result.get("stdout") or "")[:1200],
            "stderr": str(result.get("stderr") or "")[:400],
        }
    elif tool_name in {"terminal_start", "terminal_write", "terminal_read", "terminal_resize", "terminal_close"}:
        summary = {
            "terminal_session_id": result.get("terminal_session_id") or result.get("session_id"),
            "transcript_artifact_ref": result.get("transcript_artifact_ref") or result.get("artifact_ref"),
            "status": result.get("status"),
            "bytes_written": result.get("bytes_written"),
            "bytes_read": result.get("bytes_read"),
            "output": str(result.get("output") or "")[:1200],
            "command": result.get("command") or (result.get("session") or {}).get("command"),
            "cols": result.get("cols"),
            "rows": result.get("rows"),
            "exit_code": result.get("exit_code"),
        }
    elif tool_name == "read_artifact":
        summary = {
            "artifact_ref": result.get("artifact_ref"),
            "resolved_path": result.get("resolved_path"),
            "kind": result.get("kind"),
            "json_path": result.get("json_path"),
            "excerpt": str(result.get("excerpt") or "")[:1200],
            "error": result.get("error"),
            "detail": result.get("detail"),
        }
    elif tool_name == "list_source_files":
        summary = {
            "repo_root": result.get("repo_root"),
            "glob": result.get("glob"),
            "count": result.get("count"),
            "files": list(result.get("files") or [])[:20],
        }
    elif tool_name == "search_source_code":
        summary = {
            "repo_root": result.get("repo_root"),
            "pattern": result.get("pattern"),
            "glob": result.get("glob"),
            "count": result.get("count"),
            "matches": list(result.get("matches") or [])[:10],
        }
    elif tool_name == "read_source_file":
        summary = {
            "repo_root": result.get("repo_root"),
            "path": result.get("path"),
            "start_line": result.get("start_line"),
            "end_line": result.get("end_line"),
            "excerpt": str(result.get("excerpt") or "")[:1600],
        }
    elif tool_name == "zap_get_sites":
        summary = {
            "target": result.get("target"),
            "count": result.get("count"),
            "sites": list(result.get("sites") or [])[:20],
            "source": result.get("source"),
        }
    elif tool_name == "zap_spider":
        summary = {
            "target": result.get("target"),
            "scan_id": result.get("scan_id"),
            "status": result.get("status"),
            "recurse": result.get("recurse"),
            "max_children": result.get("max_children"),
            "source": result.get("source"),
        }
    elif tool_name == "zap_list_alerts":
        summary = {
            "target": result.get("target"),
            "count": result.get("count"),
            "alerts": list(result.get("alerts") or [])[:10],
            "source": result.get("source"),
        }
    else:
        summary = {
            key: value
            for key, value in result.items()
            if key in {"target", "url", "final_url", "status_code", "title", "returncode", "error", "detail"}
        }
        if not summary:
            summary = {key: value for key, value in list(result.items())[:10]}
    return {key: value for key, value in summary.items() if value not in (None, "", [], {})}


def _wrap_oracle_tool_result(
    *,
    req: AgentRequest,
    task_id: str,
    tool_name: str,
    call_index: int,
    arguments: Dict[str, Any],
    result: Dict[str, Any],
) -> Dict[str, Any]:
    summary = _tool_result_summary(tool_name, result)
    status = "error" if result.get("error") else "ok"
    artifact_payload = {
        "schema": "shannon.oracle_tool_result.v1",
        "run_id": req.run_id,
        "task_id": task_id,
        "agent_role": _default_agent_role(req),
        "analysis_domain": str(req.analysis_domain or "").strip().lower() or None,
        "call_index": call_index,
        "tool_name": tool_name,
        "tool_family": "hexstrike" if tool_name.startswith("hexstrike_") else "local",
        "status": status,
        "arguments": arguments,
        "summary": summary,
        "result": result,
    }
    artifact_ref = _persist_agent_payload(
        task_id,
        req.run_id,
        f"tool_call_{call_index:02d}_{tool_name}.json",
        artifact_payload,
    )
    return {
        "schema": artifact_payload["schema"],
        "tool_name": tool_name,
        "call_index": call_index,
        "status": status,
        "summary": summary,
        "artifact_ref": artifact_ref,
    }


def _tool_artifact_refs(tool_results: List[Dict[str, Any]]) -> List[str]:
    refs: List[str] = []
    for item in tool_results:
        if not isinstance(item, dict):
            continue
        artifact_ref = str(item.get("artifact_ref") or "").strip()
        if artifact_ref:
            refs.append(artifact_ref)
    return refs


def _oracle_tool_handlers(
    req: AgentRequest,
    *,
    task_id: str,
    browser_session_id: Optional[str] = None,
) -> Dict[str, Any]:
    browser_executor = _browser_executor_for_request(req, browser_session_id=browser_session_id)
    executor_input = json.dumps(req.scope_summary)
    call_state = {"count": 0}
    agent_role = _default_agent_role(req)
    allowed_tool_names = set(
        get_allowed_oracle_tool_names(
            agent_role=agent_role,
            analysis_domain=req.analysis_domain,
        )
    )

    handlers: Dict[str, Any] = {}
    for tool_name in get_agent_tool_catalog("shannon_executor"):
        prefixed_tool_name = f"hexstrike_{tool_name}"
        if prefixed_tool_name not in allowed_tool_names:
            continue

        async def _handler(arguments: dict, actual_tool_name: str = tool_name) -> dict:
            call_state["count"] += 1
            result = _decode_hexstrike_result(
                await _hexstrike_call(actual_tool_name, arguments, executor_input, timeout=PROBE_TIMEOUT_S)
            )
            return _wrap_oracle_tool_result(
                req=req,
                task_id=task_id,
                tool_name=f"hexstrike_{actual_tool_name}",
                call_index=call_state["count"],
                arguments=arguments,
                result=result,
            )

        handlers[prefixed_tool_name] = _handler

    local_handlers = {
        "zap_get_sites": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="zap_get_sites",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _zap_get_sites(arguments, req),
        ),
        "zap_spider": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="zap_spider",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _zap_spider(arguments, req),
        ),
        "zap_list_alerts": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="zap_list_alerts",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _zap_list_alerts(arguments, req),
        ),
        "list_source_files": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="list_source_files",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _list_source_files(arguments, req),
        ),
        "search_source_code": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="search_source_code",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _search_source_code(arguments, req),
        ),
        "read_source_file": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="read_source_file",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _read_source_file(arguments, req),
        ),
        "browser_navigate": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="browser_navigate",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _browser_navigate(arguments, req.scope_summary, browser_executor=browser_executor),
        ),
        "browser_click": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="browser_click",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _browser_click(arguments, req.scope_summary, browser_executor=browser_executor),
        ),
        "browser_fill": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="browser_fill",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _browser_fill(arguments, req.scope_summary, browser_executor=browser_executor),
        ),
        "browser_execute_js": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="browser_execute_js",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _browser_execute_js(arguments, req.scope_summary, browser_executor=browser_executor),
        ),
        "browser_capture_dom": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="browser_capture_dom",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _browser_capture_dom(arguments, req.scope_summary, browser_executor=browser_executor),
        ),
        "browser_get_console": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="browser_get_console",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _browser_get_console(arguments, req.scope_summary, browser_executor=browser_executor),
        ),
        "browser_get_network": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="browser_get_network",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _browser_get_network(arguments, req.scope_summary, browser_executor=browser_executor),
        ),
        "terminal_start": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="terminal_start",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _terminal_start(arguments, req),
        ),
        "terminal_write": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="terminal_write",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _terminal_write(arguments, req),
        ),
        "terminal_read": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="terminal_read",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _terminal_read(arguments, req),
        ),
        "terminal_resize": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="terminal_resize",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _terminal_resize(arguments, req),
        ),
        "terminal_close": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="terminal_close",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _terminal_close(arguments, req),
        ),
        "shell_run_scoped": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="shell_run_scoped",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _shell_run_scoped(arguments, req.scope_summary),
        ),
        "read_artifact": lambda arguments: _oracle_browser_tool_call(
            req=req,
            task_id=task_id,
            tool_name="read_artifact",
            call_state=call_state,
            arguments=arguments,
            runner=lambda: _read_artifact(arguments, req, task_id=task_id),
        ),
    }
    handlers.update({
        name: handler
        for name, handler in local_handlers.items()
        if name in allowed_tool_names
    })
    return handlers


async def _oracle_browser_tool_call(
    *,
    req: AgentRequest,
    task_id: str,
    tool_name: str,
    call_state: Dict[str, int],
    arguments: Dict[str, Any],
    runner: Any,
) -> Dict[str, Any]:
    call_state["count"] += 1
    result = await runner()
    return _wrap_oracle_tool_result(
        req=req,
        task_id=task_id,
        tool_name=tool_name,
        call_index=call_state["count"],
        arguments=arguments,
        result=result if isinstance(result, dict) else {"raw_result": result},
    )


def _create_oracle_client(runtime: Dict[str, Any]) -> Any:
    if runtime["family"] == "anthropic":
        return anthropic.AsyncAnthropic(api_key=runtime["api_key"])
    return AsyncOpenAI(api_key=runtime["api_key"], base_url=runtime["base_url"])


async def _run_agent_mode(req: AgentRequest) -> dict:
    if not ORACLE_ENABLED:
        limits = _resolve_agent_limits(req, ORACLE_RUNTIME)
        request_summary = _agent_request_summary(req, limits=limits)
        return {
            "schema": AGENT_RESULT_SCHEMA,
            "status": "disabled",
            "run_id": req.run_id,
            "request": request_summary,
            "runtime": {
                "provider": ORACLE_RUNTIME["family"],
                "provider_preset": ORACLE_RUNTIME["preset"],
                "model": ORACLE_RUNTIME["model"],
                "browser_session_id": req.browser_session_id,
                "browser_session_created": False,
                "browser_session_error": None,
                "context_run_id": None,
                "context_source": "disabled",
                "repo_path": req.repo_path,
                "reasoning_effort": limits["reasoning_effort"],
                "prompt_caching_enabled": bool(ORACLE_RUNTIME.get("prompt_caching")),
                "prompt_cache_ttl": ORACLE_RUNTIME.get("prompt_cache_ttl"),
                "limits": {
                    "max_turns": limits["max_turns"],
                    "max_tool_calls": limits["max_tool_calls"],
                    "max_retries": limits["max_retries"],
                },
            },
            "agent_trace_ref": None,
            "tool_call_refs": [],
            "new_candidates": [],
            "evidence_refs": [],
            "validator_handoff": {"recommended_mode": "typed_verify", "candidate_ids": []},
            "usage": _usage_with_metadata(
                _base_usage_dict(),
                provider_family=ORACLE_RUNTIME["family"],
                provider_preset=ORACLE_RUNTIME["preset"],
                model=ORACLE_RUNTIME["model"],
                prompt_caching_enabled=bool(ORACLE_RUNTIME.get("prompt_caching")),
                prompt_cache_ttl=ORACLE_RUNTIME.get("prompt_cache_ttl"),
            ),
            "findings": [],
            "context": {
                "context_run_id": None,
                "context_source": "disabled",
                "prior_findings_count": len(list(req.prior_findings or [])),
                "local_hypotheses_count": 0,
                "oracle_focus_hypotheses_count": 0,
                "local_hypothesis_status": "disabled",
                "local_hypothesis_error": None,
            },
            "results": {
                "tool_results": [],
                "local_hypotheses": [],
                "oracle_focus_hypotheses": [],
                "new_candidates": [],
                "exploit_queue": [],
                "validator_handoff": {"recommended_mode": "typed_verify", "candidate_ids": []},
                "raw_output": "",
            },
            "artifacts": {
                "agent_trace_ref": None,
                "tool_call_refs": [],
                "compaction_refs": [],
                "local_hypotheses_ref": None,
                "evidence_refs": [],
                "task_state_ref": None,
            },
        }

    resume_state = _resume_task_state(req)
    if resume_state and str(resume_state.get("status") or "").lower() == "completed":
        trace_payload = _agent_payload_from_ref(str(resume_state.get("agent_trace_ref") or ""))
        if isinstance(trace_payload, dict):
            return trace_payload
        return dict(resume_state)

    task_id = str(req.resume_task_id or f"agent-{uuid.uuid4()}")
    runtime = _resolve_agent_runtime(req)
    limits = _resolve_agent_limits(req, runtime)
    checkpoint = _resume_checkpoint_state(resume_state)
    request_summary = _agent_request_summary(req, limits=limits)
    prior_context = _resolve_prior_context(req)
    existing_browser_session_id = str((resume_state or {}).get("browser_session_id") or "").strip() or None
    if existing_browser_session_id:
        browser_session_id = existing_browser_session_id
        browser_session_created = bool((resume_state or {}).get("browser_session_created") or False)
        browser_session_error = (resume_state or {}).get("browser_session_error")
    else:
        browser_session_id, browser_session_created, browser_session_error = await _ensure_browser_session(req)

    local_hypotheses = _resume_local_hypotheses(resume_state)
    if local_hypotheses:
        local_hypothesis_result = {
            "status": (resume_state or {}).get("local_hypothesis_status") or "resumed",
            "error": (resume_state or {}).get("local_hypothesis_error"),
        }
    else:
        local_hypothesis_result = await _generate_local_hypotheses(req, prior_context, task_id=task_id)
        local_hypotheses = list(local_hypothesis_result.get("local_hypotheses") or [])
    oracle_focus_hypotheses = _prioritize_records(
        local_hypotheses,
        intent=req.intent,
        targets=list(req.targets or []),
        limit=min(LOCAL_HYPOTHESIS_ORACLE_LIMIT, max(len(local_hypotheses), 0)),
    )
    oracle_focus_prior_findings = _prioritize_records(
        list(prior_context.get("prior_findings") or []),
        intent=req.intent,
        targets=list(req.targets or []),
        limit=max(LOCAL_HYPOTHESIS_ORACLE_LIMIT, 4),
    )
    local_hypotheses_ref = str((resume_state or {}).get("local_hypotheses_ref") or "").strip() or None
    if local_hypotheses and not local_hypotheses_ref:
        local_hypotheses_ref = _persist_agent_payload(task_id, req.run_id, "local_hypotheses.json", local_hypotheses)
    _record_task_state(task_id, {
        "status": "running",
        "run_id": req.run_id,
        "mode": "agent",
        "findings": [],
        "request": request_summary,
        "provider": runtime["family"],
        "provider_preset": runtime["preset"],
        "model": runtime["model"],
        "exploit_queue": [],
        "browser_session_id": browser_session_id,
        "browser_session_created": browser_session_created,
        "browser_session_error": browser_session_error,
        "context_run_id": prior_context.get("context_run_id"),
        "context_source": prior_context.get("context_source"),
        "local_hypotheses_count": len(local_hypotheses),
        "oracle_focus_hypotheses_count": len(oracle_focus_hypotheses),
        "local_hypotheses_ref": local_hypotheses_ref,
        "local_hypothesis_status": local_hypothesis_result.get("status"),
        "local_hypothesis_error": local_hypothesis_result.get("error"),
        "compaction_refs": list((resume_state or {}).get("compaction_refs") or checkpoint.get("compaction_refs") or []),
        "checkpoint": checkpoint,
    })
    client = _create_oracle_client(runtime)
    loop_result = {"output_text": "", "tool_results": [], "usage": _base_usage_dict()}
    compaction_refs: List[str] = list((resume_state or {}).get("compaction_refs") or checkpoint.get("compaction_refs") or [])
    prompt_bundle = _oracle_prompt_bundle(
        req,
        prior_findings=oracle_focus_prior_findings,
        local_hypotheses=oracle_focus_hypotheses,
        prompt_caching_enabled=bool(runtime.get("prompt_caching")),
        prompt_cache_ttl=runtime.get("prompt_cache_ttl"),
    )
    prompt_bundle_ref = _persist_agent_payload(task_id, req.run_id, "prompt_bundle.json", prompt_bundle)
    _record_task_state(task_id, {**dict(_tasks.get(task_id) or {}), "prompt_bundle_ref": prompt_bundle_ref})
    attempt_number = max(1, int(checkpoint.get("attempt") or 1))
    max_attempts = max(1, int(limits["max_retries"]) + 1)
    resume_same_attempt = bool(checkpoint.get("turns") or checkpoint.get("compactions") or checkpoint.get("tool_results"))
    while attempt_number <= max_attempts:
        current_attempt = attempt_number
        loop_result = await run_responses_tool_loop(
            client=client,
            provider_preset=runtime["preset"],
            model=runtime["model"],
            system_prompt=prompt_bundle["system_prompt"],
            system_prompt_blocks=list(prompt_bundle.get("system_prompt_blocks") or []),
            user_input=json.dumps(
                {
                    "intent": req.intent,
                    "targets": req.targets,
                    "candidate": req.candidate,
                    "prior_evidence_refs": prior_context["prior_evidence_refs"],
                    "all_local_hypotheses_count": len(local_hypotheses),
                    "local_hypothesis_status": local_hypothesis_result.get("status"),
                    "local_hypothesis_error": local_hypothesis_result.get("error"),
                    "scope_summary": req.scope_summary,
                    "context_run_id": prior_context.get("context_run_id"),
                    "context_source": prior_context.get("context_source"),
                    "browser_session_id": browser_session_id,
                    "attempt": current_attempt,
                    "request": request_summary,
                }
            ),
            tools=get_oracle_tools(
                agent_role=_default_agent_role(req),
                analysis_domain=req.analysis_domain,
            ),
            tool_handlers=_oracle_tool_handlers(req, task_id=task_id, browser_session_id=browser_session_id),
            max_turns=limits["max_turns"],
            max_tool_calls=limits["max_tool_calls"],
            reasoning_effort=limits["reasoning_effort"],
            compaction_threshold=AGENT_COMPACTION_THRESHOLD,
            keep_recent_turns=AGENT_COMPACTION_KEEP_RECENT,
            enable_prompt_caching=bool(runtime.get("prompt_caching")),
            prompt_cache_ttl=runtime.get("prompt_cache_ttl"),
            persist_compaction=lambda payload: compaction_refs.append(
                _persist_agent_compaction(task_id, req.run_id, index=len(compaction_refs) + 1, payload=payload)
            ) or compaction_refs[-1],
            initial_turns=list(checkpoint.get("turns") or []) if resume_same_attempt else None,
            initial_compactions=list(checkpoint.get("compactions") or []) if resume_same_attempt else None,
            initial_tool_results=list(checkpoint.get("tool_results") or []) if resume_same_attempt else None,
            initial_usage=dict(checkpoint.get("usage") or {}) if resume_same_attempt else None,
            persist_checkpoint=lambda payload: _update_agent_checkpoint(
                task_id,
                run_id=req.run_id,
                checkpoint={**payload, "attempt": current_attempt, "compaction_refs": list(compaction_refs)},
            ),
        )
        if str(req.mode).lower() != "exploit" or loop_result.get("tool_results"):
            break
        attempt_number += 1
        checkpoint = {}
        resume_same_attempt = False
    raw_text = loop_result.get("output_text") or ""
    tool_results = list(loop_result.get("tool_results") or [])
    tool_artifact_refs = _tool_artifact_refs(tool_results)
    candidate = req.candidate or {}
    extracted_candidates = extract_candidates_from_tool_results(
        intent=req.intent,
        tool_results=tool_results,
        targets=list(req.targets or []),
    )
    if not extracted_candidates and isinstance(candidate, dict):
        seeded_claim_type = str(candidate.get("claim_type") or "")
        seeded_target = str(candidate.get("target") or (req.targets[0] if req.targets else ""))
        seeded_endpoint = str(candidate.get("endpoint") or "")
        if seeded_claim_type and seeded_target:
            extracted_candidates = [
                {
                    "claim_type": seeded_claim_type,
                    "target": {
                        "method": str(candidate.get("method") or "GET"),
                        "endpoint": seeded_endpoint or "/",
                        "params": candidate.get("params") if isinstance(candidate.get("params"), dict) else None,
                        "headers": None,
                        "body": None,
                    },
                    "title": str(candidate.get("title") or seeded_claim_type.replace("_", " ").title()),
                    "evidence_refs": list(tool_artifact_refs),
                    "auth_context": {"authenticated": False, "role": "anonymous", "session_fixed": False},
                    "success_condition": str(candidate.get("success_condition") or "Confirm the original candidate with a concrete verifier."),
                    "verifier_hint": str(candidate.get("verifier_hint") or f"probe_{seeded_claim_type}"),
                    "target_url": seeded_target,
                }
            ]
    new_candidates = []
    for index, item in enumerate(extracted_candidates, start=1):
        target_spec = dict(item.get("target") or {})
        target_url = str(item.get("target_url") or (req.targets[0] if req.targets else ""))
        new_candidates.append(
            {
                "candidate_id": f"{task_id}-candidate-{index}",
                "source": "shannon-agent",
                "title": str(item.get("title") or f"Shannon Candidate {index}"),
                "claim_type": str(item.get("claim_type") or ""),
                "severity_claimed": "medium",
                "target": target_url,
                "endpoint": target_spec.get("endpoint"),
                "params": list((target_spec.get("params") or {}).keys()),
                "evidence_refs": list(item.get("evidence_refs") or []),
                "metadata": {
                    "target": target_spec,
                    "auth_context": item.get("auth_context") or {},
                    "success_condition": item.get("success_condition"),
                    "verifier_hint": item.get("verifier_hint"),
                },
                "exploit_status": "POTENTIAL" if str(req.mode).lower() == "exploit" else None,
            }
        )
    evidence_refs = list(tool_artifact_refs)
    artifacts = {
        "agent_trace_ref": None,
        "tool_call_refs": list(tool_artifact_refs),
        "compaction_refs": list(compaction_refs),
        "local_hypotheses_ref": local_hypotheses_ref,
        "prompt_bundle_ref": prompt_bundle_ref,
        "evidence_refs": list(evidence_refs),
        "task_state_ref": None,
    }
    response = {
        "schema": AGENT_RESULT_SCHEMA,
        "task_id": task_id,
        "run_id": req.run_id,
        "status": "completed",
        "request": request_summary,
        "runtime": {
            "provider": runtime["family"],
            "provider_preset": runtime["preset"],
            "model": runtime["model"],
            "browser_session_id": browser_session_id,
            "browser_session_created": browser_session_created,
            "browser_session_error": browser_session_error,
            "context_run_id": prior_context.get("context_run_id"),
            "context_source": prior_context.get("context_source"),
            "repo_path": req.repo_path,
            "reasoning_effort": limits["reasoning_effort"],
            "prompt_caching_enabled": bool(runtime.get("prompt_caching")),
            "prompt_cache_ttl": runtime.get("prompt_cache_ttl"),
            "prompt_blocks": {
                "count": len(prompt_bundle.get("system_prompt_blocks") or []),
                "stable_count": int(prompt_bundle.get("cache", {}).get("stable_block_count") or 0),
                "cacheable_count": int(prompt_bundle.get("cache", {}).get("cacheable_block_count") or 0),
                "bundle_ref": prompt_bundle_ref,
            },
            "limits": {
                "max_turns": limits["max_turns"],
                "max_tool_calls": limits["max_tool_calls"],
                "max_retries": limits["max_retries"],
            },
        },
        "context": {
            "context_run_id": prior_context.get("context_run_id"),
            "context_source": prior_context.get("context_source"),
            "prior_findings_count": len(prior_context["prior_findings"]),
            "local_hypotheses_count": len(local_hypotheses),
            "oracle_focus_hypotheses_count": len(oracle_focus_hypotheses),
            "local_hypotheses_ref": local_hypotheses_ref,
            "local_hypothesis_status": local_hypothesis_result.get("status"),
            "local_hypothesis_error": local_hypothesis_result.get("error"),
        },
        "provider": runtime["family"],
        "provider_preset": runtime["preset"],
        "model": runtime["model"],
        "browser_session_id": browser_session_id,
        "browser_session_created": browser_session_created,
        "browser_session_error": browser_session_error,
        "context_run_id": prior_context.get("context_run_id"),
        "context_source": prior_context.get("context_source"),
        "prior_findings_count": len(prior_context["prior_findings"]),
        "local_hypotheses_count": len(local_hypotheses),
        "oracle_focus_hypotheses_count": len(oracle_focus_hypotheses),
        "local_hypotheses_ref": local_hypotheses_ref,
        "local_hypothesis_status": local_hypothesis_result.get("status"),
        "local_hypothesis_error": local_hypothesis_result.get("error"),
        "agent_trace_ref": None,
        "tool_call_refs": list(tool_artifact_refs),
        "compaction_refs": list(compaction_refs),
        "prompt_bundle_ref": prompt_bundle_ref,
        "tool_results": tool_results,
        "local_hypotheses": local_hypotheses,
        "oracle_focus_hypotheses": oracle_focus_hypotheses,
        "findings": list(new_candidates),
        "new_candidates": new_candidates,
        "evidence_refs": evidence_refs,
        "artifacts": artifacts,
        "results": {
            "tool_results": tool_results,
            "local_hypotheses": local_hypotheses,
            "oracle_focus_hypotheses": oracle_focus_hypotheses,
            "new_candidates": new_candidates,
            "exploit_queue": [
                {
                    "candidate_id": item["candidate_id"],
                    "mode": req.mode,
                    "attempts": current_attempt,
                    "status": "ready" if loop_result.get("tool_results") else "exhausted",
                }
                for item in new_candidates
            ],
            "validator_handoff": {
                "recommended_mode": "typed_verify",
                "candidate_ids": [item["candidate_id"] for item in new_candidates],
            },
            "raw_output": raw_text,
        },
        "summary": {
            "attempts": current_attempt,
            "tool_result_count": len(tool_results),
            "finding_count": len(new_candidates),
            "prior_findings_count": len(prior_context["prior_findings"]),
            "local_hypotheses_count": len(local_hypotheses),
            "oracle_focus_hypotheses_count": len(oracle_focus_hypotheses),
        },
        "exploit_queue": [],
        "validator_handoff": {},
        "usage": _usage_with_metadata(
            loop_result.get("usage"),
            provider_family=runtime["family"],
            provider_preset=runtime["preset"],
            model=runtime["model"],
            prompt_caching_enabled=bool(runtime.get("prompt_caching")),
            prompt_cache_ttl=runtime.get("prompt_cache_ttl"),
        ),
        "raw_output": raw_text,
    }
    response["exploit_queue"] = list(response["results"]["exploit_queue"])
    response["validator_handoff"] = dict(response["results"]["validator_handoff"])
    response["agent_trace_ref"] = _persist_agent_trace(task_id, req.run_id, response)
    response["artifacts"]["agent_trace_ref"] = response["agent_trace_ref"]
    _record_task_state(task_id, {
        "status": "completed",
        "run_id": req.run_id,
        "mode": "agent",
        "findings": [],
        "request": request_summary,
        "provider": runtime["family"],
        "provider_preset": runtime["preset"],
        "model": runtime["model"],
        "browser_session_id": browser_session_id,
        "browser_session_created": browser_session_created,
        "browser_session_error": browser_session_error,
        "context_run_id": prior_context.get("context_run_id"),
        "context_source": prior_context.get("context_source"),
        "local_hypotheses_count": len(local_hypotheses),
        "oracle_focus_hypotheses_count": len(oracle_focus_hypotheses),
        "local_hypotheses_ref": local_hypotheses_ref,
        "local_hypothesis_status": local_hypothesis_result.get("status"),
        "local_hypothesis_error": local_hypothesis_result.get("error"),
        "agent_trace_ref": response["agent_trace_ref"],
        "prompt_bundle_ref": prompt_bundle_ref,
        "tool_call_refs": evidence_refs,
        "compaction_refs": list(compaction_refs),
        "exploit_queue": list(response.get("exploit_queue") or []),
        "usage": response["usage"],
        "checkpoint": {
            "status": "completed",
            "attempt": current_attempt,
            "turn_count": len(list(loop_result.get("turns") or [])),
            "tool_result_count": len(tool_results),
            "turns": list(loop_result.get("turns") or []),
            "compactions": list(loop_result.get("compactions") or []),
            "compaction_refs": list(compaction_refs),
            "tool_results": tool_results,
            "usage": response["usage"],
            "last_output_text": raw_text,
        },
    })
    response["artifacts"]["task_state_ref"] = str(_tasks[task_id].get("task_state_ref") or "")
    response["task_state_ref"] = response["artifacts"]["task_state_ref"]
    return response


def _browser_executor_for_request(req: AgentRequest, *, browser_session_id: Optional[str] = None) -> ChimeraBrowserMediator | None:
    if BROWSER_EXECUTOR_MODE != "mediated":
        return None
    effective_session_id = browser_session_id or req.browser_session_id
    if not effective_session_id:
        return None
    return ChimeraBrowserMediator(session_id=effective_session_id, chimera_base_url=CHIMERA_CORE_URL)


def _terminal_mediator() -> ChimeraTerminalMediator:
    return ChimeraTerminalMediator(chimera_base_url=CHIMERA_CORE_URL)


def _terminal_tool_result(result: Dict[str, Any]) -> Dict[str, Any]:
    session = result.get("session") if isinstance(result.get("session"), dict) else {}
    payload = dict(result)
    payload.setdefault("terminal_session_id", result.get("session_id") or session.get("session_id"))
    payload.setdefault("transcript_artifact_ref", result.get("artifact_ref") or session.get("transcript_artifact_ref"))
    return payload


async def _browser_navigate(
    arguments: dict,
    scope_summary: dict,
    *,
    browser_executor: ChimeraBrowserMediator | None = None,
) -> dict:
    url = str(arguments.get("url") or "")
    try:
        _ensure_agent_scope(arguments, scope_summary)
    except ValueError as exc:
        return _scope_violation_result(exc, target=url)
    decision = await _evaluate_policy(
        tool="browser",
        scope_summary=scope_summary,
        target=url,
        method="GET",
        action_class="passive",
        risk_class="passive",
        browser_actions=["navigate", "wait_for_navigation"],
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=url)

    async def _http_fallback() -> dict:
        async with _httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(url)
        return {
            "url": url,
            "final_url": str(resp.url),
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body_excerpt": resp.text[:2000],
            "browser_fallback": "httpx",
        }

    if browser_executor is not None:
        return await browser_executor.execute(
            {
                "actions": [
                    {"type": "navigate", "url": url},
                    {"type": "wait_for_navigation"},
                ],
                "capture_har": True,
                "capture_screenshots": True,
                "extract_console": True,
                "context": {},
            },
            url=url,
        )
    if BROWSER_TOOL_EXECUTOR is not None:
        return await BROWSER_TOOL_EXECUTOR(
            {
                "actions": [
                    {"type": "navigate", "url": url},
                    {"type": "wait_for_navigation"},
                ],
                "capture_har": True,
                "capture_screenshots": True,
                "extract_console": True,
                "context": {},
            }
        )
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return await _http_fallback()
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=BROWSER_TOOL_HEADLESS,
                devtools=(BROWSER_TOOL_DEVTOOLS if not BROWSER_TOOL_HEADLESS else False),
                slow_mo=BROWSER_TOOL_SLOW_MO_MS,
            )
            page = await browser.new_page()
            resp = await page.goto(url, wait_until="networkidle", timeout=30000)
            result = {
                "url": url,
                "final_url": page.url,
                "status_code": resp.status if resp else 0,
                "headers": await resp.all_headers() if resp else {},
                "body_excerpt": (await page.content())[:2000],
                "browser_runtime": {
                    "headless": BROWSER_TOOL_HEADLESS,
                    "devtools": BROWSER_TOOL_DEVTOOLS,
                    "slow_mo_ms": BROWSER_TOOL_SLOW_MO_MS,
                },
            }
            await browser.close()
            return result
    except Exception:
        return await _http_fallback()


async def _browser_capture_dom(
    arguments: dict,
    scope_summary: dict,
    *,
    browser_executor: ChimeraBrowserMediator | None = None,
) -> dict:
    url = str(arguments.get("url") or "")
    try:
        _ensure_agent_scope(arguments, scope_summary)
    except ValueError as exc:
        return _scope_violation_result(exc, target=url)
    browser_actions = ["extract_dom", "extract_console"]
    action_class = "passive"
    if url:
        browser_actions = ["navigate", "wait_for_navigation", *browser_actions]
    decision = await _evaluate_policy(
        tool="browser",
        scope_summary=scope_summary,
        target=url or None,
        method="GET",
        action_class=action_class,
        risk_class=action_class,
        browser_actions=browser_actions,
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=url or None)

    async def _http_fallback() -> dict:
        async with _httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(url)
        title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        return {
            "url": url,
            "status_code": resp.status_code,
            "title": title_match.group(1).strip() if title_match else "",
            "dom_excerpt": resp.text[:4000],
            "browser_fallback": "httpx",
        }

    if browser_executor is not None:
        actions = [
            {"type": "extract_dom"},
            {"type": "extract_console"},
        ]
        if url:
            actions = [
                {"type": "navigate", "url": url},
                {"type": "wait_for_navigation"},
                *actions,
            ]
        return await browser_executor.execute(
            {
                "actions": actions,
                "capture_har": True,
                "capture_screenshots": True,
                "extract_console": True,
                "context": {},
            },
            url=url or None,
        )
    if BROWSER_TOOL_EXECUTOR is not None:
        return await BROWSER_TOOL_EXECUTOR(
            {
                "actions": [
                    {"type": "navigate", "url": url},
                    {"type": "wait_for_navigation"},
                    {"type": "extract_dom"},
                    {"type": "extract_console"},
                ],
                "capture_har": True,
                "capture_screenshots": True,
                "extract_console": True,
                "context": {},
            }
        )
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return await _http_fallback()
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=BROWSER_TOOL_HEADLESS,
                devtools=(BROWSER_TOOL_DEVTOOLS if not BROWSER_TOOL_HEADLESS else False),
                slow_mo=BROWSER_TOOL_SLOW_MO_MS,
            )
            page = await browser.new_page()
            console: List[Dict[str, str]] = []
            page.on("console", lambda msg: console.append({"type": msg.type, "text": msg.text}))
            resp = await page.goto(url, wait_until="networkidle", timeout=30000)
            result = {
                "url": url,
                "status_code": resp.status if resp else 0,
                "title": await page.title(),
                "dom_excerpt": (await page.content())[:4000],
                "console": console,
                "browser_runtime": {
                    "headless": BROWSER_TOOL_HEADLESS,
                    "devtools": BROWSER_TOOL_DEVTOOLS,
                    "slow_mo_ms": BROWSER_TOOL_SLOW_MO_MS,
                },
            }
            await browser.close()
            return result
    except Exception:
        return await _http_fallback()


async def _browser_click(
    arguments: dict,
    scope_summary: dict,
    *,
    browser_executor: ChimeraBrowserMediator | None = None,
) -> dict:
    if browser_executor is None:
        return {"error": "browser_session_required", "detail": "browser_click requires a mediated browser session"}
    selector = str(arguments.get("selector") or "").strip()
    url = str(arguments.get("url") or "")
    if not selector:
        return {"error": "missing_selector"}
    target = url or None
    try:
        if target:
            _ensure_agent_scope({"url": target}, scope_summary)
    except ValueError as exc:
        return _scope_violation_result(exc, target=target)
    decision = await _evaluate_policy(
        tool="browser",
        scope_summary=scope_summary,
        target=target,
        method="GET",
        action_class="low_impact",
        risk_class="low_impact",
        browser_actions=["click"],
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=target)
    return await browser_executor.execute(
        {
            "actions": [{"type": "click", "selector": selector}],
            "capture_har": True,
            "capture_screenshots": True,
            "extract_console": True,
            "context": {},
        },
        url=target,
    )


async def _browser_fill(
    arguments: dict,
    scope_summary: dict,
    *,
    browser_executor: ChimeraBrowserMediator | None = None,
) -> dict:
    if browser_executor is None:
        return {"error": "browser_session_required", "detail": "browser_fill requires a mediated browser session"}
    fields = arguments.get("fields") or {}
    if not isinstance(fields, dict) or not fields:
        return {"error": "missing_fields"}
    url = str(arguments.get("url") or "")
    target = url or None
    try:
        if target:
            _ensure_agent_scope({"url": target}, scope_summary)
    except ValueError as exc:
        return _scope_violation_result(exc, target=target)
    decision = await _evaluate_policy(
        tool="browser",
        scope_summary=scope_summary,
        target=target,
        method="GET",
        action_class="low_impact",
        risk_class="low_impact",
        browser_actions=["fill"],
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=target)
    actions = [{"type": "fill", "selector": str(selector), "value": str(value)} for selector, value in fields.items()]
    return await browser_executor.execute(
        {
            "actions": actions,
            "capture_har": True,
            "capture_screenshots": True,
            "extract_console": True,
            "context": {},
        },
        url=target,
    )


async def _browser_execute_js(
    arguments: dict,
    scope_summary: dict,
    *,
    browser_executor: ChimeraBrowserMediator | None = None,
) -> dict:
    if browser_executor is None:
        return {"error": "browser_session_required", "detail": "browser_execute_js requires a mediated browser session"}
    js_code = str(arguments.get("js_code") or "").strip()
    url = str(arguments.get("url") or "")
    if not js_code:
        return {"error": "missing_js_code"}
    target = url or None
    try:
        if target:
            _ensure_agent_scope({"url": target}, scope_summary)
    except ValueError as exc:
        return _scope_violation_result(exc, target=target)
    decision = await _evaluate_policy(
        tool="browser",
        scope_summary=scope_summary,
        target=target,
        method="GET",
        action_class="low_impact",
        risk_class="low_impact",
        browser_actions=["execute_js"],
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=target)
    return await browser_executor.execute(
        {
            "actions": [{"type": "execute_js", "js_code": js_code}],
            "capture_har": True,
            "capture_screenshots": True,
            "extract_console": True,
            "context": {},
        },
        url=target,
    )


async def _browser_get_console(
    arguments: dict,
    scope_summary: dict,
    *,
    browser_executor: ChimeraBrowserMediator | None = None,
) -> dict:
    if browser_executor is None:
        return {"error": "browser_session_required", "detail": "browser_get_console requires a mediated browser session"}
    limit = int(arguments.get("limit") or 50)
    decision = await _evaluate_policy(
        tool="browser",
        scope_summary=scope_summary,
        target=None,
        method="GET",
        action_class="passive",
        risk_class="passive",
        browser_actions=["extract_console"],
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision)
    result = await browser_executor.get_console(limit=max(1, min(limit, 2000)))
    return {
        "browser_session_id": result.get("session", {}).get("session_id") or result.get("session_id"),
        "count": result.get("count"),
        "console": result.get("console"),
        "artifact_ref": result.get("artifact_ref"),
        "capture_artifact_ref": result.get("capture_artifact_ref"),
    }


async def _browser_get_network(
    arguments: dict,
    scope_summary: dict,
    *,
    browser_executor: ChimeraBrowserMediator | None = None,
) -> dict:
    if browser_executor is None:
        return {"error": "browser_session_required", "detail": "browser_get_network requires a mediated browser session"}
    limit = int(arguments.get("limit") or 50)
    decision = await _evaluate_policy(
        tool="browser",
        scope_summary=scope_summary,
        target=None,
        method="GET",
        action_class="passive",
        risk_class="passive",
        browser_actions=["extract_dom"],
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision)
    result = await browser_executor.get_network(limit=max(1, min(limit, 2000)))
    return {
        "browser_session_id": result.get("session", {}).get("session_id") or result.get("session_id"),
        "count": result.get("count"),
        "network": result.get("network"),
        "artifact_ref": result.get("artifact_ref"),
        "capture_artifact_ref": result.get("capture_artifact_ref"),
    }


async def _terminal_start(arguments: dict, req: AgentRequest) -> dict:
    command = [str(item) for item in list(arguments.get("command") or [])]
    if not command:
        return {"error": "missing_command"}
    target = str(arguments.get("target") or (req.targets[0] if req.targets else "")).strip() or None
    if target:
        try:
            _ensure_agent_scope({"url": target}, req.scope_summary)
        except ValueError as exc:
            return _scope_violation_result(exc, target=target)
    decision = await _evaluate_policy(
        tool="terminal",
        scope_summary=req.scope_summary,
        target=target,
        action_class="low_impact",
        risk_class="low_impact",
        command=command,
        has_env_vars=any("=" in item and not item.startswith("http") for item in command[1:]),
        metadata={"binary": command[0]},
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=target)
    try:
        result = await _terminal_mediator().start(
            command=command,
            run_id=req.run_id,
            target=target,
            scope_summary=_policy_scope_summary(req.scope_summary),
            cwd=str(arguments.get("cwd") or "").strip() or None,
            cols=max(40, min(int(arguments.get("cols") or 120), 400)),
            rows=max(10, min(int(arguments.get("rows") or 36), 200)),
        )
    except Exception as exc:
        return {"error": "terminal_request_failed", "detail": str(exc), "target": target}
    return _terminal_tool_result(result)


async def _terminal_write(arguments: dict, req: AgentRequest) -> dict:
    session_id = str(arguments.get("session_id") or "").strip()
    data = str(arguments.get("data") or "")
    if not session_id:
        return {"error": "missing_session_id"}
    decision = await _evaluate_policy(
        tool="terminal",
        scope_summary=req.scope_summary,
        action_class="low_impact",
        risk_class="low_impact",
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision)
    try:
        result = await _terminal_mediator().write(session_id, data=data)
    except Exception as exc:
        return {"error": "terminal_request_failed", "detail": str(exc), "terminal_session_id": session_id}
    return _terminal_tool_result(result)


async def _terminal_read(arguments: dict, req: AgentRequest) -> dict:
    session_id = str(arguments.get("session_id") or "").strip()
    if not session_id:
        return {"error": "missing_session_id"}
    decision = await _evaluate_policy(
        tool="terminal",
        scope_summary=req.scope_summary,
        action_class="passive",
        risk_class="passive",
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision)
    try:
        result = await _terminal_mediator().read(
            session_id,
            max_bytes=max(1, min(int(arguments.get("max_bytes") or 8192), 65536)),
            timeout_ms=max(0, min(int(arguments.get("timeout_ms") or 50), 5000)),
        )
    except Exception as exc:
        return {"error": "terminal_request_failed", "detail": str(exc), "terminal_session_id": session_id}
    return _terminal_tool_result(result)


async def _terminal_resize(arguments: dict, req: AgentRequest) -> dict:
    session_id = str(arguments.get("session_id") or "").strip()
    if not session_id:
        return {"error": "missing_session_id"}
    decision = await _evaluate_policy(
        tool="terminal",
        scope_summary=req.scope_summary,
        action_class="low_impact",
        risk_class="low_impact",
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision)
    try:
        result = await _terminal_mediator().resize(
            session_id,
            cols=max(40, min(int(arguments.get("cols") or 120), 400)),
            rows=max(10, min(int(arguments.get("rows") or 36), 200)),
        )
    except Exception as exc:
        return {"error": "terminal_request_failed", "detail": str(exc), "terminal_session_id": session_id}
    return _terminal_tool_result(result)


async def _terminal_close(arguments: dict, req: AgentRequest) -> dict:
    session_id = str(arguments.get("session_id") or "").strip()
    if not session_id:
        return {"error": "missing_session_id"}
    decision = await _evaluate_policy(
        tool="terminal",
        scope_summary=req.scope_summary,
        action_class="low_impact",
        risk_class="low_impact",
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision)
    try:
        result = await _terminal_mediator().close(session_id)
    except Exception as exc:
        return {"error": "terminal_request_failed", "detail": str(exc), "terminal_session_id": session_id}
    return _terminal_tool_result(result)


async def _shell_run_scoped(arguments: dict, scope_summary: dict) -> dict:
    command = list(arguments.get("command") or [])
    if not command:
        return {"error": "missing command"}
    command_targets = extract_targets_from_command(command)
    if command_targets:
        try:
            _ensure_agent_scope({"targets": command_targets}, scope_summary)
        except ValueError as exc:
            return _scope_violation_result(exc, target=command_targets)
    allowlisted = {"curl", "httpx", "subfinder", "nuclei", "dalfox", "nmap", "katana"}
    if command[0] not in allowlisted:
        return {"error": "command_not_allowed", "command": command[0]}
    decision = await _evaluate_policy(
        tool="shell",
        scope_summary=scope_summary,
        target=command_targets[0] if command_targets else None,
        action_class="low_impact",
        risk_class="low_impact",
        command=command,
        has_env_vars=any("=" in arg and not arg.startswith("http") for arg in command[1:]),
        metadata={"binary": command[0]},
    )
    if decision.get("decision") != "allow":
        return _policy_block_result(decision, target=command_targets[0] if command_targets else None)
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return {"error": "command_not_found", "command": command[0]}
    stdout, stderr = await proc.communicate()
    return {
        "command": command,
        "returncode": int(proc.returncode or 0),
        "stdout": stdout.decode("utf-8", errors="replace")[:4000],
        "stderr": stderr.decode("utf-8", errors="replace")[:2000],
    }


# ---------------------------------------------------------------------------
# Analysis entrypoint
# ---------------------------------------------------------------------------

async def _run_analysis(task_id: str, query: str) -> None:
    if PROVIDER != "openai_compatible":
        await _run_analysis_single(task_id, query)
        return

    raw_plan = raw_findings = raw_final = ""
    total_usage: dict = _base_usage_dict()
    try:
        clipped = _clip_to_budget(query)

        # Stage 1: Planner (temp=0 for determinism)
        logger.info("Task %s [1/3] planner=%s", task_id, PLANNER_MODEL)
        raw_plan, u1 = await _call_model(PLANNER_MODEL, PLANNER_SYSTEM_PROMPT, clipped)
        _save_raw_llm_artifact(raw_plan, f"{task_id}_s1_plan")
        _accumulate_usage(total_usage, u1)
        plan_data = _parse_stage("planner", raw_plan)

        # Stage 1.5: Auto-probe — Chimera dispatches HexStrike per check (no LLM)
        probe_results: List[Dict[str, Any]] = []
        if HEXSTRIKE_ENABLED:
            checks = plan_data.get("checks", [])
            logger.info("Task %s [1.5/3] auto-probing %d check(s) via HexStrike", task_id, len(checks))
            probe_results = await _auto_probe_checks(task_id, checks, clipped)
            logger.info("Task %s auto-probe complete: %d result(s)", task_id, len(probe_results))

        # Stage 2: Executor — receives plan + probe results, returns grounded findings
        logger.info("Task %s [2/3] executor=%s", task_id, EXECUTOR_MODEL)
        executor_input = json.dumps({"query": clipped, "plan": plan_data, "probe_results": probe_results})
        raw_findings, u2 = await _call_model(EXECUTOR_MODEL, EXECUTOR_SYSTEM_PROMPT, executor_input)
        _save_raw_llm_artifact(raw_findings, f"{task_id}_s2_findings")
        _accumulate_usage(total_usage, u2)
        findings_data = _parse_stage("executor", raw_findings)

        # Stage 3: Validator (temp=0 for determinism)
        logger.info("Task %s [3/3] validator=%s", task_id, VALIDATOR_MODEL)
        validator_input = json.dumps({"query": clipped, "findings": findings_data.get("findings", [])})
        raw_final, u3 = await _call_model(VALIDATOR_MODEL, VALIDATOR_SYSTEM_PROMPT, validator_input)
        _save_raw_llm_artifact(raw_final, f"{task_id}_s3_final")
        _accumulate_usage(total_usage, u3)
        final_data = _parse_stage("validator", raw_final)

        findings: List[Dict[str, Any]] = final_data.get("findings", [])
        _tasks[task_id] = {
            "status": "completed",
            "findings": findings,
            "provider": PROVIDER,
            "model": f"{PLANNER_MODEL}|{EXECUTOR_MODEL}|{VALIDATOR_MODEL}",
            "stages": {
                "planner":   PLANNER_MODEL,
                "executor":  EXECUTOR_MODEL,
                "validator": VALIDATOR_MODEL,
            },
            "usage": _usage_with_metadata(
                total_usage,
                provider_family="openai_compatible",
                provider_preset="openai_compatible",
                model=f"{PLANNER_MODEL}|{EXECUTOR_MODEL}|{VALIDATOR_MODEL}",
                prompt_caching_enabled=False,
                prompt_cache_ttl=None,
            ),
        }
        logger.info("Task %s completed with %d findings", task_id, len(findings))

    except Exception as exc:
        snippet = (raw_final or raw_findings or raw_plan)[:500]
        logger.error("Task %s chain failed: %s", task_id, exc)
        _tasks[task_id] = {
            "status": "failed",
            "error": str(exc),
            "raw_output": snippet,
            "findings": [],
            "provider": PROVIDER,
            "model": f"{PLANNER_MODEL}|{EXECUTOR_MODEL}|{VALIDATOR_MODEL}",
        }


async def _run_analysis_single(task_id: str, query: str) -> None:
    """Original single-call flow used by the Anthropic provider."""
    raw_text = ""
    usage = None
    try:
        clipped_query = _clip_to_budget(query)
        logger.info("Task %s: calling provider=%s model=%s", task_id, PROVIDER, MODEL)
        raw_text, usage = await _generate_response_text_with_usage(clipped_query)

        _save_raw_llm_artifact(raw_text, task_id)

        coerced = _coerce_json_object(raw_text)
        try:
            data = json.loads(coerced)
        except json.JSONDecodeError:
            logger.warning(
                "Task %s: initial response not JSON (first 120 chars: %r); retrying with repair prompt",
                task_id,
                raw_text[:120],
            )
            repair_query = f"{REPAIR_PROMPT}\n\nOriginal query: {clipped_query[:500]}"
            raw_text, usage = await _generate_response_text_with_usage(repair_query)
            _save_raw_llm_artifact(raw_text, task_id)
            coerced = _coerce_json_object(raw_text)
            data = json.loads(coerced)

        findings: List[Dict[str, Any]] = data.get("findings", [])
        task_record: Dict[str, Any] = {
            "status": "completed",
            "findings": findings,
            "provider": PROVIDER,
            "model": MODEL,
        }
        task_record["usage"] = _usage_with_metadata(
            usage,
            provider_family="anthropic" if PROVIDER == "anthropic" else "openai_compatible",
            provider_preset="anthropic" if PROVIDER == "anthropic" else "openai_compatible",
            model=MODEL,
            prompt_caching_enabled=bool(PROVIDER == "anthropic" and ANTHROPIC_PROMPT_CACHING),
            prompt_cache_ttl=ANTHROPIC_PROMPT_CACHE_TTL if PROVIDER == "anthropic" else None,
        )
        _tasks[task_id] = task_record
        logger.info("Task %s completed with %d findings", task_id, len(findings))

    except json.JSONDecodeError as exc:
        snippet = raw_text[:500] if raw_text else "(empty)"
        logger.error("Task %s JSON parse error after retry: %s", task_id, exc)
        logger.error("Task %s raw_output snippet: %r", task_id, snippet)
        _tasks[task_id] = {
            "status": "failed",
            "error": f"JSON parse error: {exc}",
            "raw_output": snippet,
            "findings": [],
            "provider": PROVIDER,
            "model": MODEL,
        }
    except Exception as exc:
        snippet = raw_text[:500] if raw_text else "(empty)"
        logger.error("Task %s failed: %s", task_id, exc)
        _tasks[task_id] = {
            "status": "failed",
            "error": str(exc),
            "raw_output": snippet,
            "findings": [],
            "provider": PROVIDER,
            "model": MODEL,
        }


# ---------------------------------------------------------------------------
# LLM client functions
# ---------------------------------------------------------------------------

async def _call_model(model: str, system_prompt: str, user_content: str, temperature: float = TEMPERATURE) -> "tuple[str, dict | None]":
    """Call a specific model via the OpenAI-compatible backend. Returns (text, usage_or_None)."""
    client = AsyncOpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
    response = await client.chat.completions.create(
        model=model,
        temperature=temperature,
        max_tokens=MAX_TOKENS,
        response_format={"type": "json_object"},
        # Pass Ollama-specific options to improve reliability
        extra_body={"options": {"num_ctx": LOCAL_LLM_MAX_TOKENS, "mirostat": 2}},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_content},
        ],
    )
    if not response.choices:
        raise RuntimeError(f"Model {model} returned no choices")
    text = _extract_text_content(response.choices[0].message.content)
    return text, _response_usage_dict(response)


async def _call_model_text(model: str, system_prompt: str, user_content: str) -> "tuple[str, dict | None]":
    """Call model in free-text mode (no JSON constraint) so it can emit <hexstrike_call> tags."""
    client = AsyncOpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
    response = await client.chat.completions.create(
        model=model,
        temperature=TEMPERATURE,
        max_tokens=MAX_TOKENS,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_content},
        ],
    )
    if not response.choices:
        raise RuntimeError(f"Model {model} returned no choices")
    text = _extract_text_content(response.choices[0].message.content)
    return text, _response_usage_dict(response)


async def _generate_response_text_with_usage(query: str):
    """Return (text, usage_dict_or_None) for the LLM response. Used by Anthropic path."""
    if PROVIDER == "anthropic":
        return await _generate_anthropic_response_with_usage(query)
    if PROVIDER == "openai_compatible":
        return await _generate_openai_compatible_response_with_usage(query)
    raise RuntimeError(
        "Unsupported SHANNON_PROVIDER. Expected 'anthropic', 'openai', or 'openai_compatible'."
    )


async def _generate_response_text(query: str) -> str:
    text, _ = await _generate_response_text_with_usage(query)
    return text


async def _generate_anthropic_response(query: str) -> str:
    text, _ = await _generate_anthropic_response_with_usage(query)
    return text


async def _generate_anthropic_response_with_usage(query: str):
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not configured")

    client = anthropic.AsyncAnthropic(api_key=api_key)
    kwargs: Dict[str, Any] = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": query}],
    }
    if ANTHROPIC_PROMPT_CACHING:
        cache_control: Dict[str, str] = {"type": "ephemeral"}
        if _normalized_cache_ttl(ANTHROPIC_PROMPT_CACHE_TTL) == "1h":
            cache_control["ttl"] = "1h"
        kwargs["cache_control"] = cache_control
    message = await client.messages.create(**kwargs)
    return _extract_text_content(message.content), _response_usage_dict(message)


async def _generate_openai_compatible_response(query: str) -> str:
    text, _ = await _generate_openai_compatible_response_with_usage(query)
    return text


async def _generate_openai_compatible_response_with_usage(query: str):
    client = AsyncOpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
    kwargs: dict = dict(
        model=MODEL,
        temperature=TEMPERATURE,
        max_tokens=MAX_TOKENS,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": query},
        ],
    )
    kwargs["response_format"] = {"type": "json_object"}
    response = await client.chat.completions.create(**kwargs)
    if not response.choices:
        raise RuntimeError("OpenAI-compatible backend returned no choices")
    text = _extract_text_content(response.choices[0].message.content)
    return text, _response_usage_dict(response)


def _extract_text_content(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict):
                text = item.get("text")
                if text:
                    parts.append(str(text))
                continue
            text = getattr(item, "text", None)
            if text:
                parts.append(str(text))
        return "\n".join(part.strip() for part in parts if part).strip()

    text = getattr(content, "text", None)
    if text:
        return str(text).strip()

    raise RuntimeError("LLM response did not include text content")


def _coerce_json_object(text: str) -> str:
    cleaned = text.strip()

    if "```" in cleaned:
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
        if fenced:
            cleaned = fenced.group(1).strip()
        else:
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned).strip()

    if not cleaned.startswith("{"):
        obj_match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if obj_match:
            cleaned = obj_match.group(0)

    return cleaned

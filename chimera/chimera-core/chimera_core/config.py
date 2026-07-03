import json
import os
from pathlib import Path
from typing import Any, Dict


def _default_agent_provider() -> str:
    explicit = os.getenv("CHIMERA_AGENT_PROVIDER")
    if explicit:
        return explicit
    if os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.getenv("NVIDIA_API_KEY"):
        return "nvidia_nim"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    return "ollama"


def _default_agent_model(provider: str) -> str:
    if provider == "anthropic":
        return "claude-sonnet-4-20250514"
    if provider == "nvidia_nim":
        return "meta/llama-4-maverick-17b-128e-instruct"
    if provider == "openai":
        return "gpt-4o"
    if provider == "ollama":
        return "qwen2.5-coder:7b"
    return ""


def _default_agent_base_url(provider: str) -> str:
    if provider == "nvidia_nim":
        return "https://integrate.api.nvidia.com/v1"
    if provider == "openai":
        return os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    if provider == "ollama":
        return "http://ollama:11434/v1"
    return ""


def _default_role_provider(provider: str, role: str) -> str:
    if role == "report":
        return os.getenv("CHIMERA_REPORT_PROVIDER", "ollama")
    if role == "exploit":
        return os.getenv("CHIMERA_EXPLOIT_PROVIDER", os.getenv("CHIMERA_ANALYSIS_PROVIDER", provider))
    if role == "analysis":
        return os.getenv("CHIMERA_ANALYSIS_PROVIDER", provider)
    return provider


def _default_role_model(provider: str, role: str, fallback: str) -> str:
    env_name = {
        "analysis": "CHIMERA_ANALYSIS_MODEL",
        "exploit": "CHIMERA_EXPLOIT_MODEL",
        "report": "CHIMERA_REPORT_MODEL",
    }.get(role)
    if env_name and os.getenv(env_name):
        return str(os.getenv(env_name))
    if role == "report":
        return fallback
    return fallback


def _default_role_base_url(provider: str, role: str, fallback: str) -> str:
    env_name = {
        "analysis": "CHIMERA_ANALYSIS_BASE_URL",
        "exploit": "CHIMERA_EXPLOIT_BASE_URL",
        "report": "CHIMERA_REPORT_BASE_URL",
    }.get(role)
    if env_name and os.getenv(env_name):
        return str(os.getenv(env_name))
    if role == "analysis" and provider != _default_agent_provider():
        return _default_agent_base_url(provider)
    return fallback

def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"true", "1", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _get_default_config() -> Dict[str, Any]:
    """
    Generate default config with supabase auto-enabled if env vars are present.
    Also loads security tool permissions from environment.
    """
    supabase_enabled = _env_bool(
        "CHIMERA_SUPABASE_ENABLED",
        bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY")),
    )

    # Parse allowed binaries from env
    allowed_binaries_env = os.getenv("CHIMERA_ALLOWED_BINARIES", "")
    if allowed_binaries_env:
        allowed_binaries = [b.strip() for b in allowed_binaries_env.split(",") if b.strip()]
    else:
        # Default safe binaries
        allowed_binaries = ["python", "python3", "autoswagger", "strix", "zap", "curl", "httpx", "subfinder", "nc", "netcat"]

    # Parse allow_destructive flag
    allow_destructive = os.getenv("CHIMERA_ALLOW_DESTRUCTIVE", "false").lower() in {"true", "1", "yes"}
    shannon_base_url = os.getenv("SHANNON_BASE_URL", "http://localhost:18080").rstrip("/")
    agent_provider = _default_agent_provider()
    agent_model = os.getenv("CHIMERA_AGENT_MODEL", _default_agent_model(agent_provider))
    agent_base_url = os.getenv("CHIMERA_AGENT_BASE_URL", _default_agent_base_url(agent_provider))
    autonomous_enabled = _env_bool("CHIMERA_SHANNON_AUTONOMOUS_ENABLED", True)
    autonomous_provider = os.getenv("CHIMERA_SHANNON_AUTONOMOUS_PROVIDER_PRESET", agent_provider)
    autonomous_model = os.getenv("CHIMERA_SHANNON_AUTONOMOUS_MODEL", _default_agent_model(autonomous_provider))
    autonomous_base_url = os.getenv("CHIMERA_SHANNON_AUTONOMOUS_BASE_URL", _default_agent_base_url(autonomous_provider))

    return {
        "project": {
            "name": "chimera",
            "workspace": "./workspaces/default",
        },
        "logging": {
            "level": "INFO",
        },
        "events": {
            "enabled": True,
        },
        "supabase": {
            "enabled": supabase_enabled,
        },
        "security": {
            "allowed_binaries": allowed_binaries,
            "allow_destructive": allow_destructive,
            "destructive_tools": ["sqlmap", "ffuf", "hydra", "wfuzz"],
        },
        "shannon": {
            "enabled": _env_bool("CHIMERA_SHANNON_ENABLED", True),
            "verify_availability": _env_bool("CHIMERA_SHANNON_VERIFY_AVAILABILITY", True),
            "mode": "verify",
            "driver": "http",
            "base_url": shannon_base_url,
            "healthcheck_url": os.getenv("SHANNON_HEALTHCHECK_URL", f"{shannon_base_url}/health"),
            "availability_timeout_s": _env_float("SHANNON_AVAILABILITY_TIMEOUT_S", 2.0),
            "vuln_types": ["injection", "xss", "ssrf", "broken_auth", "authz", "upload", "business_logic"],
            "output_file": "findings.json",
            "allowed_binaries": allowed_binaries,
            "oracle": {
                "enabled": _env_bool("SHANNON_ORACLE_ENABLED", True),
                "provider": os.getenv("SHANNON_ORACLE_PROVIDER", "openai"),
                "model": os.getenv("SHANNON_ORACLE_MODEL", "gpt-5.4"),
                "base_url": os.getenv("SHANNON_ORACLE_BASE_URL", os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")),
                "reasoning": os.getenv("SHANNON_ORACLE_REASONING", "medium"),
                "max_turns": int(os.getenv("SHANNON_ORACLE_MAX_TURNS", "6")),
                "max_tool_calls": int(os.getenv("SHANNON_ORACLE_MAX_TOOL_CALLS", "12")),
            },
            "autonomous": {
                "enabled": autonomous_enabled,
                "task_runtime": os.getenv("CHIMERA_SHANNON_AUTONOMOUS_RUNTIME", "autonomous"),
                "provider_preset": autonomous_provider,
                "model": autonomous_model,
                "base_url": autonomous_base_url,
                "max_turns": int(os.getenv("CHIMERA_SHANNON_AUTONOMOUS_MAX_TURNS", os.getenv("CHIMERA_AGENT_MAX_TURNS", "200"))),
                "max_tool_calls": int(os.getenv("CHIMERA_SHANNON_AUTONOMOUS_MAX_TOOL_CALLS", "16")),
                "max_retries": int(os.getenv("CHIMERA_SHANNON_AUTONOMOUS_MAX_RETRIES", "1")),
                "reasoning_effort": os.getenv("CHIMERA_SHANNON_AUTONOMOUS_REASONING_EFFORT") or None,
                "repo_path": os.getenv("CHIMERA_SHANNON_AUTONOMOUS_REPO_PATH") or os.getenv("CHIMERA_REPO_PATH") or None,
                "browser_session_id": os.getenv("CHIMERA_SHANNON_BROWSER_SESSION_ID") or None,
                "auto_create_browser_session": _env_bool("CHIMERA_SHANNON_AUTO_CREATE_BROWSER_SESSION", True),
                "browser_session_mode": os.getenv("CHIMERA_SHANNON_BROWSER_SESSION_MODE", "mediated"),
                "zap_mcp_enabled": _env_bool("CHIMERA_SHANNON_ZAP_MCP_ENABLED", True),
                "role_assignments": {
                    "analysis": {
                        "provider_preset": _default_role_provider(autonomous_provider, "analysis"),
                        "model": _default_role_model(_default_role_provider(autonomous_provider, "analysis"), "analysis", autonomous_model),
                        "base_url": _default_role_base_url(_default_role_provider(autonomous_provider, "analysis"), "analysis", autonomous_base_url),
                        "max_turns": int(os.getenv("CHIMERA_ANALYSIS_MAX_TURNS", os.getenv("CHIMERA_SHANNON_AUTONOMOUS_MAX_TURNS", os.getenv("CHIMERA_AGENT_MAX_TURNS", "200")))),
                    },
                    "exploit": {
                        "provider_preset": _default_role_provider(autonomous_provider, "exploit"),
                        "model": _default_role_model(_default_role_provider(autonomous_provider, "exploit"), "exploit", autonomous_model),
                        "base_url": _default_role_base_url(_default_role_provider(autonomous_provider, "exploit"), "exploit", autonomous_base_url),
                        "max_turns": int(os.getenv("CHIMERA_EXPLOIT_MAX_TURNS", os.getenv("CHIMERA_SHANNON_AUTONOMOUS_MAX_TURNS", os.getenv("CHIMERA_AGENT_MAX_TURNS", "200")))),
                    },
                    "report": {
                        "provider_preset": _default_role_provider(autonomous_provider, "report"),
                        "model": _default_role_model(_default_role_provider(autonomous_provider, "report"), "report", autonomous_model),
                        "base_url": _default_role_base_url(_default_role_provider(autonomous_provider, "report"), "report", autonomous_base_url),
                        "max_turns": int(os.getenv("CHIMERA_REPORT_MAX_TURNS", "40")),
                    },
                },
            },
        },
        "agent": {
            "provider": agent_provider,
            "model": agent_model,
            "base_url": agent_base_url,
            "max_turns": int(os.getenv("CHIMERA_AGENT_MAX_TURNS", "200")),
            "max_input_tokens": int(os.getenv("CHIMERA_AGENT_MAX_INPUT_TOKENS", "5000000")),
            "max_output_tokens": int(os.getenv("CHIMERA_AGENT_MAX_OUTPUT_TOKENS", "500000")),
            "repo_path": os.getenv("CHIMERA_REPO_PATH") or None,
            "role_assignments": {
                "analysis": {
                    "provider": os.getenv("CHIMERA_ANALYSIS_PROVIDER", agent_provider),
                    "model": os.getenv("CHIMERA_ANALYSIS_MODEL", agent_model),
                    "base_url": os.getenv("CHIMERA_ANALYSIS_BASE_URL", agent_base_url),
                },
                "exploit": {
                    "provider": os.getenv("CHIMERA_EXPLOIT_PROVIDER", os.getenv("CHIMERA_ANALYSIS_PROVIDER", agent_provider)),
                    "model": os.getenv("CHIMERA_EXPLOIT_MODEL", os.getenv("CHIMERA_ANALYSIS_MODEL", agent_model)),
                    "base_url": os.getenv("CHIMERA_EXPLOIT_BASE_URL", os.getenv("CHIMERA_ANALYSIS_BASE_URL", agent_base_url)),
                },
                "report": {
                    "provider": os.getenv("CHIMERA_REPORT_PROVIDER", "ollama"),
                    "model": os.getenv("CHIMERA_REPORT_MODEL", agent_model),
                    "base_url": os.getenv("CHIMERA_REPORT_BASE_URL", agent_base_url),
                },
            },
        },
        "pipeline": {
            "strategy": os.getenv("CHIMERA_PIPELINE_STRATEGY", "phased_autonomous"),
            "analysis_domains": ["injection", "xss", "ssrf", "auth", "authz", "upload", "business"],
        },
        "strix": {
            # STRIX_BIN: override the strix executable path (e.g. /app/.venv/bin/strix).
            # Defaults to the strix binary alongside chimera-core's Python interpreter.
            "binary": os.getenv("STRIX_BIN") or None,
        },
        "recon": {
            "zypheron": {
                "binary": os.getenv("ZYPHERON_BINARY", "zypheron"),
                "timeout_s": 1800,
            },
            "vibepentester": {
                "workdir": os.getenv("VIBEPENTESTER_WORKDIR", "/app/tools/vibe-pentester"),
                "timeout_s": 1800,
            },
            "decepticon": {
                "workdir": os.getenv("DECEPTICON_WORKDIR", "/app/tools/decepticon"),
                "timeout_s": 1800,
            },
        },
    }


DEFAULT_CONFIG: Dict[str, Any] = _get_default_config()


def get_config_path() -> Path:
    env_path = os.getenv("CHIMERA_CONFIG")
    if env_path:
        return Path(env_path).expanduser()
    return Path.home() / ".chimera" / "config.json"


def load_config(path: Path = None) -> Dict[str, Any]:
    config_path = path or get_config_path()
    base_config = _get_default_config()
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            file_config = json.load(handle)
            # Merge file config with defaults, preferring file values
            for key, value in file_config.items():
                if isinstance(value, dict) and key in base_config and isinstance(base_config[key], dict):
                    base_config[key].update(value)
                else:
                    base_config[key] = value
            return base_config
    return base_config


def write_default_config(path: Path = None) -> Path:
    config_path = path or get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if not config_path.exists():
        with config_path.open("w", encoding="utf-8") as handle:
            json.dump(DEFAULT_CONFIG, handle, indent=2)
    return config_path

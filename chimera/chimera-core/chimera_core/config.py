import json
import os
from pathlib import Path
from typing import Any, Dict

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
    supabase_enabled = bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY"))

    # Parse allowed binaries from env
    allowed_binaries_env = os.getenv("CHIMERA_ALLOWED_BINARIES", "")
    if allowed_binaries_env:
        allowed_binaries = [b.strip() for b in allowed_binaries_env.split(",") if b.strip()]
    else:
        # Default safe binaries
        allowed_binaries = ["python", "python3", "autoswagger", "strix", "curl", "httpx", "subfinder", "nc", "netcat"]

    # Parse allow_destructive flag
    allow_destructive = os.getenv("CHIMERA_ALLOW_DESTRUCTIVE", "false").lower() in {"true", "1", "yes"}
    shannon_base_url = os.getenv("SHANNON_BASE_URL", "http://localhost:8080").rstrip("/")

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
            "vuln_types": ["injection", "xss", "ssrf", "broken_auth"],
            "output_file": "findings.json",
            "query_template": (
                "Verify {targets} for {vuln_types} and return JSON findings with proof-of-exploit steps."
            ),
            "allowed_binaries": allowed_binaries,
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

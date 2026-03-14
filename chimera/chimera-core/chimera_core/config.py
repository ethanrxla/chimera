import json
import os
from pathlib import Path
from typing import Any, Dict

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
            "enabled": True,  # Enable Shannon for AI-powered verification
            "mode": "verify",
            "driver": "http",
            "base_url": "http://localhost:8080",
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

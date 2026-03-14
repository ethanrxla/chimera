import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import json
import yaml


DEFAULT_UNIFIED_CONFIG: Dict[str, Any] = {
    "tools": {},
}

ALLOWED_TOOL_KEYS = {
    "enabled",
    "version",
    "type",
    "binary",
    "entrypoint",
    "workdir",
    "timeout_s",
    "options",
}


def get_unified_config_path() -> Path:
    env_path = os.getenv("CHIMERA_UNIFIED_CONFIG")
    if env_path:
        return Path(env_path).expanduser()
    return Path.cwd() / "chimera_config.yml"


def load_unified_config(path: Optional[Path] = None) -> Dict[str, Any]:
    config_path = path or get_unified_config_path()
    if config_path.exists():
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        return data or {}
    return dict(DEFAULT_UNIFIED_CONFIG)


def write_default_unified_config(path: Optional[Path] = None) -> Path:
    config_path = path or get_unified_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if not config_path.exists():
        config_path.write_text(yaml.safe_dump(DEFAULT_UNIFIED_CONFIG, sort_keys=False), encoding="utf-8")
    return config_path


def validate_unified_config(config: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    tools = config.get("tools")
    if tools is None:
        errors.append("Missing required key: tools")
        return errors
    if not isinstance(tools, dict):
        errors.append("tools must be a mapping")
        return errors

    for tool_name, tool_cfg in tools.items():
        if not isinstance(tool_cfg, dict):
            errors.append(f"tools.{tool_name} must be a mapping")
            continue
        for key in tool_cfg:
            if key not in ALLOWED_TOOL_KEYS:
                errors.append(f"tools.{tool_name} has unknown key: {key}")
        if "enabled" in tool_cfg and not isinstance(tool_cfg["enabled"], bool):
            errors.append(f"tools.{tool_name}.enabled must be boolean")
        if "timeout_s" in tool_cfg and not isinstance(tool_cfg["timeout_s"], int):
            errors.append(f"tools.{tool_name}.timeout_s must be integer")
        if "entrypoint" in tool_cfg and not isinstance(tool_cfg["entrypoint"], list):
            errors.append(f"tools.{tool_name}.entrypoint must be a list")
        if "options" in tool_cfg and not isinstance(tool_cfg["options"], dict):
            errors.append(f"tools.{tool_name}.options must be a mapping")
    return errors


def set_unified_value(config: Dict[str, Any], key_path: str, value: str) -> Dict[str, Any]:
    if not key_path:
        raise ValueError("key_path is required")
    parsed_value = yaml.safe_load(value)
    parts = key_path.split(".")
    node: Dict[str, Any] = config
    for part in parts[:-1]:
        if part not in node or not isinstance(node[part], dict):
            node[part] = {}
        node = node[part]
    node[parts[-1]] = parsed_value
    return config


def save_unified_config(config: Dict[str, Any], path: Optional[Path] = None) -> Path:
    config_path = path or get_unified_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return config_path


def import_registry(registry_path: Path, dest_path: Optional[Path] = None) -> Path:
    config = load_unified_config(dest_path)
    registry = json_load(registry_path)
    tools = registry.get("tools")
    if not isinstance(tools, dict):
        raise ValueError("Registry file missing tools object")
    config.setdefault("tools", {})
    config["tools"].update(tools)
    return save_unified_config(config, dest_path)


def json_load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

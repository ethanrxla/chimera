from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from chimera_core.config_manager import load_unified_config
from chimera_core.runtime import Runtime


class ToolRunner:
    def __init__(self, runtime: Runtime) -> None:
        self.runtime = runtime
        self.config = load_unified_config()

    def tool_config(self, tool_name: str) -> Dict[str, object]:
        tools = self.config.get("tools") or {}
        tool = tools.get(tool_name) if isinstance(tools, dict) else None
        return tool if isinstance(tool, dict) else {}

    def base_command(self, tool_name: str, default_command: List[str]) -> List[str]:
        tool_cfg = self.tool_config(tool_name)
        if tool_cfg.get("enabled") is False:
            raise RuntimeError(f"Tool disabled in config: {tool_name}")
        if tool_cfg.get("type") == "docker":
            raise NotImplementedError(f"Docker tools not supported yet: {tool_name}")
        binary = tool_cfg.get("binary")
        if isinstance(binary, str) and binary:
            return [binary]
        entrypoint = tool_cfg.get("entrypoint")
        if isinstance(entrypoint, list) and entrypoint:
            return [str(item) for item in entrypoint]
        return list(default_command)

    def workdir(self, tool_name: str, default: Optional[Path] = None) -> Optional[Path]:
        tool_cfg = self.tool_config(tool_name)
        workdir = tool_cfg.get("workdir")
        if isinstance(workdir, str) and workdir:
            return Path(workdir)
        return default

    def run(
        self,
        tool_name: str,
        command: List[str],
        *,
        task_id: Optional[str] = None,
        timeout_s: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[Path] = None,
    ):
        effective_cwd = self.workdir(tool_name, cwd)
        return self.runtime.run_cmd(
            command,
            cwd=effective_cwd,
            timeout_s=timeout_s,
            env=env,
            task_id=task_id,
        )

    def run_external(
        self,
        tool_name: str,
        command: List[str],
        *,
        task_id: Optional[str] = None,
        timeout_s: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[Path] = None,
        tool_profile=None,
        mode: Optional[str] = None,
    ):
        effective_cwd = self.workdir(tool_name, cwd)
        return self.runtime.run_external_tool(
            command=command,
            cwd=effective_cwd,
            timeout_s=timeout_s,
            env=env,
            task_id=task_id,
            tool_profile=tool_profile,
            mode=mode,
        )

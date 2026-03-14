import ipaddress
import os
import socket
import subprocess
import threading
import time
from typing import Iterable, List, Optional, Set, Dict, Any
from pathlib import Path
import requests # Import requests

from chimera_core.scope import ScopeGraph, ScopePolicy
from chimera_core.ratelimit import RateLimiter
from chimera_core.sinks.base import EventSink
from chimera_core.logging import log_event, setup_logging
from chimera_core.modules.safety.policy import SafetyPolicy
from chimera_core.modules.safety.enforcer import SafetyEnforcer
from chimera_core.modules.runtime.tool_profile import ToolProfile

class RuntimeCancelledError(RuntimeError):
    pass

class ToolOutputError(Exception):
    pass

class ExternalToolTimeout(Exception):
    pass

class RuntimeReplayViolation(Exception):
    pass

class Runtime:
    def __init__(
        self,
        scope_graph: ScopeGraph,
        scope_policy: ScopePolicy,
        event_store: EventSink,
        artifacts_root: Path,
        run_id: str = "mock_run_id",
        allowed_binaries: Optional[Iterable[str]] = None,
        max_output_bytes: int = 200_000,
        cancel_event: Optional[threading.Event] = None,
        replay_mode: bool = False,
        safety_policy: Optional[SafetyPolicy] = None,
        mode: str = "fixture",
    ):
        self.scope_graph = scope_graph
        self.scope_policy = scope_policy
        self.event_store = event_store
        self.artifacts_root = artifacts_root
        self.run_id = run_id
        self.allowed_binaries: Set[str] = {name.lower() for name in (allowed_binaries or {"python", "python3", "autoswagger", "strix", "curl"})}
        self.max_output_bytes = max_output_bytes
        self.max_artifacts_bytes = 1_000_000
        self.artifacts_bytes_written = 0
        self._cap_warned = False
        self.cancel_event = cancel_event or threading.Event()
        self.active_process: Optional[subprocess.Popen] = None
        self.logger = setup_logging()
        self.replay_mode = replay_mode
        self.safety_policy = safety_policy or SafetyPolicy()
        self.safety_enforcer = SafetyEnforcer(self.safety_policy)
        self.mode = mode
        # TODO: Implement per-host rate limiting
        effective_rps = min(scope_policy.max_rps, self.safety_policy.rps)
        self.rate_limiter = RateLimiter(effective_rps)

    def _extract_targets(self, command: List[str]) -> List[str]:
        """A simple heuristic to find a URL or domain in a command list."""
        targets: List[str] = []
        for index, arg in enumerate(command):
            if index == 0:
                continue
            # Skip command flags/options
            if arg.startswith("-"):
                continue
            # URLs are definitely targets
            if arg.startswith("http://") or arg.startswith("https://"):
                targets.append(arg)
                continue
            # Skip file paths
            if "/" in arg or "\\" in arg:
                continue
            # Skip Python module names (e.g., strix.interface.main)
            # These don't have TLDs and usually have multiple segments
            if "." in arg:
                # Check if it looks like a domain (has common TLD) vs module name
                parts = arg.split(".")
                # Common TLDs - if last part is one of these, likely a domain
                tlds = {"com", "org", "net", "edu", "gov", "io", "co", "us", "uk", "dev", "app", "xyz", "me"}
                if len(parts) >= 2 and parts[-1].lower() in tlds:
                    targets.append(arg)
                    continue
                # Otherwise skip (likely a module name or version number)
            # Check for IP addresses
            try:
                ipaddress.ip_address(arg)
                targets.append(arg)
            except ValueError:
                continue
        return targets

    def _is_private_ip(self, ip: ipaddress._BaseAddress) -> bool:
        return ip.is_private or ip.is_loopback or ip.is_link_local

    def _is_ip_allowed(self, ip: ipaddress._BaseAddress) -> bool:
        if not self.scope_policy.allow_ip_targets:
            return False
        for entry in self.scope_graph.allowed_domains:
            try:
                if "/" in entry:
                    if ip in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if ip == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                continue
        return False

    def _check_target_scope(self, target: str) -> None:
        try:
            parsed = ipaddress.ip_address(target)
            if not self._is_ip_allowed(parsed):
                raise ValueError(f"Target out of scope: {target}")
            if self._is_private_ip(parsed) and not self.scope_policy.allow_private_ips:
                raise ValueError(f"Target out of scope: {target}")
            return
        except ValueError:
            pass

        if not self.scope_graph.is_in_scope(target):
            raise ValueError(f"Target out of scope: {target}")

        hostname = target
        if target.startswith("http://") or target.startswith("https://"):
            try:
                from urllib.parse import urlparse
                hostname = urlparse(target).hostname or target
            except Exception:
                hostname = target

        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return
        for info in infos:
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if self._is_private_ip(ip) and not self.scope_policy.allow_private_ips:
                raise ValueError(f"Target out of scope: {hostname}")

    def _validate_command(self, command: List[str]) -> None:
        if not command:
            raise ValueError("Command is empty")
        binary = Path(command[0]).name.lower()
        if binary.startswith("python"):
            return
        if binary not in self.allowed_binaries:
            raise ValueError(f"Command not allowed: {binary}")

        forbidden = (";", "|", "&", "$", "`", "<", ">", "\n", "\r")
        for arg in command:
            if any(token in arg for token in forbidden) or "$(" in arg or "&&" in arg or "||" in arg:
                raise ValueError(f"Suspicious argument blocked: {arg}")

    def cancel(self) -> None:
        self.cancel_event.set()
        if self.active_process and self.active_process.poll() is None:
            self.active_process.terminate()

    def _execute_subprocess(
        self,
        command: List[str],
        cwd: Optional[Path] = None,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """Wraps the subprocess call to allow for easy mocking in tests."""
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=env,
        )
        self.active_process = process
        try:
            start = time.time() if timeout is not None else None
            while True:
                if self.cancel_event.is_set():
                    process.terminate()
                    raise RuntimeCancelledError("Run cancelled")
                try:
                    stdout, stderr = process.communicate(timeout=0.2)
                    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                except subprocess.TimeoutExpired:
                    if timeout is not None and start is not None:
                        if (time.time() - start) >= timeout:
                            process.terminate()
                            raise ExternalToolTimeout("Command timed out") # Use ExternalToolTimeout
                    continue
        finally:
            self.active_process = None

    def run_cmd(
        self,
        command: List[str],
        cwd: Optional[Path] = None,
        timeout: Optional[int] = None,
        timeout_s: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        task_id: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        """
        Executes a command, enforcing scope and rate limits.
        """
        if self.cancel_event.is_set():
            raise RuntimeCancelledError("Run cancelled")
        command_id = task_id or "cmd"
        run_artifacts_dir = self.artifacts_root / self.run_id
        command_dir = run_artifacts_dir / "commands" / command_id
        command_dir.mkdir(parents=True, exist_ok=True)

        self._validate_command(command)

        self.event_store.emit({
            "event_type": "cmd_started",
            "payload": {
                "run_id": self.run_id,
                "task_id": task_id,
                "command": command,
            },
        })
        log_event(self.logger, "INFO", "cmd_started", run_id=self.run_id, task_id=task_id, command=command)

        # 1. Enforce Scope
        if self.safety_policy.enforce_scope:
            targets = self._extract_targets(command)
            for target in targets:
                self._check_target_scope(target)

        # 2. Enforce Rate Limiting
        if not self.rate_limiter.acquire():
            # TODO: Emit event for rate limit exceeded
            raise Exception("Rate limit exceeded")

        # 3. Execute Command
        effective_timeout = timeout_s if timeout_s is not None else timeout
        result = self._execute_subprocess(command, cwd=cwd, timeout=effective_timeout, env=env)

        stdout_text = result.stdout or ""
        stderr_text = result.stderr or ""
        stdout_bytes = stdout_text.encode("utf-8", errors="ignore")
        stderr_bytes = stderr_text.encode("utf-8", errors="ignore")
        if len(stdout_bytes) > self.max_output_bytes:
            stdout_text = stdout_bytes[: self.max_output_bytes].decode("utf-8", errors="ignore")
            self.event_store.emit({
                "event_type": "output_truncated",
                "payload": {
                    "run_id": self.run_id,
                    "task_id": task_id,
                    "stream": "stdout",
                    "original_bytes": len(stdout_bytes),
                    "kept_bytes": len(stdout_text.encode("utf-8", errors="ignore")),
                },
            })
            log_event(self.logger, "WARNING", "output_truncated", run_id=self.run_id, task_id=task_id, stream="stdout", original_bytes=len(stdout_bytes))
        if len(stderr_bytes) > self.max_output_bytes:
            stderr_text = stderr_bytes[: self.max_output_bytes].decode("utf-8", errors="ignore")
            self.event_store.emit({
                "event_type": "output_truncated",
                "payload": {
                    "run_id": self.run_id,
                    "task_id": task_id,
                    "stream": "stderr",
                    "original_bytes": len(stderr_bytes),
                    "kept_bytes": len(stderr_text.encode("utf-8", errors="ignore")),
                },
            })
            log_event(self.logger, "WARNING", "output_truncated", run_id=self.run_id, task_id=task_id, stream="stderr", original_bytes=len(stderr_bytes))

        total_bytes = len(stdout_text.encode("utf-8", errors="ignore")) + len(stderr_text.encode("utf-8", errors="ignore"))
        projected = self.artifacts_bytes_written + total_bytes
        if projected > self.max_artifacts_bytes:
            if not self._cap_warned:
                self.event_store.emit({
                    "event_type": "run_limit_warning",
                    "payload": {
                        "run_id": self.run_id,
                        "task_id": task_id,
                        "limit_bytes": self.max_artifacts_bytes,
                    },
                })
                log_event(self.logger, "WARNING", "run_limit_warning", run_id=self.run_id, task_id=task_id, limit_bytes=self.max_artifacts_bytes)
                self._cap_warned = True
            allowed = max(self.max_artifacts_bytes - self.artifacts_bytes_written, 0)
            combined = (stdout_text + stderr_text).encode("utf-8", errors="ignore")
            combined = combined[:allowed]
            stdout_text = combined.decode("utf-8", errors="ignore")
            stderr_text = ""
            total_bytes = len(stdout_text.encode("utf-8", errors="ignore"))
        self.artifacts_bytes_written += total_bytes

        stdout_path = command_dir / "stdout.txt"
        stderr_path = command_dir / "stderr.txt"
        stdout_path.write_text(stdout_text, encoding="utf-8")
        stderr_path.write_text(stderr_text, encoding="utf-8")

        self.event_store.emit({
            "event_type": "artifact_saved",
            "payload": {
                "run_id": self.run_id,
                "task_id": task_id,
                "path": str(stdout_path),
                "stream": "stdout",
            },
        })
        log_event(self.logger, "INFO", "artifact_saved", run_id=self.run_id, task_id=task_id, path=str(stdout_path), stream="stdout")
        self.event_store.emit({
            "event_type": "artifact_saved",
            "payload": {
                "run_id": self.run_id,
                "task_id": task_id,
                "path": str(stderr_path),
                "stream": "stderr",
            },
        })
        log_event(self.logger, "INFO", "artifact_saved", run_id=self.run_id, task_id=task_id, path=str(stderr_path), stream="stderr")
        self.event_store.emit({
            "event_type": "cmd_finished",
            "payload": {
                "run_id": self.run_id,
                "task_id": task_id,
                "returncode": result.returncode,
            },
        })
        log_event(self.logger, "INFO", "cmd_finished", run_id=self.run_id, task_id=task_id, returncode=result.returncode)

        return result

    def run_external_tool(
        self,
        command: List[str],
        cwd: Optional[Path] = None,
        timeout: Optional[int] = None,
        timeout_s: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        task_id: Optional[str] = None,
        tool_profile: Optional[ToolProfile] = None,
        mode: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        """
        Executes external tooling, respecting replay safety locks.
        """
        if self.replay_mode:
            raise RuntimeReplayViolation("External execution blocked in replay mode")
        run_mode = mode or self.mode
        tool_name = tool_profile.name if tool_profile else Path(command[0]).name
        scope_ok = True
        if self.safety_policy.enforce_scope:
            try:
                for target in self._extract_targets(command):
                    self._check_target_scope(target)
            except ValueError:
                scope_ok = False
        effective_timeout = self.safety_enforcer.check_before_external_exec(
            tool=tool_name,
            cmd=command,
            mode=run_mode,
            scope_ok=scope_ok,
            timeout_s=timeout_s,
            tool_profile=tool_profile,
        )
        return self.run_cmd(
            command=command,
            cwd=cwd,
            timeout=timeout,
            timeout_s=effective_timeout,
            env=env,
            task_id=task_id,
        )

    def _request(
        self,
        method: str,
        service: str,
        path: str,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        auth: Optional[requests.auth.HTTPBasicAuth] = None,
    ) -> requests.Response:
        # Here you would implement the actual rate limiting and retry logic
        # For now, it's a direct call using requests.
        url = f"https://api.{service}.com/v1{path}" # Assuming a consistent base URL pattern
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        # For HackerOne specifically, we'd need to fetch auth details
        if service == "hackerone":
            token_id = os.getenv("H1_TOKEN_ID")
            token_value = os.getenv("H1_TOKEN_VALUE")
            if token_id and token_value:
                auth = (token_id, token_value)
            else:
                raise ValueError("H1_TOKEN_ID and H1_TOKEN_VALUE environment variables must be set for HackerOne service.")


        response = requests.request(
            method,
            url,
            headers=headers,
            params=query,
            json=body,
            auth=auth,
            files=files,
        )
        response.raise_for_status()
        return response

    def http_get(self, service: str, path: str, query: Optional[Dict[str, Any]] = None) -> requests.Response:
        return self._request("GET", service, path, query=query)

    def http_post(self, service: str, path: str, body: Optional[Dict[str, Any]] = None) -> requests.Response:
        return self._request("POST", service, path, body=body)

    def http_patch(self, service: str, path: str, body: Optional[Dict[str, Any]] = None) -> requests.Response:
        return self._request("PATCH", service, path, body=body)

    def http_delete(self, service: str, path: str) -> requests.Response:
        return self._request("DELETE", service, path)

    def check_for_cancellation(self) -> None:
        if self.cancel_event and self.cancel_event.is_set():
            raise RuntimeCancelledError("Runtime cancelled by user.")


# These were previously duplicated or incorrectly placed
# class RuntimeCancelledError(Exception):
#     pass

# class ToolOutputError(Exception):
#     pass

# class ExternalToolTimeout(Exception):
#     pass


    

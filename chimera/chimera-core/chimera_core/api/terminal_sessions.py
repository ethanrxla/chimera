from __future__ import annotations

import asyncio
import json
import os
import pty
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class PersistentTerminalSession:
    session_id: str
    command: List[str]
    artifacts_dir: str
    cwd: Optional[str] = None
    cols: int = 120
    rows: int = 36

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()
        self._master_fd: Optional[int] = None
        self._slave_fd: Optional[int] = None
        self._process: Optional[subprocess.Popen[str]] = None
        self._artifacts_path = Path(self.artifacts_dir)
        self._artifacts_path.mkdir(parents=True, exist_ok=True)
        self._transcript_path = self._artifacts_path / "transcript.jsonl"
        self._latest_output = ""
        self._started_at = datetime.now(timezone.utc).isoformat()

    async def start(self) -> Dict[str, object]:
        async with self._lock:
            if self._process is not None:
                return self.metadata()
            master_fd, slave_fd = pty.openpty()
            self._set_winsize(slave_fd, rows=self.rows, cols=self.cols)
            self._process = subprocess.Popen(
                self.command,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                cwd=self.cwd or None,
                text=False,
                start_new_session=True,
                close_fds=True,
            )
            os.close(slave_fd)
            self._master_fd = master_fd
            self._slave_fd = None
            os.set_blocking(master_fd, False)
            self._append_transcript("system", f"started: {' '.join(self.command)}")
            return self.metadata()

    async def write(self, data: str) -> Dict[str, object]:
        async with self._lock:
            self._require_running()
            assert self._master_fd is not None
            payload = data.encode("utf-8")
            written = os.write(self._master_fd, payload)
            self._append_transcript("input", data)
            return {
                "session_id": self.session_id,
                "bytes_written": written,
                "artifact_ref": self._relative_ref(self._transcript_path),
            }

    async def read(self, *, max_bytes: int = 8192, timeout_ms: int = 50) -> Dict[str, object]:
        deadline = asyncio.get_running_loop().time() + max(timeout_ms, 0) / 1000.0
        chunks: List[bytes] = []
        async with self._lock:
            self._require_running()
            assert self._master_fd is not None
            while True:
                try:
                    chunk = os.read(self._master_fd, max_bytes)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if sum(len(item) for item in chunks) >= max_bytes:
                        break
                except BlockingIOError:
                    if chunks or asyncio.get_running_loop().time() >= deadline:
                        break
                    await asyncio.sleep(0.01)
                except OSError:
                    break
            output = b"".join(chunks).decode("utf-8", errors="replace")
            if output:
                self._latest_output = output
                self._append_transcript("output", output)
            return {
                "session_id": self.session_id,
                "output": output,
                "bytes_read": len(output.encode("utf-8")),
                "artifact_ref": self._relative_ref(self._transcript_path),
                "exit_code": self._process.poll() if self._process is not None else None,
            }

    async def resize(self, *, cols: int, rows: int) -> Dict[str, object]:
        async with self._lock:
            self._require_running()
            assert self._master_fd is not None
            self.cols = cols
            self.rows = rows
            self._set_winsize(self._master_fd, rows=rows, cols=cols)
            self._append_transcript("system", f"resize: {cols}x{rows}")
            return {
                "session_id": self.session_id,
                "cols": cols,
                "rows": rows,
                "artifact_ref": self._relative_ref(self._transcript_path),
            }

    async def close(self) -> Dict[str, object]:
        async with self._lock:
            exit_code = None
            if self._process is not None:
                if self._process.poll() is None:
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self._process.kill()
                        self._process.wait(timeout=2)
                exit_code = self._process.returncode
                self._process = None
            if self._master_fd is not None:
                os.close(self._master_fd)
                self._master_fd = None
            self._append_transcript("system", "closed")
            return {
                "session_id": self.session_id,
                "status": "closed",
                "exit_code": exit_code,
                "artifact_ref": self._relative_ref(self._transcript_path),
            }

    def metadata(self) -> Dict[str, object]:
        return {
            "session_id": self.session_id,
            "command": list(self.command),
            "cwd": self.cwd,
            "cols": self.cols,
            "rows": self.rows,
            "started_at": self._started_at,
            "artifacts_dir": str(self._artifacts_path),
            "transcript_artifact_ref": self._relative_ref(self._transcript_path),
            "latest_output": self._latest_output[-4000:],
            "status": self._status(),
            "pid": self._process.pid if self._process is not None else None,
            "exit_code": self._process.poll() if self._process is not None else None,
        }

    def _status(self) -> str:
        if self._process is None:
            return "closed"
        if self._process.poll() is None:
            return "running"
        return "exited"

    def _require_running(self) -> None:
        if self._process is None or self._master_fd is None:
            raise RuntimeError("Terminal session is not running")

    def _append_transcript(self, stream: str, data: str) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "stream": stream,
            "data": data,
        }
        with self._transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload))
            handle.write("\n")

    def _relative_ref(self, path: Path) -> str:
        return path.name

    @staticmethod
    def _set_winsize(fd: int, *, rows: int, cols: int) -> None:
        import array
        import fcntl
        import termios

        winsize = array.array("H", [rows, cols, 0, 0])
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

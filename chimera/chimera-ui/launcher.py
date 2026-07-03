import os
import subprocess
import platform
import json
import queue
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import tkinter.font as tkfont
import threading
import random
import time
import math
import platform as _platform

UNICODE_SKULL_ART = """
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠀⠈⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⠻⣿⣿⣿⣿⣿⣿⣷⡀⢸⣿⣷⠀⠀⣾⣿⡇⢀⣾⣿⣿⣿⣿⣿⣿⠟⣿⣿
⣿⣿⡆⠙⣿⣿⣿⣿⣿⣿⣄⠈⠛⠋⡰⢆⠙⠛⠁⣠⣿⣿⣿⣿⣿⣿⠋⢰⣿⣿
⣿⣿⣿⡀⠈⠻⣿⣿⣿⣿⣿⣿⣦⣤⣤⣤⣤⣴⣿⣿⣿⣿⣿⣿⠟⠁⢀⣿⣿⣿
⣿⣿⣿⣷⡀⠀⠘⢿⣿⣿⣿⡇⠘⢿⣿⣿⡿⠃⢸⣿⣿⣿⡿⠃⠀⢀⣾⣿⣿⣿
⣿⣿⣿⣿⣷⣄⠀⠀⠙⠿⣿⣿⣦⣀⠈⠁⣀⣴⣿⣿⠿⠋⠀⠀⣠⣾⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠈⠻⢿⣿⣿⣿⣿⡿⠟⠁⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⣀⣭⡿⠟⠉⠀⠀⢀⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣏⡉⢻⣿⠟⠋⠁⠀⠀⢀⣠⣴⣿⡟⢉⣹⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⠿⣿⠿⠛⢷⡄⠹⣇⣀⣠⣴⣾⣟⣉⣸⠏⢠⡾⠛⠿⣿⠿⣿⣿⣿⣿
⣿⣿⣿⡇⠀⢸⣧⣤⣾⣿⣄⣹⣿⣿⣿⣿⣿⣿⣏⣠⣿⣷⣤⣼⡇⠀⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
"""

ASCII_SKULL_ART = r"""
          .-'''''-.
        .'         `.
       /  .-'''-.    \
      /  /       \    \
      |  | .--.  |    |
      |  | |  |  |    |
      |  | '--'  |    |
      |  |  __   |    |
      \  \ (__) /    /
       \  `-..-'    /
        `.        .'
          `-....-'
"""

UNICODE_MATRIX_CHARS = "ᚻᚫᚲᚴᛖᚱ01@#$%&*!?<>/\\[]{}|=+-_"
ASCII_MATRIX_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*!?<>/\\[]{}|=+-_"


def _is_wsl() -> bool:
    try:
        return "microsoft" in _platform.uname().release.lower()
    except Exception:
        return False


def use_unicode_ui() -> bool:
    flag = os.getenv("CHIMERA_UNICODE_UI")
    if flag is not None:
        return flag not in {"0", "false", "no"}
    return not _is_wsl()


def use_unicode_matrix() -> bool:
    flag = os.getenv("CHIMERA_UNICODE_MATRIX")
    if flag is not None:
        return flag not in {"0", "false", "no"}
    return use_unicode_ui()


def use_unicode_skull() -> bool:
    flag = os.getenv("CHIMERA_UNICODE_SKULL")
    if flag is not None:
        return flag not in {"0", "false", "no"}
    return True


def pick_font_family(root, candidates, fallback):
    try:
        families = set(tkfont.families(root))
    except tk.TclError:
        families = set(tkfont.families())
    for name in candidates:
        if name in families:
            return name
    return fallback


def open_path(path: Path) -> None:
    """
    Open a path with the system's default opener.
    In headless/WSL environments, show the path instead.
    """
    if platform.system() == "Windows":
        try:
            os.startfile(str(path))
        except Exception as e:
            messagebox.showinfo("Path", f"File location:\n{path}\n\nError: {e}")
        return

    opener = "open" if platform.system() == "Darwin" else "xdg-open"
    try:
        # Check if we're in a headless environment (WSL, Docker, no DISPLAY)
        if _is_wsl() or not os.getenv("DISPLAY"):
            messagebox.showinfo("Artifact Path", f"File location:\n{path}\n\nUse 'cat' or 'less' to view in terminal.")
            return
        subprocess.run([opener, str(path)], check=False)
    except FileNotFoundError:
        messagebox.showinfo("Artifact Path", f"File location:\n{path}\n\nOpener '{opener}' not found. Use terminal to view.")


class ModernTheme:
    """Toxic cyberpunk theme with blood red accents"""
    BG_DARK = "#000000"
    BG_MEDIUM = "#0a0a0a"
    BG_LIGHT = "#1a1a1a"
    FG_DARK = "#ff0000"
    FG_LIGHT = "#ff1a1a"
    ACCENT = "#ff0000"
    ACCENT_HOVER = "#cc0000"
    ERROR = "#ff0000"
    SUCCESS = "#ff1a1a"
    WARNING = "#ff3366"
    HEADER_FG = "#ff0000"
    TEXT_SHADOW = "#330000"


class MatrixRain:
    def __init__(self, root):
        self.root = root
        self.title_font = pick_font_family(
            root,
            ["Pirata One", "Myopium", "BlackChancery", "Times New Roman"],
            tkfont.nametofont("TkDefaultFont").cget("family"),
        )
        self.matrix_font = pick_font_family(
            root,
            ["DejaVu Sans Mono", "Noto Sans Mono", "Ubuntu Mono", "Ubuntu Sans Mono", "Nimbus Mono PS", "Courier New"],
            tkfont.nametofont("TkFixedFont").cget("family"),
        )
        self.skull_font = pick_font_family(
            root,
            ["DejaVu Sans Mono", "Noto Sans Mono", "Ubuntu Mono", "Ubuntu Sans Mono", "Nimbus Mono PS", "Courier New"],
            tkfont.nametofont("TkFixedFont").cget("family"),
        )
        self.canvas = tk.Canvas(
            root,
            bg='black',
            width=1200,
            height=800
        )
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self.use_unicode_matrix = use_unicode_matrix()
        self.use_unicode_skull = use_unicode_skull()
        self.matrix_chars = UNICODE_MATRIX_CHARS if self.use_unicode_matrix else ASCII_MATRIX_CHARS
        self.streams = []
        self.is_running = True
        self.max_streams = 40
        self.frame_delay = 80

        self.root.bind('1', self.stop_animation)

        self.canvas.create_text(
            600, 400,
            text=UNICODE_SKULL_ART if self.use_unicode_skull else ASCII_SKULL_ART,
            font=(self.skull_font, 16),
            fill="#ff0000",
            anchor="center"
        )

        self.animate()

    def stop_animation(self, event=None):
        self.is_running = False
        self.canvas.destroy()
        self.root.unbind('1')
        ChimeraLauncher(self.root)

    def animate(self):
        if not self.is_running:
            return

        if random.random() < 0.2 and len(self.streams) < self.max_streams:
            for _ in range(2):
                x = random.randint(0, 1200)
                self.streams.append({
                    "x": x,
                    "y": 0,
                    "speed": random.randint(5, 20),
                    "color": random.choice([
                        "#00ff41",
                        "#cc00cc",
                        "#990099",
                        "#00cc00",
                    ]),
                    "length": random.randint(5, 15),
                    "items": []
                })

        for stream in self.streams[:]:
            y = stream["y"]
            for item in stream["items"]:
                self.canvas.delete(item)
            new_items = []

            for i in range(stream["length"]):
                char = random.choice(self.matrix_chars)

                fade = 1 - (i / stream["length"])
                opacity = int(255 * fade)
                color = stream["color"][:-2] + f"{opacity:02x}"

                drift = math.sin(y/50) * 3
                x_pos = stream["x"] + drift

                item_id = self.canvas.create_text(
                    x_pos, y - i*15,
                    text=char,
                    font=(self.matrix_font, 14),
                    fill=color,
                    tags="rain"
                )
                new_items.append(item_id)

                if random.random() < 0.05:
                    flash_id = self.canvas.create_text(
                        x_pos, y - i*15,
                        text=char,
                        font=(self.matrix_font, 14),
                        fill="#ffffff",
                        tags="rain"
                    )
                    new_items.append(flash_id)

            stream["y"] += stream["speed"]
            stream["items"] = new_items

            if stream["y"] > 800:
                for item in stream["items"]:
                    self.canvas.delete(item)
                self.streams.remove(stream)

        self.root.after(self.frame_delay, self.animate)



class ChimeraAPIClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def create_run(
        self,
        scope_text: str,
        live: bool,
        max_workers: int,
        live_confirm: str,
        rate_limit_rps: int,
        per_task_timeout_s: int,
        program_name: str,
    ) -> dict:
        payload = {
            "scope_text": scope_text,
            "live": live,
            "max_workers": max_workers,
            "live_confirm": live_confirm,
            "rate_limit_rps": rate_limit_rps,
            "per_task_timeout_s": per_task_timeout_s,
            "program_name": program_name,
        }
        return self._request_json("POST", "/runs", payload=payload)

    def get_run(self, run_id: str) -> dict:
        return self._request_json("GET", f"/runs/{run_id}")

    def list_runs(self, limit: int = 20, offset: int = 0) -> list:
        return self._request_json("GET", f"/runs?limit={limit}&offset={offset}")

    def plan_run(self, scope_text: str, live: bool, max_workers: int, live_confirm: str, pipeline: str = "task_runner") -> dict:
        payload = {
            "scope_text": scope_text,
            "live": live,
            "max_workers": max_workers,
            "live_confirm": live_confirm,
            "pipeline": pipeline,
        }
        return self._request_json("POST", "/runs/plan", payload=payload)

    def get_findings(self, run_id: str) -> list:
        return self._request_json("GET", f"/runs/{run_id}/findings")

    def get_findings_filtered(
        self,
        run_id: str,
        classification: str = "",
        tool: str = "",
        min_confidence: str = "",
        query: str = "",
    ) -> list:
        params = []
        if classification and classification != "ALL":
            params.append(f"classification={classification}")
        if tool and tool != "ALL":
            params.append(f"tool={tool}")
        if min_confidence:
            params.append(f"min_confidence={min_confidence}")
        if query:
            params.append(f"q={query}")
        suffix = f"?{'&'.join(params)}" if params else ""
        return self._request_json("GET", f"/runs/{run_id}/findings{suffix}")

    def get_finding_detail(self, run_id: str, stable_id: str) -> dict:
        return self._request_json("GET", f"/runs/{run_id}/findings/{stable_id}")

    def get_runs_diff(
        self,
        base_run_id: str,
        compare_run_id: str,
        classification: str = "",
    ) -> dict:
        params = [f"base_run_id={base_run_id}", f"compare_run_id={compare_run_id}"]
        if classification and classification != "ALL":
            params.append(f"classification={classification}")
        suffix = "&".join(params)
        return self._request_json("GET", f"/runs/diff?{suffix}")

    def list_artifacts(self, run_id: str) -> list:
        return self._request_json("GET", f"/runs/{run_id}/artifacts")

    def get_artifact(self, run_id: str, artifact_path: str) -> bytes:
        import urllib.request
        url = f"{self.base_url}/runs/{run_id}/artifacts/{artifact_path}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read()

    def get_events_tail(self, run_id: str, limit: int = 200) -> list:
        return self._request_json("GET", f"/runs/{run_id}/events_tail?limit={limit}")

    def get_status(self) -> dict:
        return self._request_json("GET", "/status")

    def _request_json(self, method: str, path: str, payload: dict = None) -> dict:
        import urllib.request
        import urllib.error
        url = f"{self.base_url}{path}"
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8")
            raise RuntimeError(detail or f"HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"API unreachable at {self.base_url}: {exc.reason}") from exc

    def stream_events(self, run_id: str, cursor: int = 0, tail: bool = True):
        import urllib.request

        url = f"{self.base_url}/runs/{run_id}/events?cursor={cursor}&tail={'true' if tail else 'false'}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if line.startswith("data:"):
                    yield line.replace("data:", "", 1).strip()


class ChimeraLauncher:
    def __init__(self, root):
        self.root = root
        self.root.title("Chimera Security Suite")
        self.root.geometry("1280x820")
        self.root.minsize(1100, 760)

        self.api_url = tk.StringVar(value=os.getenv("CHIMERA_API_URL", "http://127.0.0.1:8000/v1"))
        self.artifacts_root = tk.StringVar(value=os.getenv("CHIMERA_ARTIFACTS_DIR", str(Path.cwd() / "artifacts")))
        self.max_workers = tk.IntVar(value=2)
        self.rate_limit_rps = tk.IntVar(value=10)
        self.per_task_timeout_s = tk.IntVar(value=1200)
        self.live_mode = tk.BooleanVar(value=True)
        self.live_confirm = tk.StringVar(value="")
        self.live_authorized = tk.BooleanVar(value=False)
        self.program_name = tk.StringVar(value="Other")
        self.status_var = tk.StringVar(value="[ READY ]")
        self.banner_var = tk.StringVar(value="MODE: LIVE | Manifest: N/A | Scope: UNKNOWN | Exec: UNKNOWN")
        self.status_payload = {}
        self.plan_ready = False

        self.current_run_id = None
        self.current_artifacts_dir = None
        self.console_paused = tk.BooleanVar(value=False)
        self.console_queue = queue.Queue()
        self.console_thread = None
        self.console_stop = threading.Event()
        self.findings_cache = []
        self.runs_cache = []

        self.font_ui = pick_font_family(
            root,
            ["Myopium", "Pirata One", "BlackChancery", "Times New Roman"],
            tkfont.nametofont("TkDefaultFont").cget("family"),
        )
        self.font_mono = pick_font_family(
            root,
            ["DejaVu Sans Mono", "Noto Sans Mono", "Ubuntu Mono", "Ubuntu Sans Mono", "Nimbus Mono PS", "Courier New"],
            tkfont.nametofont("TkFixedFont").cget("family"),
        )
        self.font_header = pick_font_family(
            root,
            ["BlackChancery", "Black Chancery", "Myopium", "Pirata One"],
            self.font_ui,
        )

        self.root.option_add("*Font", self.font_ui)
        self.configure_theme()

        self.main_container = ttk.Frame(root, style="Matrix.TFrame")
        self.main_container.pack(fill=tk.BOTH, expand=True)
        self.create_sidebar()

        self.content_frame = ttk.Frame(self.main_container, style="Matrix.TFrame")
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.create_status_bar()
        self._create_mode_banner()
        self.show_runs()
        self.refresh_status()
        self.root.after(120, self.flush_console_queue)

    def configure_theme(self):
        style = ttk.Style()
        style.configure(".",
                       background=ModernTheme.BG_DARK,
                       foreground=ModernTheme.FG_DARK,
                       font=(self.font_ui, 10))
        style.configure("Matrix.TFrame", background=ModernTheme.BG_DARK)
        style.configure("Matrix.TLabel",
                       background=ModernTheme.BG_DARK,
                       foreground=ModernTheme.FG_DARK,
                       font=(self.font_mono, 10))
        style.configure("Header.TLabel",
                       background=ModernTheme.BG_DARK,
                       foreground=ModernTheme.HEADER_FG,
                       font=(self.font_header, 22, "bold"))
        style.configure("Matrix.TButton",
                       background=ModernTheme.BG_DARK,
                       foreground=ModernTheme.FG_DARK,
                       font=(self.font_mono, 10, "bold"),
                       padding=8,
                       borderwidth=2,
                       relief="raised")
        style.map("Matrix.TButton",
                  background=[("active", ModernTheme.BG_LIGHT)],
                  foreground=[("active", ModernTheme.FG_LIGHT)])
        style.configure("Sidebar.TButton",
                       background=ModernTheme.BG_MEDIUM,
                       foreground=ModernTheme.FG_DARK,
                       font=(self.font_mono, 11, "bold"),
                       padding=12,
                       borderwidth=0)
        style.map("Sidebar.TButton",
                  background=[("active", ModernTheme.BG_LIGHT)],
                  foreground=[("active", ModernTheme.FG_LIGHT)])

    def create_sidebar(self):
        sidebar = ttk.Frame(self.main_container, style="Matrix.TFrame")
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        logo_label = ttk.Label(
            sidebar,
            text="[ CHIMERA ]\n[ CORE ]",
            font=(self.font_ui, 22, "bold"),
            foreground=ModernTheme.FG_DARK,
            background=ModernTheme.BG_DARK,
            justify=tk.CENTER
        )
        logo_label.pack(pady=(0, 20))

        nav_buttons = [
            ("[ RUNS ]", self.show_runs),
            ("[ CONSOLE ]", self.show_console),
            ("[ FINDINGS ]", self.show_findings),
            ("[ REPLAY & DIFF ]", self.show_replay_diff),
            ("[ ARTIFACTS ]", self.show_artifacts),
            ("[ SETTINGS ]", self.show_settings),
        ]

        for text, command in nav_buttons:
            btn = ttk.Button(
                sidebar,
                text=text,
                command=command,
                style="Sidebar.TButton"
            )
            btn.pack(fill=tk.X, pady=4)

    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def create_status_bar(self):
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=5)

    def _create_mode_banner(self):
        banner = ttk.Label(
            self.root,
            textvariable=self.banner_var,
            relief=tk.RIDGE,
            anchor=tk.W,
            background=ModernTheme.BG_MEDIUM,
            foreground=ModernTheme.FG_LIGHT,
            padding=6,
        )
        banner.pack(fill=tk.X, side=tk.TOP)

    def _get_client(self) -> ChimeraAPIClient:
        return ChimeraAPIClient(self.api_url.get())

    def refresh_status(self):
        # Get current UI state instead of relying on old runs
        mode = "LIVE" if self.live_mode.get() else "FIXTURE"

        # Check if scope is loaded in the text box (widget may be destroyed)
        scope_ok = "UNKNOWN"
        if hasattr(self, "scope_text") and self.scope_text.winfo_exists():
            scope_text = self.scope_text.get("1.0", tk.END).strip()
            scope_ok = "OK" if scope_text else "EMPTY"

        # Get API status for additional info (non-blocking)
        client = self._get_client()
        run_mode = None
        run_status = None
        run_phase = None
        if self.current_run_id:
            try:
                info = client.get_run(self.current_run_id)
                if info:
                    self.current_run_info = info
                    self.current_artifacts_dir = info.get("artifacts_dir")
                    resolved_run_id = info.get("run_id")
                    if resolved_run_id and resolved_run_id != self.current_run_id:
                        self.current_run_id = resolved_run_id
                    options = info.get("options", {})
                    run_mode = info.get("mode") or ("live" if options.get("live") else "fixture")
                    run_status = info.get("status")
            except Exception:
                pass
        try:
            payload = client.get_status()
            self.status_payload = payload
            safety_state = payload.get("safety_state", {})
            exec_allowed = "ALLOWED" if safety_state.get("external_exec_allowed") or not self.live_mode.get() else "BLOCKED"

            # Check if there's an active run streaming
            mode_from_api = payload.get("mode")
            active_run = payload.get("active_run", {})
            phase = active_run.get("phase")
            stream_enabled = mode_from_api == "live" and phase == "running"

            if run_status:
                phase_map = {
                    "created": "planning",
                    "running": "running",
                    "completed": "done",
                    "cancelled": "done",
                    "failed": "error",
                }
                run_phase = phase_map.get(run_status, "idle")

            # Determine streaming status message
            if hasattr(self, "stream_notice") and self.stream_notice.winfo_exists():
                # Priority 1: Use confirmed run info if available
                if run_mode == "live" and run_phase == "running":
                    self.stream_notice.config(text="Streaming enabled - Live scan in progress")
                elif run_mode == "live" and run_phase in ["planning", "created"]:
                    self.stream_notice.config(text="Initializing live scan...")
                elif run_mode == "live" and run_phase in ["done"]:
                    self.stream_notice.config(text="Live scan completed")
                elif run_mode == "fixture" and run_phase in ["running", "planning", "created"]:
                    self.stream_notice.config(text="Running in fixture/replay mode (test data)")
                elif run_mode == "fixture" and run_phase in ["done"]:
                    self.stream_notice.config(text="Fixture run completed")
                # Priority 2: Use UI state if user just clicked Run but run hasn't started yet
                elif self.current_run_id and self.live_mode.get():
                    self.stream_notice.config(text="Starting live scan...")
                elif self.current_run_id and not self.live_mode.get():
                    self.stream_notice.config(text="Starting fixture run...")
                # Priority 3: Use API status as fallback
                elif mode_from_api == "live" and phase == "running":
                    self.stream_notice.config(text="Streaming enabled")
                elif mode_from_api == "live" and phase in ["planning", "created"]:
                    self.stream_notice.config(text="Live scan starting...")
                elif mode_from_api == "fixture":
                    self.stream_notice.config(text="Fixture/replay mode")
                # Default: No active run
                else:
                    self.stream_notice.config(text="No active scan")
        except Exception as exc:
            # If API is down, still show UI state
            exec_allowed = "UNKNOWN"
            self.status_payload = {}

        # Update banner with current UI state
        plan_status = "READY" if self.plan_ready else "PENDING"
        self.banner_var.set(f"MODE: {mode} | Scope: {scope_ok} | Plan: {plan_status} | Exec: {exec_allowed}")
        self.update_run_controls()

    def _handle_api_error(self, exc: Exception) -> None:
        message = str(exc)
        if "API unreachable" in message:
            retry = messagebox.askretrycancel(
                "API Unreachable",
                f"{message}\n\nRetry or open Settings to update the API URL.",
            )
            if retry:
                self.refresh_status()
            else:
                self.show_settings()
        self.status_var.set(f"[ ERROR ] {message}")

    def show_runs(self):
        self.clear_content()
        header = ttk.Label(self.content_frame, text="[ RUNS ]", style="Header.TLabel")
        header.pack(anchor=tk.W)

        # Pipeline Selector
        pipeline_frame = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        pipeline_frame.pack(fill=tk.X, pady=(10, 10))

        ttk.Label(
            pipeline_frame,
            text="Pipeline:",
            style="Matrix.TLabel",
            font=(self.font_mono, 11, "bold")
        ).pack(side=tk.LEFT, padx=(0, 15))

        if not hasattr(self, 'pipeline_var'):
            self.pipeline_var = tk.StringVar(value="task_runner")

        ttk.Radiobutton(
            pipeline_frame,
            text="Task Runner (Autoswagger/Strix/Shannon)",
            variable=self.pipeline_var,
            value="task_runner",
            command=self._on_pipeline_changed,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=5)

        ttk.Radiobutton(
            pipeline_frame,
            text="Recon Pipeline (Zypheron/Vibe/Decepticon)",
            variable=self.pipeline_var,
            value="recon",
            command=self._on_pipeline_changed,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=5)

        scope_label = ttk.Label(self.content_frame, text="Scope (YAML):", style="Matrix.TLabel")
        scope_label.pack(anchor=tk.W, pady=(12, 4))

        self.scope_text = scrolledtext.ScrolledText(
            self.content_frame,
            height=10,
            wrap=tk.WORD,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            insertbackground=ModernTheme.FG_DARK,
            font=(self.font_mono, 10),
        )
        self.scope_text.pack(fill=tk.BOTH, expand=False)
        self.scope_text.bind("<KeyRelease>", lambda _event: self._mark_plan_stale())

        controls = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        controls.pack(fill=tk.X, pady=10)

        ttk.Button(
            controls,
            text="[ LOAD SCOPE FILE ]",
            command=self.load_scope_file,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Checkbutton(
            controls,
            text="Live Mode (required)",
            variable=self.live_mode,
            command=self._toggle_live,
            style="Matrix.TButton",
            state="disabled",
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Checkbutton(
            controls,
            text="I have authorization",
            variable=self.live_authorized,
            command=self.update_run_controls,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(controls, text="Live confirm:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(6, 4))
        confirm_entry = ttk.Entry(controls, textvariable=self.live_confirm, width=16)
        confirm_entry.pack(side=tk.LEFT, padx=(0, 10))
        confirm_entry.bind("<KeyRelease>", lambda _event: self.update_run_controls())

        ttk.Label(controls, text="Program:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(6, 4))
        program_combo = ttk.Combobox(
            controls,
            textvariable=self.program_name,
            values=["HackerOne", "Bugcrowd", "Other"],
            width=10,
            state="readonly",
        )
        program_combo.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(controls, text="max_workers:", style="Matrix.TLabel").pack(side=tk.LEFT)
        ttk.Spinbox(controls, from_=1, to=8, textvariable=self.max_workers, width=5).pack(side=tk.LEFT, padx=6)

        ttk.Label(controls, text="rps:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(8, 0))
        ttk.Spinbox(controls, from_=1, to=50, textvariable=self.rate_limit_rps, width=5).pack(side=tk.LEFT, padx=6)

        ttk.Label(controls, text="timeout_s:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(8, 0))
        ttk.Spinbox(controls, from_=5, to=1200, textvariable=self.per_task_timeout_s, width=6).pack(side=tk.LEFT, padx=6)

        action_row = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        action_row.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(
            action_row,
            text="[ GENERATE PLAN ]",
            command=self.generate_plan_preview,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.run_button = ttk.Button(
            action_row,
            text="[ RUN ]",
            command=self.start_run,
            style="Matrix.TButton"
        )
        self.run_button.pack(side=tk.LEFT)

        self.plan_preview = scrolledtext.ScrolledText(
            self.content_frame,
            height=8,
            wrap=tk.WORD,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_LIGHT,
            insertbackground=ModernTheme.FG_DARK,
            font=(self.font_mono, 10),
        )
        self.plan_preview.pack(fill=tk.BOTH, expand=True, pady=(12, 0))

        history_frame = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        history_frame.pack(fill=tk.BOTH, expand=True, pady=(16, 0))
        history_header = ttk.Label(history_frame, text="[ RECENT RUNS ]", style="Header.TLabel")
        history_header.pack(anchor=tk.W)

        history_controls = ttk.Frame(history_frame, style="Matrix.TFrame")
        history_controls.pack(fill=tk.X, pady=(6, 6))
        ttk.Button(
            history_controls,
            text="[ REFRESH ]",
            command=self.refresh_runs_history,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT)

        columns = ("status", "created_at", "targets", "findings")
        self.runs_table = ttk.Treeview(history_frame, columns=columns, show="headings", height=6)
        self.runs_table.heading("status", text="STATUS")
        self.runs_table.heading("created_at", text="CREATED")
        self.runs_table.heading("targets", text="TARGETS")
        self.runs_table.heading("findings", text="FINDINGS")
        self.runs_table.column("status", width=110)
        self.runs_table.column("created_at", width=180)
        self.runs_table.column("targets", width=360)
        self.runs_table.column("findings", width=90)
        self.runs_table.pack(fill=tk.BOTH, expand=True)
        self.runs_table.bind("<Double-1>", lambda _: self.select_run_from_history())

        # Initialize recon config vars if needed
        if not hasattr(self, 'recon_zypheron_binary'):
            self.recon_zypheron_binary = tk.StringVar(value="zypheron")
            self.recon_vibe_entrypoint = tk.StringVar(value="python vibe-pentester.py")
            self.recon_vibe_workdir = tk.StringVar(value="/app/tools/vibe-pentester")
            self.recon_vibe_output_dir = tk.StringVar(value="/artifacts/vibe-reports")
            self.recon_decepticon_entrypoint = tk.StringVar(value="python decepticon.py")
            self.recon_decepticon_workdir = tk.StringVar(value="/app/tools/decepticon")
            self.recon_decepticon_output_dir = tk.StringVar(value="/artifacts/decepticon-out")
            self.recon_allow_destructive = tk.BooleanVar(value=False)

        self.refresh_runs_history()
        self.update_run_controls()

    def _on_pipeline_changed(self):
        """Handle pipeline selection change - update UI visibility"""
        self.plan_ready = False
        self.plan_preview.delete("1.0", tk.END)
        pipeline = self.pipeline_var.get()
        if pipeline == "recon":
            self.plan_preview.insert(tk.END, "[ RECON PIPELINE MODE ]\n")
            self.plan_preview.insert(tk.END, "Sequential execution: Zypheron → VibePenTester → Decepticon\n\n")
            self.plan_preview.insert(tk.END, "Generate plan to see recon workflow details.")
        else:
            self.plan_preview.insert(tk.END, "[ TASK RUNNER MODE ]\n")
            self.plan_preview.insert(tk.END, "Generate plan to see task execution order.")
        self.update_run_controls()

    def _toggle_live(self):
        if not self.live_mode.get():
            self.live_mode.set(True)
        self.update_run_controls()
        self.refresh_status()  # Update footer to show mode change

    def load_scope_file(self):
        from tkinter import filedialog
        file_path = filedialog.askopenfilename(filetypes=[("YAML files", "*.yml *.yaml"), ("All files", "*.*")])
        if not file_path:
            return
        try:
            content = Path(file_path).read_text(encoding="utf-8")
        except OSError as exc:
            messagebox.showerror("Error", f"Failed to read scope file: {exc}")
            return
        self.scope_text.delete("1.0", tk.END)
        self.scope_text.insert(tk.END, content)
        self._mark_plan_stale()

    def generate_plan_preview(self):
        text = self.scope_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Plan", "Paste scope YAML first.")
            return
        live = self.live_mode.get()
        confirm_text = self.live_confirm.get().strip()
        if live and confirm_text != "I UNDERSTAND":
            messagebox.showerror("Plan", "Live mode requires typing I UNDERSTAND.")
            return

        # Get selected pipeline
        pipeline = self.pipeline_var.get() if hasattr(self, 'pipeline_var') else "task_runner"

        client = self._get_client()
        try:
            response = client.plan_run(
                scope_text=text,
                live=live,
                max_workers=self.max_workers.get(),
                live_confirm=confirm_text,
                pipeline=pipeline,
            )
            tasks = response.get("plan", {}).get("tasks", [])
            notes = response.get("notes", [])
            warnings = response.get("warnings", [])
            preview_lines = ["[ PLAN PREVIEW ]"]
            for task in tasks:
                deps = ",".join(task.get("depends_on", [])) or "none"
                preview_lines.append(
                    f"- {task.get('adapter')} → {task.get('target')} (deps: {deps})"
                )
            if not tasks:
                preview_lines.append("- (no targets detected)")
            if notes:
                preview_lines.append("")
                preview_lines.append("[ NOTES ]")
                preview_lines.extend([f"- {note}" for note in notes])
            if warnings:
                preview_lines.append("")
                preview_lines.append("[ WARNINGS ]")
                preview_lines.extend([f"- {warning}" for warning in warnings])
        except Exception as exc:
            self._handle_api_error(exc)
            preview_lines = [
                "[ OFFLINE PLAN PREVIEW ]",
                f"- API unavailable: {exc}",
                "",
            ]
            try:
                import yaml
                scope = yaml.safe_load(text) or {}
                allowlist = scope.get("allowlist", [])
                for target in allowlist:
                    lowered = str(target).lower()
                    if any(marker in lowered for marker in ["/api", "/v1", "/swagger.json", "/openapi.json"]):
                        preview_lines.append(f"- autoswagger → {target}")
                    else:
                        preview_lines.append(f"- strix → {target}")
                if not allowlist:
                    preview_lines.append("- (no targets detected)")
            except Exception:
                preview_lines.append("- (failed to parse scope offline)")

        preview = "\n".join(preview_lines)
        self.plan_preview.delete("1.0", tk.END)
        self.plan_preview.insert(tk.END, preview)
        self.plan_ready = True
        self.update_run_controls()
        self.refresh_status()  # Update footer to show plan is ready

    def start_run(self):
        """Start run based on selected pipeline"""
        pipeline = self.pipeline_var.get() if hasattr(self, 'pipeline_var') else "task_runner"

        if pipeline == "task_runner":
            self._submit_task_runner_run()
        else:
            self._submit_recon_run()

    def _submit_task_runner_run(self):
        """Submit Task Runner Pipeline run (existing logic)"""
        scope_text = self.scope_text.get("1.0", tk.END).strip()
        if not scope_text:
            messagebox.showinfo("Run", "Paste scope YAML first.")
            return
        if not self.plan_ready:
            messagebox.showinfo("Run", "Generate a plan before running.")
            return
        live = self.live_mode.get()
        confirm_text = self.live_confirm.get().strip()
        if live:
            confirm = messagebox.askyesno(
                "Live Mode Confirmation",
                "Live mode will execute real tools against the scope. Continue?",
            )
            if not confirm:
                return
            if not self.live_authorized.get():
                messagebox.showerror("Run", "Authorization checkbox is required for live mode.")
                return
            if confirm_text != "I UNDERSTAND":
                messagebox.showerror("Run", "Live mode requires typing I UNDERSTAND.")
                return

        self.status_var.set("[ RUN SUBMITTED ]")
        client = self._get_client()

        def _run():
            try:
                response = client.create_run(
                    scope_text,
                    live=live,
                    max_workers=self.max_workers.get(),
                    live_confirm=confirm_text,
                    rate_limit_rps=self.rate_limit_rps.get(),
                    per_task_timeout_s=self.per_task_timeout_s.get(),
                    program_name=self.program_name.get(),
                )
                self.current_run_id = response.get("run_id")
                self.status_var.set(f"[ RUN CREATED ] {self.current_run_id}")
                self.switch_to_console()
            except Exception as exc:
                self._handle_api_error(exc)

        threading.Thread(target=_run, daemon=True).start()

    def _submit_recon_run(self):
        """Submit Recon Pipeline run"""
        scope_text = self.scope_text.get("1.0", tk.END).strip()
        if not scope_text:
            messagebox.showinfo("Run", "Paste scope YAML first.")
            return

        live = self.live_mode.get()
        confirm_text = self.live_confirm.get().strip()
        allow_destructive = self.recon_allow_destructive.get() if hasattr(self, 'recon_allow_destructive') else False

        if live:
            message = (
                "Recon Pipeline will execute REAL SECURITY TOOLS:\n\n"
                "• Zypheron: nmap, masscan, subfinder, amass\n"
                "• VibePenTester: nmap, nikto, nuclei"
            )
            if allow_destructive:
                message += ", sqlmap, ffuf, wfuzz"
            message += "\n• Decepticon: AI analysis (LLM API calls)\n\n"
            message += "This is LIVE PENETRATION TESTING. Continue?"

            confirm = messagebox.askyesno("Recon Pipeline - Live Mode", message)
            if not confirm:
                return
            if not self.live_authorized.get():
                messagebox.showerror("Run", "Authorization checkbox is required for live mode.")
                return
            if confirm_text != "I UNDERSTAND":
                messagebox.showerror("Run", "Live mode requires typing I UNDERSTAND.")
                return

        self.status_var.set("[ RECON RUN SUBMITTED ]")
        client = self._get_client()

        def _run():
            try:
                import urllib.request
                import urllib.error

                # Prepare payload
                payload = {
                    "scope_text": scope_text,
                    "live": live,
                    "live_confirm": confirm_text,
                    "rate_limit_rps": self.rate_limit_rps.get(),
                    "timeout_s": self.per_task_timeout_s.get(),
                    "program_name": self.program_name.get(),
                    "allow_destructive": allow_destructive,
                    "max_workers": self.max_workers.get(),
                    # Zypheron config
                    "zypheron_config": {
                        "binary": self.recon_zypheron_binary.get()
                    },
                    # VibePenTester config
                    "vibe_entrypoint": self.recon_vibe_entrypoint.get().split(),
                    "vibe_workdir": self.recon_vibe_workdir.get(),
                    "vibe_output_dir": self.recon_vibe_output_dir.get(),
                    "vibe_timeout_s": self.per_task_timeout_s.get(),
                    "vibe_extra_args": [],
                    "vibe_env": {},
                    # Decepticon config
                    "decepticon_entrypoint": self.recon_decepticon_entrypoint.get().split(),
                    "decepticon_workdir": self.recon_decepticon_workdir.get(),
                    "decepticon_output_dir": self.recon_decepticon_output_dir.get(),
                    "decepticon_timeout_s": self.per_task_timeout_s.get(),
                    "decepticon_extra_args": [],
                    "decepticon_env": {},
                }

                # Call recon API
                url = f"{client.base_url}/recon/run"
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(url, data=data, method="POST")
                req.add_header("Content-Type", "application/json")

                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8")
                    response = json.loads(body) if body else {}

                self.current_run_id = response.get("run_id")
                self.status_var.set(f"[ RECON RUN CREATED ] {self.current_run_id}")
                messagebox.showinfo(
                    "Recon Pipeline Started",
                    f"Run ID: {self.current_run_id}\n\n"
                    "Pipeline: Zypheron → VibePenTester → Decepticon\n\n"
                    "Switch to Console tab to monitor progress."
                )
                self.switch_to_console()
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8")
                self._handle_api_error(RuntimeError(detail or f"HTTP {exc.code}"))
            except Exception as exc:
                self._handle_api_error(exc)

        threading.Thread(target=_run, daemon=True).start()

    def refresh_runs_history(self):
        client = self._get_client()
        try:
            runs = client.list_runs(limit=20, offset=0)
        except Exception as exc:
            self._handle_api_error(exc)
            return
        self.runs_cache = runs
        self.refresh_status()
        if not hasattr(self, "runs_table"):
            return
        for row in self.runs_table.get_children():
            self.runs_table.delete(row)
        for run in runs:
            run_id = run.get("run_id")
            stats = run.get("stats", {})
            targets = ", ".join(run.get("scope", {}).get("allowlist", []))
            self.runs_table.insert(
                "",
                tk.END,
                iid=run_id,
                values=(
                    run.get("status"),
                    run.get("created_at"),
                    targets,
                    stats.get("findings_total", 0),
                ),
            )

    def select_run_from_history(self):
        selection = self.runs_table.selection()
        if not selection:
            return
        run_id = selection[0]
        self.current_run_id = run_id
        self.status_var.set(f"[ RUN SELECTED ] {run_id}")
        self._refresh_run_info()

    def switch_to_console(self):
        self.root.after(0, self.show_console)

    def show_console(self):
        self.clear_content()
        header = ttk.Label(self.content_frame, text="[ CONSOLE ]", style="Header.TLabel")
        header.pack(anchor=tk.W)

        action_row = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        action_row.pack(fill=tk.X, pady=(6, 6))
        ttk.Button(
            action_row,
            text="[ OPEN RUNS ]",
            command=self.show_runs,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(
            action_row,
            text="[ SELECT LATEST ]",
            command=self.select_latest_run,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT)

        self.refresh_status()

        # Refresh run info if we have a run selected
        if self.current_run_id:
            self._refresh_run_info()

        run_info = getattr(self, "current_run_info", {}) or {}
        options = run_info.get("options", {})
        stats = run_info.get("stats", {}) or {}
        scope_info = run_info.get("scope_normalized") or run_info.get("scope") or {}
        allowlist = scope_info.get("allowlist", [])

        # Format targets for display
        if allowlist:
            targets = ", ".join(allowlist[:3])  # Show first 3 targets
            if len(allowlist) > 3:
                targets += f" (+{len(allowlist) - 3} more)"
        else:
            targets = "Loading..." if self.current_run_id else "No run selected"
        if options.get("live"):
            banner = ttk.Label(
                self.content_frame,
                text="LIVE MODE ENABLED",
                foreground="#ff3333",
                background=ModernTheme.BG_DARK,
                font=(self.font_header, 16, "bold"),
            )
            banner.pack(anchor=tk.W, pady=(8, 0))
        summary = ttk.Label(
            self.content_frame,
            text=(
                f"Targets: {targets} | Findings: {stats.get('findings_total', 0)} | "
                f"Verified probes: {stats.get('verification_passed', 0)} | "
                f"Cache skips: {stats.get('verification_skipped_cache_hits', 0)}"
            ),
            style="Matrix.TLabel",
        )
        summary.pack(anchor=tk.W, pady=(4, 8))

        notebook = ttk.Notebook(self.content_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        stream_tab = ttk.Frame(notebook, style="Matrix.TFrame")
        artifacts_tab = ttk.Frame(notebook, style="Matrix.TFrame")
        events_tab = ttk.Frame(notebook, style="Matrix.TFrame")
        notebook.add(stream_tab, text="Stream")
        notebook.add(artifacts_tab, text="Artifacts")
        notebook.add(events_tab, text="Events")

        self._build_stream_tab(stream_tab)
        self._build_artifacts_tab(artifacts_tab)
        self._build_events_tab(events_tab)

        self.console_output.tag_configure("task", foreground="#ff3366")
        self.console_output.tag_configure("cmd", foreground="#00ff41")
        self.console_output.tag_configure("artifact", foreground="#00ccff")
        self.console_output.tag_configure("error", foreground="#ff3333")

        if self.current_run_id:
            self._refresh_artifacts_list()
            self._refresh_events_tail()

    def select_latest_run(self):
        if not self.runs_cache:
            self.refresh_runs_history()
        if not self.runs_cache:
            messagebox.showinfo("Runs", "No runs available.")
            return
        run_id = self.runs_cache[0].get("run_id")
        if not run_id:
            messagebox.showinfo("Runs", "Latest run is missing an ID.")
            return
        self.current_run_id = run_id
        self.status_var.set(f"[ RUN SELECTED ] {run_id}")
        self._refresh_run_info()

    def start_event_stream(self):
        if not self.current_run_id:
            messagebox.showinfo("Console", "No run selected.")
            return
        if self.console_thread and self.console_thread.is_alive():
            return
        self.console_stop.clear()
        self.console_thread = threading.Thread(target=self._stream_events, daemon=True)
        self.console_thread.start()

    def stop_event_stream(self):
        self.console_stop.set()

    def _stream_events(self):
        client = self._get_client()
        try:
            for payload in client.stream_events(self.current_run_id, cursor=0, tail=True):
                if self.console_stop.is_set():
                    break
                self.console_queue.put(payload)
        except Exception as exc:
            self.console_queue.put(json.dumps({"event_type": "error", "payload": {"message": str(exc)}}))

    def replay_events_from_file(self):
        if not self.current_run_id:
            messagebox.showinfo("Console", "No run selected.")
            return
        if not self.current_artifacts_dir:
            self._refresh_run_info()
        if not self.current_artifacts_dir:
            messagebox.showerror("Console", "Artifacts directory not available.")
            return
        events_path = Path(self.current_artifacts_dir) / "events.jsonl"
        if not events_path.exists():
            messagebox.showerror("Console", f"Event log not found: {events_path}")
            return

        def _replay():
            try:
                for line in events_path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        self.console_queue.put(line.strip())
            except Exception as exc:
                self.console_queue.put(json.dumps({"event_type": "error", "payload": {"message": str(exc)}}))

        threading.Thread(target=_replay, daemon=True).start()

    def flush_console_queue(self):
        if hasattr(self, "console_output") and not self.console_paused.get():
            if self.console_output.winfo_exists():
                while not self.console_queue.empty():
                    payload = self.console_queue.get()
                    self._append_console(payload)
        if self.root.winfo_exists():
            self.root.after(120, self.flush_console_queue)

    def _append_console(self, payload: str):
        if not hasattr(self, "console_output") or not self.console_output.winfo_exists():
            return
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = {"event_type": "log", "payload": {"message": payload}}
        event_type = data.get("event_type", "log")
        message = json.dumps(data.get("payload", {}))
        tag = "task"
        if "cmd" in event_type:
            tag = "cmd"
        elif "artifact" in event_type:
            tag = "artifact"
        elif "error" in event_type or "failed" in event_type:
            tag = "error"
        self.console_output.insert(tk.END, f"[{event_type}] {message}\n", tag)
        self.console_output.see(tk.END)

    def _build_stream_tab(self, parent):
        controls = ttk.Frame(parent, style="Matrix.TFrame")
        controls.pack(fill=tk.X, pady=(6, 6))
        ttk.Button(
            controls,
            text="[ START STREAM ]",
            command=self.start_event_stream,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(
            controls,
            text="[ STOP STREAM ]",
            command=self.stop_event_stream,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(
            controls,
            text="[ LOAD EVENTS ]",
            command=self._load_console_events_tail,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(
            controls,
            text="Pause",
            variable=self.console_paused,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT)

        self.stream_notice = ttk.Label(
            parent,
            text="Streaming disabled in replay mode.",
            style="Matrix.TLabel",
        )
        self.stream_notice.pack(anchor=tk.W, padx=4, pady=(0, 6))

        self.console_output = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            height=20,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            font=(self.font_mono, 10),
            insertbackground=ModernTheme.FG_DARK
        )
        self.console_output.pack(fill=tk.BOTH, expand=True)

        self.console_output.tag_configure("task", foreground="#ff3366")
        self.console_output.tag_configure("cmd", foreground="#00ff41")
        self.console_output.tag_configure("artifact", foreground="#00ccff")
        self.console_output.tag_configure("error", foreground="#ff3333")

    def _load_console_events_tail(self):
        if not self.current_run_id:
            messagebox.showinfo("Console", "No run selected.")
            return
        client = self._get_client()
        try:
            events = client.get_events_tail(self.current_run_id, limit=200)
        except Exception as exc:
            self._handle_api_error(exc)
            return
        self.console_output.delete("1.0", tk.END)
        for line in events:
            self._append_console(line)

    def _build_artifacts_tab(self, parent):
        toolbar = ttk.Frame(parent, style="Matrix.TFrame")
        toolbar.pack(fill=tk.X, pady=(6, 6))
        ttk.Button(
            toolbar,
            text="[ REFRESH ]",
            command=self._refresh_artifacts_list,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(
            toolbar,
            text="[ OPEN LOCAL ]",
            command=self._open_selected_artifact_local,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))

        body = ttk.Frame(parent, style="Matrix.TFrame")
        body.pack(fill=tk.BOTH, expand=True)

        self.artifacts_list = tk.Listbox(
            body,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            font=(self.font_mono, 10),
            height=12,
        )
        self.artifacts_list.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8), pady=4)
        self.artifacts_list.bind("<<ListboxSelect>>", lambda _event: self._show_selected_artifact())

        self.artifact_viewer = scrolledtext.ScrolledText(
            body,
            wrap=tk.WORD,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_LIGHT,
            font=(self.font_mono, 10),
            insertbackground=ModernTheme.FG_DARK,
        )
        self.artifact_viewer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _build_events_tab(self, parent):
        toolbar = ttk.Frame(parent, style="Matrix.TFrame")
        toolbar.pack(fill=tk.X, pady=(6, 6))
        ttk.Button(
            toolbar,
            text="[ REFRESH ]",
            command=self._refresh_events_tail,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.events_viewer = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_LIGHT,
            font=(self.font_mono, 10),
            insertbackground=ModernTheme.FG_DARK,
        )
        self.events_viewer.pack(fill=tk.BOTH, expand=True)

    def _refresh_artifacts_list(self):
        if not self.current_run_id:
            return
        client = self._get_client()
        try:
            artifacts = client.list_artifacts(self.current_run_id)
        except Exception as exc:
            self._handle_api_error(exc)
            return
        self.artifacts_cache = artifacts
        self.artifacts_list.delete(0, tk.END)
        for item in artifacts:
            label = f"{item.get('kind','artifact')} | {item.get('path')}"
            self.artifacts_list.insert(tk.END, label)

    def _selected_artifact(self):
        selection = self.artifacts_list.curselection()
        if not selection or not getattr(self, "artifacts_cache", None):
            return None
        return self.artifacts_cache[selection[0]]

    def _show_selected_artifact(self):
        artifact = self._selected_artifact()
        if not artifact:
            return
        client = self._get_client()
        try:
            content = client.get_artifact(self.current_run_id, artifact["path"])
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                text = "<binary artifact>"
        except Exception as exc:
            text = f"<failed to load artifact: {exc}>"
        self.artifact_viewer.delete("1.0", tk.END)
        self.artifact_viewer.insert(tk.END, text)

    def _open_selected_artifact_local(self):
        artifact = self._selected_artifact()
        if not artifact:
            messagebox.showinfo("Artifacts", "Select an artifact first.")
            return
        if not self.current_artifacts_dir:
            self._refresh_run_info()
        if not self.current_artifacts_dir:
            messagebox.showerror("Artifacts", "Artifacts directory not available.")
            return
        path = Path(self.current_artifacts_dir) / artifact["path"]
        if not path.exists():
            messagebox.showerror("Artifacts", f"Local artifact not found: {path}")
            return
        open_path(path)

    def _refresh_events_tail(self):
        if not self.current_run_id:
            return
        client = self._get_client()
        try:
            events = client.get_events_tail(self.current_run_id, limit=200)
        except Exception as exc:
            self._handle_api_error(exc)
            return
        self.events_viewer.delete("1.0", tk.END)
        for line in events:
            self.events_viewer.insert(tk.END, f"{line}\n")

    def show_findings(self):
        self.clear_content()
        header = ttk.Label(self.content_frame, text="[ FINDINGS ]", style="Header.TLabel")
        header.pack(anchor=tk.W)

        controls = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        controls.pack(fill=tk.X, pady=(10, 6))
        ttk.Button(
            controls,
            text="[ REFRESH ]",
            command=self.refresh_findings,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.finding_class_filter = tk.StringVar(value="ALL")
        ttk.Label(controls, text="Class:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(6, 4))
        class_combo = ttk.Combobox(
            controls,
            textvariable=self.finding_class_filter,
            values=["ALL", "REPORT_READY", "NEEDS_REVIEW", "NOISE"],
            width=14,
            state="readonly",
        )
        class_combo.pack(side=tk.LEFT, padx=(0, 10))
        class_combo.bind("<<ComboboxSelected>>", lambda _event: self.refresh_findings())

        self.finding_tool_filter = tk.StringVar(value="ALL")
        ttk.Label(controls, text="Tool:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(6, 4))
        self.finding_tool_combo = ttk.Combobox(
            controls,
            textvariable=self.finding_tool_filter,
            values=["ALL", "autoswagger", "strix", "shannon", "zypheron", "vibepentester", "decepticon"],
            width=14,
            state="readonly",
        )
        self.finding_tool_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.finding_tool_combo.bind("<<ComboboxSelected>>", lambda _event: self.refresh_findings())

        self.finding_min_conf = tk.StringVar(value="")
        ttk.Label(controls, text="Min conf:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(6, 4))
        min_entry = ttk.Entry(controls, textvariable=self.finding_min_conf, width=6)
        min_entry.pack(side=tk.LEFT, padx=(0, 10))
        min_entry.bind("<KeyRelease>", lambda _event: self.refresh_findings())

        self.finding_search = tk.StringVar(value="")
        ttk.Label(controls, text="Search:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(6, 4))
        search_entry = ttk.Entry(controls, textvariable=self.finding_search, width=18)
        search_entry.pack(side=tk.LEFT, padx=(0, 10))
        search_entry.bind("<KeyRelease>", lambda _event: self.refresh_findings())
        ttk.Button(
            controls,
            text="[ OPEN REPORT ]",
            command=self.open_report,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT)

        body = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        body.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(body, style="Matrix.TFrame")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right = ttk.Frame(body, style="Matrix.TFrame")
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        columns = ("severity", "title", "target", "tool", "confidence", "classification")
        self.findings_table = ttk.Treeview(
            left,
            columns=columns,
            show="headings",
            height=14
        )
        for col in columns:
            self.findings_table.heading(col, text=col.upper())
            width = 120
            if col == "title":
                width = 320
            elif col == "target":
                width = 220
            self.findings_table.column(col, width=width)
        self.findings_table.pack(fill=tk.BOTH, expand=True)
        self.findings_table.bind("<<TreeviewSelect>>", lambda _: self._load_finding_detail())

        detail_header = ttk.Label(right, text="[ DETAIL ]", style="Matrix.TLabel")
        detail_header.pack(anchor=tk.W)

        self.finding_meta = ttk.Label(right, text="Select a finding", style="Matrix.TLabel")
        self.finding_meta.pack(anchor=tk.W, pady=(4, 6))

        evidence_frame = ttk.Frame(right, style="Matrix.TFrame")
        evidence_frame.pack(fill=tk.BOTH, expand=False, pady=(6, 6))
        ttk.Label(evidence_frame, text="Evidence:", style="Matrix.TLabel").pack(anchor=tk.W)
        self.evidence_list = tk.Listbox(
            evidence_frame,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            font=(self.font_mono, 10),
            height=4,
        )
        self.evidence_list.pack(fill=tk.X, expand=False)
        self.evidence_list.bind("<<ListboxSelect>>", lambda _event: self._open_evidence_anchor())

        provenance_frame = ttk.Frame(right, style="Matrix.TFrame")
        provenance_frame.pack(fill=tk.BOTH, expand=False, pady=(6, 6))
        ttk.Label(provenance_frame, text="Provenance:", style="Matrix.TLabel").pack(anchor=tk.W)
        self.provenance_list = tk.Listbox(
            provenance_frame,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            font=(self.font_mono, 10),
            height=5,
        )
        self.provenance_list.pack(fill=tk.X, expand=False)
        self.provenance_list.bind("<<ListboxSelect>>", lambda _event: self._open_provenance_ref())

        self.finding_details = scrolledtext.ScrolledText(
            right,
            height=8,
            wrap=tk.WORD,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_LIGHT,
            font=(self.font_mono, 10),
            insertbackground=ModernTheme.FG_DARK
        )
        self.finding_details.pack(fill=tk.BOTH, expand=True)

        self.refresh_findings()

    def refresh_findings(self):
        if not self.current_run_id:
            messagebox.showinfo("Findings", "No run selected.")
            return
        client = self._get_client()
        try:
            findings = client.get_findings_filtered(
                self.current_run_id,
                classification=self.finding_class_filter.get(),
                tool=self.finding_tool_filter.get(),
                min_confidence=self.finding_min_conf.get(),
                query=self.finding_search.get(),
            )
        except Exception as exc:
            messagebox.showerror("Findings", f"Failed to load findings: {exc}")
            return
        for row in self.findings_table.get_children():
            self.findings_table.delete(row)
        self.findings_cache = {finding.get("stable_id"): finding for finding in findings}
        tools = sorted({finding.get("tool", "unknown") for finding in findings})
        tool_values = ["ALL"] + tools
        if hasattr(self, "finding_tool_combo"):
            self.finding_tool_combo.configure(values=tool_values)
            if self.finding_tool_filter.get() not in tool_values:
                self.finding_tool_filter.set("ALL")
        for finding in findings:
            stable_id = finding.get("stable_id")
            self.findings_table.insert(
                "", tk.END, iid=stable_id,
                values=(
                    finding.get("severity"),
                    finding.get("title"),
                    finding.get("target"),
                    finding.get("tool"),
                    f"{finding.get('confidence', 0):.2f}",
                    finding.get("classification"),
                )
            )

    def _load_finding_detail(self):
        selection = self.findings_table.selection()
        if not selection:
            return
        stable_id = selection[0]
        client = self._get_client()
        try:
            detail = client.get_finding_detail(self.current_run_id, stable_id)
        except Exception as exc:
            messagebox.showerror("Findings", f"Failed to load detail: {exc}")
            return

        self.detail_run_id = self.current_run_id
        self.finding_detail_payload = detail
        meta = (
            f"{detail.get('severity', '').upper()} | "
            f"Conf: {detail.get('confidence', 0):.2f} | "
            f"{detail.get('classification', '')}"
        )
        self.finding_meta.config(text=meta)

        self.evidence_cache = detail.get("evidence", {}).get("anchors", [])
        self.evidence_list.delete(0, tk.END)
        for anchor in self.evidence_cache:
            label = f"{anchor.get('kind')} | {anchor.get('path') or anchor.get('id')}"
            self.evidence_list.insert(tk.END, label)

        self.provenance_cache = detail.get("provenance", {}).get("derived_from", [])
        self.provenance_list.delete(0, tk.END)
        produced_by = detail.get("provenance", {}).get("produced_by", "unknown")
        self.provenance_list.insert(tk.END, f"produced_by: {produced_by}")
        for ref in self.provenance_cache:
            label = f"{ref.get('kind')} | {ref.get('id')}"
            self.provenance_list.insert(tk.END, label)

        description = detail.get("description") or detail.get("reproduction") or ""
        self.finding_details.delete("1.0", tk.END)
        self.finding_details.insert(tk.END, description)

    def _open_evidence_anchor(self):
        if not getattr(self, "evidence_cache", None):
            return
        selection = self.evidence_list.curselection()
        if not selection:
            return
        anchor = self.evidence_cache[selection[0]]
        if anchor.get("kind") != "artifact" or not anchor.get("path"):
            return
        client = self._get_client()
        run_id = getattr(self, "detail_run_id", None) or self.current_run_id
        if not run_id:
            return
        try:
            content = client.get_artifact(run_id, anchor["path"])
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                text = "<binary artifact>"
        except Exception as exc:
            text = f"<failed to load artifact: {exc}>"
        self.finding_details.delete("1.0", tk.END)
        self.finding_details.insert(tk.END, text)

    def _open_provenance_ref(self):
        selection = self.provenance_list.curselection()
        if not selection or not getattr(self, "provenance_cache", None):
            return
        index = selection[0] - 1
        if index < 0 or index >= len(self.provenance_cache):
            return
        ref = self.provenance_cache[index]
        if ref.get("kind") != "artifact":
            return
        path = ref.get("note") or ref.get("id", "").replace("artifact:", "")
        if not path:
            return
        client = self._get_client()
        run_id = getattr(self, "detail_run_id", None) or self.current_run_id
        if not run_id:
            return
        try:
            content = client.get_artifact(run_id, path)
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                text = "<binary artifact>"
        except Exception as exc:
            text = f"<failed to load artifact: {exc}>"
        self.finding_details.delete("1.0", tk.END)
        self.finding_details.insert(tk.END, text)

    def open_report(self):
        if not self.current_run_id or not self.current_artifacts_dir:
            self._refresh_run_info()
        if self.current_artifacts_dir:
            report_path = Path(self.current_artifacts_dir) / "report.md"
            if report_path.exists():
                open_path(report_path)

    def show_replay_diff(self):
        self.clear_content()
        header = ttk.Label(self.content_frame, text="[ REPLAY & DIFF ]", style="Header.TLabel")
        header.pack(anchor=tk.W)

        controls = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        controls.pack(fill=tk.X, pady=(10, 6))
        ttk.Button(
            controls,
            text="[ REFRESH ]",
            command=self._refresh_replay_diff,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.diff_base_var = tk.StringVar(value="")
        ttk.Label(controls, text="Base:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(6, 4))
        self.diff_base_combo = ttk.Combobox(
            controls,
            textvariable=self.diff_base_var,
            values=[],
            width=16,
            state="readonly",
        )
        self.diff_base_combo.pack(side=tk.LEFT, padx=(0, 10))

        self.diff_compare_var = tk.StringVar(value="")
        ttk.Label(controls, text="Compare:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(6, 4))
        self.diff_compare_combo = ttk.Combobox(
            controls,
            textvariable=self.diff_compare_var,
            values=[],
            width=16,
            state="readonly",
        )
        self.diff_compare_combo.pack(side=tk.LEFT, padx=(0, 10))

        self.diff_class_filter = tk.StringVar(value="ALL")
        ttk.Label(controls, text="Scope:", style="Matrix.TLabel").pack(side=tk.LEFT, padx=(6, 4))
        class_combo = ttk.Combobox(
            controls,
            textvariable=self.diff_class_filter,
            values=["ALL", "REPORT_READY"],
            width=14,
            state="readonly",
        )
        class_combo.pack(side=tk.LEFT, padx=(0, 10))
        class_combo.bind("<<ComboboxSelected>>", lambda _event: self._refresh_replay_diff())

        self.diff_summary_var = tk.StringVar(value="Select runs to compare.")
        summary_label = ttk.Label(self.content_frame, textvariable=self.diff_summary_var, style="Matrix.TLabel")
        summary_label.pack(anchor=tk.W, pady=(4, 8))

        body = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        body.pack(fill=tk.BOTH, expand=True)

        lists_frame = ttk.Frame(body, style="Matrix.TFrame")
        lists_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        detail_frame = ttk.Frame(body, style="Matrix.TFrame")
        detail_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        self.diff_new_list = self._build_diff_list(lists_frame, "NEW")
        self.diff_removed_list = self._build_diff_list(lists_frame, "REMOVED")
        self.diff_changed_list = self._build_diff_list(lists_frame, "CHANGED")

        self.diff_new_list.bind("<<ListboxSelect>>", lambda _event: self._load_diff_detail("new"))
        self.diff_removed_list.bind("<<ListboxSelect>>", lambda _event: self._load_diff_detail("removed"))
        self.diff_changed_list.bind("<<ListboxSelect>>", lambda _event: self._load_diff_detail("changed"))

        detail_header = ttk.Label(detail_frame, text="[ DETAIL ]", style="Matrix.TLabel")
        detail_header.pack(anchor=tk.W)

        self.finding_meta = ttk.Label(detail_frame, text="Select a finding", style="Matrix.TLabel")
        self.finding_meta.pack(anchor=tk.W, pady=(4, 6))

        evidence_frame = ttk.Frame(detail_frame, style="Matrix.TFrame")
        evidence_frame.pack(fill=tk.BOTH, expand=False, pady=(6, 6))
        ttk.Label(evidence_frame, text="Evidence:", style="Matrix.TLabel").pack(anchor=tk.W)
        self.evidence_list = tk.Listbox(
            evidence_frame,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            font=(self.font_mono, 10),
            height=4,
        )
        self.evidence_list.pack(fill=tk.X, expand=False)
        self.evidence_list.bind("<<ListboxSelect>>", lambda _event: self._open_evidence_anchor())

        provenance_frame = ttk.Frame(detail_frame, style="Matrix.TFrame")
        provenance_frame.pack(fill=tk.BOTH, expand=False, pady=(6, 6))
        ttk.Label(provenance_frame, text="Provenance:", style="Matrix.TLabel").pack(anchor=tk.W)
        self.provenance_list = tk.Listbox(
            provenance_frame,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            font=(self.font_mono, 10),
            height=5,
        )
        self.provenance_list.pack(fill=tk.X, expand=False)
        self.provenance_list.bind("<<ListboxSelect>>", lambda _event: self._open_provenance_ref())

        self.finding_details = scrolledtext.ScrolledText(
            detail_frame,
            height=8,
            wrap=tk.WORD,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_LIGHT,
            font=(self.font_mono, 10),
            insertbackground=ModernTheme.FG_DARK
        )
        self.finding_details.pack(fill=tk.BOTH, expand=True)

        self._populate_diff_runs()

    def _build_diff_list(self, parent: ttk.Frame, title: str) -> tk.Listbox:
        frame = ttk.Frame(parent, style="Matrix.TFrame")
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        ttk.Label(frame, text=f"{title}:", style="Matrix.TLabel").pack(anchor=tk.W)
        listbox = tk.Listbox(
            frame,
            bg=ModernTheme.BG_MEDIUM,
            fg=ModernTheme.FG_DARK,
            font=(self.font_mono, 10),
            height=6,
        )
        listbox.pack(fill=tk.BOTH, expand=True)
        return listbox

    def _populate_diff_runs(self):
        client = self._get_client()
        try:
            runs = client.list_runs(limit=30, offset=0)
        except Exception as exc:
            self._handle_api_error(exc)
            return
        run_ids = [run.get("run_id") for run in runs if run.get("run_id")]
        self.diff_base_combo.configure(values=run_ids)
        self.diff_compare_combo.configure(values=run_ids)
        if not run_ids:
            return
        if not self.diff_base_var.get():
            self.diff_base_var.set(run_ids[0])
        if not self.diff_compare_var.get():
            if len(run_ids) > 1:
                self.diff_compare_var.set(run_ids[1])
            else:
                self.diff_compare_var.set(run_ids[0])
        self._refresh_replay_diff()

    def _refresh_replay_diff(self):
        base_run_id = self.diff_base_var.get()
        compare_run_id = self.diff_compare_var.get()
        if not base_run_id or not compare_run_id:
            return
        client = self._get_client()
        try:
            diff = client.get_runs_diff(
                base_run_id,
                compare_run_id,
                classification=self.diff_class_filter.get(),
            )
        except Exception as exc:
            self._handle_api_error(exc)
            return

        counts = diff.get("counts", {})
        findings_counts = counts.get("findings", {})
        report_counts = counts.get("report_ready", {})
        promoted_counts = counts.get("promoted", {})
        warnings_counts = counts.get("warnings", {})

        summary = (
            f"Findings {findings_counts.get('base', 0)} → {findings_counts.get('compare', 0)} "
            f"({findings_counts.get('delta', 0):+}) | "
            f"Report-ready {report_counts.get('base', 0)} → {report_counts.get('compare', 0)} "
            f"({report_counts.get('delta', 0):+}) | "
            f"Promoted {promoted_counts.get('base', 0)} → {promoted_counts.get('compare', 0)} "
            f"({promoted_counts.get('delta', 0):+}) | "
            f"Warnings {warnings_counts.get('base', 0)} → {warnings_counts.get('compare', 0)} "
            f"({warnings_counts.get('delta', 0):+})"
        )
        self.diff_summary_var.set(summary)

        self.diff_new_cache = self._diff_list_payload(diff.get("new", []), compare_run_id)
        self.diff_removed_cache = self._diff_list_payload(diff.get("removed", []), base_run_id)
        self.diff_changed_cache = self._diff_list_payload(diff.get("changed", []), compare_run_id)

        self._render_diff_list(self.diff_new_list, self.diff_new_cache, prefix="NEW")
        self._render_diff_list(self.diff_removed_list, self.diff_removed_cache, prefix="REMOVED")
        self._render_diff_list(self.diff_changed_list, self.diff_changed_cache, prefix="CHANGED")

    def _diff_list_payload(self, items: list, run_id: str) -> list:
        payload = []
        for item in items:
            if item.get("summary"):
                merged = dict(item.get("summary") or {})
                merged["stable_id"] = item.get("stable_id")
            elif "to" in item:
                merged = dict(item.get("to") or {})
                merged.update({
                    "stable_id": item.get("stable_id"),
                    "title": item.get("title", ""),
                    "target": item.get("target", ""),
                    "tool": item.get("tool", ""),
                })
            else:
                merged = item
            payload.append({
                "stable_id": merged.get("stable_id"),
                "title": merged.get("title", ""),
                "severity": merged.get("severity", ""),
                "classification": merged.get("classification", ""),
                "confidence": merged.get("confidence", 0.0),
                "target": merged.get("target", ""),
                "tool": merged.get("tool", ""),
                "run_id": run_id,
            })
        return payload

    def _render_diff_list(self, listbox: tk.Listbox, items: list, prefix: str):
        listbox.delete(0, tk.END)
        for item in items:
            title = item.get("title") or item.get("stable_id") or "<untitled>"
            label = f"{item.get('severity', '')} | {item.get('classification', '')} | {title}"
            listbox.insert(tk.END, label)

    def _load_diff_detail(self, list_name: str):
        if list_name == "new":
            listbox = self.diff_new_list
            items = getattr(self, "diff_new_cache", [])
        elif list_name == "removed":
            listbox = self.diff_removed_list
            items = getattr(self, "diff_removed_cache", [])
        else:
            listbox = self.diff_changed_list
            items = getattr(self, "diff_changed_cache", [])
        selection = listbox.curselection()
        if not selection:
            return
        item = items[selection[0]]
        stable_id = item.get("stable_id")
        run_id = item.get("run_id")
        if not stable_id or not run_id:
            return
        client = self._get_client()
        try:
            detail = client.get_finding_detail(run_id, stable_id)
        except Exception as exc:
            messagebox.showerror("Diff", f"Failed to load detail: {exc}")
            return
        self.detail_run_id = run_id
        self.finding_detail_payload = detail

        meta = (
            f"{detail.get('severity', '').upper()} | "
            f"Conf: {detail.get('confidence', 0):.2f} | "
            f"{detail.get('classification', '')}"
        )
        self.finding_meta.config(text=meta)

        self.evidence_cache = detail.get("evidence", {}).get("anchors", [])
        self.evidence_list.delete(0, tk.END)
        for anchor in self.evidence_cache:
            label = f"{anchor.get('kind')} | {anchor.get('path') or anchor.get('id')}"
            self.evidence_list.insert(tk.END, label)

        self.provenance_cache = detail.get("provenance", {}).get("derived_from", [])
        self.provenance_list.delete(0, tk.END)
        produced_by = detail.get("provenance", {}).get("produced_by", "unknown")
        self.provenance_list.insert(tk.END, f"produced_by: {produced_by}")
        for ref in self.provenance_cache:
            label = f"{ref.get('kind')} | {ref.get('id')}"
            self.provenance_list.insert(tk.END, label)

        description = detail.get("description") or detail.get("reproduction") or ""
        self.finding_details.delete("1.0", tk.END)
        self.finding_details.insert(tk.END, description)

    def show_artifacts(self):
        self.clear_content()
        header = ttk.Label(self.content_frame, text="[ ARTIFACTS ]", style="Header.TLabel")
        header.pack(anchor=tk.W)

        controls = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        controls.pack(fill=tk.X, pady=(10, 6))
        ttk.Button(
            controls,
            text="[ REFRESH ]",
            command=self.refresh_artifacts,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(
            controls,
            text="[ OPEN FOLDER ]",
            command=self.open_artifacts_folder,
            style="Matrix.TButton"
        ).pack(side=tk.LEFT)

        self.artifacts_tree = ttk.Treeview(self.content_frame)
        self.artifacts_tree.pack(fill=tk.BOTH, expand=True)
        self.artifacts_tree.bind("<Double-1>", lambda _: self.open_selected_artifact_file())

    def refresh_artifacts(self):
        if not self.current_run_id or not self.current_artifacts_dir:
            self._refresh_run_info()
        if not self.current_artifacts_dir:
            return
        root = Path(self.current_artifacts_dir)
        self.artifacts_tree.delete(*self.artifacts_tree.get_children())

        def insert_node(parent, path: Path):
            node = self.artifacts_tree.insert(parent, tk.END, text=path.name, values=(str(path),))
            if path.is_dir():
                for child in sorted(path.iterdir()):
                    insert_node(node, child)

        insert_node("", root)

    def open_selected_artifact_file(self):
        selection = self.artifacts_tree.selection()
        if not selection:
            return
        path = self.artifacts_tree.item(selection[0], "values")
        if path:
            open_path(Path(path[0]))

    def open_artifacts_folder(self):
        if not self.current_artifacts_dir:
            self._refresh_run_info()
        if self.current_artifacts_dir:
            open_path(Path(self.current_artifacts_dir))

    def _refresh_run_info(self):
        if not self.current_run_id:
            return
        client = self._get_client()
        try:
            info = client.get_run(self.current_run_id)
        except Exception:
            return
        resolved_run_id = info.get("run_id")
        if resolved_run_id and resolved_run_id != self.current_run_id:
            self.current_run_id = resolved_run_id
        self.current_artifacts_dir = info.get("artifacts_dir")
        self.current_run_info = info

    def update_run_controls(self):
        # Check if live mode requirements are met
        live_ready = True
        if self.live_mode.get():
            live_ready = self.live_authorized.get() and self.live_confirm.get().strip() == "I UNDERSTAND"

        # Simple check: plan ready + live requirements (if live mode)
        ready = self.plan_ready and live_ready

        state = tk.NORMAL if ready else tk.DISABLED
        if hasattr(self, "run_button") and self.run_button.winfo_exists():
            self.run_button.config(state=state)

    def _mark_plan_stale(self):
        if self.plan_ready:
            self.plan_ready = False
            self.update_run_controls()

    def show_settings(self):
        self.clear_content()
        header = ttk.Label(self.content_frame, text="[ SETTINGS ]", style="Header.TLabel")
        header.pack(anchor=tk.W)

        form = ttk.Frame(self.content_frame, style="Matrix.TFrame")
        form.pack(fill=tk.X, pady=10)

        ttk.Label(form, text="API URL:", style="Matrix.TLabel").grid(row=0, column=0, sticky=tk.W, padx=4, pady=4)
        ttk.Entry(form, textvariable=self.api_url, width=50).grid(row=0, column=1, sticky=tk.W, padx=4, pady=4)

        ttk.Label(form, text="Artifacts Root:", style="Matrix.TLabel").grid(row=1, column=0, sticky=tk.W, padx=4, pady=4)
        ttk.Entry(form, textvariable=self.artifacts_root, width=50, state="readonly").grid(row=1, column=1, sticky=tk.W, padx=4, pady=4)

        ttk.Label(form, text="Max Workers:", style="Matrix.TLabel").grid(row=2, column=0, sticky=tk.W, padx=4, pady=4)
        ttk.Spinbox(form, from_=1, to=8, textvariable=self.max_workers, width=6).grid(row=2, column=1, sticky=tk.W, padx=4, pady=4)

        info = ttk.Label(
            self.content_frame,
            text="UI is read-only and triggers runs via the API. Tools never execute in the UI.",
            style="Matrix.TLabel",
            wraplength=700,
        )
        info.pack(anchor=tk.W, pady=(10, 0))


def main():
    root = tk.Tk()
    if os.getenv("CHIMERA_MATRIX", "1") in {"0", "false", "no"}:
        ChimeraLauncher(root)
    else:
        MatrixRain(root)
    root.mainloop()


if __name__ == "__main__":
    main()

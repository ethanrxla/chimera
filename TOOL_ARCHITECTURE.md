# Chimera Tool Architecture - Comprehensive Guide

## Overview

Chimera orchestrates **two distinct tool pipelines** for bug bounty penetration testing:

1. **Task Runner Pipeline** - Direct security adapters (Autoswagger, Strix, Shannon)
2. **Recon Pipeline** - Intelligence gathering and enrichment (Zypheron, VibePenTester, Decepticon)

---

## Pipeline 1: Task Runner (Existing)

### Architecture

```
┌─────────────────────────────────────────┐
│         Chimera Orchestrator            │
│  (chimera_core/orchestrator.py)         │
└──────────┬──────────────────────────────┘
           │
           ├──> PlanRunner (runner.py)
           │
     ┌─────┴────────┬──────────┬─────────┐
     │              │          │         │
┌────▼─────┐  ┌────▼────┐ ┌───▼────┐ ┌──▼──────┐
│Autoswagger│  │  Strix  │ │Shannon │ │NetUtils │
│ Adapter   │  │ Adapter │ │Adapter │ │ Adapter │
└───────────┘  └─────────┘ └────────┘ └─────────┘
```

### 1. Autoswagger Adapter

**Purpose**: API endpoint discovery and OpenAPI specification testing

**Location**: `chimera_core/adapters/autoswagger_adapter.py`

**Tool Location**: `tools/autoswagger/autoswagger.py`

**What it does**:
- Discovers API endpoints from web applications
- Attempts to generate OpenAPI/Swagger specs
- Tests API endpoints for common vulnerabilities
- Identifies authentication mechanisms

**Execution**:
```python
command = [sys.executable, str(self.tool_path)]
command.extend(["-rate", str(rate)])
command.extend(targets)
# Runs: python autoswagger.py -rate 10 https://api.example.com
```

**External Dependencies**: Pure Python, HTTP client libraries

**Fixture Mode**: Returns empty findings or mock data

**Live Mode**: Makes real HTTP requests to discover APIs

---

### 2. Strix Adapter

**Purpose**: Web application penetration testing with AI guidance

**Location**: `chimera_core/adapters/strix_adapter.py`

**Tool Location**: `tools/strix/` (Poetry project with multiple modules)

**What it does**:
- AI-guided web application security testing
- Crawls and maps application structure
- Tests for OWASP Top 10 vulnerabilities
- Generates detailed penetration test reports

**Execution**:
```python
command = [sys.executable, "-m", "strix.interface.main", "-n"]
command.extend(["--scan-mode", mode])
command.extend(["--run-name", run_name])
command.extend(["--instruction", instruction])
command.extend(["--target", target])
# Runs: python -m strix.interface.main -n --target https://example.com
```

**External Dependencies**:
- **May use**: Playwright/Selenium for browser automation
- **Potentially integrates**: SQLMap, XSS scanners (configurable)
- Does NOT directly call nmap/netcat (focused on web layer)

**Outputs**:
- `penetration_test_report.md` - Human-readable findings
- `vulnerabilities.csv` - Structured findings
- `vulnerabilities/*.md` - Individual vuln reports

**Fixture Mode**: Returns pre-generated mock findings

**Live Mode**: Actively tests targets, generates real findings

---

### 3. Shannon Adapter

**Purpose**: Advanced verification and AI-powered testing

**Location**: `chimera_core/adapters/shannon_adapter.py`

**Tool Location**: `tools/shannon/` (complex multi-service architecture)

**Architecture**:
```
Shannon = {
  "llm-service": "AI reasoning engine",
  "playwright-service": "Browser automation",
  "desktop": "UI components",
  "deploy": "Kubernetes/Docker configs"
}
```

**What it does**:
- AI-powered vulnerability verification
- Complex attack chain generation
- Proof-of-concept exploit development
- False positive reduction

**Execution Modes**:

**Mode 1: HTTP Driver** (Default)
```python
# Shannon runs as a service
response = httpx.post(
    f"{base_url}/api/v1/tasks",
    json={"query": query, "session_id": session_id}
)
# Poll for results
status = httpx.get(f"{base_url}/api/v1/tasks/{task_id}")
```

**Mode 2: Command Driver**
```python
command = ["shannon-cli", "--target", "{target}", "--output", "{output_dir}"]
result = runtime.run_cmd(command)
```

**External Dependencies**:
- **Playwright**: Browser automation (headless Chrome/Firefox)
- **LLM APIs**: Claude, OpenAI, OpenRouter
- **Potentially configurable**: Custom tools via `allowed_binaries` config

**Fixture Mode**: Returns mock verification results

**Live Mode**: Actually verifies vulnerabilities with browser automation

---

### 4. NetUtils Adapter

**Purpose**: Network utilities wrapper (basic recon)

**Location**: `chimera_core/adapters/net_utils_adapter.py`

**What it does**:
- Basic network connectivity tests
- DNS resolution
- Port checking
- HTTP header inspection

**External Dependencies**: Python standard library (socket, urllib)

---

## Pipeline 2: Recon Gatherers (Separate Orchestrator)

### Architecture

```
┌──────────────────────────────────────────────┐
│      Recon Orchestrator                      │
│  (modules/recon_gatherers/orchestrator.py)   │
└──────────┬───────────────────────────────────┘
           │
           │  Sequential Pipeline:
           │
     ┌─────▼──────────┐
     │   Zypheron     │  Step 1: Asset Discovery
     │   (discover)   │
     └─────┬──────────┘
           │
           │  Discovered assets →
           │
     ┌─────▼──────────┐
     │ VibePenTester  │  Step 2: Penetration Testing
     │   (scan)       │
     └─────┬──────────┘
           │
           │  Scan results + findings →
           │
     ┌─────▼──────────┐
     │  Decepticon    │  Step 3: AI Enrichment
     │  (enrich)      │
     └────────────────┘
           │
           ▼  Promoted findings + suggested actions
```

### 1. Zypheron Adapter

**Purpose**: Reconnaissance and asset discovery

**Location**: `chimera_core/modules/recon_gatherers/zypheron_adapter.py`

**What it does**:
- Asset enumeration (hosts, domains, subdomains)
- Service discovery (open ports, running services)
- Initial network mapping

**Execution**:
```python
command = ["zypheron", "scan", target]
result = runtime.run_external_tool(command, tool_profile=TOOL_PROFILE)
```

**Output Parsing**:
```python
# Parses stdout for structured data:
[ASSET] host: 192.168.1.1
[ASSET] domain: example.com
[SERVICE] host: example.com, port: 443, proto: tcp, service: https
```

**External Tools Used**:
Zypheron is likely a WRAPPER around:
- **nmap**: Port scanning, service detection
- **masscan**: Fast port scanning
- **subfinder/amass**: Subdomain enumeration
- **DNS tools**: dig, host, nslookup

**Fixture Mode**: Returns mock asset lists

**Live Mode**:
- **ACTUALLY RUNS NMAP** and other recon tools
- Performs real network scans
- **IMPORTANT**: Respects scope and rate limits

**Artifacts**:
- `zypheron_stdout.txt` - Tool output with assets
- `zypheron_stderr.txt` - Errors/warnings

---

### 2. VibePenTester Adapter

**Purpose**: Automated penetration testing with reporting

**Location**: `chimera_core/modules/recon_gatherers/vibepentester_adapter.py`

**What it does**:
- Executes penetration tests on discovered assets
- Runs multiple security tools in sequence
- Generates comprehensive reports
- Structured vulnerability output

**Execution**:
```python
cmd = config.entrypoint + ["--target", target_url, "--output", str(output_dir)]
result = runtime.run_external_tool(cmd, cwd=workdir, env=env)
```

**External Tools Used**:
VibePenTester is likely a FRAMEWORK that orchestrates:
- **nmap**: Service version detection
- **nikto**: Web server scanning
- **sqlmap**: SQL injection testing
- **wfuzz/ffuf**: Fuzzing and directory brute-forcing
- **Burp Suite CLI**: Automated scans (if configured)
- **nuclei**: Template-based vulnerability scanning
- **Custom scripts**: Python/bash testing modules

**Configuration**:
```python
VibePenTesterConfig(
    entrypoint=["python", "vibe-pentester.py"],
    workdir=Path("/tools/vibe-pentester"),
    output_dir=Path("/artifacts/reports"),
    extra_args=["--intensity", "medium"],
    env={"API_KEY": "xxx"},
    timeout_s=1800
)
```

**Outputs**:
- Multiple report files (JSON, Markdown, HTML)
- Structured findings parsed into ReconBundle

**Fixture Mode**: Returns pre-generated reports

**Live Mode**:
- **RUNS REAL SECURITY TOOLS**
- Can execute destructive tests (configurable)
- **CRITICAL**: Only runs on authorized targets

---

### 3. Decepticon Adapter

**Purpose**: AI-powered enrichment and finding prioritization

**Location**: `chimera_core/modules/recon_gatherers/decepticon_adapter.py`

**Enricher**: `modules/recon_gatherers/enrichment/decepticon_enricher.py`

**What it does**:
- Analyzes findings from Zypheron + VibePenTester
- Uses AI (LLMs) to correlate and prioritize vulnerabilities
- Generates attack chains and exploitation paths
- Creates "suggested actions" for security researchers
- Promotes high-confidence findings to report-ready status

**Input**: ReconBundles from previous stages
```json
{
  "bundles": [
    {
      "tool": "zypheron",
      "observed_assets": [...],
      "services": [...]
    },
    {
      "tool": "vibepentester",
      "findings": [...]
    }
  ]
}
```

**Execution**:
```python
cmd = config.entrypoint + [
    "--input", str(input_path),  # bundles.json
    "--output", str(output_dir)
]
result = runtime.run_external_tool(cmd)
```

**AI Processing**:
1. **Contextual Analysis**: Understands target environment
2. **Finding Correlation**: Links related vulnerabilities
3. **Impact Assessment**: Calculates real-world severity
4. **Exploitation Planning**: Suggests attack chains
5. **Report Generation**: Creates human-readable analysis

**Outputs**:
- `notes.md`: AI-generated analysis notes
- `suggested_actions.json`: Prioritized action items
- **Promoted findings**: High-confidence vulnerabilities

**External Dependencies**:
- **LLM APIs**: Claude, GPT-4, etc. (via ANTHROPIC_API_KEY, OPENAI_API_KEY)
- **Reasoning engines**: Custom analysis models
- **Knowledge bases**: CVE databases, exploit patterns

**Fixture Mode**: Returns mock enrichment

**Live Mode**: Uses real AI to analyze findings

---

## External Kali Linux Tools Integration

### How Chimera Uses Kali Tools

Chimera integrates with Kali tools through **adapter wrappers** and **safety enforcement**:

#### 1. **Runtime Safety Layer**

**Location**: `chimera_core/runtime.py`

**Safety Checks**:
```python
def run_external_tool(self, command, tool_profile, mode):
    # 1. Validate tool is allowed
    if tool not in safety_policy.allowed_tools:
        raise ValueError(f"Tool {tool} not in allowed list")

    # 2. Check if destructive
    if tool in safety_policy.destructive_tool_markers:
        if not safety_policy.allow_destructive:
            raise ValueError(f"Destructive tool {tool} blocked")

    # 3. Enforce scope
    targets = self._extract_targets(command)
    for target in targets:
        self._check_target_scope(target)  # Validates against allowlist

    # 4. Apply rate limiting
    self.rate_limiter.acquire()

    # 5. Execute with timeout
    result = subprocess.run(command, timeout=timeout_s)
```

#### 2. **Allowed Binaries Configuration**

**Location**: `.env` or `config.json`

```python
# chimera_core/config.py
DEFAULT_CONFIG = {
    "shannon": {
        "allowed_binaries": ["sqlmap", "nmap", "masscan", "nuclei"]
    }
}

# Runtime checks
allowed_binaries = {"python", "python3", "autoswagger", "strix", "curl"}
allowed_binaries.update(config.get("shannon", {}).get("allowed_binaries", []))
```

#### 3. **Safety Policy**

**Location**: `chimera_core/modules/safety/policy.py`

```python
SafetyPolicy(
    enforce_scope=True,
    allow_external_execution=True,  # Must be True for live mode
    allowed_tools=frozenset({"zypheron", "vibepentester", "nmap", "nuclei"}),
    blocked_tools=frozenset({"rm", "dd", "mkfs"}),  # System tools
    destructive_tool_markers=frozenset({"sqlmap", "ffuf", "hydra"}),
    allow_destructive=False,  # Requires explicit enable
    max_workers=2,
    rps=10.0,
    timeout_s=1800
)
```

#### 4. **Tools Likely Used by Each Adapter**

| Adapter | Primary Tools | Purpose | Destructive? |
|---------|--------------|---------|--------------|
| **Zypheron** | nmap, masscan, subfinder, amass, dnsx | Asset discovery | No |
| **VibePenTester** | nmap, nikto, sqlmap, nuclei, wfuzz, ffuf | Active testing | Yes (sqlmap) |
| **Strix** | Playwright, custom scanners | Web testing | Moderate |
| **Shannon** | Playwright, custom exploits | Verification | Moderate |
| **Autoswagger** | HTTP libraries | API discovery | No |

---

## Recommended Integration: Option A

### Add Recon Pipeline Alongside Task Runner

**Why This Is Best**:
1. Keeps existing task runner intact
2. Clear separation of concerns
3. Obvious which pipeline you're running
4. Prevents confusion between fixture and recon results
5. Each pipeline has appropriate safety controls

### Implementation Plan

#### Backend Changes

**1. Add New API Endpoint**

**Location**: `chimera_core/api/routes.py`

```python
@router.post("/v1/recon/run")
async def create_recon_run(request: Request, payload: Dict[str, object]):
    """
    Executes the Recon Pipeline (Zypheron → VibePenTester → Decepticon)
    """
    scope_text = payload.get("scope_text")
    if not scope_text:
        raise HTTPException(status_code=400, detail="scope_text required")

    live = bool(payload.get("live", False))
    live_confirm = payload.get("live_confirm")
    if live and live_confirm != "I UNDERSTAND":
        raise HTTPException(status_code=400, detail="Live confirmation required")

    # Parse scope
    scope_manifest = _load_scope(scope_text)
    scope_graph, scope_policy = normalize_scope(scope_manifest)

    # Extract targets
    targets = payload.get("targets") or scope_graph.allowed_domains

    # Tool configs
    zypheron_config = payload.get("zypheron_config", {})
    vibe_config = VibePenTesterConfig(
        entrypoint=payload.get("vibe_entrypoint", ["python", "vibe-pentester.py"]),
        workdir=Path(payload.get("vibe_workdir", "/app/tools/vibe-pentester")),
        output_dir=Path(payload.get("vibe_output_dir", "/artifacts/vibe-reports")),
        extra_args=payload.get("vibe_extra_args", []),
        env=payload.get("vibe_env", {}),
        timeout_s=payload.get("vibe_timeout_s", 1800),
        mode="live" if live else "fixture"
    )
    decepticon_config = DecepticonConfig(
        entrypoint=payload.get("decepticon_entrypoint", ["python", "decepticon.py"]),
        workdir=Path(payload.get("decepticon_workdir", "/app/tools/decepticon")),
        output_dir=Path(payload.get("decepticon_output_dir", "/artifacts/decepticon-out")),
        extra_args=payload.get("decepticon_extra_args", []),
        env=payload.get("decepticon_env", {}),
        timeout_s=payload.get("decepticon_timeout_s", 1800),
        mode="live" if live else "fixture"
    )

    # Create runtime
    run_manager = RunManager(request.app.state.artifacts_root)
    run = run_manager.create_run(scope_hash="recon-pipeline", mode="live" if live else "safe")

    safety_policy = SafetyPolicy(
        allow_external_execution=live,
        allow_destructive=payload.get("allow_destructive", False),
        allowed_tools=frozenset({"zypheron", "vibepentester", "decepticon", "nmap", "nuclei"}),
        enforce_scope=True,
        rps=payload.get("rate_limit_rps", 10),
        timeout_s=payload.get("timeout_s", 1800)
    )

    runtime = Runtime(
        scope_graph=scope_graph,
        scope_policy=scope_policy,
        event_store=LocalSink(run.artifacts_dir, run.run_id),
        artifacts_root=request.app.state.artifacts_root,
        run_id=run.run_id,
        safety_policy=safety_policy,
        mode="live" if live else "fixture"
    )

    sink = ReconSink(artifacts_root=runtime.artifacts_root, run_id=run.run_id)

    def _run_pipeline():
        try:
            # Step 1: Zypheron
            zypheron_results = []
            for target in targets:
                result = run_zypheron_and_persist(
                    target=target,
                    runtime=runtime,
                    sink=sink,
                    program_handle=payload.get("program_name")
                )
                zypheron_results.append(result)

            # Step 2: VibePenTester
            vibe_results = []
            for target in targets:
                result = run_vibepentester_and_persist(
                    target=target,
                    runtime=runtime,
                    config=vibe_config,
                    sink=sink,
                    program_handle=payload.get("program_name")
                )
                vibe_results.append(result)

            # Step 3: Decepticon (enriches all findings)
            all_bundles = []
            for result in zypheron_results + vibe_results:
                all_bundles.extend(result.bundles)

            decepticon_result = run_decepticon_and_persist(
                bundles=all_bundles,
                runtime=runtime,
                config=decepticon_config,
                sink=sink,
                program_handle=payload.get("program_name")
            )

            return {
                "status": "completed",
                "zypheron": len(zypheron_results),
                "vibepentester": len(vibe_results),
                "decepticon": decepticon_result
            }
        except Exception as exc:
            return {"status": "failed", "error": str(exc)}

    # Run in background thread
    thread = threading.Thread(target=_run_pipeline, daemon=True)
    thread.start()

    return JSONResponse({
        "run_id": run.run_id,
        "pipeline": "recon",
        "status": "created",
        "targets": targets,
        "mode": "live" if live else "fixture"
    })
```

**2. Add Supporting Endpoints**

```python
@router.get("/v1/recon/runs/{run_id}")
async def get_recon_run(request: Request, run_id: str):
    """Get recon pipeline run status and results"""
    pass

@router.get("/v1/recon/runs/{run_id}/bundles")
async def get_recon_bundles(request: Request, run_id: str):
    """Get all ReconBundles from a run"""
    pass

@router.get("/v1/recon/runs/{run_id}/suggested_actions")
async def get_suggested_actions(request: Request, run_id: str):
    """Get Decepticon's suggested actions"""
    pass
```

#### UI Changes

**Location**: `chimera/chimera-ui/launcher.py`

**1. Add Pipeline Selector to Runs Page**

```python
def show_runs(self):
    # ... existing code ...

    # Add Pipeline Selector
    pipeline_frame = ttk.Frame(self.content_frame, style="Matrix.TFrame")
    pipeline_frame.pack(fill=tk.X, pady=10)

    ttk.Label(
        pipeline_frame,
        text="Pipeline:",
        style="Matrix.TLabel"
    ).pack(side=tk.LEFT, padx=5)

    self.pipeline_var = tk.StringVar(value="task_runner")

    ttk.Radiobutton(
        pipeline_frame,
        text="Task Runner (Autoswagger/Strix/Shannon)",
        variable=self.pipeline_var,
        value="task_runner",
        command=self._on_pipeline_changed
    ).pack(side=tk.LEFT, padx=10)

    ttk.Radiobutton(
        pipeline_frame,
        text="Recon Pipeline (Zypheron/Vibe/Decepticon)",
        variable=self.pipeline_var,
        value="recon",
        command=self._on_pipeline_changed
    ).pack(side=tk.LEFT, padx=10)

    # Config sections (show/hide based on pipeline)
    self._create_task_runner_config()  # Existing
    self._create_recon_config()  # New

def _create_recon_config(self):
    """Create Recon Pipeline configuration UI"""
    self.recon_config_frame = ttk.Frame(self.content_frame, style="Matrix.TFrame")

    # Zypheron Config
    zypheron_frame = ttk.LabelFrame(
        self.recon_config_frame,
        text="Zypheron (Asset Discovery)",
        style="Matrix.TFrame"
    )
    zypheron_frame.pack(fill=tk.X, pady=5)

    # Binary path
    ttk.Label(zypheron_frame, text="Binary:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    self.zypheron_binary = tk.StringVar(value="zypheron")
    ttk.Entry(zypheron_frame, textvariable=self.zypheron_binary, width=40).grid(row=0, column=1, padx=5, pady=2)

    # VibePenTester Config
    vibe_frame = ttk.LabelFrame(
        self.recon_config_frame,
        text="VibePenTester (Scanning)",
        style="Matrix.TFrame"
    )
    vibe_frame.pack(fill=tk.X, pady=5)

    # Entrypoint
    ttk.Label(vibe_frame, text="Entrypoint:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
    self.vibe_entrypoint = tk.StringVar(value="python vibe-pentester.py")
    ttk.Entry(vibe_frame, textvariable=self.vibe_entrypoint, width=40).grid(row=0, column=1, padx=5, pady=2)

    # Workdir
    ttk.Label(vibe_frame, text="Workdir:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
    self.vibe_workdir = tk.StringVar(value="/app/tools/vibe-pentester")
    ttk.Entry(vibe_frame, textvariable=self.vibe_workdir, width=40).grid(row=1, column=1, padx=5, pady=2)

    # Output dir
    ttk.Label(vibe_frame, text="Output Dir:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
    self.vibe_output_dir = tk.StringVar(value="/artifacts/vibe-reports")
    ttk.Entry(vibe_frame, textvariable=self.vibe_output_dir, width=40).grid(row=2, column=1, padx=5, pady=2)

    # Decepticon Config
    decepticon_frame = ttk.LabelFrame(
        self.recon_config_frame,
        text="Decepticon (AI Enrichment)",
        style="Matrix.TFrame"
    )
    decepticon_frame.pack(fill=tk.X, pady=5)

    # Similar fields as VibePenTester
    # ... (entrypoint, workdir, output_dir)

    # Initially hide recon config
    self.recon_config_frame.pack_forget()

def _on_pipeline_changed(self):
    """Toggle config visibility based on selected pipeline"""
    if self.pipeline_var.get() == "task_runner":
        self.recon_config_frame.pack_forget()
        self.task_runner_config_frame.pack(fill=tk.X, pady=10)
    else:
        self.task_runner_config_frame.pack_forget()
        self.recon_config_frame.pack(fill=tk.X, pady=10)

def _submit_run(self):
    """Submit run based on selected pipeline"""
    pipeline = self.pipeline_var.get()

    if pipeline == "task_runner":
        self._submit_task_runner_run()  # Existing logic
    else:
        self._submit_recon_run()  # New logic

def _submit_recon_run(self):
    """Submit Recon Pipeline run"""
    scope_text = self.scope_text.get("1.0", tk.END).strip()
    if not scope_text:
        messagebox.showinfo("Run", "Paste scope YAML first.")
        return

    live = self.live_mode.get()
    confirm_text = self.live_confirm.get().strip()

    if live:
        confirm = messagebox.askyesno(
            "Live Mode Confirmation",
            "Recon Pipeline will execute REAL TOOLS (nmap, sqlmap, etc.) against targets. Continue?",
        )
        if not confirm:
            return
        if not self.live_authorized.get():
            messagebox.showerror("Run", "Authorization checkbox required for live mode.")
            return
        if confirm_text != "I UNDERSTAND":
            messagebox.showerror("Run", "Live mode requires typing I UNDERSTAND.")
            return

    self.status_var.set("[ RECON RUN SUBMITTED ]")
    client = self._get_client()

    def _run():
        try:
            payload = {
                "scope_text": scope_text,
                "live": live,
                "live_confirm": confirm_text,
                "rate_limit_rps": self.rate_limit_rps.get(),
                "timeout_s": self.per_task_timeout_s.get(),
                "program_name": self.program_name.get(),
                "allow_destructive": self.allow_destructive.get() if hasattr(self, 'allow_destructive') else False,
                # Zypheron config
                "zypheron_config": {
                    "binary": self.zypheron_binary.get()
                },
                # VibePenTester config
                "vibe_entrypoint": self.vibe_entrypoint.get().split(),
                "vibe_workdir": self.vibe_workdir.get(),
                "vibe_output_dir": self.vibe_output_dir.get(),
                "vibe_timeout_s": self.per_task_timeout_s.get(),
                # Decepticon config (similar structure)
            }

            response = client._request_json("POST", "/recon/run", payload=payload)
            self.current_run_id = response.get("run_id")
            self.status_var.set(f"[ RECON RUN CREATED ] {self.current_run_id}")
            self.switch_to_console()
        except Exception as exc:
            self._handle_api_error(exc)

    threading.Thread(target=_run, daemon=True).start()
```

**2. Update Findings Tab**

Add tool filter for recon tools:

```python
def show_findings(self):
    # ... existing code ...

    # Tool filter dropdown
    tool_options = [
        "ALL",
        "autoswagger",
        "strix",
        "shannon",
        "zypheron",
        "vibepentester",
        "decepticon"
    ]

    # ... rest of UI ...
```

**3. Update Artifacts Tab**

Display recon-specific artifacts:

```python
def show_artifacts(self):
    # ... existing code ...

    # Show recon bundles, suggested actions, analysis notes
    if artifact_kind == "suggested_actions":
        # Display Decepticon's action items
        pass
    elif artifact_kind == "analysis_notes":
        # Display Decepticon's markdown notes
        pass
```

---

## Event Flow Examples

### Task Runner Pipeline

```json
// Task Runner events
{
  "event_type": "execution_phase_started",
  "payload": {
    "mode": "live",
    "task_count": 3,
    "message": "Starting execution of 3 tasks in LIVE mode"
  }
}

{
  "event_type": "task_executing",
  "payload": {
    "adapter": "strix",
    "target": "https://example.com",
    "mode": "live",
    "message": "Executing strix against https://example.com in live mode"
  }
}

{
  "event_type": "cmd_started",
  "payload": {
    "command": ["python", "-m", "strix.interface.main", "--target", "https://example.com"]
  }
}

{
  "event_type": "artifact_saved",
  "payload": {
    "path": "/artifacts/run-123/strix/task-0/raw_output.json",
    "tool": "strix"
  }
}

{
  "event_type": "task_completed",
  "payload": {
    "task_id": "strix-scan-0",
    "findings_count": 3,
    "artifacts_count": 5
  }
}
```

### Recon Pipeline

```json
// Recon Pipeline events
{
  "event_type": "recon_phase_started",
  "payload": {
    "phase": "asset_discovery",
    "tool": "zypheron",
    "targets": ["example.com"]
  }
}

{
  "event_type": "cmd_started",
  "payload": {
    "command": ["zypheron", "scan", "example.com"],
    "mode": "live"
  }
}

{
  "event_type": "assets_discovered",
  "payload": {
    "observed_assets": [
      {"type": "host", "value": "192.168.1.1"},
      {"type": "domain", "value": "api.example.com"}
    ],
    "services": [
      {"host": "example.com", "port": 443, "service": "https"}
    ]
  }
}

{
  "event_type": "recon_phase_started",
  "payload": {
    "phase": "penetration_testing",
    "tool": "vibepentester"
  }
}

{
  "event_type": "findings_discovered",
  "payload": {
    "tool": "vibepentester",
    "findings_count": 12
  }
}

{
  "event_type": "recon_phase_started",
  "payload": {
    "phase": "enrichment",
    "tool": "decepticon"
  }
}

{
  "event_type": "enrichment_completed",
  "payload": {
    "promoted_findings": 3,
    "suggested_actions": 5
  }
}
```

---

## Safety and Compliance

### Live Mode Checklist

Before enabling live mode for Recon Pipeline:

- [ ] **Authorization**: Explicit permission to test targets
- [ ] **Scope Validation**: All targets in allowlist
- [ ] **Rate Limits**: Configured to avoid DoS
- [ ] **Destructive Tools**: Explicitly enabled only if needed
- [ ] **Monitoring**: Console streaming active
- [ ] **Scope File**: Properly configured with denylist
- [ ] **Bug Bounty Rules**: Program allows automated scanning

### Tool Permissions

| Tool | Requires Live Mode | Destructive | Needs Authorization |
|------|-------------------|-------------|---------------------|
| Autoswagger | Yes | No | Moderate |
| Strix | Yes | Moderate | Yes |
| Shannon | Yes | Moderate | Yes |
| Zypheron | Yes | No | Yes |
| VibePenTester | Yes | **Yes** | **Absolutely** |
| Decepticon | Yes (for AI) | No | Yes |

### Blocked Operations

Chimera **NEVER** allows:
- System-level destructive commands (`rm -rf`, `dd`, `mkfs`)
- Attacks on private IPs (unless explicitly enabled)
- Targets outside scope
- Rate limit violations
- Execution without proper authorization in live mode

---

## Summary

**Task Runner Pipeline** (Current):
- Direct adapters for web/API security testing
- Autoswagger, Strix, Shannon work independently
- Each produces findings immediately
- Live mode executes tools against targets

**Recon Pipeline** (Separate, needs integration):
- Sequential intelligence gathering → testing → enrichment
- Zypheron → VibePenTester → Decepticon
- Each stage builds on previous
- Uses external Kali tools (nmap, sqlmap, etc.)
- AI enrichment produces actionable intelligence

**Integration Recommendation**:
- Add `/v1/recon/run` API endpoint
- Add Pipeline selector in UI
- Keep both pipelines separate
- Reuse existing safety infrastructure
- Document tool permissions clearly

**External Tools Used**:
- **Zypheron**: nmap, masscan, subfinder, amass
- **VibePenTester**: nmap, nikto, sqlmap, nuclei, ffuf
- **Strix**: Playwright (browser automation)
- **Shannon**: Playwright, custom exploits
- **Decepticon**: LLM APIs (Claude, GPT-4)

All external tool execution is:
1. Validated against allowlist
2. Scope-enforced
3. Rate-limited
4. Timeout-controlled
5. Logged with full provenance

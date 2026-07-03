# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Chimera is an evidence-driven application security orchestration platform for bug bounty and pentest work. It normalizes scope, routes work through capability-driven planning, executes tool chains, and produces deterministic validators with replay artifacts. LLMs generate hypotheses; validators produce proof.

## Commands

### chimera-core (Python / FastAPI)

```bash
cd chimera/chimera-core
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

# Run API server
uvicorn chimera_core.api.app:create_app --factory --host 127.0.0.1 --port 8000

# Run CLI
PYTHONPATH=chimera-core python3 -m chimera_core <command>   # config | runs | findings | sync-db

# Tests
.venv/bin/python -m pytest tests/unit -q
.venv/bin/python -m pytest tests/integration/test_api.py -q
.venv/bin/python -m pytest tests/unit/test_scope.py::test_scope_allowlist_allows_subdomains -v
.venv/bin/python -m pytest tests/ -m "not live" -q          # skip tests requiring a live target
.venv/bin/python -m pytest tests/unit -q --cov=chimera_core
```

`pytest.ini` sets `asyncio_mode = auto`. The `live` marker gates tests that need a real target.

### chimera-cli (Rust)

```bash
cd chimera/chimera-cli
cargo build
cargo run -- --help
cargo run -- --target https://crapi.example.com
cargo test
```

### Docker Compose

```bash
# Core stack
docker compose up -d chimera-core chimera-cli chimera-ui

# Include optional local LLM (GPU required)
docker compose --profile local-llm up -d sec-llm shannon chimera-core chimera-ui chimera-cli

# Include vulnerable lab targets
docker compose --profile lab up -d juice-shop metasploitable2

# Build individual images
docker build -f chimera/docker/core.Dockerfile -t chimera-core .
docker build -f chimera/docker/cli.Dockerfile  -t chimera-cli .
docker build -f chimera/docker/ui.Dockerfile   -t chimera-ui .
```

Secrets go in a `.env` file at the repo root (not committed). Key env vars:
- `CHIMERA_ARTIFACTS_DIR`, `CHIMERA_CACHE_DIR`
- `STRIX_LLM` (e.g. `openai/gpt-5`)
- `SHANNON_BASE_URL` (defaults to `http://shannon:8080`)
- `CHIMERA_API_BASE` (CLI → core, defaults to `http://chimera-core:8000/v1`)

## Architecture

### Services

| Service | Stack | Port | Purpose |
|---------|-------|------|---------|
| **chimera-core** | Python / FastAPI | 8000 | Orchestrator, planner, validators, API |
| **chimera-cli** | Rust / ratatui | — | TUI control surface; HTTP client to core |
| **chimera-ui** | Python / Tkinter + xvfb | — | Browser launcher (Playwright) |
| **shannon** | Python | 8080 | 3-stage LLM oracle (planner→executor→validator); executor has live HexStrike tool-call loop |
| **hexstrike** | Python / FastAPI + Flask | 8888 | Unified tool execution server: 150+ active security tools (nmap, nuclei, gobuster, sqlmap, dalfox, ffuf, katana, subfinder, httpx, nikto, …) + LLM-powered analysis endpoints |
| **ollama** | Ollama | 11434 | Local GPU inference for Shannon (qwen2.5-coder:7b planner/validator, whiterabbitneo-13b executor) |
| **sec-llm** | vLLM (local-llm profile) | 8001 | OpenAI-compatible local inference (Ampere/Hopper only; use Ollama on RTX 50-series) |
| **juice-shop** | OWASP Juice Shop (lab) | 3000 | Vulnerable practice target |

### chimera-core internals

```
chimera_core/
├── api/
│   ├── app.py          # FastAPI factory (create_app)
│   ├── routes.py       # /v1/runs, /status, /parser, /browser, /chains, /replays
│   └── recon_routes.py
├── adapters/           # Tool integrations: autoswagger, strix, shannon, browser, subfinder …
├── validators/         # Deterministic validators: bola, auth, jwt, rate_limit
├── modules/
│   ├── recon_gatherers/  # Recon pipeline
│   ├── safety/           # Safety policy enforcement
│   └── runtime/
├── sinks/              # Artifact persistence: local, supabase, tee
├── capabilities/       # Browser capability registry
├── orchestrator.py     # Job lifecycle management
├── runner.py           # PlanRunner – executes plans step by step
├── runtime.py          # Task scheduler
├── planner.py          # Capability-driven plan generation
├── scope.py            # ScopeGraph – allowlist/denylist enforcement
├── findings.py         # Finding data model
└── events.py           # Disk-backed event bus / event store
```

### Data flow

1. **Scope** manifest (YAML) → `ScopeGraph` enforces allow/deny at every step
2. **Planner** selects tool chain based on declared capabilities, not a fixed pipeline
3. **Adapters** execute: `autoswagger` → `strix` → `shannon` (oracle)
   - Strix supports partial-success: exit code ≠ 0 is accepted when `events.jsonl` contains `run.completed` or `vulnerabilities.csv` has data rows. Only the failed task's downstream dependents are blocked; independent chains continue.
   - Shannon's executor stage has a live tool-call loop: it emits `<hexstrike_call>` blocks, Chimera dispatches to HexStrike, injects results back, and re-runs up to `HEXSTRIKE_MAX_TOOL_TURNS` times (default 3).
4. **Validators** produce deterministic proof with replay artifacts
5. **Chain analysis** escalates correlated low-severity findings into exploit chains
6. **Sinks** persist JSON, markdown, and POC bundles (local or Supabase)

### Key concepts

- **Scope-first**: Every run starts from a scope manifest; the runtime refuses out-of-scope requests.
- **Evidence graph**: Findings carry prerequisites, proof artifacts, validation status, and chain links.
- **Deterministic validation**: Shannon/LLMs suggest; validators prove. Findings without proof are hypotheses only.
- **Deterministic chain analysis**: Exploit chains are inferred from explicit rule preconditions (`CHAIN_RULES` in `chimera_core/chain_analysis.py`), not LLM judgment. This means you can prove the analyzer is **complete** (fires on every valid rule match) and **sound** (never fires when preconditions don't hold) purely with in-memory `Finding` objects — no live target needed. Tests should call `synthesize_chains()` directly. Add a new `ChainRule` before writing a test for it; the test failing RED proves the rule is absent, passing GREEN proves it fires correctly.
- **Capability routing**: The planner matches job requirements against adapter capabilities — there is no hard-coded tool order.

## Mathematical specification

`docs/spec/math_spec.md` is the formal specification of Chimera's runtime guarantees. It defines:
- Scope enforcement as a set-language constraint with the `InScope(x)` predicate
- Execution plans as DAGs with feasibility/precedence/rate-limit constraints
- Event log invariants (monotone `seq`, run-local consistency)
- The evidence graph `G=(V,E)` with typed nodes and labelled edges
- Eight must-hold invariants (I-SCOPE-1 through I-ART-2, I-PROV-1)
- Property-based test ideas (§9) tied directly to the repo schema

When writing tests or validators, check `docs/spec/math_spec.md` §8–9 first — the invariants are the source of truth for what a test must prove.

## Scope manifests

Example files: `scope.yml`, `scope_juiceshop.yml`, `scope_test.yml` at the repo root. Pass a scope file to a run to constrain allowed targets and tool behaviour.

## Tools directory

`tools/` contains bundled integrations shipped alongside core:

- `autoswagger/` – OpenAPI spec discovery and endpoint enumeration
- `strix/` – Active testing engine; includes 19 HexStrike tool wrappers (`strix/strix/tools/hexstrike/`)
- `shannon/` / `shannon-svc/` – LLM oracle (also runs as a standalone service); executor stage calls HexStrike tools live during analysis
- `hexstrike-mcp/` – Unified tool execution server: proxies upstream [hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) (150+ tools, Flask, port 8887) plus our own FastAPI LLM-analysis endpoints (port 8889) behind a single proxy on port 8888. The 19 tools accessible from Strix/Shannon map to `/api/tools/<name>` routes on the Flask upstream.
- `zypheron/` – Extended recon
- `vibe-pentester/` – Vibe-mode test runner
- `decepticon/` – Deception/honeypot utilities

`tools/registry.json` is the canonical list of available tools and their capabilities.

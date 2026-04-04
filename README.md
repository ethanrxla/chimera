# Chimera

Chimera is an evidence-driven bug bounty and application security orchestration platform. This repository is the top-level workspace for the Python runtime, Rust CLI, UI shell, bundled tool integrations, Docker assets, and local lab targets used to run and validate the stack.

## Repository Layout

- `chimera/`: primary product code and docs
- `chimera/chimera-core/`: FastAPI runtime, planner, validators, reporting, and artifact persistence
- `chimera/chimera-cli/`: Rust operator CLI and TUI
- `chimera/chimera-ui/`: legacy UI launcher and assets
- `chimera/docker/`: Dockerfiles for the core, CLI, and UI containers
- `tools/`: bundled external tools and adapters used by Chimera
- `docs/`: top-level design and configuration notes
- `chimera_master_plan.md`: execution roadmap and current strategic direction

## What This Repo Supports

- Scope-first scan orchestration for web, API, and browser targets
- Capability-driven planning instead of a fixed single scan chain
- Deterministic validators and replay artifacts for findings
- Dockerized operator workflow for the API, CLI, and UI
- Optional local lab targets for end-to-end testing

## Quick Start

Prerequisites:

- Docker Desktop or a working Docker Engine
- WSL integration enabled if you are running from WSL
- an `.env` file at the repo root if you need non-default secrets or model settings

Start the main stack:

```bash
cd /home/theif/projects/kali-docker
docker compose up -d chimera-core chimera-ui chimera-cli
```

Useful follow-up commands:

```bash
docker compose ps
docker compose logs -f chimera-core
docker compose exec chimera-cli bash
```

The main services are:

- `chimera-core`: FastAPI runtime on port `8000`
- `chimera-ui`: containerized UI launcher
- `chimera-cli`: persistent Rust CLI container for `docker compose exec`

## Local Security Model Service

Chimera's `shannon` verification service can target either Anthropic or an OpenAI-compatible backend. The repo now defaults to the local OpenAI-compatible path, and the bundled vLLM service defaults to `WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B`.

Use an external OpenAI-compatible endpoint:

```bash
export SHANNON_PROVIDER=openai_compatible
export SHANNON_MODEL=WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B
export SHANNON_OPENAI_BASE_URL=http://<your-llm-host>:8000/v1
export SHANNON_OPENAI_API_KEY=dummy
docker compose up -d shannon chimera-core chimera-ui chimera-cli
```

Or run the bundled local vLLM profile on a GPU host with the default WhiteRabbit preset:

```bash
export HUGGING_FACE_HUB_TOKEN=hf_...
docker compose --profile local-llm up -d sec-llm shannon chimera-core chimera-ui chimera-cli
```

Switch presets without changing Chimera:

```bash
# Default preset
export LOCAL_LLM_PRESET=whiterabbit-qwen

# Alternative presets
export LOCAL_LLM_PRESET=whiterabbit-llama-8b
export LOCAL_LLM_PRESET=deephat
```

Notes:

- The optional `sec-llm` service uses `vllm/vllm-openai` and exposes port `8001` on the host.
- It keeps `deephat` as a Docker network alias for backward compatibility.
- The model weights are cached under `${HOME}/.cache/huggingface`.
- No manual model repo clone is required for the default path. `vLLM` downloads the model weights from Hugging Face into the mounted cache on first start.
- WhiteRabbitNeo and DeepHat both carry additional usage restrictions beyond their base model licenses. Review the model cards before enabling them in production workflows.

## Optional Lab Targets

Bring up the local lab profile:

```bash
cd /home/theif/projects/kali-docker
docker compose --profile lab up -d juice-shop metasploitable2
```

Lab services included in the root `docker-compose.yml`:

- `juice-shop`: OWASP Juice Shop on port `3000`
- `metasploitable2`: Metasploitable 2 on ports `2222`, `8080`, and `8443`

The repo also includes a Juice Shop-specific scope manifest:

```bash
scope_juiceshop.yml
```

## Typical Workflow

Run the stack:

```bash
docker compose up -d chimera-core chimera-ui chimera-cli
```

Check health from inside the core container:

```bash
docker exec chimera-core python -c 'import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000/v1/health").read().decode())'
```

Open a shell in the CLI container:

```bash
docker compose exec chimera-cli bash
```

For direct local development outside Docker, use the product docs in `chimera/README.md`.

## Primary Docs

- [chimera/README.md](/home/theif/projects/kali-docker/chimera/README.md): main product overview, API usage, CLI usage, and current MVP status
- [chimera/docs/DEV_QUICKSTART.md](/home/theif/projects/kali-docker/chimera/docs/DEV_QUICKSTART.md): developer quickstart
- [chimera/docs/CLI_Operations_Guide.md](/home/theif/projects/kali-docker/chimera/docs/CLI_Operations_Guide.md): CLI operations
- [docs/UNIFIED_CONFIG_USAGE.md](/home/theif/projects/kali-docker/docs/UNIFIED_CONFIG_USAGE.md): unified configuration notes
- [chimera_master_plan.md](/home/theif/projects/kali-docker/chimera_master_plan.md): roadmap and execution plan

## Current Focus

The current repo state is centered on:

- stabilizing the Dockerized operator workflow
- validating live end-to-end runs against local lab targets
- wiring the Rust CLI cleanly into the newer parser, oracle, chain, and replay APIs
- hardening browser-backed execution and packaging

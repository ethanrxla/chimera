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

## First-Time Setup

### 1. Clone with submodules

The `tools/` integrations are git submodules. Clone everything in one command:

```bash
git clone --recurse-submodules https://github.com/ethanrxla/chimera.git
cd chimera
```

If you already cloned without `--recurse-submodules`, initialise them now:

```bash
git submodule update --init --recursive
```

> Upstream submodule commits may occasionally be unreachable (force-pushed/deleted). Git will fall back to the remote's HEAD — the tools still work; run `git submodule status` to see any drift.

### 2. Create your `.env`

```bash
cp .env.example .env
```

Open `.env` and fill in at minimum `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) for the core stack to function. All variables are documented with comments in `.env.example`.

### 3. Install Docker Engine (native, not Docker Desktop)

```bash
sudo apt update
sudo apt install -y docker.io
sudo usermod -aG docker "$USER"
# Log out and back in, or: newgrp docker
```

> Docker Desktop is not required and not recommended on Linux. Use native `docker.io` + Compose plugin.

### 4. Start the core stack

```bash
docker compose up -d chimera-core chimera-ui chimera-cli
```

Useful follow-up commands:

```bash
docker compose ps
docker compose logs -f chimera-core
docker compose exec chimera-cli bash
```

### 5. Build the Rust CLI (optional, recommended for TUI)

Running the CLI binary directly on the host gives the best terminal experience (proper resize, persistent state at `~/.config/chimera/`):

```bash
# One-time: install Rust if not present
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"

# Build
cd chimera/chimera-cli
cargo build --release
# Binary: chimera/chimera-cli/target/release/chimera-cli
# Default API base is http://127.0.0.1:8000/v1 (points at the containerised core)
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

Or run a local GPU model via Ollama + GGUF — the recommended path for RTX 50-series (Blackwell):

```bash
# 1. Start Ollama with GPU
COMPOSE_PROFILES=ollama docker compose up -d ollama

# 2. Pull the model (one-time, ~8 GB download)
docker exec ollama-gpu ollama pull hf.co/bartowski/WhiteRabbitNeo-13B-v1-GGUF:Q4_K_M

# 3. Confirm the model name Ollama assigned
docker exec ollama-gpu ollama list

# 4. Start the rest of the stack
COMPOSE_PROFILES=ollama,lab docker compose up -d shannon chimera-core chimera-cli juice-shop
```

Shannon's default `SHANNON_OPENAI_BASE_URL` already points to `http://ollama:11434/v1`. The only `.env` values needed:

```bash
SHANNON_PROVIDER=openai_compatible
SHANNON_MODEL=hf.co/bartowski/WhiteRabbitNeo-13B-v1-GGUF:Q4_K_M
```

**7B fallback** if 13B exceeds VRAM (~4 GB instead of ~8 GB):

```bash
docker exec ollama-gpu ollama pull hf.co/bartowski/WhiteRabbitNeo-V3-7B-GGUF:IQ4_XS
# then set: SHANNON_MODEL=hf.co/bartowski/WhiteRabbitNeo-V3-7B-GGUF:IQ4_XS
```

> **Compose v5 note:** `--profile` flags combined with explicit service names trigger a validation bug in Docker Compose v5 (`no such service`). Use `COMPOSE_PROFILES=` as an environment variable instead — it is evaluated before service name resolution.

Notes:

- Ollama model weights are stored in the `ollama-models` Docker volume — no re-download on container restart.
- `SHANNON_OPENAI_API_KEY` defaults to `dummy` — Ollama does not require auth.
- WhiteRabbitNeo carries additional usage restrictions beyond its base model license. Review the model card before enabling in production workflows.

## Alternative: vLLM / AWQ (non-Blackwell hardware only)

> **RTX 50-series warning:** `vllm/vllm-openai:latest` does not ship compiled CUDA kernels for Blackwell (sm_120) and crashes silently before emitting logs. Use the Ollama path above on RTX 5070/5080/5090.

On CUDA 12 / Ampere-Hopper hardware, the `local-llm` profile runs vLLM with AWQ quantization:

```bash
export HUGGING_FACE_HUB_TOKEN=hf_...
export SHANNON_PROVIDER=openai_compatible
export SHANNON_MODEL=Mistral-7B-Instruct-v0.3-AWQ
COMPOSE_PROFILES=local-llm docker compose up -d sec-llm shannon chimera-core chimera-cli
```

Available presets via `LOCAL_LLM_PRESET`: `whiterabbit-qwen` (default) · `whiterabbit-13b` · `whiterabbit-llama-8b` · `deephat`.

## GPU Setup (Pop!_OS + Docker Engine + NVIDIA Container Toolkit)

Verify the host GPU driver works:

```bash
nvidia-smi
```

Install Docker Engine (native `docker.io`, not Docker Desktop):

```bash
sudo apt update
sudo apt install -y docker.io
sudo usermod -aG docker "$USER"
newgrp docker   # activates group in current shell; no logout needed
```

If you previously used Docker Desktop or migrated from WSL2, remove the stale credential helper it leaves in `~/.docker/config.json` — native Docker Engine has no `docker-credential-desktop` binary and every `docker pull` will fail with `error getting credentials`:

```bash
python3 -c "
import json, pathlib
p = pathlib.Path.home() / '.docker/config.json'
c = json.loads(p.read_text())
c.pop('credsStore', None)
p.write_text(json.dumps(c, indent='\t'))
print('removed credsStore, done')
"
```

Install NVIDIA Container Toolkit and configure Docker runtime (Ubuntu 24.04 Noble / Pop!_OS 24.04):

```bash
# Add the NVIDIA Container Toolkit repo (modern keyring approach — required on Noble)
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

curl -s -L "https://nvidia.github.io/libnvidia-container/stable/deb/$(. /etc/os-release; echo "$ID$VERSION_CODENAME")/nvidia-container-toolkit.list" \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt update
sudo apt install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

> **Note (Pop!_OS):** The old `nvidia-docker` PPA does not carry a Noble entry. Use the `libnvidia-container` path above instead.

Confirm Docker can see the GPU:

```bash
docker run --rm --gpus all nvidia/cuda:12.6.0-base-ubuntu24.04 nvidia-smi
```

## Ollama (GPU) — quick reference

See the [Local Security Model Service](#local-security-model-service) section above for the full setup. Quick reference for the GGUF pull commands:

```bash
# 13B Q4_K_M (~8 GB VRAM) — recommended for RTX 5070
docker exec ollama-gpu ollama pull hf.co/bartowski/WhiteRabbitNeo-13B-v1-GGUF:Q4_K_M

# 7B IQ4_XS (~4 GB VRAM) — faster, more headroom
docker exec ollama-gpu ollama pull hf.co/bartowski/WhiteRabbitNeo-V3-7B-GGUF:IQ4_XS

# Confirm loaded models and exact name for SHANNON_MODEL
docker exec ollama-gpu ollama list
```

## Optional Lab Targets

Bring up the local lab profile:

```bash
cd /home/ethanrisden/whitehat/chimera
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

- [chimera/README.md](chimera/README.md): main product overview, API usage, CLI usage, and current MVP status
- [chimera/docs/DEV_QUICKSTART.md](chimera/docs/DEV_QUICKSTART.md): developer quickstart
- [chimera/docs/CLI_Operations_Guide.md](chimera/docs/CLI_Operations_Guide.md): CLI operations
- [docs/UNIFIED_CONFIG_USAGE.md](docs/UNIFIED_CONFIG_USAGE.md): unified configuration notes
- [chimera_master_plan.md](chimera_master_plan.md): roadmap and execution plan

## Current Focus

The current repo state is centered on:

- stabilizing the Dockerized operator workflow
- validating live end-to-end runs against local lab targets
- wiring the Rust CLI cleanly into the newer parser, oracle, chain, and replay APIs
- hardening browser-backed execution and packaging

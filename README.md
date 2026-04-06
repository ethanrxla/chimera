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

Or run the bundled local vLLM profile on a GPU host. Shannon must be pointed at sec-llm explicitly — the default provider is Anthropic:

```bash
# Default preset (Mistral-7B AWQ, ~4 GB VRAM)
export HUGGING_FACE_HUB_TOKEN=hf_...
export LOCAL_LLM_PRESET=whiterabbit-qwen
export SHANNON_PROVIDER=openai_compatible
export SHANNON_MODEL=Mistral-7B-Instruct-v0.3-AWQ
COMPOSE_PROFILES=local-llm docker compose up -d sec-llm shannon chimera-core chimera-ui chimera-cli
```

> **Compose v5 note:** `--profile` flags combined with explicit service names trigger a validation bug in Docker Compose v5 (`no such service`). Use `COMPOSE_PROFILES=` as an environment variable instead — it is evaluated before service name resolution.

Switch presets without changing Chimera (set `SHANNON_MODEL` to match the served model name):

```bash
# WhiteRabbitNeo 13B AWQ — best fit for RTX 5070 12 GB (~8 GB VRAM, context 4096)
export LOCAL_LLM_PRESET=whiterabbit-13b
export LOCAL_LLM_MAX_MODEL_LEN=4096
export LOCAL_LLM_GPU_MEMORY_UTILIZATION=0.82
export SHANNON_MODEL=WhiteRabbitNeo-13B-AWQ

# Llama 3.1 8B WhiteRabbitNeo (no AWQ, higher VRAM per token)
export LOCAL_LLM_PRESET=whiterabbit-llama-8b
export SHANNON_MODEL=Llama-3.1-WhiteRabbitNeo-2-8B

# DeepHat 7B
export LOCAL_LLM_PRESET=deephat
export SHANNON_MODEL=DeepHat-V1-7B
```

> **RTX 5070 / Blackwell note:** The vLLM service runs with `--enforce-eager` which disables CUDA graphs. This is required for Blackwell (sm_120) until vLLM ships pre-compiled Blackwell kernels. Inference is slightly slower but functionally correct.

Notes:

- The optional `sec-llm` service uses `vllm/vllm-openai` and exposes port `8001` on the host.
- It keeps `deephat` as a Docker network alias for backward compatibility.
- The model weights are cached under `${HOME}/.cache/huggingface`.
- No manual model repo clone is required for the default path. `vLLM` downloads the model weights from Hugging Face into the mounted cache on first start.
- WhiteRabbitNeo and DeepHat both carry additional usage restrictions beyond their base model licenses. Review the model cards before enabling them in production workflows.

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

## Option A: Run WhiteRabbitNeo via Ollama (GPU)

This repo includes an optional `ollama` profile that runs Ollama with GPU access and persists models in a Docker volume.

Start Ollama:

```bash
docker compose --profile ollama up -d ollama
```

Pull the model once:

```bash
docker exec -it ollama-gpu ollama pull whiterabbitneo
```

Point Shannon at Ollama's OpenAI-compatible endpoint:

```bash
export SHANNON_PROVIDER=openai_compatible
export SHANNON_MODEL=whiterabbitneo
export SHANNON_OPENAI_BASE_URL=http://ollama:11434/v1
export SHANNON_OPENAI_API_KEY=dummy
docker compose up -d shannon chimera-core chimera-ui chimera-cli
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

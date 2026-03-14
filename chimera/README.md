# Chimera

Chimera is an evidence-driven bug bounty and application security orchestration platform.

It is built to find, validate, chain, and replay security issues across web apps, APIs, GraphQL endpoints, browser surfaces, and LLM-assisted workflows without relying on an LLM to prove the vulnerability.

## What Chimera Does

- Normalizes testing scope and enforces it at runtime.
- Routes work through capability-driven planning instead of a fixed tool chain.
- Uses existing tools such as `autoswagger`, `strix`, `zypheron`, `vibepentester`, `decepticon`, `subfinder`, and `shannon`.
- Runs deterministic validators for classes such as BOLA/IDOR, JWT issues, rate limit weaknesses, auth exposure, and DOM-XSS tracing.
- Persists evidence, replay manifests, exploit chains, and report artifacts for each run.
- Produces replayable proof-of-concept artifacts and POC bundles for validated findings and exploit chains.
- Syncs local run artifacts into the existing Supabase database without changing schema.
- Exposes an API and a Rust CLI for scan control, browser sessions, oracle-style hypothesis generation, chain inspection, and replay access.

## Current Layout

- [chimera-core](/home/theif/projects/kali-docker/chimera/chimera-core): Python runtime, planner, validators, API, reporting, DB sync.
- [chimera-cli](/home/theif/projects/kali-docker/chimera/chimera-cli): Rust operator CLI.
- [chimera-ui](/home/theif/projects/kali-docker/chimera/chimera-ui): UI shell and launcher assets.
- [docker](/home/theif/projects/kali-docker/chimera/docker): container assets for the core runtime.
- [docs](/home/theif/projects/kali-docker/chimera/docs): operator and developer documentation.

## Core Concepts

- Scope-first execution: targets are normalized into a scope manifest and enforced during tool execution.
- Evidence graph: findings carry prerequisites, proof artifacts, replay steps, validation status, and chain relationships.
- Deterministic validation: LLMs can suggest hypotheses or action sequences, but validators and replay artifacts prove the issue.
- Chain-aware reporting: low-severity findings can be escalated into exploit-chain records with persisted graphs and POC bundles.

## Main Interfaces

Python core CLI:

```bash
cd /home/theif/projects/kali-docker/chimera
./scripts/run_core.sh --help
```

Core API:

```bash
cd /home/theif/projects/kali-docker/chimera/chimera-core
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn chimera_core.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

Rust operator CLI:

```bash
cd /home/theif/projects/kali-docker/chimera/chimera-cli
. "$HOME/.cargo/env"
cargo run -- --help
```

Dockerized CLI:

```bash
cd /home/theif/projects/kali-docker
docker compose up -d chimera-core chimera-cli
docker compose exec chimera-cli bash
```

## Basic Usage

Run the API, then use either the Python shell wrapper or the Rust CLI.

Example scope:

```yaml
allowlist:
  - https://crapi.example.com
denylist: []
```

Example API actions:

```bash
curl -X POST http://127.0.0.1:8000/v1/parser/interpret \
  -H 'content-type: application/json' \
  -d '{"text":"scan https://crapi.example.com with recon pipeline"}'

curl -X POST http://127.0.0.1:8000/v1/runs \
  -H 'content-type: application/json' \
  -d '{"scope_text":"allowlist:\n  - https://crapi.example.com\ndenylist: []","live":true,"live_confirm":"I UNDERSTAND"}'

curl http://127.0.0.1:8000/v1/status
```

Example Rust CLI actions:

```bash
cargo run -- --target https://crapi.example.com
cargo run -- viz --run <run_id>
cargo run -- chain --run <run_id>
cargo run -- exploit --run <run_id> <chain_id> --replay
```

## Browser And Oracle Endpoints

Chimera now exposes:

- persistent browser sessions under `/v1/browser/sessions`
- parser normalization under `/v1/parser/interpret`
- Shannon oracle hypotheses under `/v1/shannon/oracle`
- Shannon execution tasks under `/v1/shannon/tasks`
- chain and replay APIs under `/v1/runs/{run_id}/chains` and `/v1/runs/{run_id}/replays/{finding_id}`

## Exploit Proofs And Lab Targets

Chimera already supports deterministic exploit proof artifacts through:

- `proof_artifacts`
- `replay_steps`
- `poc_bundles/`
- chain/replay API endpoints

Metasploitable is now available in the root Docker Compose file as an optional lab target:

```bash
cd /home/theif/projects/kali-docker
docker compose --profile lab up -d metasploitable2
```

Current limitation:

- Metasploit/`msfconsole` is not yet a first-class Chimera adapter or validator stage.
- Metasploitable is available as a vulnerable target environment, not as an orchestrated exploit module inside Chimera.

## Reports And Artifacts

Each run persists artifacts under `artifacts/<run_id>/`, including:

- `findings.json`
- `summary.json`
- `report.md`
- `chains.json`
- `chain_graphs.json`
- `rejected_findings.json`
- `poc_bundles/`

## Database Sync

If Supabase is configured, Chimera can sync an existing run directory into the current database tables:

```bash
cd /home/theif/projects/kali-docker/chimera/chimera-core
./.venv/bin/python -m chimera_core sync-db --run-id <run_id> --artifacts-root artifacts
```

## MVP Status

Chimera is already beyond a scanner prototype. The remaining work for a strong MVP is mostly integration polish:

- persistent browser session hardening against real Playwright runtimes
- stronger Shannon/oracle integration with production LLM backends
- CLI consumption of the new parser/oracle/chain/replay endpoints
- end-to-end smoke runs against Juice Shop, crAPI, VAmPI, and an LLM target
- packaging and operator-facing install/run flow cleanup

See [DEV_QUICKSTART.md](/home/theif/projects/kali-docker/chimera/docs/DEV_QUICKSTART.md) and [CLI_Operations_Guide.md](/home/theif/projects/kali-docker/chimera/docs/CLI_Operations_Guide.md) for current operational details.

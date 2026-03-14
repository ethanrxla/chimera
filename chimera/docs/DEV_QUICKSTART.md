# Dev Quickstart

## Prereqs

- Python 3.11+
- Rust toolchain for the Rust CLI
- Playwright-capable environment if you want browser automation
- Optional: Supabase credentials in env for DB sync

## Core Setup

```bash
cd /home/theif/projects/kali-docker/chimera/chimera-core
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Run The Python CLI

```bash
cd /home/theif/projects/kali-docker/chimera
./scripts/run_core.sh --help
```

## Run The API

```bash
cd /home/theif/projects/kali-docker/chimera/chimera-core
. .venv/bin/activate
uvicorn chimera_core.api.app:create_app --factory --host 127.0.0.1 --port 8000
```

## Run The Rust CLI

```bash
cd /home/theif/projects/kali-docker/chimera/chimera-cli
. "$HOME/.cargo/env"
cargo run -- --help
```

## Useful Checks

```bash
cd /home/theif/projects/kali-docker/chimera/chimera-core
.venv/bin/python -m pytest tests/unit -q
.venv/bin/python -m pytest tests/integration/test_api.py -q
```

## Current API Highlights

- `/v1/runs`
- `/v1/status`
- `/v1/browser/sessions`
- `/v1/parser/interpret`
- `/v1/shannon/oracle`
- `/v1/shannon/tasks`
- `/v1/runs/{run_id}/chains`
- `/v1/runs/{run_id}/replays/{finding_id}`

## Notes

- Config defaults to `~/.chimera/config.json`.
- Artifacts default to `chimera/chimera-core/artifacts` unless overridden.
- LLM use is for hypothesis generation and narrative support, not core validation.

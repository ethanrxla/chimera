# CLI Operations Guide

## Interfaces

- Python wrapper: `./scripts/run_core.sh`
- Rust operator CLI: `chimera/chimera-cli`
- Core API: `uvicorn chimera_core.api.app:create_app --factory`

## Scope-First Usage

Example scope:

```yaml
allowlist:
  - https://crapi.example.com
denylist: []
```

The Rust CLI can also infer scope from:

- a pasted target
- a pasted list of targets
- natural language like `scan https://crapi.example.com with recon pipeline`

via `/v1/parser/interpret`.

## Rust CLI

```bash
cd /home/theif/projects/kali-docker/chimera/chimera-cli
. "$HOME/.cargo/env"

cargo run --
cargo run -- console
cargo run -- --target https://crapi.example.com
cargo run -- scan --target https://juice-shop.local --pipeline recon
cargo run -- status
cargo run -- viz --run <run_id>
cargo run -- chain --run <run_id>
cargo run -- exploit --run <run_id> <chain_id> --replay
cargo run -- oracle --run <run_id> "What could go wrong with this GraphQL endpoint?"
```

Running `cargo run --` in a TTY now opens the Chimera operator console. The Ratatui shell is split
into a menu, context panel, recent-runs panel, output/log pane, footer hints, and a bottom input
bar. Startup now opens with a matrix-rain splash screen; press `1` or `Enter` to continue, `?` for
startup help, or set `CHIMERA_MATRIX=0` to skip the splash. The console itself supports three input
modes:

- `NORMAL`: menu-driven navigation and pane switching
- `COMMAND`: exact commands for predictable operator flows
- `NLP`: model-backed requests routed through `/v1/parser/interpret`

Default keys:

```text
j/k or arrows  move
Enter          open or execute
Tab            switch pane
:              command mode
/              NLP mode
?              help modal
q              back or quit
```

Useful console commands:

```text
set target https://crapi.example.com
set workflow standard
set pipeline recon
set program HackerOne Demo
scan quick
show runs
show findings
show logs
theme red
oracle What could go wrong with this GraphQL endpoint?
```

Example NLP prompts:

```text
set the target to 10.0.0.8 and show the next recommended step
run the standard workflow on the current target
why did this command fail
```

## Browser Operations

Browser automation is exposed through `/v1/browser/sessions`.

Typical flow:

1. `POST /v1/browser/sessions`
2. `POST /v1/browser/sessions/{session_id}/analyze`
3. `POST /v1/browser/sessions/{session_id}/suggest-task`
4. `POST /v1/browser/sessions/{session_id}/execute`
5. `POST /v1/browser/sessions/{session_id}/trace-xss`

## Chain And Replay Operations

- `GET /v1/runs/{run_id}/chains`
- `GET /v1/runs/{run_id}/chains/{chain_id}`
- `GET /v1/runs/{run_id}/replays/{finding_id}`

## Shannon Operations

- Hypothesis/oracle: `POST /v1/shannon/oracle`
- Execution task: `POST /v1/shannon/tasks`
- Task polling: `GET /v1/shannon/tasks/{task_id}`

## Troubleshooting

- API down: verify `CHIMERA_API_BASE` or start the core API locally.
- Browser failures: confirm Playwright is installed and the browser runtime is available.
- Scope errors: re-run through `/v1/parser/interpret` or provide a clean YAML scope.
- Missing replay data: confirm the finding or chain was validated and artifacts were persisted.

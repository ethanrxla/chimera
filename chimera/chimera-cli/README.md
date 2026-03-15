# Chimera CLI

`chimera-cli` is the Rust control surface for the Chimera backend.

It is scope-first:
- `chimera-cli --target https://crapi.example.com` generates a valid scope manifest automatically
- `chimera-cli scan --scope-file scope.yaml` uses an existing scope file
- the last target, scope file, pipeline, and run id are remembered in local CLI state

Default API base:

```text
http://127.0.0.1:8000/v1
```

Examples:

```bash
cargo run --
cargo run -- console
cargo run -- --target https://crapi.example.com
cargo run -- scan --target https://juice-shop.local --pipeline recon
cargo run -- status
cargo run -- viz --run <run_id>
cargo run -- chain --run <run_id>
cargo run -- exploit --run <run_id> <chain_id> --replay
```

The CLI is a frontend over the existing Chimera API and artifacts. It does not invent its own protocol.

When launched in a terminal with no subcommand, Chimera now opens an idle ratatui console instead
of printing a one-shot status block. The console keeps recent runs, telemetry, and findings visible
while exposing an msfconsole-style prompt for commands such as:

```text
set target https://crapi.example.com
set pipeline recon
run
use <run_id>
show findings
oracle What could go wrong with this GraphQL endpoint?
```

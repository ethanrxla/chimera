# CLI Operations Guide

## Install / Launch

- Core API: `scripts/run_core.sh`
- UI: `scripts/run_ui.sh`

## Config

- API URL: `CHIMERA_API_URL`
- Artifacts root: `CHIMERA_ARTIFACTS_DIR`
- Allowed binaries: `CHIMERA_ALLOWED_BINARIES`

## Scope YAML

Example:
```yaml
allowlist:
  - https://example.com
denylist:
  - admin.example.com
```

## Modes

- Fixture run (no external execution)
- Live run (requires confirm token)
- Replay run (reparse artifacts only)

## Common Commands

```bash
chimera plan --scope scope.yml
chimera run --mode fixture --scope scope.yml
chimera run --mode live --scope scope.yml --live-confirm "I UNDERSTAND"
chimera replay --run <run_id>
chimera export --run <run_id> --report-packet
```

## Troubleshooting

- API down: verify `CHIMERA_API_URL`, restart core
- Scope hash mismatch: regenerate scope, rerun plan
- Tool not allowed: update SafetyPolicy allowlist
- Replay lock violation: ensure replay mode uses `run_external_tool`


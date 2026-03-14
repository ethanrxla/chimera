# UI State Machine

## Inputs (from `/status`)

- mode: fixture | live | replay
- safety_state.external_exec_allowed
- safety_state.live_confirm_required
- safety_state.destructive_allowed
- safety_state.blocked_reasons[]
- scope_state.loaded
- scope_state.hash_ok
- active_run.phase

## Button Enable/Disable Rules

- RUN disabled when:
  - scope_state.loaded == false
  - safety_state.blocked_reasons not empty
  - mode == replay
  - live_confirm_required == true and confirm token missing (UI provides token)
- RUN enabled when:
  - scope_state.loaded == true
  - safety_state.blocked_reasons empty
  - mode in {fixture, live}
  - live confirm satisfied (live only)

- REPLAY enabled when:
  - a run is selected
  - mode == replay OR replay-capable flag present in UI

## Banner Text

Display: `MODE: <MODE> | Manifest: <hash> | Scope: <OK/MISMATCH> | Exec: <ALLOWED/BLOCKED>`

## Error Handling

- If API unreachable:
  - show banner with Exec: BLOCKED
  - show modal: API unreachable + Retry + Open Settings


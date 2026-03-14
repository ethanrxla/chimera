# Autoswagger Adapter Contract

This document defines the adapter contract for integrating Autoswagger into
the Chimera orchestrator (Phase B).

## Adapter interface

`AutoswaggerAdapter` must implement:

- `build_command(targets: List[str]) -> List[str]`
  - Builds the CLI command for autoswagger with safety flags.
  - Must enforce scope before returning a command.
- `normalize(raw_output: str) -> List[Finding]`
  - Parses JSON output into normalized findings.
- `run() -> dict` (optional in Phase B fixtures)
  - Executes autoswagger and returns:
    - `events`: log entries
    - `artifacts`: artifacts metadata
    - `raw_output_refs`: raw stdout strings or file refs

## Required inputs

- `scope_graph`: `ScopeGraph` used for allow/deny checks.
- `scope_policy`: `ScopePolicy` for rate limiting defaults.
- `options`: flags toggles (`verbose`, `risk`, `include_all`, `product`, `stats`, `brute`, `json`).
- `rate_limits`: overrides for requests per second.
- `run_id`, `task_id`, `scope_hash`: embedded into findings.

## Command generation rules

- Must call `autoswagger.py` with `sys.executable`.
- Must include `-rate <N>` using `rate_limits.requests_per_second` if set,
  otherwise `scope_policy.max_rps`.
- Must include only safe allowlisted targets.

## Normalization rules (MVP)

Input is JSON from `autoswagger.py -json` or `-product`:

```json
{
  "endpoints": [
    {
      "url": "https://api.example.com/users",
      "method": "GET",
      "status": 200,
      "pii": ["email"],
      "secrets": [],
      "response_size": 2048
    }
  ]
}
```

Create a `Finding` when:
- `pii` or `secrets` is non-empty, or
- `large_response` is true (if present).

Set:
- `title`: "Unauthenticated API data exposure"
- `severity`: `medium` if secrets, otherwise `low`
- `affected_target`: `url`

## Fixtures

Fixtures live in `chimera/chimera-core/tests/fixtures/autoswagger/`.

Tests:
- Command generation includes flags + rate.
- Scope enforcement rejects out-of-scope targets.
- Normalization produces stable findings from fixture output.

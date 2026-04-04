# HexStrike Integration Plan

## Goal

Use HexStrike as a specialist MCP-backed execution layer inside Chimera's Decepticon stage, then layer deterministic Chimera validators on top for API auth issues such as BOLA, IDOR, and broken authorization.

## Phase 1: MCP Bridge Into Decepticon

Implemented in this repo:

- Decepticon MCP config now includes optional HexStrike entries for:
  - `planner`
  - `reconnaissance`
  - `initial_access`
- The MCP loader resolves environment variables from `mcp_config.json`, so HexStrike can be enabled per environment without hard-coded paths.
- Chimera runtime now preserves the parent environment when tool-specific env overrides are provided, which keeps HexStrike-related variables available during Decepticon execution.

Recommended HexStrike variables:

```bash
HEXSTRIKE_ENABLED=true
HEXSTRIKE_MCP_COMMAND=python3
HEXSTRIKE_MCP_ENTRYPOINT=/path/to/hexstrike-ai/hexstrike_mcp.py
HEXSTRIKE_SERVER_URL=http://localhost:8888
```

## Phase 2: API Recon Expansion

Short-term integration target:

- Let Decepticon's `reconnaissance` agent call HexStrike workflows that expose:
  - bug bounty recon
  - exploit generation
  - parameter discovery tooling such as Arjun when available through HexStrike
- Preserve Chimera's normalized output path by feeding results back into `ReconBundle.web_endpoints`, `ReconBundle.findings`, and output artifacts.

This avoids building a second recon framework inside Chimera while still keeping Chimera's persistence and reporting model.

## Phase 3: OWASP API Auth Chain Agent

Build a Chimera-side analysis layer focused on OWASP API auth failures:

1. Start from discovered endpoints and parameters from Zypheron, VibePentester, Decepticon, and HexStrike.
2. Generate candidate object references and identity transitions.
3. Queue deterministic validation for:
   - BOLA / IDOR
   - broken function-level authorization
   - JWT / auth exposure weaknesses
4. Feed confirmed findings into Chimera's existing exploit-chain analysis.

Useful current Chimera primitives:

- [`BOLAValidator`](/home/theif/projects/kali-docker/chimera/chimera-core/chimera_core/validators/bola_validator.py)
- [`chain_analysis.py`](/home/theif/projects/kali-docker/chimera/chimera-core/chimera_core/chain_analysis.py)
- [`runner.py`](/home/theif/projects/kali-docker/chimera/chimera-core/chimera_core/runner.py)

## Why This Split

- HexStrike is good at broad offensive execution and tool coverage.
- Decepticon is already the agentic enrichment point inside Chimera.
- Chimera's validators are where proof-grade, replayable authorization findings should be confirmed.

That division keeps the stack modular:

- HexStrike for specialist offensive capability
- Decepticon for agent delegation
- Chimera for normalization, validation, and chainable evidence

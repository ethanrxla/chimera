# Kali Docker Workspace

This workspace is centered on [Chimera](/home/theif/projects/kali-docker/chimera/README.md), an evidence-driven security testing platform for bug bounty and application security workflows.

## Main Components

- [chimera](/home/theif/projects/kali-docker/chimera): core product, API, Rust CLI, UI, Docker assets.
- [tools](/home/theif/projects/kali-docker/tools): bundled external tools and tool integrations used by Chimera.
- [docs/UNIFIED_CONFIG_USAGE.md](/home/theif/projects/kali-docker/docs/UNIFIED_CONFIG_USAGE.md): unified configuration notes.
- [chimera_master_plan.md](/home/theif/projects/kali-docker/chimera_master_plan.md): implementation roadmap.

## Docker Entry Points

The root [docker-compose.yml](/home/theif/projects/kali-docker/docker-compose.yml) now includes:

- `chimera-core`: FastAPI backend and runtime
- `chimera-ui`: legacy UI container
- `chimera-cli`: Rust operator CLI container
- `metasploitable2`: optional lab target under the `lab` profile

Start the core stack:

```bash
docker compose up -d chimera-core chimera-ui chimera-cli
```

Start the optional vulnerable lab target:

```bash
docker compose --profile lab up -d metasploitable2
```

## MVP Remaining Work

The main remaining Chimera MVP gaps are:

- end-to-end live validation against Juice Shop, crAPI, VAmPI, and an LLM target
- Rust CLI integration with the new parser/oracle/chain/replay endpoints
- production hardening for persistent Playwright sessions
- packaging/install polish so operators can bring the stack up without repo-specific steps

For current Chimera usage and architecture, use [chimera/README.md](/home/theif/projects/kali-docker/chimera/README.md).


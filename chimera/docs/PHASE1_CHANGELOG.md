# Phase 1 Changelog

## Summary of changes
- Added Chimera shell structure: `chimera-core/`, `chimera-ui/`, `docs/`, `docker/`, `models/`, `scripts/`, `archive/`.
- Ported a minimal Tkinter UI shell into `chimera-ui/launcher.py` using safe placeholders.
- Added core skeleton: config loader, logging setup, event bus, CLI entry point.
- Preserved StarCoder artifact in `models/starcoder/` and archived legacy model outputs.
- Quarantined legacy Windows-first and offensive tooling under `archive/legacy-rootkit/`.

## Build status
- Before: not run in this environment (read-only sandbox + network restricted).
- After: not run in this environment for the same constraints.

## Known issues
- Tkinter requires `python3-tk` on many Linux distros.
- Chimera integrations are placeholders; no real orchestration yet.
- Archived data may be large; consider Git LFS or external storage.
## Launcher refactor
- D:\whitehat\chimera-ui\launcher.py now mirrors the OG UI visuals and animations, with model loading disabled and Windows-only paths removed for Linux-first startup.

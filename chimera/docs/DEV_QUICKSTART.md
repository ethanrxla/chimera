# Dev Quickstart (WSL/Linux)

## Prereqs
- Python 3.9+
- Tkinter (`python3-tk` package on Debian/Ubuntu)

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Run the core CLI
```bash
PYTHONPATH=chimera-core python3 -m chimera_core --help
```

## Run the UI shell
```bash
python3 chimera-ui/launcher.py
```

## Notes
- Config file defaults to `~/.chimera/config.json` and can be created via `python3 -m chimera_core config --init`.
- The UI is a shell only; real integrations will land in later phases.

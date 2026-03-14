#!/usr/bin/env bash
set -euo pipefail

PYTHONPATH="$(pwd)/chimera-core" python3 -m chimera_core "$@"

#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="${TOR_PROXY_CONTAINER:-tor-proxy}"

docker_cmd=(docker)
if ! docker ps >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
  docker_cmd=(sudo docker)
fi

"${docker_cmd[@]}" rm -f "$CONTAINER_NAME"

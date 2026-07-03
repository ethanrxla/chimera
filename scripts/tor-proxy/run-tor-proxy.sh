#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

IMAGE_NAME="${TOR_PROXY_IMAGE:-local/tor-proxy:bookworm}"
CONTAINER_NAME="${TOR_PROXY_CONTAINER:-tor-proxy}"
HOST_ADDR="${TOR_PROXY_HOST_ADDR:-127.0.0.1}"
HOST_PORT="${TOR_PROXY_HOST_PORT:-9050}"

docker_cmd=(docker)
if ! docker ps >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1; then
    docker_cmd=(sudo docker)
  fi
fi

if ! "${docker_cmd[@]}" ps >/dev/null 2>&1; then
  echo "Cannot access Docker. Run this with sudo, or add your user to the docker group." >&2
  exit 1
fi

"${docker_cmd[@]}" build -t "$IMAGE_NAME" "$SCRIPT_DIR"

if "${docker_cmd[@]}" ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
  "${docker_cmd[@]}" rm -f "$CONTAINER_NAME" >/dev/null
fi

"${docker_cmd[@]}" run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "${HOST_ADDR}:${HOST_PORT}:9050" \
  "$IMAGE_NAME" >/dev/null

cat <<EOF
Tor SOCKS proxy is running.

Container: $CONTAINER_NAME
Proxy:     socks5h://${HOST_ADDR}:${HOST_PORT}

Test:
  curl --socks5-hostname ${HOST_ADDR}:${HOST_PORT} https://check.torproject.org/api/ip

Use for current shell:
  export ALL_PROXY=socks5h://${HOST_ADDR}:${HOST_PORT}
  export HTTP_PROXY=socks5h://${HOST_ADDR}:${HOST_PORT}
  export HTTPS_PROXY=socks5h://${HOST_ADDR}:${HOST_PORT}
EOF

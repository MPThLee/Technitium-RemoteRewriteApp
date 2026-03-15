#!/bin/sh
set -eu

NETWORK_NAME="${SMOKE_NETWORK_NAME:-remote-rewrite-app-smoke}"
TECHNITIUM_CONTAINER="${SMOKE_TECHNITIUM_CONTAINER:-remote-rewrite-app-technitium}"
SOURCE_CONTAINER="${SMOKE_SOURCE_CONTAINER:-remote-rewrite-app-source}"

docker rm -f "$TECHNITIUM_CONTAINER" >/dev/null 2>&1 || true
docker rm -f "$SOURCE_CONTAINER" >/dev/null 2>&1 || true
docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true

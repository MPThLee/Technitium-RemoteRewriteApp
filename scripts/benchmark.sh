#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Release}"
SDK_IMAGE="${SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:9.0}"

if command -v dotnet >/dev/null 2>&1; then
  sh "$ROOT_DIR/scripts/prepare-sdk.sh" "${TECHNITIUM_SDK_VERSION:-14.3.0}"
  dotnet run \
    --project "$ROOT_DIR/tests/RemoteRewriteApp.Benchmarks/RemoteRewriteApp.Benchmarks.csproj" \
    -c "$CONFIGURATION"
else
  docker run --rm \
    -v "$ROOT_DIR:/work" \
    -w /work \
    "$SDK_IMAGE" \
    sh -lc "sh scripts/prepare-sdk.sh ${TECHNITIUM_SDK_VERSION:-14.3.0} >/dev/null && dotnet run --project tests/RemoteRewriteApp.Benchmarks/RemoteRewriteApp.Benchmarks.csproj -c $CONFIGURATION"
fi

#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Release}"
SDK_VERSION="${TECHNITIUM_SDK_VERSION:-$(tr -d '[:space:]' < "$ROOT_DIR/.technitium-version")}"

sh "$ROOT_DIR/scripts/prepare-sdk.sh" "$SDK_VERSION"
dotnet test "$ROOT_DIR/tests/RemoteRewriteApp.Tests/RemoteRewriteApp.Tests.csproj" -c "$CONFIGURATION"

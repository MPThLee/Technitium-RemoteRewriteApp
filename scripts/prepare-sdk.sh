#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
DEFAULT_VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/.technitium-version")"
VERSION="${1:-$DEFAULT_VERSION}"
SDK_DIR="$ROOT_DIR/vendor/technitium"
CHECKSUM_FILE="$ROOT_DIR/scripts/technitium-sdk-sha256.txt"
ARCHIVE_URL="https://download.technitium.com/dns/archive/$VERSION/DnsServerPortable.tar.gz"

case "$VERSION" in
  ''|*[!0-9.]*)
    printf '%s\n' "Invalid Technitium version: $VERSION" >&2
    exit 1
    ;;
esac

EXPECTED_SHA256="$(awk -v version="$VERSION" '$1 == version { print $2; exit }' "$CHECKSUM_FILE")"
case "$EXPECTED_SHA256" in
  ''|*[!0-9a-f]*)
    printf '%s\n' "No valid pinned SHA-256 for Technitium version $VERSION" >&2
    exit 1
    ;;
esac

if [ "${#EXPECTED_SHA256}" -ne 64 ]; then
  printf '%s\n' "No valid pinned SHA-256 for Technitium version $VERSION" >&2
  exit 1
fi

mkdir -p "$SDK_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
ARCHIVE_PATH="$TMP_DIR/DnsServerPortable.tar.gz"

curl \
  --fail \
  --show-error \
  --silent \
  --location \
  --connect-timeout 15 \
  --max-time 120 \
  --max-filesize 268435456 \
  --proto '=https' \
  --proto-redir '=https' \
  "$ARCHIVE_URL" \
  -o "$ARCHIVE_PATH"

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA256="$(sha256sum "$ARCHIVE_PATH" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{ print $1 }')"
else
  printf '%s\n' "sha256sum or shasum is required to verify $ARCHIVE_URL" >&2
  exit 1
fi

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  printf '%s\n' "Technitium archive checksum mismatch for version $VERSION" >&2
  printf '%s\n' "Expected: $EXPECTED_SHA256" >&2
  printf '%s\n' "Actual:   $ACTUAL_SHA256" >&2
  exit 1
fi

tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR" \
  DnsServerCore.ApplicationCommon.dll \
  TechnitiumLibrary.Net.dll

cp "$TMP_DIR/DnsServerCore.ApplicationCommon.dll" "$SDK_DIR/"
cp "$TMP_DIR/TechnitiumLibrary.Net.dll" "$SDK_DIR/"

printf '%s\n' "Prepared Technitium SDK DLLs in $SDK_DIR from version $VERSION"

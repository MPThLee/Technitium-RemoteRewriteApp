#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DEFAULT_VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/.technitium-version")"
VERSION="${1:-$DEFAULT_VERSION}"
SDK_DIR="$ROOT_DIR/vendor/technitium"
ARCHIVE_URL="https://download.technitium.com/dns/archive/$VERSION/DnsServerPortable.tar.gz"

case "$VERSION" in
  ''|*[!0-9.]*)
    printf '%s\n' "Invalid Technitium version: $VERSION" >&2
    exit 1
    ;;
esac

mkdir -p "$SDK_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl --fail --show-error --silent --location "$ARCHIVE_URL" -o "$TMP_DIR/DnsServerPortable.tar.gz"
tar -xzf "$TMP_DIR/DnsServerPortable.tar.gz" -C "$TMP_DIR"

cp "$TMP_DIR/DnsServerCore.ApplicationCommon.dll" "$SDK_DIR/"
cp "$TMP_DIR/TechnitiumLibrary.Net.dll" "$SDK_DIR/"

printf '%s\n' "Prepared Technitium SDK DLLs in $SDK_DIR from version $VERSION"

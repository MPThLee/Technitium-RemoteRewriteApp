#!/bin/sh
set -eu

VERSION="${1:-14.3.0}"
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SDK_DIR="$ROOT_DIR/vendor/technitium"
ARCHIVE_URL="https://download.technitium.com/dns/archive/$VERSION/DnsServerPortable.tar.gz"

mkdir -p "$SDK_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -L "$ARCHIVE_URL" -o "$TMP_DIR/DnsServerPortable.tar.gz"
tar -xzf "$TMP_DIR/DnsServerPortable.tar.gz" -C "$TMP_DIR"

cp "$TMP_DIR/DnsServerCore.ApplicationCommon.dll" "$SDK_DIR/"
cp "$TMP_DIR/TechnitiumLibrary.Net.dll" "$SDK_DIR/"

printf '%s\n' "Prepared Technitium SDK DLLs in $SDK_DIR from version $VERSION"

#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
CONFIGURATION="${CONFIGURATION:-Release}"
HTTP_PORT="${TECHNITIUM_HTTP_PORT:-15380}"
TECHNITIUM_IMAGE="${TECHNITIUM_IMAGE:-technitium/dns-server:latest}"
SOURCE_IMAGE="${SOURCE_IMAGE:-busybox:latest}"
SDK_IMAGE="${SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:9.0}"
NETWORK_NAME="${SMOKE_NETWORK_NAME:-remote-rewrite-app-smoke}"
TECHNITIUM_CONTAINER="${SMOKE_TECHNITIUM_CONTAINER:-remote-rewrite-app-technitium}"
SOURCE_CONTAINER="${SMOKE_SOURCE_CONTAINER:-remote-rewrite-app-source}"
RESOURCE_LABEL="com.remoterewriteapp.smoke=true"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.smoke.XXXXXX")"
SOURCE_BASE_URL="http://${SOURCE_CONTAINER}"

cleanup() {
  docker rm -f "$TECHNITIUM_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$SOURCE_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR"

cat >"$TMP_DIR/dns.txt" <<'EOF'
||rewrite.example.com^$dnsrewrite=192.0.2.55
||edge*.glob.example.com^$dnsrewrite=203.0.113.77
/node[0-9]+\.regex\.example\.com/$dnsrewrite=198.51.100.88
EOF

cat >"$TMP_DIR/rewrite.json" <<'EOF'
{
  "rules": [
    {
      "matchType": "suffix",
      "pattern": "manifest.example.com",
      "answers": [
        {
          "type": "A",
          "value": "198.51.100.42"
        }
      ]
    }
  ]
}
EOF

chmod 755 "$TMP_DIR"
chmod 644 "$TMP_DIR/dns.txt" "$TMP_DIR/rewrite.json"

if command -v dotnet >/dev/null 2>&1; then
  SMOKE_BASE_URL="http://127.0.0.1:${HTTP_PORT}"
  SMOKE_APP_ZIP="$ROOT_DIR/dist/RemoteRewriteApp.zip"

  package_app() {
    sh "$ROOT_DIR/scripts/package-app.sh"
  }

  run_smoke_runner() {
    dotnet run \
      --project "$ROOT_DIR/tests/RemoteRewriteApp.SmokeTests/RemoteRewriteApp.SmokeTests.csproj" \
      -c "$CONFIGURATION" \
      -- \
      "$SMOKE_BASE_URL" \
      "$SMOKE_APP_ZIP" \
      "${SOURCE_BASE_URL}/dns.txt" \
      "${SOURCE_BASE_URL}/rewrite.json"
  }
else
  SMOKE_BASE_URL="http://${TECHNITIUM_CONTAINER}:5380"
  SMOKE_APP_ZIP="/work/dist/RemoteRewriteApp.zip"

  package_app() {
    docker run --rm \
      -v "$ROOT_DIR:/work" \
      -w /work \
      "$SDK_IMAGE" \
      sh -lc "sh scripts/package-app.sh"
  }

  run_smoke_runner() {
    docker run --rm \
      -v "$ROOT_DIR:/work" \
      -w /work \
      --network "$NETWORK_NAME" \
      "$SDK_IMAGE" \
      sh -lc "wget -qO- '${SOURCE_BASE_URL}/dns.txt' >/dev/null && wget -qO- '${SOURCE_BASE_URL}/rewrite.json' >/dev/null && dotnet run --project tests/RemoteRewriteApp.SmokeTests/RemoteRewriteApp.SmokeTests.csproj -c $CONFIGURATION -- '$SMOKE_BASE_URL' '$SMOKE_APP_ZIP' '${SOURCE_BASE_URL}/dns.txt' '${SOURCE_BASE_URL}/rewrite.json'"
  }
fi

package_app

docker rm -f "$TECHNITIUM_CONTAINER" >/dev/null 2>&1 || true
docker rm -f "$SOURCE_CONTAINER" >/dev/null 2>&1 || true
docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true

printf '%s\n' "[smoke] creating docker network $NETWORK_NAME"
docker network create "$NETWORK_NAME" >/dev/null

printf '%s\n' "[smoke] starting remote source container $SOURCE_CONTAINER"
docker run -d --rm \
  --name "$SOURCE_CONTAINER" \
  --network "$NETWORK_NAME" \
  --label "$RESOURCE_LABEL" \
  --network-alias rewrite-source \
  -v "$TMP_DIR:/www:ro" \
  "$SOURCE_IMAGE" \
  sh -c "httpd -f -p 80 -h /www" >/dev/null

printf '%s\n' "[smoke] starting Technitium container $TECHNITIUM_CONTAINER"
docker run -d --rm \
  --name "$TECHNITIUM_CONTAINER" \
  --network "$NETWORK_NAME" \
  --label "$RESOURCE_LABEL" \
  -p "127.0.0.1:${HTTP_PORT}:5380" \
  "$TECHNITIUM_IMAGE" >/dev/null

printf '%s\n' "[smoke] running live Technitium install/config/query/uninstall test"
run_smoke_runner

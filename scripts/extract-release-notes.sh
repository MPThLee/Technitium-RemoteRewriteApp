#!/bin/sh
set -eu

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <tag> [changelog-file]" >&2
  exit 1
fi

TAG_NAME=$1
CHANGELOG_FILE=${2:-CHANGELOG.md}

awk -v tag="$TAG_NAME" '
  $0 ~ "^## " tag "([[:space:]]|-|$)" { capture=1; next }
  capture && /^## / { exit }
  capture { print }
' "$CHANGELOG_FILE"

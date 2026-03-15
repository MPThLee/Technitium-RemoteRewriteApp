#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

OUTPUT_FILE=${1:-CHANGELOG.md}

{
  echo "# Changelog"
  echo
  echo "This file is maintained automatically from Git history."
  echo

  latest_tag=$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)
  if [ -n "$latest_tag" ]; then
    unreleased=$(git log --no-merges --format='- %s' "${latest_tag}..HEAD")
    if [ -n "$unreleased" ]; then
      echo "## Unreleased"
      echo
      printf '%s\n' "$unreleased"
      echo
    fi
  fi

  for tag in $(git tag --list 'v*' --sort=-creatordate); do
    tag_date=$(git log -1 --format=%cs "$tag")
    previous_tag=$(git describe --tags --abbrev=0 --match 'v*' "${tag}^" 2>/dev/null || true)

    echo "## ${tag} - ${tag_date}"
    echo

    if [ -n "$previous_tag" ]; then
      git log --no-merges --format='- %s' "${previous_tag}..${tag}"
    else
      git log --no-merges --format='- %s' "${tag}"
    fi

    echo
  done
} > "$OUTPUT_FILE"

#!/usr/bin/env bash
#
# fetch.sh - clone ripgrep at an exact pinned tag into upstream/.
#
# Idempotent: a re-run over an existing checkout verifies the pin instead of
# re-cloning, and fails loudly if the checkout has drifted from the pinned
# commit. The pin is both the tag and its dereferenced commit SHA, so a moved
# or re-pointed tag upstream cannot silently change what we build.

set -euo pipefail

export LC_ALL=C

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

REPO_URL="https://github.com/BurntSushi/ripgrep.git"
PIN_TAG="15.2.0"
# Commit that annotated tag 15.2.0 dereferences to (refs/tags/15.2.0^{}).
PIN_SHA="e89fff89ac9af12e8d4ce9d5fd07beb408ca730f"
DEST="$SCRIPT_DIR/upstream"

die() {
  printf 'fetch: %s\n' "$1" >&2
  exit 1
}

verify_pin() {
  local head
  head="$(git -C "$DEST" rev-parse HEAD)"
  if [ "$head" != "$PIN_SHA" ]; then
    die "pin mismatch: upstream/ is at $head but pin is $PIN_SHA ($PIN_TAG). Remove upstream/ and re-run to re-clone."
  fi
  printf 'fetch: verified upstream/ at %s (%s)\n' "$PIN_SHA" "$PIN_TAG"
}

if [ -d "$DEST/.git" ]; then
  verify_pin
  exit 0
fi

if [ -e "$DEST" ]; then
  die "$DEST exists but is not a git checkout; remove it and re-run."
fi

printf 'fetch: cloning %s at %s (depth 1)\n' "$REPO_URL" "$PIN_TAG"
git clone --depth 1 --branch "$PIN_TAG" "$REPO_URL" "$DEST"
verify_pin

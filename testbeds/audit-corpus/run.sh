#!/usr/bin/env bash
# audit-corpus: build and audit one minimal reproducer per widely-used crate
# through the packaged native path (`patina audit <dir>`). Every reproducer
# must audit clean. The probe crate imports a dynamic loader the shim never
# defines, so its audit must be refused: the leg that shows the audit can fail.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
# patina and every reproducer's guest build stage under one target directory,
# never a target/ inside a corpus crate.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target/testbeds/audit-corpus}"
PATINA="$CARGO_TARGET_DIR/release/patina"
PROBE=selftest-dynamic-loading

cargo build --release --quiet -p cargo-patina --manifest-path "$repo_root/Cargo.toml" || {
  echo "FATAL: cargo build --release -p cargo-patina failed" >&2
  exit 3
}
log="$(mktemp "${TMPDIR:-/tmp}/audit-corpus.XXXXXX")"
trap 'rm -f "$log"' EXIT

fail=0
for dir in "$here"/crates/*/; do
  crate="$(basename "$dir")"
  "$PATINA" audit "$dir" >"$log" 2>&1
  rc=$?
  refused=0
  grep -q 'unsupported native imports:' "$log" && refused=1
  if [[ "$crate" == "$PROBE" ]]; then
    [[ $refused -eq 1 ]] && { echo "PASS $crate (refused, as it must be)"; continue; }
  elif [[ $rc -eq 0 && $refused -eq 0 ]]; then
    echo "PASS $crate"
    continue
  fi
  echo "FAIL $crate (exit $rc):"
  sed 's/^/  | /' "$log"
  fail=1
done
[[ $fail -eq 0 ]] || { echo "audit-corpus: FAIL"; exit 1; }
echo "audit-corpus: PASS"

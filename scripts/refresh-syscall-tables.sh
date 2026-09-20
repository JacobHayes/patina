#!/usr/bin/env bash
# refresh-syscall-tables.sh — re-fetch the vendored kernel syscall tables and
# report drift.
#
# The native shim's syscall registry (crates/patina-native-shim/src/registry/)
# is gated against VENDORED copies of the upstream kernel tables under
# crates/patina-native-shim/abi/. A refresh is a reviewed commit, never an
# ambient download: this script fetches the same upstream files, prints the
# diff against the vendored copies, and exits non-zero when anything changed.
# With --apply it also overwrites the vendored copies (still exiting non-zero
# on change), so the registry tests then say exactly which new numbers need a
# row.
#
# Exit codes: 0 = vendored tables match upstream; 1 = drift (diff printed);
# 2 = usage error or a fetch failure.

set -euo pipefail

usage() {
  cat <<'USAGE'
usage: scripts/refresh-syscall-tables.sh [--apply]

Fetches the upstream syscall tables the registry is gated against and diffs
them against the vendored copies under crates/patina-native-shim/abi/. Prints
the diff and exits 1 on any change; with --apply the vendored copies are
overwritten first so the change can be reviewed and committed.

  --apply   overwrite the vendored copies with the fetched files
  -h, --help
USAGE
}

apply=0
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  --apply) apply=1 ;;
  "") ;;
  *) printf 'refresh-syscall-tables: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."

# vendored path -> upstream URL. The Linux tables come from torvalds/linux
# master (x86_64: arch/x86/entry/syscalls/syscall_64.tbl; the generic table
# arm64 has used since 6.11: scripts/syscall.tbl); the Darwin table from
# apple-oss-distributions/xnu at the registry-pinned reference revision.
tables=(
  'crates/patina-native-shim/abi/linux/syscall_64.tbl=https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl'
  'crates/patina-native-shim/abi/linux/syscall.tbl=https://raw.githubusercontent.com/torvalds/linux/master/scripts/syscall.tbl'
)

# The Rust source is authoritative for the revision and source-path pairs.
darwin_registry=crates/patina-native-shim/src/registry/darwin.rs
revision=$(sed -n 's/^pub const REVISION: &str = "\([^"]*\)";/\1/p' "$darwin_registry")
[[ $revision =~ ^[0-9a-f]{40}$ ]] || { echo "invalid Darwin revision" >&2; exit 2; }
source_count=0
while IFS=' ' read -r file upstream; do
  tables+=("crates/patina-native-shim/abi/darwin/$file=https://raw.githubusercontent.com/apple-oss-distributions/xnu/$revision/$upstream")
  source_count=$((source_count + 1))
done < <(sed -n '/^pub const SOURCES:/,/^];/s/^    ("\([^"]*\)", "\([^"]*\)"),/\1 \2/p' "$darwin_registry")
[[ $source_count -eq 6 ]] || { echo "incomplete Darwin source list" >&2; exit 2; }

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

changed=0
for spec in "${tables[@]}"; do
  path=${spec%%=*}
  url=${spec#*=}
  fetched="$tmpdir/$(basename "$path")"
  if ! curl -fsSL -o "$fetched" "$url"; then
    echo "refresh-syscall-tables: FAILED to fetch $url" >&2
    exit 2
  fi
  if [ ! -s "$fetched" ]; then
    echo "refresh-syscall-tables: fetched an EMPTY file from $url" >&2
    exit 2
  fi
  if [ ! -f "$path" ]; then
    echo "refresh-syscall-tables: vendored table missing: $path" >&2
    exit 2
  fi
  if ! diff -u "$path" "$fetched"; then
    changed=1
    echo "refresh-syscall-tables: $path differs from $url" >&2
    if [ "$apply" = 1 ]; then
      cp "$fetched" "$path"
      echo "refresh-syscall-tables: updated $path (review, then run the registry tests)" >&2
    fi
  fi
done

if [ "$changed" = 1 ]; then
  echo "refresh-syscall-tables: DRIFT — the vendored tables differ from upstream (see diff above)" >&2
  exit 1
fi
echo "refresh-syscall-tables: PASS (${#tables[@]} vendored tables match upstream)"

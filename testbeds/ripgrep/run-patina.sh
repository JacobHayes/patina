#!/usr/bin/env bash
#
# ============================================================================
# UNTESTED SKETCH - DO NOT rely on this yet.
# ============================================================================
#
# This is the *intended* future shape of running ripgrep under Patina. It has
# NEVER been executed successfully and is NOT wired into run-native.sh. It
# exists to pin down the real `cargo patina` CLI surface (verified against
# crates/cargo-patina/src/lib.rs) so the eventual "run real OSS under Patina"
# change has a concrete starting point. Expect it to need iteration: the risks
# section of README.md lists why (mmap imports, CPU feature detection, thread
# pool sizing, filesystem/readdir ordering, tty detection).
#
# CLI shape (from crates/cargo-patina/src/lib.rs):
#   Whole-package native build (parse_native_build, ~line 946):
#     cargo patina native-build <PKG_PATH> [--package N] [--bin N] \
#         [--release] [--output PATH]
#     * PKG_PATH is a directory or a Cargo.toml; anything not ending in .rs is
#       treated as a package. --package/--bin select within a workspace.
#     * On success it prints:  PATINA_NATIVE_BUILD output=<path>
#   Static symbol audit (parse_native_audit, ~line 908):
#     cargo patina native-audit <BIN> [--allow SYMBOL ...]
#   Deterministic run (parse_native_run, ~line 1060):
#     cargo patina native-run <BIN> [--seed N | --record P | --replay P] \
#         [--fingerprint S] [--net-latency-nanos N] -- <PROGRAM ARGS...>
#
# `cargo patina ...` assumes the cargo-patina binary is on PATH. If it is not,
# substitute:
#   cargo run -q -p cargo-patina --bin cargo-patina -- <SUBCOMMAND> ...

set -euo pipefail

export LC_ALL=C
unset RIPGREP_CONFIG_PATH

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

UPSTREAM="$SCRIPT_DIR/upstream"          # ripgrep source (from fetch.sh)
CORPUS="$SCRIPT_DIR/corpus"              # deterministic corpus (from gen-corpus.sh)
PATINA_OUT="$SCRIPT_DIR/out-patina"      # kept separate from native out/
RG_PATINA="$PATINA_OUT/rg-patina"

# How to invoke the Patina CLI. Override with PATINA="cargo run -q -p ..." if the
# cargo-patina binary is not installed on PATH.
PATINA="${PATINA:-cargo patina}"

printf '*** UNTESTED SKETCH: this has not been run successfully. ***\n' >&2

"$SCRIPT_DIR/fetch.sh"
"$SCRIPT_DIR/gen-corpus.sh" >/dev/null
mkdir -p "$PATINA_OUT"

# ---------------------------------------------------------------------------
# 1. Build the ripgrep binary (package `ripgrep`, bin `rg`) under Patina.
#    The workspace manifest lives at upstream/Cargo.toml.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2086  # $PATINA may intentionally be multiple words
$PATINA native-build "$UPSTREAM/Cargo.toml" \
  --package ripgrep \
  --bin rg \
  --release \
  --output "$RG_PATINA"

# ---------------------------------------------------------------------------
# 2. (Optional) Audit the built binary's imported symbols. ripgrep is very
#    likely to import mmap/madvise (memmap2) and CPU-feature / thread-count
#    probes; --allow them explicitly once their names are known, e.g.:
#      $PATINA native-audit "$RG_PATINA" --allow mmap --allow madvise
# ---------------------------------------------------------------------------
# shellcheck disable=SC2086
$PATINA native-audit "$RG_PATINA" || {
  printf 'native-audit flagged symbols; inspect and re-run with --allow ...\n' >&2
}

# ---------------------------------------------------------------------------
# 3. Run a search under the deterministic runtime. Flags mirror the native
#    battery for determinism, plus -j1 to pin scheduling under Patina's
#    deterministic scheduler. Paths stay relative by cd-ing into corpus first
#    is not possible here (native-run takes a binary, not a shell), so we pass
#    the corpus path explicitly; expect absolute paths in output unless a
#    relative corpus path is used.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2086
$PATINA native-run "$RG_PATINA" --seed 0 -- \
  --no-mmap --color never --sort path -j1 \
  --no-heading --line-number \
  -e 'PATINA_MARKER' "$CORPUS"

# ---------------------------------------------------------------------------
# 4. Record / replay determinism check (intended usage): record a trace, then
#    replay it and confirm identical output.
#      $PATINA native-run "$RG_PATINA" --record "$PATINA_OUT/trace.bin" -- ... \
#      $PATINA native-run "$RG_PATINA" --replay "$PATINA_OUT/trace.bin" -- ...
# ---------------------------------------------------------------------------

: "$REPO_ROOT"  # referenced for context; silence unused-variable linters
printf '*** END UNTESTED SKETCH ***\n' >&2

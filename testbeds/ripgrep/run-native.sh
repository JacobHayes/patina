#!/usr/bin/env bash
#
# run-native.sh - build ripgrep from upstream/ and run a deterministic battery
# of searches over corpus/, snapshotting stdout + exit code for each and
# comparing against checked-in expected/ snapshots.
#
# First run records expected/ as the baseline (and passes). Every later run
# must reproduce those snapshots byte-for-byte or the battery exits nonzero.
#
# All searches run with cwd = corpus/ and target `.`, so captured paths are
# relative (`./...`) and host-independent. Determinism is enforced with a fixed
# flag set applied to every command:
#   --no-mmap             : never memory-map (spec requirement; avoids mmap path)
#   --color never         : no ANSI escapes regardless of tty
#   --sort path           : stable output order independent of thread scheduling
#   --no-require-git      : honor in-tree .gitignore even though corpus/ is not a
#                           git repo, so ignore-vs-unrestricted is testable
#   --no-ignore-parent    : never read ignore files above corpus/, so results do
#                           not depend on where this testbed is checked out
# RIPGREP_CONFIG_PATH is cleared so a host rc file cannot perturb output.

set -euo pipefail

export LC_ALL=C
unset RIPGREP_CONFIG_PATH

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$SCRIPT_DIR/corpus"
OUT="$SCRIPT_DIR/out"
EXPECTED="$SCRIPT_DIR/expected"

# This testbed is host-driver-shaped: the guest is the unmodified ripgrep binary
# and this battery stays outside it. RUNNER is the single point of substitution —
# every battery case invokes "${RUNNER[@]}" and nothing references rg directly.
# The Patina phase swaps this one line for a cargo-patina invocation, e.g.:
#   RUNNER=(cargo patina native-run "$SCRIPT_DIR/out-patina/rg-patina" --seed 0 --)
# (note: native-run takes the corpus as an argument rather than via cwd, so that
# phase passes the corpus path explicitly instead of relying on `cd`).
RUNNER=("$SCRIPT_DIR/upstream/target/release/rg")

COMMON=(--no-mmap --color never --sort path --no-require-git --no-ignore-parent)

# ---------------------------------------------------------------------------
# Build inputs: pinned source, release binary, deterministic corpus.
# ---------------------------------------------------------------------------

"$SCRIPT_DIR/fetch.sh"

printf 'run-native: building ripgrep (release, default features)\n'
( cd "$SCRIPT_DIR/upstream" && cargo build --release )

printf 'run-native: regenerating deterministic corpus\n'
"$SCRIPT_DIR/gen-corpus.sh" >/dev/null

if [ ! -x "${RUNNER[0]}" ]; then
  printf 'run-native: runner not found or not executable: %s\n' "${RUNNER[0]}" >&2
  exit 1
fi

rm -rf -- "$OUT"
mkdir -p "$OUT"
mkdir -p "$EXPECTED"

# ---------------------------------------------------------------------------
# Battery. Each entry captures stdout and exit code under a stable name.
# ---------------------------------------------------------------------------

# run_one NAME [RG-ARGS...]
# Runs the RUNNER from within corpus/ with the common flags plus per-command
# args. Captures stdout and the real exit code (no pipe in between). Every
# battery case goes through here, so the RUNNER swap is the only change the
# Patina phase needs.
run_one() {
  local name="$1"
  shift
  local code
  set +e
  ( cd "$CORPUS" && "${RUNNER[@]}" "${COMMON[@]}" "$@" ) \
    > "$OUT/$name.stdout" 2> "$OUT/$name.stderr"
  code=$?
  set -e
  printf '%d\n' "$code" > "$OUT/$name.exit"
}

# 1. Plain literal search (full match lines, grep-style path:line:text).
run_one literal_plain      --no-heading --line-number -e 'PATINA_MARKER' .
# 2. Regex with character classes and escaped metacharacters.
run_one regex_classes      --no-heading --line-number -e 'user[0-9]+@example\.com' .
# 3. Case-insensitive (matches PATINA / Patina / patina); file list.
run_one case_insensitive   -i -l -e 'patina' .
# 4. Word-boundary match (TODO as a whole word).
run_one word_boundary      --no-heading --line-number -w -e 'TODO' .
# 5. Count mode (per-file match counts).
run_one count_mode         -c -e 'function' .
# 6. Files-with-matches only.
run_one files_with_matches -l -e 'Result' .
# 7. Type filter: restrict to Rust files.
run_one type_filter_rust   -t rust -l -e 'fn ' .
# 8. Type negation: exclude Rust files.
run_one type_negate        -T rust -l -e 'function' .
# 9. Ignore-respecting: DEBUG lives only in ignored logs/build (expect no hits).
run_one ignore_respecting  -l -e 'DEBUG' .
# 10. Unrestricted (-u) bypasses ignore rules; DEBUG now surfaces.
run_one unrestricted       -u -l -e 'DEBUG' .
# 11. Fixed thread count over long-line files.
run_one fixed_threads      -j2 --no-heading --line-number -e 'LONGLINE_END_MARKER' .

# ---------------------------------------------------------------------------
# Compare against expected/, recording a baseline on first run.
# ---------------------------------------------------------------------------

status=0
new=0
pass=0
fail=0

for out_file in "$OUT"/*.stdout "$OUT"/*.exit; do
  base="$(basename "$out_file")"
  exp_file="$EXPECTED/$base"
  if [ ! -f "$exp_file" ]; then
    cp "$out_file" "$exp_file"
    printf 'NEW   %s (baseline recorded)\n' "$base"
    new=$((new + 1))
  elif diff -u "$exp_file" "$out_file" >/dev/null; then
    printf 'PASS  %s\n' "$base"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s\n' "$base"
    diff -u "$exp_file" "$out_file" || true
    fail=$((fail + 1))
    status=1
  fi
done

printf '\nrun-native: %d passed, %d new baselines, %d failed\n' "$pass" "$new" "$fail"
if [ "$status" -ne 0 ]; then
  printf 'run-native: BATTERY FAILED (snapshot mismatch)\n' >&2
fi
exit "$status"

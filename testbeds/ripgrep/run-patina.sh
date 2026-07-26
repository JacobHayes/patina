#!/usr/bin/env bash
#
# run-patina.sh - build the UNMODIFIED ripgrep package under Patina and run the
# SAME deterministic battery as run-native.sh, but through the Patina native
# (linked-shim) runtime, comparing stdout + exit code against the SAME checked-in
# expected/ snapshots. Exits nonzero on any mismatch.
#
# This is the Patina counterpart to run-native.sh. It reuses run-native's flag
# set and the identical expected/ snapshots. Two things differ under Patina and
# are handled here, each for a documented reason:
#
#   1. Guest working directory. Under the deterministic runtime the guest cwd is
#      the virtual root "/" and the in-memory filesystem rejects relative paths
#      (it is absolute-only). The corpus is mounted read-only at the guest root
#      via `--mount`, so the search TARGET is "/" instead of native's ".". rg
#      then prints paths as "/docs/..." where native prints "./docs/...". The
#      ONLY normalization applied is rewriting that leading "/" back to "./" on
#      stdout (NORMALIZE below). The traversal set and --sort path order are
#      identical; only the root prefix differs. expected/ and rg are untouched.
#
#   2. Linked-but-runtime-dormant host symbols (transitional allowance). ripgrep
#      links a subprocess-spawn surface (std::process + grep-cli: fork/
#      posix_spawn*/waitpid/pipe/setsid/setgid/uid/pgid/groups/chdir/chroot/execvp)
#      plus host-query symbols (__NSGetExecutablePath/gethostname/getpwuid_r).
#      These are NOT statically unreachable: they are reached from rg::main by
#      DIRECT calls (rg::main -> run -> SearchWorker::search ->
#      CommandReaderBuilder::build -> Command::spawn -> fork/posix_spawnp); only a
#      RUNTIME flag (--pre/-z, never set by this battery) keeps them dormant, and
#      a static reachability audit cannot prove a flag is never set (see
#      PATINA-RESULTS.md "Pre-run audit"). The proper fix is per-symbol
#      interposition: the spawn family becomes shim deny-traps that abort
#      deterministically if ever reached, and the host-query symbols return fixed
#      deterministic values — so each drops off the import table and its allowance
#      disappears. Until those shim stubs land (task #15 shim portion) the
#      remaining 23 are listed EXPLICITLY here (never `all`), so a NEW unsupported
#      import a future rg release might add still fails the gate closed. Already
#      handled and removed from this list: isatty (interposed -> deterministic
#      non-tty), memset_pattern16 + sigaddset/sigemptyset (known-safe pure
#      compute), and dlsym (the shim's own host-alias resolution primitive,
#      auto-allowed as control-plane, so not an allowance at all).
#
# All searches carry the identical flag set and per-case arguments as native:
#   --no-mmap --color never --sort path --no-require-git --no-ignore-parent
# Note: --sort path forces ripgrep to abandon parallelism and search on a single
# thread (documented rg behavior), so the battery does not exercise rg's thread
# pool — it is single-threaded regardless of -j. That is intentional: --sort is
# required for output that matches native byte-for-byte. rg's real thread pool IS
# exercised and shown deterministic in PATINA-RESULTS.md via an unsorted run.

set -euo pipefail

export LC_ALL=C
unset RIPGREP_CONFIG_PATH

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
CORPUS="$SCRIPT_DIR/corpus"
OUT="$SCRIPT_DIR/out-patina"
EXPECTED="$SCRIPT_DIR/expected"
RG_PATINA="$OUT/rg-patina"

# How to invoke the Patina CLI. Prefer a release cargo-patina on PATH or in the
# workspace target dir; override with PATINA=... if needed.
if [ -n "${PATINA:-}" ]; then
  :
elif [ -x "$REPO_ROOT/target/release/cargo-patina" ]; then
  PATINA="$REPO_ROOT/target/release/cargo-patina"
else
  PATINA="cargo run -q -p cargo-patina --bin cargo-patina --"
fi

# EMPTY — ripgrep now runs allowance-free (reason 2 above). Every symbol that
# once forced a downgrade is dispositioned: the 20-strong subprocess-spawn family
# are shim deny-traps (abort deterministically if ever reached), the host-query
# symbols (__NSGetExecutablePath/gethostname/getpwuid_r) return fixed
# deterministic values, the pure-compute members (memset_pattern16, sigaddset,
# sigemptyset) are known-safe, isatty is interposed, and dlsym is the shim's own
# control-plane primitive — so none appears as an unhandled import. Left empty,
# the pre-run gate stays fully default-deny: any NEW unsupported import a future
# rg release adds fails closed with no allowance to hide behind.
ALLOW_UNSUPPORTED=""

COMMON=(--no-mmap --color never --sort path --no-require-git --no-ignore-parent)

# Rewrite the guest-root path prefix "/" back to native's "./" (reason 1 above).
# Every rg output line begins with a path (grep format PATH:LINE:TEXT, or PATH,
# or PATH:COUNT), so a leading "/" is always the path root.
normalize() {
  sed 's|^/|./|'
}

# ---------------------------------------------------------------------------
# Build inputs: pinned source, Patina-linked release binary, corpus.
# ---------------------------------------------------------------------------

"$SCRIPT_DIR/fetch.sh"

printf 'run-patina: building cargo-patina (release; embeds the shim C)\n'
( cd "$REPO_ROOT" && cargo build --release -p cargo-patina >/dev/null 2>&1 )

printf 'run-patina: native-building the UNMODIFIED ripgrep package under Patina\n'
mkdir -p "$OUT"
# shellcheck disable=SC2086  # $PATINA may intentionally be multiple words
$PATINA patina native-build "$SCRIPT_DIR/upstream/Cargo.toml" \
  --package ripgrep --bin rg --release --output "$RG_PATINA" >/dev/null

printf 'run-patina: regenerating deterministic corpus\n'
"$SCRIPT_DIR/gen-corpus.sh" >/dev/null

if [ ! -x "$RG_PATINA" ]; then
  printf 'run-patina: patina rg not found or not executable: %s\n' "$RG_PATINA" >&2
  exit 1
fi

rm -f -- "$OUT"/*.stdout "$OUT"/*.stderr "$OUT"/*.exit 2>/dev/null || true

# run_one NAME [RG-ARGS...]
# Runs rg under Patina over the corpus mounted at the guest root, targeting "/".
# Captures normalized stdout and the real exit code, mirroring run-native's
# run_one so the same expected/ snapshots apply.
run_one() {
  local name="$1"
  shift
  local code
  # Only pass the downgrade hatch when there is something to downgrade; an empty
  # value is rejected by the CLI (it demands `all` or a non-empty list). With the
  # list empty, ripgrep runs under the pure default-deny gate.
  local allow_args=()
  if [ -n "$ALLOW_UNSUPPORTED" ]; then
    allow_args=(--allow-unsupported-symbols "$ALLOW_UNSUPPORTED")
  fi
  set +e
  # shellcheck disable=SC2086
  $PATINA patina native-run "$RG_PATINA" \
    --seed 0 --mount "$CORPUS" \
    "${allow_args[@]}" \
    -- "${COMMON[@]}" "$@" / \
    > "$OUT/$name.raw" 2> "$OUT/$name.stderr"
  code=$?
  set -e
  normalize < "$OUT/$name.raw" > "$OUT/$name.stdout"
  rm -f -- "$OUT/$name.raw"
  printf '%d\n' "$code" > "$OUT/$name.exit"
}

# Battery — identical cases and args to run-native.sh, target "/" not ".".
run_one literal_plain      --no-heading --line-number -e 'PATINA_MARKER'
run_one regex_classes      --no-heading --line-number -e 'user[0-9]+@example\.com'
run_one case_insensitive   -i -l -e 'patina'
run_one word_boundary      --no-heading --line-number -w -e 'TODO'
run_one count_mode         -c -e 'function'
run_one files_with_matches -l -e 'Result'
run_one type_filter_rust   -t rust -l -e 'fn '
run_one type_negate        -T rust -l -e 'function'
run_one ignore_respecting  -l -e 'DEBUG'
run_one unrestricted       -u -l -e 'DEBUG'
run_one fixed_threads      -j2 --no-heading --line-number -e 'LONGLINE_END_MARKER'

# ---------------------------------------------------------------------------
# Compare against the SAME expected/ snapshots as native.
# ---------------------------------------------------------------------------

status=0
pass=0
fail=0

for out_file in "$OUT"/*.stdout "$OUT"/*.exit; do
  base="$(basename "$out_file")"
  exp_file="$EXPECTED/$base"
  if [ ! -f "$exp_file" ]; then
    printf 'MISS  %s (no native baseline to compare against)\n' "$base" >&2
    fail=$((fail + 1))
    status=1
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

printf '\nrun-patina: %d passed, %d failed (compared to native expected/)\n' "$pass" "$fail"
if [ "$status" -ne 0 ]; then
  printf 'run-patina: BATTERY FAILED under Patina (snapshot mismatch)\n' >&2
fi
exit "$status"

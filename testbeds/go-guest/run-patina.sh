#!/usr/bin/env bash
###############################################################################
# go-guest — a pure-Go program built by `cargo patina build --go` (Linux).
#
# The guest (main.go) uses only the Go standard library: goroutines that block
# (so the runtime starts threads, through the shim's pthread_create), a channel,
# timers, SHA-1 (which links Go's crypto/internal/boring/sig build marker), a
# file round trip in the guest filesystem and fmt; a goroutine that computes
# without calls until a timer cancels it, a loop that calls nothing until a
# timer's goroutine sets a word, and goroutines that allocate while the
# garbage collector sweeps (each stopped as compute-bound before Go guests got
# a compute meter and one P). The Go command the PATH
# names switches to exactly the release go.mod's toolchain line pins, and the
# script refuses to build with any other.
#
# It asserts:
#   [1] the pre-run audit is CLEAN with no allowance, and reports the Go build
#       marker as a marker, not as a far-transfer refusal;
#   [2] the guest runs with the expected GO_GUEST_RESULT;
#   [3] two same-seed runs are byte-identical (stdout AND captured stderr,
#       virtual elapsed time included);
#   [4] a recorded run replays byte-identically (stdout and stderr);
#   [5] four other seeds reach the same GO_GUEST_RESULT.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target/testbeds/go-guest}"
export CARGO_TARGET_DIR="$target_dir"
built="$target_dir/patina/go-guest"
# PATINA_CLI names a cargo-patina already built from this checkout; otherwise
# the release CLI builds here.
PATINA="${PATINA_CLI:-$target_dir/release/cargo-patina}"
out="$target_dir/patina"

if [[ $(uname -s) != Linux ]]; then
  echo "FATAL: Go guests build on Linux only" >&2; exit 3
fi
if ! command -v go >/dev/null; then
  echo "FATAL: no go on PATH (any Go >= 1.21 switches to go.mod's toolchain)" >&2; exit 3
fi
# The release go.mod pins is the one that builds. Its toolchain line is only a
# minimum to the go command, so GOTOOLCHAIN names it exactly: a go on PATH that
# is another release (1.21 or newer) switches to it, downloading it if needed.
pinned="$(sed -n 's/^toolchain //p' "$here/go.mod")"
export GOTOOLCHAIN="$pinned"
if [[ $(go -C "$here" env GOVERSION) != "$pinned" ]]; then
  echo "FATAL: go builds with $(go -C "$here" env GOVERSION), not go.mod's $pinned" >&2; exit 3
fi
if [[ -z ${PATINA_CLI:-} ]] && ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if [[ ! -x $PATINA ]]; then
  echo "FATAL: $PATINA is not an executable cargo-patina" >&2; exit 3
fi
if ! mkdir -p "$out"; then
  echo "FATAL: mkdir $out failed" >&2; exit 3
fi

echo "==> building the Go guest (cargo patina build --go)"
if ! "$PATINA" patina build "$here" --go --output "$built" --release -- -trimpath >/dev/null; then
  echo "FATAL: patina build --go of the Go guest failed" >&2; exit 3
fi

echo "==> [1] audit: clean, the build marker reported as one"
if ! "$PATINA" patina audit "$built" >"$out/audit.txt" 2>&1; then
  echo "go-guest: FAIL [1] audit refused the guest" >&2
  cat "$out/audit.txt" >&2; exit 1
fi
if ! grep -q 'crypto/internal/boring/sig.StandardCrypto' "$out/audit.txt" \
  || grep -q '(far-transfer)' "$out/audit.txt"; then
  echo "go-guest: FAIL [1] the audit does not report the Go build marker as a marker" >&2
  cat "$out/audit.txt" >&2; exit 1
fi

echo "==> [2]/[3] run + byte-identical repeats (seed 1)"
for run in 1 2; do
  if ! "$PATINA" patina run "$built" --seed 1 >"$out/run$run.out" 2>"$out/run$run.err"; then
    echo "go-guest: FAIL [2] run $run exited nonzero" >&2
    cat "$out/run$run.out" "$out/run$run.err" >&2; exit 1
  fi
done
for stream in out err; do
  if ! cmp -s "$out/run1.$stream" "$out/run2.$stream"; then
    echo "go-guest: FAIL [3] two same-seed runs differ on std$stream" >&2
    diff "$out/run1.$stream" "$out/run2.$stream" >&2 || true
    exit 1
  fi
done
expected='^GO_GUEST_RESULT sha=3411092e total=4950 data="hello from go\\n" mode=-rw-r----- slept=true compute=cancelled allocated=8000$'
if ! grep -Eq "$expected" "$out/run1.out"; then
  echo "go-guest: FAIL [2] unexpected GO_GUEST_RESULT:" >&2
  cat "$out/run1.out" >&2; exit 1
fi
if ! grep -q '^GO_GUEST_STDERR ' "$out/run1.err"; then
  echo "go-guest: FAIL [2] the guest's stderr line did not reach stderr" >&2
  cat "$out/run1.err" >&2; exit 1
fi

echo "==> [4] record → replay byte-identical"
"$PATINA" patina run "$built" --seed 1 --record "$out/go-guest.patina" \
  >"$out/record.out" 2>"$out/record.err" || {
  echo "go-guest: FAIL [4] record run failed" >&2; cat "$out/record.err" >&2; exit 1; }
"$PATINA" patina replay "$built" "$out/go-guest.patina" \
  >"$out/replay.out" 2>"$out/replay.err" || {
  echo "go-guest: FAIL [4] replay failed" >&2; cat "$out/replay.err" >&2; exit 1; }
for stream in out err; do
  if ! cmp -s "$out/record.$stream" "$out/replay.$stream"; then
    echo "go-guest: FAIL [4] record/replay diverged on std$stream" >&2
    diff "$out/record.$stream" "$out/replay.$stream" >&2 || true
    exit 1
  fi
done

echo "==> [5] the same result under four other seeds"
for seed in 0 2 3 4; do
  if ! "$PATINA" patina run "$built" --seed "$seed" >"$out/seed-$seed.out" 2>&1; then
    echo "go-guest: FAIL [5] seed $seed exited nonzero" >&2
    cat "$out/seed-$seed.out" >&2; exit 1
  fi
  if ! grep -Eq "$expected" "$out/seed-$seed.out"; then
    echo "go-guest: FAIL [5] seed $seed produced a different result" >&2
    cat "$out/seed-$seed.out" >&2; exit 1
  fi
done

grep -E "$expected" "$out/run1.out"
echo "GO_GUEST_LEGS_RAN legs=audit-clean,run,seed-stable,record-replay,seed-sweep"

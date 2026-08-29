#!/usr/bin/env bash
###############################################################################
# fifo-ipc — the named-pipe (FIFO) MRE.
#
# The guest (src/main.rs) is a plain std program plus libc's `mkfifo`,
# `mkfifoat` and `mknod`. A FIFO is the one entry kind whose NAME is filesystem
# state while its BYTES are not, so it only works when both halves are modeled:
# the entry lives in the deterministic filesystem (stat/lstat/getdents/rename/
# unlink/chmod), and the transfer runs over the same in-process pipe machinery
# an anonymous `pipe(2)` uses (blocking opens that park and wake through the
# scheduler, EOF, EPIPE, EAGAIN).
#
# Unlike the rustix-default and cap-std-dirfd MREs this one is NOT SUD-only: it
# reaches every call through libc, so it runs on every platform the native shim
# supports. The raw-syscall `mknodat` row is proved by the SUD battery in
# scripts/validate-native-shim.sh.
#
# It asserts:
#   [1] the pre-run audit is CLEAN — no --allow-unsupported-symbols, and the
#       mkfifo/mknod family appears nowhere in it;
#   [2] the guest runs with the expected FIFO_RESULT;
#   [3] two same-seed runs are byte-identical (stdout AND captured stderr);
#   [4] a recorded run replays byte-identically;
#   [5] four different seeds all reach the same result (the FIFO model is a
#       function of the program, not of the schedule the seed picks).
#
# RED demonstration: before `mkfifo` was interposed the guest could not even be
# audited — `mkfifo` was an unsupported-symbol refusal (escape class
# `filesystem`) — and forcing it through with --allow-unsupported-symbols made
# the call escape to the host, where it failed ENOENT on a path only the
# in-memory filesystem has.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
built="$here/target/patina/fifo-ipc"
PATINA="$repo_root/target/release/cargo-patina"
out="$here/target/patina"

# The build prelude fails CLOSED (FATAL) — a gate that cannot build must never
# read as a silent green (the fuzz-sweep FATAL convention).
if ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if ! mkdir -p "$out"; then
  echo "FATAL: mkdir $out failed" >&2; exit 3
fi

echo "==> building the fifo-ipc MRE (packaged native build)"
if ! "$PATINA" patina build "$here" --output "$built" --release >/dev/null; then
  echo "FATAL: patina build of the fifo-ipc MRE failed" >&2; exit 3
fi

echo "==> [1] audit: clean, with no mkfifo/mknod residue"
if ! "$PATINA" patina audit "$built" >"$out/audit.txt" 2>&1; then
  echo "fifo-ipc: FAIL [1] audit refused the guest" >&2
  cat "$out/audit.txt" >&2; exit 1
fi
if grep -Eq 'mkfifo|mknod' "$out/audit.txt"; then
  echo "fifo-ipc: FAIL [1] the audit still names the mkfifo/mknod family" >&2
  cat "$out/audit.txt" >&2; exit 1
fi

echo "==> [2]/[3] run + byte-identical repeats (seed 1)"
if ! "$PATINA" patina run "$built" --seed 1 >"$out/run1.out" 2>"$out/run1.err"; then
  echo "fifo-ipc: FAIL [2] run exited nonzero" >&2
  cat "$out/run1.out" "$out/run1.err" >&2; exit 1
fi
if ! "$PATINA" patina run "$built" --seed 1 >"$out/run2.out" 2>"$out/run2.err"; then
  echo "fifo-ipc: FAIL [2] second run exited nonzero" >&2; exit 1
fi
# Both streams: a refusal diagnostic lands on the CAPTURED stderr, so comparing
# stdout alone would not notice a nondeterministic deny.
for stream in out err; do
  if ! cmp -s "$out/run1.$stream" "$out/run2.$stream"; then
    echo "fifo-ipc: FAIL [3] two same-seed runs differ on std$stream" >&2
    diff "$out/run1.$stream" "$out/run2.$stream" >&2 || true
    exit 1
  fi
done
expected='^FIFO_RESULT kind=fifo mode=0644 dents=pipe:fifo spellings=mkfifo,mkfifoat,mknod nonblock=open\+enxio rendezvous=fifo-bytes eof=0 epipe=1 eagain=1 rdwr=nowait denied=1 unlinked=alive$'
if ! grep -Eq "$expected" "$out/run1.out"; then
  echo "fifo-ipc: FAIL [2] unexpected FIFO_RESULT:" >&2
  cat "$out/run1.out" >&2; exit 1
fi

echo "==> [4] record → replay byte-identical"
"$PATINA" patina run "$built" --seed 1 --record "$out/mre.patina" \
  --fingerprint fifo-ipc-v1 >"$out/record.out" 2>/dev/null || {
  echo "fifo-ipc: FAIL [4] record run failed" >&2; exit 1; }
"$PATINA" patina replay "$built" "$out/mre.patina" \
  --fingerprint fifo-ipc-v1 >"$out/replay.out" 2>/dev/null || {
  echo "fifo-ipc: FAIL [4] replay failed" >&2; exit 1; }
if ! cmp -s "$out/record.out" "$out/replay.out"; then
  echo "fifo-ipc: FAIL [4] record/replay diverged" >&2; exit 1; fi

echo "==> [5] the same result under four different seeds"
for seed in 0 2 3 4; do
  if ! "$PATINA" patina run "$built" --seed "$seed" >"$out/seed-$seed.out" 2>&1; then
    echo "fifo-ipc: FAIL [5] seed $seed exited nonzero" >&2
    cat "$out/seed-$seed.out" >&2; exit 1
  fi
  if ! grep -Eq "$expected" "$out/seed-$seed.out"; then
    echo "fifo-ipc: FAIL [5] seed $seed produced a different result" >&2
    cat "$out/seed-$seed.out" >&2; exit 1
  fi
done

grep -E "$expected" "$out/run1.out"
# Loud execution proof for CI-log grepping: prints only after every leg passed.
echo "FIFO_LEGS_RAN legs=audit-clean,run,seed-stable,record-replay,seed-sweep"

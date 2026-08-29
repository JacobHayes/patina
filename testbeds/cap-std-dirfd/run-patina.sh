#!/usr/bin/env bash
###############################################################################
# cap-std-dirfd — the directory-descriptor-relative (`*at`) resolution MRE.
#
# The guest (src/main.rs) is a plain std + cap-std program. cap-std is the
# capability-based filesystem API: it opens ONE directory through std (libc ->
# the C interposer) and then performs every later operation relative to that
# descriptor, resolving each path component itself. Those `*at` calls reach the
# kernel through rustix's DEFAULT backend, i.e. as raw inline `syscall`
# instructions on x86_64, trapped by syscall-user-dispatch.
#
# So the guest drives BOTH halves of the `*at` surface in one process and only
# works if they share one directory-descriptor table:
#   openat/statx/readlinkat/faccessat/mkdirat/unlinkat/renameat/symlinkat
#   against a real dirfd, plus getdents64 over a descriptor derived with
#   fcntl(dirfd, F_GETFL) + openat(dirfd, ".").
#
# This testbed is SUD-ONLY (same gate as rustix-default): on a non-SUD kernel or
# a non-Linux host it prints a LOUD, COUNTED skip line and exits 0 — never a
# silent pass. Where SUD is present it asserts:
#   [1] the raw `*at` sites audit as SUD-managed;
#   [2] the guest runs with the expected CAPSTD_RESULT;
#   [3] two same-seed runs are byte-identical (stdout AND captured stderr);
#   [4] a recorded run replays byte-identically.
#
# RED demonstration: with dirfd-relative resolution removed (every `*at` row
# refusing a non-AT_FDCWD descriptor with ENOSYS, and the libc `open` refusing
# O_PATH), leg [2] fails at the very first step —
#   Dir::open_ambient_dir: Function not implemented (os error 38).
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
built="$here/target/patina/cap-std-dirfd"
PATINA="$repo_root/target/release/cargo-patina"

# The build prelude fails CLOSED (FATAL) — a gate that cannot build must never
# read as a silent green (the fuzz-sweep FATAL convention).
if ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if ! mkdir -p "$here/target/patina"; then
  echo "FATAL: mkdir $here/target/patina failed" >&2; exit 3
fi

# ---- SUD availability gate (loud, counted skip; never a silent pass) ----
sud_kernel=0
if [[ "$(uname -s)" == Linux ]]; then
  cc="${CC:-cc}"
  probe_c="$(mktemp "${TMPDIR:-/tmp}/sud_support.XXXXXX.c")"
  probe_bin="${probe_c%.c}"
  cat >"$probe_c" <<'C'
#include <sys/prctl.h>
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
int main(void) { return prctl(PR_SET_SYSCALL_USER_DISPATCH, 0, 0, 0, 0) == 0 ? 0 : 1; }
C
  if "$cc" "$probe_c" -o "$probe_bin" 2>/dev/null && "$probe_bin"; then
    sud_kernel=1
  fi
  rm -f "$probe_c" "$probe_bin"
fi

if [[ "$sud_kernel" != 1 ]]; then
  # COUNTED, LOUD skip: one grep-able line the SUD gate looks for. Never green.
  echo "cap-std-dirfd: SKIPPED 1 (host lacks syscall-user-dispatch: $(uname -s) $(uname -m); SUD is x86_64 Linux >= 5.11)"
  exit 0
fi

echo "==> building the cap-std-dirfd MRE (packaged native build)"
if ! "$PATINA" patina build "$here" --output "$built" --release >/dev/null; then
  echo "FATAL: patina build of the cap-std-dirfd MRE failed" >&2; exit 3
fi

echo "==> [1] audit: the raw *at sites must be reported SUD-managed"
if ! "$PATINA" patina audit "$built" >"$here/target/patina/audit.txt" 2>&1; then
  echo "cap-std-dirfd: FAIL [1] audit refused a SUD-managed binary" >&2
  cat "$here/target/patina/audit.txt" >&2; exit 1
fi
if ! grep -q 'SUD-managed' "$here/target/patina/audit.txt"; then
  echo "cap-std-dirfd: FAIL [1] audit did not report direct-syscall (SUD-managed)" >&2
  cat "$here/target/patina/audit.txt" >&2; exit 1
fi

echo "==> [2]/[3] run + byte-identical repeats (seed 1)"
if ! "$PATINA" patina run "$built" --seed 1 \
    >"$here/target/patina/run1.out" 2>"$here/target/patina/run1.err"; then
  echo "cap-std-dirfd: FAIL [2] run exited nonzero" >&2
  cat "$here/target/patina/run1.out" "$here/target/patina/run1.err" >&2; exit 1
fi
if ! "$PATINA" patina run "$built" --seed 1 \
    >"$here/target/patina/run2.out" 2>"$here/target/patina/run2.err"; then
  echo "cap-std-dirfd: FAIL [2] second run exited nonzero" >&2; exit 1
fi
# Both streams: a refusal diagnostic lands on the CAPTURED stderr, so comparing
# stdout alone would not notice a nondeterministic deny.
for stream in out err; do
  if ! cmp -s "$here/target/patina/run1.$stream" "$here/target/patina/run2.$stream"; then
    echo "cap-std-dirfd: FAIL [3] two same-seed runs differ on std$stream" >&2
    diff "$here/target/patina/run1.$stream" "$here/target/patina/run2.$stream" >&2 || true
    exit 1
  fi
done
expected='^CAPSTD_RESULT root=/capstd-mre read=alpha-bytes dents=alpha.txt,sub nested=beta link=sub/moved.txt modes=enforced\+created pinned=node opath=nocost,list=r,walk=x$'
if ! grep -Eq "$expected" "$here/target/patina/run1.out"; then
  echo "cap-std-dirfd: FAIL [2] unexpected CAPSTD_RESULT:" >&2
  cat "$here/target/patina/run1.out" >&2; exit 1
fi

echo "==> [4] record → replay byte-identical"
"$PATINA" patina run "$built" --seed 1 --record "$here/target/patina/mre.patina" \
  --fingerprint capstd-dirfd-v1 >"$here/target/patina/record.out" 2>/dev/null || {
  echo "cap-std-dirfd: FAIL [4] record run failed" >&2; exit 1; }
"$PATINA" patina replay "$built" "$here/target/patina/mre.patina" \
  --fingerprint capstd-dirfd-v1 >"$here/target/patina/replay.out" 2>/dev/null || {
  echo "cap-std-dirfd: FAIL [4] replay failed" >&2; exit 1; }
if ! cmp -s "$here/target/patina/record.out" "$here/target/patina/replay.out"; then
  echo "cap-std-dirfd: FAIL [4] record/replay diverged" >&2; exit 1; fi

grep -E "$expected" "$here/target/patina/run1.out"
# Loud execution proof for CI-log grepping: prints only after every leg passed.
echo "CAPSTD_LEGS_RAN branch=sud legs=audit-sud-managed,run,seed-stable,record-replay"

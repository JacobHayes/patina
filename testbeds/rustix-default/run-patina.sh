#!/usr/bin/env bash
###############################################################################
# rustix-default — the syscall-user-dispatch (SUD) acceptance MRE.
#
# The guest (src/main.rs) is a plain std + rustix program on rustix's DEFAULT
# backend. On Linux that backend (linux_raw) emits raw inline `syscall`
# instructions with no libc wrapper — the exact binary class the import audit
# cannot see and the instruction scan refuses. Built through the packaged native
# path, `cargo patina build` DROPS `--cfg rustix_use_libc` on x86_64 (SUD is
# available there), so the raw syscalls stay raw and are trapped at run time by
# the SIGSYS dispatcher into the deterministic runtime.
#
# This testbed is SUD-ONLY. SUD needs the kernel's generic-entry code
# (x86_64 >= 5.11; arm64 not yet), so on a non-SUD kernel or a non-Linux host
# the whole battery prints a LOUD, COUNTED skip line and exits 0 — never a silent
# pass. Where SUD is present (GitHub CI's x86_64 runners), it asserts:
#   [1] audit reports the raw-syscall sites as SUD-managed (proving the dropped
#       rustix_use_libc + the direct-syscall downgrade);
#   [2] the program runs, observing virtual time / deterministic FS / SimNet /
#       seed entropy, with the expected RUSTIX_RESULT;
#   [3] two same-seed runs are byte-identical;
#   [4] entropy varies across seeds (seed-derived, not wall-random);
#   [5] a recorded run replays byte-identically.
#
# RED demonstration (documented, runs on the x86_64 CI gate): reverting the
# rustix_use_libc drop makes leg [1]'s SUD-managed assertion moot (the binary
# would carry no raw syscalls); deleting the getdents64 SUD row makes the
# directory-iteration assertion in the guest panic (dents=... empty).
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
built="$here/target/patina/rustix-default"
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
  echo "rustix-default: SKIPPED 1 (host lacks syscall-user-dispatch: $(uname -s) $(uname -m); SUD is x86_64 Linux >= 5.11)"
  exit 0
fi

echo "==> building the rustix-default MRE (packaged native build; rustix_use_libc dropped on x86_64)"
if ! "$PATINA" patina build "$here" --output "$built" --release >/dev/null; then
  echo "FATAL: patina build of the rustix-default MRE failed" >&2; exit 3
fi

echo "==> [1] audit: the raw-syscall sites must be reported SUD-managed"
if ! "$PATINA" patina audit "$built" >"$here/target/patina/audit.txt" 2>&1; then
  echo "rustix-default: FAIL [1] audit refused a SUD-managed binary" >&2
  cat "$here/target/patina/audit.txt" >&2; exit 1
fi
if ! grep -q 'SUD-managed' "$here/target/patina/audit.txt"; then
  echo "rustix-default: FAIL [1] audit did not report direct-syscall (SUD-managed)" >&2
  cat "$here/target/patina/audit.txt" >&2; exit 1
fi

echo "==> [2]/[3] run + byte-identical repeats (seed 1)"
r1="$("$PATINA" patina run "$built" --seed 1 2>"$here/target/patina/run1.err")" || {
  echo "rustix-default: FAIL [2] run exited nonzero" >&2; cat "$here/target/patina/run1.err" >&2; exit 1; }
r2="$("$PATINA" patina run "$built" --seed 1 2>/dev/null)" || {
  echo "rustix-default: FAIL [2] second run exited nonzero" >&2; exit 1; }
if [[ "$r1" != "$r2" ]]; then
  echo "rustix-default: FAIL [3] two same-seed runs differ" >&2
  printf 'run1: %s\nrun2: %s\n' "$r1" "$r2" >&2; exit 1
fi
if ! grep -q '^RUSTIX_RESULT fs=rustix-default-mre dents=alpha,beta ' <<<"$r1"; then
  echo "rustix-default: FAIL [2] unexpected RUSTIX_RESULT: $r1" >&2; exit 1
fi

echo "==> [4] entropy varies across seeds"
distinct="$(for s in 1 2 3 4; do "$PATINA" patina run "$built" --seed "$s" 2>/dev/null; done \
  | grep -o 'rand=[0-9a-f]*' | sort -u | wc -l | tr -d ' ')"
if [[ "$distinct" -lt 2 ]]; then
  echo "rustix-default: FAIL [4] raw getrandom did not vary across seeds" >&2; exit 1
fi

echo "==> [5] record → replay byte-identical"
"$PATINA" patina run "$built" --seed 1 --record "$here/target/patina/mre.patina" \
  --fingerprint rustix-mre-v1 >"$here/target/patina/record.out" 2>/dev/null || {
  echo "rustix-default: FAIL [5] record run failed" >&2; exit 1; }
"$PATINA" patina replay "$built" "$here/target/patina/mre.patina" \
  --fingerprint rustix-mre-v1 >"$here/target/patina/replay.out" 2>/dev/null || {
  echo "rustix-default: FAIL [5] replay failed" >&2; exit 1; }
if ! cmp -s "$here/target/patina/record.out" "$here/target/patina/replay.out"; then
  echo "rustix-default: FAIL [5] record/replay diverged" >&2; exit 1; fi

echo "$r1"
# Loud execution proof for CI-log grepping: prints only after every leg passed.
echo "RUSTIX_LEGS_RAN branch=sud legs=audit-sud-managed,run,seed-stable,seed-varying-entropy,record-replay"

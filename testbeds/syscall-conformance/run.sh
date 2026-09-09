#!/usr/bin/env bash
###############################################################################
# syscall-conformance — the host-oracle conformance harness
# (docs/arcs/syscall-conformance.md §4).
#
# Every probes/<family>/<name>.rs binary is a self-checking scenario that
# issues its calls through a vehicle (--vehicle libc|syscall|raw) and writes
# typed observation events as JSONL on stdout. The same binary runs in four
# modes, and every leg either passes, fails loudly, or is a COUNTED skip:
#   native  as a plain program — the host kernel is the oracle. The normalized
#           stream must equal expected/<probe>.<os>-<arch>.jsonl exactly; the
#           host kernel must be at least the blessing kernel; a host kernel that
#           predates one of the probe's rows marks it HOST-UNAVAILABLE.
#   patina  under `cargo patina run` — a difference from the blessing must be
#           declared in divergences.toml (undeclared = FAIL) and every
#           declaration must still diverge (stale = FAIL), so the file is always
#           exactly the current gap.
#   replay  `run --record` then `replay` — the two streams must be
#           byte-identical, and the recorded stream passes the patina diff.
#   leak    the shim-linked binary directly under strace with the
#           validate-native-shim.sh default-deny filter (its trace set widened
#           to the classes the probes touch): no host syscall may escape.
# --selftest proves each gate can fail: planted divergence, planted stale
# divergence, planted event-count drift (both directions), planted stale
# probe-level declaration, the host gate's refusals (`conform selftest`), and a
# planted openat("/etc/hostname") escape under the leak leg's EXACT strace
# invocation and filter.
#
# Exit codes: 0 every leg passed (or a loud, counted skip); 1 a leg failed;
# 2 usage; 3 FATAL prelude (build/tooling), never a silent green.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
PATINA="$repo_root/target/release/cargo-patina"
out="$here/target/conformance"
conform="$here/target/release/conform"
divergences="$here/divergences.toml"
manifest="$here/probes.toml"

usage() {
  cat <<'EOF'
usage: testbeds/syscall-conformance/run.sh [--mode M[,M...]] [--vehicle V[,V...]]
         [--probe ID]... [--bless] [--selftest] [--fast] [--help]

  --mode      native|patina|replay|leak, comma-separated (default: all four)
  --vehicle   libc|syscall|raw, comma-separated (default: all three; raw is
              x86_64 Linux only and needs a SUD kernel under patina)
  --probe     run one probe id (repeatable), e.g. fs/open_rw
  --bless     re-record expected/<probe>.<os>-<arch>.jsonl from the native libc
              vehicle on THIS host, then run the requested legs against it
  --selftest  prove every gate can fail, then exit
  --fast      the check:fast tier: --mode native,patina --vehicle libc
EOF
}

modes=(native patina replay leak)
vehicles=(libc syscall raw)
probes=()
bless=0
selftest=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; IFS=, read -r -a modes <<<"$2"; shift 2 ;;
    --vehicle) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; IFS=, read -r -a vehicles <<<"$2"; shift 2 ;;
    --probe) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; probes+=("$2"); shift 2 ;;
    --bless) bless=1; shift ;;
    --selftest) selftest=1; shift ;;
    --fast) modes=(native patina); vehicles=(libc); shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "syscall-conformance: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
for mode in "${modes[@]}"; do
  case "$mode" in native|patina|replay|leak) ;; *) echo "syscall-conformance: unknown mode: $mode" >&2; exit 2 ;; esac
done
for vehicle in "${vehicles[@]}"; do
  case "$vehicle" in libc|syscall|raw) ;; *) echo "syscall-conformance: unknown vehicle: $vehicle" >&2; exit 2 ;; esac
done

if [[ "$(uname -s)" != Linux ]]; then
  # COUNTED, LOUD skip: the probes are the Linux syscall ABI.
  echo "syscall-conformance: SKIPPED 1 (Linux-only: the probes are the Linux syscall ABI; this is $(uname -s) $(uname -m))"
  exit 0
fi
host_kernel="$(uname -r)"
host_arch="$(uname -m)"
host_glibc="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
platform="linux-$host_arch"

# ---- prelude: fails CLOSED (FATAL) — a gate that cannot build never reads green
if ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if ! mkdir -p "$out"; then
  echo "FATAL: mkdir $out failed" >&2; exit 3
fi
if ! cargo build --release --quiet --manifest-path "$here/Cargo.toml"; then
  echo "FATAL: native build of the conformance probes failed" >&2; exit 3
fi
if [[ ! -x "$conform" ]]; then
  echo "FATAL: $conform missing after the build" >&2; exit 3
fi
if ! virtual_abi="$("$conform" abi "$manifest")"; then
  echo "FATAL: probes.toml is not loadable" >&2; exit 3
fi
mapfile -t all_probes < <("$conform" list "$manifest")
if [[ ${#all_probes[@]} -eq 0 ]]; then
  echo "FATAL: probes.toml lists no probes" >&2; exit 3
fi
if [[ ${#probes[@]} -eq 0 ]]; then
  probes=("${all_probes[@]}")
else
  for probe in "${probes[@]}"; do
    if ! printf '%s\n' "${all_probes[@]}" | grep -qx -- "$probe"; then
      echo "syscall-conformance: unknown probe $probe (see probes.toml)" >&2; exit 2
    fi
  done
fi
# The differ refuses a malformed divergences.toml; surface that before any leg.
if ! "$conform" declared-failing "${probes[0]}" libc "$divergences" >/dev/null 2>"$out/divergences.err"; then
  if [[ -s "$out/divergences.err" ]]; then
    echo "FATAL: divergences.toml is not loadable:" >&2; cat "$out/divergences.err" >&2; exit 3
  fi
fi

# ---- the strace leak filter: validate-native-shim.sh's default-deny, verbatim,
# with the trace set widened to every class the probes touch (%process, %signal,
# %ipc on top of the original file/network/desc/memory/clock/entropy set). The
# awk allow-list is name/path-keyed, so widening the trace set cannot loosen it.
# Additions to the name-only prelude regex are the thread-lifecycle rows a
# managed thread's host pthread_create issues (clone3/clone, set_robust_list,
# rseq, set_tid_address, gettid, prlimit64, sched_getaffinity, mprotect on the
# new stack, rt_sigprocmask) — process-local, no fs/net/clock/entropy reach —
# and exit_group's sibling `exit` for the thread's own end. Everything else is
# printed = DENIED. The planted self-test below runs the SAME variables.
strace_events='trace=%file,%network,%desc,%memory,%clock,%process,%signal,%ipc,nanosleep,gettimeofday,futex,rt_sigaction,rt_sigprocmask,rt_sigreturn,sigaltstack,sched_yield,exit_group,exit,getrandom'
strace_filter='
  function trusted_path(a) {
    return (a ~ /\.so(\.|"|$)/) || (a ~ /"\/etc\/ld\.so\.cache"/) || (a ~ /"\/etc\/ld\.so\.preload"/) || (a ~ /"\/proc\/self\/maps"/)
  }
  {
    line = $0
    sub(/^[0-9]+ +/, "", line)
    if (line ~ /^--- / || line ~ /^\+\+\+ /) next
    # A call split across two lines by a concurrent thread: the `unfinished`
    # line carries the name and arguments and is judged by the rules below
    # with the marker stripped; the `resumed` line carries only the return
    # value and is dropped. (Stricter, not looser: an openat on a trusted path
    # whose fd arrives on a resumed line is never entered into `trusted`.)
    if (line ~ /^<\.\.\. [a-z_0-9]+ resumed>/) next
    sub(/ <unfinished \.\.\.>$/, ")", line)
    syscall = line
    sub(/\(.*/, "", syscall)
    args = line
    sub(/^[^(]*\(/, "", args)
    if (syscall ~ /^(openat|openat2|open)$/ && trusted_path(args) && line ~ /= *[0-9]+$/) {
      ret = line; sub(/^.*= */, "", ret); sub(/[^0-9].*/, "", ret); if (ret != "") trusted[ret] = 1
    }
    if (syscall == "close") { cfd = args; sub(/[^0-9].*/, "", cfd); if (cfd != "") delete trusted[cfd] }
    if (syscall ~ /^(execve|brk|arch_prctl|mmap|mmap2|munmap|mprotect|madvise|futex|sched_yield|sigaltstack|rt_sigaction|rt_sigprocmask|rt_sigreturn|exit|exit_group|close)$/) next
    if (syscall ~ /^(clone|clone3|set_robust_list|rseq|set_tid_address|gettid|prlimit64|sched_getaffinity)$/) next
    if (syscall == "getrandom" && args ~ /GRND_NONBLOCK/) next
    if (syscall ~ /^(openat|openat2|open|newfstatat|readlink|readlinkat)$/ && trusted_path(args)) next
    if (syscall ~ /^(faccessat|faccessat2|access)$/ && args ~ /"\/etc\/ld\.so\.preload"/) next
    if (syscall ~ /^(read|pread64|fstat|fcntl|lseek)$/) {
      fd = args; sub(/[^0-9].*/, "", fd)
      if (fd ~ /^[0-3]$/ || (fd != "" && (fd in trusted))) next
    }
    if (syscall == "write" && args ~ /^[0-3][,)]/) next
    print line
  }
'

have_strace=0
if command -v strace >/dev/null 2>&1; then have_strace=1; fi

# ---- SUD availability (the raw vehicle under patina needs it): loud, counted
sud_kernel=0
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
if "$cc" "$probe_c" -o "$probe_bin" 2>/dev/null && "$probe_bin"; then sud_kernel=1; fi
rm -f "$probe_c" "$probe_bin"

# ---- --selftest: every gate must be able to fail
if [[ $selftest == 1 ]]; then
  status=0
  echo "==> conform selftest (differ + host gate, planted failures)"
  if ! "$conform" selftest; then status=1; fi
  echo "==> strace leak selftest (planted openat(\"/etc/hostname\") through syscall(2))"
  if [[ $have_strace == 1 ]]; then
    leak_bin="$here/target/release/selftest-leak"
    if strace -f -s 4096 -e "$strace_events" -o "$out/selftest-leak.strace" \
        "$leak_bin" --vehicle syscall >"$out/selftest-leak.out" 2>"$out/selftest-leak.err"; then :; fi
    awk "$strace_filter" "$out/selftest-leak.strace" >"$out/selftest-leak.denied"
    if [[ ! -s "$out/selftest-leak.denied" ]]; then
      echo "SELFTEST FAILED: strace leak: the planted openat(\"/etc/hostname\") escape was not flagged; the filter cannot catch a real escape" >&2
      status=1
    elif ! grep -Eq 'openat.*"/etc/hostname"' "$out/selftest-leak.denied"; then
      echo "SELFTEST FAILED: strace leak: denied set is non-empty but does not contain the planted openat(\"/etc/hostname\")" >&2
      cat "$out/selftest-leak.denied" >&2
      status=1
    else
      echo "SELFTEST ok: strace leak: planted escape flagged: $(grep -E 'openat.*"/etc/hostname"' "$out/selftest-leak.denied" | head -1)"
    fi
  elif [[ "${PATINA_REQUIRE_STRACE:-0}" == 1 ]]; then
    echo "SELFTEST FAILED: PATINA_REQUIRE_STRACE=1 but strace is not on PATH" >&2; status=1
  else
    echo "SELFTEST SKIPPED 1: strace leak (strace not on PATH)"
  fi
  if [[ $status != 0 ]]; then
    echo "syscall-conformance: SELFTEST FAILED — a gate cannot fail" >&2; exit 1
  fi
  echo "CONFORMANCE_SELFTEST_RAN cases=differ,host-gate,strace-leak"
  exit 0
fi

# ---- patina builds (one shim-linked binary per probe), only when needed
need_patina=0
for mode in "${modes[@]}"; do
  case "$mode" in patina|replay|leak) need_patina=1 ;; esac
done
if [[ $need_patina == 1 ]]; then
  mkdir -p "$out/patina"
  for probe in "${probes[@]}"; do
    bin="${probe//\//-}"
    if ! "$PATINA" patina build "$here" --bin "$bin" --output "$out/patina/$bin" --release >"$out/patina/$bin.build.log" 2>&1; then
      echo "FATAL: patina build of $probe failed:" >&2; cat "$out/patina/$bin.build.log" >&2; exit 3
    fi
  done
fi

passed=0
failed=0
skipped=0
unavailable=0
legs=()

fail_leg() {
  local leg=$1 why=$2 log=${3:-}
  failed=$((failed + 1))
  echo "FAIL $leg: $why" >&2
  if [[ -n "$log" && -s "$log" ]]; then
    sed 's/^/    /' "$log" >&2
  fi
}

pass_leg() {
  local leg=$1 note=${2:-}
  passed=$((passed + 1))
  echo "PASS $leg${note:+ ($note)}"
}

skip_leg() {
  local leg=$1 why=$2
  skipped=$((skipped + 1))
  echo "SKIP $leg: $why"
}

# Run the differ for one leg; prints its lines (indented) on failure.
diff_leg() {
  local mode=$1 probe=$2 vehicle=$3 expected=$4 raw=$5 status=$6 leg=$7 err=$8
  local report="$raw.diff"
  if "$conform" diff "$mode" "$probe" "$vehicle" "$expected" "$raw" "$divergences" "$status" >"$report" 2>&1; then
    local note
    note="$(grep -E 'declared' "$report" | head -1 || true)"
    pass_leg "$leg" "$note"
    return 0
  fi
  {
    cat "$report"
    if [[ -s "$err" ]]; then echo "--- probe stderr (tail) ---"; tail -n 20 "$err"; fi
  } >"$report.full"
  fail_leg "$leg" "conformance diff failed" "$report.full"
  return 1
}

for probe in "${probes[@]}"; do
  bin="${probe//\//-}"
  expected="$here/expected/$probe.$platform.jsonl"
  legdir="$out/$bin"
  mkdir -p "$legdir"
  native_bin="$here/target/release/$bin"

  if [[ $bless == 1 ]]; then
    echo "==> blessing $probe from the native libc vehicle on $platform ($host_kernel, glibc $host_glibc)"
    if ! "$native_bin" --vehicle libc --strict >"$legdir/bless.raw.jsonl" 2>"$legdir/bless.err"; then
      fail_leg "$probe[bless]" "the probe does not pass natively; refusing to bless" "$legdir/bless.err"
      continue
    fi
    if ! "$conform" bless "$probe" "$legdir/bless.raw.jsonl" "$expected" linux "$host_arch" "$host_kernel" "$host_glibc" "$manifest"; then
      fail_leg "$probe[bless]" "conform bless failed"
      continue
    fi
  fi

  if [[ ! -f "$expected" ]]; then
    skip_leg "$probe" "UNBLESSED on $platform (no $expected; run --bless on a $platform host)"
    continue
  fi
  gate="$("$conform" host-check "$probe" "$manifest" "$expected" "$host_kernel" 2>&1)"
  gate_rc=$?
  if [[ $gate_rc == 5 ]]; then
    unavailable=$((unavailable + 1))
    echo "HOST-UNAVAILABLE $probe: $gate"
    continue
  elif [[ $gate_rc != 0 ]]; then
    fail_leg "$probe[host-gate]" "$gate"
    continue
  fi

  for mode in "${modes[@]}"; do
    for vehicle in "${vehicles[@]}"; do
      leg="$probe[$mode/$vehicle]"
      if [[ $vehicle == raw && $host_arch != x86_64 ]]; then
        skip_leg "$leg" "the raw vehicle is x86_64-only (this is $host_arch)"; continue
      fi
      if [[ $vehicle == raw && $mode != native && $sud_kernel != 1 ]]; then
        skip_leg "$leg" "host lacks syscall-user-dispatch (raw under patina needs x86_64 Linux >= 5.11)"; continue
      fi
      raw="$legdir/$mode.$vehicle.jsonl"
      err="$legdir/$mode.$vehicle.err"
      case "$mode" in
        native)
          if "$native_bin" --vehicle "$vehicle" --strict >"$raw" 2>"$err"; then status=ok; else status=failed; fi
          diff_leg native "$probe" "$vehicle" "$expected" "$raw" "$status" "$leg" "$err" || true
          ;;
        patina)
          if "$PATINA" patina run "$out/patina/$bin" --seed 1 -- --vehicle "$vehicle" >"$raw" 2>"$err"; then status=ok; else status=failed; fi
          diff_leg patina "$probe" "$vehicle" "$expected" "$raw" "$status" "$leg" "$err" || true
          ;;
        replay)
          if reason="$("$conform" declared-failing "$probe" "$vehicle" "$divergences")"; then
            # A probe the supervisor refuses or that dies before its first
            # recorded event leaves no trace to replay; the patina leg already
            # holds it to its declaration.
            skip_leg "$leg" "declared failing under patina; nothing to replay ($reason)"; continue
          fi
          trace="$legdir/replay.$vehicle.patina"
          rm -f "$trace"
          if "$PATINA" patina run "$out/patina/$bin" --seed 1 --record "$trace" --fingerprint syscall-conformance-v1 \
              -- --vehicle "$vehicle" >"$raw" 2>"$err"; then status=ok; else status=failed; fi
          if [[ ! -s "$trace" ]]; then
            fail_leg "$leg" "record produced no trace" "$err"; continue
          fi
          replayed="$legdir/replay.$vehicle.replayed.jsonl"
          if ! "$PATINA" patina replay "$out/patina/$bin" "$trace" --fingerprint syscall-conformance-v1 >"$replayed" 2>"$replayed.err"; then
            # A probe declared failing under patina fails identically on replay;
            # the byte-identity check below is what the leg proves either way.
            :
          fi
          if ! cmp -s "$raw" "$replayed"; then
            diff "$raw" "$replayed" >"$legdir/replay.$vehicle.divergence" 2>&1 || true
            fail_leg "$leg" "record and replay event streams differ" "$legdir/replay.$vehicle.divergence"; continue
          fi
          if [[ ! -s "$raw" ]]; then
            fail_leg "$leg" "record produced no events (vacuous replay identity)" "$err"; continue
          fi
          diff_leg patina "$probe" "$vehicle" "$expected" "$raw" "$status" "$leg" "$err" || true
          ;;
        leak)
          if [[ $have_strace != 1 ]]; then
            if [[ "${PATINA_REQUIRE_STRACE:-0}" == 1 ]]; then
              echo "FATAL: PATINA_REQUIRE_STRACE=1 but strace is not on PATH; the leak leg cannot run" >&2; exit 3
            fi
            skip_leg "$leg" "strace not on PATH"; continue
          fi
          if reason="$("$conform" declared-failing "$probe" "$vehicle" "$divergences")"; then
            # Bypassing the supervisor would run a binary the audit refuses,
            # so a leak here would be the audit's finding, not the runtime's.
            skip_leg "$leg" "declared failing under patina; not run outside the supervisor ($reason)"; continue
          fi
          PATINA_MODE=seeded PATINA_SEED=9 \
            strace -f -s 4096 -e "$strace_events" -o "$legdir/leak.$vehicle.strace" \
              "$out/patina/$bin" --vehicle "$vehicle" >"$raw" 2>"$err"
          status=$?
          awk "$strace_filter" "$legdir/leak.$vehicle.strace" >"$legdir/leak.$vehicle.denied"
          if [[ -s "$legdir/leak.$vehicle.denied" ]]; then
            fail_leg "$leg" "host syscalls escaped the deterministic boundary:" "$legdir/leak.$vehicle.denied"; continue
          fi
          if [[ ! -s "$raw" ]]; then
            fail_leg "$leg" "the probe recorded no events under strace (vacuous leak leg)" "$err"; continue
          fi
          if [[ $status != 0 ]]; then
            fail_leg "$leg" "the probe exited $status under strace" "$err"; continue
          fi
          pass_leg "$leg" "$(wc -l <"$raw" | tr -d ' ') events, no escaped syscall"
          ;;
      esac
    done
  done
done

echo "syscall-conformance: passed=$passed failed=$failed skipped=$skipped host_unavailable=$unavailable (platform $platform, kernel $host_kernel, glibc $host_glibc, virtual ABI $virtual_abi)"
if [[ $failed != 0 ]]; then
  exit 1
fi
if [[ $passed == 0 ]]; then
  # Nothing ran: a counted, loud skip (e.g. an unblessed platform), never a
  # LEGS_RAN line.
  echo "syscall-conformance: SKIPPED $((skipped + unavailable)) (no leg ran on $platform)"
  exit 0
fi
# Loud execution proof for CI-log grepping: prints only after every leg passed.
echo "CONFORMANCE_LEGS_RAN modes=$(IFS=,; echo "${modes[*]}") vehicles=$(IFS=,; echo "${vehicles[*]}") probes=${#probes[@]} passed=$passed skipped=$skipped host_unavailable=$unavailable"

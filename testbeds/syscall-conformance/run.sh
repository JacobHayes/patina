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
#           predates one of the probe's rows, or implements a row the probe
#           asserts absent (past the virtual ABI level), marks it
#           HOST-UNAVAILABLE. The virtual ABI level and each row's first kernel
#           come from `cargo patina syscalls --format json` (the registry).
#   patina  under `cargo patina run` — a difference from the blessing must be
#           declared in divergences.toml (undeclared = FAIL) and every
#           declaration must still diverge (stale = FAIL), so the file is always
#           exactly the current gap.
#   replay  `run --record` then `replay` — the two streams must be
#           byte-identical, and the recorded stream passes the patina diff.
#   leak    the shim-linked binary directly under strace with the
#           default-deny filter over the classes the probes touch:
#           no host syscall may escape. A
#           probe blessed to die by a signal is also run directly, unstraced
#           and unsupervised by patina, and its waitpid outcome (signal AND
#           core flag) must be the blessed one.
#
# Every leg runs under `conform supervise`: its own process group, a wall-clock
# timeout (PATINA_CONFORMANCE_LEG_TIMEOUT seconds, default 60) that kills the
# whole group, and — the one line the harness itself appends to a stream — the
# process outcome the supervisor OBSERVED (`__termination`: the native leg's
# waitpid status; the `guest_exit` of the `cargo patina … --format json`
# envelope for patina/replay). It is compared like any other event and never
# copied from the expectation.
#
# --selftest proves each gate can fail: planted divergence, planted stale
# divergence, planted event-count drift (both directions), planted wrong or
# missing termination, a stale pending declaration, an abort whose pinned
# diagnostic is absent, the frozen declaration rule's refusals, the host gate's
# refusals (`conform selftest`), a planted openat("/etc/hostname") escape under
# the leak leg's EXACT strace invocation and filter, and a planted
# never-returning process group under the leg timeout.
#
# Exit codes: 0 every leg passed (or a loud, counted skip); 1 a leg failed;
# 2 usage; 3 FATAL prelude (build/tooling), never a silent green.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target/testbeds/syscall-conformance}"
export CARGO_TARGET_DIR="$target_dir"
PATINA="$target_dir/release/cargo-patina"
out="$target_dir/conformance"
conform="$target_dir/release/conform"
divergences="$here/divergences.toml"
manifest="$here/probes.toml"
registry="$out/registry.json"
leg_timeout="${PATINA_CONFORMANCE_LEG_TIMEOUT:-60}"

usage() {
  cat <<'EOF'
usage: testbeds/syscall-conformance/run.sh [--mode M[,M...]] [--vehicle V[,V...]]
         [--probe ID]... [--bless] [--selftest] [--fast] [--help]

  --mode      native|patina|replay|leak, comma-separated (default: all four)
  --vehicle   libc|syscall|raw, comma-separated (default: all three; raw is
              x86_64 Linux only and needs a SUD kernel under patina; a probe
              with no shape through a vehicle exits 4 and is a counted skip)
  --probe     run one probe id (repeatable), e.g. fs/open_rw
  --bless     re-record expected/<probe>.<os>-<arch>.jsonl from the native libc
              vehicle on THIS host, then run the requested legs against it
  --selftest  prove every gate can fail, then exit
  --fast      the check:fast tier: --mode native,patina --vehicle libc

  PATINA_CONFORMANCE_LEG_TIMEOUT  seconds before a leg's process group is
                                  killed and the leg fails (default 60)
EOF
}

# Three host properties a probe may observe are pinned here so the native oracle
# and the virtual kernel start from the same process state: standard input is
# /dev/null (a probe reading fd 0 sees EOF on both sides and never blocks on a
# terminal), RLIMIT_NOFILE is the virtual kernel's own 1024 (the shim's
# `patina_fd_limit`), so EMFILE and the F_DUPFD/dup2 bounds fall at one number,
# and the umask is the 022 every virtual process starts with, so the first
# `umask(2)` answers the same previous mask on both sides.
exec </dev/null
ulimit -S -n 1024 || { echo "syscall-conformance: FATAL: cannot pin RLIMIT_NOFILE to 1024" >&2; exit 3; }
umask 022

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
if ! [[ "$leg_timeout" =~ ^[0-9]+$ ]] || [[ "$leg_timeout" == 0 ]]; then
  echo "syscall-conformance: PATINA_CONFORMANCE_LEG_TIMEOUT must be a positive integer (seconds), not '$leg_timeout'" >&2; exit 2
fi

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
if ! cargo build --release --quiet --manifest-path "$repo_root/Cargo.toml" -p cargo-patina; then
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
# The registry is the source of the virtual ABI level and every row's `since`;
# the manifest must name only registry rows (and of the right kind).
if ! "$PATINA" patina syscalls --os linux --arch "$host_arch" --format json >"$registry" 2>"$registry.err"; then
  echo "FATAL: cargo patina syscalls --format json failed:" >&2; cat "$registry.err" >&2; exit 3
fi
if ! virtual_abi="$("$conform" abi "$registry")"; then
  echo "FATAL: $registry is not a patina.syscalls/v1 registry" >&2; exit 3
fi
if ! "$conform" check-manifest "$manifest" "$registry" >/dev/null; then
  echo "FATAL: probes.toml disagrees with the registry (see above)" >&2; exit 3
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

# ---- the strace leak filter: default-deny policy over process, signal, IPC,
# file, network, descriptor, memory, clock and entropy syscalls.
# The awk allow-list is name/path-keyed; tracing a class does not allow it.
# Additions to the name-only prelude regex are the thread-lifecycle rows a
# managed thread's host pthread_create issues (clone3/clone, set_robust_list,
# rseq, set_tid_address, gettid, prlimit64, sched_getaffinity, mprotect on the
# new stack, rt_sigprocmask) — process-local, no fs/net/clock/entropy reach —
# and exit_group's sibling `exit` for the thread's own end.
#
# The ONE signal allowance is the shim's own delivery vehicle (the signals
# family design, docs/arcs/syscall-conformance-signals.md §2.4): a kernel-built
# frame is obtained by signalling the CALLING THREAD ITSELF — `tgkill(pid, tid,
# …)` / `rt_tgsigqueueinfo(pid, tid, …)` with pid the traced process and tid the
# thread issuing the call (strace's own line prefix), or `tkill(tid, …)` with
# that tid. The predicate is target == self, any signal number: never a signal
# name list, never a uid, never a process-directed `kill`/`rt_sigqueueinfo`. A
# modeled row reaching the host (a `kill`, a `rt_sigpending`, a `signalfd4`) is
# printed = DENIED. The planted self-test below runs the SAME variables.
strace_events='trace=%file,%network,%desc,%memory,%clock,%process,%signal,%ipc,nanosleep,gettimeofday,futex,rt_sigaction,rt_sigprocmask,rt_sigreturn,sigaltstack,sched_yield,exit_group,exit,getrandom'
strace_filter='
  function trusted_path(a) {
    return (a ~ /\.so(\.|"|$)/) || (a ~ /"\/etc\/ld\.so\.cache"/) || (a ~ /"\/etc\/ld\.so\.preload"/) || (a ~ /"\/proc\/self\/maps"/)
  }
  function self_directed(name, a, caller,    n, parts, tgid, tid) {
    n = split(a, parts, /, */)
    if (name == "tgkill" || name == "rt_tgsigqueueinfo") {
      tgid = parts[1]; tid = parts[2]
      return (n >= 3 && tgid == pid && tid == caller)
    }
    if (name == "tkill") {
      tid = parts[1]
      return (n >= 2 && tid == caller)
    }
    return 0
  }
  {
    line = $0
    caller = ""
    if (match(line, /^[0-9]+ +/)) { caller = substr(line, 1, RLENGTH); sub(/ +$/, "", caller) }
    sub(/^[0-9]+ +/, "", line)
    if (pid == "" && line ~ /^execve\(/) pid = caller
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
    if (syscall ~ /^(tgkill|tkill|rt_tgsigqueueinfo)$/ && self_directed(syscall, args, caller)) next
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
  echo "==> vehicle architecture applicability detector"
  vehicle_test=vehicle::tests::legacy_rows_match_architecture_table_and_refuse_before_dispatch
  if ! cargo test --manifest-path "$here/Cargo.toml" --lib -- --exact "$vehicle_test" >"$out/selftest-vehicle.log" 2>"$out/selftest-vehicle.err" ||
     ! grep -Fxq "test $vehicle_test ... ok" "$out/selftest-vehicle.log"; then
    echo "SELFTEST FAILED: vehicle architecture detector failed or did not execute" >&2
    cat "$out/selftest-vehicle.log" "$out/selftest-vehicle.err" >&2
    status=1
  else
    echo "SELFTEST ok: vehicle architecture applicability detector executed and passed"
  fi
  echo "==> conform selftest (differ + termination + pending + frozen rule + design obligations + host gate, planted failures)"
  if ! "$conform" selftest; then status=1; fi
  echo "==> strace leak selftest (planted openat(\"/etc/hostname\") through syscall(2); planted self-signal allowance bounds)"
  if [[ $have_strace == 1 ]]; then
    leak_bin="$target_dir/release/selftest-leak"
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
    # The self-signal allowance, on synthetic strace lines through the SAME
    # filter: a tgkill/tkill/rt_tgsigqueueinfo to the calling thread passes; a
    # process-directed kill/rt_sigqueueinfo, a tgkill to ANOTHER thread, a
    # rt_sigpending, and a signalfd4 are all denied, whatever the signal name.
    synthetic="$out/selftest-leak.synthetic.strace"
    cat >"$synthetic" <<'STRACE'
4242 execve("/x/probe", ["/x/probe"], 0x7ffd /* 3 vars */) = 0
4242 tgkill(4242, 4242, SIGUSR1)          = 0
4242 --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_TKILL, si_pid=4242, si_uid=1000} ---
4242 rt_sigreturn({mask=[]})              = 0
4243 tgkill(4242, 4243, SIGRT_3)          = 0
4243 tkill(4243, SIGTERM)                 = 0
4243 rt_tgsigqueueinfo(4242, 4243, SIGUSR2, {si_signo=SIGUSR2, si_code=SI_QUEUE, si_pid=1, si_uid=1000}) = 0
4242 tgkill(4242, 4243, SIGUSR1)          = 0
4242 tgkill(4243, 4243, SIGUSR1)          = 0
4243 tkill(4242, SIGUSR1)                 = 0
4242 kill(4242, SIGUSR1)                  = 0
4242 rt_sigqueueinfo(4242, SIGUSR1, {si_signo=SIGUSR1, si_code=SI_QUEUE, si_pid=1, si_uid=1000}) = 0
4242 rt_sigpending([], 8)                 = 0
4242 signalfd4(-1, [USR1], 8, SFD_NONBLOCK) = 5
4242 exit_group(0)                        = ?
STRACE
    awk "$strace_filter" "$synthetic" >"$synthetic.denied"
    expected_denied='tgkill(4242, 4243, SIGUSR1)
tgkill(4243, 4243, SIGUSR1)
tkill(4242, SIGUSR1)
kill(4242, SIGUSR1)
rt_sigqueueinfo(4242, SIGUSR1, {si_signo=SIGUSR1, si_code=SI_QUEUE, si_pid=1, si_uid=1000})
rt_sigpending([], 8)
signalfd4(-1, [USR1], 8, SFD_NONBLOCK)'
    got_denied="$(sed -E 's/ += .*$//' "$synthetic.denied")"
    if [[ "$got_denied" != "$expected_denied" ]]; then
      echo "SELFTEST FAILED: strace leak: the self-signal allowance is not exactly 'to the calling thread'; denied set was:" >&2
      cat "$synthetic.denied" >&2
      echo "expected exactly:" >&2
      echo "$expected_denied" >&2
      status=1
    else
      echo "SELFTEST ok: strace leak: self-directed tgkill/tkill/rt_tgsigqueueinfo allowed; cross-thread, process-directed, rt_sigpending and signalfd4 denied"
    fi
  elif [[ "${PATINA_REQUIRE_STRACE:-0}" == 1 ]]; then
    echo "SELFTEST FAILED: PATINA_REQUIRE_STRACE=1 but strace is not on PATH" >&2; status=1
  else
    echo "SELFTEST SKIPPED 1: strace leak (strace not on PATH)"
  fi
  echo "==> leg-timeout selftest (planted never-returning process group under conform supervise)"
  timeout_out="$out/selftest-timeout.jsonl"
  timeout_err="$out/selftest-timeout.err"
  "$conform" supervise native 1 "$timeout_out" "$timeout_err" -- \
    sh -c 'echo planted-timeout-stderr >&2; sleep 600 & sleep 600' >"$out/selftest-timeout.verdict" 2>&1
  timeout_rc=$?
  pgid="$(grep -o 'pgid=[0-9]*' "$out/selftest-timeout.verdict" | cut -d= -f2)"
  if [[ $timeout_rc != 3 ]]; then
    echo "SELFTEST FAILED: leg timeout: conform supervise returned $timeout_rc, not 3, for a never-returning process group" >&2
    cat "$out/selftest-timeout.verdict" >&2
    status=1
  elif [[ -n "$pgid" ]] && ps -o pid= -g "$pgid" 2>/dev/null | grep -q .; then
    echo "SELFTEST FAILED: leg timeout: process group $pgid survived the timeout:" >&2
    ps -o pid=,comm= -g "$pgid" >&2
    status=1
  elif ! grep -q '"kind":"timeout"' "$timeout_out"; then
    echo "SELFTEST FAILED: leg timeout: the stream did not record a timeout termination" >&2
    cat "$timeout_out" >&2
    status=1
  elif ! grep -q planted-timeout-stderr "$timeout_err"; then
    echo "SELFTEST FAILED: leg timeout: the leg's stderr was not captured" >&2
    status=1
  else
    echo "SELFTEST ok: leg timeout killed process group $pgid and recorded a timeout termination; stderr tail: $(tail -n 1 "$timeout_err")"
  fi
  echo "==> direct-termination selftest (an exit code of 128+N is not a death by signal N)"
  "$conform" supervise native 30 "$out/selftest-died.jsonl" "$out/selftest-died.err" -- sh -c 'kill -TERM $$' >/dev/null 2>&1
  "$conform" supervise native 30 "$out/selftest-exited.jsonl" "$out/selftest-exited.err" -- sh -c 'exit 143' >/dev/null 2>&1
  died="$("$conform" termination-of "$out/selftest-died.jsonl" full)"
  exited="$("$conform" termination-of "$out/selftest-exited.jsonl" full)"
  if [[ "$died" != "signaled 15" || "$exited" != "exited 143" || "$died" == "$exited" ]]; then
    echo "SELFTEST FAILED: direct termination: a real SIGTERM death read '$died' and an exit(143) read '$exited'; the leak leg's waitpid comparison cannot tell them apart" >&2
    status=1
  else
    echo "SELFTEST ok: direct termination: waitpid reads a real death as '$died' and the 128+N impostor as '$exited'"
  fi
  if [[ $status != 0 ]]; then
    echo "syscall-conformance: SELFTEST FAILED — a gate cannot fail" >&2; exit 1
  fi
  echo "CONFORMANCE_SELFTEST_RAN cases=vehicle-architecture,differ,termination,pending,frozen-rule,obligations,host-gate,strace-leak,self-signal-bounds,leg-timeout,direct-termination"
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

# Run one supervised leg process: kind native|patina, the stream and stderr
# paths, then the command. Returns conform's status (0 ran, 3 timeout, 2 the
# supervisor's output was not an envelope); the termination line is in the
# stream either way.
supervise() {
  local kind=$1 raw=$2 err=$3
  shift 3
  "$conform" supervise "$kind" "$leg_timeout" "$raw" "$err" -- "$@" >"$raw.verdict" 2>&1
}

# A probe that has no shape through the leg's vehicle says so by exiting 4
# (`EXIT_VEHICLE_UNAVAILABLE`, `probe_main!(…, libc)`) before recording
# anything: the stream is only the supervisor's termination line. A counted
# SKIP, never a pass — and never an empty stream that "matched".
vehicle_unavailable() {
  local raw=$1
  [[ "$("$conform" termination-of "$raw" 2>/dev/null)" == "exited 4" && "$(grep -c . "$raw")" == 1 ]]
}

# Run the differ for one leg; prints its lines (indented) on failure.
diff_leg() {
  local mode=$1 probe=$2 vehicle=$3 expected=$4 raw=$5 leg=$6 err=$7
  local report="$raw.diff"
  if "$conform" diff "$mode" "$probe" "$vehicle" "$expected" "$raw" "$divergences" "$err" >"$report" 2>&1; then
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
  native_bin="$target_dir/release/$bin"

  if [[ $bless == 1 ]]; then
    echo "==> blessing $probe from the native libc vehicle on $platform ($host_kernel, glibc $host_glibc)"
    supervise native "$legdir/bless.raw.jsonl" "$legdir/bless.err" "$native_bin" --vehicle libc --strict
    bless_rc=$?
    if [[ $bless_rc == 3 ]]; then
      fail_leg "$probe[bless]" "wall-clock timeout ($leg_timeout s); refusing to bless" "$legdir/bless.err"
      continue
    fi
    if ! "$conform" bless "$probe" "$legdir/bless.raw.jsonl" "$expected" linux "$host_arch" "$host_kernel" "$host_glibc" "$manifest" "$registry" 2>"$legdir/bless.conform.err"; then
      cat "$legdir/bless.conform.err" "$legdir/bless.err" >"$legdir/bless.refused" 2>/dev/null
      fail_leg "$probe[bless]" "the probe does not pass natively; refusing to bless" "$legdir/bless.refused"
      continue
    fi
  fi

  if [[ ! -f "$expected" ]]; then
    skip_leg "$probe" "UNBLESSED on $platform (no $expected; run --bless on a $platform host)"
    continue
  fi
  gate="$("$conform" host-check "$probe" "$manifest" "$registry" "$expected" "$host_kernel" 2>&1)"
  gate_rc=$?
  if [[ $gate_rc == 5 ]]; then
    unavailable=$((unavailable + 1))
    echo "HOST-UNAVAILABLE $probe: $gate"
    continue
  elif [[ $gate_rc != 0 ]]; then
    fail_leg "$probe[host-gate]" "$gate"
    continue
  fi
  blessed_term="$("$conform" termination-of "$expected")"

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
          supervise native "$raw" "$err" "$native_bin" --vehicle "$vehicle" --strict
          if [[ $? == 3 ]]; then
            fail_leg "$leg" "wall-clock timeout ($leg_timeout s); the process group was killed" "$err"; continue
          fi
          if vehicle_unavailable "$raw"; then
            skip_leg "$leg" "$(tail -n 1 "$err")"; continue
          fi
          diff_leg native "$probe" "$vehicle" "$expected" "$raw" "$leg" "$err" || true
          ;;
        patina)
          supervise patina "$raw" "$err" "$PATINA" patina run "$out/patina/$bin" --seed 1 --format json -- --vehicle "$vehicle"
          rc=$?
          if [[ $rc == 3 ]]; then
            fail_leg "$leg" "wall-clock timeout ($leg_timeout s); the process group was killed" "$err"; continue
          elif [[ $rc == 2 ]]; then
            fail_leg "$leg" "the supervisor produced no patina.result/v1 envelope" "$raw.verdict"; continue
          fi
          if vehicle_unavailable "$raw"; then
            skip_leg "$leg" "$(tail -n 1 "$err")"; continue
          fi
          diff_leg patina "$probe" "$vehicle" "$expected" "$raw" "$leg" "$err" || true
          ;;
        replay)
          # A dump left by an earlier run must never stand in for this one's
          # (the family gate reads these): gone before anything can skip.
          rm -f "$legdir/replay.$vehicle.trace-info.json" "$legdir/replay.$vehicle.trace-events.jsonl"
          if reason="$("$conform" declared-failing "$probe" "$vehicle" "$divergences")"; then
            # A probe the supervisor refuses, that is not conformant yet, or
            # that dies at a declared event leaves no complete trace to replay;
            # the patina leg already holds it to its declaration.
            skip_leg "$leg" "declared failing under patina; nothing to replay ($reason)"; continue
          fi
          trace="$legdir/replay.$vehicle.patina"
          rm -f "$trace"
          supervise patina "$raw" "$err" "$PATINA" patina run "$out/patina/$bin" --seed 1 --record "$trace" \
            --fingerprint syscall-conformance-v1 --format json -- --vehicle "$vehicle"
          rc=$?
          if [[ $rc == 3 ]]; then
            fail_leg "$leg" "wall-clock timeout ($leg_timeout s) while recording; the process group was killed" "$err"; continue
          elif [[ $rc == 2 ]]; then
            fail_leg "$leg" "the recording supervisor produced no patina.result/v1 envelope" "$raw.verdict"; continue
          fi
          if vehicle_unavailable "$raw"; then
            skip_leg "$leg" "$(tail -n 1 "$err")"; continue
          fi
          if [[ ! -s "$trace" ]]; then
            fail_leg "$leg" "record produced no trace" "$err"; continue
          fi
          # The recorded trace AS THE SUPERVISOR REPORTS IT, for the family
          # gate's trace obligations (gate.sh: the format version and the
          # signal_generated ops a probe's generations must have recorded).
          if ! "$PATINA" patina trace info "$trace" --format json >"$legdir/replay.$vehicle.trace-info.json" 2>"$legdir/replay.$vehicle.trace.err" ||
             ! "$PATINA" patina trace events "$trace" --format json >"$legdir/replay.$vehicle.trace-events.jsonl" 2>>"$legdir/replay.$vehicle.trace.err"; then
            rm -f "$legdir/replay.$vehicle.trace-info.json" "$legdir/replay.$vehicle.trace-events.jsonl"
            fail_leg "$leg" "the supervisor cannot read back the trace it recorded" "$legdir/replay.$vehicle.trace.err"; continue
          fi
          replayed="$legdir/replay.$vehicle.replayed.jsonl"
          supervise patina "$replayed" "$replayed.err" "$PATINA" patina replay "$out/patina/$bin" "$trace" \
            --fingerprint syscall-conformance-v1 --format json
          rc=$?
          if [[ $rc == 3 ]]; then
            fail_leg "$leg" "wall-clock timeout ($leg_timeout s) while replaying; the process group was killed" "$replayed.err"; continue
          elif [[ $rc == 2 ]]; then
            fail_leg "$leg" "the replay supervisor produced no patina.result/v1 envelope" "$replayed.verdict"; continue
          fi
          if ! cmp -s "$raw" "$replayed"; then
            diff "$raw" "$replayed" >"$legdir/replay.$vehicle.divergence" 2>&1 || true
            fail_leg "$leg" "record and replay event streams (including the termination) differ" "$legdir/replay.$vehicle.divergence"; continue
          fi
          if [[ "$(grep -c . "$raw")" -lt 2 ]]; then
            fail_leg "$leg" "record produced no events (vacuous replay identity)" "$err"; continue
          fi
          diff_leg patina "$probe" "$vehicle" "$expected" "$raw" "$leg" "$err" || true
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
          supervise native "$raw" "$err" env PATINA_MODE=seeded PATINA_SEED=9 \
            strace -f -s 4096 -e "$strace_events" -o "$legdir/leak.$vehicle.strace" \
              "$out/patina/$bin" --vehicle "$vehicle"
          if [[ $? == 3 ]]; then
            fail_leg "$leg" "wall-clock timeout ($leg_timeout s) under strace; the process group was killed" "$err"; continue
          fi
          if vehicle_unavailable "$raw"; then
            skip_leg "$leg" "$(tail -n 1 "$err")"; continue
          fi
          awk "$strace_filter" "$legdir/leak.$vehicle.strace" >"$legdir/leak.$vehicle.denied"
          if [[ -s "$legdir/leak.$vehicle.denied" ]]; then
            fail_leg "$leg" "host syscalls escaped the deterministic boundary:" "$legdir/leak.$vehicle.denied"; continue
          fi
          if [[ "$(grep -c . "$raw")" -lt 2 ]]; then
            fail_leg "$leg" "the probe recorded no events under strace (vacuous leak leg)" "$err"; continue
          fi
          # strace ends the way its tracee did (it re-raises a terminating
          # signal on itself), so the supervised outcome must be the blessed
          # one: a probe that dies by its own SIG_DFL signal is not an escape.
          observed_term="$("$conform" termination-of "$raw")"
          if [[ "$observed_term" != "$blessed_term" ]]; then
            fail_leg "$leg" "the probe ended '$observed_term' under strace; blessed '$blessed_term'" "$err"; continue
          fi
          # A blessed signal death is checked once more WITHOUT any supervisor
          # in between: the shim-linked binary run directly, its outcome read
          # from waitpid. The guest must really die by that signal, with the
          # core flag the host kernel gives it — an exit code that a supervisor
          # translates into "signaled" does not survive this.
          direct_note=""
          if [[ "$blessed_term" == signaled* ]]; then
            direct="$legdir/direct.$vehicle.jsonl"
            supervise native "$direct" "$direct.err" env PATINA_MODE=seeded PATINA_SEED=9 \
              "$out/patina/$bin" --vehicle "$vehicle"
            if [[ $? == 3 ]]; then
              fail_leg "$leg" "wall-clock timeout ($leg_timeout s) in the direct run; the process group was killed" "$direct.err"; continue
            fi
            direct_term="$("$conform" termination-of "$direct" full)"
            blessed_full="$("$conform" termination-of "$expected" full)"
            if [[ "$direct_term" != "$blessed_full" ]]; then
              fail_leg "$leg" "run directly (no supervisor) the guest ended '$direct_term'; blessed '$blessed_full'" "$direct.err"; continue
            fi
            direct_note=", waitpid: $direct_term"
          fi
          pass_leg "$leg" "$(($(grep -c . "$raw") - 1)) events, no escaped syscall, $observed_term$direct_note"
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

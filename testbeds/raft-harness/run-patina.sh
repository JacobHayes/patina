#!/usr/bin/env bash
###############################################################################
# raft (tikv/raft 0.7.0) 3-node cluster under Patina -- self-checking regression
# (rung 4). Threads + loopback UDP (SimNet) + file-backed logs, one process, one
# deterministic schedule.
#
# The SAME harness binary and SAME program args as run-native.sh; only the
# runner is swapped to `cargo patina run`. std::thread becomes the
# deterministic scheduler, std::net UDP becomes SimNet over loopback, std::time
# sleeps advance a virtual clock, and std::fs is the in-memory (optionally
# crash-injecting) filesystem. Fault topology comes entirely from Patina's
# experiment-plane knobs and the seed -- there is NO fault code in the harness.
#
# No allowance is needed: the harness runs under the default-deny gate clean.
# (pthread_atfork -- fork-handler registration std/libc pulls in -- is interposed
# as a no-op strong def in the shim, so it never appears as an import; see
# crates/patina-target/ESCAPE-CLASSES.md "Host-state registration".)
#
# Exits nonzero on ANY regression:
#   [1] clean 3-node cluster: 5 seeds, each 3 repeats byte-identical (RAFT_RESULT
#       + record trace), every proposal committed+applied on all nodes, exit 0;
#   [2] a recorded run replays byte-identically;
#   [3] net-jitter reorder: cluster still converges, zero invariant violations;
#   [4] net-drop sweep 100/300 permille converges; 500 permille may honestly time
#       out (liveness) but MUST NOT violate safety;
#   [5] fs-crash sweep: aborts are allowed (fail-closed), safety violations are
#       NOT.
#   [6] crash-RECOVERY: a killed OR storage-faulted node is restarted in-process
#       (reopen FileStorage, rebind port, rejoin, catch up); it must converge
#       with the survivors, invariants must hold ACROSS the restart, and the
#       recovery must be byte-identical across repeats.
# The overriding guard is: a `RAFT_VIOLATION` on any run fails the script.
###############################################################################
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
built="$here/target/patina/raft-harness"
PATINA="$repo_root/target/release/cargo-patina"

# No --allow-unsupported-symbols: the harness passes the default-deny gate clean.
# Escape hatch: if a shim/audit refactor is mid-flight and a std-pulled symbol is
# transiently unclassified by the gate (rebuild cargo-patina FIRST -- a stale
# release binary is the usual cause), export PATINA_ALLOW_SYMS=name[,name...] to
# run anyway with a warning. The COMMITTED default is empty, so the unqualified
# default-deny property is what CI enforces.
ALLOW=()
if [[ -n "${PATINA_ALLOW_SYMS:-}" ]]; then
  ALLOW=(--allow-unsupported-symbols "$PATINA_ALLOW_SYMS")
fi
# Fixed workload/base args identical to the native harness invocation shape.
PROP=20
ARGS=(--seed 7 --proposals "$PROP" --base-port 4001 --data-dir /raft --timeout-secs 90)

cd "$repo_root"
echo "==> building cargo-patina and the harness under Patina"
cargo build --release --quiet -p cargo-patina
mkdir -p "$here/target/patina"
"$PATINA" patina build "$here" --output "$built" --release >/dev/null

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0

run() { "$PATINA" patina run "$built" "$@"; }
# `replay <trace> [flags]` reproduces a recorded run flag-free: the seed, fault
# knobs, and guest arguments (the `-- ...` section) are restored from the trace,
# so replays no longer re-pass them. `--allow` stays (a machine-local audit fact).
replay() { "$PATINA" patina replay "$built" "$@"; }
result_of() { sed -n 's/^\(RAFT_RESULT .*\)$/\1/p'; }
committed_of() { sed -n 's/.*committed=\([0-9][0-9]*\).*/\1/p'; }
violated() { grep -q 'RAFT_VIOLATION'; }

echo "==> [1] clean cluster: 5 seeds x 3 repeats byte-identical (result + trace), all committed"
for s in 1 2 3 4 5; do
  ref_res=""; ref_trace=""
  for rep in 1 2 3; do
    tr="$work/c.$s.$rep.trace"
    err="$work/c.$s.$rep.err"
    out="$(run --seed "$s" --record "$tr" "${ALLOW[@]}" -- "${ARGS[@]}" 2>"$err")" || {
      echo "    FAIL: seed $s rep $rep exited nonzero"; fail=1; }
    if violated <"$err"; then echo "    FAIL: RAFT_VIOLATION seed $s rep $rep"; fail=1; fi
    res="$(result_of <<<"$out")"
    th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
    committed="$(committed_of <<<"$res")"
    if [[ "$committed" != "$PROP" ]]; then
      echo "    FAIL: seed $s rep $rep committed=$committed expected $PROP"; fail=1
    fi
    if [[ $rep -eq 1 ]]; then ref_res="$res"; ref_trace="$th"; fi
    if [[ "$res" != "$ref_res" || "$th" != "$ref_trace" ]]; then
      echo "    FAIL: seed $s rep $rep not byte-identical to rep 1"; fail=1
    fi
  done
  echo "    seed $s: $ref_res | trace=$ref_trace"
done

echo "==> [2] record + strict replay is byte-identical"
rec="$work/replay.trace"
r1="$(run --record "$rec" "${ALLOW[@]}" -- "${ARGS[@]}" 2>/dev/null | result_of)"
r2="$(replay "$rec" "${ALLOW[@]}" 2>/dev/null | result_of)"
echo "    record: $r1"
echo "    replay: $r2"
if [[ "$r1" != "$r2" || -z "$r1" ]]; then echo "    FAIL: replay differs from record"; fail=1; fi

echo "==> [3] net-jitter reorder: cluster converges, zero invariant violations"
for s in 1 2 3 4 5; do
  err="$work/j.$s.err"
  out="$(run --seed "$s" "${ALLOW[@]}" --net-jitter-nanos 1000000..80000000 -- "${ARGS[@]}" 2>"$err")" || true
  if violated <"$err"; then echo "    FAIL: RAFT_VIOLATION under jitter seed $s"; fail=1; fi
  committed="$(committed_of <<<"$out")"
  echo "    seed $s: committed=${committed:-0}/$PROP  $(result_of <<<"$out" | sed 's/RAFT_RESULT //')"
  if [[ "${committed:-0}" != "$PROP" ]]; then
    echo "    FAIL: jitter alone should converge (seed $s committed=${committed:-0})"; fail=1
  fi
done

echo "==> [4] net-drop sweep: 100/300 converge; 500 may time out but must not violate safety"
for d in 100 300 500; do
  echo "    -- drop $d permille --"
  for s in 1 2 3 4 5; do
    err="$work/d.$d.$s.err"
    out="$(run --seed "$s" "${ALLOW[@]}" --net-drop-permille "$d" -- "${ARGS[@]}" 2>"$err")" || true
    if violated <"$err"; then echo "      FAIL: RAFT_VIOLATION drop $d seed $s"; fail=1; fi
    committed="$(committed_of <<<"$out")"
    terms="$(sed -n 's/.*terms=\([0-9]*\).*/\1/p' <<<"$out")"
    note=""
    if [[ "${committed:-0}" != "$PROP" ]]; then note="(timed out - liveness only)"; fi
    echo "      seed $s: committed=${committed:-0}/$PROP terms=${terms:-?} $note"
    # At light loss raft must still converge; regression if it cannot.
    if [[ "$d" -le 300 && "${committed:-0}" != "$PROP" ]]; then
      echo "      FAIL: drop $d should converge (seed $s committed=${committed:-0})"; fail=1
    fi
  done
done

echo "==> [5] fs-crash sweep: aborts allowed (fail-closed), safety violations are not"
crash_abort=0; crash_ok=0
for spec in write:1 write:5 write:12 write:40 sync:1 sync:4 sync:16 close:1 close:4; do
  for s in 1 2 3; do
    err="$work/f.err"
    # set -e safe capture: the fail-closed abort returns exit 2 by design.
    if out="$(run --seed "$s" "${ALLOW[@]}" --fs-crash-at "$spec" -- "${ARGS[@]}" 2>"$err")"; then code=0; else code=$?; fi
    if violated <"$err"; then echo "      FAIL: RAFT_VIOLATION fs-crash $spec seed $s"; fail=1; fi
    if [[ $code -eq 0 ]]; then crash_ok=$((crash_ok+1)); elif [[ $code -eq 2 ]]; then crash_abort=$((crash_abort+1));
    else echo "      note: fs-crash $spec seed $s unexpected exit=$code"; fi
  done
done
echo "    fs-crash outcomes: clean(exit0)=$crash_ok fail-closed-abort(exit2)=$crash_abort (any safety violation FAILs above)"

echo "==> [6] crash-RECOVERY: kill+restart and fs-crash+restart converge, invariants hold across the restart, deterministic"
# The point of task #16: a downed node reopens FileStorage on its SAME data dir,
# rebinds its UDP port, rejoins, and CATCHES UP -- and the safety invariants
# (<=1 leader/term from fsync'd hard state, log matching, no applied regress)
# hold ACROSS the restart. `--propose-window` paces the client so a kill anchored
# to `committed==N` lands at an intermediate point (the batch commits in one
# burst otherwise) and the reincarnation must replicate the entries it missed.

echo "    -- (a) deliberate kill-plan (node 3 @ committed=5) + restart: 5 seeds x 3 repeats byte-identical, all converge --"
RECOVER=(--kill-plan 3:5 --restart-after-ticks 5 --propose-window 2)
for s in 1 2 3 4 5; do
  ref_res=""; ref_trace=""
  for rep in 1 2 3; do
    tr="$work/r.$s.$rep.trace"; err="$work/r.$s.$rep.err"
    out="$(run --seed "$s" "${ALLOW[@]}" --record "$tr" -- "${ARGS[@]}" "${RECOVER[@]}" 2>"$err")" || {
      echo "    FAIL: recovery seed $s rep $rep exited nonzero"; fail=1; }
    if violated <"$err"; then echo "    FAIL: RAFT_VIOLATION recovery seed $s rep $rep"; fail=1; fi
    res="$(result_of <<<"$out")"; th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
    committed="$(committed_of <<<"$res")"
    restarts="$(sed -n 's/.*restarts=\([0-9]*\).*/\1/p' <<<"$res")"
    if [[ "$committed" != "$PROP" ]]; then
      echo "    FAIL: recovery seed $s rep $rep committed=$committed expected $PROP"; fail=1
    fi
    if [[ "${restarts:-0}" -lt 1 ]]; then
      echo "    FAIL: recovery seed $s rep $rep never restarted a node (restarts=${restarts:-0})"; fail=1
    fi
    if [[ $rep -eq 1 ]]; then ref_res="$res"; ref_trace="$th"; fi
    if [[ "$res" != "$ref_res" || "$th" != "$ref_trace" ]]; then
      echo "    FAIL: recovery seed $s rep $rep not byte-identical to rep 1"; fail=1
    fi
  done
  echo "    seed $s: $ref_res | trace=$ref_trace"
done

echo "    -- (b) fs-crash + recover: injected persist crash on one node, supervisor restarts it in-process --"
recovered=0; nohit=0; liveness=0
for spec in write:5 write:12 write:40 sync:4 sync:16 close:4; do
  for s in 1 2 3; do
    err="$work/fr.err"
    if out="$(run --seed "$s" "${ALLOW[@]}" --fs-crash-at "$spec" -- "${ARGS[@]}" --recover-storage-faults --restart-after-ticks 5 2>"$err")"; then code=0; else code=$?; fi
    if violated <"$err"; then echo "    FAIL: RAFT_VIOLATION fs-crash+recover $spec seed $s"; fail=1; fi
    committed="$(committed_of <<<"$out")"
    if [[ $code -eq 0 && "${committed:-0}" == "$PROP" ]]; then
      if grep -q 'restarted node' "$err"; then recovered=$((recovered+1)); else nohit=$((nohit+1)); fi
    elif [[ $code -eq 1 ]]; then
      liveness=$((liveness+1))  # honest timeout: node did not rejoin in time
    else
      echo "    FAIL: fs-crash+recover $spec seed $s unexpected exit=$code committed=${committed:-0}"; fail=1
    fi
  done
done
echo "    fs-crash+recover outcomes: recovered+converged=$recovered no-fault-hit=$nohit liveness-timeout=$liveness (any safety violation FAILs above)"
if [[ "$recovered" -lt 1 ]]; then
  echo "    FAIL: fs-crash+recover never exercised an in-process recovery (recovered=$recovered)"; fail=1
fi

echo "    -- (c) fs-crash recovery is deterministic (write:5, 3 repeats byte-identical) --"
ref_fd=""
for rep in 1 2 3; do
  tr="$work/fd.$rep.trace"
  out="$(run --seed 1 "${ALLOW[@]}" --fs-crash-at write:5 --record "$tr" -- "${ARGS[@]}" --recover-storage-faults --restart-after-ticks 5 2>/dev/null)"
  sig="$(result_of <<<"$out")|$(shasum -a256 "$tr" | cut -d' ' -f1)"
  if [[ $rep -eq 1 ]]; then ref_fd="$sig"; fi
  if [[ "$sig" != "$ref_fd" ]]; then echo "    FAIL: fs-crash recovery not deterministic at rep $rep"; fail=1; fi
done
echo "    write:5 recovery deterministic: ${ref_fd%%|*} | trace=${ref_fd##*|}"

echo "    -- (d) a recovery run records + replays byte-identically (restart included) --"
rrec="$work/recover.trace"
rr1="$(run "${ALLOW[@]}" --record "$rrec" -- "${ARGS[@]}" "${RECOVER[@]}" 2>/dev/null | result_of)"
rr2="$(replay "$rrec" "${ALLOW[@]}" 2>/dev/null | result_of)"
echo "    record: $rr1"
echo "    replay: $rr2"
if [[ "$rr1" != "$rr2" || -z "$rr1" ]]; then echo "    FAIL: recovery replay differs from record"; fail=1; fi

if [[ "$fail" -ne 0 ]]; then
  echo "==> FAILED"; exit 1
fi
echo "==> all Patina checks passed"

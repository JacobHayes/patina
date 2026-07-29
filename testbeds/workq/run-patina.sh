#!/usr/bin/env bash
###############################################################################
# workq — a single-process durable work queue under Patina. Self-checking
# regression gate: threads (deterministic scheduler) + loopback UDP (SimNet) +
# WAL segment files (the in-memory / crash-injecting filesystem) + virtual-time
# timers, all in one process, one deterministic schedule.
#
# The SAME binary and SAME guest args as run-native.sh; only the runner is
# swapped to `cargo patina run`. Fault topology (drop/reorder/jitter, fs-crash,
# cooperative buggify) comes entirely from Patina's knobs and the seed — there is
# NO fault code in the harness. The harness runs under the default-deny symbol
# gate clean (no allowance).
#
# Exits nonzero on ANY regression:
#   [1] clean run: 5 seeds x 3 repeats byte-identical (WORKQ_RESULT + record
#       trace), every job completed (failed 0), exit 0;
#   [2] a recorded run replays byte-identically;
#   [3] net-jitter and net-drop: the queue converges (every acked job terminates
#       as completed or failed) and NEVER violates an invariant;
#   [4] fs-crash sweep: a fail-closed WORKQ_ABORT is allowed, a WORKQ_VIOLATION
#       is not;
#   [5] crash-RECOVERY: the server is killed + restarted in-process on the same
#       WAL (--crash-at-completed); acked jobs survive, the run converges, and it
#       is byte-identical across repeats. Plus the in-process fail-closed-recovery
#       self-test (invariant 5: mid-log corruption aborts, never truncates).
#   [6] a buggify sweep via the shared ../buggify-campaign.sh accumulator: every
#       cooperative-fault gen holds its always! invariants (no ALWAYS_VIOLATION)
#       and the campaign meets its sometimes! coverage (no SOMETIMES_UNMET).
#   [7] seeded-bug catch: each `--bug` on its pinned seed+config MUST be caught by
#       an existing invariant/liveness gate (fail-closed: a bug that slips through
#       fails the leg), and the failing run records + strict-replays byte-identically.
# The overriding guard: a WORKQ_VIOLATION on any run fails the script.
#
# Determinism model (see the crate module doc for the full statement): Patina is
# per-platform, per-seed schedule-deterministic, so WITHIN a platform legs [1]/[5]
# gate byte-identical repeats and [2] gates record/replay identity, and the trace
# hashes are platform-local by design. ACROSS platforms the invariant
# is the `applied_hash`, which is computed over the run OUTCOME sorted by each job's
# schedule-invariant client identity — not its completion order — so the same seed
# yields the same applied_hash on macOS and Linux even though the schedule differs.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
built="$here/target/patina/workq"
PATINA="$repo_root/target/release/cargo-patina"

# shellcheck source=../buggify-campaign.sh
source "$here/../buggify-campaign.sh"

# No --allow-unsupported-symbols: the harness passes the default-deny gate clean.
# Escape hatch: if a shim/audit refactor transiently unclassifies a std-pulled
# symbol, export PATINA_ALLOW_SYMS=name[,name...]. The
# COMMITTED default is empty, so the unqualified default-deny property is enforced.
ALLOW=()
if [[ -n "${PATINA_ALLOW_SYMS:-}" ]]; then
  ALLOW=(--allow-unsupported-symbols "$PATINA_ALLOW_SYMS")
fi

# Fixed workload/base args, identical to the native harness invocation shape. The
# guest --seed fixes the payload workload; the Patina run --seed varies the
# schedule and fault draws.
JOBS=24
ARGS=(--seed 7 --jobs "$JOBS" --workers 3 --producers 2 --base-port 5001 --data-dir /workq --timeout-secs 90)

cd "$repo_root"
echo "==> building cargo-patina and the workq harness under Patina"
# The legs below run without `set -e` (each handles its own nonzero exits), so
# the build prelude must fail CLOSED explicitly: a gate that cannot build must
# certify nothing — silently reusing a stale prebuilt binary would be a false
# green (the fuzz-sweep FATAL convention).
if ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if ! mkdir -p "$here/target/patina"; then
  echo "FATAL: mkdir $here/target/patina failed" >&2; exit 3
fi
if ! "$PATINA" patina build "$here" --output "$built" --release >/dev/null; then
  echo "FATAL: patina build of the workq harness failed" >&2; exit 3
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
start_secs=$SECONDS

run() { "$PATINA" patina run "$built" "$@"; }
replay() { "$PATINA" patina replay "$built" "$@"; }
result_of() { sed -n 's/^\(WORKQ_RESULT .*\)$/\1/p'; }
field_of() { sed -n "s/.*$1=\([0-9][0-9]*\).*/\1/p"; }
violated() { grep -q 'WORKQ_VIOLATION'; }
# Surface a guest stderr tail on FAIL (a bare FAIL is undiagnosable from CI logs).
stderr_tail() { [[ -s "$1" ]] && sed -n '1,20p' "$1" | sed 's/^/      stderr| /'; }

echo "==> [1] clean run: 5 seeds x 3 repeats byte-identical (result + trace), all completed"
for s in 1 2 3 4 5; do
  ref_res=""; ref_trace=""
  for rep in 1 2 3; do
    tr="$work/c.$s.$rep.trace"; err="$work/c.$s.$rep.err"
    out="$(run --seed "$s" --record "$tr" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" 2>"$err")" || {
      echo "    FAIL: seed $s rep $rep exited nonzero"; fail=1; stderr_tail "$err"; }
    if violated <"$err"; then echo "    FAIL: WORKQ_VIOLATION seed $s rep $rep"; fail=1; fi
    res="$(result_of <<<"$out")"
    th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
    comp="$(field_of completed <<<"$res")"; failed="$(field_of failed <<<"$res")"
    if [[ "$comp" != "$JOBS" || "$failed" != "0" ]]; then
      echo "    FAIL: seed $s rep $rep completed=$comp failed=$failed expected $JOBS/0"; fail=1
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
r1="$(run --seed 2 --record "$rec" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" 2>/dev/null | result_of)"
r2="$(replay "$rec" ${ALLOW[@]+"${ALLOW[@]}"} 2>/dev/null | result_of)"
echo "    record: $r1"
echo "    replay: $r2"
if [[ "$r1" != "$r2" || -z "$r1" ]]; then echo "    FAIL: replay differs from record"; fail=1; fi

echo "==> [3] net-jitter + net-drop: converge (all terminal), zero invariant violations"
converged() { # result-line -> 0 if enqueued==JOBS and completed+failed==enqueued
  local res="$1" e c d
  e="$(field_of enqueued <<<"$res")"; c="$(field_of completed <<<"$res")"; d="$(field_of failed <<<"$res")"
  [[ "${e:-0}" == "$JOBS" && $(( ${c:-0} + ${d:-0} )) -eq "${e:-0}" ]]
}
echo "    -- net-jitter reorder --"
for s in 1 2 3 4 5; do
  err="$work/j.$s.err"
  out="$(run --seed "$s" ${ALLOW[@]+"${ALLOW[@]}"} --net-jitter-nanos 1000000..80000000 -- "${ARGS[@]}" 2>"$err")" || true
  if violated <"$err"; then echo "      FAIL: WORKQ_VIOLATION under jitter seed $s"; fail=1; fi
  res="$(result_of <<<"$out")"
  echo "      seed $s: ${res#WORKQ_RESULT }"
  converged "$res" || { echo "      FAIL: jitter did not converge (seed $s)"; fail=1; }
done
echo "    -- net-drop sweep (permille) --"
for d in 100 200 300; do
  for s in 1 2 3; do
    err="$work/d.$d.$s.err"
    out="$(run --seed "$s" ${ALLOW[@]+"${ALLOW[@]}"} --net-drop-permille "$d" -- "${ARGS[@]}" 2>"$err")" || true
    if violated <"$err"; then echo "      FAIL: WORKQ_VIOLATION drop $d seed $s"; fail=1; fi
    res="$(result_of <<<"$out")"
    echo "      drop $d seed $s: ${res#WORKQ_RESULT }"
    converged "$res" || { echo "      FAIL: drop $d should converge (seed $s)"; fail=1; }
  done
done

echo "==> [4] fs-crash sweep: fail-closed WORKQ_ABORT allowed, WORKQ_VIOLATION never"
crash_abort=0; crash_ok=0
for spec in write:1 write:5 write:12 write:40 sync:1 sync:4 sync:16 close:1 close:4; do
  for s in 1 2 3; do
    err="$work/f.err"
    # set -e safe capture: a fail-closed abort returns exit 2 by design.
    if out="$(run --seed "$s" ${ALLOW[@]+"${ALLOW[@]}"} --fs-crash-at "$spec" -- "${ARGS[@]}" 2>"$err")"; then code=0; else code=$?; fi
    if violated <"$err"; then echo "      FAIL: WORKQ_VIOLATION fs-crash $spec seed $s"; fail=1; fi
    if [[ $code -eq 0 ]]; then crash_ok=$((crash_ok+1));
    elif [[ $code -eq 2 ]]; then crash_abort=$((crash_abort+1));
    else echo "      note: fs-crash $spec seed $s unexpected exit=$code"; stderr_tail "$err"; fi
  done
done
echo "    fs-crash outcomes: clean(exit0)=$crash_ok fail-closed-abort(exit2)=$crash_abort (any WORKQ_VIOLATION FAILs above)"

echo "==> [5] crash-RECOVERY: kill+restart in-process on the same WAL, converge, byte-identical"
echo "    -- (a) crash at completed=10 + restart: 5 seeds x 3 repeats byte-identical, all converge --"
for s in 1 2 3 4 5; do
  ref_res=""; ref_trace=""
  for rep in 1 2 3; do
    tr="$work/r.$s.$rep.trace"; err="$work/r.$s.$rep.err"
    out="$(run --seed "$s" --record "$tr" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" --crash-at-completed 10 2>"$err")" || {
      echo "    FAIL: recovery seed $s rep $rep exited nonzero"; fail=1; stderr_tail "$err"; }
    if violated <"$err"; then echo "    FAIL: WORKQ_VIOLATION recovery seed $s rep $rep"; fail=1; fi
    if ! grep -q 'crashed + restarted' "$err"; then
      echo "    FAIL: recovery seed $s rep $rep never restarted the server"; fail=1
    fi
    res="$(result_of <<<"$out")"; th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
    converged "$res" || { echo "    FAIL: recovery seed $s rep $rep did not converge"; fail=1; }
    if [[ $rep -eq 1 ]]; then ref_res="$res"; ref_trace="$th"; fi
    if [[ "$res" != "$ref_res" || "$th" != "$ref_trace" ]]; then
      echo "    FAIL: recovery seed $s rep $rep not byte-identical to rep 1"; fail=1
    fi
  done
  echo "    seed $s: $ref_res | trace=$ref_trace"
done
echo "    -- (b) a recovery run records + replays byte-identically --"
rrec="$work/recover.trace"
rr1="$(run --seed 1 --record "$rrec" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" --crash-at-completed 10 2>/dev/null | result_of)"
rr2="$(replay "$rrec" ${ALLOW[@]+"${ALLOW[@]}"} 2>/dev/null | result_of)"
echo "    record: $rr1"; echo "    replay: $rr2"
if [[ "$rr1" != "$rr2" || -z "$rr1" ]]; then echo "    FAIL: recovery replay differs from record"; fail=1; fi
echo "    -- (c) in-process fail-closed-recovery self-test (invariant 5) --"
serr="$work/self.err"
if sout="$(run ${ALLOW[@]+"${ALLOW[@]}"} -- --check-recovery-fail-closed 2>"$serr")"; then scode=0; else scode=$?; fi
if violated <"$serr"; then echo "    FAIL: recovery self-test reported WORKQ_VIOLATION"; fail=1; stderr_tail "$serr"; fi
if [[ $scode -ne 0 ]] || ! grep -q 'WORKQ_RECOVERY_SELFTEST ok' <<<"$sout"; then
  echo "    FAIL: recovery self-test did not pass (exit=$scode)"; fail=1
else
  echo "    ${sout}"
fi

echo "==> [6] buggify sweep via ../buggify-campaign.sh (ALWAYS_VIOLATION / SOMETIMES_UNMET classes)"
BUGGIFY_GENS="${WORKQ_BUGGIFY_GENS:-30}"
CAMPAIGN_STATE="$work/campaign-state.json"
rm -f "$CAMPAIGN_STATE"
always_violations=0
# Per-gen config is a pure function of SHA-256("workq-buggify-$G"), so any gen is
# re-runnable by number. buggify-after-setup is ALWAYS on (the workload reaches
# setup_complete()); fire/activation both skew high so redelivery + job-failed
# coverage is met across the campaign. No fs-crash here: this leg isolates the
# cooperative-fault classes.
for (( G=1; G<=BUGGIFY_GENS; G++ )); do
  hex="$(printf 'workq-buggify-%s' "$G" | shasum -a256 | cut -c1-16)"
  b0=$(( 16#${hex:0:2} )); b1=$(( 16#${hex:2:2} )); b2=$(( 16#${hex:4:2} ))
  gseed=$(( (b0 << 8 | b1) ))
  fire=$(( 300 + (b2 % 8) * 100 ))          # 300..1000
  act=$(( 400 + (b0 % 7) * 100 ))           # 400..1000
  err="$work/b.$G.err"
  if out="$(run --seed "$gseed" --buggify="$fire" --buggify-activation-permille "$act" --buggify-after-setup ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" 2>"$err")"; then gcode=0; else gcode=$?; fi
  # A WORKQ_VIOLATION is always a hard failure.
  if violated <"$err"; then echo "    FAIL: WORKQ_VIOLATION buggify gen $G (seed=$gseed fire=$fire act=$act)"; fail=1; stderr_tail "$err"; fi
  # Classify via the shared buggify layer (ALWAYS_VIOLATION and the fatal markers).
  class="$(buggify_class "$gcode" "$out" "$(cat "$err")")"
  if [[ "$class" == ALWAYS_VIOLATION ]]; then
    echo "    FAIL: ALWAYS_VIOLATION buggify gen $G"; always_violations=$((always_violations+1)); fail=1
  elif [[ -n "$class" && "$class" != "OK" ]]; then
    echo "    FAIL: buggify class $class at gen $G"; fail=1; stderr_tail "$err"
  fi
  campaign_accumulate "$CAMPAIGN_STATE" "$(sdk_report_line "$err")"
done
# Campaign-level SOMETIMES_UNMET: a sometimes! site reached but never satisfied.
unmet=()
while IFS= read -r line; do [[ -n "$line" ]] && unmet+=("$line"); done < <(campaign_sometimes_unmet "$CAMPAIGN_STATE")
echo "    buggify campaign: gens=$BUGGIFY_GENS always_violations=$always_violations sometimes_unmet=${#unmet[@]}"
if (( ${#unmet[@]} > 0 )); then
  echo "    FAIL: unmet sometimes-sites:"; for line in "${unmet[@]}"; do echo "      $line"; done; fail=1
fi
python3 - "$CAMPAIGN_STATE" <<'PY' 2>/dev/null || true
import json, sys
s = json.load(open(sys.argv[1]))
print(f"    per-site coverage (generations={s.get('generations',0)} gens_with_report={s.get('gens_with_report',0)}):")
for label, r in sorted(s.get("sites", {}).items()):
    extra = f" satisfied={r['sometimes_satisfied']}" if r["kind"] == "sometimes" else \
            (f" fired_gens={r['fired_gens']} total_fires={r['total_fires']}" if r["kind"] in ("fault","delay") else "")
    print(f"      {label} [{r['kind']}] reached={r['reached']} activated_gens={r['activated_gens']}{extra}")
PY

echo "==> [7] seeded-bug catch: each --bug on its pinned seed+config MUST be caught"
# Each entry: NAME | run-seed | extra Patina knobs | extra guest args | expected marker.
# The demo is FAIL-CLOSED: if a run comes back clean (exit 0, no marker), the bug
# slipped past the invariants and the leg FAILS -- so it can never go vacuous. Then
# the failing run is recorded and strict-replayed, requiring a byte-identical result
# + trace hash (the violation reproduces exactly).
bug_leg() {
  local name="$1" bseed="$2" pknobs="$3" gargs="$4" marker="$5"
  local tr="$work/bug.$name.trace" err="$work/bug.$name.err" out code
  # shellcheck disable=SC2086
  if out="$(run --seed "$bseed" $pknobs --record "$tr" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" $gargs 2>"$err")"; then code=0; else code=$?; fi
  local res; res="$(result_of <<<"$out")"
  echo "    -- $name (seed $bseed): ${res#WORKQ_RESULT } exit=$code"
  # Caught == nonzero exit AND the expected marker present on stderr.
  if [[ $code -eq 0 ]] || ! grep -q "$marker" "$err"; then
    echo "    FAIL: bug '$name' NOT caught (exit=$code, expected '$marker') -- demo went vacuous"; fail=1; stderr_tail "$err"; return
  fi
  echo "        caught: $(grep -m1 "$marker" "$err")"
  # Strict replay must reproduce the failing run byte-identically (result + trace).
  local th rout rerr rth
  th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
  rerr="$work/bug.$name.replay.err"
  rout="$(replay "$tr" ${ALLOW[@]+"${ALLOW[@]}"} 2>"$rerr")" || true
  rth="$(shasum -a256 "$tr" | cut -d' ' -f1)"
  if [[ "$(result_of <<<"$rout")" != "$res" || "$th" != "$rth" ]]; then
    echo "    FAIL: bug '$name' replay not byte-identical to record"; fail=1
  elif ! grep -q "$marker" "$rerr"; then
    echo "    FAIL: bug '$name' replay did not reproduce '$marker'"; fail=1
  else
    echo "        replay reproduced identically (trace=$th)"
  fi
}
# dedup-ignore-producer: two producers reuse client_seq, so half the jobs are
# deduped away and the run can never converge -> the completion gate fails closed.
bug_leg dedup-ignore-producer 1 "" "--timeout-secs 20 --bug dedup-ignore-producer" WORKQ_FAILURE
# skip-redelivery-commit: a redelivered job's durable Complete record is skipped,
# so the WAL loses an acked completion -> the no-loss invariant fires.
bug_leg skip-redelivery-commit 2 "--buggify=500 --buggify-after-setup" "--bug skip-redelivery-commit" WORKQ_VIOLATION
# apply-check-outside-lock: the worker's exactly-once "already applied?" check sits
# OUTSIDE the apply critical section, so two workers holding early-redelivered
# duplicates of one job both pass it and double-apply -> the exactly-once invariant
# fires. early-redelivery (buggify) forces the concurrent duplicate; the small tick
# shrinks redelivery latency into the apply window so the race is deterministic.
bug_leg apply-check-outside-lock 1 "--buggify=500 --buggify-after-setup" "--tick-ms 2 --bug apply-check-outside-lock" WORKQ_VIOLATION

elapsed=$(( SECONDS - start_secs ))
echo "==> wall time: ${elapsed}s"
if [[ "$fail" -ne 0 ]]; then
  echo "==> FAILED"; exit 1
fi
echo "==> all Patina checks passed"

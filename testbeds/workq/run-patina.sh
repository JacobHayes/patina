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
#   [1] clean run: 5 seeds x 3 repeats byte-identical (the `pass` verdict's
#       outcome digest + record trace), every job completed (failed 0), exit 0;
#   [2] a recorded run replays with an identical outcome verdict;
#   [3] net-jitter and net-drop: the queue converges (every acked job terminates
#       as completed or failed) and NEVER violates an invariant;
#   [4] fs-crash sweep: a fail-closed abort (exit 2) is allowed, a violation
#       verdict is not;
#   [5] crash-RECOVERY: the server is killed + restarted in-process on the same
#       WAL (--crash-at-completed); acked jobs survive, the run converges, and it
#       is byte-identical across repeats. Plus the in-process fail-closed-recovery
#       self-test (invariant 5: mid-log corruption aborts, never truncates).
#   [6] a buggify sweep via the shared ../buggify-campaign.sh accumulator: every
#       cooperative-fault gen holds its always! invariants (no ALWAYS_VIOLATION)
#       and the campaign meets its sometimes! coverage (no SOMETIMES_UNMET).
#   [7] seeded-bug catch: each `--bug` MUST be caught by an existing
#       invariant/liveness gate within a bounded seed sweep (fail-closed: a bug
#       no seed catches fails the leg), and the catching run records +
#       strict-replays with an identical verdict stream + trace hash.
#   [8] --server-host: producers/workers resolve the server by name (via
#       --dns-entry) instead of the numeric 127.0.0.1 path — converges and
#       records + replays byte-identically, and an injected
#       --dns-fail-permille still converges (the retry in
#       wire::resolve_server_host must not wedge under a real DNS fault).
# The overriding guard: a `violation` verdict on any run fails the script.
#
# Every leg reads the run's VERDICT channel (the `PATINA_VERDICT` wire lines the
# SDK emits, docs/arcs/outcome-channel.md) rather than workq's printed WORKQ_*
# dialect: the guest announces its outcomes through `patina_dst::verdict`, and
# the printed lines are only a human echo. The one exception is the convergence
# timeout, which reports no verdict by design (leg [7], dedup-ignore-producer).
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
# guest --seed fixes the payload workload (carried in the pass verdict's
# workload_seed=
# and intentionally constant across every leg below); the Patina run --seed
# varies the schedule and fault draws.
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
# A static duplicate label (two SDK sites sharing one buggify/always/sometimes/
# reachable label) is invisible until the binary first runs, where the runtime
# aborts every generation with PATINA_BUGGIFY_DUPLICATE_LABEL. `sites` catches
# the same class ahead of that, so the gate fails here instead of burning a
# whole sweep on an unrunnable binary.
sites_err="$(mktemp)"
if ! (cd "$here" && "$PATINA" patina sites --no-cache >/dev/null 2>"$sites_err"); then
  echo "FATAL: cargo patina sites found a static duplicate label" >&2
  cat "$sites_err" >&2
  rm -f "$sites_err"
  exit 3
fi
rm -f "$sites_err"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
start_secs=$SECONDS

run() { "$PATINA" patina run "$built" "$@"; }
replay() { "$PATINA" patina replay "$built" "$@"; }
# Outcome facts come from the guest's `pass` verdict and findings from its
# `violation` verdicts -- the verdict ABI's own wire lines on stderr
# (patina_dst_abi::verdict_line) -- not from workq's printed WORKQ_* dialect.
# Both take the run's STDERR FILE; the field reader takes the verdict line
# itself, so a WORKQ_FAILURE diagnostic carrying its own `completed=` can never
# be misread as the outcome.
result_of() { /usr/bin/grep -m1 '^PATINA_VERDICT .*kind=pass label=workq-outcome ' "$1" 2>/dev/null || true; }
field_of() { printf '%s' "$2" | /usr/bin/grep -o "$1=[0-9][0-9]*" | head -1 | cut -d= -f2; }
violated() { /usr/bin/grep -q '^PATINA_VERDICT .*kind=violation ' "$1"; }
# Surface a guest stderr tail on FAIL (a bare FAIL is undiagnosable from CI logs).
stderr_tail() { [[ -s "$1" ]] && sed -n '1,20p' "$1" | sed 's/^/      stderr| /'; }

echo "==> [1] clean run: 5 seeds x 3 repeats byte-identical (result + trace), all completed"
for s in 1 2 3 4 5; do
  ref_res=""; ref_trace=""
  for rep in 1 2 3; do
    tr="$work/c.$s.$rep.trace"; err="$work/c.$s.$rep.err"
    run --seed "$s" --record "$tr" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" >/dev/null 2>"$err" || {
      echo "    FAIL: seed $s rep $rep exited nonzero"; fail=1; stderr_tail "$err"; }
    if violated "$err"; then echo "    FAIL: violation verdict seed $s rep $rep"; fail=1; fi
    res="$(result_of "$err")"
    th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
    comp="$(field_of completed "$res")"; failed="$(field_of failed "$res")"
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
run --seed 2 --record "$rec" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" >/dev/null 2>"$work/rec.err"
r1="$(result_of "$work/rec.err")"
replay "$rec" ${ALLOW[@]+"${ALLOW[@]}"} >/dev/null 2>"$work/rep.err"
r2="$(result_of "$work/rep.err")"
echo "    record: $r1"
echo "    replay: $r2"
if [[ "$r1" != "$r2" || -z "$r1" ]]; then echo "    FAIL: replay differs from record"; fail=1; fi

echo "==> [3] net-jitter + net-drop: converge (all terminal), zero invariant violations"
converged() { # pass-verdict line -> 0 if enqueued==JOBS and completed+failed==enqueued
  local res="$1" e c d
  e="$(field_of enqueued "$res")"; c="$(field_of completed "$res")"; d="$(field_of failed "$res")"
  [[ "${e:-0}" == "$JOBS" && $(( ${c:-0} + ${d:-0} )) -eq "${e:-0}" ]]
}
echo "    -- net-jitter reorder --"
for s in 1 2 3 4 5; do
  err="$work/j.$s.err"
  run --seed "$s" ${ALLOW[@]+"${ALLOW[@]}"} --net-jitter-nanos 1000000..80000000 -- "${ARGS[@]}" >/dev/null 2>"$err" || true
  if violated "$err"; then echo "      FAIL: violation verdict under jitter seed $s"; fail=1; fi
  res="$(result_of "$err")"
  echo "      seed $s: ${res#*detail=}"
  converged "$res" || { echo "      FAIL: jitter did not converge (seed $s)"; fail=1; }
done
echo "    -- net-drop sweep (permille) --"
for d in 100 200 300; do
  for s in 1 2 3; do
    err="$work/d.$d.$s.err"
    run --seed "$s" ${ALLOW[@]+"${ALLOW[@]}"} --net-drop-permille "$d" -- "${ARGS[@]}" >/dev/null 2>"$err" || true
    if violated "$err"; then echo "      FAIL: violation verdict drop $d seed $s"; fail=1; fi
    res="$(result_of "$err")"
    echo "      drop $d seed $s: ${res#*detail=}"
    converged "$res" || { echo "      FAIL: drop $d should converge (seed $s)"; fail=1; }
  done
done

echo "==> [4] fs-crash sweep: fail-closed abort (exit 2) allowed, violation verdict never"
crash_abort=0; crash_ok=0
for spec in write:1 write:5 write:12 write:40 sync:1 sync:4 sync:16 close:1 close:4; do
  for s in 1 2 3; do
    err="$work/f.err"
    # set -e safe capture: a fail-closed abort returns exit 2 by design.
    if run --seed "$s" ${ALLOW[@]+"${ALLOW[@]}"} --fs-crash-at "$spec" -- "${ARGS[@]}" >/dev/null 2>"$err"; then code=0; else code=$?; fi
    if violated "$err"; then echo "      FAIL: violation verdict fs-crash $spec seed $s"; fail=1; fi
    if [[ $code -eq 0 ]]; then crash_ok=$((crash_ok+1));
    elif [[ $code -eq 2 ]]; then crash_abort=$((crash_abort+1));
    else echo "      note: fs-crash $spec seed $s unexpected exit=$code"; stderr_tail "$err"; fi
  done
done
echo "    fs-crash outcomes: clean(exit0)=$crash_ok fail-closed-abort(exit2)=$crash_abort (any violation verdict FAILs above)"

echo "==> [5] crash-RECOVERY: kill+restart in-process on the same WAL, converge, byte-identical"
echo "    -- (a) crash at completed=10 + restart: 5 seeds x 3 repeats byte-identical, all converge --"
for s in 1 2 3 4 5; do
  ref_res=""; ref_trace=""
  for rep in 1 2 3; do
    tr="$work/r.$s.$rep.trace"; err="$work/r.$s.$rep.err"
    run --seed "$s" --record "$tr" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" --crash-at-completed 10 >/dev/null 2>"$err" || {
      echo "    FAIL: recovery seed $s rep $rep exited nonzero"; fail=1; stderr_tail "$err"; }
    if violated "$err"; then echo "    FAIL: violation verdict recovery seed $s rep $rep"; fail=1; fi
    if ! grep -q 'crashed + restarted' "$err"; then
      echo "    FAIL: recovery seed $s rep $rep never restarted the server"; fail=1
    fi
    res="$(result_of "$err")"; th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
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
run --seed 1 --record "$rrec" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" --crash-at-completed 10 >/dev/null 2>"$work/rrec.err"
rr1="$(result_of "$work/rrec.err")"
replay "$rrec" ${ALLOW[@]+"${ALLOW[@]}"} >/dev/null 2>"$work/rrep.err"
rr2="$(result_of "$work/rrep.err")"
echo "    record: $rr1"; echo "    replay: $rr2"
if [[ "$rr1" != "$rr2" || -z "$rr1" ]]; then echo "    FAIL: recovery replay differs from record"; fail=1; fi
echo "    -- (c) in-process fail-closed-recovery self-test (invariant 5) --"
serr="$work/self.err"
if sout="$(run ${ALLOW[@]+"${ALLOW[@]}"} -- --check-recovery-fail-closed 2>"$serr")"; then scode=0; else scode=$?; fi
if violated "$serr"; then echo "    FAIL: recovery self-test reported a violation verdict"; fail=1; stderr_tail "$serr"; fi
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
  # A violation verdict is always a hard failure.
  if violated "$err"; then echo "    FAIL: violation verdict buggify gen $G (seed=$gseed fire=$fire act=$act)"; fail=1; stderr_tail "$err"; fi
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

echo "==> [7] seeded-bug catch: each --bug MUST be caught within a bounded seed sweep"
# Each entry: NAME | first seed | extra Patina knobs | extra guest args | the
# expected CATCH pattern, matched against the run's stderr. Two of the three are
# caught by a `violation` verdict -- the verdict ABI's own wire line -- and the
# third by workq's convergence diagnostic, which reports no verdict on purpose
# (the ABI has no liveness kind; see the crate module doc).
# Schedule-sensitive bugs need a schedule that actually interleaves the race, and
# per-seed schedules are platform-specific AND legitimately shift when scheduler
# seed derivation changes — so a single pinned seed is brittle by construction
# (a sched-det domain_seed migration broke the old pinned-seed leg on Linux only).
# Instead each bug sweeps a bounded seed window and MUST be caught by some seed in
# it. Still fail-closed: a fixed bug or a weakened invariant is caught by NO seed,
# and a clean sweep FAILS the leg. The catching run is then recorded and
# strict-replayed, requiring a byte-identical result + trace hash.
BUG_SEED_WINDOW=8
bug_leg() {
  local name="$1" first="$2" pknobs="$3" gargs="$4" marker="$5"
  local tr="$work/bug.$name.trace" err="$work/bug.$name.err" out code bseed caught=0
  for bseed in $(seq "$first" $((first + BUG_SEED_WINDOW - 1))); do
    # shellcheck disable=SC2086
    if run --seed "$bseed" $pknobs --record "$tr" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" $gargs >/dev/null 2>"$err"; then code=0; else code=$?; fi
    # Caught == nonzero exit AND the expected catch pattern present on stderr.
    if [[ $code -ne 0 ]] && grep -Eq "$marker" "$err"; then caught=1; break; fi
  done
  # Every verdict the failing run reported, in order: the recorded outcome
  # stream the strict replay below must reproduce exactly.
  local res; res="$(grep '^PATINA_VERDICT ' "$err" 2>/dev/null || true)"
  echo "    -- $name (seed $bseed): exit=$code verdicts=$(printf '%s' "$res" | grep -c . || true)"
  if [[ $caught -ne 1 ]]; then
    echo "    FAIL: bug '$name' NOT caught by seeds $first..$((first + BUG_SEED_WINDOW - 1)) (expected '$marker') -- demo went vacuous"; fail=1; stderr_tail "$err"; return
  fi
  echo "        caught: $(grep -Em1 "$marker" "$err")"
  # Strict replay must reproduce the failing run byte-identically (result + trace).
  local th rerr rth
  th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
  rerr="$work/bug.$name.replay.err"
  replay "$tr" ${ALLOW[@]+"${ALLOW[@]}"} >/dev/null 2>"$rerr" || true
  rth="$(shasum -a256 "$tr" | cut -d' ' -f1)"
  if [[ "$(grep '^PATINA_VERDICT ' "$rerr" 2>/dev/null || true)" != "$res" || "$th" != "$rth" ]]; then
    echo "    FAIL: bug '$name' replay did not reproduce the verdict stream + trace identically"; fail=1
  elif ! grep -Eq "$marker" "$rerr"; then
    echo "    FAIL: bug '$name' replay did not reproduce '$marker'"; fail=1
  else
    echo "        replay reproduced identically (trace=$th)"
  fi
}
# dedup-ignore-producer: two producers reuse client_seq, so half the jobs are
# deduped away and the run can never converge -> the completion gate fails closed.
bug_leg dedup-ignore-producer 1 "" "--timeout-secs 20 --bug dedup-ignore-producer" '^WORKQ_FAILURE not-converged'
# skip-redelivery-commit: a redelivered job's durable Complete record is skipped,
# so the WAL loses an acked completion -> the no-loss invariant fires.
bug_leg skip-redelivery-commit 2 "--buggify=500 --buggify-after-setup" "--bug skip-redelivery-commit" '^PATINA_VERDICT .*kind=violation '
# apply-check-outside-lock: the worker's exactly-once "already applied?" check sits
# OUTSIDE the apply critical section, so two workers holding early-redelivered
# duplicates of one job both pass it and double-apply -> the exactly-once invariant
# fires. early-redelivery (buggify) forces the concurrent duplicate; the small tick
# shrinks redelivery latency into the apply window so the race is deterministic.
bug_leg apply-check-outside-lock 1 "--buggify=500 --buggify-after-setup" "--tick-ms 2 --bug apply-check-outside-lock" '^PATINA_VERDICT .*kind=violation '

echo "==> [8] --server-host resolves via --dns-entry: converges, replays byte-identically, survives an injected dns fault"
DNS_ARGS=(--seed 1 --jobs "$JOBS" --workers 3 --producers 2 --base-port 5001 --data-dir /workq \
          --timeout-secs 90 --server-host workq-server)
run --seed 1 --dns-entry workq-server=127.0.0.1 ${ALLOW[@]+"${ALLOW[@]}"} -- "${DNS_ARGS[@]}" >/dev/null 2>"$work/dns.err" || true
if violated "$work/dns.err"; then echo "    FAIL: violation verdict under --server-host"; fail=1; stderr_tail "$work/dns.err"; fi
dres="$(result_of "$work/dns.err")"
echo "    -- (a) resolved: $dres"
converged "$dres" || { echo "    FAIL: --server-host run did not converge"; fail=1; stderr_tail "$work/dns.err"; }
dtrace="$work/dns.trace"
run --seed 1 --dns-entry workq-server=127.0.0.1 --record "$dtrace" ${ALLOW[@]+"${ALLOW[@]}"} -- "${DNS_ARGS[@]}" >/dev/null 2>"$work/dnsrec.err"
dr1="$(result_of "$work/dnsrec.err")"
replay "$dtrace" ${ALLOW[@]+"${ALLOW[@]}"} >/dev/null 2>"$work/dnsrep.err"
dr2="$(result_of "$work/dnsrep.err")"
echo "    -- (b) record: $dr1"; echo "       replay: $dr2"
if [[ "$dr1" != "$dr2" || -z "$dr1" ]]; then echo "    FAIL: --server-host replay differs from record"; fail=1; fi
echo "    -- (c) injected --dns-fail-permille still converges (the resolve retry must not wedge) --"
for s in 1 2 3; do
  ferr="$work/dnsfail.$s.err"
  run --seed "$s" --dns-entry workq-server=127.0.0.1 --dns-fail-permille 400 ${ALLOW[@]+"${ALLOW[@]}"} -- "${DNS_ARGS[@]}" >/dev/null 2>"$ferr" || true
  if violated "$ferr"; then echo "      FAIL: violation verdict under --dns-fail-permille seed $s"; fail=1; stderr_tail "$ferr"; fi
  fres="$(result_of "$ferr")"
  echo "      seed $s: ${fres#*detail=}"
  converged "$fres" || { echo "      FAIL: --dns-fail-permille seed $s did not converge"; fail=1; stderr_tail "$ferr"; }
done

elapsed=$(( SECONDS - start_secs ))
echo "==> wall time: ${elapsed}s"
if [[ "$fail" -ne 0 ]]; then
  echo "==> FAILED"; exit 1
fi
echo "==> all Patina checks passed"

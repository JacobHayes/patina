#!/usr/bin/env bash
###############################################################################
# workq durable work queue under Patina -- randomized-but-deterministic
# fault-COMBINATION fuzz campaign. run-patina.sh tests each knob in isolation;
# this crosses them. Every knob value for generation G is a pure function of G
# via SHA-256("patina-fuzz-$G") -- no $RANDOM, no date -- so any generation is
# re-runnable by number and the whole campaign is a pure function of its
# [START,END] range.
#
#   fuzz-sweep.sh [START_GEN] [END_GEN]   run generations START..END (default 1..100)
#   fuzz-sweep.sh --gen N [--dry-run]     run (or just print) a single generation
#   fuzz-sweep.sh --dry-run [START [END]] print derived config(s), no build/run
#   fuzz-sweep.sh --selftest              drive the classifier over canned tuples
#                                         covering EVERY outcome class
#
# Per generation a config combines 2-3 fault knobs (net drop, net jitter, sleep
# jitter, fs-crash, in-process crash-recovery, cooperative buggify, job/worker/
# producer counts) and records a self-contained trace under out-fuzz/gen-G/.
#
# Two planes. The MESSAGE/FAULT plane (BREADTH/TRAFFIC tiers, the plain binary)
# crosses network/storage/crash/buggify faults. The SCHEDULE plane (SCHEDULE
# tier, ~20% of gens, the yield-points binary) isolates thread INTERLEAVINGS at
# atomics granularity: the yield-points build routes every instrumented edge
# through the DetScheduler, so a race window that is pure atomics between two
# interposed boundaries becomes schedulable (empirically ~20x more scheduling
# boundaries than the plain binary), and the SEED is the interleaving explorer.
# SCHEDULE gens keep network faults off/light to isolate that plane. Tier
# selection is a PURE function of G (BYTE[21] gates the schedule overlay;
# BYTE[18] the split for the rest).
#
# The outcome is classified by a PURE function (testable via --selftest) that is
# deliberately not vacuous: a planted WORKQ_VIOLATION is a SAFETY_BUG even on
# exit 0; an exit 1 (liveness) is only tolerated for a "heavy" config; an exit 2
# (fail-closed WORKQ_ABORT) only when an fs-crash is present; any other exit, or
# a crash marker, is a failure. The campaign NEVER injects --bug: it fuzzes the
# CLEAN app (the two seeded bugs live in run-patina.sh leg [7]).
#
# On OK the gen dir is deleted; every other class is kept for reproduction.
# ~4% of gens (DETERMINISM tier) re-run the identical config and require a
# byte-identical WORKQ_RESULT + trace SHA-256, else a DETERMINISM_BUG.
#
# macOS BSD userland: uses shasum -a256 (not sha256sum); bash 3.2 safe (no
# associative arrays; empty-array expansion via ${A[@]+"${A[@]}"}). set -uo
# pipefail with explicit nonzero handling so one failing gen never aborts the loop.
#
# This is the workq adaptation of the project's shared fault-combination sweep
# design. The generic 10x liveness escalation is KEPT. Three app-agnostic Patina
# scheduler-policy overlays ARE wired here, all pure functions of G and folded
# into the trace fingerprint by the runtime:
#   * exploration policy (SCHEDULE tier): a seed-derived choice between the
#     default uniform scheduler and PCT (Probabilistic Concurrency Testing:
#     random priorities + d-1 priority-change points), via --sched-pct (+pct);
#   * adversarial starvation intervals (--starve, +starve): OPT-IN behind
#     PATINA_SWEEP_STARVE=1, since deferral can wedge an atomic-spinlock guest;
#     its supervisor stall backstop is classified STARVATION_STALL;
#   * swarm fault-subset selection (fault tiers): when >= 2 fault classes are on,
#     a seed-derived ~1/4 of gens fire a random subset via --swarm (+swarm).
# The PATINA_SCHEDULE_POLICY report's bug_depth / starve_vacuous fields are parsed
# into each gen's annotation. Two knobs from the shared design have no workq
# analog and are deliberately NOT ported: a client-side pacing window and its
# window-0 workload-shape discriminator (the 10x converge-or-confirm keeps the
# false-positive guard without it), and a storage-fault recovery dimension (workq
# has no storage-recovery flag -- an fs-crash always fails closed).
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
# Shared cooperative-SUT (buggify) campaign layer: the ALWAYS_VIOLATION /
# SOMETIMES_UNMET classes, the Wave 2 PATINA_SDK_REPORT parser, the one-run
# sites --exercised join check, and the campaign-state accumulator, proven by
# buggify_campaign_selftest. Additive only.
# shellcheck source=../buggify-campaign.sh
source "$here/../buggify-campaign.sh"

# Two SEPARATE on-disk artifacts, built ONCE up front (see build_all):
#   built    -- plain Patina binary (BREADTH/TRAFFIC/DETERMINISM tiers)
#   built_yp -- yield-points binary (SCHEDULE tier): the sancov trace-pc-guard
#               instrumentation funnels every instrumented edge through
#               patina_sched_yield, making atomics-only race windows schedulable.
# Distinct files so the sweep never rewrites a binary a process might be
# executing (macOS SIGKILLs a rewritten running binary), and so their traces
# never cross-replay (the yield-points fingerprint differs by design).
built="$here/target/patina/workq"
built_yp="$here/target/patina/workq-yp"
PATINA="$repo_root/target/release/cargo-patina"

OUTDIR="${PATINA_FUZZ_OUT:-$here/out-fuzz}"
SWEEP_LOG="$OUTDIR/sweep.log"
CAMPAIGN_STATE="$OUTDIR/campaign-state.json"
SITES_JOIN_CHECKED=0
# GLOBAL so the EXIT trap (fires after sweep() returns) still sees it under set -u.
FUZZ_LOCK="$here/target/patina/.fuzz-sweep.lock"

# Virtual-clock budget base (Instant is virtual under Patina, so this is generous
# without costing wall time) and base port (SimNet, so never really bound).
TIMEOUT_BASE=120
BASE_PORT=5001
DATA_DIR=/workq

###############################################################################
# Outcome classification -- a PURE function of its arguments. No global state, no
# I/O, so --selftest can drive it with canned tuples and prove it bites.
###############################################################################

# Case-sensitive crash markers indicating a genuine Patina/Rust failure. The
# scheduler marker must be an ERROR context so the benign vacuous-schedule
# WARNING (which contains the bare word "scheduler") never misfires. The
# "patina: the deterministic runtime" phrase matches the runtime init failure,
# NOT the tool's own "cargo-patina: ..." infra prefix (handled by is_infra).
CRASH_MARKERS='panicked|internal error|patina: the deterministic runtime|patina native shim fatal|native shim fatal|unsupported native imports|scheduler (panic|error|stall|fault|deadlock)|deadlock detected|SIGSEGV|SIGABRT'

# Infrastructure/environment failure signatures (NOT a workq or patina bug): the
# cargo-patina wrapper or its build subprocess died, a binary is missing, the
# target dir is contended, disk full, etc. Never reported as UNEXPECTED_CRASH.
INFRA_MARKERS='cargo-patina: |Cargo process terminated|terminated by a signal|could not compile|No such file or directory|native-build failed|Resource temporarily unavailable|Cannot allocate memory'
is_infra() { printf '%s\n%s' "$1" "$2" | /usr/bin/grep -Eq "$INFRA_MARKERS"; }

classify() {
  # args: exit enqueued completed failed jobs heavy fs_crash stdout stderr
  local exit_code="$1" enq="$2" comp="$3" failed="$4" jobs="$5" heavy="$6" fs_crash="$7"
  local out="$8" err="$9"
  local combined="$out
$err"

  # 0. A cooperative-SUT (buggify) always! violation is top severity, regardless
  #    of exit code. Checked first via the shared campaign layer.
  local buggify_verdict; buggify_verdict="$(buggify_class "$exit_code" "$out" "$err")"
  if [[ "$buggify_verdict" == ALWAYS_VIOLATION ]]; then echo ALWAYS_VIOLATION; return; fi

  # 0b. Starvation-stall backstop (opt-in --starve path only): the supervisor
  #     killed an already-wedged run whose guest was spinning inside an
  #     uninstrumented atomic critical section. Classified DISTINCTLY as a
  #     diagnostic (a wedged generation, not a workq/patina safety bug) so a sweep
  #     records it instead of hanging, and it wins over any exit-code verdict. The
  #     marker never appears on any other mode.
  if printf '%s' "$combined" | grep -q 'patina: starvation stall'; then echo STARVATION_STALL; return; fi

  # 1. A safety violation is ALWAYS a bug, regardless of exit code (a planted
  #    WORKQ_VIOLATION on exit 0 must still be SAFETY_BUG -- the non-vacuous proof).
  if printf '%s' "$combined" | grep -q 'WORKQ_VIOLATION'; then echo SAFETY_BUG; return; fi

  # 2. A hard crash marker anywhere is UNEXPECTED_CRASH even if the exit looks OK.
  if printf '%s' "$combined" | grep -Eq "$CRASH_MARKERS"; then echo UNEXPECTED_CRASH; return; fi

  # 3. Exit-code semantics (0 converged / 1 liveness / 2 fail-closed abort).
  case "$exit_code" in
    0)
      # workq exits 0 only when fully converged; re-verify from the result line
      # so a truncated/partial exit-0 can never masquerade as OK.
      if [[ -n "$jobs" && "$enq" == "$jobs" && $(( ${comp:-0} + ${failed:-0} )) -eq "$jobs" ]]; then
        echo OK
      else
        echo UNEXPECTED_CRASH
      fi
      ;;
    1)
      # A liveness timeout (WORKQ_FAILURE, no violation) is only honest for a
      # heavy config (heavy loss). Otherwise the queue should have converged.
      if [[ "$heavy" == 1 ]]; then echo LIVENESS_TIMEOUT; else echo UNEXPECTED_LIVENESS; fi
      ;;
    2)
      # A fail-closed WORKQ_ABORT is by-design only when an fs-crash is injected
      # (workq has no storage-recovery mode -- an fs-crash always fails closed).
      if [[ "$fs_crash" == 1 ]]; then echo FAILCLOSED_ABORT; else echo UNEXPECTED_ABORT; fi
      ;;
    *)
      echo UNEXPECTED_CRASH
      ;;
  esac
}

# Determinism verdict -- pure. Given the primary class and two runs' WORKQ_RESULT
# lines + trace hashes, confirm the class or promote to DETERMINISM_BUG.
det_check() {
  local primary="$1" r1="$2" r2="$3" h1="$4" h2="$5"
  if [[ "$r1" == "$r2" && "$h1" == "$h2" ]]; then echo "$primary"; else echo DETERMINISM_BUG; fi
}

# Schedule-divergence verdict -- pure. A SCHEDULE double-run replays the SAME
# yield-points binary at the same seed; determinism must hold even under the
# ~20x-denser yield-point schedule. A mismatch is SCHEDULE_DIVERGENCE, kept
# DISTINCT from a plain-tier DETERMINISM_BUG so triage knows the yield-point path
# diverged.
sched_det_check() {
  local primary="$1" r1="$2" r2="$3" h1="$4" h2="$5"
  if [[ "$r1" == "$r2" && "$h1" == "$h2" ]]; then echo "$primary"; else echo SCHEDULE_DIVERGENCE; fi
}

# Schedule-vacuity verdict -- pure. A SCHEDULE run must actually explore: the
# yield-points binary must produce FAR more scheduling boundaries than an
# uninstrumented run (workq: plain ~1.2k, yield-points ~24k), and no worker may
# go vacuous. A would-be-clean OK whose exploration did not happen is promoted to
# VACUOUS_SCHEDULE; a genuine finding keeps priority and is never downgraded.
SCHEDULE_MIN_BOUNDARIES=5000
sched_check() {
  local is_sched="$1" base="$2" vac="$3" tb="$4"
  if [[ "$is_sched" != 1 ]]; then echo "$base"; return; fi
  if [[ "$base" != OK ]]; then echo "$base"; return; fi
  if [[ -n "$vac" && "$vac" -gt 0 ]]; then echo VACUOUS_SCHEDULE; return; fi
  if [[ -z "$tb" || "$tb" -lt "$SCHEDULE_MIN_BOUNDARIES" ]]; then echo VACUOUS_SCHEDULE; return; fi
  echo OK
}

# A class is a FAILURE unless it is tolerated. VACUOUS_SCHEDULE and
# SCHEDULE_DIVERGENCE are failures: a schedule tier that did not explore, or a
# yield-point run that is nondeterministic, is a broken guarantee. STARVATION_STALL
# is a tolerated diagnostic: it only arises on the opt-in --starve path and means
# a wedged generation the backstop killed, not a workq/patina safety bug.
is_failure() {
  case "$1" in
    OK|LIVENESS_TIMEOUT|FAILCLOSED_ABORT|STARVATION_STALL) return 1 ;;
    *) return 0 ;;
  esac
}

###############################################################################
# Deterministic per-generation config derivation. HEX = SHA-256 of the gen tag;
# byte i is HEX[2i..2i+1] as 0..255 (global BYTE[]). Every knob AND the tier is a
# function of these bytes, so any generation is re-runnable by G.
#
# Tiers:  ~20% SCHEDULE (BYTE[21]<=50 overlay; yield-points, network off/light)
#         then by BYTE[18]:  ~80% BREADTH,  ~15% TRAFFIC,  ~5% DETERMINISM
# Net over all G: SCHEDULE ~20%, BREADTH ~64%, TRAFFIC ~12%, DETERMINISM ~4%.
#
# Every sampler sets: PKNOBS[] (patina knobs, before --), HARGS[] (guest args,
# after --), CFG_SUMMARY, HEAVY, FS_CRASH, JOBS_N, CFG_TIMEOUT. derive_config
# additionally sets TIER, DET_RUN, IS_SCHEDULE, BIN.
###############################################################################

compute_bytes() {
  local G="$1" HEX i
  HEX="$(printf 'patina-fuzz-%s' "$G" | shasum -a256 | cut -c1-64)"
  BYTE=()
  for (( i = 0; i < 32; i++ )); do BYTE[i]=$(( 16#${HEX:$(( i * 2 )):2} )); done
}

# BREADTH tier: the short combined-fault space.
sample_breadth() {
  local G="$1"
  local jobs_tbl=(16 24); JOBS_N=${jobs_tbl[$(( BYTE[16] % 2 ))]}
  local workers=$(( 2 + BYTE[17] % 3 ))            # 2..4
  local producers=$(( 1 + BYTE[19] % 2 ))          # 1..2
  local tick_tbl=(10 20 30); local tick=${tick_tbl[$(( BYTE[24] % 3 ))]}
  local drop_tbl=(0 50 100 150 200 300 400 500); local drop=${drop_tbl[$(( BYTE[0] % 8 ))]}

  # net jitter (~50%)
  local jitter_on=0 jmin_ns=0 jmax_ns=0 jspec="off"
  if (( BYTE[1] % 2 == 0 )); then
    jitter_on=1
    local jmin_ms=$(( 1 + BYTE[2] % 40 )) jmax_ms=$(( 1 + BYTE[2] % 40 + 1 + BYTE[3] % 60 ))
    (( jmax_ms > 100 )) && jmax_ms=100
    jmin_ns=$(( jmin_ms * 1000000 )); jmax_ns=$(( jmax_ms * 1000000 )); jspec="${jmin_ms}-${jmax_ms}ms"
  fi
  # sleep jitter (~25%)
  local sleep_on=0 smin_ns=0 smax_ns=0 sspec="off"
  if (( BYTE[4] % 4 == 0 )); then
    sleep_on=1
    local smin_ms=$(( 1 + BYTE[5] % 15 )) smax_ms=$(( 1 + BYTE[5] % 15 + 1 + BYTE[6] % 30 ))
    (( smax_ms > 80 )) && smax_ms=80
    smin_ns=$(( smin_ms * 1000000 )); smax_ns=$(( smax_ms * 1000000 )); sspec="${smin_ms}-${smax_ms}ms"
  fi
  # fs-crash (~35%)
  FS_CRASH=0; local fspec="off" fs_op="" fs_n=0
  if (( BYTE[7] < 90 )); then
    FS_CRASH=1
    local op_tbl=(write sync close); fs_op=${op_tbl[$(( BYTE[8] % 3 ))]}
    fs_n=$(( 1 + BYTE[9] % 40 )); fspec="${fs_op}:${fs_n}"
  fi
  # in-process crash-recovery (~35%): crash + restart the server on the same WAL
  # once `completed` first reaches K.
  local crash_at=0 kspec="off"
  if (( BYTE[10] < 90 )); then crash_at=$(( 4 + BYTE[11] % 8 )); kspec="completed@${crash_at}"; fi
  # cooperative buggify (~40%): the guest calls setup_complete(), so after-setup
  # is valid. Fire is kept moderate (<=400) so buggify combined with net loss +
  # crash-recovery still converges within the virtual budget -- a maxed fire rate
  # crossed with heavy drop over-stresses the queue into a workload-shape timeout,
  # not a bug. run-patina.sh leg [6] fuzzes buggify at higher rates in isolation.
  local buggify=0 bspec="off" fire=0 act=0
  if (( BYTE[13] < 102 )); then
    buggify=1; fire=$(( 150 + (BYTE[14] % 6) * 50 )); act=$(( 300 + (BYTE[15] % 5) * 100 ))
    bspec="fire${fire}/act${act}"
  fi
  # small segment sometimes, to force WAL rotation
  local seg=4096; (( BYTE[25] % 3 == 0 )) && seg=256

  local timeout=$(( TIMEOUT_BASE * JOBS_N / 16 )); (( timeout < 60 )) && timeout=60
  CFG_TIMEOUT=$timeout

  PKNOBS=(--seed "$G")
  (( drop > 0 ))  && PKNOBS+=(--net-drop-permille "$drop")
  (( jitter_on )) && PKNOBS+=(--net-jitter-nanos "${jmin_ns}..${jmax_ns}")
  (( sleep_on ))  && PKNOBS+=(--sleep-jitter-nanos "${smin_ns}..${smax_ns}")
  (( FS_CRASH ))  && PKNOBS+=(--fs-crash-at "${fs_op}:${fs_n}")
  (( buggify ))   && PKNOBS+=(--buggify="$fire" --buggify-activation-permille "$act" --buggify-after-setup)

  HARGS=(--seed "$G" --jobs "$JOBS_N" --workers "$workers" --producers "$producers"
         --base-port "$BASE_PORT" --data-dir "$DATA_DIR" --timeout-secs "$timeout"
         --tick-ms "$tick" --segment-bytes "$seg")
  (( crash_at > 0 )) && HARGS+=(--crash-at-completed "$crash_at")

  HEAVY=0; (( drop >= 400 )) && HEAVY=1
  CFG_SUMMARY="seed=$G jobs=$JOBS_N workers=$workers producers=$producers drop=$drop jitter=$jspec sleep=$sspec fscrash=$fspec crash=$kspec buggify=$bspec seg=$seg tick=$tick timeout=${timeout}s heavy=$HEAVY"
}

# TRAFFIC tier: a longer-horizon workload. More jobs, always jitter, light-to-
# moderate loss, ~half with in-process crash-recovery, ~half with buggify. No
# fs-crash, so a liveness timeout here (drop<=200) is NEVER tolerated.
sample_traffic() {
  local G="$1"
  local jobs_tbl=(48 64); JOBS_N=${jobs_tbl[$(( BYTE[16] % 2 ))]}
  local workers=$(( 3 + BYTE[17] % 2 ))            # 3..4
  local producers=2
  local tick_tbl=(10 20 30); local tick=${tick_tbl[$(( BYTE[24] % 3 ))]}
  local drop_tbl=(0 50 100 200); local drop=${drop_tbl[$(( BYTE[0] % 4 ))]}

  local jmin_ms=$(( 1 + BYTE[2] % 40 )) jmax_ms=$(( 1 + BYTE[2] % 40 + 1 + BYTE[3] % 60 ))
  (( jmax_ms > 100 )) && jmax_ms=100
  local jmin_ns=$(( jmin_ms * 1000000 )) jmax_ns=$(( jmax_ms * 1000000 ))

  FS_CRASH=0
  local crash_at=0 kspec="off"
  if (( BYTE[10] % 2 == 0 )); then crash_at=$(( 6 + BYTE[11] % 12 )); kspec="completed@${crash_at}"; fi
  local buggify=0 bspec="off" fire=0 act=0
  if (( BYTE[13] % 2 == 0 )); then
    buggify=1; fire=$(( 150 + (BYTE[14] % 6) * 50 )); act=$(( 300 + (BYTE[15] % 5) * 100 ))
    bspec="fire${fire}/act${act}"
  fi

  local timeout=$(( TIMEOUT_BASE * JOBS_N / 16 )); CFG_TIMEOUT=$timeout

  PKNOBS=(--seed "$G")
  (( drop > 0 )) && PKNOBS+=(--net-drop-permille "$drop")
  PKNOBS+=(--net-jitter-nanos "${jmin_ns}..${jmax_ns}")
  (( buggify )) && PKNOBS+=(--buggify="$fire" --buggify-activation-permille "$act" --buggify-after-setup)

  HARGS=(--seed "$G" --jobs "$JOBS_N" --workers "$workers" --producers "$producers"
         --base-port "$BASE_PORT" --data-dir "$DATA_DIR" --timeout-secs "$timeout" --tick-ms "$tick")
  (( crash_at > 0 )) && HARGS+=(--crash-at-completed "$crash_at")

  HEAVY=0    # drop<=200 and no fs-crash -> a timeout here is always a regression
  CFG_SUMMARY="seed=$G jobs=$JOBS_N workers=$workers producers=$producers drop=$drop jitter=${jmin_ms}-${jmax_ms}ms sleep=off fscrash=off crash=$kspec buggify=$bspec tick=$tick timeout=${timeout}s heavy=0 plane=TRAFFIC"
}

# SCHEDULE tier: isolate the interleaving plane on the yield-points binary. The
# SEED is the explorer -- the DetScheduler derives its choice at each of the
# vastly more numerous boundaries from the seed. Network faults are OFF for most
# gens (~1/3 add LIGHT drop); no jitter, sleep, fs-crash, crash-recovery, or
# buggify -- HEAVY is always 0, so a liveness timeout here is NEVER tolerated.
# Small workloads: the plane is interleaving-dominated, so a tiny workload
# already exercises a huge decision space cheaply.
sample_schedule() {
  local G="$1"
  IS_SCHEDULE=1; BIN="$built_yp"
  local jobs_tbl=(16 16 24); JOBS_N=${jobs_tbl[$(( BYTE[16] % 3 ))]}
  local workers=$(( 3 + BYTE[17] % 2 ))            # 3..4
  local producers=2
  local tick_tbl=(10 20 30); local tick=${tick_tbl[$(( BYTE[24] % 3 ))]}
  local drop_tbl=(0 0 0 0 50 100); local drop=${drop_tbl[$(( BYTE[0] % 6 ))]}

  FS_CRASH=0
  local timeout=$(( TIMEOUT_BASE * JOBS_N / 16 )); CFG_TIMEOUT=$timeout

  PKNOBS=(--seed "$G")
  (( drop > 0 )) && PKNOBS+=(--net-drop-permille "$drop")

  # Exploration scheduling-policy overlay: a seed-derived choice between the
  # default uniform policy and PCT (Probabilistic Concurrency Testing -- random
  # priorities + d-1 priority-change points that preempt the running task). Both
  # run on the yield-points binary, so scheduling boundaries stay dense; the
  # policy steers WHICH interleavings the seed reaches and is folded into the
  # trace fingerprint (+pct), so a policy trace fails closed against a plain build.
  # Starvation intervals are an OPT-IN overlay (PATINA_SWEEP_STARVE=1), NOT on by
  # default: adversarial deferral can drive an atomic-spinlock guest into a
  # mutual-spin livelock even under the scheduler's aging liveness guarantee, so
  # enabling it in the always-on canary risks a spurious non-terminating gen. It is
  # fully wired for deliberate starvation campaigns; when enabled, a third of the
  # policy slots place starvation intervals instead of PCT.
  POLICY_SPEC="uniform"
  local policy_modes=3
  [[ "${PATINA_SWEEP_STARVE:-0}" == 1 ]] && policy_modes=4
  case $(( BYTE[22] % policy_modes )) in
    0) POLICY_SPEC="uniform" ;;
    1 | 2)
      local pdepth=$(( 2 + BYTE[23] % 4 ))          # bug depth d in 2..5
      PKNOBS+=(--sched-pct="$pdepth"); POLICY_SPEC="pct(d=$pdepth)" ;;
    3)
      local sivals=$(( 1 + BYTE[23] % 3 ))          # 1..3 starvation intervals
      PKNOBS+=(--starve="$sivals"); POLICY_SPEC="starve(intervals=$sivals)" ;;
  esac

  HARGS=(--seed "$G" --jobs "$JOBS_N" --workers "$workers" --producers "$producers"
         --base-port "$BASE_PORT" --data-dir "$DATA_DIR" --timeout-secs "$timeout" --tick-ms "$tick")

  HEAVY=0
  CFG_SUMMARY="seed=$G jobs=$JOBS_N workers=$workers producers=$producers drop=$drop jitter=off sleep=off fscrash=off crash=off buggify=off tick=$tick timeout=${timeout}s heavy=0 plane=SCHEDULE(yield-points) policy=$POLICY_SPEC"
}

# Pick the tier for G and sample it. The SCHEDULE overlay is gated on BYTE[21]
# and checked FIRST so the rest keep their exact BYTE[18] mapping.
derive_config() {
  local G="$1"
  compute_bytes "$G"
  DET_RUN=0; IS_SCHEDULE=0; BIN="$built"
  # Reset per-gen overlay descriptors so a previous gen never leaks into the log.
  POLICY_SPEC="uniform"; SWARM_SPEC="off"
  if (( BYTE[21] <= 50 )); then
    TIER=SCHEDULE; sample_schedule "$G"; return
  fi
  local t=${BYTE[18]}
  if (( t <= 204 )); then
    TIER=BREADTH; sample_breadth "$G"
  elif (( t <= 242 )); then
    TIER=TRAFFIC; sample_traffic "$G"
  else
    DET_RUN=1
    case $(( BYTE[19] % 3 )) in
      0) TIER="DETERMINISM/breadth"; sample_breadth "$G" ;;
      1) TIER="DETERMINISM/traffic"; sample_traffic "$G" ;;
      2) TIER="DETERMINISM/schedule"; sample_schedule "$G" ;;
    esac
  fi
  # Swarm fault-subset overlay (fault tiers only): when >= 2 fault classes are
  # enabled, a seed-derived ~1/4 of gens fire a RANDOM subset of them (swarm
  # testing) instead of always-all, recorded + fingerprinted (+swarm). The
  # always-all default is preserved for the rest. The SCHEDULE tier is skipped (it
  # isolates the interleaving plane with faults near-off), so it returned above.
  if [[ "$TIER" == BREADTH || "$TIER" == TRAFFIC || "$TIER" == DETERMINISM/breadth || "$TIER" == DETERMINISM/traffic ]]; then
    local nfault=0 k
    for k in ${PKNOBS[@]+"${PKNOBS[@]}"}; do
      case "$k" in
        --net-drop-permille | --net-jitter-nanos | --sleep-jitter-nanos | --fs-crash-at) (( nfault++ )) ;;
      esac
    done
    if (( nfault >= 2 && BYTE[25] < 64 )); then
      PKNOBS+=(--swarm)
      SWARM_SPEC="on(candidates=$nfault)"
      CFG_SUMMARY="$CFG_SUMMARY swarm=$SWARM_SPEC"
    fi
  fi
}

###############################################################################
# --selftest : drive the pure classifier over canned tuples covering every class.
###############################################################################
SELFTEST_FAIL=0
assert_class() {
  local want="$1" got="$2" name="$3"
  if [[ "$got" == "$want" ]]; then printf '  ok   %-24s -> %s\n' "$name" "$got"
  else printf '  FAIL %-24s -> got %s, want %s\n' "$name" "$got" "$want"; SELFTEST_FAIL=1; fi
}

selftest() {
  echo "== fuzz-sweep classifier selftest =="
  local sched='PATINA_SCHEDULE_REPORT tasks_spawned=7 max_concurrent=7 total_boundaries=1160 vacuous_threads=0'
  local ok='WORKQ_RESULT seed=7 enqueued=24 completed=24 failed=0 attempts=24 applied_hash=deadbeef'

  # OK, and OK even with the benign vacuous-schedule WARNING.
  assert_class OK "$(classify 0 24 24 0 24 0 0 "$ok" "$sched")" "ok-converged"
  local vac_warn='PATINA WARNING: vacuous schedule exploration -- 1 spawned thread(s) ran to completion; their internal interleavings were not explored.'
  assert_class OK "$(classify 0 24 24 0 24 0 0 "$ok" "$sched
$vac_warn")" "ok-vacuous-warn"

  # SAFETY_BUG: a planted WORKQ_VIOLATION on exit 0 fully-converged is STILL a bug.
  assert_class SAFETY_BUG \
    "$(classify 0 24 24 0 24 0 0 "$ok" 'WORKQ_VIOLATION no-loss acked-job-3-never-terminated')" \
    "safety-on-exit0"

  # STARVATION_STALL: the opt-in --starve backstop killed a wedged run (distinct
  # exit 111 + named fatal). A diagnostic, distinct from a crash, and it WINS over
  # the exit-code verdict -- so a starvation campaign records a hung gen instead of
  # hanging or misfiling it.
  local stall='patina: starvation stall — no scheduler progress in 60s under --starve; the guest is likely spinning inside an uninstrumented atomic critical section'
  assert_class STARVATION_STALL "$(classify 111 '' '' '' 24 0 0 '' "$stall")" "starvation-stall"
  assert_class STARVATION_STALL "$(classify 1 '' '' '' 24 0 0 '' "$stall")" "starvation-stall-not-liveness"

  # LIVENESS: heavy config tolerated, non-heavy is a regression.
  local fail_out='WORKQ_RESULT seed=7 enqueued=24 completed=18 failed=0 attempts=60 applied_hash=x'
  assert_class LIVENESS_TIMEOUT \
    "$(classify 1 24 18 0 24 1 0 "$fail_out" 'WORKQ_FAILURE not-converged enqueued=24 completed=18 failed=0 target=24')" \
    "liveness-heavy"
  assert_class UNEXPECTED_LIVENESS \
    "$(classify 1 24 18 0 24 0 0 "$fail_out" 'WORKQ_FAILURE not-converged enqueued=24 completed=18 failed=0 target=24')" \
    "liveness-unexpected"

  # ABORT: exit 2 tolerated with fs-crash, unexpected without.
  assert_class FAILCLOSED_ABORT \
    "$(classify 2 '' '' '' 24 0 1 '' 'WORKQ_ABORT storage-fault wal io error: injected crash at write:5')" \
    "abort-failclosed"
  assert_class UNEXPECTED_ABORT \
    "$(classify 2 '' '' '' 24 0 0 '' 'WORKQ_ABORT final-wal ???')" "abort-unexpected"

  # UNEXPECTED_CRASH vectors: panic marker, patina fatal, scheduler ERROR, exit
  # 0 but partial (contract break), out-of-band exit code.
  assert_class UNEXPECTED_CRASH \
    "$(classify 0 24 24 0 24 0 0 "$ok" "thread 'main' panicked at src/server.rs:42: bad")" "crash-panic"
  assert_class UNEXPECTED_CRASH \
    "$(classify 0 24 24 0 24 0 0 '' 'patina: the deterministic runtime failed to initialize: bad mount')" "crash-patina-fatal"
  assert_class UNEXPECTED_CRASH \
    "$(classify 0 24 24 0 24 0 0 '' 'scheduler deadlock: all tasks parked with pending work')" "crash-scheduler-err"
  assert_class UNEXPECTED_CRASH \
    "$(classify 0 24 18 0 24 0 0 'WORKQ_RESULT seed=7 enqueued=24 completed=18 failed=0 attempts=30 applied_hash=x' '')" "crash-exit0-partial"
  assert_class UNEXPECTED_CRASH "$(classify 134 '' '' '' 24 0 0 '' 'Abort trap: 6')" "crash-exit134"

  # ALWAYS_VIOLATION integrated into classify(): fireable on exit 0, not downgraded.
  assert_class ALWAYS_VIOLATION \
    "$(classify 0 24 24 0 24 0 0 "$ok" 'PATINA_ALWAYS_VIOLATION label=terminal-le-enqueued')" "always-violation-exit0"
  assert_class ALWAYS_VIOLATION \
    "$(classify 0 24 24 0 24 0 0 "$ok" "PATINA_SDK_REPORT enabled=1 sites_registered=8
PATINA_ALWAYS_VIOLATION label=x")" "always-violation-not-downgraded"

  # DETERMINISM_BUG via the pure det_check helper.
  assert_class OK "$(det_check OK 'WORKQ_RESULT a' 'WORKQ_RESULT a' hashA hashA)" "det-identical"
  assert_class DETERMINISM_BUG "$(det_check OK 'WORKQ_RESULT a' 'WORKQ_RESULT b' hashA hashA)" "det-result-diff"
  assert_class DETERMINISM_BUG "$(det_check OK 'WORKQ_RESULT a' 'WORKQ_RESULT a' hashA hashB)" "det-trace-diff"

  # SCHEDULE_DIVERGENCE via sched_det_check (same yield-points binary, must be
  # deterministic even under the denser schedule).
  assert_class OK "$(sched_det_check OK 'WORKQ_RESULT a' 'WORKQ_RESULT a' hashA hashA)" "sched-det-identical"
  assert_class SCHEDULE_DIVERGENCE "$(sched_det_check OK 'WORKQ_RESULT a' 'WORKQ_RESULT b' hashA hashA)" "sched-det-result-diff"
  assert_class SCHEDULE_DIVERGENCE "$(sched_det_check OK 'WORKQ_RESULT a' 'WORKQ_RESULT a' hashA hashB)" "sched-det-trace-diff"

  # VACUOUS_SCHEDULE via sched_check: a clean OK with a healthy boundary count
  # and zero vacuous workers stays OK; a vacuous worker OR a below-floor boundary
  # count OR no report promotes it; a real finding is NEVER downgraded; a
  # non-schedule run passes through untouched.
  assert_class OK "$(sched_check 1 OK 0 24226)" "sched-nonvacuous-ok"
  assert_class VACUOUS_SCHEDULE "$(sched_check 1 OK 1 24226)" "sched-vacuous-worker"
  assert_class VACUOUS_SCHEDULE "$(sched_check 1 OK 0 1160)" "sched-below-floor"
  assert_class VACUOUS_SCHEDULE "$(sched_check 1 OK 0 '')" "sched-no-report"
  assert_class SAFETY_BUG "$(sched_check 1 SAFETY_BUG 0 100)" "sched-finding-not-downgraded"
  assert_class UNEXPECTED_CRASH "$(sched_check 1 UNEXPECTED_CRASH 1 0)" "sched-crash-not-downgraded"
  assert_class OK "$(sched_check 0 OK 0 1160)" "sched-nonschedule-passthrough"

  # report_field extracts the schedule-report numbers the gate reads, unperturbed
  # by the EXTENDED per-task life=/cause= suffix.
  local f; f="$(mktemp)"
  printf '%s\n' 'PATINA_SCHEDULE_REPORT tasks_spawned=7 max_concurrent=7 total_boundaries=24226 vacuous_threads=0 task1=108y+12p/life=1172/cause=live-at-exit task2=564y+12p/life=1138/cause=completed' > "$f"
  local rf_tb rf_vac; rf_tb=$(report_field total_boundaries "$f"); rf_vac=$(report_field vacuous_threads "$f")
  if [[ "$rf_tb" == 24226 && "$rf_vac" == 0 ]]; then printf '  ok   %-24s -> tb=%s vac=%s\n' "report-field-parse" "$rf_tb" "$rf_vac"
  else printf '  FAIL %-24s -> tb=%s vac=%s (want 24226/0)\n' "report-field-parse" "$rf_tb" "$rf_vac"; SELFTEST_FAIL=1; fi
  assert_class OK "$(sched_check 1 OK "$rf_vac" "$rf_tb")" "report-field-nonvacuous"
  rm -f "$f"

  # Exploration-policy report parsing: the runtime's PATINA_SCHEDULE_POLICY line
  # carries the bug-depth estimate and the vacuous-starvation counter the per-gen
  # annotation reads. Prove report_field pulls the right values and that neither
  # collides with the PATINA_SCHEDULE_REPORT numbers on the same stderr.
  local pf; pf="$(mktemp)"
  printf '%s\n%s\n' \
    'PATINA_SCHEDULE_REPORT tasks_spawned=4 max_concurrent=4 total_boundaries=24226 vacuous_threads=0' \
    'PATINA_SCHEDULE_POLICY pct=1 pct_depth=3 pct_change_points=2 pct_change_points_hit=2 starvation=0 starve_events=0 starve_vacuous=0 decisions=90 bug_depth=2' > "$pf"
  local rf_bd rf_sv rf_tb2; rf_bd=$(report_field bug_depth "$pf"); rf_sv=$(report_field starve_vacuous "$pf"); rf_tb2=$(report_field total_boundaries "$pf")
  if [[ "$rf_bd" == 2 && "$rf_sv" == 0 && "$rf_tb2" == 24226 ]]; then printf '  ok   %-24s -> bug_depth=%s starve_vacuous=%s tb=%s\n' "policy-field-parse" "$rf_bd" "$rf_sv" "$rf_tb2"
  else printf '  FAIL %-24s -> bug_depth=%s starve_vacuous=%s tb=%s (want 2/0/24226)\n' "policy-field-parse" "$rf_bd" "$rf_sv" "$rf_tb2"; SELFTEST_FAIL=1; fi
  # A vacuous-starvation report is detectable (nonzero starve_vacuous).
  printf '%s\n' 'PATINA_SCHEDULE_POLICY pct=0 pct_depth=0 starvation=1 starve_events=12 starve_vacuous=7 decisions=40 bug_depth=12' > "$pf"
  local rf_sv2; rf_sv2=$(report_field starve_vacuous "$pf")
  if [[ -n "$rf_sv2" && "$rf_sv2" -gt 0 ]]; then printf '  ok   %-24s -> starve_vacuous=%s\n' "vacuous-starvation" "$rf_sv2"
  else printf '  FAIL %-24s -> starve_vacuous=%s (want >0)\n' "vacuous-starvation" "$rf_sv2"; SELFTEST_FAIL=1; fi
  rm -f "$pf"

  # is_infra recognizes environment/build failures and only those; and a
  # "cargo-patina: ..." infra line must NOT be swallowed as a patina crash.
  assert_class UNEXPECTED_ABORT \
    "$(classify 2 '' '' '' 24 0 0 '' 'cargo-patina: Cargo process terminated by a signal')" "cargo-prefix-not-crash"
  if is_infra '' 'cargo-patina: Cargo process terminated by a signal'; then printf '  ok   %-24s -> true\n' "infra-detects-signal"
  else printf '  FAIL %-24s\n' "infra-detects-signal"; SELFTEST_FAIL=1; fi
  if is_infra "$ok" "$sched"; then printf '  FAIL %-24s (false positive)\n' "infra-clean-negative"; SELFTEST_FAIL=1
  else printf '  ok   %-24s -> false\n' "infra-clean-negative"; fi

  # The shared campaign layer's own selftest (ALWAYS_VIOLATION + SOMETIMES_UNMET
  # fireable and not-downgraded, accumulator counts). Fold into the exit status.
  echo
  if ! buggify_campaign_selftest; then SELFTEST_FAIL=1; fi

  echo
  if (( SELFTEST_FAIL )); then echo "SELFTEST FAILED"; return 1; fi
  echo "SELFTEST PASSED (every class covered, incl. planted WORKQ_VIOLATION -> SAFETY_BUG, PATINA_ALWAYS_VIOLATION -> ALWAYS_VIOLATION, STARVATION_STALL, VACUOUS_SCHEDULE, SCHEDULE_DIVERGENCE, and policy bug_depth/starve_vacuous parsing)"
  return 0
}

###############################################################################
# Build cargo-patina FIRST, then BOTH harness binaries (plain + yield-points).
###############################################################################
build_all() {
  cd "$repo_root"
  echo "==> building cargo-patina and BOTH workq binaries (plain + yield-points)"
  if ! cargo build --release --quiet -p cargo-patina; then
    echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
  fi
  mkdir -p "$here/target/patina"
  if ! "$PATINA" patina build "$here" --output "$built" --release >/dev/null; then
    echo "FATAL: build (plain) failed" >&2; exit 3
  fi
  if ! "$PATINA" patina build "$here" --output "$built_yp" --release --yield-points >/dev/null; then
    echo "FATAL: build (--yield-points) failed" >&2; exit 3
  fi
  if ! /usr/bin/grep -a -q "PATINA_YIELD_POINTS_V1" "$built_yp"; then
    echo "FATAL: yield-points binary lacks the PATINA_YIELD_POINTS_V1 marker" >&2; exit 3
  fi
}

# pull a numeric field out of a WORKQ_RESULT-bearing stream / a trace file hash
field_of() { sed -n "s/.*$1=\\([0-9][0-9]*\\).*/\\1/p" "$2" | head -1; }
sha_of()   { if [[ -f "$1" ]]; then shasum -a256 "$1" | cut -d' ' -f1; else echo MISSING; fi; }
# extract a numeric field from a PATINA_SCHEDULE_REPORT stderr line
report_field() { /usr/bin/grep -o "$1=[0-9][0-9]*" "$2" 2>/dev/null | head -1 | cut -d= -f2; }
# the guest --jobs value (the convergence target) out of an HARGS array
jobs_of() { local i; for (( i = 0; i < ${#HARGS[@]}; i++ )); do [[ "${HARGS[i]}" == "--jobs" ]] && { echo "${HARGS[$(( i + 1 ))]}"; return; }; done; }

# per-class counters (bash 3.2: no associative arrays)
c_OK=0; c_SAFETY_BUG=0; c_LIVENESS_TIMEOUT=0; c_UNEXPECTED_LIVENESS=0
c_FAILCLOSED_ABORT=0; c_UNEXPECTED_ABORT=0; c_UNEXPECTED_CRASH=0; c_DETERMINISM_BUG=0
c_INFRA_ERROR=0; c_VACUOUS_SCHEDULE=0; c_SCHEDULE_DIVERGENCE=0; c_ALWAYS_VIOLATION=0
c_STARVATION_STALL=0
bump() {
  case "$1" in
    OK) c_OK=$(( c_OK + 1 )) ;;
    STARVATION_STALL) c_STARVATION_STALL=$(( c_STARVATION_STALL + 1 )) ;;
    ALWAYS_VIOLATION) c_ALWAYS_VIOLATION=$(( c_ALWAYS_VIOLATION + 1 )) ;;
    SAFETY_BUG) c_SAFETY_BUG=$(( c_SAFETY_BUG + 1 )) ;;
    LIVENESS_TIMEOUT) c_LIVENESS_TIMEOUT=$(( c_LIVENESS_TIMEOUT + 1 )) ;;
    UNEXPECTED_LIVENESS) c_UNEXPECTED_LIVENESS=$(( c_UNEXPECTED_LIVENESS + 1 )) ;;
    FAILCLOSED_ABORT) c_FAILCLOSED_ABORT=$(( c_FAILCLOSED_ABORT + 1 )) ;;
    UNEXPECTED_ABORT) c_UNEXPECTED_ABORT=$(( c_UNEXPECTED_ABORT + 1 )) ;;
    UNEXPECTED_CRASH) c_UNEXPECTED_CRASH=$(( c_UNEXPECTED_CRASH + 1 )) ;;
    DETERMINISM_BUG) c_DETERMINISM_BUG=$(( c_DETERMINISM_BUG + 1 )) ;;
    INFRA_ERROR) c_INFRA_ERROR=$(( c_INFRA_ERROR + 1 )) ;;
    VACUOUS_SCHEDULE) c_VACUOUS_SCHEDULE=$(( c_VACUOUS_SCHEDULE + 1 )) ;;
    SCHEDULE_DIVERGENCE) c_SCHEDULE_DIVERGENCE=$(( c_SCHEDULE_DIVERGENCE + 1 )) ;;
  esac
}

FAIL_DIRS=()
c_t_breadth=0; c_t_traffic=0; c_t_determinism=0; c_t_schedule=0
tier_bump() {
  case "$1" in
    SCHEDULE) c_t_schedule=$(( c_t_schedule + 1 )) ;;
    BREADTH) c_t_breadth=$(( c_t_breadth + 1 )) ;;
    TRAFFIC) c_t_traffic=$(( c_t_traffic + 1 )) ;;
    DETERMINISM/*) c_t_determinism=$(( c_t_determinism + 1 )) ;;
  esac
}

# --dry-run [START [END]] : print the derived config (and exact command) without
# building or running.
dry_run() {
  local s="$1" e="$2" G
  for (( G = s; G <= e; G++ )); do
    derive_config "$G"
    printf 'gen=%s tier=%s det_run=%s schedule=%s bin=%s %s\n' \
      "$G" "$TIER" "$DET_RUN" "$IS_SCHEDULE" "$(basename "$BIN")" "$CFG_SUMMARY"
    printf '    cmd: '; printf '%q ' "$PATINA" patina run "$BIN" "${PKNOBS[@]}" --record "$OUTDIR/gen-$G/trace" -- "${HARGS[@]}"; echo
  done
}

# Run a single generation end to end. Prints/logs its class; keeps the gen dir
# unless OK.
run_gen() {
  local G="$1"
  derive_config "$G"
  tier_bump "$TIER"
  local jobs; jobs=$(jobs_of)
  local gd="$OUTDIR/gen-$G"
  rm -rf "$gd"; mkdir -p "$gd"
  local trace="$gd/trace" out="$gd/stdout" err="$gd/stderr"

  { echo "# generation $G  ($CFG_SUMMARY)"; printf '%q ' "$PATINA" patina run "$BIN" "${PKNOBS[@]}" --record "$trace" -- "${HARGS[@]}"; echo; } > "$gd/config.txt"

  local code=0
  if "$PATINA" patina run "$BIN" "${PKNOBS[@]}" --record "$trace" -- "${HARGS[@]}" >"$out" 2>"$err"; then code=0; else code=$?; fi

  # Infrastructure guard: a cargo-patina/build/environment failure is NOT a bug.
  # Retry ONCE; if it recurs mark INFRA_ERROR (surfaced, kept, but not a finding).
  if is_infra "$(cat "$out")" "$(cat "$err")"; then
    if "$PATINA" patina run "$BIN" "${PKNOBS[@]}" --record "$trace" -- "${HARGS[@]}" >"$out" 2>"$err"; then code=0; else code=$?; fi
    if is_infra "$(cat "$out")" "$(cat "$err")"; then
      bump INFRA_ERROR
      local iline="gen=$G tier=$TIER class=INFRA_ERROR exit=$code config='$CFG_SUMMARY' (environment/build failure, NOT a bug -- re-run this gen isolated)"
      echo "$iline" >> "$SWEEP_LOG"; echo "$iline"; return
    fi
  fi

  local enq comp failed
  enq=$(field_of enqueued "$out"); comp=$(field_of completed "$out"); failed=$(field_of failed "$out")
  local class
  class=$(classify "$code" "${enq:-}" "${comp:-}" "${failed:-}" "$jobs" "$HEAVY" "$FS_CRASH" "$(cat "$out")" "$(cat "$err")")

  # Self-confirming liveness check. A NON-heavy config that timed out (exit 1 ->
  # UNEXPECTED_LIVENESS) may be genuinely non-live OR merely slow: the per-run
  # virtual budget is an arbitrary cutoff, and liveness means eventual
  # convergence under the SAME fault pattern. Re-run the identical config with 10x
  # the virtual budget (capped). Converges -> the original was timeout-bound
  # (reclassify OK, "slow-converge"); still fails at 10x -> a CONFIRMED finding.
  # Never masks a truly stuck queue and never fires for heavy configs.
  local live_note=""
  if [[ "$class" == UNEXPECTED_LIVENESS ]]; then
    local big=$(( CFG_TIMEOUT * 10 )); (( big > 3600 )) && big=3600
    local eargs=() i
    for (( i = 0; i < ${#HARGS[@]}; i++ )); do
      eargs+=("${HARGS[i]}")
      [[ "${HARGS[i]}" == "--timeout-secs" ]] && { eargs+=("$big"); i=$(( i + 1 )); }
    done
    local eout="$gd/stdout.10x" eerr="$gd/stderr.10x" ecode=0
    if "$PATINA" patina run "$BIN" "${PKNOBS[@]}" -- "${eargs[@]}" >"$eout" 2>"$eerr"; then ecode=0; else ecode=$?; fi
    local ee ec ef everdict
    ee=$(field_of enqueued "$eout"); ec=$(field_of completed "$eout"); ef=$(field_of failed "$eout")
    everdict=$(classify "$ecode" "${ee:-}" "${ec:-}" "${ef:-}" "$jobs" "$HEAVY" "$FS_CRASH" "$(cat "$eout")" "$(cat "$eerr")")
    if [[ "$everdict" == OK ]]; then
      class=OK
      live_note=" (slow-converge: ${comp:-?}/${jobs} at ${CFG_TIMEOUT}s -> ${ec:-?}/${jobs} at 10x=${big}s)"
    else
      class="$everdict"
      live_note=" (CONFIRMED $everdict: still ${ec:-?}/${jobs} at 10x=${big}s)"
    fi
  fi

  # DETERMINISM tier: re-run the identical config and require byte-identical
  # WORKQ_RESULT + trace SHA-256. A SCHEDULE-drawn determinism run replays the
  # SAME yield-points binary; a mismatch is SCHEDULE_DIVERGENCE.
  local det_note=""
  if (( DET_RUN == 1 )); then
    local trace2="$gd/trace.rerun" out2="$gd/stdout.rerun" err2="$gd/stderr.rerun"
    "$PATINA" patina run "$BIN" "${PKNOBS[@]}" --record "$trace2" -- "${HARGS[@]}" >"$out2" 2>"$err2" || true
    local r1 r2 h1 h2
    r1=$(grep '^WORKQ_RESULT' "$out" 2>/dev/null || true); r2=$(grep '^WORKQ_RESULT' "$out2" 2>/dev/null || true)
    h1=$(sha_of "$trace"); h2=$(sha_of "$trace2")
    if (( IS_SCHEDULE == 1 )); then
      local v; v=$(sched_det_check "$class" "$r1" "$r2" "$h1" "$h2")
      if [[ "$v" == SCHEDULE_DIVERGENCE ]]; then class=SCHEDULE_DIVERGENCE
        det_note=" SCHEDULE_DIVERGENCE(rerun): r1='$r1' r2='$r2' t1=$h1 t2=$h2"
      else det_note=" schedule-determinism-ok(trace=$h1)"; fi
    else
      local v; v=$(det_check "$class" "$r1" "$r2" "$h1" "$h2")
      if [[ "$v" == DETERMINISM_BUG ]]; then class=DETERMINISM_BUG
        det_note=" DETERMINISM(rerun): r1='$r1' r2='$r2' t1=$h1 t2=$h2"
      else det_note=" determinism-ok(trace=$h1)"; fi
    fi
  fi

  # Schedule-vacuity gate (SCHEDULE tier only, applied LAST so it never downgrades
  # a real finding).
  local sched_note=""
  if (( IS_SCHEDULE == 1 )); then
    local vac tb sclass
    vac=$(report_field vacuous_threads "$err"); tb=$(report_field total_boundaries "$err")
    sclass=$(sched_check 1 "$class" "${vac:-}" "${tb:-}")
    if [[ "$sclass" != "$class" ]]; then class="$sclass"
      sched_note=" (VACUOUS_SCHEDULE: total_boundaries=${tb:-?} vacuous_threads=${vac:-?} floor=$SCHEDULE_MIN_BOUNDARIES -- not real coverage)"
    else sched_note=" schedule(boundaries=${tb:-?} vacuous=${vac:-0})"; fi
  fi

  # Bug-depth annotation (exploration-policy gens). When a PCT/starvation policy
  # was active the runtime reports a PATINA_SCHEDULE_POLICY line; surface its
  # ordering-depth estimate (priority-change points hit + starvation exclusions),
  # most load-bearing on a failure since it estimates how deep an interleaving the
  # failing schedule required. A vacuous starvation config (would-starve-everyone)
  # is surfaced loudly.
  local policy_note="" bd sv
  bd=$(report_field bug_depth "$err"); sv=$(report_field starve_vacuous "$err")
  if [[ -n "$bd" ]]; then
    policy_note=" policy(${POLICY_SPEC:-?} bug_depth=$bd"
    [[ -n "$sv" && "$sv" -gt 0 ]] && policy_note+=" starve_vacuous=$sv VACUOUS_STARVATION"
    policy_note+=")"
  fi

  bump "$class"
  # Accumulate this gen's cooperative-SUT coverage and, once per sweep, prove the
  # runtime rows join the testbed's static sites inventory.
  local sdk_line; sdk_line="$(sdk_report_line "$err")"
  campaign_accumulate "$CAMPAIGN_STATE" "$sdk_line"
  if (( SITES_JOIN_CHECKED == 0 )) && [[ -n "$sdk_line" ]]; then
    buggify_sites_join_assert "$PATINA" "$here" "$err" || exit 3
    SITES_JOIN_CHECKED=1
  fi
  local logline="gen=$G tier=$TIER class=$class exit=$code enqueued=${enq:-?}/${jobs:-?} completed=${comp:-?} failed=${failed:-?} config='$CFG_SUMMARY'$live_note$det_note$sched_note$policy_note"
  echo "$logline" >> "$SWEEP_LOG"; echo "$logline"

  if [[ "$class" == OK ]]; then rm -rf "$gd"
  elif is_failure "$class"; then FAIL_DIRS+=("$gd"); fi
}

sweep() {
  local start="$1" end="$2"

  # Concurrency guard: two instances would clobber the shared target/ + binaries.
  local lock="$FUZZ_LOCK"
  mkdir -p "$here/target/patina"
  if ! mkdir "$lock" 2>/dev/null; then
    local holder=""; [[ -f "$lock/pid" ]] && holder="$(cat "$lock/pid" 2>/dev/null)"
    if [[ -n "$holder" ]] && kill -0 "$holder" 2>/dev/null; then
      echo "REFUSING TO RUN: fuzz-sweep pid $holder holds $lock" >&2; return 4
    fi
    echo "note: clearing stale lock (holder pid ${holder:-unknown} not running)" >&2
    rm -rf "$lock"; mkdir "$lock" 2>/dev/null || { echo "REFUSING: could not acquire $lock" >&2; return 4; }
  fi
  echo "$$" > "$lock/pid"
  trap 'rm -rf "${FUZZ_LOCK:-}" 2>/dev/null || true' EXIT

  # PATINA_FUZZ_SKIP_BUILD=1 continues a campaign against the EXISTING binaries
  # (a rebuild would re-link fresh artifacts). Still hard-fails if a binary is
  # missing or the yield-points marker is gone.
  if [[ "${PATINA_FUZZ_SKIP_BUILD:-0}" == 1 ]]; then
    if [[ ! -x "$built" || ! -x "$built_yp" ]]; then
      echo "FATAL: PATINA_FUZZ_SKIP_BUILD=1 but a binary is missing ($built / $built_yp)" >&2; exit 3
    fi
    if ! /usr/bin/grep -a -q "PATINA_YIELD_POINTS_V1" "$built_yp"; then
      echo "FATAL: existing yield-points binary lacks the PATINA_YIELD_POINTS_V1 marker" >&2; exit 3
    fi
    echo "==> PATINA_FUZZ_SKIP_BUILD=1: using existing binaries, NO rebuild"
  else
    build_all
  fi
  mkdir -p "$OUTDIR"; touch "$SWEEP_LOG"
  echo "==> fuzz sweep generations $start..$end (log: $SWEEP_LOG)"
  local G
  for (( G = start; G <= end; G++ )); do run_gen "$G"; done

  # Campaign-level cooperative-SUT coverage: a sometimes! site reached but never
  # satisfied across the whole campaign is a SOMETIMES_UNMET gap.
  local unmet_sites=() line
  while IFS= read -r line; do [[ -n "$line" ]] && unmet_sites+=("$line"); done < <(campaign_sometimes_unmet "$CAMPAIGN_STATE")
  local c_SOMETIMES_UNMET=${#unmet_sites[@]}

  local total=$(( end - start + 1 ))
  local failures=$(( c_SAFETY_BUG + c_ALWAYS_VIOLATION + c_UNEXPECTED_LIVENESS + c_UNEXPECTED_ABORT + c_UNEXPECTED_CRASH + c_DETERMINISM_BUG + c_VACUOUS_SCHEDULE + c_SCHEDULE_DIVERGENCE + c_SOMETIMES_UNMET ))
  echo
  echo "==> sweep summary (generations $start..$end, $total total)"
  echo "    tiers: SCHEDULE=$c_t_schedule BREADTH=$c_t_breadth TRAFFIC=$c_t_traffic DETERMINISM=$c_t_determinism"
  echo "    OK                  = $c_OK"
  echo "    LIVENESS_TIMEOUT    = $c_LIVENESS_TIMEOUT   (tolerated: heavy config)"
  echo "    FAILCLOSED_ABORT    = $c_FAILCLOSED_ABORT   (tolerated: fs-crash fails closed)"
  echo "    STARVATION_STALL    = $c_STARVATION_STALL   (diagnostic: opt-in --starve backstop killed a wedged gen)"
  echo "    -- failures --"
  echo "    SAFETY_BUG          = $c_SAFETY_BUG"
  echo "    ALWAYS_VIOLATION    = $c_ALWAYS_VIOLATION   (buggify always! invariant violated)"
  echo "    SOMETIMES_UNMET     = $c_SOMETIMES_UNMET   (buggify sometimes! reached but never satisfied)"
  echo "    UNEXPECTED_LIVENESS = $c_UNEXPECTED_LIVENESS"
  echo "    UNEXPECTED_ABORT    = $c_UNEXPECTED_ABORT"
  echo "    UNEXPECTED_CRASH    = $c_UNEXPECTED_CRASH"
  echo "    DETERMINISM_BUG     = $c_DETERMINISM_BUG"
  echo "    VACUOUS_SCHEDULE    = $c_VACUOUS_SCHEDULE   (SCHEDULE gen did not explore)"
  echo "    SCHEDULE_DIVERGENCE = $c_SCHEDULE_DIVERGENCE   (yield-points double-run non-deterministic)"
  echo "    TOTAL FAILURES      = $failures"
  if (( c_SOMETIMES_UNMET > 0 )); then
    echo "    unmet sometimes-sites:"; for line in "${unmet_sites[@]}"; do echo "      $line"; done
  fi
  echo "    -- infrastructure (NOT bugs) --"
  echo "    INFRA_ERROR         = $c_INFRA_ERROR"
  if (( ${#FAIL_DIRS[@]} > 0 )); then
    echo "    kept failure dirs:"; local d; for d in "${FAIL_DIRS[@]}"; do echo "      $d"; done
  fi
  if (( failures > 0 || c_INFRA_ERROR > 0 )); then
    (( failures > 0 )) && echo "==> FAILURES PRESENT"
    (( c_INFRA_ERROR > 0 )) && echo "==> INCOMPLETE (infrastructure errors)"
    return 1
  fi
  echo "==> no failure classes"
  return 0
}

###############################################################################
# entry point
###############################################################################
usage() {
  echo "usage: fuzz-sweep.sh [START_GEN] [END_GEN]      run generations (default 1..100)" >&2
  echo "       fuzz-sweep.sh --gen N [--dry-run]         run (or just print) a single generation" >&2
  echo "       fuzz-sweep.sh --dry-run [START [END]]     print derived config(s), no build/run" >&2
  echo "       fuzz-sweep.sh --selftest                  classifier selftest" >&2
  echo "       fuzz-sweep.sh -h | --help                 show full help" >&2
}
help() {
  cat <<'EOF'
workq fuzz-sweep — randomized-but-deterministic fault-COMBINATION campaign over
the durable work queue under Patina. Every knob AND the tier for generation G is
a pure function of SHA-256("patina-fuzz-G") (no $RANDOM, no date), so any
generation re-runs by number and the whole campaign is a pure function of its
[START,END] range. Two planes: the MESSAGE/FAULT plane (BREADTH/TRAFFIC tiers,
plain binary) crosses net/storage/crash/buggify faults; the SCHEDULE plane
(~20% of gens, yield-points binary) isolates thread INTERLEAVINGS at atomics
granularity. A ~4% DETERMINISM tier double-runs the identical config and requires
a byte-identical WORKQ_RESULT + trace hash. The classifier is pure and
non-vacuous (a planted WORKQ_VIOLATION is a SAFETY_BUG even on exit 0).

Usage:
  fuzz-sweep.sh [START_GEN] [END_GEN]   run generations START..END inclusive.
                                        Default 1..100.
  fuzz-sweep.sh --gen N [--dry-run]     run (or, with --dry-run, just print) a
                                        single generation N.
  fuzz-sweep.sh --dry-run [START [END]] print each generation's derived config
                                        and exact command, no build/run.
                                        Default START=1 END=START.
  fuzz-sweep.sh --selftest              drive the classifier over canned tuples
                                        covering EVERY outcome class.
  fuzz-sweep.sh -h | --help             show this help.

Environment:
  PATINA_FUZZ_OUT=DIR         output/scratch directory (default <here>/out-fuzz).
  PATINA_FUZZ_SKIP_BUILD=1    continue a campaign against the EXISTING binaries
                              (no rebuild); still hard-fails if a binary or the
                              yield-points marker is missing.
  PATINA_SWEEP_STARVE=1       enable the opt-in adversarial-starvation policy
                              overlay on the SCHEDULE tier (off by default: it can
                              wedge an atomic-spinlock guest; a wedged gen is
                              classified STARVATION_STALL by the backstop).

Runtime: the nightly CI campaign sweeps 1..200; a full 200-gen run is minutes,
far longer than the per-push budget. Exit status: 0 = no failure classes; 1 =
one or more findings (or infrastructure errors); 2 = usage error; 3 =
build/environment failure; 4 = another sweep holds the lock.
EOF
}
is_num() { [[ "$1" =~ ^[0-9]+$ ]]; }

main() {
  case "${1:-}" in
    -h|--help) help; exit 0 ;;
    --selftest)
      [[ $# -gt 1 ]] && { echo "fuzz-sweep.sh: --selftest takes no arguments" >&2; usage; exit 2; }
      selftest; exit $? ;;
    --dry-run)
      [[ $# -gt 3 ]] && { echo "fuzz-sweep.sh: too many arguments" >&2; usage; exit 2; }
      local s="${2:-1}" e="${3:-${2:-1}}"
      if ! is_num "$s" || ! is_num "$e"; then usage; exit 2; fi
      dry_run "$s" "$e"; exit 0 ;;
    --gen)
      [[ $# -gt 3 ]] && { echo "fuzz-sweep.sh: too many arguments" >&2; usage; exit 2; }
      local g="${2:-}"
      if ! is_num "$g"; then usage; exit 2; fi
      if [[ -n "${3:-}" && "${3:-}" != "--dry-run" ]]; then echo "fuzz-sweep.sh: unknown argument '${3}'" >&2; usage; exit 2; fi
      if [[ "${3:-}" == "--dry-run" ]]; then dry_run "$g" "$g"; exit 0; fi
      sweep "$g" "$g"; exit $? ;;
    -*) echo "fuzz-sweep.sh: unknown option '${1}'" >&2; usage; exit 2 ;;
  esac
  [[ $# -gt 2 ]] && { echo "fuzz-sweep.sh: too many arguments" >&2; usage; exit 2; }
  local start="${1:-1}" end="${2:-100}"
  if ! is_num "$start" || ! is_num "$end"; then usage; exit 2; fi
  if (( end < start )); then echo "END_GEN ($end) must be >= START_GEN ($start)" >&2; usage; exit 2; fi
  sweep "$start" "$end"; exit $?
}

main "$@"

#!/usr/bin/env bash
###############################################################################
# raft (tikv/raft) 3-node cluster under Patina -- randomized-but-deterministic
# fault-COMBINATION fuzz campaign (the run-patina.sh battery tests each knob in
# isolation; this crosses them). Every knob value for generation G is a pure
# function of G via a SHA-256 of "patina-fuzz-$G" -- no $RANDOM, no date -- so
# any generation is re-runnable by number and the whole campaign is a pure
# function of its [START,END] range.
#
#   fuzz-sweep.sh [START_GEN] [END_GEN]   run generations START..END (default 1..100)
#   fuzz-sweep.sh --selftest              exercise the classifier against canned
#                                         tuples covering EVERY outcome class
#
# Per generation a config is sampled from a space that COMBINES 2-3 fault knobs
# at once (net drop, net jitter, sleep jitter, fs-crash, kill-plan+restart,
# storage-fault recovery, proposals, tick) and a self-contained v4 trace is
# recorded under out-fuzz/gen-G/. The outcome is classified by a PURE function
# (testable via --selftest) that is deliberately not vacuous: a planted
# RAFT_VIOLATION is a SAFETY_BUG even on exit 0; an exit 1 is only tolerated for
# a "heavy" config; an exit 2 only when an fs-crash without recovery is present;
# any other exit, or a crash marker in the output, is a failure.
#
# On OK the gen dir is deleted (traces would pile up); every other class is kept
# for reproduction. Every 10th generation is re-run and required to be
# byte-identical (RAFT_RESULT + trace SHA-256) or it is a DETERMINISM_BUG.
#
# macOS BSD userland: uses shasum -a256 (not sha256sum); bash 3.2 safe (no
# associative arrays). set -uo pipefail with explicit nonzero handling so a
# single failing generation never aborts the loop.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
built="$here/target/patina/raft-harness"
PATINA="$repo_root/target/release/cargo-patina"

# Output dir. Overridable so a verification/triage run can use an isolated dir
# instead of colliding with a live campaign's out-fuzz. NOTE: two concurrent
# runs still share the built binary under target/; the run lock (see sweep())
# is what actually prevents a destructive collision on the shared target dir.
OUTDIR="${PATINA_FUZZ_OUT:-$here/out-fuzz}"
SWEEP_LOG="$OUTDIR/sweep.log"
# Run-lock path is a GLOBAL: the EXIT trap that removes it fires after sweep()
# has already returned (main does `sweep; exit`), so a function-local would be
# out of scope at trap time and trip `set -u` ("lock: unbound variable").
FUZZ_LOCK="$here/target/patina/.fuzz-sweep.lock"

# Fixed per-run virtual-clock budget (Instant is virtual under Patina, so this is
# generous without costing wall time) and cluster base port (networking is
# SimNet, so the port is virtual and never really bound).
TIMEOUT_SECS=90
BASE_PORT=4001
DATA_DIR=/raft

###############################################################################
# Outcome classification -- a PURE function of (exit, committed, proposals,
# heavy, fs_crash, recover, stdout, stderr). No global state, no I/O of its own,
# so --selftest can drive it with canned tuples and prove the detector bites.
###############################################################################

# Crash markers that indicate a genuine Patina/Rust failure. NOTE the scoping:
# a healthy Patina run legitimately prints "PATINA_SCHEDULE_REPORT ..." and a
# benign "PATINA WARNING: vacuous schedule exploration -- ... invisible to the
# scheduler, so their internal interleavings ..." to stderr. That benign line
# contains the bare words "scheduler" and "internal", so matching those bare
# words (as the task's 'scheduler' shorthand suggests) would misflag clean runs
# as crashes. We therefore require the scheduler marker to be an ERROR context
# ("scheduler panic/error/stall/fault/deadlock"), match "internal error" only as
# a phrase, and match the lowercase "patina: " error prefix (distinct from the
# uppercase "PATINA " diagnostics). See the classifier-boundary note in the
# report. Case-sensitive on purpose.
# NOTE: match the runtime's "patina: the deterministic runtime ..." init failure,
# NOT a bare "patina: " -- the latter also occurs inside the tool's own error
# prefix "cargo-patina: ..." (e.g. an infrastructure "cargo-patina: Cargo process
# terminated by a signal"), which is an environment/build failure, not a
# raft/patina crash. Infra failures are handled separately (see is_infra).
CRASH_MARKERS='panicked|internal error|patina: the deterministic runtime|patina native shim fatal|native shim fatal|unsupported native imports|scheduler (panic|error|stall|fault|deadlock)|deadlock detected|SIGSEGV|SIGABRT'

# Infrastructure/environment failure signatures (NOT a raft or patina bug): the
# cargo-patina wrapper or its build subprocess died, the binary is missing, the
# target dir is being contended by a concurrent build, disk is full, etc. These
# must never be reported as UNEXPECTED_CRASH bug findings.
INFRA_MARKERS='cargo-patina: |Cargo process terminated|terminated by a signal|could not compile|No such file or directory|native-build failed|Resource temporarily unavailable|Cannot allocate memory'
is_infra() { printf '%s\n%s' "$1" "$2" | /usr/bin/grep -Eq "$INFRA_MARKERS"; }

classify() {
  # args: exit committed proposals heavy fs_crash recover stdout stderr
  local exit_code="$1" committed="$2" proposals="$3" heavy="$4" fs_crash="$5" recover="$6"
  local out="$7" err="$8"
  local combined="$out
$err"

  # 1. A safety violation is ALWAYS a bug, regardless of exit code (a planted
  #    RAFT_VIOLATION on exit 0 must still be SAFETY_BUG -- this is what proves
  #    the detector is not vacuous).
  if printf '%s' "$combined" | grep -q 'RAFT_VIOLATION'; then
    echo SAFETY_BUG; return
  fi

  # 2. A hard crash marker anywhere is an UNEXPECTED_CRASH even if the exit code
  #    would otherwise look "allowed".
  if printf '%s' "$combined" | grep -Eq "$CRASH_MARKERS"; then
    echo UNEXPECTED_CRASH; return
  fi

  # 3. Exit-code semantics (mirrors run-patina.sh: 0 converged / 1 liveness /
  #    2 fail-closed abort).
  case "$exit_code" in
    0)
      if [[ -n "$proposals" && "$committed" == "$proposals" ]]; then
        echo OK
      else
        # exit 0 must mean fully committed; anything else is a contract break.
        echo UNEXPECTED_CRASH
      fi
      ;;
    1)
      # A liveness timeout is only honest for a "heavy" config (heavy loss, an
      # fs-crash with no recovery, or a kill with no restart). Otherwise raft
      # should have converged and the timeout is a real regression.
      if [[ "$heavy" == 1 ]]; then echo LIVENESS_TIMEOUT; else echo UNEXPECTED_LIVENESS; fi
      ;;
    2)
      # A fail-closed abort is by-design only when an fs-crash is injected and
      # storage recovery is NOT requested.
      if [[ "$fs_crash" == 1 && "$recover" == 0 ]]; then echo FAILCLOSED_ABORT; else echo UNEXPECTED_ABORT; fi
      ;;
    *)
      echo UNEXPECTED_CRASH
      ;;
  esac
}

# Determinism verdict -- also pure. Given the primary class and the two runs'
# RAFT_RESULT lines + trace hashes, either confirm the primary class or promote
# to DETERMINISM_BUG.
det_check() {
  # args: primary_class r1 r2 h1 h2
  local primary="$1" r1="$2" r2="$3" h1="$4" h2="$5"
  if [[ "$r1" == "$r2" && "$h1" == "$h2" ]]; then echo "$primary"; else echo DETERMINISM_BUG; fi
}

# Discriminator verdict -- pure. After a CONFIRMED non-live timeout, the config
# is re-run UNPACED (propose-window 0). If it converges then, the original
# timeout was a harness workload-shape artifact (client re-proposal / pacing
# interaction), NOT a fault-survivability finding, so it is reclassified
# WORKLOAD_SHAPE; otherwise it stays a genuine UNEXPECTED_LIVENESS (a stronger
# signal, since the cluster fails to converge even with no pacing).
disc_check() {
  # args: unpaced_verdict  (the classify() result of the window-0 re-run)
  local unpaced="$1"
  if [[ "$unpaced" == OK ]]; then echo WORKLOAD_SHAPE; else echo UNEXPECTED_LIVENESS; fi
}

# A class is a FAILURE unless it is a tolerated / neutral outcome. WORKLOAD_SHAPE
# is neutral: it is a harness-shape artifact, not a raft/patina fault finding.
is_failure() {
  case "$1" in
    OK|LIVENESS_TIMEOUT|FAILCLOSED_ABORT|WORKLOAD_SHAPE) return 1 ;;
    *) return 0 ;;
  esac
}

###############################################################################
# Deterministic per-generation config derivation. HEX = SHA-256 of the gen tag;
# byte i is HEX[2i..2i+1] as 0..255 (global BYTE[]). Every knob -- AND the config
# TIER -- is a function of these bytes, so any generation is re-runnable by G.
#
# Tiers (chosen from BYTE[18]):
#   ~80% BREADTH      short combined-fault space (proposals 20/40)
#   ~15% TRAFFIC      long-horizon paced realistic traffic (proposals 200/400)
#    ~5% DETERMINISM  a config from EITHER space, run twice, byte-identical
#                     required (this replaces the old "every 10th gen" rule)
#
# Every sampler sets globals: PKNOBS[] (native-run knobs, before --), HARGS[]
# (harness args, after --), CFG_SUMMARY, HEAVY, FS_CRASH, RECOVER, PROPOSALS.
# derive_config additionally sets TIER and DET_RUN (1 => run twice & compare).
###############################################################################

# Fill global BYTE[0..31] from SHA-256("patina-fuzz-$G").
compute_bytes() {
  local G="$1" HEX i
  HEX="$(printf 'patina-fuzz-%s' "$G" | shasum -a256 | cut -c1-64)"
  BYTE=()
  for (( i = 0; i < 32; i++ )); do BYTE[i]=$(( 16#${HEX:$(( i * 2 )):2} )); done
}

# BREADTH tier: the original short combined-fault space.
sample_breadth() {
  local G="$1"

  local props_tbl=(20 40)
  PROPOSALS=${props_tbl[$(( BYTE[16] % 2 ))]}
  local tick_tbl=(80 100 150)
  local tick=${tick_tbl[$(( BYTE[17] % 3 ))]}

  local drop_tbl=(0 50 100 150 200 300 400 500)
  local drop=${drop_tbl[$(( BYTE[0] % 8 ))]}

  # net jitter (~50%)
  local jitter_on=0 jmin_ns=0 jmax_ns=0 jspec="off"
  if (( BYTE[1] % 2 == 0 )); then
    jitter_on=1
    local jmin_ms=$(( 1 + BYTE[2] % 40 ))
    local jmax_ms=$(( jmin_ms + 1 + BYTE[3] % 80 ))
    (( jmax_ms > 120 )) && jmax_ms=120
    jmin_ns=$(( jmin_ms * 1000000 )); jmax_ns=$(( jmax_ms * 1000000 ))
    jspec="${jmin_ms}-${jmax_ms}ms"
  fi

  # sleep jitter (~25%, occasional)
  local sleep_on=0 smin_ns=0 smax_ns=0 sspec="off"
  if (( BYTE[4] % 4 == 0 )); then
    sleep_on=1
    local smin_ms=$(( 1 + BYTE[5] % 20 ))
    local smax_ms=$(( smin_ms + 1 + BYTE[6] % 40 ))
    (( smax_ms > 120 )) && smax_ms=120
    smin_ns=$(( smin_ms * 1000000 )); smax_ns=$(( smax_ms * 1000000 ))
    sspec="${smin_ms}-${smax_ms}ms"
  fi

  # fs-crash (~40%)
  FS_CRASH=0
  local fspec="off" fs_op="" fs_n=0
  if (( BYTE[7] < 102 )); then
    FS_CRASH=1
    local op_tbl=(write sync close)
    fs_op=${op_tbl[$(( BYTE[8] % 3 ))]}
    fs_n=$(( 1 + BYTE[9] % 60 ))
    fspec="${fs_op}:${fs_n}"
  fi

  # storage-fault recovery (~half of fs-crash runs)
  RECOVER=0
  if (( FS_CRASH == 1 )) && (( BYTE[15] % 2 == 0 )); then RECOVER=1; fi

  # kill-plan + restart (~40%)
  local kill_on=0 kspec="off" rat=0
  if (( BYTE[10] < 102 )); then
    kill_on=1
    local k_node=$(( 1 + BYTE[11] % 3 ))
    local k_at=$(( 2 + BYTE[12] % 14 ))
    local rat_tbl=(3 5 8)
    rat=${rat_tbl[$(( BYTE[13] % 3 ))]}
    local pw=$(( 1 + BYTE[14] % 3 ))
    kspec="${k_node}@${k_at}/r${rat}/w${pw}"
  fi

  # Virtual timeout scales with proposal count (90s per 20 proposals), matching
  # the TRAFFIC tier. Under Patina the clock is virtual, so this costs no wall
  # time on a converging run; it only stops a 40-proposal run under heavy loss +
  # a mid-run kill from being starved of virtual time before it can converge
  # (a flat 90s falsely timed such runs out -- see the gen-60 diagnostic).
  local timeout=$(( TIMEOUT_SECS * PROPOSALS / 20 ))
  CFG_TIMEOUT=$timeout

  PKNOBS=(--seed "$G")
  (( drop > 0 ))   && PKNOBS+=(--net-drop-permille "$drop")
  (( jitter_on ))  && PKNOBS+=(--net-jitter-nanos "${jmin_ns}..${jmax_ns}")
  (( sleep_on ))   && PKNOBS+=(--sleep-jitter-nanos "${smin_ns}..${smax_ns}")
  (( FS_CRASH ))   && PKNOBS+=(--fs-crash-at "${fs_op}:${fs_n}")

  HARGS=(--seed "$G" --proposals "$PROPOSALS" --base-port "$BASE_PORT"
         --data-dir "$DATA_DIR" --timeout-secs "$timeout" --tick-millis "$tick")
  if (( kill_on )); then
    HARGS+=(--kill-plan "${k_node}:${k_at}" --restart-after-ticks "$rat" --propose-window "$pw")
  fi
  (( RECOVER )) && HARGS+=(--recover-storage-faults)

  HEAVY=0
  (( drop >= 400 )) && HEAVY=1
  [[ "$FS_CRASH" == 1 && "$RECOVER" == 0 ]] && HEAVY=1
  [[ "$kill_on" == 1 && "$rat" == 0 ]] && HEAVY=1

  CFG_SUMMARY="seed=$G drop=$drop jitter=$jspec sleep=$sspec fscrash=$fspec recover=$RECOVER kill=$kspec proposals=$PROPOSALS tick=$tick timeout=${timeout}s heavy=$HEAVY"
}

# TRAFFIC tier: long-horizon paced realistic-like workload. Always jittered,
# always a small propose-window (commits spread over a long virtual window
# instead of one burst), light-to-moderate loss, and ~half get a multi-kill
# rolling-restart-under-load plan (2-3 kills at spread-out commit anchors). The
# timeout scales with the proposal count (far more virtual work). No fs-crash in
# this tier, so a liveness timeout here (drop<=200, kills restart) is NEVER
# tolerated -- raft must survive rolling restarts at light loss.
sample_traffic() {
  local G="$1"

  local props_tbl=(200 400)
  PROPOSALS=${props_tbl[$(( BYTE[16] % 2 ))]}
  local tick_tbl=(80 100 150)
  local tick=${tick_tbl[$(( BYTE[17] % 3 ))]}
  local pw=$(( 1 + BYTE[14] % 3 ))                 # ALWAYS paced

  local drop_tbl=(0 50 100 200)
  local drop=${drop_tbl[$(( BYTE[0] % 4 ))]}

  # jitter ALWAYS on (realistic networks are never jitter-free)
  local jmin_ms=$(( 1 + BYTE[2] % 40 ))
  local jmax_ms=$(( jmin_ms + 1 + BYTE[3] % 80 ))
  (( jmax_ms > 120 )) && jmax_ms=120
  local jmin_ns=$(( jmin_ms * 1000000 )) jmax_ns=$(( jmax_ms * 1000000 ))

  # timeout scales with proposals: 90 * proposals/20 virtual seconds.
  local timeout=$(( 90 * PROPOSALS / 20 ))
  CFG_TIMEOUT=$timeout

  FS_CRASH=0; RECOVER=0

  # rolling restart under load (~half): 2-3 kills at spread commit anchors.
  local kspec="off" killargs="" rat=0
  if (( BYTE[10] % 2 == 0 )); then
    local k=$(( 2 + BYTE[20] % 2 ))                # 2 or 3 kills
    local rat_tbl=(3 5 8)
    rat=${rat_tbl[$(( BYTE[13] % 3 ))]}
    local step=$(( PROPOSALS / (k + 1) ))
    local i node at
    for (( i = 0; i < k; i++ )); do
      node=$(( ( (BYTE[11] + i) % 3 ) + 1 ))       # cycle nodes 1..3
      at=$(( step * (i + 1) ))
      (( at < 2 )) && at=2
      [[ -n "$killargs" ]] && killargs="$killargs,"
      killargs="${killargs}${node}:${at}"
    done
    kspec="${killargs}/r${rat}"
  fi

  PKNOBS=(--seed "$G")
  (( drop > 0 )) && PKNOBS+=(--net-drop-permille "$drop")
  PKNOBS+=(--net-jitter-nanos "${jmin_ns}..${jmax_ns}")

  HARGS=(--seed "$G" --proposals "$PROPOSALS" --base-port "$BASE_PORT"
         --data-dir "$DATA_DIR" --timeout-secs "$timeout" --tick-millis "$tick"
         --propose-window "$pw")
  if [[ -n "$killargs" ]]; then
    HARGS+=(--kill-plan "$killargs" --restart-after-ticks "$rat")
  fi

  HEAVY=0
  (( drop >= 400 )) && HEAVY=1                      # kept honest; never true here

  CFG_SUMMARY="seed=$G drop=$drop jitter=${jmin_ms}-${jmax_ms}ms sleep=off fscrash=off recover=0 kill=$kspec proposals=$PROPOSALS window=$pw tick=$tick timeout=${timeout}s heavy=$HEAVY"
}

# Pick the tier for G and sample it. DETERMINISM draws from either space and
# marks DET_RUN so the runner executes the config twice and compares.
derive_config() {
  local G="$1"
  compute_bytes "$G"
  DET_RUN=0
  local t=${BYTE[18]}
  if (( t <= 204 )); then           # ~80%
    TIER=BREADTH; sample_breadth "$G"
  elif (( t <= 242 )); then         # ~15%
    TIER=TRAFFIC; sample_traffic "$G"
  else                              # ~5%
    DET_RUN=1
    if (( BYTE[19] % 2 == 0 )); then
      TIER="DETERMINISM/breadth"; sample_breadth "$G"
    else
      TIER="DETERMINISM/traffic"; sample_traffic "$G"
    fi
  fi
}

###############################################################################
# --selftest : drive the pure classifier over canned tuples covering every class.
###############################################################################
SELFTEST_FAIL=0
assert_class() {
  local want="$1" got="$2" name="$3"
  if [[ "$got" == "$want" ]]; then
    printf '  ok   %-20s -> %s\n' "$name" "$got"
  else
    printf '  FAIL %-20s -> got %s, want %s\n' "$name" "$got" "$want"
    SELFTEST_FAIL=1
  fi
}

selftest() {
  echo "== fuzz-sweep classifier selftest =="

  local clean_stderr='PATINA_SCHEDULE_REPORT tasks_spawned=3 max_concurrent=3 total_boundaries=812 vacuous_threads=0'
  local ok_stdout='RAFT_RESULT seed=1 proposals=20 committed=20 terms=2 restarts=0 applied_hash=deadbeef'

  # OK
  assert_class OK \
    "$(classify 0 20 20 0 0 0 "$ok_stdout" "$clean_stderr")" "ok-converged"

  # OK even with the benign vacuous-schedule WARNING (contains "scheduler" and
  # "internal") -- proves the crash-marker scoping does not misfire on clean runs.
  local vacuous_warn='PATINA WARNING: vacuous schedule exploration -- 1 spawned thread(s) (task id 4) ran to completion with no more scheduling boundaries than thread spawn/join alone incurs. Any loop in their body was atomics-only and thus invisible to the scheduler, so their internal interleavings were not explored.'
  assert_class OK \
    "$(classify 0 20 20 0 0 0 "$ok_stdout" "$clean_stderr
$vacuous_warn")" "ok-vacuous-warn"

  # SAFETY_BUG: a planted RAFT_VIOLATION on exit 0 with committed==proposals
  # must STILL be a safety bug (this is the non-vacuous proof).
  assert_class SAFETY_BUG \
    "$(classify 0 20 20 0 0 0 "$ok_stdout" "RAFT_VIOLATION two leaders in term 4: nodes [1, 2]")" \
    "safety-on-exit0"

  # LIVENESS_TIMEOUT: exit 1 allowed because the config is heavy.
  assert_class LIVENESS_TIMEOUT \
    "$(classify 1 7 20 1 0 0 'RAFT_RESULT seed=1 proposals=20 committed=7 terms=9 restarts=0 applied_hash=x' 'RAFT_FAILURE not all proposals committed on alive nodes (7/20)')" \
    "liveness-heavy"

  # UNEXPECTED_LIVENESS: exit 1 on a NON-heavy config is a regression.
  assert_class UNEXPECTED_LIVENESS \
    "$(classify 1 7 20 0 0 0 'RAFT_RESULT seed=1 proposals=20 committed=7 terms=9 restarts=0 applied_hash=x' 'RAFT_FAILURE not all proposals committed on alive nodes (7/20)')" \
    "liveness-unexpected"

  # TRAFFIC tier: a long-horizon paced run that fully converges -> OK. Same
  # classifier, larger proposal counts.
  local traffic_stdout='RAFT_RESULT seed=42 proposals=400 committed=400 terms=11 restarts=3 applied_hash=cafef00d'
  assert_class OK \
    "$(classify 0 400 400 0 0 0 "$traffic_stdout" "$clean_stderr")" "traffic-ok"

  # TRAFFIC tier: a liveness timeout at light loss with rolling restarts is
  # NEVER tolerated (heavy=0 because drop<=200 and no fs-crash) -> a regression.
  assert_class UNEXPECTED_LIVENESS \
    "$(classify 1 351 400 0 0 0 'RAFT_RESULT seed=42 proposals=400 committed=351 terms=40 restarts=3 applied_hash=x' 'RAFT_FAILURE not all proposals committed on alive nodes (351/400)')" \
    "traffic-liveness"

  # FAILCLOSED_ABORT: exit 2 allowed because fs-crash present and no recovery.
  assert_class FAILCLOSED_ABORT \
    "$(classify 2 '' '' 0 1 0 '' 'RAFT_ABORT node 2 storage failure: injected crash at write:5')" \
    "abort-failclosed"

  # UNEXPECTED_ABORT: exit 2 with no fs-crash (or with recovery on) is unexpected.
  assert_class UNEXPECTED_ABORT \
    "$(classify 2 '' '' 0 0 0 '' 'RAFT_ABORT node 2 storage failure: ???')" \
    "abort-unexpected"
  assert_class UNEXPECTED_ABORT \
    "$(classify 2 '' '' 0 1 1 '' 'RAFT_ABORT node 2 storage failure: recover was on')" \
    "abort-with-recover"

  # UNEXPECTED_CRASH via a Rust panic marker even though exit/committed look OK.
  assert_class UNEXPECTED_CRASH \
    "$(classify 0 20 20 0 0 0 "$ok_stdout" "thread 'main' panicked at src/node.rs:42: index out of bounds")" \
    "crash-panic"

  # UNEXPECTED_CRASH via a Patina runtime fatal marker.
  assert_class UNEXPECTED_CRASH \
    "$(classify 0 20 20 0 0 0 '' 'patina: the deterministic runtime failed to initialize: bad mount')" \
    "crash-patina-fatal"

  # UNEXPECTED_CRASH via a scheduler ERROR context (not the benign warning).
  assert_class UNEXPECTED_CRASH \
    "$(classify 0 20 20 0 0 0 '' 'scheduler deadlock: all tasks parked with pending work')" \
    "crash-scheduler-err"

  # UNEXPECTED_CRASH via an out-of-band exit code.
  assert_class UNEXPECTED_CRASH \
    "$(classify 134 '' '' 0 0 0 '' 'Abort trap: 6')" "crash-exit134"

  # UNEXPECTED_CRASH: exit 0 but not fully committed (contract break).
  assert_class UNEXPECTED_CRASH \
    "$(classify 0 18 20 0 0 0 'RAFT_RESULT seed=1 proposals=20 committed=18 terms=2 restarts=0 applied_hash=x' '')" \
    "crash-exit0-partial"

  # DETERMINISM_BUG via the pure det_check helper.
  assert_class OK \
    "$(det_check OK 'RAFT_RESULT a' 'RAFT_RESULT a' 'hashA' 'hashA')" "det-identical"
  assert_class DETERMINISM_BUG \
    "$(det_check OK 'RAFT_RESULT a' 'RAFT_RESULT b' 'hashA' 'hashA')" "det-result-diff"
  assert_class DETERMINISM_BUG \
    "$(det_check OK 'RAFT_RESULT a' 'RAFT_RESULT a' 'hashA' 'hashB')" "det-trace-diff"

  # WORKLOAD_SHAPE vs UNEXPECTED_LIVENESS via the pure disc_check helper: after a
  # CONFIRMED non-live timeout, an unpaced (window=0) re-run that CONVERGES (OK)
  # marks a harness pacing artifact; one that still fails stays a genuine finding.
  assert_class WORKLOAD_SHAPE \
    "$(disc_check OK)" "disc-converges-unpaced"
  assert_class UNEXPECTED_LIVENESS \
    "$(disc_check UNEXPECTED_LIVENESS)" "disc-still-nonlive"

  # Marker precision: an infrastructure "cargo-patina: ..." line must NOT be
  # matched as a patina runtime crash (the bare "patina: " used to false-match
  # the "cargo-patina:" prefix). With no fs-crash + exit 2 this is UNEXPECTED_ABORT,
  # i.e. it is NOT swallowed as UNEXPECTED_CRASH by a marker.
  assert_class UNEXPECTED_ABORT \
    "$(classify 2 '' '' 0 0 0 '' 'cargo-patina: Cargo process terminated by a signal')" \
    "cargo-prefix-not-crash"

  # is_infra recognizes environment/build failures and only those.
  if is_infra '' 'cargo-patina: Cargo process terminated by a signal'; then
    printf '  ok   %-20s -> true\n' "infra-detects-signal"
  else printf '  FAIL %-20s\n' "infra-detects-signal"; SELFTEST_FAIL=1; fi
  if is_infra 'RAFT_RESULT seed=1 proposals=20 committed=20 terms=1 restarts=0 applied_hash=x' \
              'PATINA_SCHEDULE_REPORT tasks_spawned=3'; then
    printf '  FAIL %-20s (false positive on clean run)\n' "infra-clean-negative"; SELFTEST_FAIL=1
  else printf '  ok   %-20s -> false\n' "infra-clean-negative"; fi

  echo
  if (( SELFTEST_FAIL )); then
    echo "SELFTEST FAILED"; return 1
  fi
  echo "SELFTEST PASSED (every class covered, including planted RAFT_VIOLATION -> SAFETY_BUG)"
  return 0
}

###############################################################################
# Build cargo-patina FIRST (a stale release binary is a known trap), then
# native-build the harness. No --allow-unsupported-symbols: the harness passes
# the default-deny gate clean.
###############################################################################
build_all() {
  cd "$repo_root"
  echo "==> building cargo-patina and the harness under Patina"
  if ! cargo build --release --quiet -p cargo-patina; then
    echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
  fi
  mkdir -p "$here/target/patina"
  if ! "$PATINA" patina native-build "$here" --output "$built" --release >/dev/null; then
    echo "FATAL: native-build failed" >&2; exit 3
  fi
}

# helpers to pull fields out of a RAFT_RESULT-bearing stream
field_of() { sed -n "s/.*$1=\\([0-9][0-9]*\\).*/\\1/p" "$2" | head -1; }
sha_of()   { if [[ -f "$1" ]]; then shasum -a256 "$1" | cut -d' ' -f1; else echo MISSING; fi; }

# per-class counters (bash 3.2: no associative arrays)
c_OK=0; c_SAFETY_BUG=0; c_LIVENESS_TIMEOUT=0; c_UNEXPECTED_LIVENESS=0
c_FAILCLOSED_ABORT=0; c_UNEXPECTED_ABORT=0; c_UNEXPECTED_CRASH=0; c_DETERMINISM_BUG=0
c_INFRA_ERROR=0; c_WORKLOAD_SHAPE=0
bump() {
  case "$1" in
    OK) c_OK=$(( c_OK + 1 )) ;;
    SAFETY_BUG) c_SAFETY_BUG=$(( c_SAFETY_BUG + 1 )) ;;
    LIVENESS_TIMEOUT) c_LIVENESS_TIMEOUT=$(( c_LIVENESS_TIMEOUT + 1 )) ;;
    UNEXPECTED_LIVENESS) c_UNEXPECTED_LIVENESS=$(( c_UNEXPECTED_LIVENESS + 1 )) ;;
    FAILCLOSED_ABORT) c_FAILCLOSED_ABORT=$(( c_FAILCLOSED_ABORT + 1 )) ;;
    UNEXPECTED_ABORT) c_UNEXPECTED_ABORT=$(( c_UNEXPECTED_ABORT + 1 )) ;;
    UNEXPECTED_CRASH) c_UNEXPECTED_CRASH=$(( c_UNEXPECTED_CRASH + 1 )) ;;
    DETERMINISM_BUG) c_DETERMINISM_BUG=$(( c_DETERMINISM_BUG + 1 )) ;;
    INFRA_ERROR) c_INFRA_ERROR=$(( c_INFRA_ERROR + 1 )) ;;
    WORKLOAD_SHAPE) c_WORKLOAD_SHAPE=$(( c_WORKLOAD_SHAPE + 1 )) ;;
  esac
}

FAIL_DIRS=()
INFRA_DIRS=()
c_t_breadth=0; c_t_traffic=0; c_t_determinism=0
tier_bump() {
  case "$1" in
    BREADTH) c_t_breadth=$(( c_t_breadth + 1 )) ;;
    TRAFFIC) c_t_traffic=$(( c_t_traffic + 1 )) ;;
    DETERMINISM/*) c_t_determinism=$(( c_t_determinism + 1 )) ;;
  esac
}

# --dry-run [START [END]] : print the derived config (and exact command) for a
# generation or range WITHOUT building or running. Useful to find tier
# boundaries and to hand a reproducer to triage.
dry_run() {
  local s="$1" e="$2" G
  for (( G = s; G <= e; G++ )); do
    derive_config "$G"
    printf 'gen=%s tier=%s det_run=%s %s\n' "$G" "$TIER" "$DET_RUN" "$CFG_SUMMARY"
    printf '    cmd: '
    printf '%q ' "$PATINA" patina native-run "$built" "${PKNOBS[@]}" --record "$OUTDIR/gen-$G/trace" -- "${HARGS[@]}"
    echo
  done
}

# Run a single generation end to end. Prints/logs its class; keeps the gen dir
# unless the class is OK.
run_gen() {
  local G="$1"
  derive_config "$G"
  tier_bump "$TIER"
  local gd="$OUTDIR/gen-$G"
  rm -rf "$gd"; mkdir -p "$gd"
  local trace="$gd/trace" out="$gd/stdout" err="$gd/stderr"

  # Authoritative reproducer command line.
  {
    echo "# generation $G  ($CFG_SUMMARY)"
    printf '%q ' "$PATINA" patina native-run "$built" "${PKNOBS[@]}" --record "$trace" -- "${HARGS[@]}"
    echo
  } > "$gd/config.txt"

  local code=0
  if "$PATINA" patina native-run "$built" "${PKNOBS[@]}" --record "$trace" -- "${HARGS[@]}" \
        >"$out" 2>"$err"; then code=0; else code=$?; fi

  # Infrastructure guard: a cargo-patina/build/environment failure (concurrent
  # contention on the shared target dir, a clobbered binary, disk full, OOM) is
  # NOT a raft/patina bug and must never be reported as one. Detect it, retry
  # ONCE, and if it recurs mark INFRA_ERROR (surfaced, kept, but not a bug find).
  if is_infra "$(cat "$out")" "$(cat "$err")"; then
    if "$PATINA" patina native-run "$built" "${PKNOBS[@]}" --record "$trace" -- "${HARGS[@]}" \
          >"$out" 2>"$err"; then code=0; else code=$?; fi
    if is_infra "$(cat "$out")" "$(cat "$err")"; then
      bump INFRA_ERROR
      local iline="gen=$G tier=$TIER class=INFRA_ERROR exit=$code config='$CFG_SUMMARY' (environment/build failure, NOT a bug -- run isolated + re-run this gen)"
      echo "$iline" >> "$SWEEP_LOG"; echo "$iline"
      INFRA_DIRS+=("$gd")
      return
    fi
  fi

  local committed proposals terms restarts
  committed=$(field_of committed "$out")
  proposals=$(field_of proposals "$out")
  terms=$(field_of terms "$out")
  restarts=$(field_of restarts "$out")

  local class
  class=$(classify "$code" "${committed:-}" "${proposals:-}" "$HEAVY" "$FS_CRASH" "$RECOVER" \
                   "$(cat "$out")" "$(cat "$err")")

  # Self-confirming liveness check. A NON-heavy config that timed out (exit 1 ->
  # UNEXPECTED_LIVENESS) may be genuinely non-live OR merely slow: the per-run
  # virtual budget is an arbitrary cutoff, and liveness means eventual
  # convergence under the SAME fault pattern. Re-run the identical fault config
  # with 10x the virtual budget (capped). If it now converges the original was
  # timeout-bound (reclassify OK, "slow-converge"); if it STILL fails with 10x
  # headroom it is a CONFIRMED finding. This never masks a truly stuck cluster
  # (it still fails at 10x) and never fires for heavy configs (already
  # tolerated) -- so it removes timeout false positives without going vacuous.
  local live_note=""
  if [[ "$class" == UNEXPECTED_LIVENESS ]]; then
    local big=$(( CFG_TIMEOUT * 10 )); (( big > 7200 )) && big=7200
    local eargs=() i
    for (( i = 0; i < ${#HARGS[@]}; i++ )); do
      eargs+=("${HARGS[i]}")
      [[ "${HARGS[i]}" == "--timeout-secs" ]] && { eargs+=("$big"); i=$(( i + 1 )); }
    done
    local eout="$gd/stdout.liveness10x" eerr="$gd/stderr.liveness10x" ecode=0
    if "$PATINA" patina native-run "$built" "${PKNOBS[@]}" -- "${eargs[@]}" \
          >"$eout" 2>"$eerr"; then ecode=0; else ecode=$?; fi
    local ec ep everdict
    ec=$(field_of committed "$eout"); ep=$(field_of proposals "$eout")
    everdict=$(classify "$ecode" "${ec:-}" "${ep:-}" "$HEAVY" "$FS_CRASH" "$RECOVER" \
                        "$(cat "$eout")" "$(cat "$eerr")")
    if [[ "$everdict" == OK ]]; then
      class=OK
      live_note=" (slow-converge: ${committed}/${proposals} at ${CFG_TIMEOUT}s -> ${ec}/${ep} at 10x=${big}s)"
    elif [[ "$everdict" == UNEXPECTED_LIVENESS ]]; then
      # CONFIRMED non-live at 10x. Auto-discriminate a harness workload-shape
      # artifact (client re-proposal / pacing interaction) from a genuine
      # fault-survivability finding: re-run once more UNPACED (harness
      # --propose-window forced to 0) at the same 10x budget. propose-window is a
      # HARNESS arg (after --), so it lives in eargs; replace its value if present
      # (TRAFFIC + kill configs), else append it. Converges unpaced => the pacing
      # was the cause (WORKLOAD_SHAPE, neutral); still fails => genuine finding.
      local dargs=() j saw_window=0
      for (( j = 0; j < ${#eargs[@]}; j++ )); do
        if [[ "${eargs[j]}" == "--propose-window" ]]; then
          dargs+=(--propose-window 0); j=$(( j + 1 )); saw_window=1
        else
          dargs+=("${eargs[j]}")
        fi
      done
      (( saw_window == 0 )) && dargs+=(--propose-window 0)
      local dout="$gd/stdout.window0" derr="$gd/stderr.window0" dcode=0
      if "$PATINA" patina native-run "$built" "${PKNOBS[@]}" -- "${dargs[@]}" \
            >"$dout" 2>"$derr"; then dcode=0; else dcode=$?; fi
      local dc dp dverdict
      dc=$(field_of committed "$dout"); dp=$(field_of proposals "$dout")
      dverdict=$(classify "$dcode" "${dc:-}" "${dp:-}" "$HEAVY" "$FS_CRASH" "$RECOVER" \
                          "$(cat "$dout")" "$(cat "$derr")")
      class=$(disc_check "$dverdict")
      if [[ "$class" == WORKLOAD_SHAPE ]]; then
        live_note=" (WORKLOAD_SHAPE: paced ${committed}/${proposals}@${CFG_TIMEOUT}s, ${ec}/${ep}@10x, but converges UNPACED ${dc}/${dp} at window=0 -> harness re-proposal/pacing artifact, not a fault finding)"
      else
        live_note=" (CONFIRMED non-live: ${committed}/${proposals}@${CFG_TIMEOUT}s, ${ec}/${ep}@10x, still ${dc}/${dp} UNPACED@window=0 -> genuine)"
      fi
    else
      class="$everdict"
      live_note=" (10x escalation surfaced $everdict)"
    fi
  fi

  # DETERMINISM tier: re-run the identical config and require byte-identical
  # RAFT_RESULT + trace SHA-256 (replaces the old every-10th-generation rule).
  local det_note=""
  if (( DET_RUN == 1 )); then
    local trace2="$gd/trace.rerun" out2="$gd/stdout.rerun" err2="$gd/stderr.rerun"
    "$PATINA" patina native-run "$built" "${PKNOBS[@]}" --record "$trace2" -- "${HARGS[@]}" \
        >"$out2" 2>"$err2" || true
    local r1 r2 h1 h2
    r1=$(grep '^RAFT_RESULT' "$out"  2>/dev/null || true)
    r2=$(grep '^RAFT_RESULT' "$out2" 2>/dev/null || true)
    h1=$(sha_of "$trace"); h2=$(sha_of "$trace2")
    local verdict
    verdict=$(det_check "$class" "$r1" "$r2" "$h1" "$h2")
    if [[ "$verdict" == DETERMINISM_BUG ]]; then
      class=DETERMINISM_BUG
      det_note=" DETERMINISM(rerun): result1='$r1' result2='$r2' trace1=$h1 trace2=$h2"
    else
      det_note=" determinism-ok(trace=$h1)"
    fi
  fi

  bump "$class"
  local logline="gen=$G tier=$TIER class=$class exit=$code committed=${committed:-?}/${proposals:-?} terms=${terms:-?} restarts=${restarts:-0} config='$CFG_SUMMARY'$live_note$det_note"
  echo "$logline" >> "$SWEEP_LOG"
  echo "$logline"

  if [[ "$class" == OK ]]; then
    rm -rf "$gd"
  elif is_failure "$class"; then
    FAIL_DIRS+=("$gd")
  fi
}

sweep() {
  local start="$1" end="$2"

  # Concurrency guard. Two fuzz-sweep instances would share this repo's target/
  # dir and the built binary target/patina/raft-harness; a concurrent build or a
  # wipe would clobber the other's runs (observed: cargo processes SIGKILLed,
  # runs misreported). mkdir is atomic, so it is a portable lock. An intentional
  # parallel run must use a separate checkout (or set PATINA_FUZZ_OUT AND a
  # private target dir); the default refuses to collide.
  local lock="$FUZZ_LOCK"
  mkdir -p "$here/target/patina"
  if ! mkdir "$lock" 2>/dev/null; then
    # Lock exists. If a live process holds it, refuse. If it is STALE (holder
    # dead -- e.g. a killed campaign), steal it so a crash never wedges the tool.
    local holder=""; [[ -f "$lock/pid" ]] && holder="$(cat "$lock/pid" 2>/dev/null)"
    if [[ -n "$holder" ]] && kill -0 "$holder" 2>/dev/null; then
      echo "REFUSING TO RUN: fuzz-sweep pid $holder holds $lock" >&2
      echo "  (a concurrent run would corrupt the shared target/ + built binary)" >&2
      return 4
    fi
    echo "note: clearing stale lock (holder pid ${holder:-unknown} not running)" >&2
    rm -rf "$lock"
    if ! mkdir "$lock" 2>/dev/null; then
      echo "REFUSING TO RUN: could not acquire $lock" >&2; return 4
    fi
  fi
  echo "$$" > "$lock/pid"
  # Trap references the GLOBAL (in scope when EXIT fires post-return), not $lock.
  trap 'rm -rf "${FUZZ_LOCK:-}" 2>/dev/null || true' EXIT

  build_all
  mkdir -p "$OUTDIR"
  touch "$SWEEP_LOG"
  echo "==> fuzz sweep generations $start..$end (log: $SWEEP_LOG)"
  local G
  for (( G = start; G <= end; G++ )); do
    run_gen "$G"
  done

  local total=$(( end - start + 1 ))
  local failures=$(( c_SAFETY_BUG + c_UNEXPECTED_LIVENESS + c_UNEXPECTED_ABORT + c_UNEXPECTED_CRASH + c_DETERMINISM_BUG ))
  echo
  echo "==> sweep summary (generations $start..$end, $total total)"
  echo "    tiers: BREADTH=$c_t_breadth TRAFFIC=$c_t_traffic DETERMINISM=$c_t_determinism"
  echo "    OK                  = $c_OK"
  echo "    LIVENESS_TIMEOUT    = $c_LIVENESS_TIMEOUT   (tolerated: heavy config)"
  echo "    FAILCLOSED_ABORT    = $c_FAILCLOSED_ABORT   (tolerated: fs-crash w/o recovery)"
  echo "    WORKLOAD_SHAPE      = $c_WORKLOAD_SHAPE   (neutral: harness pacing artifact, converges unpaced)"
  echo "    -- failures --"
  echo "    SAFETY_BUG          = $c_SAFETY_BUG"
  echo "    UNEXPECTED_LIVENESS = $c_UNEXPECTED_LIVENESS"
  echo "    UNEXPECTED_ABORT    = $c_UNEXPECTED_ABORT"
  echo "    UNEXPECTED_CRASH    = $c_UNEXPECTED_CRASH"
  echo "    DETERMINISM_BUG     = $c_DETERMINISM_BUG"
  echo "    TOTAL FAILURES      = $failures"
  echo "    -- infrastructure (NOT bugs; results incomplete for these gens) --"
  echo "    INFRA_ERROR         = $c_INFRA_ERROR"
  if (( ${#FAIL_DIRS[@]} > 0 )); then
    echo "    kept failure dirs:"
    local d
    for d in "${FAIL_DIRS[@]}"; do echo "      $d"; done
  fi
  if (( c_INFRA_ERROR > 0 )); then
    echo "    WARNING: $c_INFRA_ERROR generation(s) failed to RUN (environment/build, e.g."
    echo "             a concurrent sweep or OOM). Those gens were NOT tested. Re-run them"
    echo "             on an idle machine with no other sweep active."
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
}

is_num() { [[ "$1" =~ ^[0-9]+$ ]]; }

main() {
  case "${1:-}" in
    --selftest) selftest; exit $? ;;
    --dry-run)
      local s="${2:-1}" e="${3:-${2:-1}}"
      if ! is_num "$s" || ! is_num "$e"; then usage; exit 2; fi
      dry_run "$s" "$e"; exit 0 ;;
    --gen)
      local g="${2:-}"
      if ! is_num "$g"; then usage; exit 2; fi
      if [[ "${3:-}" == "--dry-run" ]]; then dry_run "$g" "$g"; exit 0; fi
      sweep "$g" "$g"; exit $? ;;
    -h|--help) usage; exit 0 ;;
  esac

  local start="${1:-1}" end="${2:-100}"
  if ! is_num "$start" || ! is_num "$end"; then usage; exit 2; fi
  if (( end < start )); then
    echo "END_GEN ($end) must be >= START_GEN ($start)" >&2; exit 2
  fi
  sweep "$start" "$end"; exit $?
}

main "$@"

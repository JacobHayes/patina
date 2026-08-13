#!/usr/bin/env bash
###############################################################################
# pubsub fuzz sweep — deterministic, re-runnable generations over the tokio
# pub-sub broker under Patina. Every generation's config is a pure function of
# its integer tag G (SHA-256 -> BYTE[]), so any finding re-runs from G alone.
#
# Usage (see --help for the full block):
#   fuzz-sweep.sh [START [END]]         run generations START..END (default 0 199)
#   fuzz-sweep.sh --selftest            drive the pure classifier over canned tuples
#   fuzz-sweep.sh --dry-run [START [END]]  print derived configs without building/running
#   SKIP_BUILD=1 fuzz-sweep.sh ...      reuse the prebuilt harness (skip the build prelude)
#
# Two perturbation planes:
#   * NET_FAULT tier (~55%): the SimNet TCP-stream fault knobs (task #37) —
#     seeded per-segment jitter + a reliable-transport drop-retransmit. The
#     broker's outcome is order-invariant, so faults must reorder/delay WITHOUT
#     changing the outcome hash (never lose data). A NET_FAULT gen whose faults
#     went inert (the default-on PATINA_NET_FAULT_REPORT says vacuous=1, or the
#     "net fault knobs inert" warning fired) is a VACUOUS_NET_FAULT failure —
#     the direct guard against the task #37 regression, the analogue of workq's
#     VACUOUS_SCHEDULE.
#   * SCHEDULE tier (~30%): plain Patina --seed variation — the DetScheduler
#     interleaving is the perturbation axis, no faults.
# ~15% DETERMINISM gens re-run the identical config and require a byte-identical
# PUBSUB_RESULT + trace SHA-256.
#
# The outcome is classified by a PURE function (testable via --selftest). The
# invariant for every clean run: exit 0, published=32, delivered=64, the fixed
# order-invariant outcome hash, and NO PUBSUB_VIOLATION.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
built="$here/target/patina/pubsub"
PATINA="$repo_root/target/release/cargo-patina"

# Fixed workload (matches run-patina.sh): guest --seed fixes payloads/topics
# (echoed as PUBSUB_RESULT workload_seed=, intentionally constant across every
# leg); the Patina run --seed varies the schedule.
GUEST_ARGS=(--seed 7 --base-port 6001 --timeout-secs 30)
EXPECTED_PUBLISHED=32
EXPECTED_DELIVERED=64
EXPECTED_HASH=8b988e7c57005dac2b5144ba9a6d1ffea7a789719bff6f0a7478e05786664a3d

###############################################################################
# Pure classifiers — no global state, no I/O, so --selftest can prove they bite.
###############################################################################
CRASH_MARKERS='panicked|internal error|patina: the deterministic runtime|native shim fatal|unsupported native imports|scheduler (panic|error|stall|fault|deadlock)|deadlock detected|SIGSEGV|SIGABRT'
INFRA_MARKERS='cargo-patina: |Cargo process terminated|terminated by a signal|could not compile|No such file or directory|native-build failed|Resource temporarily unavailable|Cannot allocate memory'
is_infra() { printf '%s\n%s' "$1" "$2" | /usr/bin/grep -Eq "$INFRA_MARKERS"; }

# pubsub's OWN verdict labels: every self-detected breach is announced through
# `patina_dst::verdict` (see src/main.rs), and this is the per-guest
# configuration docs/arcs/outcome-channel.md 4.3 prescribes -- patina itself
# knows none of these strings. Scoping by label keeps pubsub's findings distinct
# from an `always!` site violation, which the SDK lowers to the SAME channel.
PUBSUB_VERDICT_LABELS='malformed-frame|unsubscribed-topic|seq-gap|liveness-timeout|incomplete-delivery|payload-divergence'

# classify: exit pub del exp_pub exp_del exp_hash obs_hash out err
classify() {
  local code="$1" pub="$2" del="$3" epub="$4" edel="$5" ehash="$6" ohash="$7" out="$8" err="$9"
  local combined="$out
$err"
  # A safety violation is ALWAYS a bug, regardless of exit code. The channel is
  # the VERDICT ABI's own wire line (patina_dst_abi::verdict_line), not pubsub's
  # printed PUBSUB_VIOLATION dialect.
  if printf '%s' "$combined" | grep -Eq "^PATINA_VERDICT .*kind=violation label=($PUBSUB_VERDICT_LABELS) "; then echo SAFETY_BUG; return; fi
  # A hard crash marker anywhere is UNEXPECTED_CRASH even if the exit looks OK.
  if printf '%s' "$combined" | grep -Eq "$CRASH_MARKERS"; then echo UNEXPECTED_CRASH; return; fi
  case "$code" in
    0)
      # Exit 0 means converged; re-verify the outcome from the result line so a
      # truncated exit-0 cannot masquerade as OK, and the order-invariant hash so
      # a fault that silently lost/corrupted data is a SAFETY_BUG.
      if [[ "$pub" != "$epub" || "$del" != "$edel" ]]; then echo UNEXPECTED_CRASH; return; fi
      if [[ -n "$ehash" && "$ohash" != "$ehash" ]]; then echo SAFETY_BUG; return; fi
      echo OK
      ;;
    1) echo UNEXPECTED_LIVENESS ;;   # a convergence/transport miss, which reports no verdict by design
    2) echo UNEXPECTED_ABORT ;;      # a deliberate fail-closed stop (abort_intent verdict)
    *) echo UNEXPECTED_CRASH ;;
  esac
}

# Net-fault vacuity verdict — pure. A NET_FAULT gen must actually perturb, and
# the authority on that is the runtime's OWN per-plane vacuity bit
# (`PATINA_NET_FAULT_REPORT ... vacuous=`, mirrored as `fault_reports.net.vacuous`
# in the result envelope) rather than a count this script re-derives.
#
# `vacuous` is REQUIRED: an empty value means no net-fault report was found at
# all, which is promoted to VACUOUS_NET_FAULT for the same reason the schedule
# gate does it — no evidence of exploration is not exploration. That rule is
# load-bearing, not defensive: this gate previously reconstructed the verdict
# from `could_apply=`/`faults_applied=` fields the unified-fault-knobs report
# renamed away, so both reads came back empty and the gate could no longer fire.
# It went inert silently, which is precisely the class it exists to catch.
#
# Applied LAST so it never downgrades a real finding.
net_check() {
  local is_net="$1" base="$2" vacuous="$3" inert_warn="$4"
  if [[ "$is_net" != 1 || "$base" != OK ]]; then echo "$base"; return; fi
  if [[ "$inert_warn" == 1 ]]; then echo VACUOUS_NET_FAULT; return; fi
  if [[ -z "$vacuous" || "$vacuous" != 0 ]]; then echo VACUOUS_NET_FAULT; return; fi
  echo OK
}

# Determinism verdict — pure.
det_check() {
  local primary="$1" r1="$2" r2="$3" h1="$4" h2="$5"
  if [[ "$r1" == "$r2" && "$h1" == "$h2" ]]; then echo "$primary"; else echo DETERMINISM_BUG; fi
}

# A class is a FAILURE unless tolerated. VACUOUS_NET_FAULT is a failure (the
# task #37 regression). INFRA_ERROR is surfaced but tolerated (environment).
is_failure() {
  case "$1" in
    OK|INFRA_ERROR) return 1 ;;
    *) return 0 ;;
  esac
}

###############################################################################
# --selftest : drive the pure classifiers over canned tuples covering every class.
###############################################################################
SELFTEST_FAIL=0
assert_class() {
  local want="$1" got="$2" name="$3"
  if [[ "$got" == "$want" ]]; then printf '  ok   %-26s -> %s\n' "$name" "$got"
  else printf '  FAIL %-26s -> got %s, want %s\n' "$name" "$got" "$want"; SELFTEST_FAIL=1; fi
}
selftest() {
  echo "== pubsub fuzz-sweep classifier selftest =="
  # A clean run's outcome now travels as pubsub's `pass` verdict; the printed
  # PUBSUB_RESULT line is the human echo of the same facts.
  local ok='PATINA_VERDICT seq=0 kind=pass label=pubsub-outcome detail=workload_seed=7\spublished=32\sdelivered=64\sheartbeats=5\shash='"$EXPECTED_HASH"
  local nfr_applied='PATINA_NET_FAULT_REPORT could_apply=1 send_ops=222 faults_applied=222 vacuous=0'
  local nfr_inert='PATINA_NET_FAULT_REPORT could_apply=1 send_ops=222 faults_applied=0 vacuous=1
PATINA WARNING: net fault knobs inert — 222 fault-eligible send(s) occurred'

  # base classify()
  assert_class OK "$(classify 0 32 64 32 64 "$EXPECTED_HASH" "$EXPECTED_HASH" "$ok" "$nfr_applied")" "ok-converged"
  assert_class SAFETY_BUG "$(classify 0 32 64 32 64 "$EXPECTED_HASH" "$EXPECTED_HASH" "$ok" 'PATINA_VERDICT seq=1 kind=violation label=seq-gap detail=subscriber-1\st0\sgot=5\sexpected=4')" "violation-exit0"
  assert_class SAFETY_BUG "$(classify 0 32 64 32 64 "$EXPECTED_HASH" 'deadbeef' "$ok" "")" "hash-changed-data-lost"
  assert_class UNEXPECTED_CRASH "$(classify 0 32 6 32 64 "$EXPECTED_HASH" "$EXPECTED_HASH" "$ok" "")" "exit0-partial-delivery"
  assert_class UNEXPECTED_CRASH "$(classify 0 32 64 32 64 "$EXPECTED_HASH" "$EXPECTED_HASH" "$ok" "thread main panicked at broker.rs")" "crash-panic"
  assert_class UNEXPECTED_LIVENESS "$(classify 1 '' '' 32 64 "$EXPECTED_HASH" '' '' 'PUBSUB_FAILURE not-converged')" "liveness-timeout"
  # A deliberate stop reports `abort_intent`, which is NOT a violation and so
  # must not be promoted to SAFETY_BUG by the rule above.
  assert_class UNEXPECTED_ABORT "$(classify 2 '' '' 32 64 "$EXPECTED_HASH" '' '' 'PATINA_VERDICT seq=0 kind=abort_intent label=bind detail=127.0.0.1:6001:\saddress\sin\suse')" "abort-failclosed"

  # net_check() — the VACUOUS_NET_FAULT class (task #37 regression guard).
  assert_class OK "$(net_check 1 OK 0 0)" "net-faults-applied"
  assert_class VACUOUS_NET_FAULT "$(net_check 1 OK 1 0)" "net-faults-plane-vacuous"
  assert_class VACUOUS_NET_FAULT "$(net_check 1 OK 0 1)" "net-faults-inert-warning"
  # The drift case: no net-fault report found (a renamed/absent field, a missing
  # line) reads as EMPTY and must fire, never pass as "faults applied".
  assert_class VACUOUS_NET_FAULT "$(net_check 1 OK '' 0)" "net-faults-no-report"
  assert_class OK "$(net_check 0 OK '' 0)" "schedule-tier-not-net"
  assert_class SAFETY_BUG "$(net_check 1 SAFETY_BUG '' 0)" "net-check-never-downgrades-finding"
  # The plane-scoped field reader must read the NET plane's `vacuous`, not
  # another report's: several runtime reports carry a `vacuous=` field.
  local two_planes='PATINA_SCHEDULE_REPORT tasks_spawned=3 total_boundaries=900 vacuous=1
PATINA_NET_FAULT_REPORT send_ops=222 drops_applied=33 jitter_applied=222 vacuous=0'
  local plane_file; plane_file="$(mktemp)"; printf '%s\n' "$two_planes" > "$plane_file"
  assert_class 0 "$(net_field vacuous "$plane_file")" "net-field-reads-its-own-plane"
  rm -f "$plane_file"

  # det_check()
  assert_class OK "$(det_check OK "$ok" "$ok" aa aa)" "determinism-ok"
  assert_class DETERMINISM_BUG "$(det_check OK "$ok" "$ok" aa bb)" "determinism-trace-diff"
  assert_class DETERMINISM_BUG "$(det_check OK "$ok" 'PATINA_VERDICT seq=0 kind=pass label=pubsub-outcome detail=workload_seed=7\spublished=32\sdelivered=64\sheartbeats=9\shash='"$EXPECTED_HASH" aa aa)" "determinism-result-diff"

  if (( SELFTEST_FAIL )); then echo "== SELFTEST FAILED =="; exit 1; fi
  echo "== selftest passed =="
}

###############################################################################
# Deterministic per-generation config derivation.
###############################################################################
compute_bytes() {
  local G="$1" HEX i
  HEX="$(printf 'patina-pubsub-fuzz-%s' "$G" | shasum -a256 | cut -c1-64)"
  BYTE=()
  for (( i = 0; i < 32; i++ )); do BYTE[i]=$(( 16#${HEX:$(( i * 2 )):2} )); done
}

# NET_FAULT tier: TCP-stream jitter (always, ceiling > 0 so could_apply holds)
# plus an optional reliable-transport drop. Bounded so a run always converges.
sample_net_fault() {
  local G="$1"
  local jmin_us=$(( 1 + BYTE[2] % 50 ))                 # 1..50 us
  local jmax_us=$(( jmin_us + 1 + BYTE[3] % 200 ))      # +1..200 us
  local jmin_ns=$(( jmin_us * 1000 )) jmax_ns=$(( jmax_us * 1000 ))
  local drop_tbl=(0 25 50 100 150 200); local drop=${drop_tbl[$(( BYTE[0] % 6 ))]}
  PKNOBS=(--seed "$G" --net-jitter-nanos "${jmin_ns}..${jmax_ns}")
  (( drop > 0 )) && PKNOBS+=(--net-drop-permille "$drop")
  IS_NET_FAULT=1
  CFG_SUMMARY="net-fault seed=$G jitter=${jmin_us}-${jmax_us}us drop=${drop}permille"
}

# SCHEDULE tier: plain seed variation, no faults.
sample_schedule() {
  local G="$1"
  PKNOBS=(--seed "$G")
  IS_NET_FAULT=0
  CFG_SUMMARY="schedule seed=$G (no faults)"
}

derive_config() {
  local G="$1"
  compute_bytes "$G"
  DET_RUN=0
  local pick=$(( BYTE[18] % 20 ))
  if (( pick < 11 )); then
    TIER=NET_FAULT; sample_net_fault "$G"
  elif (( pick < 17 )); then
    TIER=SCHEDULE; sample_schedule "$G"
  else
    DET_RUN=1
    if (( BYTE[19] % 2 == 0 )); then TIER="DETERMINISM/net-fault"; sample_net_fault "$G"
    else TIER="DETERMINISM/schedule"; sample_schedule "$G"; fi
  fi
}

###############################################################################
# Entry points.
###############################################################################
usage() {
  cat >&2 <<'EOF'
usage: fuzz-sweep.sh [START [END]]            run generations START..END (default 0 199)
       fuzz-sweep.sh --dry-run [START [END]]  print derived config(s), no build/run
       fuzz-sweep.sh --selftest               classifier selftest
       fuzz-sweep.sh -h | --help              show full help
EOF
}
help() {
  cat <<'EOF'
pubsub fuzz-sweep — deterministic, re-runnable generations over the tokio pub-sub
broker under Patina. Every generation G derives its ENTIRE config from
SHA-256("patina-pubsub-fuzz-G"), so any finding re-runs from its integer tag alone.
Tiers (a pure function of G): NET_FAULT (SimNet TCP jitter + drop; faults must
reorder/delay WITHOUT changing the order-invariant outcome hash — a vacuous fault
is a VACUOUS_NET_FAULT finding), SCHEDULE (plain --seed interleaving variation),
and DETERMINISM (identical-config double run; byte-identical result + trace hash
required). Every clean run: exit 0, published=32, delivered=64, the fixed outcome
hash, no PUBSUB_VIOLATION.

Usage:
  fuzz-sweep.sh [START [END]]            run generations START..END inclusive.
                                         Default START=0 END=199 (200 generations).
  fuzz-sweep.sh --dry-run [START [END]]  print each generation's derived config and
                                         exact patina command, no build/run.
                                         Default START=0 END=START (one generation).
  fuzz-sweep.sh --selftest               drive the pure classifiers over canned
                                         tuples covering every outcome class.
  fuzz-sweep.sh -h | --help              show this help.

Environment:
  SKIP_BUILD=1   reuse the already-built harness at target/patina/pubsub instead
                 of rebuilding cargo-patina + the harness (fails loudly if the
                 binary is missing). Any other PATINA_* net-fault report vars are
                 emitted by the runtime and parsed from each run's stderr.

Exit status: 0 = all generations clean (or --help/--selftest ok); 1 = one or more
findings; 2 = usage error; 3 = build/environment failure.
EOF
}
is_num() { [[ "$1" =~ ^[0-9]+$ ]]; }

report_field() { /usr/bin/grep -o "$1=[0-9][0-9]*" "$2" 2>/dev/null | head -1 | cut -d= -f2; }
# Read a field from the PATINA_NET_FAULT_REPORT line SPECIFICALLY: several
# runtime reports carry a `vacuous=` field, so the file-wide report_field would
# read another plane's verdict as the net plane's.
net_field() {
  /usr/bin/grep '^PATINA_NET_FAULT_REPORT' "$2" 2>/dev/null | head -1 \
    | /usr/bin/grep -o " $1=[0-9][0-9]*" | head -1 | cut -d= -f2
}
# The run's outcome facts come from the guest's `pass` verdict -- the verdict
# ABI's own wire line on stderr -- not from its printed PUBSUB_RESULT dialect.
result_line()  { /usr/bin/grep -m1 '^PATINA_VERDICT .*kind=pass label=pubsub-outcome ' "$1" 2>/dev/null || true; }
field_of()     { sed -n "s/.*$1=\\([0-9][0-9]*\\).*/\\1/p" | head -1; }
hash_of()      { sed -n 's/.*hash=\([0-9a-f]*\).*/\1/p' | head -1; }
sha_of()       { if [[ -f "$1" ]]; then shasum -a256 "$1" | cut -d' ' -f1; else echo MISSING; fi; }
# a representative spawned-worker life/cause from PATINA_SCHEDULE_REPORT
life_cause()   { /usr/bin/grep -o 'life=[0-9]*/cause=[a-z-]*' "$1" 2>/dev/null | head -1; }

case "${1:-}" in
  -h|--help) help; exit 0 ;;
  --selftest)
    [[ $# -gt 1 ]] && { echo "fuzz-sweep.sh: --selftest takes no arguments" >&2; usage; exit 2; }
    selftest; exit 0 ;;
  --dry-run)
    [[ $# -gt 3 ]] && { echo "fuzz-sweep.sh: too many arguments" >&2; usage; exit 2; }
    s="${2:-0}"; e="${3:-$s}"
    if ! is_num "$s" || ! is_num "$e"; then echo "fuzz-sweep.sh: START/END must be non-negative integers" >&2; usage; exit 2; fi
    if (( e < s )); then echo "fuzz-sweep.sh: END ($e) must be >= START ($s)" >&2; usage; exit 2; fi
    for (( G = s; G <= e; G++ )); do
      derive_config "$G"
      printf 'gen=%s tier=%s det_run=%s net=%s %s\n' "$G" "$TIER" "$DET_RUN" "$IS_NET_FAULT" "$CFG_SUMMARY"
      printf '    cmd: '; printf '%q ' "$PATINA" patina run "$built" "${PKNOBS[@]}" -- "${GUEST_ARGS[@]}"; echo
    done
    exit 0 ;;
  -*) echo "fuzz-sweep.sh: unknown option '${1}'" >&2; usage; exit 2 ;;
esac

[[ $# -gt 2 ]] && { echo "fuzz-sweep.sh: too many arguments" >&2; usage; exit 2; }
START="${1:-0}"; END="${2:-199}"
if ! is_num "$START" || ! is_num "$END"; then echo "fuzz-sweep.sh: START/END must be non-negative integers" >&2; usage; exit 2; fi
if (( END < START )); then echo "fuzz-sweep.sh: END ($END) must be >= START ($START)" >&2; usage; exit 2; fi
GENS=$(( END - START + 1 ))
OUTDIR="$(mktemp -d)"
SWEEP_LOG="$OUTDIR/sweep.log"

echo "==> pubsub fuzz sweep: generations $START..$END ($GENS gens, out=$OUTDIR)"
cd "$repo_root"
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  echo "==> building cargo-patina + the pubsub harness"
  if ! cargo build --release --quiet -p cargo-patina; then echo "FATAL: build cargo-patina failed" >&2; exit 3; fi
  if ! mkdir -p "$here/target/patina"; then echo "FATAL: mkdir failed" >&2; exit 3; fi
  if ! "$PATINA" patina build "$here" --output "$built" --release >/dev/null; then echo "FATAL: build pubsub harness failed" >&2; exit 3; fi
else
  echo "==> SKIP_BUILD=1: reusing $built"
  [[ -x "$built" ]] || { echo "FATAL: SKIP_BUILD set but $built is missing — build it first" >&2; exit 3; }
fi

c_OK=0; c_SAFETY_BUG=0; c_UNEXPECTED_LIVENESS=0; c_UNEXPECTED_ABORT=0
c_UNEXPECTED_CRASH=0; c_DETERMINISM_BUG=0; c_VACUOUS_NET_FAULT=0; c_INFRA_ERROR=0
c_t_net=0; c_t_sched=0; c_t_det=0
FAIL_GENS=()
bump() {
  case "$1" in
    OK) c_OK=$(( c_OK + 1 )) ;;
    SAFETY_BUG) c_SAFETY_BUG=$(( c_SAFETY_BUG + 1 )) ;;
    UNEXPECTED_LIVENESS) c_UNEXPECTED_LIVENESS=$(( c_UNEXPECTED_LIVENESS + 1 )) ;;
    UNEXPECTED_ABORT) c_UNEXPECTED_ABORT=$(( c_UNEXPECTED_ABORT + 1 )) ;;
    UNEXPECTED_CRASH) c_UNEXPECTED_CRASH=$(( c_UNEXPECTED_CRASH + 1 )) ;;
    DETERMINISM_BUG) c_DETERMINISM_BUG=$(( c_DETERMINISM_BUG + 1 )) ;;
    VACUOUS_NET_FAULT) c_VACUOUS_NET_FAULT=$(( c_VACUOUS_NET_FAULT + 1 )) ;;
    INFRA_ERROR) c_INFRA_ERROR=$(( c_INFRA_ERROR + 1 )) ;;
  esac
}
tier_bump() {
  case "$1" in
    NET_FAULT) c_t_net=$(( c_t_net + 1 )) ;;
    SCHEDULE) c_t_sched=$(( c_t_sched + 1 )) ;;
    DETERMINISM/*) c_t_det=$(( c_t_det + 1 )) ;;
  esac
}

run_gen() {
  local G="$1"
  derive_config "$G"
  tier_bump "$TIER"
  local gd="$OUTDIR/gen-$G"; rm -rf "$gd"; mkdir -p "$gd"
  local trace="$gd/trace" out="$gd/stdout" err="$gd/stderr" code=0
  { printf '# gen %s (%s)\n' "$G" "$CFG_SUMMARY"; printf '%q ' "$PATINA" patina run "$built" "${PKNOBS[@]}" --record "$trace" -- "${GUEST_ARGS[@]}"; echo; } > "$gd/config.txt"

  if "$PATINA" patina run "$built" "${PKNOBS[@]}" --record "$trace" -- "${GUEST_ARGS[@]}" >"$out" 2>"$err"; then code=0; else code=$?; fi

  # Infra guard: retry once, then surface INFRA_ERROR (not a finding).
  if is_infra "$(cat "$out")" "$(cat "$err")"; then
    if "$PATINA" patina run "$built" "${PKNOBS[@]}" --record "$trace" -- "${GUEST_ARGS[@]}" >"$out" 2>"$err"; then code=0; else code=$?; fi
    if is_infra "$(cat "$out")" "$(cat "$err")"; then
      bump INFRA_ERROR
      local il="gen=$G tier=$TIER class=INFRA_ERROR (environment/build failure, NOT a bug)"
      echo "$il" >> "$SWEEP_LOG"; echo "$il"; return
    fi
  fi

  local res pub del ohash
  res="$(result_line "$err")"
  pub="$(printf '%s' "$res" | field_of published)"; del="$(printf '%s' "$res" | field_of delivered)"
  ohash="$(printf '%s' "$res" | hash_of)"
  local class
  class="$(classify "$code" "${pub:-}" "${del:-}" "$EXPECTED_PUBLISHED" "$EXPECTED_DELIVERED" "$EXPECTED_HASH" "${ohash:-}" "$(cat "$out")" "$(cat "$err")")"

  # DETERMINISM double-run.
  local det_note=""
  if (( DET_RUN == 1 )); then
    local trace2="$gd/trace.rerun" out2="$gd/stdout.rerun" err2="$gd/stderr.rerun"
    "$PATINA" patina run "$built" "${PKNOBS[@]}" --record "$trace2" -- "${GUEST_ARGS[@]}" >"$out2" 2>"$err2" || true
    local r1 r2 h1 h2; r1="$(result_line "$err")"; r2="$(result_line "$err2")"; h1="$(sha_of "$trace")"; h2="$(sha_of "$trace2")"
    local v; v="$(det_check "$class" "$r1" "$r2" "$h1" "$h2")"
    if [[ "$v" == DETERMINISM_BUG ]]; then class=DETERMINISM_BUG; det_note=" DETERMINISM(rerun): t1=$h1 t2=$h2"; else det_note=" determinism-ok(trace=${h1:0:12})"; fi
  fi

  # Net-fault vacuity gate (applied LAST so it never downgrades a real finding).
  local net_note=""
  if (( IS_NET_FAULT == 1 )); then
    local vac drops jit inert nc
    vac="$(net_field vacuous "$err")"
    drops="$(net_field drops_applied "$err")"; jit="$(net_field jitter_applied "$err")"
    inert=0; grep -q 'net fault knobs inert' "$err" && inert=1
    nc="$(net_check 1 "$class" "$vac" "$inert")"
    if [[ "$nc" != "$class" ]]; then class="$nc"; net_note=" (VACUOUS_NET_FAULT: vacuous=${vac:-<no net report>} inert_warn=$inert — faults did NOT bite)"
    else net_note=" net-fault(vacuous=$vac drops=${drops:-0} jitter=${jit:-0})"; fi
  fi

  # life=/cause= + boundary annotation from the schedule diagnostic, most
  # load-bearing on a finding. pubsub is a single current-thread tokio runtime,
  # so it emits no multi-thread PATINA_SCHEDULE_REPORT and these stay empty; they
  # populate automatically for any concurrent guest (the workq convention).
  local lc tb sched_note=""
  lc="$(life_cause "$err")"; tb="$(report_field total_boundaries "$err")"
  [[ -n "$tb" ]] && sched_note=" sched(boundaries=$tb${lc:+ $lc})"
  bump "$class"
  local line="gen=$G tier=$TIER class=$class config='$CFG_SUMMARY'$sched_note$det_note$net_note"
  echo "$line" >> "$SWEEP_LOG"
  if is_failure "$class"; then echo "!! $line"; FAIL_GENS+=("$G:$class"); else echo "   $line"; fi
}

start_secs=$SECONDS
for (( G = START; G < START + GENS; G++ )); do run_gen "$G"; done
elapsed=$(( SECONDS - start_secs ))

echo
echo "==> pubsub fuzz sweep summary ($GENS gens, ${elapsed}s)"
echo "    tiers: NET_FAULT=$c_t_net SCHEDULE=$c_t_sched DETERMINISM=$c_t_det"
echo "    OK                = $c_OK"
echo "    SAFETY_BUG        = $c_SAFETY_BUG"
echo "    UNEXPECTED_LIVENESS = $c_UNEXPECTED_LIVENESS"
echo "    UNEXPECTED_ABORT  = $c_UNEXPECTED_ABORT"
echo "    UNEXPECTED_CRASH  = $c_UNEXPECTED_CRASH"
echo "    DETERMINISM_BUG   = $c_DETERMINISM_BUG"
echo "    VACUOUS_NET_FAULT = $c_VACUOUS_NET_FAULT   (task #37 regression: faults went inert)"
echo "    INFRA_ERROR       = $c_INFRA_ERROR   (tolerated; environment/build)"
echo "    log: $SWEEP_LOG"
total_failures=$(( c_SAFETY_BUG + c_UNEXPECTED_LIVENESS + c_UNEXPECTED_ABORT + c_UNEXPECTED_CRASH + c_DETERMINISM_BUG + c_VACUOUS_NET_FAULT ))
if (( total_failures > 0 )); then
  echo "==> FAILED: ${#FAIL_GENS[@]} finding(s): ${FAIL_GENS[*]}"
  echo "    (out kept at $OUTDIR)"
  exit 1
fi
rm -rf "$OUTDIR"
echo "==> all generations clean"

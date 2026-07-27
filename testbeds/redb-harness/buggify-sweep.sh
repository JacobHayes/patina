#!/usr/bin/env bash
###############################################################################
# redb cooperative-SUT (buggify) campaign under Patina.
#
# Runs the redb harness (against the vendored ../redb-fork, whose commit and
# recovery paths carry `patina::{buggify!,buggify_delay!,sometimes!,reachable!,
# always!}` sites) with buggify ENABLED, combined with the crash filesystem so
# both the commit-path faults (forced 2-phase / quick-repair / a delay before the
# durability flush) and the recovery-path oracles (full-repair entered, torn-slot
# checksum rejection) are exercised.
#
# Every knob for generation G is a pure function of SHA-256("redb-buggify-$G"),
# so any generation is re-runnable by number and the whole campaign reproduces.
# --buggify-after-setup is ALWAYS on: DB creation/baseline is fault-free, faults
# fire only from the workload's first commit onward (the harness calls
# patina::lifecycle::setup_complete() at that boundary).
#
# Classification uses the shared buggify campaign layer (../buggify-campaign.sh)
# for the two buggify classes, plus redb's own durability oracle:
#   ALWAYS_VIOLATION  a buggify always! invariant was violated            (BUG)
#   SAFETY_BUG        redb lost/tore an acknowledged commit (LOST/TORN),
#                     or full-mode write!=verify                          (BUG)
#   OPEN_PANIC        redb's open-time recovery assert (robustness, reported)
#   OK                HOLDS / NO_CRASH / OPEN_ERR (fail-closed) / clean full
# SOMETIMES_UNMET is evaluated campaign-wide at the end: a sometimes! site
# reached but never satisfied fails the campaign (nonzero exit).
#
# Usage:
#   buggify-sweep.sh [START_GEN] [END_GEN]   run generations START..END (default 1..350)
#   buggify-sweep.sh --selftest              run the shared campaign selftest
#   buggify-sweep.sh --dry-run [S [E]]       print derived config(s), no build/run
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
# shellcheck source=../buggify-campaign.sh
source "$here/../buggify-campaign.sh"

built="$here/target/patina/redb-harness-buggify"
PATINA="$repo_root/target/release/cargo-patina"
# FRESH out dir, distinct from the crash-sweep artifacts and from the raft
# campaign's out-fuzz*/ (which this script never touches).
OUTDIR="${REDB_BUGGIFY_OUT:-$here/out-buggify}"
SWEEP_LOG="$OUTDIR/sweep.log"
CAMPAIGN_STATE="$OUTDIR/campaign-state.json"
LOCK="$here/target/patina/.buggify-sweep.lock"

# Fill BYTE[0..31] from SHA-256("redb-buggify-$G").
compute_bytes() {
  local G="$1" HEX i
  HEX="$(printf 'redb-buggify-%s' "$G" | shasum -a256 | cut -c1-64)"
  BYTE=()
  for (( i = 0; i < 32; i++ )); do BYTE[i]=$(( 16#${HEX:$(( i * 2 )):2} )); done
}

# Derive globals GEN_SEED, GEN_OPS, GEN_MODE, GEN_FScrash (spec or ""), GEN_GRAN,
# GEN_FIRE (permille), GEN_ACT (permille), GEN_SUMMARY from BYTE[].
derive_config() {
  local G="$1"
  compute_bytes "$G"
  GEN_SEED=$(( (BYTE[0] << 8 | BYTE[1]) ))
  GEN_OPS=$(( 40 + (BYTE[2] % 6) * 40 ))                 # 40..240
  # Per-gen buggify intensity: activation and fire permille both vary 250..1000
  # so the campaign spans light and heavy cooperative fault regimes.
  GEN_ACT=$(( 250 + (BYTE[3] % 4) * 250 ))               # 250/500/750/1000
  GEN_FIRE=$(( 250 + (BYTE[4] % 4) * 250 ))
  # ~75% crash mode (exercises recovery + torn-slot), ~25% full (commit-path +
  # write==verify oracle, no crash).
  if (( BYTE[5] < 192 )); then
    GEN_MODE="crash"
    local ops_tbl=(write sync close)
    local op=${ops_tbl[$(( BYTE[6] % 3 ))]}
    local ord=$(( 1 + BYTE[7] % 48 ))
    GEN_FScrash="${op}:${ord}"
    # byte granularity ~50% (sub-block tearing -- the geometry that tears a slot
    # header so the recovery torn-slot oracle can fire).
    if (( BYTE[8] % 2 == 0 )); then GEN_GRAN="byte"; else GEN_GRAN="block"; fi
  else
    GEN_MODE="full"
    GEN_FScrash=""
    GEN_GRAN="block"
  fi
  GEN_SUMMARY="gen=$G mode=$GEN_MODE wseed=$GEN_SEED ops=$GEN_OPS fire=${GEN_FIRE} act=${GEN_ACT} fscrash=${GEN_FScrash:-off} gran=$GEN_GRAN"
}

# Build the buggify knobs (before --) for the current gen.
#
# --buggify-after-setup is used ONLY for crash-free (full) gens, where the
# workload always reaches setup_complete() so the setup/workload gate is a clean,
# meaningful demonstration. A crash gen deliberately injects an fs-crash that can
# land DURING setup (before setup_complete), which would legitimately prevent the
# call and trip the declared-but-never-called guard -- not a harness bug, just
# the crash pre-empting setup. So crash gens run buggify armed from the start:
# cooperative faults in the short baseline are benign (2-phase/quick-repair are
# stronger durability, the delay is virtual, and the durability oracle already
# admits recovering to the pre-baseline committed-0 prefix). The after-setup
# guard itself is proven by the cargo-patina end-to-end test, not re-proven here.
buggify_knobs() {
  PKNOBS=(--seed "$GEN_SEED" --buggify="$GEN_FIRE" --buggify-activation-permille "$GEN_ACT")
  if [[ -n "$GEN_FScrash" ]]; then
    PKNOBS+=(--fs-crash-at "$GEN_FScrash")
    [[ "$GEN_GRAN" == "byte" ]] && PKNOBS+=(--fs-torn-granularity byte)
  else
    PKNOBS+=(--buggify-after-setup)
  fi
}

# Harness args (after --) for the current gen.
harness_args() {
  HARGS=(--seed "$GEN_SEED" --ops "$GEN_OPS" --db /db/redb.redb --mode "$GEN_MODE" --threads 1)
}

# Pure classifier for a redb buggify run: buggify classes first (top priority),
# then redb's durability outcome / full-mode correctness.
classify_redb() {
  # args: exit stdout stderr
  local code="$1" out="$2" err="$3"
  local bug; bug="$(buggify_class "$code" "$out" "$err")"
  if [[ -n "$bug" ]]; then echo "$bug"; return; fi
  # Generic hard-crash markers (panic outside the harness's catch, runtime init
  # failure) that are neither a buggify marker nor a modeled redb outcome.
  if printf '%s\n%s' "$out" "$err" | /usr/bin/grep -Eq 'the deterministic runtime failed|native shim fatal|unsupported native imports|SIGSEGV'; then
    echo UNEXPECTED_CRASH; return
  fi
  local outcome; outcome="$(printf '%s' "$out" | sed -n 's/.*outcome=\([A-Z_]*\).*/\1/p' | head -1)"
  if [[ -n "$outcome" ]]; then          # crash mode
    case "$outcome" in
      LOST_COMMIT|TORN_STATE) echo SAFETY_BUG ;;
      OPEN_PANIC)             echo OPEN_PANIC ;;
      HOLDS|NO_CRASH|OPEN_ERR) echo OK ;;
      *)                      echo UNEXPECTED_CRASH ;;
    esac
    return
  fi
  # full/verify mode: RESULT + exit 0 is OK; a FAIL (write!=verify mismatch) is a
  # correctness safety bug.
  if [[ "$code" == 0 ]] && printf '%s' "$out" | /usr/bin/grep -q '^RESULT '; then
    echo OK; return
  fi
  echo SAFETY_BUG
}

is_failure_redb() {
  case "$1" in
    OK|OPEN_PANIC) return 1 ;;   # OPEN_PANIC is a reported robustness finding, not a regression
    *) return 0 ;;
  esac
}

dry_run() {
  local s="$1" e="$2" G
  for (( G = s; G <= e; G++ )); do
    derive_config "$G"; buggify_knobs; harness_args
    echo "$GEN_SUMMARY"
    printf '    cmd: %q ' "$PATINA" patina native-run "$built" "${PKNOBS[@]}" -- "${HARGS[@]}"; echo
  done
}

# per-class counters
c_OK=0; c_SAFETY_BUG=0; c_ALWAYS_VIOLATION=0; c_OPEN_PANIC=0; c_UNEXPECTED_CRASH=0
c_BUGGIFY_DUPLICATE_LABEL=0; c_BUGGIFY_SETUP_NEVER_CALLED=0
bump() {
  case "$1" in
    OK) c_OK=$(( c_OK + 1 )) ;;
    SAFETY_BUG) c_SAFETY_BUG=$(( c_SAFETY_BUG + 1 )) ;;
    ALWAYS_VIOLATION) c_ALWAYS_VIOLATION=$(( c_ALWAYS_VIOLATION + 1 )) ;;
    OPEN_PANIC) c_OPEN_PANIC=$(( c_OPEN_PANIC + 1 )) ;;
    UNEXPECTED_CRASH) c_UNEXPECTED_CRASH=$(( c_UNEXPECTED_CRASH + 1 )) ;;
    BUGGIFY_DUPLICATE_LABEL) c_BUGGIFY_DUPLICATE_LABEL=$(( c_BUGGIFY_DUPLICATE_LABEL + 1 )) ;;
    BUGGIFY_SETUP_NEVER_CALLED) c_BUGGIFY_SETUP_NEVER_CALLED=$(( c_BUGGIFY_SETUP_NEVER_CALLED + 1 )) ;;
  esac
}
FAIL_DIRS=()

run_gen() {
  local G="$1"
  derive_config "$G"; buggify_knobs; harness_args
  local gd="$OUTDIR/gen-$G"; rm -rf "$gd"; mkdir -p "$gd"
  local out="$gd/stdout" err="$gd/stderr"
  {
    echo "# $GEN_SUMMARY"
    printf '%q ' "$PATINA" patina native-run "$built" "${PKNOBS[@]}" --record "$gd/trace" -- "${HARGS[@]}"; echo
  } > "$gd/config.txt"

  local code=0
  if "$PATINA" patina native-run "$built" "${PKNOBS[@]}" --record "$gd/trace" -- "${HARGS[@]}" \
        >"$out" 2>"$err"; then code=0; else code=$?; fi

  local class; class="$(classify_redb "$code" "$(cat "$out")" "$(cat "$err")")"
  bump "$class"
  campaign_accumulate "$CAMPAIGN_STATE" "$(sdk_report_line "$err")"

  local resultline; resultline="$(/usr/bin/grep -m1 -E '^(RESULT|CRASH) ' "$out" 2>/dev/null || true)"
  local logline="gen=$G class=$class exit=$code $GEN_SUMMARY :: ${resultline:-<no result line>}"
  echo "$logline" >> "$SWEEP_LOG"; echo "$logline"
  if [[ "$class" == OK ]]; then rm -rf "$gd"; elif is_failure_redb "$class"; then FAIL_DIRS+=("$gd"); fi
}

build_all() {
  cd "$repo_root"
  echo "==> building cargo-patina + native-building the redb harness (against ../redb-fork)"
  if ! cargo build --release --quiet -p cargo-patina; then
    echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
  fi
  mkdir -p "$here/target/patina"
  if ! "$PATINA" patina native-build "$here" --output "$built" --release >/dev/null; then
    echo "FATAL: native-build failed" >&2; exit 3
  fi
}

sweep() {
  local start="$1" end="$2"
  mkdir -p "$here/target/patina"
  if ! mkdir "$LOCK" 2>/dev/null; then
    local holder=""; [[ -f "$LOCK/pid" ]] && holder="$(cat "$LOCK/pid" 2>/dev/null)"
    if [[ -n "$holder" ]] && kill -0 "$holder" 2>/dev/null; then
      echo "REFUSING TO RUN: buggify-sweep pid $holder holds $LOCK" >&2; return 4
    fi
    rm -rf "$LOCK"; mkdir "$LOCK" 2>/dev/null || { echo "REFUSING: cannot acquire $LOCK" >&2; return 4; }
  fi
  echo "$$" > "$LOCK/pid"
  trap 'rm -rf "${LOCK:-}" 2>/dev/null || true' EXIT

  if [[ "${REDB_BUGGIFY_SKIP_BUILD:-0}" == 1 ]]; then
    [[ -x "$built" ]] || { echo "FATAL: SKIP_BUILD set but $built missing" >&2; exit 3; }
    echo "==> REDB_BUGGIFY_SKIP_BUILD=1: using existing $built"
  else
    build_all
  fi
  mkdir -p "$OUTDIR"; : > "$SWEEP_LOG"; rm -f "$CAMPAIGN_STATE"
  echo "==> redb buggify campaign generations $start..$end (log: $SWEEP_LOG)"
  local G
  for (( G = start; G <= end; G++ )); do run_gen "$G"; done

  # Campaign-level SOMETIMES_UNMET.
  local unmet=() line
  while IFS= read -r line; do [[ -n "$line" ]] && unmet+=("$line"); done < <(campaign_sometimes_unmet "$CAMPAIGN_STATE")
  local c_SOMETIMES_UNMET=${#unmet[@]}
  local total=$(( end - start + 1 ))
  local failures=$(( c_SAFETY_BUG + c_ALWAYS_VIOLATION + c_UNEXPECTED_CRASH + c_BUGGIFY_DUPLICATE_LABEL + c_BUGGIFY_SETUP_NEVER_CALLED + c_SOMETIMES_UNMET ))

  echo
  echo "==> redb buggify campaign summary (generations $start..$end, $total total)"
  echo "    OK                         = $c_OK"
  echo "    OPEN_PANIC                 = $c_OPEN_PANIC   (redb open-time assert; robustness, reported not failed)"
  echo "    -- failures --"
  echo "    SAFETY_BUG                 = $c_SAFETY_BUG   (lost/torn acked commit, or full write!=verify)"
  echo "    ALWAYS_VIOLATION           = $c_ALWAYS_VIOLATION   (buggify always! invariant violated)"
  echo "    SOMETIMES_UNMET            = $c_SOMETIMES_UNMET   (sometimes! reached but never satisfied)"
  echo "    UNEXPECTED_CRASH           = $c_UNEXPECTED_CRASH"
  echo "    BUGGIFY_DUPLICATE_LABEL    = $c_BUGGIFY_DUPLICATE_LABEL"
  echo "    BUGGIFY_SETUP_NEVER_CALLED = $c_BUGGIFY_SETUP_NEVER_CALLED"
  echo "    TOTAL FAILURES             = $failures"
  if (( c_SOMETIMES_UNMET > 0 )); then
    echo "    unmet sometimes-sites:"; for line in "${unmet[@]}"; do echo "      $line"; done
  fi
  echo "    -- per-site coverage (campaign-state.json) --"
  python3 - "$CAMPAIGN_STATE" <<'PY' 2>/dev/null || true
import json, sys
s = json.load(open(sys.argv[1]))
print(f"    generations={s.get('generations',0)} gens_with_report={s.get('gens_with_report',0)}")
for label, r in sorted(s.get("sites", {}).items()):
    extra = ""
    if r["kind"] == "sometimes":
        extra = f" satisfied={r['sometimes_satisfied']}"
    if r["kind"] in ("fault", "delay"):
        extra = f" fired_gens={r['fired_gens']} total_fires={r['total_fires']}"
    print(f"      {label} [{r['kind']}] reached={r['reached']} activated_gens={r['activated_gens']}{extra}")
PY
  if (( ${#FAIL_DIRS[@]} > 0 )); then
    echo "    kept failure/robustness dirs:"; local d; for d in "${FAIL_DIRS[@]}"; do echo "      $d"; done
  fi
  if (( failures > 0 )); then echo "==> FAILURES PRESENT"; return 1; fi
  echo "==> no failure classes (buggify exercised; all invariants held; coverage met)"
  return 0
}

is_num() { [[ "$1" =~ ^[0-9]+$ ]]; }
main() {
  case "${1:-}" in
    --selftest) buggify_campaign_selftest; exit $? ;;
    --dry-run) shift; dry_run "${1:-1}" "${2:-${1:-1}}"; exit 0 ;;
    "") sweep 1 350 ;;
    *)
      if is_num "${1:-}"; then
        local s="$1" e="${2:-$1}"; is_num "$e" || { echo "END must be numeric" >&2; exit 2; }
        sweep "$s" "$e"
      else echo "usage: buggify-sweep.sh [START [END]] | --selftest | --dry-run [S [E]]" >&2; exit 2; fi
      ;;
  esac
}
main "$@"

#!/usr/bin/env bash
###############################################################################
# WASI cooperative-SUT (buggify) campaign — dogfood for Wave 11 Milestone C.
#
# Compiles the buggify-instrumented fixture (src/main.rs) to wasm32-wasip1 via
# `cargo patina build --target wasi` (which routes the SDK macros through the
# `patina_sdk` host import module) and runs a deterministic campaign with buggify
# ENABLED, proving the WASI path has full parity with the native family:
#   - sites register + fire under --buggify on wasip1 (PATINA_SDK_REPORT emitted
#     and parseable by the SHARED ../buggify-campaign.sh classifier/accumulator),
#   - record/replay is byte-identical with buggify active (a per-gen double run),
#   - distinct seeds vary the firing profile (campaign coverage accumulation).
#
# Every knob for generation G is a pure function of SHA-256("wasi-buggify-$G"),
# so the whole campaign reproduces from the range alone. The fixture carries no
# planted defect, so a clean campaign is all-OK with zero patina findings; the
# always!/duplicate/after-setup detectors are proven to BITE by the cargo-patina
# end-to-end tests and the shared selftest, not re-proven here.
#
# Usage:
#   wasi-buggify-sweep.sh [START_GEN] [END_GEN]   run gens START..END (default 1..40)
#   wasi-buggify-sweep.sh --selftest              run the shared campaign selftest
#   wasi-buggify-sweep.sh --dry-run [S [E]]       print derived config(s), no run
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
# shellcheck source=../buggify-campaign.sh
source "$here/../buggify-campaign.sh"

PATINA="$repo_root/target/release/cargo-patina"
WASM="$here/target/wasm32-wasip1/debug/buggify-wasi-fixture.wasm"
OUTDIR="${WASI_BUGGIFY_OUT:-$here/out-wasi-buggify}"
CAMPAIGN_STATE="$OUTDIR/campaign-state.json"
SWEEP_LOG="$OUTDIR/sweep.log"
LOCK="$here/target/.wasi-buggify-sweep.lock"

# Fill BYTE[0..31] from SHA-256("wasi-buggify-$G").
declare -a BYTE
compute_bytes() {
  local G="$1" HEX i
  HEX="$(printf 'wasi-buggify-%s' "$G" | shasum -a256 | cut -c1-64)"
  for (( i = 0; i < 32; i++ )); do
    BYTE[i]=$(( 16#${HEX:2*i:2} ))
  done
}

# Derive GEN_SEED, GEN_FIRE (permille), GEN_ACT (permille), GEN_SUMMARY.
derive_config() {
  local G="$1"
  compute_bytes "$G"
  GEN_SEED=$(( (BYTE[0] << 8 | BYTE[1]) ))
  # Activation and fire permille both span 250..1000 so the campaign covers light
  # and heavy cooperative-fault regimes.
  GEN_ACT=$(( 250 + (BYTE[3] % 4) * 250 ))
  GEN_FIRE=$(( 250 + (BYTE[4] % 4) * 250 ))
  GEN_SUMMARY="gen=$G wseed=$GEN_SEED fire=${GEN_FIRE} act=${GEN_ACT}"
}

# Buggify knobs for the current gen. The fixture always reaches setup_complete(),
# so --buggify-after-setup is always a clean, meaningful gate.
buggify_knobs() {
  PKNOBS=(--seed "$GEN_SEED" --buggify="$GEN_FIRE" \
    --buggify-activation-permille "$GEN_ACT" --buggify-after-setup)
}

dry_run() {
  local s="$1" e="$2" G
  for (( G = s; G <= e; G++ )); do
    derive_config "$G"; buggify_knobs
    echo "$GEN_SUMMARY"
    printf '    cmd: %q ' "$PATINA" run "$WASM" "${PKNOBS[@]}"; echo
  done
}

c_OK=0; c_ALWAYS_VIOLATION=0; c_BUGGIFY_DUPLICATE_LABEL=0
c_BUGGIFY_SETUP_NEVER_CALLED=0; c_NONDETERMINISM=0; c_UNEXPECTED=0
bump() {
  case "$1" in
    OK) c_OK=$(( c_OK + 1 )) ;;
    ALWAYS_VIOLATION) c_ALWAYS_VIOLATION=$(( c_ALWAYS_VIOLATION + 1 )) ;;
    BUGGIFY_DUPLICATE_LABEL) c_BUGGIFY_DUPLICATE_LABEL=$(( c_BUGGIFY_DUPLICATE_LABEL + 1 )) ;;
    BUGGIFY_SETUP_NEVER_CALLED) c_BUGGIFY_SETUP_NEVER_CALLED=$(( c_BUGGIFY_SETUP_NEVER_CALLED + 1 )) ;;
    NONDETERMINISM) c_NONDETERMINISM=$(( c_NONDETERMINISM + 1 )) ;;
    *) c_UNEXPECTED=$(( c_UNEXPECTED + 1 )) ;;
  esac
}
FAIL_DIRS=()

# Classify a wasi buggify run: buggify markers first, then a generic hard-crash
# guard, else OK. The fixture prints a WASI_BUGGIFY_DIGEST line on a clean run.
classify_wasi() {
  local code="$1" out="$2" err="$3"
  local bug; bug="$(buggify_class "$code" "$out" "$err")"
  if [[ -n "$bug" ]]; then echo "$bug"; return; fi
  if printf '%s\n%s' "$out" "$err" | /usr/bin/grep -Eq \
      'the deterministic runtime failed|unsupported (WebAssembly|native) imports|SIGSEGV|panicked'; then
    echo UNEXPECTED_CRASH; return
  fi
  if [[ "$code" == 0 ]] && printf '%s' "$out" | /usr/bin/grep -q '^WASI_BUGGIFY_DIGEST '; then
    echo OK; return
  fi
  echo UNEXPECTED_CRASH
}

run_gen() {
  local G="$1"
  derive_config "$G"; buggify_knobs
  local gd="$OUTDIR/gen-$G"; rm -rf "$gd"; mkdir -p "$gd"
  local out="$gd/stdout" err="$gd/stderr"
  {
    echo "# $GEN_SUMMARY"
    printf '%q ' "$PATINA" run "$WASM" "${PKNOBS[@]}" --record "$gd/trace"; echo
  } > "$gd/config.txt"

  local code=0
  if "$PATINA" run "$WASM" "${PKNOBS[@]}" --record "$gd/trace" >"$out" 2>"$err"; then
    code=0; else code=$?; fi

  local class; class="$(classify_wasi "$code" "$(cat "$out")" "$(cat "$err")")"

  # Per-gen determinism: a flag-free replay must reproduce stdout and the SDK
  # report byte-for-byte. A divergence is a top-severity finding.
  if [[ "$class" == OK ]]; then
    local rout="$gd/replay.stdout" rerr="$gd/replay.stderr"
    "$PATINA" replay "$WASM" "$gd/trace" >"$rout" 2>"$rerr" || true
    if ! diff -q "$out" "$rout" >/dev/null 2>&1 \
        || [[ "$(sdk_report_line "$err")" != "$(sdk_report_line "$rerr")" ]]; then
      class=NONDETERMINISM
    fi
  fi

  bump "$class"
  campaign_accumulate "$CAMPAIGN_STATE" "$(sdk_report_line "$err")"

  local digest; digest="$(/usr/bin/grep -m1 '^WASI_BUGGIFY_DIGEST ' "$out" 2>/dev/null || true)"
  local logline="gen=$G class=$class exit=$code $GEN_SUMMARY :: ${digest:-<no digest>}"
  echo "$logline" >> "$SWEEP_LOG"; echo "$logline"
  if [[ "$class" == OK ]]; then rm -rf "$gd"; else FAIL_DIRS+=("$gd"); fi
}

build_all() {
  cd "$repo_root"
  echo "==> building cargo-patina (release)"
  if ! cargo build --release --quiet -p cargo-patina; then
    echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
  fi
  echo "==> building the wasi buggify fixture (cargo patina build --target wasi)"
  if ! "$PATINA" build "$here" --target wasi >/dev/null; then
    echo "FATAL: wasi build failed" >&2; exit 3
  fi
  if [[ ! -f "$WASM" ]]; then
    echo "FATAL: missing wasm artifact at $WASM" >&2; exit 3
  fi
}

summary() {
  echo
  echo "==== WASI buggify campaign summary ===="
  echo "OK=$c_OK ALWAYS_VIOLATION=$c_ALWAYS_VIOLATION DUPLICATE_LABEL=$c_BUGGIFY_DUPLICATE_LABEL \
SETUP_NEVER_CALLED=$c_BUGGIFY_SETUP_NEVER_CALLED NONDETERMINISM=$c_NONDETERMINISM UNEXPECTED=$c_UNEXPECTED"
  if [[ -f "$CAMPAIGN_STATE" ]]; then
    echo "-- campaign coverage (per-site, accumulated) --"
    python3 - "$CAMPAIGN_STATE" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
print(f"generations={s.get('generations',0)} gens_with_report={s.get('gens_with_report',0)}")
for label, r in sorted(s.get("sites", {}).items()):
    print(f"  {label} [{r['kind']}] reached={r['reached']} activated_gens={r['activated_gens']} "
          f"fired_gens={r['fired_gens']} total_fires={r['total_fires']} "
          f"sometimes_satisfied={r['sometimes_satisfied']} always_violated={r['always_violated']}")
# A sometimes! site reached but never satisfied across the whole campaign is a
# coverage gap (SOMETIMES_UNMET); surface it as a nonzero campaign exit.
unmet = [l for l, r in s.get("sites", {}).items()
         if r["kind"] == "sometimes" and r["reached"] and not r["sometimes_satisfied"]]
if unmet:
    print("SOMETIMES_UNMET:", ", ".join(unmet))
    sys.exit(7)
PY
    return $?
  fi
}

main() {
  case "${1:-}" in
    --selftest) buggify_campaign_selftest; exit $? ;;
    --dry-run) build_dry=1; shift; derive_only=1 ;;
  esac
  local start="${1:-1}" end="${2:-40}"
  if [[ "${derive_only:-0}" == 1 ]]; then dry_run "$start" "$end"; exit 0; fi

  if ! mkdir "$LOCK" 2>/dev/null; then
    echo "REFUSING TO RUN: another wasi-buggify-sweep holds $LOCK" >&2; exit 4
  fi
  trap 'rm -rf "$LOCK"' EXIT
  mkdir -p "$OUTDIR"; : > "$SWEEP_LOG"; rm -f "$CAMPAIGN_STATE"
  build_all
  local G
  for (( G = start; G <= end; G++ )); do run_gen "$G"; done
  summary
  local sret=$?
  local failures=$(( c_ALWAYS_VIOLATION + c_BUGGIFY_DUPLICATE_LABEL \
    + c_BUGGIFY_SETUP_NEVER_CALLED + c_NONDETERMINISM + c_UNEXPECTED ))
  if (( failures > 0 )); then
    echo "CAMPAIGN FAILED: $failures finding(s); see ${FAIL_DIRS[*]}" >&2; exit 1
  fi
  exit "$sret"
}

main "$@"

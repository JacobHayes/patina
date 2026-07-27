#!/usr/bin/env bash
###############################################################################
# redb commit-slot torn-write GEOMETRY sweep + byte-granularity gap detector.
#
# Background. The buggify dogfood campaign (buggify-sweep.sh) reached the redb
# recovery oracle `sometimes!(corrupted, "redb-recovery-torn-slot-checksum-
# rejected")` 214 times but never satisfied it: no injected crash ever produced
# a commit slot whose stored checksum disagreed with its recomputed checksum
# while its version byte still parsed. The hypothesis was that redb's two-slot
# commit geometry resists byte-granularity tearing.
#
# The real cause is a Patina tooling gap: under `native-run` the shim ALWAYS
# installs the crash filesystem with the DEFAULT crash policy (whole-BLOCK
# tearing, seed 0), so `--fs-torn-granularity byte` is parsed, forwarded, and
# read into the config -- then discarded. A whole-block tear reverts a modified
# block wholesale (durable OR live, never a mix), so a commit slot can never end
# up torn, and the oracle is unsatisfiable BY CONSTRUCTION. With byte
# granularity actually applied, the site fires deterministically (see
# GEOMETRY.md, reproducer seed=1 write:7).
#
# This script is the standing detector for that gap class. For a fixed workload
# it runs a panel of crash points at BOTH `--fs-torn-granularity block` and
# `--fs-torn-granularity byte` and classifies the campaign-wide result:
#
#   SAFETY_BUG                a run lost or tore an acknowledged commit (redb
#                             durability bug) -- report immediately   (exit 3)
#   VACUOUS_BYTE_GRANULARITY  the byte panel is byte-identical to the block
#                             panel: byte granularity is INERT end-to-end, the
#                             torn-slot class is untestable                (exit 2)
#   TORN_SLOT_SATISFIED       byte granularity is active AND the torn-slot
#                             oracle fired at least once                    (exit 0)
#   BYTE_ACTIVE_UNSAT         byte granularity is active (byte != block) but the
#                             oracle never fired in this panel -- widen it  (exit 4)
#
# The classifier (`classify_panel`) is a pure function of two newline-separated
# record streams, so `--selftest` proves every verdict bites on canned input
# without building or running anything.
#
# Usage:
#   geometry-sweep.sh [SEEDS]     run the panel (default patina seeds 1..12)
#   geometry-sweep.sh --selftest  run the pure-classifier selftest
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"

PATINA="$repo_root/target/release/cargo-patina"
BUILT="$here/target/patina/redb-geometry"
OUTDIR="${REDB_GEOMETRY_OUT:-$here/out-geometry}"

# Fixed workload for the panel: a small deterministic redb crash workload whose
# first data commit writes a non-empty commit slot (see GEOMETRY.md write-map).
WSEED=7
OPS=30
# Crash points to probe. The offset-0 super-header writes for this workload land
# at low `write:N` ordinals; 1..40 covers setup and the first several commits.
NMIN=1
NMAX=40

# --- Pure classifier -------------------------------------------------------
#
# A "record" is one line: `gran=<block|byte> n=<N> site=<s0|s1> outcome=<LABEL>`.
# classify_panel reads the BLOCK records from $1 and the BYTE records from $2
# (files, one record per line, paired by n) and prints exactly one verdict
# token. It is a pure function of its inputs so the selftest can drive it.
classify_panel() {
  local block_file="$1" byte_file="$2"
  BLOCK_FILE="$block_file" BYTE_FILE="$byte_file" python3 - <<'PY'
import os, sys

def load(path):
    recs = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            fields = dict(tok.split("=", 1) for tok in line.split())
            key = (fields.get("seed", "?"), fields["n"])
            recs[key] = (fields.get("site", "s0"), fields.get("outcome", ""))
    return recs

block = load(os.environ["BLOCK_FILE"])
byte = load(os.environ["BYTE_FILE"])

# A lost/torn acknowledged commit is a real redb durability bug and outranks any
# coverage verdict.
safety = {"LOST_COMMIT", "TORN_STATE"}
if any(o in safety for (_, o) in list(block.values()) + list(byte.values())):
    print("SAFETY_BUG")
    sys.exit(0)

# Byte granularity is INERT if, for every probed crash point, the byte run is
# byte-identical (site flag AND recovery outcome) to the block run. That is the
# gap: the sub-block tearing knob changed nothing end-to-end.
keys = sorted(set(block) | set(byte))
vacuous = bool(keys) and all(block.get(k) == byte.get(k) for k in keys)
if vacuous:
    print("VACUOUS_BYTE_GRANULARITY")
    sys.exit(0)

# Byte is active. Did the torn-slot oracle fire under byte tearing?
if any(site == "s1" for (site, _) in byte.values()):
    print("TORN_SLOT_SATISFIED")
    sys.exit(0)

print("BYTE_ACTIVE_UNSAT")
PY
}

# --- Selftest: prove every verdict on canned fixtures ----------------------
selftest() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0
  check() { # name expected actual
    if [[ "$2" == "$3" ]]; then echo "  ok   $1 -> $3"; else
      echo "  FAIL $1: expected $2 got $3"; fail=1; fi
  }

  # 1. Vacuous: byte identical to block at every point -> the gap.
  printf 'gran=block n=1 site=s0 outcome=HOLDS\ngran=block n=2 site=s0 outcome=OPEN_ERR\n' >"$tmp/b1"
  printf 'gran=byte n=1 site=s0 outcome=HOLDS\ngran=byte n=2 site=s0 outcome=OPEN_ERR\n'  >"$tmp/y1"
  check vacuous VACUOUS_BYTE_GRANULARITY "$(classify_panel "$tmp/b1" "$tmp/y1")"

  # 2. Satisfied: byte differs AND the oracle fires somewhere under byte.
  printf 'gran=block n=1 site=s0 outcome=HOLDS\ngran=block n=2 site=s0 outcome=HOLDS\n' >"$tmp/b2"
  printf 'gran=byte n=1 site=s1 outcome=HOLDS\ngran=byte n=2 site=s0 outcome=OPEN_ERR\n' >"$tmp/y2"
  check satisfied TORN_SLOT_SATISFIED "$(classify_panel "$tmp/b2" "$tmp/y2")"

  # 3. Active but unsatisfied: byte differs (outcomes) but oracle never fires.
  printf 'gran=block n=1 site=s0 outcome=HOLDS\n' >"$tmp/b3"
  printf 'gran=byte n=1 site=s0 outcome=OPEN_ERR\n' >"$tmp/y3"
  check active_unsat BYTE_ACTIVE_UNSAT "$(classify_panel "$tmp/b3" "$tmp/y3")"

  # 4. Safety bug outranks everything, even a vacuous panel.
  printf 'gran=block n=1 site=s0 outcome=LOST_COMMIT\n' >"$tmp/b4"
  printf 'gran=byte n=1 site=s0 outcome=LOST_COMMIT\n' >"$tmp/y4"
  check safety SAFETY_BUG "$(classify_panel "$tmp/b4" "$tmp/y4")"

  if [[ "$fail" -ne 0 ]]; then echo "SELFTEST FAILED"; return 1; fi
  echo "SELFTEST PASSED"
}

# --- One run: emit a single record line ------------------------------------
run_one() { # gran N -> "gran=.. n=.. site=.. outcome=.."
  local gran="$1" n="$2" out site outcome
  out="$("$PATINA" patina native-run "$BUILT" --seed "$PSEED" \
        --fs-crash-at "write:$n" --fs-torn-granularity "$gran" \
        -- --seed "$WSEED" --ops "$OPS" --db /db/redb.redb --mode crash --threads 1 2>&1)"
  site="$(printf '%s' "$out" \
    | grep -o 'redb-recovery-torn-slot-checksum-rejected|sometimes|[^ ]*' \
    | grep -oE 's[01]' | head -1)"
  outcome="$(printf '%s' "$out" | sed -n 's/.*outcome=\([A-Z_]*\).*/\1/p' | head -1)"
  printf 'gran=%s seed=%s n=%s site=%s outcome=%s\n' "$gran" "$PSEED" "$n" "${site:-s0}" "${outcome:-NONE}"
}

build_once() {
  cd "$repo_root" || exit 3
  echo "==> building cargo-patina + native-building the redb harness"
  cargo build --release --quiet -p cargo-patina || { echo "FATAL: cargo-patina build failed" >&2; exit 3; }
  mkdir -p "$here/target/patina"
  "$PATINA" patina native-build "$here" --output "$BUILT" --release >/dev/null \
    || { echo "FATAL: native-build failed" >&2; exit 3; }
}

main() {
  # SEEDS is a space-separated list in $1; split it into an array on purpose.
  local seeds; read -ra seeds <<<"${1:-1 2 3 4 5 6 7 8 9 10 11 12}"
  build_once
  rm -rf "$OUTDIR"; mkdir -p "$OUTDIR"
  local block_f="$OUTDIR/block.records" byte_f="$OUTDIR/byte.records"
  : >"$block_f"; : >"$byte_f"
  for PSEED in "${seeds[@]}"; do
    for (( n = NMIN; n <= NMAX; n++ )); do
      # Serialize: one native-run at a time (single writer of BUILT).
      run_one block "$n" >>"$block_f"
      run_one byte  "$n" >>"$byte_f"
    done
    echo "    seed $PSEED done ($(grep -c 'site=s1' "$byte_f") byte fires so far)"
  done
  local verdict; verdict="$(classify_panel "$block_f" "$byte_f")"
  local byte_fires; byte_fires="$(grep -c 'site=s1' "$byte_f")"
  local block_fires; block_fires="$(grep -c 'site=s1' "$block_f")"
  echo "=== geometry sweep verdict: $verdict ==="
  echo "    seeds=${seeds[*]} write:$NMIN..$NMAX wseed=$WSEED ops=$OPS"
  echo "    torn-slot fires: byte=$byte_fires block=$block_fires (of $(wc -l <"$byte_f" | tr -d ' ') runs each)"
  echo "    records: $byte_f , $block_f"
  case "$verdict" in
    TORN_SLOT_SATISFIED)      exit 0 ;;
    VACUOUS_BYTE_GRANULARITY) echo "    -> --fs-torn-granularity byte is a NO-OP under native-run (see GEOMETRY.md)"; exit 2 ;;
    SAFETY_BUG)               echo "    -> a run lost/tore an acknowledged commit; inspect $OUTDIR"; exit 3 ;;
    BYTE_ACTIVE_UNSAT)        exit 4 ;;
    *)                        echo "    -> unexpected verdict"; exit 5 ;;
  esac
}

if [[ "${1:-}" == "--selftest" ]]; then
  selftest; exit $?
fi
main "$@"

#!/usr/bin/env bash
###############################################################################
# pubsub — a single-process tokio pub-sub broker under Patina. Self-checking
# regression gate: a real async app (TcpListener fan-in over SimNet, mio on the
# deterministic readiness reactor — kqueue on macOS, epoll on Linux —
# credit-window backpressure, heartbeat timers on the virtual clock), one
# deterministic schedule per seed.
#
# Exits nonzero on ANY regression:
#   [1] build + explicit audit: the control-plane `dlsym` residue is the ONLY
#       allowance; every run below additionally passes the baked-in
#       default-deny pre-run gate with no allowance at all;
#   [2] clean runs: 5 schedule seeds x 3 repeats byte-identical (PUBSUB_RESULT
#       + record-trace hash), each converged (published=32 delivered=64, exit
#       0) with heartbeats>0 (the HB path is alive), and the outcome hash +
#       delivered IDENTICAL across seeds — the order-invariant outcome digest
#       is schedule-invariant even though the schedules (and HB counts) differ;
#   [3] a recorded run strict-replays byte-identically;
#   [4] planted-bug catch: each `--bug` on its pinned seed MUST be caught with
#       its expected marker (fail-closed: a clean pass means the demo went
#       vacuous and the leg FAILS), and the failing run records +
#       strict-replays byte-identically.
# The overriding guard: a PUBSUB_VIOLATION on any clean run fails the script.
#
# No jitter/drop legs, deliberately: Patina's net fault knobs act on SimNet
# datagrams and are inert on this app's TCP stream path (verified — 100 permille
# drop converges byte-identically), so such a leg would be vacuous. Schedule
# seeds are the perturbation axis; the TCP-fault gap is a recorded Patina
# finding, not designed around (see README).
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
built="$here/target/patina/pubsub"
PATINA="$repo_root/target/release/cargo-patina"

# No --allow-unsupported-symbols: the harness passes the default-deny gate clean.
# Escape hatch mirror of workq's: export PATINA_ALLOW_SYMS=name[,name...] if a
# shim/audit refactor transiently unclassifies a std-pulled symbol. The
# COMMITTED default is empty, so the unqualified default-deny property is
# enforced.
ALLOW=()
if [[ -n "${PATINA_ALLOW_SYMS:-}" ]]; then
  ALLOW=(--allow-unsupported-symbols "$PATINA_ALLOW_SYMS")
fi

# Fixed workload: the guest --seed fixes payloads/topics; the Patina run --seed
# varies the schedule. Defaults: 3 topics, 4 subscribers (the last on the
# heartbeat-only sentinel), 2 publishers x 16 messages -> published=32,
# delivered=64.
ARGS=(--seed 7 --base-port 6001 --timeout-secs 30)
EXPECTED_PUBLISHED=32
EXPECTED_DELIVERED=64

cd "$repo_root"
echo "==> [1] building cargo-patina + the pubsub harness; explicit audit"
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
  echo "FATAL: patina build of the pubsub harness failed" >&2; exit 3
fi
# dlsym is the shim's Linux `__real_dlsym` control-plane residue (tolerated as
# control-plane on macOS too) — the identical allowance the shim's own
# validate-native-shim.sh audits carry. Nothing else.
if ! "$PATINA" patina audit "$built" --allow dlsym >/dev/null; then
  echo "    FAIL: audit found residue beyond the dlsym control-plane"; exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0
start_secs=$SECONDS

run() { "$PATINA" patina run "$built" "$@"; }
replay() { "$PATINA" patina replay "$built" "$@"; }
result_of() { sed -n 's/^\(PUBSUB_RESULT .*\)$/\1/p'; }
field_of() { sed -n "s/.*$1=\([0-9][0-9]*\).*/\1/p"; }
hash_of() { sed -n 's/.*hash=\([0-9a-f]*\).*/\1/p'; }
violated() { grep -q 'PUBSUB_VIOLATION'; }
stderr_tail() { [[ -s "$1" ]] && sed -n '1,20p' "$1" | sed 's/^/      stderr| /'; }

echo "==> [2] clean runs: 5 seeds x 3 repeats byte-identical; converged; cross-seed outcome invariance"
xseed_hash=""; xseed_delivered=""
for s in 1 2 3 4 5; do
  ref_res=""; ref_trace=""
  for rep in 1 2 3; do
    tr="$work/c.$s.$rep.trace"; err="$work/c.$s.$rep.err"
    out="$(run --seed "$s" --record "$tr" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" 2>"$err")" || {
      echo "    FAIL: seed $s rep $rep exited nonzero"; fail=1; stderr_tail "$err"; }
    if violated <"$err"; then echo "    FAIL: PUBSUB_VIOLATION seed $s rep $rep"; fail=1; fi
    res="$(result_of <<<"$out")"
    th="$(shasum -a256 "$tr" | cut -d' ' -f1)"
    pub="$(field_of published <<<"$res")"; del="$(field_of delivered <<<"$res")"; hb="$(field_of heartbeats <<<"$res")"
    if [[ "$pub" != "$EXPECTED_PUBLISHED" || "$del" != "$EXPECTED_DELIVERED" ]]; then
      echo "    FAIL: seed $s rep $rep published=$pub delivered=$del expected $EXPECTED_PUBLISHED/$EXPECTED_DELIVERED"; fail=1
    fi
    if [[ "${hb:-0}" -eq 0 ]]; then
      echo "    FAIL: seed $s rep $rep heartbeats=0 (the HB path went dead)"; fail=1
    fi
    if [[ $rep -eq 1 ]]; then ref_res="$res"; ref_trace="$th"; fi
    if [[ "$res" != "$ref_res" || "$th" != "$ref_trace" ]]; then
      echo "    FAIL: seed $s rep $rep not byte-identical to rep 1"; fail=1
    fi
  done
  h="$(hash_of <<<"$ref_res")"; d="$(field_of delivered <<<"$ref_res")"
  if [[ -z "$xseed_hash" ]]; then xseed_hash="$h"; xseed_delivered="$d"; fi
  if [[ "$h" != "$xseed_hash" || "$d" != "$xseed_delivered" ]]; then
    echo "    FAIL: seed $s outcome differs across seeds (hash/delivered must be schedule-invariant)"; fail=1
  fi
  echo "    seed $s: $ref_res | trace=$ref_trace"
done

echo "==> [3] record + strict replay is byte-identical"
rec="$work/replay.trace"
r1="$(run --seed 2 --record "$rec" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" 2>/dev/null | result_of)"
r2="$(replay "$rec" ${ALLOW[@]+"${ALLOW[@]}"} 2>/dev/null | result_of)"
echo "    record: $r1"
echo "    replay: $r2"
if [[ "$r1" != "$r2" || -z "$r1" ]]; then echo "    FAIL: replay differs from record"; fail=1; fi

echo "==> [4] planted-bug catch: each --bug on its pinned seed MUST be caught"
# Each entry: NAME | run-seed | expected marker. FAIL-CLOSED: a clean run means
# the bug slipped past the invariants and the leg FAILS, so the demo can never
# go vacuous. The failing run is then recorded and strict-replayed, requiring a
# byte-identical result + trace hash + marker.
bug_leg() {
  local name="$1" bseed="$2" marker="$3"
  local tr="$work/bug.$name.trace" err="$work/bug.$name.err" out code
  if out="$(run --seed "$bseed" --record "$tr" ${ALLOW[@]+"${ALLOW[@]}"} -- "${ARGS[@]}" --bug "$name" 2>"$err")"; then code=0; else code=$?; fi
  local res; res="$(result_of <<<"$out")"
  echo "    -- $name (seed $bseed): ${res:-<no result line>} exit=$code"
  if [[ $code -eq 0 ]] || ! grep -q "$marker" "$err"; then
    echo "    FAIL: bug '$name' NOT caught (exit=$code, expected '$marker') -- demo went vacuous"; fail=1; stderr_tail "$err"; return
  fi
  echo "        caught: $(grep -m1 "$marker" "$err")"
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
# lost-wakeup: the start edge fires before any just-spawned publisher has been
# polled, so both miss it and the run cannot converge.
bug_leg lost-wakeup 1 "PUBSUB_FAILURE not-converged"
# drop-read-remainder: coalesced reads at the paced subscriber lose frames ->
# per-topic seq contiguity fires.
bug_leg drop-read-remainder 1 "PUBSUB_VIOLATION.*seq-gap"
# stale-timeout: the never-re-armed idle deadline expires mid-run despite live
# heartbeats/messages.
bug_leg stale-timeout 1 "PUBSUB_VIOLATION.*liveness-timeout"

elapsed=$(( SECONDS - start_secs ))
echo "==> wall time: ${elapsed}s"
if [[ "$fail" -ne 0 ]]; then
  echo "==> FAILED"; exit 1
fi
echo "==> all Patina checks passed"

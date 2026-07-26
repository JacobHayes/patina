#!/usr/bin/env bash
# Native (non-Patina) smoke test for the buggy-smoke canary.
#
# buggy-smoke is the INVERSE of the other testbeds: it plants six real bugs that
# native testing almost always misses on fast hardware but that Patina should
# surface deterministically. This script pins down the NATIVE behavior so we know
# exactly which bugs are (and are not) visible without Patina -- that baseline is
# what makes the later Patina phase a meaningful regression canary.
#
# The binary is 100% std-pure: NO Patina imports, NO cfg(patina). The only seam
# between a native and a Patina run is the RUNNER variable below; the binary args
# are byte-for-byte identical. To dry-run the Patina invocation shape instead:
#
#   RUNNER='cargo patina run --release --' ./run-native.sh
#
# Expected native outcomes (see README for why):
#   no-fsync, tight-deadline, udp-order  -> CLEAN   (bug is latent natively)
#   deadlock                             -> CLEAN   (window almost never hits)
#   lost-update, unlucky-byte            -> EITHER  (racy / 1-in-256; recorded)
#
# The script also proves NON-VACUITY natively: lost-update trips under --stress,
# unlucky-byte trips under a bounded seed sweep, and the no-fsync crash-checker
# rejects a corrupted DB. Exit is nonzero on any unexpected outcome.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# The one seam between native and Patina. Word-split intentionally so it can
# carry flags (e.g. "cargo run --release --").
RUNNER="${RUNNER:-cargo run --release --}"

echo "==> runner: $RUNNER"
echo "==> building release binary"
cargo build --release
# Direct binary path for the tight non-vacuity loops (native-only stress; not
# part of the runner-swap story, and far faster than re-entering cargo per call).
BIN="$here/target/release/buggy-smoke"

fail=0

# run <expect: clean|either> <name> [args...]
# Runs the mode through $RUNNER, checks the single contract line and exit code.
run() {
  local expect="$1" name="$2"; shift 2
  local out rc
  set +e
  # shellcheck disable=SC2086  # RUNNER must word-split into argv.
  out="$($RUNNER --bug "$name" "$@" 2>/dev/null)"
  rc=$?
  set -e

  case "$out" in
    "CLEAN bug=$name")
      [[ $rc -eq 0 ]] || { echo "FAIL ($name): CLEAN line but exit=$rc"; fail=1; return; }
      echo "OK   ($name): CLEAN (exit 0)" ;;
    "BUG_CAUGHT bug=$name detail="*)
      [[ $rc -eq 1 ]] || { echo "FAIL ($name): BUG_CAUGHT line but exit=$rc"; fail=1; return; }
      if [[ "$expect" == clean ]]; then
        echo "FAIL ($name): expected CLEAN natively, got: $out"; fail=1; return
      fi
      echo "OK   ($name): BUG_CAUGHT tolerated :: $out" ;;
    *)
      echo "FAIL ($name): unrecognized output (exit=$rc): $out"; fail=1; return ;;
  esac
}

echo "==> per-mode native outcomes"
# Modes whose bug is latent without Patina fault injection -> must be CLEAN.
run clean  no-fsync       --iters 32
run clean  tight-deadline --iters 10
run clean  udp-order      --iters 64
# Deadlock window almost never hits natively -> must finish CLEAN in the watchdog.
run clean  deadlock       --iters 64
# Racy / probabilistic bugs -> either outcome is a valid native result.
run either lost-update    --iters 100
run either unlucky-byte

echo "==> non-vacuity: lost-update under --stress must trip natively"
set +e
stress_out="$("$BIN" --bug lost-update --stress 2>/dev/null)"; stress_rc=$?
set -e
if [[ "$stress_out" == BUG_CAUGHT* && $stress_rc -eq 1 ]]; then
  echo "OK   (lost-update --stress): $stress_out"
else
  echo "FAIL (lost-update --stress): expected BUG_CAUGHT, got (exit=$stress_rc): $stress_out"; fail=1
fi

echo "==> non-vacuity: unlucky-byte seed sweep must find an unlucky draw (<=2000)"
unlucky_seed=""
for s in $(seq 0 2000); do
  if "$BIN" --bug unlucky-byte --seed "$s" >/dev/null 2>&1; then :; else unlucky_seed="$s"; break; fi
done
if [[ -n "$unlucky_seed" ]]; then
  echo "OK   (unlucky-byte): first unlucky seed=$unlucky_seed :: $("$BIN" --bug unlucky-byte --seed "$unlucky_seed" 2>/dev/null)"
else
  echo "FAIL (unlucky-byte): no unlucky seed within 2000 draws"; fail=1
fi

echo "==> non-vacuity: no-fsync crash-checker must reject a corrupted DB"
# Native can't crash the FS, so prove the checker (the crash-phase oracle) works
# by writing a clean WAL, truncating its tail, and confirming --verify-db fails.
"$BIN" --bug no-fsync --iters 32 2>/tmp/buggy-smoke-dbpath.$$ >/dev/null
dbpath="$(sed -n 's/^db-path=//p' /tmp/buggy-smoke-dbpath.$$)"; rm -f /tmp/buggy-smoke-dbpath.$$
if [[ -z "$dbpath" || ! -f "$dbpath" ]]; then
  echo "FAIL (no-fsync checker): could not locate WAL path"; fail=1
else
  clean_out="$("$BIN" --verify-db "$dbpath" --iters 32 2>/dev/null)" || true
  size="$(wc -c < "$dbpath")"
  head -c "$((size - 20))" "$dbpath" > "$dbpath.trunc" && mv "$dbpath.trunc" "$dbpath"
  set +e
  torn_out="$("$BIN" --verify-db "$dbpath" --iters 32 2>/dev/null)"; torn_rc=$?
  set -e
  rm -rf "$(dirname "$dbpath")"
  if [[ "$clean_out" == "CLEAN bug=no-fsync" && "$torn_out" == BUG_CAUGHT* && $torn_rc -eq 1 ]]; then
    echo "OK   (no-fsync checker): clean->CLEAN, truncated->$torn_out"
  else
    echo "FAIL (no-fsync checker): clean='$clean_out' truncated(exit=$torn_rc)='$torn_out'"; fail=1
  fi
fi

echo "==> sanity: --list names exactly the six modes"
# shellcheck disable=SC2086
list_out="$($RUNNER --list 2>/dev/null)"
expected_modes="lost-update deadlock no-fsync tight-deadline udp-order unlucky-byte"
list_count="$(printf '%s\n' "$list_out" | grep -c ':')"
if [[ "$list_count" -ne 6 ]]; then
  echo "FAIL (--list): expected 6 lines, got $list_count"; fail=1
fi
for mode in $expected_modes; do
  if ! printf '%s\n' "$list_out" | grep -q "^$mode:"; then
    echo "FAIL (--list): missing mode $mode"; fail=1
  fi
done
[[ $fail -eq 0 ]] && echo "OK   (--list): all six modes present"

echo
if [[ $fail -eq 0 ]]; then
  echo "ALL NATIVE CHECKS PASSED"
else
  echo "NATIVE CHECKS FAILED"
fi
exit $fail

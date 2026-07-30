#!/usr/bin/env bash
###############################################################################
# audit-corpus — the ecosystem symbol-audit corpus, run as a strict-xfail gate.
#
# 20 minimal reproducers (one per popular crate) are each built + audited
# through the packaged native path (`cargo patina audit <dir>`). The residual
# set of unsupported native imports is normalized to sorted `symbol class`
# lines and compared, EXACTLY and in BOTH directions, against a committed
# per-crate, per-platform expectation file under expected/.
#
#   * Expected CLEAN, actual dirty        -> FAIL (a regression: something the
#                                            shim used to cover now escapes).
#   * Expected dirty, actual differs in
#     ANY way (new symbol, dropped symbol,
#     changed class, CLEAN)               -> FAIL (drift). Improvements — a crate
#                                            going cleaner, a symbol reclassified
#                                            — do not silently pass: they must be
#                                            CLAIMED by re-recording the
#                                            expectation with `--update`. This is
#                                            xfail-strict: the punchlist is the
#                                            set of committed dirty expectations,
#                                            and every entry must match to the
#                                            symbol.
#   * Expectation file MISSING for an
#     already-recorded platform           -> FAIL loudly (never skip silently).
#
# Placeholder platforms: a platform whose expectations have never been recorded
# (every file is a PLACEHOLDER sentinel — the state Linux ships in until the
# coordinator records it on real Linux) is NOT a failure. The whole gate prints
# a prominent SKIP notice and exits 0, so CI does not go red merely because a
# platform has not been recorded yet. The moment ONE real expectation exists for
# a platform, that platform is "recorded" and every crate is held strictly.
#
# Usage:
#   run.sh              build+audit every MRE, compare to this platform's
#                       expectations, print a PASS/FAIL table, exit nonzero on
#                       any failure.
#   run.sh --update     re-record this platform's expectation files from the
#                       current audit output (the explicit claim mechanism).
#   run.sh --selftest   prove BOTH failure directions fire (injected symbol,
#                       dropped symbol) against tampered copies in $TMPDIR,
#                       without touching any committed file.
#
# Bump procedure (crate versions) and the full contract live in README.md.
###############################################################################
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
crates_dir="$here/crates"
expected_dir="$here/expected"
PATINA="$repo_root/target/release/cargo-patina"

# The complete corpus, in a stable order. Keep in sync with crates/ and with the
# per-crate expectation files under expected/.
CORPUS=(
  chrono crossbeam dashmap flate2 getrandom lazy_static libc memmap2
  mimalloc num_cpus once_cell parking_lot rand rayon regex sha2 socket2
  sysinfo time zstd
)

PLACEHOLDER_SENTINEL="PLACEHOLDER-NOT-YET-RECORDED"

# ---- platform marker -------------------------------------------------------
# Expectation files are per-platform but NOT per-arch: macOS arm64 and x86_64
# share expected/<name>.macos.txt; Linux arm64 and x86_64 share
# expected/<name>.linux.txt (the coordinator records Linux on x86_64).
case "$(uname -s)" in
  Darwin) platform="macos" ;;
  Linux)  platform="linux" ;;
  *) echo "FATAL: unsupported host OS $(uname -s) (audit-corpus supports macos + linux)" >&2; exit 3 ;;
esac

expect_file() { printf '%s/%s.%s.txt\n' "$expected_dir" "$1" "$platform"; }

is_placeholder() {
  # A file is a placeholder iff its first non-empty, non-comment line is the
  # sentinel. Missing file is NOT a placeholder (that is the loud-FAIL case on a
  # recorded platform).
  local f="$1"
  [[ -f "$f" ]] || return 1
  grep -vE '^\s*(#|$)' "$f" | head -1 | grep -q "^${PLACEHOLDER_SENTINEL}"
}

# ---- normalization ---------------------------------------------------------
# Turn a captured audit log into the canonical expectation body: either the
# single word CLEAN, or sorted `symbol class` lines. The audit prints one line
#   cargo-patina: unsupported native imports: _sym1 (class1) _sym2 (class2) ...
# on refusal (and no such line when clean). macOS mangles C symbols with one
# leading underscore (`_localtime_r`); strip exactly one so the recorded name is
# the real libc symbol (`localtime_r`). Linux ELF names carry no such prefix and
# are recorded verbatim (leading underscores there, e.g. `__errno_location`, are
# real and preserved). A class may itself contain spaces/commas (the SUD-managed
# label `direct-syscall, SUD-managed`), so pairs are parsed by their parentheses,
# not by whitespace.
normalize() {
  local log="$1"
  local line
  line="$(grep 'unsupported native imports:' "$log" | head -1)"
  if [[ -z "$line" ]]; then
    echo CLEAN
    return
  fi
  # everything after the marker
  line="${line#*unsupported native imports: }"
  local strip_underscore=0
  [[ "$platform" == "macos" ]] && strip_underscore=1
  # Extract `sym (class)` pairs by parentheses; class may hold spaces/commas.
  grep -oE '[^ ]+ \([^)]+\)' <<<"$line" | awk -v strip="$strip_underscore" '
    {
      sym=$1
      s=index($0,"("); e=index($0,")")
      cls=substr($0, s+1, e-s-1)
      if (strip==1 && substr(sym,1,1)=="_") sym=substr(sym,2)
      print sym, cls
    }
  ' | LC_ALL=C sort -u
}

# ---- audit one crate -------------------------------------------------------
# Echoes the normalized expectation body for a crate to stdout. Fails HARD (exit
# 3) if the build/audit errors in a way that is neither "clean" (exit 0, no
# refusal line) nor "dirty" (refusal line present) — a broken build must never
# masquerade as a clean audit.
audit_normalized() {
  local crate="$1" log="$2"
  local rc
  "$PATINA" patina audit "$crates_dir/$crate" >"$log" 2>&1
  rc=$?
  if grep -q 'unsupported native imports:' "$log"; then
    normalize "$log"
    return 0
  fi
  if [[ $rc -eq 0 ]]; then
    echo CLEAN
    return 0
  fi
  echo "FATAL: audit of '$crate' failed (exit $rc) with no refusal line — build error, not a clean/dirty result:" >&2
  sed 's/^/  | /' "$log" >&2
  return 3
}

build_cargo_patina() {
  if ! cargo build --release --quiet -p cargo-patina; then
    echo "FATAL: cargo build --release -p cargo-patina failed" >&2
    exit 3
  fi
}

# ===========================================================================
# --selftest : prove BOTH strict failure directions fire, on tampered COPIES.
# ===========================================================================
if [[ "${1:-}" == "--selftest" ]]; then
  echo "==> audit-corpus selftest: proving both drift directions FAIL (committed files untouched)"
  build_cargo_patina
  work="$(mktemp -d "${TMPDIR:-/tmp}/audit-corpus-selftest.XXXXXX")"
  trap 'rm -rf "$work"' EXIT

  # Use `time`: a reliably-dirty MRE (localtime_r) with a single-symbol residual.
  probe=time
  actual="$work/actual.txt"
  log="$work/audit.log"
  if ! audit_normalized "$probe" "$log" >"$actual"; then
    echo "SELFTEST FATAL: could not audit probe crate '$probe'" >&2; exit 3
  fi
  if [[ "$(cat "$actual")" == "CLEAN" ]]; then
    echo "SELFTEST FATAL: probe crate '$probe' audited CLEAN; it must be dirty for the drift test" >&2
    exit 3
  fi
  echo "    probe='$probe' actual residual:"; sed 's/^/      /' "$actual"

  # compare(actual, expectation-copy) -> 0 pass / 1 fail, mirroring the main gate.
  selftest_compare() { diff -u "$2" "$1" >/dev/null 2>&1; }

  fails=0

  # Positive control: untampered expectation == actual -> MUST PASS.
  cp "$actual" "$work/exp.match.txt"
  if selftest_compare "$actual" "$work/exp.match.txt"; then
    echo "    [control ] identical expectation PASSes (as required)"
  else
    echo "    [control ] FAIL: identical expectation did not pass" >&2; fails=$((fails+1))
  fi

  # Direction 1: inject a fake symbol the audit never emits -> MUST FAIL.
  { cat "$actual"; echo "zzz_fake_injected_symbol fake-class"; } | LC_ALL=C sort -u >"$work/exp.injected.txt"
  if selftest_compare "$actual" "$work/exp.injected.txt"; then
    echo "    [inject  ] FAIL: injected fake symbol did NOT trip the gate" >&2; fails=$((fails+1))
  else
    echo "    [inject  ] injected fake symbol correctly FAILs the gate"
  fi

  # Direction 2: drop a real symbol from the expectation -> MUST FAIL.
  tail -n +2 "$actual" >"$work/exp.dropped.txt"   # remove first residual line
  if selftest_compare "$actual" "$work/exp.dropped.txt"; then
    echo "    [drop    ] FAIL: dropped real symbol did NOT trip the gate" >&2; fails=$((fails+1))
  else
    echo "    [drop    ] dropped real symbol correctly FAILs the gate"
  fi

  # Direction 3 (bonus): expected CLEAN but actual dirty -> MUST FAIL (regression).
  echo CLEAN >"$work/exp.clean.txt"
  if selftest_compare "$actual" "$work/exp.clean.txt"; then
    echo "    [clean-rg] FAIL: CLEAN expectation over dirty actual did NOT trip the gate" >&2; fails=$((fails+1))
  else
    echo "    [clean-rg] CLEAN-expected-vs-dirty correctly FAILs the gate"
  fi

  if [[ "$fails" -ne 0 ]]; then
    echo "audit-corpus selftest: FAILED ($fails direction(s) did not behave)" >&2
    exit 1
  fi
  echo "audit-corpus selftest: PASS (both drift directions + regression fire; committed files untouched)"
  exit 0
fi

# ===========================================================================
# --update / normal run
# ===========================================================================
update=0
if [[ "${1:-}" == "--update" ]]; then
  update=1
elif [[ -n "${1:-}" ]]; then
  echo "FATAL: unknown argument '$1' (expected --update or --selftest)" >&2
  exit 3
fi

build_cargo_patina
mkdir -p "$expected_dir"
logdir="$(mktemp -d "${TMPDIR:-/tmp}/audit-corpus.XXXXXX")"
trap 'rm -rf "$logdir"' EXIT

# ---- recorded-vs-placeholder decision for THIS platform --------------------
# A platform is "recorded" iff at least one non-placeholder expectation file
# exists for it. Until then, the whole gate is a loud SKIP (CI-safe).
recorded=0
for crate in "${CORPUS[@]}"; do
  f="$(expect_file "$crate")"
  if [[ -f "$f" ]] && ! is_placeholder "$f"; then
    recorded=1
    break
  fi
done

if [[ "$update" -eq 0 && "$recorded" -eq 0 ]]; then
  echo "###############################################################################"
  echo "# audit-corpus: SKIPPED — expectations for platform '$platform' are NOT recorded."
  echo "#"
  echo "# Every expected/*.$platform.txt is a $PLACEHOLDER_SENTINEL placeholder. This is"
  echo "# the expected state on a platform the coordinator has not yet recorded (Linux"
  echo "# ships this way until recorded on real Linux hardware). To record:"
  echo "#"
  echo "#     testbeds/audit-corpus/run.sh --update"
  echo "#"
  echo "# then commit the regenerated expected/*.$platform.txt files. NOT a failure —"
  echo "# exiting 0 so CI does not go red on an unrecorded platform."
  echo "###############################################################################"
  exit 0
fi

# ---- main loop -------------------------------------------------------------
declare -a rows=()
fail=0
updated=0

for crate in "${CORPUS[@]}"; do
  log="$logdir/$crate.log"
  if ! actual="$(audit_normalized "$crate" "$log")"; then
    rows+=("$crate|FATAL|build/audit error (see above)")
    fail=1
    continue
  fi
  f="$(expect_file "$crate")"

  if [[ "$update" -eq 1 ]]; then
    printf '%s\n' "$actual" >"$f"
    if [[ "$actual" == CLEAN ]]; then
      rows+=("$crate|UPDATED|CLEAN")
    else
      rows+=("$crate|UPDATED|$(wc -l <<<"$actual" | tr -d ' ') symbol(s)")
    fi
    updated=$((updated+1))
    continue
  fi

  # strict compare against the committed expectation
  if [[ ! -f "$f" ]]; then
    rows+=("$crate|FAIL|MISSING expectation ${f#$repo_root/} on recorded platform — run --update to claim")
    fail=1
    continue
  fi
  if is_placeholder "$f"; then
    rows+=("$crate|FAIL|placeholder expectation on a recorded platform — record it with --update")
    fail=1
    continue
  fi
  # Normalize the committed file the same way (drop comments/blank lines) before
  # diffing, so an operator may annotate an expectation with # comments.
  expected_body="$(grep -vE '^\s*(#|$)' "$f" | LC_ALL=C sort -u)"
  if [[ "$expected_body" == "$actual" ]]; then
    if [[ "$actual" == CLEAN ]]; then
      rows+=("$crate|PASS|CLEAN")
    else
      rows+=("$crate|PASS|$(wc -l <<<"$actual" | tr -d ' ') symbol(s)")
    fi
  else
    rows+=("$crate|FAIL|drift vs expected/${crate}.${platform}.txt")
    fail=1
    echo "----- DRIFT: $crate ($platform) -------------------------------------------"
    echo "  (< expected, committed punchlist ; > actual, this run)"
    diff <(printf '%s\n' "$expected_body") <(printf '%s\n' "$actual") | sed 's/^/  /'
    echo "  To CLAIM this change (if it is an improvement), re-record with:"
    echo "      testbeds/audit-corpus/run.sh --update"
    echo "--------------------------------------------------------------------------"
  fi
done

# ---- summary table ---------------------------------------------------------
echo
echo "audit-corpus — platform=$platform"
printf '  %-13s %-8s %s\n' "CRATE" "STATUS" "DETAIL"
printf '  %-13s %-8s %s\n' "-----" "------" "------"
for row in "${rows[@]}"; do
  IFS='|' read -r c s d <<<"$row"
  printf '  %-13s %-8s %s\n' "$c" "$s" "$d"
done
echo

if [[ "$update" -eq 1 ]]; then
  echo "audit-corpus: recorded $updated expectation file(s) for platform '$platform' (expected/*.$platform.txt). Review + commit them."
  exit 0
fi

if [[ "$fail" -ne 0 ]]; then
  echo "audit-corpus: FAIL (strict-xfail: a dirty expectation drifted, a CLEAN crate regressed, or a file is missing)."
  exit 1
fi
echo "audit-corpus: PASS (all ${#CORPUS[@]} crates match their committed $platform expectations)."
exit 0

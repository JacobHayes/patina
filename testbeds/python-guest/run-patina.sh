#!/usr/bin/env bash
###############################################################################
# python-guest — a Python application built by `patina build --python`.
#
# The guest (app/) is a directory application: its __main__.py imports its own
# module, a package and a namespace package from site-packages/ (frozen in with
# --python-path as the path finder resolves it: the app's module shadows the
# site-packages one of its name, and the package a module beside it), and
# exercises the standard library, pure and C: json, decimal, the HACL* hashes,
# zlib and gzip, re, dataclasses, seeded randomness, the virtual clocks, local
# time in a POSIX rule zone, asyncio, a thread computing without calls stopped
# by another (the compute meter), and the guest filesystem. It prints one
# PYTHON_GUEST line per fact.
#
# It asserts:
#   [1] the pre-run audit is CLEAN with no allowance;
#   [2] under Patina every fact holds, and the program's arguments reach it;
#   [3] two same-seed runs are byte-identical, and a record replays
#       byte-identically;
#   [4] other seeds draw other random values and nothing else differs;
#   [5] a raised exception exits 1 with a traceback naming the application's
#       files and lines, its source lines shown, and replays the same; an
#       unhandled KeyboardInterrupt ends the run by SIGINT, as python3's does;
#   [6] os.fork() stops the run with the process refusal, by name;
#   [7] a --python-path holding an extension module refuses the build, naming
#       it;
#   [8] plain python3 (when on PATH) runs the same application to the same
#       facts, the seeded and clock-dependent ones aside.
###############################################################################
set -uo pipefail

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  sed -n '2,/^####*$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target/testbeds/python-guest}"
export CARGO_TARGET_DIR="$target_dir"
PATINA="${PATINA_CLI:-$target_dir/release/patina}"
out="$target_dir/patina"
built="$out/python-guest"

if [[ -z ${PATINA_CLI:-} ]] && ! cargo build --release --quiet -p cargo-patina; then
  echo "FATAL: cargo build -p cargo-patina failed" >&2; exit 3
fi
if [[ ! -x $PATINA ]]; then
  echo "FATAL: $PATINA is not an executable patina" >&2; exit 3
fi
mkdir -p "$out" || { echo "FATAL: mkdir $out failed" >&2; exit 3; }
rm -f "$built"

fail() { echo "python-guest: FAIL $*" >&2; exit 1; }

echo "==> building the guest (patina build --python)"
"$PATINA" build "$here/app" --python --python-path "$here/site-packages" \
  --output "$built" --release >"$out/build.log" 2>&1 \
  || { cat "$out/build.log" >&2; echo "FATAL: patina build --python failed" >&2; exit 3; }

echo "==> [1] audit: clean"
"$PATINA" audit "$built" >"$out/audit.txt" 2>&1 \
  || { cat "$out/audit.txt" >&2; fail "[1] audit refused the guest"; }

# A POSIX rule zone, which names no zoneinfo file on any host.
zone='XST5XDT,M3.2.0,M11.1.0'

# A run's stdout and stderr, the stderr without the run's own reports.
run() {
  local name=$1; shift
  "$PATINA" run "$built" --env "TZ=$zone" "$@" >"$out/$name.out" 2>"$out/$name.raw"
  local status=$?
  grep -v '^PATINA_SCHEDULE_REPORT ' "$out/$name.raw" >"$out/$name.err"
  return "$status"
}

# The value of FACT in FILE.
fact() { sed -n "s/^PYTHON_GUEST $2=//p" "$1"; }

echo "==> [2] every fact holds"
run seed0 --seed 0 -- first second || { cat "$out/seed0.err" >&2; fail "[2] the run failed"; }
expect() {
  [[ $(fact "$out/seed0.out" "$1") == "$2" ]] \
    || fail "[2] $1 is $(fact "$out/seed0.out" "$1"), not $2"
}
expect argv "first,second"
expect version "3.14.8"
expect shadow "app"
expect tally "12"
expect namespace "hello patina"
expect json '{"a": null, "b": [1, 2]}'
expect decimal "3.305"
expect sha256 "d94f56e94b0baa93"
expect zlib "7c22221c 32 True"
expect re "patina at dst"
expect dataclass "Point(x=1, y=2)"
expect slept "0.25"
expect utc "1971-01-01T00:00:00+00:00"
expect local "1970-06-29 20:00 XDT"
expect mktime "47145600"
expect asyncio "['late', 'early']"
expect metered "True"
expect file "['one', 'two']"

echo "==> [3] same seed byte-identical, record replays byte-identically"
run again --seed 0 -- first second || fail "[3] the second run failed"
cmp -s "$out/seed0.out" "$out/again.out" && cmp -s "$out/seed0.err" "$out/again.err" \
  || fail "[3] two seed-0 runs differ"
run record --seed 0 --record "$out/run.trace" -- first second || fail "[3] the recorded run failed"
cmp -s "$out/seed0.out" "$out/record.out" || fail "[3] the recorded run differs from the plain one"
"$PATINA" replay "$built" "$out/run.trace" >"$out/replay.out" 2>"$out/replay.raw" \
  || { cat "$out/replay.raw" >&2; fail "[3] replay failed"; }
cmp -s "$out/record.out" "$out/replay.out" || fail "[3] the replay differs from the record"

echo "==> [4] other seeds draw other values, and only those"
for seed in 1 2; do
  run "seed$seed" --seed "$seed" -- first second || fail "[4] seed $seed failed"
  [[ $(fact "$out/seed$seed.out" random) != "$(fact "$out/seed0.out" random)" ]] \
    || fail "[4] seed $seed drew seed 0's random value"
  diff <(grep -v '^PYTHON_GUEST \(random\|urandom\)=' "$out/seed$seed.out") \
    <(grep -v '^PYTHON_GUEST \(random\|urandom\)=' "$out/seed0.out") >/dev/null \
    || fail "[4] seed $seed changed a fact that does not draw"
done

echo "==> [5] an exception: exit 1, a traceback with the application's lines, replayed"
run boom --seed 0 --record "$out/boom.trace" -- boom && fail "[5] the raising run exited 0"
[[ $(grep -c . "$out/boom.out") -gt 0 ]] || fail "[5] the raising run printed nothing first"
grep -q '^  File "__main__.py", line [0-9]*, in <module>$' "$out/boom.err" \
  && grep -q '^    ledger.settle({"open": 1})$' "$out/boom.err" \
  && grep -q '^  File "ledger.py", line [0-9]*, in settle$' "$out/boom.err" \
  && grep -q "^RuntimeError: unsettled accounts: \['open'\]$" "$out/boom.err" \
  || { cat "$out/boom.err" >&2; fail "[5] the traceback does not show the application's lines"; }
"$PATINA" replay "$built" "$out/boom.trace" >"$out/boom-replay.out" 2>"$out/boom-replay.raw"
grep -v '^PATINA_SCHEDULE_REPORT ' "$out/boom-replay.raw" | diff - "$out/boom.err" >/dev/null \
  || fail "[5] the replay's traceback differs"

# The guest's own SIGINT ends the run: a crash in the guest (exit 1), named
# by the line patina prints last.
run interrupt --seed 0 -- interrupt
[[ $? == 1 ]] && grep -q 'guest killed by SIGINT' "$out/interrupt.err" \
  && grep -q '^KeyboardInterrupt$' "$out/interrupt.err" \
  || { cat "$out/interrupt.err" >&2; fail "[5] a KeyboardInterrupt did not end the run by SIGINT"; }

echo "==> [6] os.fork() is the process refusal"
run fork --seed 0 -- fork && fail "[6] a forking run exited 0"
grep -q 'process spawn reached under patina: fork' "$out/fork.err" \
  || { cat "$out/fork.err" >&2; fail "[6] the fork was not refused by name"; }

echo "==> [7] an extension module refuses the build"
extension="$out/extension-site"
rm -rf "$extension" && mkdir -p "$extension/fast" && : >"$extension/fast/__init__.py" \
  && : >"$extension/fast/_speedups.cpython-314-x86_64-linux-gnu.so" \
  || { echo "FATAL: cannot stage the extension fixture" >&2; exit 3; }
if "$PATINA" build "$here/app" --python --python-path "$extension" \
  --output "$out/extension-guest" >"$out/extension.log" 2>&1; then
  fail "[7] a build with an extension module succeeded"
fi
grep -q "_speedups.cpython-314-x86_64-linux-gnu.so is an extension module" "$out/extension.log" \
  || { cat "$out/extension.log" >&2; fail "[7] the refusal does not name the extension module"; }

echo "==> [8] plain python3 runs the same application"
if command -v python3 >/dev/null; then
  (cd "$out" && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$here/site-packages" TZ="$zone" python3 "$here/app" first second) \
    >"$out/plain.out" 2>"$out/plain.err" || { cat "$out/plain.err" >&2; fail "[8] plain python3 failed"; }
  varying='^PYTHON_GUEST \(version\|random\|urandom\|slept\)='
  diff <(grep -v "$varying" "$out/plain.out") <(grep -v "$varying" "$out/seed0.out") \
    || fail "[8] plain python3 disagrees on a fact"
else
  echo "    (no python3 on PATH; skipped)"
fi

echo "python-guest: PASS"

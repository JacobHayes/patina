# 2. ./check never runs scripts against a binary it did not just build: with `cargo` stubbed to
#    fail, ./check exits non-zero with the compiler's error and runs nothing; and tests/run.py
#    refuses a patina binary older than a source its dep-info names (a failed or skipped build).
#@ tier=quick budget=15
: "${RUNS:?}"
root=$(cd "$(dirname "$0")/../.." && pwd)
die() { echo "FAIL: $*"; exit 1; }
s=$RUNS/check
mkdir -p "$s/bin"

# a. A failing build stops ./check.
printf '#!/bin/sh\necho "error[E0425]: planted" >&2\nexit 101\n' >"$s/bin/cargo"
chmod +x "$s/bin/cargo"
rc=0
PATH="$s/bin:$PATH" PATINA_CHECK_DIR="$s/a" "$root/check" quick >"$s/a.txt" 2>&1 || rc=$?
[ "$rc" != 0 ] || die "a. ./check passed with a failing build: $(tail -3 "$s/a.txt")"
grep -q 'planted' "$s/a.txt" || die "a. the compiler's error is not shown: $(tail -3 "$s/a.txt")"
! grep -q '^== ' "$s/a.txt" || die "a. ./check went on after the failed build: $(grep '^== ' "$s/a.txt" | head -1)"
echo "a. failing build: ./check exit $rc, compiler error shown, nothing run"

# b. A binary older than one of its sources is refused before any script runs.
mkdir -p "$s/b"
printf 'fn main() {}\n' >"$s/b/old.rs"
printf '#!/bin/sh\necho patina 0.0.0\n' >"$s/b/patina"
chmod +x "$s/b/patina"
printf '%s: %s %s\n' "$s/b/patina" "$s/b/old.rs" "$s/b/new.rs" >"$s/b/patina.d"
touch -d '2001-01-01' "$s/b/old.rs"
touch -d '2002-01-01' "$s/b/patina"
printf 'fn main() { edited(); }\n' >"$s/b/new.rs"
rc=0
PATINA="$s/b/patina" python3 -I "$root/tests/run.py" skeleton >"$s/b.txt" 2>&1 || rc=$?
[ "$rc" != 0 ] || die "b. run.py accepted a stale binary"
grep -q 'new\.rs' "$s/b.txt" || die "b. the refusal does not name the newer source: $(tail -3 "$s/b.txt")"
! grep -q '^PASS\|^FAIL\|^== area' "$s/b.txt" || die "b. scripts ran against the stale binary"
echo "b. stale binary: refused (exit $rc), no script run"

#!/usr/bin/env bash
# Exercise the `#[patina_dst::test]` adopter path with plain `cargo test`.
# Run from the Patina repository root; the script never changes directory.

set -euo pipefail

usage() {
  cat <<'EOF'
usage: testbeds/patina-macro-adopter/run.sh [--selftest]

Builds the local cargo-patina binary, then drives the standalone adopter crate
with plain cargo test commands:
  * a passing #[patina_dst::test] sweep;
  * a planted seeded failure whose panic must carry the seed plus test/replay
    repro commands;
  * a PATH-scrubbed run proving missing cargo-patina is a loud test failure.

--selftest is accepted for consistency with classifier-style testbed scripts and
runs the same planted proofs as the default mode.
EOF
}

case "${1:-}" in
  ""|--selftest) ;;
  -h|--help) usage; exit 0 ;;
  *) echo "patina-macro-adopter: unknown argument '$1' (expected --selftest or --help)" >&2; usage >&2; exit 2 ;;
esac

ROOT="$PWD"
MANIFEST="$ROOT/testbeds/patina-macro-adopter/Cargo.toml"
OUT="$ROOT/target/patina-macro-adopter"
CLI="$ROOT/target/debug/cargo-patina"

if [[ ! -f "$ROOT/Cargo.toml" || ! -f "$MANIFEST" ]]; then
  echo "patina-macro-adopter: run from the Patina repository root" >&2
  exit 2
fi

mkdir -p "$OUT"

echo "==> patina macro adopter: build cargo-patina"
cargo build -p cargo-patina --locked >/dev/null
if [[ ! -x "$CLI" ]]; then
  echo "patina-macro-adopter: expected executable $CLI" >&2
  exit 1
fi

echo "==> patina macro adopter: assert macro crate has no dependencies"
cargo tree -p patina-dst --locked >"$OUT/tree-patina-dst.txt"
cargo tree -p patina-dst-macros --locked >"$OUT/tree-patina-dst-macros.txt"
if [[ $(wc -l <"$OUT/tree-patina-dst.txt" | tr -d ' ') != 1 ]]; then
  echo "patina-macro-adopter: patina-dst default feature tree is not dependency-free" >&2
  cat "$OUT/tree-patina-dst.txt" >&2
  exit 1
fi
if [[ $(wc -l <"$OUT/tree-patina-dst-macros.txt" | tr -d ' ') != 1 ]]; then
  echo "patina-macro-adopter: patina-dst-macros gained dependencies" >&2
  cat "$OUT/tree-patina-dst-macros.txt" >&2
  exit 1
fi
cat "$OUT/tree-patina-dst-macros.txt"

run_pass() {
  local out="$1"
  PATINA_CLI="$CLI" cargo test --manifest-path "$MANIFEST" deterministic_pass -- --exact >"$out" 2>&1
}

run_seeded_failure() {
  local out="$1"
  set +e
  PATINA_CLI="$CLI" cargo test --manifest-path "$MANIFEST" seeded_failure_reports_repro -- --exact >"$out" 2>&1
  local status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    echo "patina-macro-adopter: planted seeded failure unexpectedly passed" >&2
    cat "$out" >&2
    exit 1
  fi
}

extract_failure_block() {
  python3 - "$1" <<'PY'
import sys
lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
start = None
for i, line in enumerate(lines):
    if "patina dst test failed:" in line:
        start = i
        break
if start is None:
    raise SystemExit("failure block not found")
out = []
for line in lines[start:]:
    out.append(line.rstrip())
    if "cargo patina replay" in line:
        break
print("\n".join(out))
PY
}

assert_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -F -- "$needle" "$file" >/dev/null; then
    echo "patina-macro-adopter: expected '$needle' in $file" >&2
    cat "$file" >&2
    exit 1
  fi
}

echo "==> patina macro adopter: passing macro test under plain cargo test"
PASS1="$OUT/pass-1.out"
PASS2="$OUT/pass-2.out"
run_pass "$PASS1"
run_pass "$PASS2"
tail -n 12 "$PASS1"

echo "==> patina macro adopter: seeded failure block under plain cargo test"
FAIL1="$OUT/seeded-failure-1.out"
FAIL2="$OUT/seeded-failure-2.out"
BLOCK1="$OUT/seeded-failure-1.block"
BLOCK2="$OUT/seeded-failure-2.block"
run_seeded_failure "$FAIL1"
run_seeded_failure "$FAIL2"
extract_failure_block "$FAIL1" >"$BLOCK1"
extract_failure_block "$FAIL2" >"$BLOCK2"
diff -u "$BLOCK1" "$BLOCK2" >/dev/null
assert_contains "$BLOCK1" "seed 7"
assert_contains "$BLOCK1" "cargo patina test"
assert_contains "$BLOCK1" "--harness-target dst_macro"
assert_contains "$BLOCK1" "--exact seeded_failure_reports_repro"
assert_contains "$BLOCK1" "cargo patina replay"
assert_contains "$FAIL1" "DST_MACRO_PLANTED_FAILURE"
cat "$BLOCK1"

echo "==> patina macro adopter: PATH-scrubbed missing-CLI refusal"
SCRUB_BIN="$OUT/path-scrub-bin"
rm -rf "$SCRUB_BIN"
mkdir -p "$SCRUB_BIN"
CARGO_BIN="$(command -v cargo)"
RUSTC_BIN="$(command -v rustc)"
RUSTDOC_BIN="$(command -v rustdoc || true)"
ln -sf "$CARGO_BIN" "$SCRUB_BIN/cargo"
ln -sf "$RUSTC_BIN" "$SCRUB_BIN/rustc"
if [[ -n "$RUSTDOC_BIN" ]]; then
  ln -sf "$RUSTDOC_BIN" "$SCRUB_BIN/rustdoc"
fi
SCRUB_PATH="$SCRUB_BIN:/usr/bin:/bin"
if PATH="$SCRUB_PATH" command -v cargo-patina >/dev/null 2>&1; then
  echo "patina-macro-adopter: scrubbed PATH still finds cargo-patina" >&2
  exit 1
fi
PATH_OUT="$OUT/path-scrub.out"
set +e
env -u PATINA_CLI PATH="$SCRUB_PATH" RUSTC="$RUSTC_BIN" "$CARGO_BIN" test --manifest-path "$MANIFEST" path_scrub_refuses_missing_cli -- --exact >"$PATH_OUT" 2>&1
PATH_STATUS=$?
set -e
if [[ $PATH_STATUS -eq 0 ]]; then
  echo "patina-macro-adopter: PATH-scrubbed run unexpectedly passed" >&2
  cat "$PATH_OUT" >&2
  exit 1
fi
assert_contains "$PATH_OUT" "could not find cargo-patina"
assert_contains "$PATH_OUT" "set PATINA_CLI"
assert_contains "$PATH_OUT" "put cargo-patina on PATH"
assert_contains "$PATH_OUT" "DST tests never skip"
grep -F "could not find cargo-patina" "$PATH_OUT" | head -1
grep -F "DST tests never skip" "$PATH_OUT" | head -1

echo "patina macro adopter: PASS"

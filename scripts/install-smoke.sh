#!/usr/bin/env bash
# Prove an installed patina serves a project that has no Patina checkout: the
# release workflow runs this against every archive before it publishes, and
# against the published release afterwards and weekly.

set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/install-smoke.sh [--go] REF

Uses the `patina` on PATH and nothing of this checkout. In a new directory:
  * a new Rust package depends on the SDK from GitHub at REF, and plain
    `cargo test` passes its #[patina_dst::test];
  * the same test fails once the tool cannot be found, so the pass above
    went through the tool;
  * the package's program builds, runs the same for one seed and differently
    for another, and a recorded run replays;
  * with --go, a Go program using the Go SDK at REF builds, runs simulated,
    and a recorded run replays.

REF is a release tag (v0.1.0) or a commit of github.com/JacobHayes/patina.
The directory is removed on success and named on failure.
EOF
}

go=0
ref=
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --go) go=1 ;;
    -*) echo "install-smoke: unknown option $arg" >&2; usage >&2; exit 2 ;;
    *) [[ -z $ref ]] || { echo "install-smoke: one REF, not two" >&2; exit 2; }; ref=$arg ;;
  esac
done
[[ -n $ref ]] || { usage >&2; exit 2; }

patina=$(command -v patina) || { echo "install-smoke: no patina on PATH" >&2; exit 2; }
if [[ $ref =~ ^v[0-9] ]]; then pin="tag = \"$ref\""; else pin="rev = \"$ref\""; fi

work=$(mktemp -d "${TMPDIR:-/tmp}/patina-install-smoke.XXXXXX")
fail() {
  echo "install-smoke: FAIL $*" >&2
  echo "install-smoke: kept $work" >&2
  exit 1
}
# Run a step, keeping its output for the failure report.
step() {
  local log=$1
  shift
  "$@" >"$work/$log" 2>&1 || { cat "$work/$log" >&2; fail "$log: $*"; }
}

echo "install-smoke: $patina ($("$patina" --version | head -n 1)), SDK at $ref, in $work"

# One seed's run, a second run of it, another seed's, and a replay of the first.
round_trip() {
  local guest=$1 name=$2
  "$patina" run "$guest" --seed 7 --record "$work/$name.patina" >"$work/$name.seed7" 2>"$work/$name.seed7.err" \
    || { cat "$work/$name.seed7.err" >&2; fail "$name: the recorded run failed"; }
  "$patina" run "$guest" --seed 7 >"$work/$name.again" 2>/dev/null || fail "$name: the repeated run failed"
  "$patina" run "$guest" --seed 8 >"$work/$name.seed8" 2>/dev/null || fail "$name: the other seed's run failed"
  "$patina" replay "$guest" "$work/$name.patina" >"$work/$name.replay" 2>"$work/$name.replay.err" \
    || { cat "$work/$name.replay.err" >&2; fail "$name: the replay failed"; }
  [[ -s $work/$name.seed7 ]] || fail "$name: the run printed nothing"
  cmp -s "$work/$name.seed7" "$work/$name.again" || fail "$name: one seed ran two ways"
  cmp -s "$work/$name.seed7" "$work/$name.replay" || fail "$name: the replay differs from its recording"
  ! cmp -s "$work/$name.seed7" "$work/$name.seed8" || fail "$name: two seeds ran the same"
}

rust=$work/rust
mkdir -p "$rust/src" "$rust/tests"
cat >"$rust/Cargo.toml" <<EOF
[package]
name = "patina-install-smoke"
version = "0.0.0"
edition = "2021"

[dev-dependencies]
patina-dst = { git = "https://github.com/JacobHayes/patina", $pin, features = ["macros"] }
EOF
cat >"$rust/src/main.rs" <<'EOF'
use std::hash::BuildHasher;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let draw = std::collections::hash_map::RandomState::new().hash_one("draw");
    println!("now={} draw={draw}", now.as_nanos());
}
EOF
cat >"$rust/tests/dst.rs" <<'EOF'
#[patina_dst::test(seeds = 2)]
fn an_hour_passes_under_patina() {
    assert!(patina_dst::is_simulated());
    let start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_secs(3600));
    assert!(start.elapsed().as_secs() >= 3600);
}
EOF

echo "==> [1] plain cargo test passes a #[patina_dst::test]"
step cargo-test.log cargo test --manifest-path "$rust/Cargo.toml"

echo "==> [2] the same test fails when the tool is missing"
if PATINA_CLI="$work/no-such-patina" cargo test --manifest-path "$rust/Cargo.toml" >"$work/cargo-test-no-tool.log" 2>&1; then
  cat "$work/cargo-test-no-tool.log" >&2
  fail "cargo test passed without the tool"
fi

echo "==> [3] build, run, replay"
step build.log "$patina" build "$rust" --output "$work/guest"
round_trip "$work/guest" rust

if ((go)); then
  echo "==> [4] a Go guest with the Go SDK builds, runs simulated, and replays"
  gomod=$work/go
  mkdir -p "$gomod"
  cat >"$gomod/main.go" <<'EOF'
package main

import (
	"fmt"
	"time"

	"github.com/JacobHayes/patina/go/patina"
)

func main() {
	fmt.Printf("simulated=%v now=%d draw=%d\n", patina.IsSimulated(), time.Now().UnixNano(), patina.Rng())
}
EOF
  (
    cd "$gomod"
    step go-mod.log go mod init example.test/patina-install-smoke
    step go-get.log go get "github.com/JacobHayes/patina/go/patina@$ref"
  )
  step go-build.log "$patina" build "$gomod" --go --output "$work/go-guest"
  round_trip "$work/go-guest" go
  grep -q '^simulated=true ' "$work/go.seed7" || { cat "$work/go.seed7" >&2; fail "go: the SDK is not simulated"; }
fi

rm -rf "$work"
echo "install-smoke: PASS"

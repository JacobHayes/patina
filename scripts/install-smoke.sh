#!/usr/bin/env bash
# Prove an installed patina serves a project that has no Patina checkout, and
# that the documented first run is true: the projects of the README's first
# run and of the tutorial (examples/) are run as the documents say. CI runs
# this on every push with the SDK of the checkout; the release workflow runs
# it against every archive before it publishes, and against the published
# release afterwards and weekly.

set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/install-smoke.sh [--go] REF

Uses the `patina` on PATH. Of this checkout it uses only examples/, the
projects the README and the tutorial walk through, copied to a new directory
with their SDK dependency set to REF:
  * the README's first run (examples/quickstart): plain `cargo test` fails on
    a seed and leaves a trace, the trace replays to the same failure, the
    fixed library passes, and the test fails once the tool cannot be found
    (so the pass went through the tool);
  * the tutorial (examples/ledger): the program builds, some seeds end clean
    and some in a violation, a recorded violation replays and renders, a
    campaign finds it, reproduces it and can be given again, and `cargo test`
    finds it too;
  * a new program builds, runs the same for one seed and differently for
    another, and a recorded run replays;
  * with --go, a Go program using the Go SDK at REF builds, runs simulated,
    and a recorded run replays.

REF is a release tag (v0.1.0), a commit of github.com/JacobHayes/patina, or
the path of a Patina checkout whose SDK to use (not with --go).
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
examples=$(cd "$(dirname "${BASH_SOURCE[0]}")/../examples" && pwd)
repository='git = "https://github.com/JacobHayes/patina"'
if [[ -d $ref ]]; then
  ((!go)) || { echo "install-smoke: --go needs a tag or a commit, not a checkout" >&2; exit 2; }
  pin="path = \"$(cd "$ref" && pwd)/crates/patina\""
elif [[ $ref =~ ^v[0-9] ]]; then
  pin="$repository, tag = \"$ref\""
else
  pin="$repository, rev = \"$ref\""
fi
# The projects build where an adopter's would, beneath themselves.
unset CARGO_TARGET_DIR

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

# One documented project, copied out of the checkout with its SDK set to REF.
example() {
  local name=$1
  cp -R "$examples/$name" "$work/$name"
  sed -i.orig -E "s|$repository, tag = \"[^\"]*\"|$pin|" "$work/$name/Cargo.toml"
  ! cmp -s "$work/$name/Cargo.toml" "$work/$name/Cargo.toml.orig" \
    || fail "$name: its manifest names no SDK release to set to $ref"
  rm "$work/$name/Cargo.toml.orig"
}
# A command that must end in a finding (status 1), its output kept.
finds() {
  local log=$1 status=0
  shift
  "$@" >"$work/$log" 2>&1 || status=$?
  ((status == 1)) || { cat "$work/$log" >&2; fail "$log: status $status, not a finding: $*"; }
}

echo "==> [1] README first run: cargo test finds a failing seed, and it replays"
example quickstart
quickstart=$work/quickstart
if cargo test --manifest-path "$quickstart/Cargo.toml" >"$work/quickstart-test.log" 2>&1; then
  cat "$work/quickstart-test.log" >&2
  fail "quickstart: cargo test passed over the planted bug"
fi
trace=$(find "$quickstart/target/patina/dst" -name 'seed-*.patina' | head -n 1)
[[ -n $trace ]] || { cat "$work/quickstart-test.log" >&2; fail "quickstart: the failing seed left no trace"; }
finds quickstart-replay.log "$patina" replay "$(dirname "$trace")/guest" "$trace"
cp "$quickstart/lib.fixed.rs" "$quickstart/src/lib.rs"
step quickstart-fixed.log cargo test --manifest-path "$quickstart/Cargo.toml"

echo "==> [2] the same test fails when the tool is missing"
if PATINA_CLI="$work/no-such-patina" cargo test --manifest-path "$quickstart/Cargo.toml" >"$work/cargo-test-no-tool.log" 2>&1; then
  cat "$work/cargo-test-no-tool.log" >&2
  fail "cargo test passed without the tool"
fi

echo "==> [3] tutorial: build, sweep seeds, record, replay, render, campaign, cargo test"
example ledger
(
  cd "$work/ledger"
  step ledger-build.log "$patina" build . --output ledger-guest
  clean= found=
  for seed in $(seq 0 39); do
    status=0
    "$patina" run ./ledger-guest --seed "$seed" --buggify >"$work/ledger-seed.log" 2>&1 || status=$?
    case $status in
      0) clean=$seed ;;
      1) found=${found:-$seed} ;;
      *) cat "$work/ledger-seed.log" >&2; fail "ledger: seed $seed ended with status $status" ;;
    esac
  done
  [[ -n $clean && -n $found ]] || fail "ledger: 40 seeds were all clean or all findings (clean=$clean found=$found)"
  finds ledger-record.log "$patina" run ./ledger-guest --seed "$found" --buggify --record bug.patina
  finds ledger-replay.log "$patina" replay ./ledger-guest bug.patina --render bug.html
  cmp -s "$work/ledger-record.log" <(grep -v '^PATINA_RENDER ' "$work/ledger-replay.log") \
    || fail "ledger: the replay differs from its recording"
  [[ -s bug.html ]] || fail "ledger: the replay rendered no page"
  finds ledger-render.log "$patina" run ./ledger-guest --seed "$found" --buggify --render run.html
  [[ -s run.html ]] || fail "ledger: a run rendered no page without --record"
  step ledger-trace.log "$patina" trace info bug.patina
  finds ledger-campaign.log "$patina" campaign ./ledger-guest --buggify --gens 30 --out-dir ledger-out
  generation=$(find ledger-out/failures -name 'generation-*.patina' | head -n 1)
  [[ -n $generation ]] || { cat "$work/ledger-campaign.log" >&2; fail "ledger: the campaign kept no failing trace"; }
  finds ledger-campaign-replay.log "$patina" replay ./ledger-guest "$generation"
  finds ledger-campaign-again.log "$patina" campaign ./ledger-guest --buggify --gens 30 --out-dir ledger-out
  if cargo test >"$work/ledger-test.log" 2>&1; then
    cat "$work/ledger-test.log" >&2
    fail "ledger: cargo test passed over the planted bug"
  fi
  [[ -n $(find target/patina/dst -name 'seed-*.patina') ]] \
    || { cat "$work/ledger-test.log" >&2; fail "ledger: cargo test failed without finding a seed"; }
)

rust=$work/rust
mkdir -p "$rust/src"
cat >"$rust/Cargo.toml" <<EOF
[package]
name = "patina-install-smoke"
version = "0.0.0"
edition = "2021"
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

echo "==> [4] a new program builds, runs by its seed, and replays"
step build.log "$patina" build "$rust" --output "$work/guest"
round_trip "$work/guest" rust

if ((go)); then
  echo "==> [5] a Go guest with the Go SDK builds, runs simulated, and replays"
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

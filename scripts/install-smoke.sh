#!/bin/bash
# Check that an installed patina (the one on PATH) runs the README's first examples outside
# this checkout: examples/quickstart (Rust, cargo) and examples/acklog-c (C, cc) are copied to a
# new directory, built there with their own tools, swept over seeds 1-20 (the bug must be
# found, the fixed variant must be ok), and the first failing seed must replay identically.
set -euo pipefail; shopt -s inherit_errexit
repo=$(cd "$(dirname "$0")/.." && pwd)
command -v patina >/dev/null || { echo "install-smoke: no patina on PATH" >&2; exit 1; }
patina doctor
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT
cp -R "$repo/examples/quickstart" "$repo/examples/acklog-c" "$repo/sdk/c/patina.h" "$work/"
cd "$work"
cargo build --quiet --manifest-path quickstart/Cargo.toml
cc -I . -o acklog acklog-c/acklog.c

# sweep NAME [options] -- CMD: the bug is found (exit 1), the fixed variant is ok (exit 0), and
# the first seed of the finding replays identically.
sweep() {
    name=$1; shift
    rc=0; patina sweep --seeds 1..20 --out "runs/$name" "$@" || rc=$?
    [ "$rc" = 1 ] || { echo "install-smoke: $name: expected a finding (exit 1), got exit $rc" >&2; exit 1; }
    patina sweep --seeds 1..20 --out "runs/$name-fixed" "$@" fixed
    first=$(sed -n 's/.*"dir": *"\([^"]*\)".*/\1/p' "runs/$name/report.json" | sed -n 1p)
    # replay exits with the replayed outcome's status; its first line says whether it repeated.
    patina replay "$first" --out "runs/$name-replay" >"runs/$name-replay.txt" || true
    grep -q '^identical' "runs/$name-replay.txt" \
        || { echo "install-smoke: $name: the replay of $first differs" >&2; exit 1; }
}
sweep quickstart -- quickstart/target/debug/jobs
sweep acklog --faults crash -- ./acklog
echo "install-smoke: ok"

#!/bin/sh
# Build examples/ into $1/examples with each language's own tool, as examples/README.md does:
# cargo (quickstart, ledger), cc (acklog-c), go (bank-go); journal-py is copied with patina.py.
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
out=${1:?output directory}/examples
mkdir -p "$out"
ex=$root/examples
export CARGO_TARGET_DIR=$PATINA_BUILD_DIR/examples GOCACHE=$PATINA_BUILD_DIR/gocache GOTOOLCHAIN=local
cargo build --quiet --manifest-path "$ex/quickstart/Cargo.toml"
cargo build --quiet --release --manifest-path "$ex/ledger/Cargo.toml"
cp "$CARGO_TARGET_DIR/debug/jobs" "$CARGO_TARGET_DIR/release/ledger" "$out/"
cc -I "$root/sdk/c" -o "$out/acklog" "$ex/acklog-c/acklog.c"
go build -C "$ex/bank-go" -o "$out/bank"
cp "$ex/journal-py/journal.py" "$root/sdk/python/patina.py" "$out/"

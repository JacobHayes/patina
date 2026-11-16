#!/bin/sh
# Cost and spin-wait guests into $1.
#   costs                per-call probes (static glibc)
#   true-static          an empty static program (start-up cost)
#   spinwait             busy-wait patterns, stock (see spinwait.c)
#   rs-spin              Rust: a spin lock held across a write, and std::sync::Mutex
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
gcc -O2 -static -pthread -o "$out/costs" "$here/costs.c"
printf 'int main(void) { return 0; }\n' | gcc -O2 -static -x c -o "$out/true-static" -
gcc -O1 -pthread -o "$out/spinwait" "$here/spinwait.c"
rustc -O --edition 2021 -o "$out/rs-spin" "$here/rs-spin.rs"

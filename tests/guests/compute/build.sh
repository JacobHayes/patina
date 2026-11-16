#!/bin/sh
# Compute-point guests into $1/compute/ (/guest/compute/ in the sandbox): C programs rebuilt
# with clang's coverage flags and sdk/c/patina_compute.c, from sources other areas already
# use where they exist (deps lists them). Without clang nothing is built and MISSING says so:
# this script succeeds, so other areas are not blocked, and tests/compute fails.
#   races, pool       the counters area's syscall-free races (races at -O1 as there; pool at
#                     -O2, where its `stats.done++` is one instruction in a stock build)
#   spinpoints        tests/guests/threads/spinpoints.c (`count`: a spin-wait that changes state)
#   spinwait          tests/guests/costs/spinwait.c with its spin lock's `pause` taken out
#   cellpoke          writes into, then unmaps, its own cell
#   loop, loop-stock  a loop between two clock reads, instrumented and not
#   mixed             threads, then stock and instrumented children (fork, vfork, exec)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:?guest dir}/compute
mkdir -p "$out"
if ! command -v clang >/dev/null; then
    echo "clang is not installed: the compute-point guests are not built" | tee "$out/MISSING" >&2
    exit 0
fi
cp="-g -pthread -fsanitize-coverage=trace-pc,trace-loads,trace-stores -fno-sanitize-link-runtime"
hook=$root/sdk/c/patina_compute.c
g=$root/tests/guests
clang -O1 $cp -o "$out/races" "$g/counters/races.c" "$hook"
clang -O2 $cp -o "$out/pool" "$g/counters/pool.c" "$hook"
clang -O2 $cp -o "$out/spinpoints" "$g/threads/spinpoints.c" "$hook"
clang -O2 $cp '-D__builtin_ia32_pause()=((void)0)' -o "$out/spinwait" "$g/costs/spinwait.c" "$hook"
clang -O2 $cp -o "$out/cellpoke" "$here/cellpoke.c" "$hook"
clang -O2 $cp -o "$out/loop" "$here/loop.c" "$hook"
clang -O2 -g -o "$out/loop-stock" "$here/loop.c"
clang -O2 $cp -o "$out/mixed" "$here/mixed.c" "$hook"

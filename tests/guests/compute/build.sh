#!/bin/sh
# Compute-point guests into $1/compute/ (/guest/compute/ in the sandbox): C programs rebuilt
# with clang's coverage flags and sdk/c/patina_compute.c, from sources other areas already
# use where they exist (deps lists them), and Rust programs built with cargo, the coverage
# RUSTFLAGS and the SDK's `compute` feature. Without clang, clang++, gcc or g++ the C guests
# are not built and MISSING says so: this script succeeds, so other areas are not blocked, and
# tests/compute fails.
#   races, pool       the counters area's syscall-free races (races at -O1 as there; pool at
#                     -O2, where its `stats.done++` is one instruction in a stock build)
#   spinpoints        tests/guests/threads/spinpoints.c (`count`: a spin-wait that changes state)
#   spinwait          tests/guests/costs/spinwait.c with its spin lock's `pause` taken out
#   cellpoke          writes into, then unmaps, its own cell
#   loop, loop-stock  a loop between two clock reads, instrumented and not
#   mixed             threads, then stock and instrumented children (fork, vfork, exec)
#   deadline          a timer that falls due inside a loop; an endless loop; CPU clocks
#   rs-race           an atomics check-then-act (Rust, cargo with the flags; Cargo.toml);
#                     rs-race-stock the same built without them
#   rs-deadline       a loop that ends when a sleeping thread sets a flag (Rust)
#   races-gcc, pool-gcc  races and pool with gcc's edges only; races-gcc builds the hook file
#                     in a step of its own without the flags (as gcc 11 and older need)
#   cxx, cxx-gcc      cxx.cc with clang++ (all three kinds) and g++ (edges), the hook file
#                     compiled as C++
#   shlib, shlib-stock  shlib.c instrumented and stock, each with libcomp.so (instrumented),
#                     libplain.so (stock) and libcompdl.so (g++, by dlopen); every
#                     instrumented image links its own copy of the hook file
# The Rust guests need no clang. If the pinned Rust toolchain rejects the flags (they name an
# LLVM pass and its options, which carry no stability promise), rs-MISSING says so and
# tests/compute/05-rust fails with it; any other build failure fails this script.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out=${1:?guest dir}/compute
mkdir -p "$out"

rf="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-trace-pc"
rf="$rf -Cllvm-args=-sanitizer-coverage-trace-loads -Cllvm-args=-sanitizer-coverage-trace-stores"
rt=${PATINA_BUILD_DIR:?}/compute-rs-target
if ! (cd "$here" && unset CARGO_ENCODED_RUSTFLAGS && RUSTFLAGS="$rf" cargo build --release --offline --locked --quiet \
    --target x86_64-unknown-linux-gnu --target-dir "$rt") 2>"$out/rs-build.err"; then
    if grep -q 'unknown pass name\|Unknown command line argument\|failed to run LLVM passes' "$out/rs-build.err"; then
        { echo "this Rust toolchain ($(rustc -V)) no longer accepts the compute-point flags RUSTFLAGS=\"$rf\":"
          grep -m3 'error\|Unknown' "$out/rs-build.err"; } | tee "$out/rs-MISSING" >&2
    else
        cat "$out/rs-build.err" >&2
        exit 1
    fi
else
    cp "$rt/x86_64-unknown-linux-gnu/release/rs-race" "$rt/x86_64-unknown-linux-gnu/release/rs-deadline" "$out/"
fi
(cd "$here" && unset CARGO_ENCODED_RUSTFLAGS RUSTFLAGS && cargo build --release --offline --locked --quiet \
    --bin rs-race --target-dir "$rt-stock")
cp "$rt-stock/release/rs-race" "$out/rs-race-stock"
rm -f "$out/rs-build.err"

if ! command -v clang >/dev/null || ! command -v clang++ >/dev/null || ! command -v gcc >/dev/null || ! command -v g++ >/dev/null; then
    echo "clang, clang++, gcc or g++ is not installed: the compute-point guests are not built" | tee "$out/MISSING" >&2
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
clang -O2 $cp -o "$out/deadline" "$here/deadline.c" "$hook"
gp="-g -pthread -fsanitize-coverage=trace-pc"
gcc -O2 -c -o "$out/hook-gcc.o" "$hook"
gcc -O1 $gp -o "$out/races-gcc" "$g/counters/races.c" "$out/hook-gcc.o"
rm "$out/hook-gcc.o"
gcc -O2 $gp -o "$out/pool-gcc" "$g/counters/pool.c" "$hook"
clang++ -O2 $cp -o "$out/cxx" "$here/cxx.cc" -x c++ "$hook"
g++ -O2 $gp -o "$out/cxx-gcc" "$here/cxx.cc" -x c++ "$hook"
clang -O2 $cp -fPIC -shared -DLIB=comp -o "$out/libcomp.so" "$here/shlib-lib.c" "$hook"
g++ -O2 $gp -fPIC -shared -DLIB=compdl -o "$out/libcompdl.so" -x c++ "$here/shlib-lib.c" "$hook"
clang -O2 -g -pthread -fPIC -shared -DLIB=plain -o "$out/libplain.so" "$here/shlib-lib.c"
link="-L$out -Wl,-rpath,\$ORIGIN -lcomp -lplain -ldl"
clang -O2 $cp -o "$out/shlib" "$here/shlib.c" "$hook" $link
clang -O2 -g -o "$out/shlib-stock" "$here/shlib.c" $link

# Scheduling: where threads switch, and what is not covered

One thread of the program runs at a time; at each scheduling point the seed decides which runs
next. Every seed is another interleaving, so races, deadlocks and ordering bugs need no flag:
sweep seeds. The points:

- every system call, and every spin hint (`pause`; on arm64 `yield`, `isb`, `wfe`, `wfi`);
- **load-time points**: as the program and every library it loads are mapped, Patina maps a
  rewritten copy of their code with a point before each backward branch, backward call,
  indirect jump and atomic instruction. Nothing changes on disk;
- **walks**: some switches are taken a few instructions past such a point, so a load, a change
  and a store between two points can be split too.

Computation moves the clock (1 ns per point passed), so a timer, a timeout or `[run]
time-limit` cuts a CPU-bound loop where it falls due. Each seed draws how often threads switch:
half the seeds often, for short programs and tests, half rarely, for long programs at their
natural pace. There is nothing to set.

A race between two plain accesses in a loop, with no system call between them, is found by
seeds alone:

<!-- transcript points
dir: /tmp/races
arch: x86_64
setup: cp "$GUESTS/rw-races" races
skip: 1
exit: 1
-->
```sh
cc -O2 -pthread -o races tests/guests/rewrite/races.c
patina sweep --seeds 1..20 -- ./races lms
```

The first run of a program rewrites each file once, and keeps the plans in
`~/.cache/patina/plans` (deleting it costs only time). A run that plans for more than a second
says so on stderr. `[run] cpus` (default 4) is the CPU count the program sees, which sizes its
thread pools; another count gives every seed another schedule.

## What is not covered

- **Code made at run time** (JIT output: V8, the JVM) and code the rewriter cannot see as code
  get no points: threads switch there only at system calls and spin hints. A thread computing
  there for 20 ms without either is checked for spinning, and yields if it is. `patina run`
  prints a `load-time points:` line naming what went without points.
- **A window far from any point** (a load and a store several instructions from the nearest
  loop, call or atomic) is split rarely. Rebuild the code with compute points (below).
- **Weak memory**: one thread runs at a time, so a store another CPU sees late never happens, and
  a locked read-modify-write is never split.
- **A seed belongs to its binaries**: the same seed is the same run only with the same program
  and libraries on the same kind of host.

A thread that computes for 10 s of CPU time without a scheduling point while another waits ends
the run `unsupported`, stop `compute-stall`, naming where it was: a spin-wait whose loop changes
something on each pass, or a calibration loop that sees no time pass. `--timeout` (wall
seconds) ends a run stuck in code without points, as `timeout`.

`[sched] preempt = "traps"` in `patina.toml` is a diagnostic: threads switch only at system
calls, spin hints and spin probes. It tells whether a finding needs a switch inside computation.

## Deeper search: rebuilt code

Rebuilt with a compiler's coverage flags and Patina's hook file, the program's own code gets a
point at every branch, and with clang and Rust at every load and store: a race between any two
accesses is found as often as one at a loop. `examples/stats-c` updates shared statistics from
four workers without their lock, a load and a store far from any point; the stock build seldom
shows it, the rebuilt one does:

<!-- transcript stats-cp
dir: /tmp/stats
exit: 0 1
-->
```sh
clang -O2 -pthread -fsanitize-coverage=trace-pc,trace-loads,trace-stores -fno-sanitize-link-runtime \
  -o stats-cp examples/stats-c/stats.c sdk/c/patina_compute.c
patina sweep --seeds 1..10 -- ./stats-cp
```

```text
new: failure exit: lost updates: N of N jobs counted; exit 1   (seed 2: patina replay /tmp/stats/patina-out/sweep/seed-2)
...
compute points: /tmp/stats/stats-cp (edges, accesses)
...
```

The build lines, with `PATINA` a checkout of the repository:

```text
C, C++  clang -fsanitize-coverage=trace-pc,trace-loads,trace-stores -fno-sanitize-link-runtime, plus PATINA/sdk/c/patina_compute.c in each executable or shared library
Rust    patina-dst with features = ["compute"], then RUSTFLAGS as below, and cargo build --target x86_64-unknown-linux-gnu (arm64: aarch64-unknown-linux-gnu)
Go      import _ "github.com/JacobHayes/patina/go/patina/compute" in package main; CGO_ENABLED=0 go build -gcflags=all=-d=libfuzzer
Python  no rebuild (3.12 or later): PATINA/sdk/python on PYTHONPATH, then python3 -m patina app.py
```

<!-- no-run rust-compute: a Rust project of your own to build -->
```sh
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 \
  -Cllvm-args=-sanitizer-coverage-trace-pc -Cllvm-args=-sanitizer-coverage-trace-loads \
  -Cllvm-args=-sanitizer-coverage-trace-stores" \
  cargo build --release --target x86_64-unknown-linux-gnu
```

Building with `cargo build --target` keeps the flags off build scripts and proc macros. A Rust program that uses nothing
else of the SDK says `use patina_dst as _;`. gcc takes `-fsanitize-coverage=trace-pc` only and
gives branches alone, which cannot split `x++`: prefer clang. In Go, points are at comparisons;
`go test` binaries cannot be built this way, so build the scenario as a `main` package. In
Python, a point is each line and each jump: races between lines are found, a race inside one
line rarely, and the interpreter's C code has none.

**Did it take?** `patina run` and `patina sweep` print a `compute points:` line naming the
rebuilt files that ran; no line means the flags did not reach the code that ran. Code not
rebuilt (libc, the prebuilt Rust standard library, the Go runtime) has no compute points. A seed
of a stock build is another run on a rebuilt one.

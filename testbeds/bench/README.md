# bench — microworkloads for the overhead benchmark

Fixed-work programs in one `std` binary, each isolating one cost that Patina adds
to a native run. `mise run bench` (`scripts/bench.py`) runs them natively and
under `cargo patina run` alongside the larger testbeds; see VALIDATION.md,
"Overhead benchmark", for how to run it and read the results.

| workload | what one iteration does | the Patina cost it isolates |
|---|---|---|
| `compute` | one SplitMix64 step folded into a digest | none per iteration: the loop makes no syscalls, so only the fixed start-up cost remains |
| `fileio` | create, write 512 bytes and close a file, then open, read back and close it | the filesystem boundary (Patina serves it from its in-memory filesystem) |
| `condvar` | one turn of a strict two-thread alternation on a `Mutex` + `Condvar` | a scheduler hand-off between two threads |
| `pipe` | one 8-byte round trip between two threads over a pair of pipes | a pipe transfer plus the hand-off it forces |
| `tcp` | one 64-byte loopback TCP echo | the SimNet stream path plus the hand-off |

```sh
bench <compute|fileio|condvar|pipe|tcp|doors> --iters N [--dir PATH]
```

`fileio` works under `--dir`, which it leaves as it found it. Each run halts and
checks itself: every read-back, reply, echo and turn is compared with what it
should be, and the loop's step count is verified. It then prints

```text
BENCH_RESULT workload=<name> iters=<n> digest=<16 hex digits>
```

The digest depends only on the workload and `--iters`, so a native run and a
Patina run with the same arguments print the same line, and the benchmark
fails when they do not. A clean run also reports a `Pass` verdict under
`bench-outcome` carrying the same fields. A failed check reports a `Violation`
under the workload's name, echoes it as `BENCH_VIOLATION`, and exits 1.

`doors --class <sync|clock|mutex|pipe|pread> --iters N --dir PATH` selects one
hot-path class per invocation. Sync calls `getpid` (checking identity without
hashing it); clock checks monotonic `clock_gettime`; mutex does uncontended
pthread lock/unlock; pipe writes then reads eight bytes on the same thread;
pread repeatedly reads and checks a primed 4 KiB file. Setup runs before the
loop. Each result also includes its class and logical libc call count (`ops`);
mutex and pipe count both doors per iteration. Every class gets its own gated
series, so another class cannot dilute a regression. `--help` prints usage.
The benchmark measures N and 2N calls and uses their elapsed-time difference
per extra logical call, subtracting fixed launch/setup/teardown costs. Both
result lines must match across legs. Signed timing differences remain in the
paired bootstrap; a nonpositive median in a draw has unbounded ratio uncertainty.
Nonpositive/undefined confidence bounds or a wide A/A interval are inconclusive;
later quiet samples can resolve isolated negative differences. Sync uses a larger
loop because its door is tiny.

The cached pread default keeps the untimed full recording within the trace
resource limit; increasing its loop can make the operation-count probe refuse.

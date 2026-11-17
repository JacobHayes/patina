# Evidence

What Patina (`ARCHITECTURE.md`) has been shown to do, one line per result. Unless a section
names another host, measured 2026-11-12 to 2026-11-16 on one host: a KVM guest, Linux 7.0,
24 vCPUs (AMD Ryzen 9 9950X), run directories on XFS; "Second hosts" adds five GitHub
runners. The scripts behind each claim are `./check evidence` and the `area` tier of each
test directory.

The workloads W1-W9 (`tests/durability/bench/workloads.py`): W1 Rust threads and files under
machine crashes, W2 tokio multi-thread, W3 SQLite from C, W4 stock static Go, W5 CPython, W6 a
shell pipeline over coreutils, W7 fork and exec, W8 sockets under network faults, W9 the fjall
harness.

## Determinism

The claim: a seed and an input give one boundary log, whatever the host does. Checked by
repeating each (workload, seed, faults) cell under varied host conditions (`patina verify
--vary repeat,cpu,load,aslr,sandbox,parallel,env,time`) and comparing digests.

| Check | Result |
|---|---|
| Final matrix: 29 workloads and attack guests x seeds 1-5 x faults off/on, 2,030 comparisons, ~15,000 runs | 1,985 identical; 20 bucket D (insn-probe under `cpu`/`parallel`, by design); 19 B6 `internal` (by design); 6 B13 (fixed, re-run 210/210 identical) |
| Soaks: W2, W6, W9 (W9 with crashes), 1,000 runs each, faults on, under `load` and `parallel` | one digest each |
| Time variant: 26 workloads and guests, runs 600 s apart | 26/26 identical |
| Seeds: every concurrent workload, 10 seeds | 10/10 distinct digests |
| `rows29` guest (29 rows no other run reached), seed 1, every variant but `time` | identical |
| Table strength (`patina table`) | 227 C, 158 A over 385 known syscalls |

The list of difference kinds did not plateau: new kinds appeared up to the last matrix. Run
the protocol again after any change to the engine, kernel, host or filesystem. A sweep
runs each seed once; repeating runs buys nothing per run.

### The thirteen differences found, and how each ended

| | What differed | Kind | Ended |
|---|---|---|---|
| B1 | `SO_COOKIE` on `AF_UNIX` | host-global counter | socket options are an allowlist; others `ENOPROTOOPT`, recorded |
| B2 | `SO_NETNS_COOKIE` | host-global counter | as B1 |
| B3 | `SO_TIMESTAMP*` cmsgs (host clock), `SO_PEERPIDFD` | host clock | as B1 |
| B4 | launcher umask reached the guest | inherited process state | every inherited item reset from one list (`sup/inherit.rs`) |
| B5 | launcher `RLIMIT_FSIZE` enforced underneath | inherited process state | rlimits fixed; fsize below the minimum ends `internal` |
| B6 | `F_SETPIPE_SZ` refused once the uid's pipe pages ran out | per-user host accounting | a refused size ends `internal` (limit, below) |
| B7 | `readlink` through a `/work` symlink to `/proc/1` | host names via a policy bypass | every path argument resolved against the policy first |
| B8 | `net-chunk-max` moved unrelated delivery draws | fault-plan coupling (engine bug) | own sub-key; split is an `Injected` record |
| B9 | host file atime moved by `relatime` | host clock through metadata | guest files are tmpfs copies; `/usr` atime reads as mtime |
| B10 | XFS speculative preallocation in stdout's block count | deferred kernel work | stdio are memfds |
| B11 | stdout extent count by writeback timing | deferred kernel work | stdio are memfds |
| B12 | `MADV_COLLAPSE` 0 or `EAGAIN` by huge-page availability | host resource | answers `EINVAL`, recorded |
| B13 | wire step read sockets of a process the kernel was still tearing down | async kernel work read before its barrier (engine bug) | exit barrier first in the step |

### Bucket D: detected only on replay, by design

| Entry | Label |
|---|---|
| JIT code (anonymous executable memory) is not scanned for `rdrand`/`rdseed` | `unscanned_exec_mappings` |
| Core identity: `cpuid` APIC fields, `rdpid`, `lsl` CPU number (shown: insn-probe, 20 comparisons; no workload) | `insn_scan.rdpid_sites` (arm64: `PACGA`, `pacga_sites`); others show as a divergence |
| XSAVE in-use bits (`xgetbv(1)`, FP headers) (argued; never varied) | none |
| In-flight descriptors freed by unix-socket GC (shown: scmrights) | `unix_sockets_in_flight` |
| Changes to host files under `/usr` | none; replay diverges at the first read |
| Per-user pipe accounting (B6) | run ends `internal` |

### Containment

Program code that reaches into the runtime ends the run `unsupported`, stop `containment`
(ARCHITECTURE.md, "Containment"); a program set on defeating the runtime is out of scope.
Measured 2026-11-16 (reproducers in `tests/determinism/attack/contain`, regression
`sandbox/11-containment`).

| Hole | Before | Now |
|---|---|---|
| C1: `ctlwrite` adds an hour to the clock's word | one store: monotonic 3700 s, run `liveness` | `containment`: read of the control region's `magic` at `0x602000000000` |
| C1: a random byte stored at a random offset of the control region (or the log) mid-run | silently changed the run | `containment` naming the address and field (as `slot 162 (tid)`); same digest twice |
| C2: `gadget`, jumps to each `0f 05` byte pair in runtime text | 611 pairs; the real `CLOCK_REALTIME` and `getrandom` returned, run `ok` | 3 pairs (the count depends on the build); each ends `containment`: the stub's after one untrapped call, before the program sees the result; the rest trapped, never made |
| `tidptr`: a thread's clear-tid pointer at the control region's published address | the runtime stored through it itself: run `internal` (runtime fault) | ignored, as the kernel does: `liveness` (glibc's join waits for ever, natively too) |
| C3 (stdout a host file), C4 (supervisor descriptors through `/proc/1/fd`) | | closed earlier |

| Check | Result |
|---|---|
| Per trap, `costs getppid` / `costs clock`, 2,000,000 calls, 5 runs each, before / after | 1.17 / 1.13 µs and 1.07 / 1.13 µs (means; within run-to-run spread) |
| `mprotect` read-only then read-write of a shared memfd mapping (the rejected design), per pair | 1.95 µs (64 KiB), 1.30 µs (1 MiB, 1 page in 64 touched), 7.8 µs (1 MiB touched) |
| W1-W9, `rs-net`, `tokio-echo`, `py-net`, `go-net`, seeds 1-2, before / after | 30/30 same outcome (`ok`); digests equal except where the program calls `execve` (W2, W4-W7): that record's first argument is the address of the path the runtime rewrote on its own stack, which moved 16 bytes; every other record equal |
| `./check` every area but `evidence` and `nightly` | all pass but `procs/09-subprocess` and `runtimes/04-shell`, which fail the same way before the change on this host |

## Finding bugs: storage

fjall 3.1.13 under the harness (`tests/guests/fjall-harness`), crash models from the
operation log; rate = seeds that reproduce / seeds run.

| Finding | Rate |
|---|---|
| F1 | 11/300 |
| F2 | 1/1,000 (seed 634) |
| F3 | 12/600 |
| F4 (a failed fsync, then a good one) | 2/1,000 |
| F5 | 56/100 |
| F6 | 1/1,000 |

SQLite: `synchronous=FULL`/WAL and `EXTRA`/DELETE kept every acknowledged row, 500/500;
`FULL`/DELETE lost acknowledged rows under `posix-strict` in 274/500 (allowed by POSIX, not
by ext4-ordered). W1 (`--crash machine:5`): correct version 500/500 under both models; planted
bug A (no fsync before the ack) caught 233/500 under ext4-ordered, 330/500 under posix-strict;
bug B caught 315/500 under posix-strict only.

## Spin-waits and scheduling points

A spin-wait loops in user space until another thread changes memory, so a run that preempts
only at system calls never hands the turn to that thread. Pause points (every executed
`pause` yields) and spin probes (a thread computing for 20 ms of CPU time is single-stepped
for a loop that changes nothing, and yields there) reach these loops without counters; what
neither reaches ends `unsupported` with stop `compute-stall`. Measured 2026-11-16 on an AMD
Ryzen 9 9950X (family 0x1a), each sweep run once under the evidence lock:
`./check evidence sched/evidence-spin` (with `PATINA_BASE` naming a build without pause
points), `runtimes/evidence-go-stalls`, `counters/evidence-go` and `counters/evidence-costs`.

Which spin-waits execute `pause`: glibc `pthread_spin_lock`, a C test-and-set lock with the
usual hint, Rust `spin_loop` locks and `std::sync::Mutex`'s spin phase, Go's `procyield`. Go's
background sweeper polling an idle heap does not; spin probes find it.

| Check (default 4 CPUs, 20 seeds a row unless stated) | Result |
|---|---|
| Spin table, 7 spin-waits, system calls only (`pause-points = false`, `spin-probes = false`) | glibc spin lock, C spin lock and Rust spin lock (each with a call inside) `compute-stall` 20/20; the 4 others `ok` |
| Spin table, pause points only | 140/140 `ok` |
| Spin table, default | 140/140 `ok` |
| W1-W9, default, with their faults | no `compute-stall`; W8 `sockets all` fails 20/20 on an injected reset (its faults draw `net-reset-permille=30` for every send, so every seed resets a connection, and the guest exits on `ECONNRESET`); W9 seed 5 failed on an injected `ENFILE` after a crash, which the harness judged a finding (fixed; `storage/11-unjudged`); the rest `ok`; W4: 26,265 pause points, 1,956 spin preemptions |
| W4 (stock Go), 100 seeds, spin probes off / on | `compute-stall` 92/100 / 0/100 |
| go-sweep, 100 seeds, spin probes off / on | 99/100 / 0/100 |
| go-sweep at 24 CPUs, 100 seeds, spin probes off / on | 97/100 / 0/100 |
| W4 and go-sweep, `--preempt branches`, 100 seeds each | 100/100 `ok`, 100 distinct digests; 5 seeds x 20 runs under `--vary cpu,load,aslr,sandbox`, faults off and on: identical |
| Spin table (call inside), `--preempt branches`, 100 seeds each | 0 stalls in 300 seeds |
| A pause-point guest under `verify --runs 5 --vary cpu,aslr` | one digest |
| Largest measured skid | 425 branches (margin 1,024) |

What still ends `compute-stall` without counters: a spin-wait with neither a system call nor
`pause` whose iterations change state (a counter or a timestamp it computes), and an endless
loop while another thread waits. A lone thread computing is left alone (2 s of compute is
`ok`).

Cost of pause points, W1-W9, faults off, seeds 1-5, one run at a time pinned to one core,
median `wall_ms`, against a build without pause points:

| | W1 | W2 | W3 | W4 | W5 | W6 | W7 | W8 | W9 |
|---|---|---|---|---|---|---|---|---|---|
| Without | 12 | 42 | 15 | 136 (1/5 `ok`) | 96 | 914 | 212 | 108 | 29 |
| `pause-points = false` | 12 | 46 | 13 | 188 | 101 | 1,118 | 213 | 109 | 28 |
| Default | 12 | 46 | 13 | 383 | 101 | 1,127 | 214 | 109 | 28 |

W4 pays for 7,242 pause points (its Go workers spinning for work); the build without them
stalls on 4 of its 5 seeds. W6's extra time is the instruction scan (the `pause` candidates
of `sh` and coreutils, decoded at every `execve`), paid with pause points on or off.

The 4-CPU default: enough workers for races, and few enough that a stock Go or tokio
runtime's idle workers do not dominate the schedule (go-sweep stalled on every seed at 24
CPUs with pause points alone).

The fjall findings below were swept at 24 CPUs before pause points. At the default their
seeds move: F1 reaches 3-4 seeds in 100, F3's liveness 3 in 100, F4 3 cells of the 100 x 10
grid; F2 and F6 appeared in none of 1,000 seeds and still reproduce at their seeds with
`--cpus 24` and `pause-points = false` (`tests/storage`).

Red/green: ignoring the page comparison of a fixed point fails `sched/10-spin` (a counting
loop was treated as a spin); a pause point that does not yield fails `insn/10-pause` (glibc
spin lock times out); a watchdog that never ends a run fails `skeleton/09-stall`; falling back
to traps when `--preempt branches` is not available fails `counters/01-unprivileged`.

Counter preemption on Intel: on an Intel Xeon 6975P-C (CI runner with a PMU),
`counters/02-counter` and `05-exact` stopped at different instructions for the same count,
`06-migrate` gave 5 different digests in 5 runs, and the race seed `03-races` relies on no
longer found the double spend. Counter preemption is therefore refused on every CPU but AMD
family 0x1a, and a seed reproduces only on the same family.

### arm64

Spin probes on arm64 step in software: a `brk` planted at the decoded successor, exclusive
pairs stepped whole, written pages by userfaultfd write-protection (ARCHITECTURE.md). Hosts:
the hosted runner (`ubuntu-24.04-arm`, Neoverse-N2, 4 CPUs, Linux 7.0, gcc 13, guests built
natively), run once from a throwaway branch, and the development VM (Apple M4, 4 CPUs, Linux
7.0; gcc guests built there, Go and Rust guests cross-built). Seeds and digests are per
architecture. 2026-11-17.

| Check (default 4 CPUs, 20 seeds a row unless stated) | Result |
|---|---|
| Spin table, 10 spin-waits (the x86_64 seven, the C lock without its hint, two `ldaxr`/`stxr` locks), system calls only, runner | glibc spin lock, C spin lock with and without the hint, Rust spin lock (each with a call inside) and both exclusive-pair locks `compute-stall` 20/20; the 4 others `ok` |
| The same, pause points only | glibc spin lock (no hint on arm64), the C lock without the hint and both exclusive-pair locks `compute-stall` 20/20; the rest `ok` |
| The same, default | 200/200 `ok`; 4,141 spin preemptions in each of glibc's and the hintless lock's 20 runs, 405 in each exclusive-pair lock's |
| W1-W9, default, with their faults, runner | no `compute-stall`; W4: 2,579 pause points, 596 spin preemptions; W8 and W6 fail 20/20 on injected errors (W6 `ok` on x86_64; no pause point or probe in it) |
| W4 (stock Go), 100 seeds, spin probes off / on, runner | `compute-stall` 84/100 / 0/100 |
| go-sweep, 100 seeds, spin probes off / on, runner | 100/100 / 0/100 |
| go-sweep at 24 CPUs, 100 seeds, spin probes off / on, runner | 97/100 / 0/100 |
| `verify --runs 5`, `--vary cpu,aslr` and `--vary repeat,cpu,load`, runner: `spinpoints flag`, the glibc, C (hint, no hint), Rust and both exclusive-pair locks, go-sweep seeds 1 and 2, W4 | one digest each; the same on the VM with `cpu,aslr` |
| Exclusive-pair locks under `verify --runs 20 --vary cpu,aslr,load`, seeds 1-100 each, runner | 200 of 200 one digest; with the retry branch after the store left out of the pair (red), 4 of 300 diverged (seeds 1-150 each): the store failed spuriously (an interrupt clears the monitor) and the retry passed the planted point, one more yield |
| `spinpoints text 1000`: 1,000 rounds, each a find, executable segments checksummed after each, runner | `text same after 1000 rounds` |
| Stock `go-race`, seeds 1-20, runner | 20/20 `ok` |

The development VM gave the same outcomes and found no divergence in 80 verifies of the
exclusive-pair locks before the retry rule; only the runner showed spurious store failures.

Cost. A probe step (a trap, a breakpoint planted and restored through `/proc/self/mem`)
takes about 4.8 us on the runner: a probe that gives up at the trace limit (`spinpoints
wander`, 65,536 steps) costs about 0.3 s of wall time (1.54 s against 1.22 s with probes off,
3 seeds); one that ends early on a loop that changes state (`spinpoints alone`) about 0.5 ms
(4 probes, 1.668 s against 1.667 s). A find takes 8 to 9 steps on `spinpoints flag` (the
run 104-108 ms), and a round of `spinpoints text` (a thread, 20 ms of CPU time spinning
before the probe, the find) 32 ms. On the VM, runs that need no probe cost the same with
probes on and off (own spin lock, spin-then-yield, mutexes, Rust: medians 9-19 ms either way,
10 seeds); those that need one end `compute-stall` without probes and `ok` with them in
40-50 ms (glibc and hintless spin locks, exclusive-pair locks), go-sweep in 259 ms (20 of
20), W4 in 168 ms (20 of 20; 3 of 20 `ok` without probes, median 48 ms).

Red/green on the VM: stepping into an exclusive pair one instruction at a time (no pair
rule), the compare-and-swap lock runs to `--timeout` (1.4 M yields) and the swap lock ends
`compute-stall`; without the written-page check, the counting spins are reported found; with
the step's breakpoints never restored, `spinpoints text` reports its text changed after
round 1. Without taking out the earlier spin point when a second loop is found right after
it (a bug the x86_64 probe had too), `spinpoints twice` dies of `SIGTRAP` on x86_64
(`sched/10-spin`).

## Instruction sites on arm64

Measured 2026-11-17 on the arm64 development VM (Apple M4, Ubuntu 24.04, Linux 7.0) and a
GitHub `ubuntu-24.04-arm` runner (Neoverse-N2, 7.0.0-1017-azure). The census is `./check
evidence insn/evidence-census` (`tests/insn/lib/census.py --summary` over `/usr/bin`,
`/usr/sbin`, `/usr/lib`, `/usr/libexec`): every aligned word of every executable section that
matches a site the scan would patch, classed by whether a literal load of the same file reads
it, or a `$d` mapping symbol marks it as data.

| | Dev VM | Runner |
|---|---|---|
| ELF files, words of executable sections | 2,493, 121.2 M | 4,421, 502.9 M |
| Words read by literal loads; words under `$d` | 2,101; 18,714 | 24,274; 217,663 |
| Pause hints in executable sections | 115 (`isb` 72, `yield` 43) | 1,066 (`isb` 966, `yield` 62, `wfe` 38) |
| `RNDR`/`RNDRRS`, `PACGA`, counter reads | 0, 0, 27 | 12, 0, 283 |
| Of those, read by a literal load or under `$d` | 0 | 0 |
| Matches in non-executable sections (not scanned) | `pacga` 17, pause 4 | `pacga` 81, pause 19 |

No literal-pool word in either census collides with a site, so the literal-load guard is a
guard, not a filter that changes what is patched; `insn/09` checks it on a guest that puts
the `yield` encoding in a literal pool. Data reached otherwise (a table addressed by `adr`)
cannot be told from code; the census found no `$d`-marked word that matches either, which is
why the policy is to patch every match the literal guard leaves.

Which spin-waits carry a hint, from their disassembly: glibc 2.39 `pthread_spin_lock` has
none (a load and branch loop; glibc's arm64 libc has no `yield`, `isb`, `wfe` or `wfi`); Rust
`spin_loop` is `isb` (the spin phase of `std::sync::Mutex` and `RwLock` too); Go 1.27
`procyield` is `isb`, older Go `yield`; libuv and libcurl use `yield`; CPython 3.14 has `wfe`.
Other `isb` sites are cache maintenance after writing code (CPython, libffi, libgcc_s, pcre2)
and straight-line-speculation padding after `ret` (40 in libgcrypt, never executed). Patching
an `isb` keeps its meaning: the exception taken on the patch and the return from it are
context synchronization events. Cost of one hint, native, per execution: dev VM `yield`
0.3 ns, `isb` 8.5 ns, `wfi` 90 ns, `wfe` 1.3 us; runner `isb` 9.4 ns, `wfi` 130-145 ns, `wfe`
6-15 us.

| Check (arm64 development VM) | Result |
|---|---|
| Spin table (`insn/10`), pause points on | own spin lock (`yield`) and Rust spin lock (`isb`) `ok`, 5 runs one digest; the same lock without a hint and glibc's spin lock `compute-stall` |
| `insn/06` scanner audit (ld.so, libc, libstdc++, libcrypto, libffi, libgcrypt, python3, Go, Rust, the insn guests) | every site the census finds is patched, none in data |
| BTI (`arm64/09`): static and dynamic programs marked BTI, `isb` spin through an indirect call; a signal handler in a `-z force-bti` shared object | `ok`, one digest; an indirect call to a non-landing pad dies of `SIGILL` in both (the patch is not a landing pad and the runtime does not answer a branch-target fault); a handler with a landing pad runs, one without dies of `SIGILL`, as natively |
| Hosts: `RNDR` (`HWCAP2_RNG`), BTI, execute-only pages | dev VM: no, yes, yes; runner: no, no, no |

Execute-only patched pages (so a guest cannot read the patch) were not built: the runner
cannot make them, and every literal-pool read from a patched page would fault and need a
load emulator.

## Compute points

Code rebuilt with clang's coverage flags and `sdk/c/patina_compute.c` (ARCHITECTURE.md,
"Scheduling points"). The race guests are `tests/guests/counters/races.c` and `pool.c`, built
stock and rebuilt (`tests/guests/compute`); `pool`'s `stats.done++` is one `incq` in the stock
-O2 build, and a load hook, a load, `inc`, a store hook and a store in the rebuilt one.

| Check | Result |
|---|---|
| `races b`, seeds 1-200: stock / rebuilt, default `compute-gap` / rebuilt, `compute-gap=8` (`compute/evidence-races`, 2026-11-16) | 0 / 0 / 26 double spends; seed 18 replays identical |
| `pool`, the same columns | 0 / 5 / 155 lost updates; seeds 9 and 1 replay identical |
| A 50 ms `setitimer` falling due inside a loop with no system call (`deadline`, C), seeds 1-20 at the seed's gap and at `compute-gap=0`; seed 1 under `verify --runs 20 --vary cpu,load,aslr,sandbox` (`compute/evidence-deadline`, 2026-11-16, AMD Ryzen 9 9950X, 10 s) | 40 of 40 `ok`; the handler ran 3,001 virtual ns after the 50 ms in every run (the arming call, the handler's clock read and the delivery), one deadline stop each; verify identical over 20 runs |
| The same for Go and Rust: `go-deadline 134217728` (a CPU loop polling `ctx.Err()` under `context.WithTimeout(50 ms)`) and `rs-deadline` (a thread sleeps 50 ms and sets a flag the loop polls; exits 0 if it sees it at 50 to 60 ms) (`compute/evidence-deadline`, 2026-11-16, AMD Ryzen 9 9950X, 28 s with C) | Go: 20 of 20 `ok` at the seed's gap (61 to 65 deadline stops) and 20 of 20 at `compute-gap=0` (1 to 21); verify identical over 20 runs. Rust: 20 of 20 `ok` at the seed's gap; at `compute-gap=0` 4 of 20: the cut stops the loop at the 50 ms, but whether the woken sleeper runs then is the seed's pick, and with no seeded switch the loop otherwise runs to its next refill (2^22 events, 4.2 ms), so the flag is seen 58 to 75 ms in (seeds 1-5 by hand); verify identical over 20 runs |
| Stock guests (`c-threads`, `rs-threads`, `spinpoints flag`, stock `races b`, `pool`, `loop-stock`, `sig-basic`, `fs-tour`, `go-sig`), seeds 1-3, the build with deadline cuts against the one before it (by hand, 2026-11-16) | 27 of 27 the same digest and `result.json` (but `wall_ms`, `sup_hwm_kb`, `spin_steps`) |
| Stock programs, this build against the build before compute points (`compute/evidence-identity`, `PATINA_BASE` = 0.6.1): W1-W9 with their faults, `c-threads`, `rs-threads`, `spinpoints flag`, stock `races b`, `pool` and a loop, seeds 1-3 | 45 of 45 the same digest and `result.json` (but its host measurements `wall_ms`, `sup_hwm_kb` and `spin_steps`, which differ between two runs of one build) |

The prototype (`patina-spike` T14, a switch at 1 event in 10) found 14 and 165 of 200. At the
default range the race guests, whose threads run 12 to 15 events after they start, are rarely
hit: tests use `compute-gap=8`.

Costs, measured by hand on 2026-11-16, one run each, pinned to one core:

| What | Cost |
|---|---|
| Rebuilt loop of 10^8 iterations (1.25 x 10^8 events), `compute-gap=0` | 125,001,003 virtual ns between its clock reads (one event per ns, one trap charge); 0.67 ns of wall time per event (the hook's armed fast path) |
| The same loop natively: hooks inert / stock build | 0.74 ns per event / 0.18 ns per iteration |
| A compute point that switches (`compute-gap=8` and `64`, one thread) | 3.5 µs each (a trap and a supervisor hand-off) |
| `counters/compute.c` (`loops`, `threads`), stock against rebuilt, seeds 1-5 under Patina | stock 0.85 s / 0.21 s; rebuilt 0.59 to 6.6 s / 0.29 to 3.8 s by the seed's mean gap (64514: 0.59 / 0.29 s; 115: 6.6 / 3.8 s); natively stock 0.41 / 0.21 s, rebuilt 0.56 / 0.26 s |

The stock `loops` run under Patina pays for spin probes (it computes with no system call); the
rebuilt one has compute points and needs none.

Red/green: an `exit` that never arms the cell fails `compute/01-races` (no failure in 40
seeds), `02-spin` (`compute-stall`) and `03-inert`; a point that does not yield fails
`01-races` and `02-spin`; unchecked cell reads and writes fail `03-inert` (the unmapped cell
ends in `SIGSEGV`, not `compute-cell`); answering a hello for an image that never made one
fails `03-inert` (a stock run gains `compute`); a point at `compute-gap=0` that never consults
the supervisor fails `03-inert` (a program that empties its cell forever never reaches its
time limit). A cell not cut at the next deadline fails `04-deadline` (the handler 69 µs late
at seed 1's gap, 335 µs at `compute-gap=0`); CPU clocks without events and a replay that does
not compare the gap fail it too; a refill that does not yield fails `02-spin` (`compute-stall`
at `compute-gap=0`).

### Rust

The SDK crate's feature `compute` and the RUSTFLAGS of docs/GUIDE.md ("The SDK"), stable
1.99.1. Guests `tests/guests/compute/rs-race.rs` (the prototype's atomics check-then-act) and
`rs-deadline.rs`, built with cargo exactly as the guide says. `rs-race`'s window is one edge:
a load hook, the load, an edge hook, then `lock sub`; a point at the edge hook is the race.

| Check | Result |
|---|---|
| `rs-race`, seeds 1-200: stock / default `compute-gap` / `compute-gap=8` (`compute/evidence-races`, 2026-11-16) | 0 / 1 / 5 double spends; seeds 106 and 52 replay identical |
| `rs-race` by hand, seeds 1-200 at `compute-gap=4` / `2` | 11 / 38 double spends |
| Lost updates of two threads, 3 each, seeds 1-200 at `compute-gap=8`, rebuilt / stock: `AtomicUsize` load then store; `Mutex` read under one lock, written under another; a shared `Cell` (`get`, `set`); an atomic load, `to_string`, a store | 36 / 0, 40 / 0, 36 / 0, 108 / 0; each first failing seed replays identical |
| The same lost update in a crate built without the flags (as the prebuilt standard library is), called from a rebuilt program | 0 / 200: no event inside it, so no point inside it |
| A rebuilt binary (`stdrace`): which functions call hooks | 28: the program's own and the generic or inlined standard-library code compiled into it; none in `Mutex::lock_contended`, `Barrier::wait` or `fmt` |
| A crate using `always!` and `sometimes!`, rebuilt, seeds 1-100 at `compute-gap=8` | its own code instrumented (12 hook calls in the checked function); `always!` violated on 2 seeds, replays identical |
| `rs-deadline`'s events per round of the same work (64 multiply-adds), `compute-gap=1024`: `opt-level` 0 / 1 / 3 / cargo `dev` profile (0, debug assertions, overflow checks) / 3 with `codegen-units` 1 / 16 | 1,688 / 194 / 195 / 2,723 / 195 / 195; every run ends `ok` at 50.03 ms |
| tokio (multi-thread, 4 workers, 8 tasks, `tokio::sync::Mutex`, `sleep`), `cargo build --target`: natively 2,000 rounds | stock 0.07 s user / rebuilt 0.17 s user (wall 2.3 s, sleep-bound) |
| The same under Patina, seed 2 (mean gap 248) / seed 1 at `compute-gap=0`, `65536`, `1024` | 3.0 s, 429,129 switches (stock: 0.19 s) / 0.27, 0.26, 0.86 s wall; `verify --runs 3 --vary cpu,aslr,load`: identical |

`cargo build` with the flags and no `--target` fails to link the build scripts (`proc-macro2`'s,
and the guests' own `rs-build.rs`): undefined `__sanitizer_cov_trace_pc`. With `--target` the
flags reach only the target's crates, and proc macros (`tokio-macros`) and build scripts are
built without them. Neither `codegen-units` nor the profile changes what is instrumented, only
how many events the same work makes. A toolchain that rejects the flags fails the guests' build
with "this Rust toolchain (...) no longer accepts the compute-point flags", shown by
`compute/05-rust` (planted by misspelling the pass name).

Red/green: hooks whose slow path never says hello fail `compute/05-rust` (no image in `compute.images`).
The SDK without the feature exports the same 16 symbols as before it and no `__sanitizer_*`.

### Go

`go/patina/compute` and `-gcflags=all=-d=libfuzzer`, go 1.27.3, `CGO_ENABLED=0`, the runtime
unpatched. Guests `tests/guests/compute/go/`: `go-race` (16 rounds of a spin barrier, then an
`atomic.Int64` check and `Add`), `go-deadline` (a CPU loop polling `ctx.Err()` under a 50 ms
`context.WithTimeout`), and W4 (`go-static`) rebuilt with the import. Measured by hand,
2026-11-16.

| Check | Result |
|---|---|
| What the compiler instruments (`go tool objdump` of W4: 20,168 hook calls) | every package but `runtime` and its internal packages (`objabi` runtimePkgs: the compiler turns the flag off there); generic runtime code instantiated in user packages (`runtime.AddCleanup[...]`) is instrumented, as is code the runtime calls back: `sync.poolCleanup` (during a stop of the world) and `internal/godebug.update`. No hook between `entersyscall` and `exitsyscall` (the `syscall` wrappers compare nothing) |
| The hooks | nosplit, no stack check, no allocation, no pointer store (the cell is a NOPTR word set in assembly), no Go comparison; the event, hello and point are assembly |
| `go-race`, seeds 1-40 at `compute-gap=8`, `--cpus` 2 / 4; stock build at 4 | 19 / 20 / 0 double spends; seed 4 replays identical, and `verify --runs 5 --vary cpu,aslr,load` is identical |
| `go-race` at the default gap, seeds 1-40 | 0 (one round only: 0 of 40 at `compute-gap=8`, hence 16 rounds) |
| `go-deadline`, default gap, seeds 1-3 | `ok`, cut by its context at 50.44 / 50.04 / 50.01 virtual ms; 2 events per iteration; 0.2 s wall at mean gap 64514, 2.0 s at 115 |
| `go-deadline` at `compute-gap=0` | not cut (runs to its bound): with no switch the timer's thread never runs; the deadline cut at gap 0 is separate work |
| 2^28 iterations, wall: rebuilt under Patina at gap 0 / stock under Patina / natively rebuilt / natively stock | 1.25 s / 0.21 s / about 4.2 ns / 0.4 ns per iteration |
| W4 rebuilt (`all`), seeds 1-20 | 20 `ok`, no `compute-stall`, `internal` or `nondeterministic`; about 918k events; `verify --runs 5 --vary cpu,load` seed 3 identical |
| W4 `net` (HTTP server and 16 clients), seeds 1-5, median `wall_ms` | stock 22 ms, rebuilt 46 ms (about 90k events) |
| `for !flag.Load() {}` on an `atomic.Bool` | has a hook (`Load` is `!= 0`, inlined and instrumented); `go-race boolspin` ends `ok` |
| `go test -c` with the flag and the package | does not link: `duplicated definition of symbol runtime.libfuzzerTraceCmp1` (internal/fuzz; with `-tags libfuzzer`, the runtime). Build the scenario as a `main` package |

Go preempts a loop without calls by a signal, honoured only at an asynchronous safe point.
Under Patina a signal is delivered as a thread leaves the runtime, which after a compute point
is inside the hook's assembly, never a safe point: in the first version a spin barrier at
`--cpus 1` was never preempted (SIGURG at the hook's `ret`, every time) and each run logged a
switch record every 8 events until `--timeout` (about 45 MB of boundary log per second of wall
time; 6 runs filled 98 GB). The hooks now check the goroutine's stack guard after a point and,
if the runtime has asked, call a function whose prologue takes the runtime's own preemption
path. `go-race boolspin` at `--cpus 1` then ends `ok` (one preemption, 10 ms of virtual time,
sysmon's interval); `go-race` at `--cpus 1`, `compute-gap=8` is still slow (one preemption per
barrier wait, 10 ms of virtual time each, 1.4 million switches): 40 of 40 seeds reach a 15 s
`--timeout`.

The flag also adds libfuzzer's 8-bit edge counters (a byte increment per block): a spin with
no comparison writes memory on every pass, so spin probes see it change and it ends
`compute-stall` rather than yielding.

Red/green: a fast path that never takes the slow path fails `compute/06-go` (`go-deadline`
never cut); a hook whose `//go:linkname` the toolchain does not resolve fails the guests' build
into `GO-BROKEN`, which `06-go` prints with the Go version.

### The default gap

Which `compute-gap` range to use when a run gives none. Each cell is one `patina sweep
--seeds 1..200 -j 6 --keep none --fault compute-gap=RANGE` (log-uniform per seed), run once
under the evidence lock on 2026-11-16, this host; about 8 minutes of sweeps in all. Tiny
programs are the race guests above. The longer ones were built for this and not kept:

- `jobq`: C, clang, 4 threads take 400 jobs from a locked queue, each job about 5,000 events
  of hashing; after a job a worker adds to a shared count without the lock, with W events
  of other work between its load and its store. About 2.0 M events a run. "every job" makes
  that update after each job, "1 in 20" after every 20th.
- `gorace`: Go, an HTTP server and 8 concurrent clients, 80 requests, about 380 k events. The
  handler reads a served count, formats a log line with `strconv.Itoa` (a few comparisons)
  or with `fmt.Sprintf` ("wide", a few hundred), and stores the count plus one.
- fjall: `tests/guests/fjall-harness`, release, rebuilt with the SDK's `compute` feature and
  the flags, under F1's `--crash machine:3` (F1 depends on the crash, not on a race). About
  4.8 M events a run.

Findings in 200 seeds:

| Program | Stock | `2..64` | `8..1024` | `64..65536` | `2..65536` |
|---|---|---|---|---|---|
| `races b` (22 events) | 0 | 38 | 4 | 0 | 6 |
| `pool` (530) | - | 110 | 32 | 5 | 41 |
| `rs-race` (190) | - | 13 | 1 | 1 | 4 |
| `go-race` | - | 86 | 18 | 2 | 25 |
| `races-gcc b` (14, edges only) | - | 19 | 2 | 0 | 3 |
| `jobq` every job, W = 4 | 0 | 154 | 145 | 80 | 101 |
| `jobq` every job, W = 200 | 0 | 200 | 200 | 191 | 189 |
| `jobq` 1 in 20, W = 4 | 0 | 0 | 0 | 1 | 0 |
| `jobq` 1 in 20, W = 200 | 0 | 0 | 0 | 3 | 1 |
| `gorace` | 0 | 0 | 0 | 0 | 0 |
| `gorace` wide | 0 | 200 | 191 | 112 | 128 |
| fjall F1 | 11 | 8 | 7 | 6 | 9 |

Cost, mean / largest `wall_ms` of one run (the tiny programs take 10 to 11 ms a run at
every setting):

| Program | Stock | `2..64` | `8..1024` | `64..65536` | `2..65536` |
|---|---|---|---|---|---|
| `jobq` every job, W = 4 | 16 / 21 | 1,145 / 4,812 | 199 / 1,205 | 33 / 123 | 378 / 4,697 |
| `gorace` wide | 37 / 68 | 259 / 966 | 72 / 266 | 43 / 73 | 116 / 1,134 |
| fjall F1 | 59 / 128 | 2,485 / 19,392 | 502 / 9,946 | 104 / 684 | 858 / 16,004 |

The fjall harness's debug build (cargo `dev` profile, about 78 M events), seed 1, one run
each at a fixed gap: 65,536: 0.26 s and 1.4 MB of run directory; 64: 5.2 s, 230 MB; 8:
35 s, 1.8 GB; 2: stopped by `ulimit -f` (4 GB) after 83 s and 45 M events. Every switch
writes a record. At the default, seeds 1, 2, 3 draw mean gaps 64,514, 248 and 115 (the
draw depends on the seed alone, so they are the same for every program) and take 0.24, 1.5
and 3.1 s, against 0.05 s stock.

What the numbers say:

- A switch has to land in the window, and the other thread has to reach its own access
  before the first resumes. Tiny programs need gaps under about 10 events. On the long
  programs a gap of 64 to a few thousand events found the dense races almost as often as
  gaps of 2, and the sparse one (`jobq` 1 in 20) was found by none: a smaller gap there buys
  nothing, because the other threads barely move between switches.
- Per seed, the wide range `2..65536` finds more than the default on every tiny program
  (4 to 12 times where the default found any) and 1.0 to 1.3 times as much on the dense long
  ones. It costs 3 to 11 times the default's mean time on the long programs, its slowest
  seed 15 to 40 times the default's slowest, and on a 78 M-event debug build a seed at gap 2
  takes minutes and writes gigabytes of log. Per second of machine time the default finds
  2.4 to 12 times as much on the long programs.
- The default stays `64..65536`, drawn log-uniformly per seed. The guide gives
  `--fault compute-gap=2..64` for short programs: it found the tiny races 13 to 43 times as
  often as the default (where the default found any), at no measurable cost. Tests that need a find in a handful of seeds keep
  their fixed gaps (`8`, or `2` for the one-edge windows).
- A known race found in fewer than 1 seed in 100 at the default: `races b`, `races-gcc b`,
  `rs-race`, `go-race` (2 in 200) and `jobq` 1 in 20. The last is missed at every range, so
  the follow-up that switches on memory another thread touched (race-directed points) is
  the next step for search; not built.

### arm64

The same hooks on Linux arm64: the SDKs' raw call is `svc #0`, Go's hook is
`go/patina/compute/compute_arm64.s`. Seeds and digests are per architecture and per kind of
host; nothing here is compared with x86_64. Hosts: the hosted runner (`ubuntu-24.04-arm`,
Neoverse-N2, 4 CPUs, Linux 7.0, clang 18, gcc 13; build `c9f0a2ac`, guests built natively) and
the development VM (Apple M4, 4 CPUs, Linux 7.0; the same build, clang, Rust and Go guests
cross-built). 2026-11-17.

| Check | Result |
|---|---|
| `compute/evidence-races`, seeds 1-200, stock / default `compute-gap` / `compute-gap=8`, runner | `races b` 0 / 0 / 30 (seed 3 replays identical); `pool` 0 / 1 / 113 (seeds 29 and 4); `rs-race` 0 / 0 / 8 (seed 17); `go-race` 0 / 0 / 102 (seed 2); stock `go-race` then ended `compute-stall` on every seed (its spin barrier needs a spin probe); with spin probes (below) it is `ok` on seeds 1-20 |
| The same on the VM | `races b` 0 / 0 / 30; `pool` 0 / 1 / 113; `rs-race` 0 / 0 / 6 (seed 2); `go-race` 0 / 0 / 102; every first failing seed replays identical |
| `compute/evidence-deadline`, runner (204 s) | C: 40 of 40 `ok`, the handler 3,001 virtual ns after the 50 ms in every run, one deadline stop each; Go: 20 of 20 at the seed's gap (62 to 65 deadline stops), 20 of 20 at `compute-gap=0`; Rust: 20 of 20 at the seed's gap, 10 of 20 at `compute-gap=0` (the sleeper's wake-up is the seed's pick, as on x86_64); `verify --runs 20 --vary cpu,load,aslr,sandbox` identical for all three |
| `compute/evidence-identity`, runner, `PATINA_BASE` = `70803a86` (compute points a stand-in): W1-W9, `c-threads`, `rs-threads`, `spinpoints flag`, stock `races b`, `pool`, a loop, seeds 1-3 | 45 of 45 the same digest and `result.json` (W4 and `spinpoints flag` end `compute-stall` in both builds: spin probes) |

What compiles to what (disassembly of the guests above): every read-modify-write on memory is a
load, an operation and a store. With clang and Rust a load hook and a store hook precede the
load and the store, so a switch can fall between them, as on x86_64; gcc gives edges only and
cannot. Atomics are never split: C `stdatomic` and Rust atomics compile, by default, to calls
of the out-of-line helpers (`__aarch64_ldadd8_acq_rel` and its siblings, from libgcc or Rust's
compiler-builtins), which are not rebuilt and choose an LSE instruction or an exclusive
`ldaxr`/`stlxr` loop at run time (both hosts have LSE); with `-march=armv8.1-a` they are single
`ldaddal`, `casal`, `swpal`, and with `-mno-outline-atomics` inline exclusive loops. Go's
`sync/atomic` is assembly in the runtime, never instrumented. Every exclusive pair in the
rebuilt `rs-race` (14) and `go-race` (413) has no call or `svc` before its store; clang and gcc
test programs the same. An atomic load (`ldar`) gets a load hook before it, as a plain load does.

Red/green (VM): the compute-point stand-in restored fails `compute/03-inert` (`arm64-unported`);
`patina.h` without its arm64 call fails `sdk/01-languages` (C inert under Patina), and so do
`patina.py` accepting only `x86_64` and the Rust SDK without its arm64 call; the Rust compute
hooks without it fail `compute/05-rust` (no hello); `compute_arm64.s` that never reports the
preemption mark fails `compute/06-go` (`boolspin` with one P livelocks).

## Costs

| What | Cost |
|---|---|
| Trap answered in the runtime | 0.75 µs |
| Trap with a supervisor hand-off | ~2.85 µs (round trip ~2.3 µs) |
| Start-up, static guest / `python3 -c pass` | 5.0 ms / 14.66 ms |
| W1 against Patina 0.5.0 | 15.5 ms vs 35.3 ms |
| W9 against Patina 0.5.0 | 31.5 ms vs 27.6 ms |
| W9 with crashes and filesystem faults | 38.9 ms per run, 148.6 runs/s (1.92x no-fault) |
| Crash materialisation | ~3 ms per MB of log |
| `fork`+`execve`+`wait` of a dynamic program | 1.5 ms (native 0.38 ms; mostly the instruction scan) |
| `--preempt branches` | 9.7 µs per trap, 1.7-2.3 ms per preemption, W1-W9 wall x0.6 to x6.5 (W1 x6.5, W2 x4.4, the rest under x2) |
| `--mount DIR:/guest:copy` copy into tmpfs | ~0.3 ms per MB |

## Known limits

Not implemented (run ends `unsupported` or the call is refused): `timer_create`,
`ITIMER_VIRTUAL`/`ITIMER_PROF`; raw, netlink and packet sockets, UDP multicast and broadcast;
`sched_*` policy calls
and `get`/`setpriority`; anything outside Linux x86_64.

- A spin-wait with neither a system call nor `pause` whose iterations change state (a
  counter, a timestamp it computes itself) ends `compute-stall` without `--preempt
  branches`. `--preempt branches` needs `CAP_PERFMON`, an exposed PMU and an AMD family
  0x1a (Zen 5) CPU, the only family checked; its seeds reproduce on the same CPU family only; a skid past
  the margin ends `internal`; a guest reading its own text during a hop or at a spin point
  sees `int3`. A lost update inside one read-modify-write instruction cannot be found by any
  preemption.
- `preempt-permille = 0` livelocks Go (it polls the clock forever).
- Per-user pipe accounting is shared by every sandbox of the uid: 9 parallel guests with 500
  pipes each end `internal`.
- The virtual inode table holds 16,384 objects; the next ends `internal`. The virtual
  `RLIMIT_NOFILE` is not enforced (`EMFILE` at the real limit, 4,091). A launcher
  `RLIMIT_FSIZE` below the boundary log's size kills `patina` with no outcome.
- Stdio are held in memory up to `PATINA_STDIO_MAX` each (1 GiB).
- Busy many-waiter workloads re-attempt often (16-thread ring: 7.4 attempts per blocking call).
- Bad guest pointers in path strings and futex words are a runtime fault (`internal`), not
  `EFAULT`; a signal frame on an unmapped guest stack likewise.
- Network differences from TCP a guest can see: no `POLLERR` on reset; `EPIPE` without a round
  trip; socket buffer and TCP options recorded and inert; `MSG_OOB` refused; no source
  address from `recvfrom`; one `connect` per socket; a reset in the accept queue fails
  `accept` with `ECONNABORTED`. UDP: a receive carries no ancillary data; `recvmmsg` returns
  once one datagram is there; a datagram's `SO_RCVBUF` charge is at least the kernel's, so a
  queue may drop slightly earlier than Linux; an unreachable port gives `ECONNREFUSED` only to
  a connected sender, and makes the socket readable, not `POLLERR`.
- Blocking-I/O gaps: `sendfile`/`copy_file_range`/`splice` with a socket or pipe side answer
  `EINVAL`; `F_SETLKW` deadlock detection is absent; `ppoll`/`pselect6`/`epoll_pwait` masks
  are not applied; `poll` restarts with the full timeout.
- Processes: another process's `/proc/<pid>` is refused (`ps` sees nothing); `fork` or a thread
  `clone` inside a vfork child ends the run; `wait4` rusage is zero; unusual `clone` flag sets
  end the run.
- Instruction scanning: 4,096 patched sites per process (`rdrand`, `rdseed` and `pause`; arm64
  `RNDR`, `RNDRRS` and the four hints); shared executable file mappings are not scanned
  (labelled); a page holding a patched site is a private copy and shows as its own line in
  `/proc/self/maps` (arm64: libpcre2's one `isb` adds two lines to `grep`'s maps). On arm64, data in text not read by a literal load is patched if it matches (none
  found, above); `CNTPCT_EL0` and `RNDR` on a host without it raise `SIGILL` as without Patina.
- Storage: the ext4 model treats preallocated holes as in place (more generous than ext4);
  F4's state has not been produced on a real device; the materialiser holds the whole log in
  memory; `/tmp` is not tracked; the initial tree has no times (virtual epoch).
- Go `os/exec` deadlocks when an injected `EIO` hits its status-pipe read (Linux never does
  that).
- Repeat stability is shown on five more hosts ("Second hosts"); the long matrix, soaks and
  time variant are from one host only.

## The SDK channel

The four SDKs share one guest script (`tests/guests/sdk`), checked by `tests/sdk/01-languages`
and `02-points` (quick, together under 1 s).

- **Inert outside Patina.** Under `strace`, each of the C, Rust, Go and Python guests makes
  exactly one call of system call `0x7061` for the whole script, answered `-1 ENOSYS`; every
  later SDK call is a load and a branch. In a Docker 29.1.3 container with the default seccomp
  profile (kernel 7.0.0), a static probe got `-1 ENOSYS` (errno 38) and the C, Go and Python
  guests ran their script unchanged and exited 0.
- **Violation.** In each language a failed `always` ends the run `violation` with
  `must-hold: balance -1`, the code after it does not run, and the boundary log ends with the
  `patina_sdk` trap followed by `SdkViolation`. `patina verify --runs 2` of that run is
  identical.
- **Accounting and declared sites.** The four languages produce equal site tables (minus
  source locations) and equal decisions at seed 5; a site declared but never reached is in the
  table with `evaluated: 0` and its location.
- **Keyed decisions.** The same seed gives the same decision bits; enabling a second point
  leaves the first's bits unchanged; another seed differs; a forced rate of 1000 fires every
  time and 0 never; a `sometimes` holds on some seeds of 1..8 and not others; forked and
  exec'd children report into the same table; with `faults-after-setup` a point is silent
  before `setup-complete` and fires after. Red/green: keying a point's firing by the global
  sequence number instead of its own count fails `02-points` ("a second point moved the first
  one's decisions"); not ending the run on a failed `always` fails `01-languages`.
- **Cost of a passing assertion under Patina.** A tight loop of trivial arithmetic with a
  passing `always` each iteration, best of three `wall_ms`:

  | Guest | 10M plain | 10M with assert | 100M plain | 100M with assert |
  |---|---|---|---|---|
  | C | 16 | 16 | 64 | 69 |
  | Rust | 16 | 16 | 67 | 67 |
  | Go | 16 | 16 | 66 | 73 |

  The assertion traps once; afterwards it is one load and a branch (Go's `Check` inlines).
  Python natively, 1M iterations: 0.09 s plain, 0.12 s with the assertion.
- **Example.** `examples/ledger` under `--buggify`, seeds 1..6: seeds 1 and 5 end
  `violation` with `ledger-sorted`, the rest `ok`.

## Faults: the plan, errno fidelity, the memory limit, attribution

Host: the development VM (kernel 7.0.0-43-generic), 2026-11-16.

- **Crash and restart with disk faults** (`./check evidence faults/evidence-crashes`, 63 s):
  ack-log under `--faults disk --crash machine`, 200 seeds per crash model: the correct
  variant is `ok` on 200 of 200 under both `ext4-ordered` and `posix-strict` (67 runs crash at
  least once, 91 and 90 crashes in all); the variant without the record fsync is caught
  (`INVARIANT acked-record-lost`), and its `faults.recent` ends with the machine crash naming
  `/work/data.log`. Under `--crash process:20` the same variant is `ok` on 100 of 100 (97 with
  a crash). Crash-point coverage over 500 seeds at `machine:20`: 1,381 crashes, 453 distinct
  post-crash trees, crashes between every write and its fsync, the record fsync and the
  acknowledgement, and the rename and the directory fsync.
- **Plan independence** (`tests/faults/15-plan.sh`): adding `--fault net-chunk-max=1..4` to an
  ack-log run under `--faults disk --crash machine:0..30` leaves every other resolved value and
  the boundary log equal. Red/green: resolving every range from one shared counter instead of a
  draw keyed by the setting's name moves the crash rate (`machine:17` to `machine:28`) and fails
  the check.
- **Errno fidelity** (`tests/faults/14-fidelity.sh`): stock Go running coreutils through
  `os/exec`, `fs-error-permille=1000 fs-short-permille=300`, is `ok`; pipes saw short transfers
  only. Red/green: letting pipes and unix sockets draw `EIO` puts an injected error on a pipe
  and fails the check.
- **Memory limit** (`tests/faults/06-memory.sh`): `mem-limit-mb=64` refuses a guest mapping
  1 MiB at a time at MiB 55 (the process's own data, runtime included, counts) on both runs of
  `verify`, and a 2 MiB `malloc` then returns NULL with `ENOMEM`. Red/green: disabling the
  check maps all 100 MiB.
- **Self-check** (`tests/faults/16-counts.sh`): a crash-enabled run whose operation log the
  test hook corrupts ends `internal`; red/green: without the end-of-run check it ends `ok`.
- **Path swaps** (`examples/serve-c`, `tests/examples/01-examples.sh`): the `lstat`-then-`open`
  server under `path-swap-permille=300` is caught on 5 of seeds 1..20 (first seed 4, replayed
  `identical`, `faults in every failing run: path-swap`) and 10 of seeds 1..40; at 200 and 500
  it is 8 of 40. The fixed variant (`O_NOFOLLOW`, then `fstat` compared with the `lstat`) is
  `ok` on 40 of 40 at each rate. The example's two sweeps add about 0.25 s to `quick`. Under
  `--crash machine:30` with `path-swap-permille=500` (seeds 1..12) and with a machine crash at
  a swap's own seq (between its two renames), `patina log ops --check` passes and replay is
  `identical`. W1 to
  W9 at seed 3, faults off and on, have the same digests as the build before path swaps (18 of
  18), and `tests/determinism/05-faultplan.sh` checks the W3 log is unchanged up to the first
  swap and that an enabled class that never fires leaves the digest unchanged.
- **UDP** (`tests/net/09-udp.sh`, 6.3 s, adds about 3 s to `quick`; guests in
  `tests/guests/udp`): a C request/response pair that retries on timeout is `ok` with faults
  off and under `net-drop-permille=200`; its variant without a retry ends `liveness` at the
  first seed tried under `net-drop-permille=50` (seeds 1, 2 and 3 all do) with
  `net-drop dropped datagram 9 from :32769 to :32768` last, and replays `identical`. A reader
  that trusts datagram order fails at the first seed under the default delivery jitter alone;
  one that orders by sequence number is `ok`. Red/green: making every datagram's delay the
  same constant makes the order-trusting reader pass seeds 1..8 and fails the check. Stock Go
  (`net.ListenPacket`, `DialUDP` with read deadlines), CPython (`socket` threads and
  `asyncio` datagram endpoints) and tokio are identical under `verify --runs 3 --vary
  cpu,aslr`, `ECONNREFUSED` from a connected send to a port nobody holds included. Lookups of
  `localhost` and `unknown.example` in C (`getaddrinfo`: `127.0.0.1`, then `EAI_NONAME`), Go
  (`[127.0.0.1 ::1]`, then "no such host" with `IsNotFound`) and Python (`gaierror -2`) are
  identical across runs and send no datagram (`net.datagrams` 0). Plan independence
  (`tests/determinism/05-faultplan.sh`, workload U1): with `net-drop-permille`,
  `net-dup-permille` or `net-reorder-permille` added, the first record that differs is the
  first injected fault. Stock TCP invariance: W1 to W9, W8 under `--faults net` and a fixed
  network plan, `rs-net`, `tokio-echo` and `go-net` (plain and `--faults net`) and `py-net`,
  seeds 1-2, give the same digest and outcome under the build before UDP and after (34 of 34).
  A program that only looks names up can still differ: glibc's `getaddrinfo`, given two or
  more addresses for a name, connects a UDP socket to each to order them, which used to fail;
  its runs now make those sockets (the same in every run). Review fixes, each with a check in
  `udp semantics` that fails without it: an error marker is queued once per socket, not once
  per refused datagram (a sender ignoring 2,000 refusals could fill the hidden end, hold later
  deliveries and never wake its reader); `FIONREAD` leaves a pending `ECONNREFUSED` pending;
  `shutdown(SHUT_RD)` wakes a thread in `poll`.

## Sweeps

`./check evidence sweep` (`tests/sweep/evidence-throughput.sh`, 400 seeds per line, `--keep
none`), 2026-11-16, this host:

| Guest | `-j` | Runs per second |
|---|---|---|
| `hello-static` | 1 | 109 |
| `hello-static` | 4 | 340 |
| `hello-static` | 8 | 529 |
| `python3` holding 500 pipes with 4 KB in each | 8, lowered to 1 | 29 (all `ok`) |

The 500-pipe guest hits the kernel's per-user pipe accounting (`fs.pipe-user-pages-soft`,
16384 pages here) at `-j 2` already: without the sweep's response, 381 of 400 runs at `-j 8`
ended `internal` (`host limit: errno 1 in pipe2`). The sweep now halves `-j` on such a run and
runs it again; a run that still hits the limit is counted in the report's `host:` line.

`tests/sweep/01-sweep.sh` (quick, about 3 s): on a guest with a lost-update race behind an
`always` and an exit 3 on a file error, 30 seeds with `fs-error-permille=30` give 19 failing
seeds in exactly two groups (9 and 10 seeds), each first seed replaying identically; the
file-error group names the injected class in every failing run. The 30 digests are equal at
`-j 4` and `-j 1`, and equal to the same seeds run alone. Red/green: adding the seed to the
signature splits the race into one group per seed and fails the check; not acting on a
replay's divergence turns a host file changing under the replay into a finding and fails it.

## Second hosts

One `patina` binary and one set of guest binaries, built once on the development VM from
`90c261f7` and copied unchanged to every host (`sha256` checked in each host's log). Each
cell is `patina verify --seed S --runs 5 --vary repeat,cpu,aslr,sandbox --mount
GUEST:/guest:copy [--faults all] -- CMD`, seeds 1 to 3, faults off and `all`: 11 guests,
66 cells, 330 runs per host. Guests: the seven of the reduced protocol (`hello-static`,
`hello-dyn`, `fs-tour`, `sockets all`, CPython `w5.py all`, `tokio-mt local`, `/bin/sh w6.sh`)
and four static ones to separate the host's libc from the engine (`fs-tour` and `sockets`
built `-static`, `tokio-mt` with `crt-static`, `go-static all`). 2026-11-16.

| Host | Image, kernel | CPU | Cells identical over 5 runs |
|---|---|---|---|
| development VM | 26.04, 7.0.0-43-generic | AMD Ryzen 9 9950X | 66/66 |
| GitHub `ubuntu-24.04` | 24.04, 7.0.0-1017-azure | AMD EPYC 9V45 | 65/66 (below) |
| GitHub `ubuntu-24.04` | 24.04, 7.0.0-1017-azure | AMD EPYC 9V74 | 66/66 |
| GitHub `ubuntu-24.04` | 24.04, 7.0.0-1017-azure | Intel Xeon 8370C | 66/66 |
| GitHub `ubuntu-24.04` | 24.04, 7.0.0-1014-aws | Intel Xeon 6975P-C | 66/66 |
| GitHub `ubuntu-latest` | 26.04, 7.0.0-1016-aws | Intel Xeon 6975P-C | 66/66 |

The runner pool moves: `ubuntu-24.04` landed on Azure AMD, Azure Intel and AWS Intel, and
`ubuntu-latest` on AWS Intel and Azure AMD, within one hour.

Within a host, the one difference: on the EPYC 9V45 runner, `w6.sh` seed 1 faults off, one
ASLR-on repeat ended `internal` (`HostError` code `HE_LOADER` right after a child's `execve`
and `Hello`: the runtime's loader failed before the new image's first instruction). Not
reproduced in 800 more ASLR-varied runs of that cell on an `ubuntu-24.04` runner, 140 on an
`ubuntu-latest` runner, 60 on the development VM, or the two later full matrices. It fails
closed (`internal`, not a silent divergence), but it varies run to run on one host: a defect,
open. Its message reads "errno 0 in read (code 2)": loader failures are printed as a system
call error.

Across hosts, cells with equal digests (of 66; the seven protocol guests, of 42, in brackets):

| | dev VM | Azure AMD 9V45 | Azure AMD 9V74 | Azure Intel 8370C | AWS Intel 24.04 | AWS Intel 26.04 |
|---|---|---|---|---|---|---|
| dev VM | | 12 (6) | 12 (6) | 12 (6) | 12 (6) | 12 (6) |
| Azure AMD 9V45 | | | 66 (42) | 36 (24) | 12 (6) | 12 (6) |
| Azure Intel 8370C | | | | | 12 (6) | 12 (6) |
| AWS Intel 24.04 | | | | | | 12 (6) |

`hello-static` and `sockets-static` give one digest per cell on all six hosts. Every other
guest differs between some hosts. The first differing record (`patina log diff`) and its
cause:

| What differed | Guests | Kind | Verdict |
|---|---|---|---|
| `uname` release (`7.0.0-43-generic`, `-1017-azure`, `-1014-aws`, `-1016-aws`) | `fs-tour`, `fs-tour-static` (the only difference for the static one) | kernel version | allowed |
| the host's `/lib64/ld-linux-x86-64.so.2` (first `rdtsc` at another address) or `/etc/ld.so.cache` (`fstat` output; Azure and AWS 24.04 images differ) | every dynamic guest, `python3`, `/bin/sh` | libc and loader from the host's `/usr` | allowed: dynamic guests run the host's `/usr` |
| a host program the guest runs (`seq` for `tokio-mt`, `os/exec` targets for `go-static`) | `tokio-mt-static`, `go-static` | host `/usr` | allowed |
| signal frame address and runtime buffer addresses moved by 0x100 or 0x180 bytes; the Rust alternate signal stack 0x3000 or 0x3eb0 bytes (`AT_MINSIGSTKSZ`) | `go-static`, `tokio-mt*`, `cpython`, `w6.sh` between AMD, Intel 8370C and Intel 6975P-C | CPU identity (XSAVE area size) | allowed |
| `/proc/self/mountinfo` 1306 or 1307 bytes: tmpfs options carry the launcher's `uid=`/`gid=` (1000 on the VM, 1001 on runners) while `stat` reports 1000 | `go-static` (Go reads mountinfo at start-up) | inherited launcher state | defect, open |

Two Azure 24.04 hosts with different AMD models give equal digests in all 66 cells.

New kinds of difference: one within a host (the ASLR-on loader failure, cause unconfirmed),
none across hosts (the mountinfo uid is the inherited-launcher-state kind, B4). What can be
promised: a seed gives the same run on one host, repeated, across CPUs, ASLR and sandboxes.
Across hosts, a statically linked guest that reads no host file gives the same run when the
CPU's XSAVE size is the same and it does not read `uname` or mountinfo; a dynamic guest
also needs the same `/usr` and `/etc/ld.so.cache`, which in practice means the same image.
Cross-host identity is not promised.

## Acceptance: fjall

fjall 3.1.13 under `tests/guests/fjall-harness` (invariants through `always!`, the two fault
points through `buggify!`), built with plain `cargo build`, debug unless named. Run by hand
with `patina sweep -j 6`, 2026-11-16, this host, patina 0.6.0-dev (`run.json` `version`;
the binary has no `--version`). `H` is the harness binary. Rate = seeds whose report group
has the finding's signature / seeds run.

| Finding | Command | Rate | First seed | Sweep wall |
|---|---|---|---|---|
| clean, debug | `sweep --seeds 1..100 -- H` | 100/100 `ok` | - | 1.4 s |
| clean, release | same, release build | 100/100 `ok` | - | 0.6 s |
| F1 `open-after-crash` (EEXIST) | `--seeds 1..300 --crash machine:3` | 6/300 | 62 | 7.7 s |
| F2 journal-entry assertion | `--seeds 1..2000 --buggify --env FJ_N=2000 --crash machine:1` | 0/2,000 | - | 66 s |
| F2, `--cpus 24` | same | 0/2,000 | - | 70 s |
| F2, `--cpus 24`, `pause-points = false` | same, seeds 1..6000 | 0/6,000 | - | 190 s |
| F3 writer sleeps forever (`liveness`) | `--seeds 1..600 --fault fs-error-permille=3 --crash machine:2 --buggify --env FJ_N=1000 --env FJ_WIPE_PARTIAL=1 --env FJ_LOG=1 --time-limit 400` | 24/600 | 31 | 10.5 s |
| F4 `batch-atomic-across-keyspaces` | `--seeds 1..10 --fault fsync-error-at=N --crash machine`, one sweep per N in 1..100 | 4/1,000 | N=35 seed 6 | 33 s |
| F5 `iterate-failed`/`reopen-failed` (UnexpectedEof) | `--seeds 1..100 --fault fs-short-permille=20` | 59/100 | 3 | 1.5 s |
| F6 `batch-atomic-across-keyspaces`, no fault but the crash | F2's sweeps | 0, 0, 2/6,000 | 2001 | (F2's) |

- Attribution: every F1 run names `crash`, every F4 run `crash, fsync-error`, every F3 run
  `fs-error`, every F5 run `fs-short`. The report names the class, not the crash kind.
- `fsync-error-at=2..4` ends `open-after-crash` in 30 of 30 runs: a failed fsync inside the
  first `Database::open` leaves the same unrecoverable partial database as F1.
- F2 and F6 under the harness before it used the SDK (buggify drawn from `getrandom`), same
  engine, `--cpus 24`, `pause-points = false`, seeds 1..2000: F2 3/2,000 (first 634), F6
  1/2,000 (first 946). The SDK harness reaches F6 at that schedule at a similar rate, F2 not
  in 6,000 seeds; nor with a `getrandom` call added at each fault point (0/2,000). At the
  default schedule, `--fault buggify-permille=1000` gives F6 1/1,000 (seed 259), F2 0/1,000.
- Replay: the first seed of F1, F3, F4, F5 and F6 replayed 5 times, each `identical` with the
  same digest; `patina verify --runs 5 --vary cpu,load` identical for each, and for the old
  harness's F2 seed 634 and F6 seed 946.
- Per run, no faults, release, `sweep -j 1` over 100 seeds: 27.6 to 30.7 ms in two
  measurements while other work shared the host (median `wall_ms` 23 to 27); debug 77 to 111 ms.
  Patina 0.5.0: 27.6 ms (release). Throughput at `-j 6`: 160 to 173 runs/s release, 62 to 69
  runs/s debug.

## Search quality: fjall F2 and F6

Why F2 and F6 of the fjall acceptance are rare at the defaults, 2026-11-16, this host, the
`engine` build after `3d485e87`. `H` is `tests/guests/fjall-harness` (debug). Each sweep is
`patina sweep -j 6 --seeds 1..2000 --buggify --env FJ_N=2000 --crash machine:1 -- H` plus
the setting named, run alone under the evidence lock; total sweep time about 15 min.

**What F2 needs** (the panic at fjall `journal/entry.rs:190`, a `debug_assert` on bytes read
back). The journal is preallocated to 64 MiB, so a batch written after the last fsync goes
into blocks a machine crash may keep or lose one by one. The panic needs a block boundary to
fall between an item's `value_len` and its `on_disk_value_len` (a 4-byte target per item),
the block before it kept and the one after it lost. The batch sizes are fixed by the batch
number, so the layout is the same in every run: in the 2,000-batch journal four batches
straddle a boundary that way, the first at offset 569,316 (batch about 800). A run finds F2
only if its one crash lands in the 2 to 5 crash points between that write and the next
journal fsync, about 1,700 crash points in, and the ext4 model then keeps the earlier block
(one draw in two) without a spontaneous commit after the write. The pre-SDK harness's three
seeds (634, 1173, 1514) all crash at that write, in runs where no fault point fired.

**What F6 needs** (`batch-atomic-across-keyspaces`, a table of keyspace `a` holding batches the
journal lost). fjall's worker persists the journal and then flushes every sealed memtable of
the keyspace, not only the one it was asked to. F6 needs the writer to commit a batch and
rotate `a` (fault point `manual-flush`) between those two steps, typically while it sleeps
100 ms in write backpressure, and then a crash after the new table and manifest are durable
and before the next journal fsync: a window of a few crash points. It all happens in the first
incarnation; the violation is found by the recovery check.

**Hypotheses.** Rates are seeds with the finding / seeds. F2 is also given as the expected
count per 2,000 seeds from 60 seeds each: one run without crash to locate the window, a forced
crash (`machine-at`) at each crash point of the window, and the chance a 1 per mille crash
first lands there.

| Setting | F2 | F6 |
|---|---|---|
| defaults | 0/2,000 (expected 0.17) | 0/2,000 |
| `--cpus 24`, `pause-points = false` | 0/6,000 (acceptance; expected 0.15) | 2/6,000 (acceptance) |
| pre-SDK harness (fault points from `getrandom`, active per process), `--cpus 24`, `pause-points = false` | 3/2,000 (acceptance), then 0/4,000 on seeds 2001..6000 (expected 0.19) | 1/2,000, then 1/4,000 |
| `manual-flush` always on (`point:manual-flush=250`): defaults | - | 0/2,000 |
| same, `pause-points = false` | - | 2/2,000 |
| same, `--cpus 24` | - | 1/2,000 |
| same, `preempt-permille = 300` | - | 1/2,000 |
| same, `preempt-permille = 30` | - | 1/2,000 |
| `point:manual-flush=1000` (fires at every evaluation): defaults | 0/2,000 | 6/2,000 |
| same, `pause-points = false` | 0/2,000 | 10/2,000 |
| `--crash machine` (3 per mille) | 0/2,000 | 1/2,000 |
| `--crash machine-at:2250..2450` (the window's region; boundary seq, as `-at` meant then; on seed 1 crash points 1,668 to 1,883 now) | 4/2,000 | 0/2,000 |

- Fault-point activation per run against per incarnation: both findings are made in the first
  incarnation and detected when the second opens the database, before any fault point is
  evaluated; F2's pre-SDK seed 634 had both points inactive. Re-drawing activation after a
  restart cannot change either, so it was not built.
- CPU count, pause points, preempt rate: the harness fixes fjall's worker count, and a run
  has about 20 pause points. In 60 seeds without a crash the number of crash points before
  F2's window fell into the same three groups at every setting (30 near 1,425, 14 between
  1,600 and 3,000, 16 beyond), set by which fault points were active. These settings move
  every draw, so they reshuffle which seeds find a bug; none changed either rate by more than
  the sampling noise of a few hits in 2,000.
- The old 3/2,000 for F2 was a run of luck: the expected count is the same for both harnesses,
  and the old harness found none in the next 4,000 seeds.
- What does change the rates: F6 scales with how often `manual-flush` fires in the window
  (6 and 10 in 2,000 at every evaluation, against about 1 in 2,000 at a quarter); F2 needs the
  crash in its window, and a crash position range over the region finds it 4 times in 2,000.
  Neither is a default to change: one is a fault point's rate, the other a window known in
  advance. The guide's "If a sweep finds nothing" gives both settings.

**At the defaults after the changes** (`-at` ranges; `unreachable` sites), same commands as
the acceptance, `H` rebuilt:

| Finding | Command | Before | After |
|---|---|---|---|
| clean | `--seeds 1..100` | 100 `ok` | 100 `ok` |
| F1 | `--seeds 1..300 --crash machine:3` | 6/300, first 62 | 6/300, first 62 |
| F2, F6 | `--seeds 1..2000 --buggify --env FJ_N=2000 --crash machine:1` | 0, 0 | 0, 0 |
| F3 | acceptance F3 command, 600 seeds | 24/600, first 31 (and 1 F6, seed 22) | the same |
| F4 | `fsync-error-at=N --crash machine`, N in 1..100 x seeds 1..10 | 4/1,000 | 4/1,000 (38 s) |
| F4, one sweep | `--seeds 1..1000 --fault fsync-error-at=1..100 --crash machine` | refused: not a number | 4/1,000 (25 s) |
| F5 | `--seeds 1..100 --fault fs-short-permille=20` | 59/100 | 59/100 |

`./check storage examples` passes (the examples find 14, 4, 11, 6 and 11 of 20 seeds). The
sweep summary no longer lists the harness's `open-after-crash`, `reopen-failed` and
`iterate-failed` (now `unreachable!`) as "`always` never evaluated"; `fresh-after-wipe-complete`,
a real invariant evaluated only with `FJ_WIPE_PARTIAL=1`, still is. No plain search over a
few seconds of seeds reaches F2; its check is a `--branch` sweep (below, "Crash-point
enumeration").

### Enumerating one seed's crash points

Does trying every crash point of a few seeds find F2 more often per CPU-second than the plain
sweep? 2026-11-16, this host, patina 0.8.0 (release), `H` debug. `tests/storage/evidence-crash-enum.sh`
(`./check evidence crash-enum`, under the evidence lock): one base run per seed
(`--seed S --buggify --env FJ_N=2000 --crash machine:0 -- H`), then one child per distinct
seq of its operation log, `--crash machine-at:SEQ` (when `-at` named a boundary seq: the
first crash point of each seq; the script now runs one child per crash point), 6 at a
time; CPU-seconds are the sum of `wall_ms`. A seed over 10,000 crash points is skipped. The plain sweep's expectation is
0.17 F2 runs in 2,000 seeds at about 0.2 CPU-s a seed: 4.3e-4 per CPU-second.

| Seed | Crash points | Children | F2 children (seq) | CPU-s | To first F2 | Children repeating a tree |
|---|---|---|---|---|---|---|
| 1 | 4,069 | 3,392 | 6 (2299, 2303, 3564, 3842, 4477, 4480) | 1,021 | 216 | 38% |
| 2 | 23,932 | skipped | | | | |
| 3 | 6,252 | 4,741 | 4 (7254, 7632, 7634, 7969) | 1,540 | 1,120 | 45% |
| 4 | 6,234 | 4,691 | 2 (3637, 7187) | 1,445 | 315 | 46% |
| all | | 12,824 | 12 | 4,006 | | |

- F2 per CPU-second: 12 / 4,006 = 3.0e-3 runs, 7 times the plain sweep's 4.3e-4. Counting
  F2 children with the same post-crash tree once: 9, 5.2 times. Every enumerated seed has F2;
  the first hit costs 216 to 1,120 CPU-s against the plain sweep's expected 2,300.
- Counting a seed once, enumeration finds 3 per 4,006 CPU-s, 1.7 times the plain rate: its
  gain is in reaching every window of a seed, not in finding more seeds.
- A child costs 0.30 CPU-s on average at 6 jobs (the base: 0.2 to 0.4). Every child
  crashed. The other non-`ok` children are F1 (`open-after-crash`, 5 or 6 a seed, all at
  seqs 125 to 143, the first `Database::open`); no F6.
- Seeds with a window: the script, then with a filter that kept only the journal writes
  within 8 KiB of the offsets of the F2 writes above (569,316, 1,097,826, 1,216,296,
  1,302,500, 1,381,000) and the operations after each up to the next journal fsync. Seeds 5 to 24: 7 over
  10,000 crash points (19,536 to 23,932), skipped; F2 in 12 of the other 13 (1 to 5 F2
  children each, 2,166 children in all). This probe uses the windows found above, so its
  rate is not a search rate.

### Crash-point enumeration

`patina sweep --branch`: each seed once with crashes on and never firing, then once per crash
point it counted (`--crash machine-at:N`), points ascending, seeds in turn.
`tests/storage/evidence-branch.sh` (`./check evidence evidence-branch`, under the evidence
lock), 2026-11-16, this host, this build (`H` debug), every sweep `-j 6 --keep fail`, run
once. CPU-s is the sum of `wall_ms` over the sweep's runs.

| Finding | Command (plus `-j 6 -- H`) | Runs with it / runs | CPU-s | Per CPU-s |
|---|---|---|---|---|
| F2, `--branch` | `--seeds 1..3 --branch --crash machine --buggify --env FJ_N=2000 --budget 200` | 2 / 7,283 (seed 1, points 1,721 and 1,724) | 1,032 | 1.9e-3 |
| F2, plain (expected) | `--seeds 1..2000 --buggify --env FJ_N=2000 --crash machine:1` | 0.17 / 2,000 | about 400 | 4.3e-4 |
| F6, same `--branch` sweep | | 4 / 7,283 (seed 2, points 1,378 to 1,382) | 1,032 | 3.9e-3 |
| F6, `--branch`, `point:manual-flush=1000` | the F2 command plus `--fault point:manual-flush=1000` | 18 / 7,179 | 1,006 | 1.8e-2 |
| F6, plain, `point:manual-flush=1000` | (Search quality, above) | 6 / 2,000 | about 9,000 (4.5 s a run) | 6.7e-4 |
| F1, `--branch` | `--seeds 1..3 --branch --crash machine --max-findings 1` | 2 / 28 (first seed 1@8) | 2 | 0.95 |
| F1, plain | `--seeds 1..300 --crash machine:3` | 6 / 300 | 38 | 0.16 |
| acklog-c, `--branch` | `--seeds 1 --branch --crash machine -- ./acklog` | 81 / 165 | 5.5 | 15 |
| acklog-c, plain | `--seeds 1..20 --crash machine -- ./acklog` | 6 / 20 | 0.46 | 13 |
| F3, `--branch` | F3's acceptance flags with `--branch --crash machine`, seeds 1..3, `--budget 120` | 46 / 6,102 (all 6,099 points) | 425 | 0.11 |
| F3, plain | F3's acceptance command, 600 seeds | 24 / 600 | 46 | 0.52 |
| F4, `--branch` | `--seeds 1..10 --branch --crash machine --fault fsync-error-at=1..100 --budget 120` | 0 / 8,000 (7,990 of 18,375 points) | 534 | 0 |
| F4, plain | `--seeds 1..1000 --fault fsync-error-at=1..100 --crash machine` | 4 / 1,000 | 103 | 3.9e-2 |

- F2 is found within the 200 s budget, 4.5 times the plain sweep's rate per CPU-second. In
  the sweep's order its first hit came after 602 CPU-s of children (the plain sweep's
  expectation is one hit per 2,300 CPU-s); seed 1 alone reaches it after 227 CPU-s.
- F6 appeared at the default rate in seed 2, the seed whose fault points are on (23,932
  crash points against 4,069 and 6,252): a seed that holds F6's prefix finds it, as expected.
  One sweep; a second with other seeds would say whether it is more than luck. With
  `manual-flush` at every evaluation, `--branch` finds F6 at about 27 times the plain rate
  per CPU-second (the plain cost is the 4.5 s base run measured for that setting).
- The early-window findings (F1, acklog-c) are found at once, at the plain rate or better.
  F3 and F4 need variety across seeds (fault plans drawn per seed, a failed fsync at a
  seed-chosen call): `--branch` spends its runs on few seeds and finds F3 5 times less often
  and F4 not at all in 120 s. Plain sweeps stay the tool for those.
- Plain sweeps unchanged: F1 6/300, F3 24/600 (and the one F6 seed), F4 (one sweep)
  4/1,000, F5 59/100, as recorded above. A run without `-at` gives the same digest as before
  the change (90 of 90 runs of W1 to W9, fjall and acklog over seeds 1 to 6, 35 with a
  crash, against the previous build).

Cost, from the F2 sweep's run directories:

| Row | Value |
|---|---|
| crash points per seed | 4,069, 6,252, 23,932 |
| child `wall_ms` | median 133; by quarter of the point's position: 110, 193, 270 ms (no child reached the last quarter) |
| share of a child's time that is the prefix it shares with its base | median 0.12 (base `wall_ms` times the crash's seq over the base's last seq, over the child's `wall_ms`) |
| children repeating a post-crash tree of the same seed | 44%, 63%, 53% |

Both criteria inputs of the deferred work: the prefix share is far below the 60% that would
make building the post-crash tree from the base's log worth a second way to produce a run;
children repeating a tree are over half in two seeds, but F2's two hits (points 1,721 and
1,724) share one tree, so skipping repeats would have dropped a finding.

`tests/storage/12-f2.sh` (nightly) is the standing check: `--seeds 1..2 --branch --crash
machine --buggify --env FJ_N=2000 --env FJ_WIPE_PARTIAL=1 --max-findings 2` must hold F2's
group. On this host it found F2 (seed 1, point 1,721) after 3,444 of 28,001 points, in
82 s; with `FJ_N=500` every one of the 7,908 points ran and only F6 was found, so the check
fails (288 s).

## Acceptance: Cairn and briefing

`patina` built from `fa1186af` (the CLI has no `--version`), 2026-11-16, this host, every
sweep under `capped`; `mise run sim` and the briefing sweep passed again on `f0031c52`. The applications are built with plain `cargo`; nothing of Patina is
linked but the SDK crate.

**Cairn** (`testbeds/durability`: the service on SQLite under disk faults and machine crashes;
`testbeds/multiplayer`: the HTTP server, four HTTP clients and an in-process agent under
buggify and network faults). Each `sim.sh` is `cargo test`, `cargo build --release`, one
`patina verify --runs 3 --vary cpu,load`, then sweeps whose exit status is the verdict
(out-of-reach oracles in the testbed's `patina.toml`):

| Command | Result |
|---|---|
| `patina sweep --seeds 1..100 -- cairn-durability` | 100 `ok` |
| `patina sweep --seeds 1..100 -- cairn-multiplayer` | 100 `ok` |
| durability `--buggify --faults disk --fault swarm=1`, 128 seeds | 128 `ok`, every oracle in reach held |
| durability `--crash machine`, 128 seeds | 128 `ok`; 2 to 3 crashes per run; all five crash oracles held, the torn log tail among them |
| durability `--crash machine --fault fs-error-permille=5`, 2000 seeds | 2000 `ok` in 64 s at `-j 6`: no acknowledged commit lost |
| durability `--crash machine -- ... --bug ack-before-commit` (planted client bug), 200 seeds | `violation always: durability-acknowledged-commit-present` in 154 of 200, attribution `crash` in every failing run; first seed replayed 5 times identical and identical under `verify --runs 5 --vary cpu,load` |
| multiplayer `--buggify`, 640 seeds; and 256 each at `buggify-permille=500` and with the commit-wait points at 1000 | all `ok`; `service-duplicate-original-committed-meanwhile` never reached |
| multiplayer `--faults net`, 64 seeds | 64 `ok`, vacuous: no resubmission answered from its receipt at the preset's rates |
| multiplayer `--faults net --fault net-reset-permille=100 --fault net-connect-refuse-permille=100`, 64 seeds | 64 `ok`, the receipt oracle held |
| `mise run sim` (both testbeds, `-j 4`) | passes in 2 min 32 s from cold testbed builds, 34 s warm; sweeps 31 s of it |

The two findings recorded for Cairn are not in its current code: the resubmission reported as
a conflict and then applied lived in the Turso store's commit path, and the lost acknowledged
commit in Turso's MVCC store; both stores were replaced by SQLite. The 2000-seed sweep is the
lost-commit setting on the replacement. The resubmission race's nearest oracle,
`service-duplicate-original-committed-meanwhile`, was not reached in 1,152 seeds (listed as
out of reach). The planted bug stands in for a finding: seeds are not compared.

**briefing**: its 81 Rust tests (7 test binaries), each alone in its own world, 5 seeds, by
this script run in the checkout (`target/debug` is mounted at its build path because tests
start the CLI by `CARGO_BIN_EXE_briefing`):

```sh
bins=$(cargo test --locked --no-run --message-format=json 2>/dev/null |
  jq -r 'select(.profile.test and .executable) | .executable')
for b in $bins; do "$b" --list --format terse |
  sed -n "s|: test\$||; s|^|$(basename "$b") |p"; done >cases
t=$(cd target/debug && pwd -P); d="$PWD/target/debug"
patina sweep --seeds 0..4 --cases cases --out OUT --mount "$t:$d" -j 6 \
  -- /bin/sh -c "set -- {}; exec $d/deps/\$1 --exact \$2 --test-threads=1"
```

| Command | Result |
|---|---|
| `patina sweep --seeds 0..4 --cases cases -j 6 --mount ...` | 405 `ok` of 405 in 3.3 s (sweep) and 3.7 s (script, warm build); the earlier engine ran 61 tests as 305 cells in 36 min with 8 refused for spawning a process |
| a test that starts the hub as a child and talks HTTP to it (6 connections), seed 3, `replay` 5 times | 5 identical |
| the same, `verify --runs 5 --vary cpu,load` | 5 identical |
| each test binary whole in one world (`http_flow`, 4 tests) | `ok` in 0.18 s |

`assets::tests::inline_script_parses` passes by skipping its check: it runs `node --check`,
and `node` is not on the guest's `PATH`.

## Acceptance: monty

pydantic/monty's harness (`dst/`, a local bookmark; nothing upstream) on the tree of its
upstream `main` without the three fixes, so its findings are present. The guests are plain
`cargo build` (debug; `--cfg patina` from a `.cargo/config.toml` compiles monty's ~450
assertion and coverage sites); the old build step, `--allow-unsupported-symbols`, `--target
native`, the staging through `patina test` and `classify.py` are gone. `patina` built from
`999be00b` (no `--version`; `run.json` says 0.6.0-dev), 2026-11-16, this host, every sweep
`-j 6` under `capped` beside other builders' work (load 5 to 10). `RT` is the round-trip
guest, `MMC` the drop-checking guest; each run executes all 736 datatest cases.

| Finding | Command | Rate | First seed | Wall |
|---|---|---|---|---|
| clean baseline | `RT`'s sweep below, seeds 0..99 | 99 `ok`, 1 finding 1 (seed 65); no `unsupported`, `internal`, `nondeterministic` | - | - |
| 1 host call at the recursion ceiling | `sweep --seeds 0..999 --budget 540 -- RT` | 6/376 (budget stopped it) | 65 | 560 s |
| 2 `sorted()` kwargs leak | `sweep --seeds 4000..5999 --budget 150 --time-limit 1000000000 --buggify -- MMC` | 0/149 | - | 156 s |
| 3 leak when a poll raises | `sweep --seeds 0..1999 --budget 270 --time-limit 1000000000 --buggify --fault buggify-permille=1000 -- MMC` | 0/290 at an injected fault | - | 277 s |
| 3, the old settings (point forced active, 5 permille) | `... --fault point:resource-time-limit-fires=5`, seeds 2000..3999, `--budget 240` | 0/489 at an injected fault | - | 245 s |
| 3, the harness's poll enumerator | `run --seed 0 --time-limit 1000000000 --env MONTY_DST_EXHAUSTIVE=1 --env MONTY_DST_CASES=slice -- MMC` | found (the drop checker aborts the guest: `crash signal: SIGABRT`) | 0 | 0.4 s |

- Finding 1 replayed 5 times from seed 65, each `identical`; `verify --seed 65 --runs 5
  --vary cpu,load` identical (one digest). The enumerator's run: the same, 5 and 5.
- Finding 2 is out of reach of this harness: the fault site that found it
  (`resource-allocation-limit-fires`) was removed from the harness for faking memory refusals
  real usage would not make. Finding 3's random-sweep reach is mostly gone too: upstream fixed
  all but one of its sites, and at `buggify-permille=1000` the fault lands on a case's first
  poll, before the remaining site. The enumerator reaches it deterministically.
- The `MMC` sweeps also show 7 runs (of 928) of an unrecorded leak of finding 3's class
  under the harness's real small memory budget (no injected fault), first seed 112 (replay 5
  identical, `verify` identical), and finding 1 as `violation` or, when its panic leaks
  values while unwinding, `crash signal: SIGABRT` (seeds 2084, 2139). A sweep groups every
  guest failure under the guest's one label (`datatest-panic`), so finding 1 and the leak
  share a group; the run's stderr tells them apart.
- SDK cost, `RT` seed 1, 7 runs each, interleaved: with monty's sites (447 in the
  table) median 6.25 s, built without them (6 sites) 6.11 s, +2%, inside the spread (5.5 to
  10.8 s); traps 288,385 against 288,197 (+188, one per first report). Natively 4.97 s and
  4.87 s.
- monty's own tests: `dst/patina/harnesses.sh OUT 0..0` builds the `monty` and `monty-fs`
  test binaries with `cargo test --no-run` and runs `patina sweep --cases` over every test,
  each alone. All 1,341 tests of 56 binaries, seed 0: 1,299 `ok`, 24 `failure` (every
  `heap_reader_compile_fail` test: it runs `cargo rustc`, which is not in the sandbox; the
  old engine refused these for spawning), 17 `failure` and 1 `timeout` (wall-clock time-limit
  tests: Patina's clock does not advance with computation, so `harnesses.sh` leaves these 64
  out). No `unsupported`, `internal` or `nondeterministic`. 191 s for the sweep, 37 s for the
  warm test build; every failing test's first seed replayed identically.

## Acceptance: rshell

The Go hunt harness (local only; findings undisclosed, so local ids and counts only) against
rshell `invariant-tooling` (unfixed; 315 SDK sites in a run's table), built with stock `go build`
against `go/patina`, one binary for native and Patina legs; its leg driver now runs `patina
run --out` and reads `result.json`. A corpus case lives in `/work` (`--work`), where file
faults land; a generated case's roots are copied in at `/`. ESCAPE and the trace coverage
checks are off (they need path strings for reads; the boundary log keeps hashes). `patina`
from `999be00b`, 2026-11-16, this host, `-j 6`, `--cpus 4`, `--preempt traps`.

| Check | Command | Result |
|---|---|---|
| corpus, no faults | 3,448 scenarios, seed 1 | 3,448 `ok`; 0 `compute-stall`, `internal`, `nondeterministic` |
| finding 001 | corpus at `fs-error-permille=40`, seed 1 | found in 1 scenario (old engine: 5); 1,153 runs had a fault injected |
| finding 004 | corpus with the run deadline cut to 30, 150 and 600 µs (seeds 1, 2, 3, the last with `fs-error-permille=40`) | found in 28 scenarios (old: 6) |
| finding 006 | 1,000 generated TOCTOU cases with a mutator thread, seeds 1..8 | not found (0/8,000; old: 19 cases, 2 to 8 of 8 seeds each) |
| finding 006, its own reproduction case | seeds 1..8, then 9..12 | 6/8, 10/12 |
| finding 006 by path swaps | the same 1,000 cases without the mutator, the case's tree as `--work`, `path-swap-permille=300`, seeds 1..8 | found in 27 cases, 30 of 8,000 runs; first among the first 20 cases to complete |

- The corpus campaign (5 legs, 17,240 runs) took 3 min 46 s, 753 child CPU-s; the TOCTOU
  campaign (8,000 runs) 1 min 52 s. No run in either ended `unsupported`: stock Go ran
  stall-free at default settings. `--preempt branches` was not measured: this host gives
  `patina` no `CAP_PERFMON`.
- Replay: the first scenario of 001 and of 004 replayed 5 times, each `identical`; `verify
  --runs 5 --vary cpu,load` identical for both.
- Findings the old engine's coverage-guided arm found first: 009 appears in the uniform deadline legs (94 of 10,344 runs;
  its repeat T1 has the same cause); T7 was not in reach of these legs.
- 006: the generated cases interleave the mutator only at system calls now; the old engine's
  Go build also preempted at memory accesses. The finding's own case still hits most seeds.
- The deadline legs cut only work that makes system calls: a CPU-bound script runs to the
  end inside a 30 µs deadline, because virtual time does not advance with computation. The
  harness's planted deadline bug is therefore not caught on a CPU-bound script.
- 006 by path swaps: Patina itself is the concurrent process. The campaign (8,000 runs) took
  1 min 45 s, 363 child CPU-s, under the shared evidence lock; three runs of it found the same
  30 runs. Every one of the 30 replays `identical`, and its operation log shows the swap that
  made it. Since the swaps rename entries themselves, the harness's name-based check is replaced
  in these legs by one over the operation log (`patina log ops`), which follows inodes.

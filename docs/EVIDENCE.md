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

System call arguments into the runtime's region (ARCHITECTURE.md, "System call arguments").
Measured 2026-11-17 on the x86_64 host above and the arm64 development VM (Apple M4, Ubuntu
24.04, Linux 7.0); base `caa853bd`. Reproducer `ptrprobe` (30 calls, both directions, direct
and inside iovecs and `msghdr`s, plus the memory calls, at 10 addresses across the region);
regression `sandbox/11-containment`.

| Check | Before | Now |
|---|---|---|
| `sandbox/11-containment`, dev VM: the old `gadget 0` (it found the runtime's mapped pages with `write(pipe, page, 1)`), seed 1, 30 runs | 2 digests, 8 runs in the minority: one page read lies in `state::PROC`, whose mount table holds the host's mount ids; CI `check-arm64` failed on it about one run in four | the same guest: `write` gets `EFAULT`, it finds nothing; 30 runs, one digest. The script (gadget now told the text's size, plus `ptrprobe`): 50 of 50 consecutive passes |
| `ptrprobe` against the base build, dev VM, at the text, data and private memory | `write`, `writev`, `pwrite64`, ... return 16 (the kernel read runtime bytes out): 9 and 16 calls differ from a hole; at the alternate stacks the kernel's writes crash the runtime (`internal`, status 139) | every call answers what a native run of the same program answers at the same (natively unmapped) address and what it answers for a hole it made itself; no byte of the runtime's arrives; `munmap` EINVAL; a buffer running into the region `EFAULT`, nothing moved |
| `/proc/self/task/TID/mem` opened through the task directory's descriptor, x86_64 | opened (read and write access to the runtime's memory) | `ENOENT`, as by path |
| The check disabled (planted), x86_64 and dev VM | | `sandbox/11-containment` fails: the runtime crashes (status 139) |
| `verify --runs 10 --vary cpu,aslr`, `ptrprobe` at 9 addresses | | identical on x86_64 and the dev VM |
| x86_64 ledger (90 cells), dev VM ledger (90 cells, 60 with a result), base / now | | identical |
| Per call, `costs getppid` / `costs pipe` (a 1-byte `write` and `read`), 2,000,000 iterations, 5 runs each minus `N=0`, base / now, two alternations | 1.08, 1.09 µs / 3.41, 3.35 µs | 1.11, 1.11 µs / 3.45, 3.37 µs (within run-to-run spread) |
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
| W1-W9, default, with their faults | no `compute-stall`; W8 `sockets all` fails 20/20 on an injected reset (its faults draw `net-reset-permille=30` for every send, so every seed resets a connection, and the guest exits on `ECONNRESET`); W9 seed 5 failed on an injected `ENFILE` after a crash, which the harness judged a finding (fixed; `storage/11-unjudged`); W6 (`fs-error-permille=20`) `failure` on 18 of 20 seeds, where an injected file-system error makes a command of the pipeline exit nonzero (no pause point or probe in it); the rest `ok`; W4: 26,265 pause points, 1,956 spin preemptions |
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
family 0x1a and (arm64) the Arm Neoverse N2 ("Branch counters on arm64"), and a seed
reproduces only on the same family.

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
| W1-W9, default, with their faults, runner | no `compute-stall`; W4: 2,579 pause points, 596 spin preemptions; W8 fails 20/20 on injected resets, as on x86_64; W6 `failure` on 20 of 20 seeds (VM: 19 of 20; x86_64: 18 of 20), an injected file-system error ending the pipeline, not an arm64 difference |
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
| ELF files, words of executable sections | 2,493, 121.2 M | 4,422, 502.9 M |
| Words read by literal loads; words under `$d` | 2,101; 18,714 | 24,274; 19,001 |
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

### Python

`python3 -m patina` (sdk/python/patina.py, ARCHITECTURE.md "Compute points"), guest
`tests/guests/compute/py/pycompute.py`. Host: AMD Ryzen 9 9950X, Linux 7.0; Python 3.14.4
(the host's `/usr/bin/python3`) and 3.12.16 (a standalone build mounted at `/py`, as the CI
runners' 3.12); 2026-11-18.

Stock behaviour first (by hand, 3.14): two threads in loops with no system call run one after
the other (10^8 passes each, a progress mark every 10^6: 1 alternation of the marks; natively
199).
The thread waiting for the GIL waits with a 5 ms timeout in virtual time, which a computing
thread never moves, so CPython's switch request is never made. Over 10 s of CPU without a
system call (`burn 1000000000`; also a two-thread loop of 9 x 10^8 passes, seeds 1 and 2) the
run ends `compute-stall`. With points and `compute-gap=0` (no seeded switch) the 5 ms request
fires in virtual time: `cpu 5000000` alternates 62 and 57 times on seeds 1 and 2 (39 natively),
one digest over three runs.

| Check (`compute/evidence-python`, 3.14 / 3.12) | Result |
|---|---|
| `cache 200` (check-then-act, two threads), seeds 1-200: stock / default gap / `compute-gap=16..256` / `compute-gap=0` | 3.14: 0 / 110 / 200 / 0; 3.12: 0 / 113 / 200 / 0; the first failing seed (2, 1) replays identical |
| `timer 50` (a 50 ms `setitimer` inside a loop with no system call), seeds 1-20 at the seed's gap and at `compute-gap=0`; stock seed 1; seed 1 under `verify --runs 20 --vary cpu,load,aslr,sandbox` | both: 40 of 40 fired, the handler at 50,004,015 virtual ns in every run, one deadline stop each; stock: never fires (20 million passes); verify identical over 20 runs |
| `burn 1000000000` (two threads, 10^9 passes each, no system call), seed 1 | stock: `compute-stall` after 10 s (both); with points: 3.12 `ok`, both threads ran, 1,395,037 switches, 452 s (3.14, `burn 450000000` by hand: `ok`, 627,808 switches, 165 s) |
| Costs, median of 5 runs, ms: natively / natively under the runner / Patina stock / with points / `compute-gap=0` | 3.14: `loop 3000000` 47 / 54 / 156 / 620 / 619; `mix 10` 143 / 179 / 666 / 971 / 945; W5 `local` 2,581 / 2,595 / 111 / 127 / 125. 3.12 under Patina: 237 / 799 / 797; 704 / 1,312 / 3,632; 128 / 156 / 154 |

By hand, 3.14 unless noted:

- **Quick check numbers** (`compute/09-python`): `cache` 0 of 40 stock, 21 of 40 with
  points; `timer 10` handler at 10,004,015 ns; `cpu 50000` 1 alternation stock, 32, 93 and 97
  on seeds 1-3 with points; identical under `verify --runs 3 --vary cpu,aslr`. 3.12 the same
  shape (`cache` 26 of 40, `cpu 200000` 387 alternations on seed 2).
- **Event sets.** `LINE` alone misses loops on one line: a 1,000-pass `while i < 1000: i += 1`
  makes 3 line events, a comprehension or generator expression of 1,000 items 1 to 3; with
  `JUMP` each pass is an event. Native count over `mix`-like code: 9.8 million lines, 11.0
  million lines and jumps, for 146 ms of work: 13 to 15 ns per event, so `LINE_EVENTS` = 15.
- **Hook cost** (natively, the hook forced on over a buffer): a callback that does nothing
  costs 25 to 40 ns per event; the cell read and write through a `memoryview` another 40;
  ctypes `c_int64.value` is slower. Per event in all: `loop` 67, `mix` 80 ns (3.14), 79 and
  99 ns (3.12). A countdown kept in Python, synchronised with the cell every 8 or 32 events,
  saved 25% or 45% but loses the exact switch place after a system call re-arms the cell:
  not used. Natively the hook would make `loop` 17 times and `mix` 7 times slower.
- **Exceptions from hooks.** An exception raised in a `JUMP` callback skips the frame's
  `except` on 3.12 and 3.14 (19 of 19 positions; 3.13 catches them), in a `BRANCH` callback on
  all three; in a `LINE` callback, or an `INSTRUCTION` callback enabled after the jump, it is
  caught. A `setitimer` handler raising inside a one-line loop and a comprehension, under
  points: `Stop caught` for both on seeds 1-8 (3.14) and seed 2 (3.12); with the jump hook's
  exception not held: the exception escaped (`failure`, seeds 1 and 2).
- **The GIL.** The point made through `ctypes.PyDLL` (which keeps the GIL) instead of `CDLL`:
  `cpu 50000` 1 alternation on seeds 1-3 (23, 95, 98 with `CDLL`), `cache` 0 of 40 (23 of 40).
- **`compute-gap=0` on 3.12** (`mix 10`): 2.6 to 4.2 s against 1.3 s at the seed's gap: a
  stretch of 2^22 events is 280,000 lines, past the 20 ms of CPU after which the stall
  watchdog probes (6 probes, 358,305 steps in one run); at 3.14's speed it stays under.
- **Free-threaded 3.14.10t**: `cache` 21 of 40 with points (0 stock), seed 2 replays
  identical; `timer`, `oneline` and `cpu` as with the GIL.
- **Stock programs unchanged**: W1-W8, U1, W5 with faults, `py-net`, `pyscript`,
  `compute/races b`, seeds 1-3, this build against `main` (0.9.1): 39 of 39 the same outcome
  and digest. Programs that import the SDK file (`sdk-py.py fail`, `script`, `journal.py`)
  read a changed file, so their digests change with any edit of it; with the 0.9.1 file under
  this build, 9 of 9 the same digest as 0.9.1.

Red/green: the jump hook not holding the exception fails `compute/09-python` (c, `oneline`
exit 1); the planted `PyDLL` above finds nothing in `cache` and runs `cpu` serially.

## Branch counters on arm64

Measured 2026-11-18 on GitHub `ubuntu-24.04-arm` runners (Azure, Arm Neoverse N2 r0p0, `MIDR_EL1`
0x410fd490, 4 CPUs, Linux 7.0.0-1017-azure; the `armv8_pmuv3_0` PMU, 6 counters a group), each
check run once from a throwaway branch.

**Is the count exact?** A probe program (C, run natively, no Patina) counted events over 50
processes per body, idle, under 4 `yes` loads, and with a thread moving it between CPUs every
300 µs:

| Check | Result |
|---|---|
| What `BR_RETIRED` (0x21) counts | every branch instruction executed, taken or not: `b.cond`, `cbz`/`cbnz`, `tbz`/`tbnz`, `b`, `bl`, `br`, `blr`, `ret`; nothing else (`svc`, `isb`: 0). A walk single-stepping every instruction with a counter read after each: every branch counted once, 0 of ~600,000 other instructions |
| Count over 50 runs, 20 bodies (calibration loops, loops, recursion, indirect calls, glibc string functions, libm, `malloc`, uncontended mutex, outline atomics, 8 threads on 4 CPUs, LSE atomics, contended `ldadd`) | one value per body, in all three conditions |
| Signals arriving (SIGUSR1 every 100 µs) | base + 1 per signal (the handler's `ret`), exactly |
| Inline `ldxr`/`stxr`, 200,000 operations | base + 2 per failed store, exactly; spurious store failures 0 to 4 per run idle, up to 7 moved; 4 million operations: 17 to 75. The count is exact, the program's path is not: hence the emulation below |
| A program reading the clock through the vDSO | not one value (its seqlock retries); Patina has no vDSO |
| Overflow, then single steps to period + 1,500 (ASLR off), 11 bodies x 3 conditions x 2 periods x 50 runs | one stop instruction in every cell; register hashes differ only by pointer-authentication-signed pointers and thread ids (keys are per process natively; Patina turns them off) |
| Skid (branches past the programmed overflow at the signal) | 11 to 333; margin 1,024 |
| Overflow signals (`TRAP_PERF`), 75 runs x 3 periods | overflows = total / period every time: none lost, none doubled |
| Exclusive pairs started per program (a breakpoint on every load-exclusive) | glibc 2.39 dynamic programs, C++, Rust, Python: 0; static glibc 4; Go 93; ubuntu 26.04: 2 in `ld.so` per program |
| Cost | `read()` of the counter 735 ns; a user read of the PMU registers (with `perf_user_access=1`) 606 ns, trapped by the hypervisor; `brk` round trip 1.2 µs |

rr counts the same event on these cores (skid allowance 1,000) and supports only programs
using LSE atomics, not exclusive pairs, for the same reason.

**Patina** (`tests/counters`, the runner; x86_64's numbers in "Spin-waits and scheduling
points"):

| Check | Result |
|---|---|
| `05-exact`: the same N reached by hops only and through the counter, N = 3,000 on six programs and N = 1,100,000 on two | 8/8 equal digests (e.g. strings: 8.6 million hops against 2,883 overflows, 2,869 landings, 2,869 stops) |
| `06-migrate`: tasks moved to a random CPU every 2 ms, 5 runs of four programs | 20/20 equal to the unmoved run (13,500 affinity changes in a strings run) |
| `evidence-compute`, 7 programs, 10 runs `--vary cpu,load,aslr,sandbox` and 10 `--vary parallel` each | all identical, the same digest both ways, checksums equal to native; largest skid 316 |
| `evidence-races` (stock builds, no compute points), 100 seeds | race b found in 1 seed with the default policy, 3 with `branches = "hunt"`; seed 16 replays 20/20 under `--vary cpu,load,aslr,sandbox`. pool: in no seed, as on x86_64: its updates are a load, an add and a store with no branch between, and a stop comes only after a branch |
| `evidence-go`: go-sweep and W4 (stock Go) at 4 CPUs, 20 seeds | 20/20 `ok` each, 20 distinct digests each, 0 stalls; seeds 1-5 x 5 runs, faults off and on: identical |
| `evidence-spin`: glibc, C and Rust spin locks, 20 seeds | 60/60 `ok`, 0 stalls; largest skid 331 |
| `04-stalls`: the exclusive-pair spin locks (`llsc-spin`), whose waiter runs only emulated exclusive instructions | `ok` |
| `evidence-workloads`: W1-W9, 3 runs of seed 1, seeds 1-3 | identical across runs, 3 distinct digests over seeds for each; W9 is a `violation` under counters (below) |

W9 under counters: its crash lands at point 15, before fjall has made its `version` file
durable, and the harness's open after the crash fails with `EEXIST`, the same in every run
(seed 1 on arm64; seed 12 of 40 on x86_64 with counters; none of 40 without). It is fjall
F1, not a Patina bug: the tree the crash left fails the same way when the harness opens a copy
of it natively, the run is the same digest in 3 of 3 runs, the harness's F1 workaround
(`FJ_WIPE_PARTIAL=1`) makes the seed `ok`, and without counters seeds 1-200 reach F1 in 14
runs (10 `EEXIST`, 4 an empty `version`). Counters move the crash points (seed 12's first
crash at point 10 with them, during fjall's first open, at point 164 without), which is why
that seed reaches F1 only with them.

Costs (`evidence-costs`, runner, median of 3): a trap with counters on costs 1.28 µs more;
a preemption 2.6 ms (loops) to 3.4 ms (fp); W1-W9 wall x0.66 (W9, which ends early) to x2.01
(W2), the rest x1.07 to x1.58.

Red/green: stopping at the overflow without the landing walk fails `05-exact` (9 of 9 cases
stop elsewhere); not subtracting the return path's three branches (`TAIL` = 0) fails it too
(9 of 9). Keeping the counted segment across an emulated exclusive instruction (a stub reading
the counter at SIGILL as at the overflow) made `04-stalls`' two exclusive-pair locks end
`compute-stall` with no preemption in 2 s (the waiter's every few branches cost an
emulation, so a long N takes seconds), where ending the segment there passes them: the
segment ends there.

Runners differ: one of the five jobs got a Neoverse V3 (`MIDR_EL1` 0x410fd841), where
`--preempt branches` is refused and the branch-counter scripts SKIP.

The period before hop segments, on x86_64 (Zen 5, `perf_event_max_sample_rate` 6,000 at
HZ 1,000: 6 samples a tick before the kernel throttles): a guest whose bursts of branches end
just short of a mid-length segment, with every third segment short, left the short period in
place for the hops after it. Counted with a scratch build: 1,104 and 1,225 overflows while
hopping and 5,487 and 6,115 hops that found the counter stopped (throttled) over two seeds;
with the period set before every segment, 30 and 0, and the same digest as before for each
seed. `dmesg` showed no new perf message either way. After it: `counters` area passes, the
90-cell ledger is unchanged. On arm64 `07-exclusive` fails with the faulting-exclusive fix
reverted (`map`: SIGILL) and with the full-table stop removed (`many` ends `ok`).

Unaligned exclusive accesses (`excl align`: each of the 27 load, store and load-then-store
forms at offsets 0, 1, 2, 4, 8, 12, 14 and 15 of a 64-byte-aligned buffer), native against
`--preempt branches`, five runner jobs (all Neoverse N2, `uscat` in `/proc/cpuinfo`; the native
table the same in each):

| Access | Native | Patina before | Patina now |
|---|---|---|---|
| Byte forms, any offset | no fault | no fault | no fault |
| Halfword, word, doubleword, word pair (2 to 8 bytes) at an unaligned offset inside one 16-byte block (e.g. `ldxr x` at +1, +4) | no fault | SIGBUS `BUS_ADRALN` | no fault |
| The same across a 16-byte boundary (`ldxrh` +15, `ldxr w` +14, `ldxr x` +12, `ldxp w` +12) | SIGBUS 1, `si_addr` the address | SIGBUS 1, the address | the same as native |
| Doubleword pair (`ldxp`/`stxp x`, 16 bytes) at any unaligned offset | SIGBUS 1, the address | SIGBUS 1, the address | the same as native |
| A store-exclusive whose monitor is clear (it would fail) | as the load of its size: the alignment check comes first | the same | the same |

The architecture's rule (`AArch64.CheckAlignment`): with FEAT_LSE2 an unaligned exclusive
access faults only when it crosses a 16-byte boundary. The emulation now applies it when the
kernel reports `HWCAP_USCAT` and faults on every unaligned address otherwise. An unaligned
`ldxr` that did not fault natively was inside one 16-byte block. `07-exclusive`'s `align` mode
compares the 216 lines with the native run; with the old rule planted it fails (`ldxrh +1`
and 40 more lines raise SIGBUS where natively they do not), and passes with the fix.

What differs from the Apple VM (Tart, Apple M4): no PMU is exposed to the guest, so
`--preempt branches` is refused there (`patina doctor`: no PMU); the hop logic and the
exclusive emulation were also run there with a software event standing in for the counter
(not shipped).

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
| `--preempt branches` | 9.7 µs per trap, 1.7-2.3 ms per preemption, W1-W9 wall x0.6 to x6.5 (W1 x6.5, W2 x4.4, the rest under x2); arm64 (runner): 1.3 µs per trap, 2.6-3.4 ms per preemption, W1-W9 x0.66 to x2.0 |
| `--mount DIR:/guest:copy` copy into tmpfs | ~0.3 ms per MB |

## Known limits

Not implemented (run ends `unsupported` or the call is refused): `timer_create`,
`ITIMER_VIRTUAL`/`ITIMER_PROF`; raw, netlink and packet sockets, UDP multicast and broadcast;
anything outside Linux x86_64 and arm64 (arm64: ARCHITECTURE.md, "Limits").

- A spin-wait with neither a system call nor `pause` whose iterations change state (a
  counter, a timestamp it computes itself) ends `compute-stall` without `--preempt
  branches`. `--preempt branches` needs `CAP_PERFMON`, an exposed PMU and an AMD family
  0x1a (Zen 5) or Arm Neoverse N2 CPU, the ones checked; its seeds reproduce on the same CPU family only; a skid past
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
  `EINVAL`; `F_SETLKW` deadlock detection is absent; `poll` restarts with the full timeout.
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

### Net preset shaping

Does a gap between the pieces of one delivery, and a log-uniform chunk size, keep what
`--faults net` finds while ending the slow-link artefact? 2026-11-19, this host, x86_64, 200
seeds a line, `patina sweep --seeds 1..200 -j 6 --keep fail --faults net` under the shared
evidence lock, `before` the 0.12.2 build and `after` the build with `net-chunk-gap-us=1..10`
in the preset. tokio, pubsub and the throughput guest unwrap a reset or a refused connect, so
they ran with `--fault net-reset-permille=0 --fault net-connect-refuse-permille=0`: the
delivery shaping alone, which is what changed.

| Guest | Before | After |
|---|---|---|
| `examples/bank-go` | 88 `balance-matches-deposits` | 88 |
| `sockets chunk naive` (a reader that assumes one read is one message) | 25 `failure` | 99 |
| `tokio-echo`, `tokio-mt net` | 0 (exit 2: the datagram classes never applied) | 0 (exit 0, those classes not applicable) |
| pubsub (`testbeds/pubsub`), clean | 0 | 0 |
| pubsub `drop-read-remainder` | 200 (179 `seq-gap`, 21 not converged) | 200 (132 `seq-gap`, 56 `malformed-frame`, 12 not converged) |
| pubsub `stale-timeout`, `lost-wakeup` | 200, 200 | 200, 200 |

Throughput over one connection, per seed (a C guest sends 256 KiB in 16 KiB writes to a
reader; virtual time from accept to EOF; resets off):

| | min | p1 | p5 | p10 | p25 | median | p90 |
|---|---|---|---|---|---|---|---|
| before | 10.5 kB/s | 16.0 kB/s | 143 kB/s | 283 kB/s | 811 kB/s | 1.74 MB/s | 3.50 MB/s |
| after | 176 kB/s | 177 kB/s | 180 kB/s | 363 kB/s | 1.88 MB/s | 3.99 MB/s | 6.02 MB/s |

Before, each piece of a split delivery waited a whole `net-delay-ms` draw, so a seed with
small chunks ran at chunk/delay (a few kB/s at 1-byte chunks), and a protocol's own timeouts
fired on that link rather than on the bug. A 48-seed pilot found the same 20 framing failures
with a 10 to 50 µs gap as with 1 to 10 µs, at a minimum throughput of 33 kB/s against 180
kB/s, so the preset takes 1..10. The log-uniform draw (`net-chunk-max=1..65536`: one seed in
17 delivers byte by byte, about one in four at most 16 bytes a piece) keeps byte-at-a-time
coverage, and `--fault net-chunk-max=1 --fault net-delay-ms=10..50` still gives the harsh
link. `testbeds/pubsub/sim.sh` (explicit `net-chunk-max=16..4096`) finds the same with the
0.12.2 build and this one: clean 0 of 200, `lost-wakeup` and `drop-read-remainder` 200,
`stale-timeout` 167. `tests/net/05-faults.sh` checks the gap: 500 one-byte pieces at
`net-delay-ms=10..10` end more than 4 virtual seconds sooner with `net-chunk-gap-us=1..1`, one
read each (red on 0.12.2, which has no such key).

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

**What a sweep counts against the program** (`tests/sweep/01-sweep.sh`, 2026-11-19, this
host). `--faults net` over a TCP-only guest (`sockets chunk correct`, resets and refusals off)
is exit 0 with `net-drop`, `net-dup` and `net-reorder` listed as not applicable; the same sweep
with `net-drop-permille` named is exit 2. On the guest that exits 3 after a file error,
`--ok-exit 3:fs-error` makes 7 of 12 runs `ok` by it and `3:mem-error` leaves those 7 findings,
also through `[run] ok-exit` and `[sweep] known` in `patina.toml` (`12 runs, 0 findings in 0
groups, 7 known, 5 ok`). An output directory of an older layout is replaced; one with no patina
output in it is refused and left as it was. A fault point no run reached is vacuous over 20 runs
under `--buggify`, noted in 4; one forced off is noted. A known entry written with the digits of
a run (`got 1, want 0`) names the signature it nearly matched (`tests/oracles/01-checks.sh`
calc, and `report.rs` unit tests); the failure group's `example:` is the first run's stderr
line with its count (`store failed after 539 bytes`). Red/green, each breaking one rule and
seeing the check fail: inverting the `--ok-exit` condition; renaming the old-layout marker the
directory check looks for; counting known runs as findings; treating every preset class as
named; requiring one firing at any count of runs; dropping the near-match search; drawing chunk
sizes uniformly; the 0.12.2 build (no `not_applicable`, no `net-chunk-gap-us`). The
change adds about 1 s of script time to `quick` (`./check quick` 214 s to 220 s of script time,
39 s to 41 s wall, noise included).

**Identity.** Runs that use none of the changed settings keep their digests: the x86 ledger
(90 cells: 15 guests, seeds 1 to 3, faults off and `--faults all`) gives 87 of 90 equal to the
0.12.2 build; the 3 others are `--faults all` cells that split a TCP delivery (`sockets` seed 2,
`go-static` seeds 2 and 3), whose chunk size and gap are now drawn differently. Seeds 1 to 20 of
`upcase --faults disk`, the file-error guest under `fs-error-permille=30`, `sockets all` with
faults off, `kvlog --crash machine:10`, `bank` under `net-reset-permille=50` and `sockets chunk
correct` under `net-chunk-max=1 net-delay-ms=10..10` (explicit single values) are equal, 120 of
120.

**Confined** (`tests/oracles/04-paths.sh`): a program that creates a file under its root and
fsyncs the root's parent directory (`paths durable`) is judged `pass`; opening `/tmp` read-only
is still `outside-roots: open /tmp`. Red: the 0.12.2 script fails the first with `open /work`.

### Sweep width

Which `-j` is fastest on four CPUs? 2026-11-19, three rounds interleaved, each line
`patina sweep -j J --keep none` over 2,000 seeds of `hello-static` and 400 of the fjall harness
(`tests/guests/fjall-harness`, release, `--buggify --env FJ_N=2000 --crash machine:1`); runs
per second, the range over the rounds. This host under `taskset -c 0-3` (the evidence lock
held); GitHub's `ubuntu-24.04` (AMD EPYC 7763, 4 vCPUs) and `ubuntu-24.04-arm` (Neoverse-N2,
4 vCPUs) in a throwaway workflow, deleted after.

| Host | Guest | `-j 2` | `-j 4` | `-j 5` | `-j 6` |
|---|---|---|---|---|---|
| this host, 4 CPUs | hello | 184-193 | 340-352 | 314-333 | 326-336 |
| this host, 4 CPUs | fjall | 25.3-25.7 | 45.7-48.5 | 46.4-48.4 | 46.7-47.3 |
| hosted x86 | hello | 65.5-65.8 | 87.7-88.6 | 87.9-88.6 | 89.4-89.8 |
| hosted x86 | fjall | 8.6 | 12.2-12.3 | 12.2 | 12.3 |
| hosted arm64 | hello | 95.8-101.4 | 143-160 | 147-160 | 153-157 |
| hosted arm64 | fjall | 12.3-12.9 | 19.9-21.0 | 19.3-20.5 | 19.3 |

One job per CPU is the fastest or within 2% of it everywhere; half the CPUs (the old default)
gives 55 to 75% of it, and one or two jobs past the CPU count gain at most 2% (hosted x86) and
lose up to 8% (arm64 fjall, this host's hello): the supervisor shares the CPUs and is not
starved at that width. The default is the CPUs this process may use, at most 8.

## Checks from outside the program

`tests/oracles/01-checks.sh` (quick, about 2 s, most of it the checker that outlives a 2 s
`--timeout`), 2026-11-18, this host: `examples/kvlog-c` (no SDK) under `--crash machine:10`
with `examples/checks/acked-kept`, seeds 1-30: 9 failing seeds in exactly one group,
`violation check: acked-record-lost: acknowledged N, N stored after the crash`, its first seed
replayed identical; `minimize` keeps the crash (`machine:10` to `machine:5`) and the
signature; `kvlog fixed` gives 30 `ok`. Red/green, each planted in turn: every checker exit
status read as a pass (the sweep exits 0 with no finding), a checker's error left `ok` (exit 2
passes), a missing checker accepted (the run starts), a checker past `--timeout` read as a pass,
the checker started after a failure, and the replay's differing verdict left
`nondeterministic` each fail the check. The first version of `acked-kept` failed on a crash
before `data.log` reached the disk (no file in `post-crash/`); the sweep reported it as
`error check` on that seed, not as a pass.

`./check evidence check-cost` (`tests/oracles/evidence-check-cost.sh`, `hello-static`, 400
seeds, `-j 8`, `--keep none`, two rounds interleaved), 2026-11-18, this host:

| Check | Runs per second, round 1 | Round 2 |
|---|---|---|
| none | 537 | 557 |
| `--check true` | 505 | 481 |
| a five-line `sh` checker reading the run directory | 472 | 475 |

`--check true` costs 6% and 14% of the rate; every run ended `ok`.

`./check evidence crash-check` (`tests/oracles/evidence-crash-check.sh`: `examples/kvlog-c`
with `examples/checks/acked-kept`, `-j 8`, `--keep none`), 2026-11-18, this host:

| Sweep | Runs | Judged: passed, failed | Not judged (no crash in this run) | Findings |
|---|---|---|---|---|
| `kvlog`, seeds 1-200, `--crash machine` | 200 | 28: 5, 23 | 172 | 23, one group, replayed identical |
| `kvlog`, seeds 1-2, `--branch --crash machine` | 88 | 86: 13, 73 | 2 (the bases) | 73, one group, replayed identical |
| `kvlog fixed`, seeds 1-200, `--crash machine` | 200 | 64: 64, 0 | 136 | 0 |
| `kvlog fixed`, seeds 1-2, `--branch --crash machine` | 248 | 246: 246, 0 | 2 (the bases) | 0 |

Under `--crash machine` most runs end before their crash fires and the checker has nothing to
judge (172 of 200); every crash point of two seeds judges 86 runs and finds the bug in 73.

The same script, for `--ok-exit` and `patina log tree`, 2026-11-18, this host: `upcase`
against one faults-off reference run with `--faults disk --ok-exit 1 --check same-tree`, seeds
1-40, gives one group, `violation check: wrong-output`, `fs-short` in every failing run and no
`failure` group; plainly, the same sweep has `failure` groups only; `upcase fixed` none. An
`--ok-exit` list stays a `failure` for a status not in it and a `crash` for a signal; the
rerun line carries the list (it reproduces a finding that needs it). `log tree` of `inc-0`
equals the guest's own listing of its final tree, refuses a non-empty directory and a pruned
run, and works on each incarnation of a machine-crashed `kvlog` run. Red/green, each planted
in turn: `--ok-exit` taking every nonzero status (a status not listed ends `ok`), and `log
tree` writing the starting tree (`--work`) instead of the final one (the checked sweep finds
nothing; the tree differs from the guest's listing) each fail the check.

`./check evidence faults-off-on` (`tests/oracles/evidence-faults-off-on.sh`,
`examples/upcase-c`, 200 seeds, `--faults disk`, `-j 8`), 2026-11-18, this host, x86_64:

| Sweep | Runs | Findings | Groups | `ok` (by `--ok-exit`) |
|---|---|---|---|---|
| plain | 200 | 13, all `failure exit` after an injected `fs-error` (clean failures) | 4 | 187 (0) |
| `--ok-exit 1 --check 'same-tree REF'` | 200 | 43 | 1: `violation check: wrong-output: Files want/out.txt and got/out.txt differ`, `fs-short` in every run, first seed replayed `identical` | 157 (13) |
| the same, `upcase fixed` | 200 | 0 | 0 | 200 (13) |

`patina minimize` of the group's first run: `fs-error-permille=0..5 fs-short-permille=0..20
fsync-error-permille=0..3 fs-delay-permille=0..20` to `fs-short-permille=0..20`. No assertion
in the program sees the bug; the 43 runs exit 0 with a short `out.txt`, `ok` in the plain
sweep.

## Oracles

Do `--check`, `--known`, `--ok-exit` and the `check:` line replace what the two motivating
adopters built by hand? Run once by hand, 2026-11-18, this host, `patina` from `ab11a704`,
every sweep `-j 6` under the shared evidence lock, `--keep fail` except the reference legs
(`--keep all`). The rshell hunt is local: ids and counts only.

**The rshell hunt.** Its driver (`corpus.py`, 2,510 lines with the path-swap legs) is kept
as the reference; its oracle functions (`judge`, `same`, the SILENT and PROTECT rules) are
imported unchanged by an 81-line checker (`CHECKER LEG REF STAGE RUNDIR`: the reference's run
is `REF/seed-1/$PATINA_CASE_NAME`; the first flag is `ORACLE: [LEG] detail`; exit 77 with the
reason when the leg's comparison oracle cannot judge), and a 41-line one for the path-swap
legs. A 96-line script writes the hunt's known table as a `--known` file. Same settings on
both sides; `--ok-exit 3,4,5,6` (the harness's own HANG, LEAK, stuck and setup statuses) so
the checker, not the exit status, names those runs.

| Leg | Old driver | Patina sweeps | Same findings, same labels? |
|---|---|---|---|
| path swaps: 1,000 generated cases × seeds 1-8 (8,000 runs), case lines `HARNESS 'CASE-JSON'`, one shared fixture as `--work` | 130 s wall, 436 child CPU-s; 30 runs in 27 cases flagged, all labelled 006 | 381 s; 30 findings in 10 groups, all labelled 006 by `--known`, `check: judged 8000 of 8000` | yes: the same 30 (case, seed, flag) and labels; one case's run has the same digest under both |
| fs errors (`fs-error-permille=40`, after setup), seed 1, against the rshell faults-off run, 3,448 corpus cases | one leg of a 4-leg 108 s campaign; SILENT in 5 cases (1 labelled 001), 10 coverage flags | 163 s; SILENT in 5 cases (3 labelled 001 by both), the same 10 coverage findings; 155 not judged (live state 101, stderr redirected 54) | 001 found as a check finding; the SILENT cases are disjoint (below); on the same runs 2 of 5 SILENT hits labelled 001 by the file and by nothing in the table |
| rshell against bash: bash under Patina (`--keep all`), then rshell's faults-off sweep checked against it | its bash leg cannot run a corpus case (the case's directory does not exist in its bubblewrap root); its coverage cell reports 0 judged | bash 601 s (two scripts loop until the default 600 s `--timeout`; the other runs total 90 CPU-s), rshell 168 s; 128 differences in 93 groups, 1,018 not judged (rshell stderr 941, bash stderr 74, no result 3) | the old leg judged nothing; not triaged here |
| one planted case (a write into a read-only root), `!planted` in the file | (its own planted gate, 736 lines) | matched on every leg; `required_unseen` empty | - |

- Why the fs-error cases differ: a corpus case is its own work tree. A `--cases` line cannot
  carry `--work`, so the sweep mounts every staged tree and each line copies its own into
  `/work` (`sh -c 'cp -a ... && exec HARNESS ...'`) with `faults-after-setup=1`. The extra
  processes before the harness move the fault draws: on the same seed the injected error lands
  on another call (shown on one case: `write` against `openat`). Both sides find 5 cases, none
  in common. The path-swap leg, whose cases share one tree, has no staging and matches exactly.
- Wall time: the checker is a Python process per run that imports the hunt's module (about
  0.1 s; a corpus run is about 25 ms of `wall_ms`), where the old driver judged in a pool of
  long-lived workers. That is 3 times the old wall on the path-swap legs and about 6 times per
  corpus leg. The reference legs kept 1.2 and 1.5 GiB; `--keep fail` kept 632 MiB for 8,000
  `ok` path-swap runs (about 75 KiB of `result.json` and `run.json` each: 315 SDK sites).
- Lines, by the driver's functions (the 767 lines of plumbing measured before, plus
  staging): 495 are not needed (the
  leg runner, pool, resume, pruning, result files, known glue); 249 (reading a run directory
  into the oracles' inputs: `finish_leg`, `parse`, the operation-log PROTECT) are imported by
  the checker; 190 that stage a case's tree from its YAML are still needed, since a case line
  cannot carry a tree. The 199 lines of known table and glue become a 36-line file. Of the
  269 lines of eligibility accounting, the per-run "why not judged" is now exit 77 and the
  `check:` line; the per-oracle floor (an oracle that judged none of a population fails the
  campaign) has no equivalent: a sweep is vacuous only when the check judged no run at all.
  The 698 lines of oracles stay as they were.

**The known table** (23 entries), as `ID PATTERN` lines over these signatures:

| Expressible | Entries | Ids |
|---|---|---|
| exactly, with signature globs | 10 | 004, 005, 008, 009, 017, 018, 019, 020, 021, T8 |
| only with a `[CASE]` pattern | 1 | 006 (by the item's name; the corpus's case lines are names, the path-swap lines are the case JSON, so its line globs the JSON instead) |
| coarser: the oracle part fits, a script or fired-fault condition is dropped | 11 | 001, 002, 003, 007, 010, 011, 013, 014, 015, 016, check-class |
| not at all | 1 | T7 (needs a frame of the panic's stack; the signature keeps the panic line) |

The glob over the signature is too coarse for half the table. Five entries (001, 002, 013,
014, 015) share one oracle and differ only by the script and the fault that fired: as globs
they are one pattern, the first wins, and the others can never match; on this run's err leg
that labelled two hits 001 that the table's own matcher leaves unlabelled. A known entry
needs to see the case's input (here a file the case line names) and the fault classes of the
run (`faults` per run is in `result.json` already), or the checker must put both into its
detail, which moves the table's logic into the checker. Separately, the old matcher read the
total injected count as "an fs error fired", so path swaps matched 010 (1,789 flags on a
corpus path-swap leg); the hunt has since fixed that, and `--known` cannot make that mistake.

**fjall F1, from outside.** The harness run with its embedder workaround for F1
(`FJ_WIPE_PARTIAL=1`, which wipes a database the crash left half-created, so the in-program
check never sees it) and `--check NATIVE-CHECK`: for each `inc-K/post-crash`, copy it and run
the harness's own binary natively on the copy, outside the simulation; its first `INVARIANT`
line is the finding (17 lines of `sh`).

| Sweep | In-program oracle (no workaround) | External native check (workaround on) |
|---|---|---|
| `--seeds 1..300 --crash machine:3` | 11 seeds, 2 groups (`open-after-crash`, two causes); 4.4 s | the same 11 seeds, the same 2 groups as `violation check`; 281 judged, 19 not judged (no crash); 60 s |
| `--seeds 1..3 --branch --crash machine` | 23 of 2,909 runs, all 2,906 points; 27 s | the same 23 runs within the first 340 points; the 45 s `--budget` stopped it there |

The post-crash trees fail the same way when opened natively: the external check finds what
the workaround hides, on the same seeds and points. It is 17 times slower per run: the native
recovery fsyncs on the host's disk.

**Defects for follow-up** (none fixed here):

1. A case line cannot carry per-case settings (`--work`, `--mount`, `--env`): staging a
   case's tree in the guest moves the schedule, so a corpus with its own tree per case cannot
   reproduce its old driver's runs.
2. A checker is a process per run; a checker in a scripting language with a real oracle
   library costs more than the run. A long-lived checker (or one run per batch) would remove it.
3. A checker that degrades silently passes every run: with one environment variable unset the
   path-swap checker could not run `patina log ops` and judged 8,000 runs `pass` (`check:
   judged 8000 of 8000`). Only a `!ID` planted case catches that; nothing tells a sweep it has
   none. The checker is not told which `patina` started it.
4. One finding per run: the first flag names the run; the hunt kept every flag (old items had
   up to 7). The rest are only in `check.out`.
5. A reference sweep of another program needs `--ok-exit` with every status
   (`$(seq -s, 1 255)`): there is no range or `any`; and one looping reference holds the whole
   leg to the 600 s default `--timeout`.
6. The report is long: 93 groups of differences printed 3 lines each (about 600 lines);
   `known: ID matched no run` is one line per unmatched entry (20 of 23 every sweep).
7. Numbers become `N` in the checker's detail, leg names included (`err7` reads `errN`), and in
   one case the appended `(inc-K)` was cut by the first-line length.
8. `report.json`: a group over many cases has `case` set to its first case (`cases` has all),
   and groups do not list their runs, so mapping a run to its known ID means recomputing it.
9. A case line that is one long argument gets the case directory `K-rw_` for all 1,000 cases.
10. `log events` lacks mark labels (to find `setup-complete`) and read paths: the hunt's
    ESCAPE oracle stays off (T7), and a swap-aware PROTECT had to use `log ops`.

### Second round: case settings, serving checkers, faults in known patterns

Defects 1 to 9, after the change that adds `--cases` line settings, `--check-serve`,
`{faults: ...}` in known patterns, `PATINA` for the checker, the `check:` health line,
`--ok-exit any`, `--check-timeout` and the shorter report. Run once by hand, 2026-11-18, this
host, every sweep `-j 6` under the shared evidence lock, `--keep fail` but the references;
the same checkers, with one change each where noted. Ids and counts only.

| Leg (3,449 corpus cases, seed 1, unless noted) | Before | After |
|---|---|---|
| fs errors with each case's own tree: `--work CASE/t:/work/t -- NAME` per line, no staging, no `faults-after-setup` | the line could not carry a tree: staged in the guest, 16 findings in 4 groups (SILENT 5 cases) | 38 findings in the same 4 groups: the 9 + 1 coverage cases and the planted case identical, SILENT in 27 cases, none of them the staged leg's 5 |
| the same leg, wall time by checker mode | (per run, through a version manager's shim, 163 s in round one) | no check 42.0 s; per run with the interpreter's path 67.9 s (1.6×); per run through the shim 101.8 s (2.4×); `--check-serve` 43.3 s (1.03×); the same 38 findings in 4 groups in all three |
| path swaps, 150 generated cases × seeds 1-2 | - | no check 1.9 s; per run through the shim 7.2 s (3.8×); with the path 4.3 s (2.3×); serving 2.3 s (1.2×); the same 3 findings in each |
| rshell checked against bash | 168.2 s; the report 505 lines | serving 35.8 s, the same 139 findings, now in 99 groups (details are no longer cut at 64 characters); the report 120 lines, the 22 unmatched known entries one line |
| bash reference | 601 s (two scripts loop to the 600 s default) | 32.6 s with `--timeout 30 --ok-exit any` |
| path swaps with the checker's `patina` variable unset (defect 3) | `check: judged 300 of 300 runs: 300 passed`, nothing else | the same, then `check: every judged run passed and no --known !ID entry shows that this check can fail`; with the checker reading `PATINA` when its own variable is unset (one line), 3 findings |

- Why the SILENT cases differ again: the fault draws follow the run's own sequence of
  eligible operations, and staging changed it. On one staged case
  (`shell_redirections_file_target_append`) the staged run had 13 eligible operations and two
  injected `EIO`s (the `close` and a `write` of its output file, which the case reports
  nothing about); the run on its own tree had 15 and none. The oracle is the same and finds
  the same class of bug on other cases; one seed is a sample of placements, not a replica.
- A line can also carry the case itself: `--work CASE/t:/work/t --name NAME -- HARNESS
  'CASE-JSON'` drops the shell and the `cat` the staged command needed: 20.4 s for the leg.
- The serving checker is the hunt's checker module behind a 15-line wrapper whose serving loop
  is 5 lines; started per run, the same file runs as before. Interpreter start-up was most of
  the per-run cost (about 30 ms with the interpreter's path, 80 ms through the shim, against
  1.5 ms of judging); a further cost was Patina's: every run hashed the checker's program,
  which through a shim is a 175 MB binary. Large files' hashes are now kept by file identity
  (device, inode, size, change time), as the `patina` binary's own is: serving through the
  shim took 9.4 s before, 2.2 s after (the unchecked sweep 2.4 s and 1.9 s).

**The known table again** (23 entries). With `{faults: ...}` and, on lines whose case is the
case JSON, a glob between its `"script":"` and `","allowed_commands"` keys, which sees the
script alone:

| Expressible | Round one | Now | Ids now |
|---|---|---|---|
| exactly | 10 | 14 | round one's, and 010 (by the fault that fired), 011, 013, 016 (a word in the script) |
| only with a `[CASE]` pattern | 1 | 1 | 006 |
| coarser | 11 | 7 | 001, 002, 003, 007, 014, 015, check-class: their script regexes use word boundaries or classes a glob has not; the fault part of 001 and 014 is exact |
| not at all | 1 | 1 | T7 |

On the leg whose lines carry the case JSON (42 findings), the new file and the table's own
matcher agree on all 41 hits but the planted one: 12 labelled the same (001 twice, 002 ten
times), 29 by neither; the planted case matched its `!` entry. Round one's file, over the same
runs, labels all 31 SILENT hits 001 and the planted one 010. On the path-swap leg the
corpus file no longer labels a path-swap PROTECT hit 010: no fs error fired.

- Runs without the new settings are unchanged: `compute/evidence-identity` against the build
  before (W1-W9, the stock thread, race and loop guests, seeds 1-3): 45 of 45 the same digest
  and `result.json`.
- Two checks that failed under load (`sweep/01-sweep`'s interrupted sweep, which found a
  process left; `skeleton/09-stall`): a `patina run` stopped by SIGTERM exited at once and
  left its sandbox to die after it. It now ends the sandbox and waits until its processes are
  gone, and a checker's, first. With CPU burners in the same cgroup, a memory-heavy
  interrupted sweep left processes in 13 of 30 tries before and none of 30 after; 01-sweep
  passed 30 of 30 under 60 burners, 09-stall 30 of 30 under 400 (3 of 12 before, killed by its
  own 8 s `timeout`, now 120 s as for every other run).

### Third round: grouping keys, judging again, case ids, the reference guard

After the change that adds `LABEL [KEY]` findings, `CLASS: detail` reasons, `patina recheck`
and `--keep checked`, case ids (`PATINA_CASE_ID`, `--only-case`) and the guard in
`same-output` and `same-tree`. `tests/oracles/evidence-triage.sh`, run once by hand,
2026-11-18, this host, `-j 8`, with `OLD_PATINA` the build before the change. The corpus: 200
generated cases `OP A B` of a shell calculator with two planted bugs (a difference above 50 is
one too many; anything times 0 is the other operand) and one difference by design (it divides
toward zero, the reference toward minus infinity), each at seeds 1-2 (400 runs), against a
reference sweep of a correct calculator; the checker compares stdout and prints what it got
and wanted.

| Leg | Result |
|---|---|
| groups, `wrong-output: got G, want W` | 3 groups by the numbers' signs, each mixing bugs: `got N, want N` 46 (e.g. `got 69, want 68`), `got -N, want -N` 12, `got N, want -N` 4 |
| groups, `wrong-output [OP]: got G, want W` | 3 groups, one per cause: `[sub]` 38, `[div]` 16, `[mul]` 8, each with its example (`[mul]: got 46, want 0`); the same groups and counts by `patina recheck` of the first sweep and by a fresh sweep |
| the 8 division cases added to the expected-differences table | `patina recheck` 0.39 s; the same sweep afresh 1.06 s; both `judged 384 of 400 runs: 338 passed, 46 failed; 16 not judged (expected 16)` and the same 2 groups |
| disk for the 400 runs | `--keep checked` 13.1 MB (here every run was judged, so as `--keep all`); `--keep fail` 6.0 MB |
| recheck of the `--keep fail` sweep with another checker | the 46 kept runs judged again, 354 pruned named and left; exit 1 (the findings), the report naming 2 checkers |
| reference made with another `--work` tree (`same-output`) | exit 2, `200 errors`, none a finding: `reference-mismatch: work differs: the reference has [".../t2",null], this run [".../t1",null] (--relax work to compare anyway)` |
| the same with `--relax work` | exit 1, `judged 200 of 200 runs: 169 passed, 31 failed` |
| fjall harness, `--buggify`, seed 1 / seeds 1-4 | this build: exit 2 (`buggify never fired: manual-flush, persist-now`) / exit 0; the build before: the same |

- The unmet-sites rule is unchanged on purpose: the fjall harness's two unmet points are its
  own (`src/main.rs`), unmet at one seed and met at four, which is what the rule is for. A
  library's sites are allowed by prefix in `patina.toml`; the change adds the line that counts
  allowed sites and, when most unmet labels share a prefix, the `[sdk] allow-unmet` entry to
  write.
- Runs without the new settings are unchanged against the build before: `hello-static` seed
  3, `kvlog` `--crash machine:10 --check acked-kept` seed 2, `sdk-rs --buggify` seed 4,
  `upcase --faults disk` seed 5, and a kvlog sweep of seeds 1-3: `result.json` and `run.json`
  identical but for `wall_ms`, `patina` and the supervisor's memory high-water mark (which
  differs between two runs of one build), every `boundary.log` byte for byte; a sdk-rs
  `--buggify` sweep's text identical. A sweep's text gains the `example:` line, `report.json`
  `checkers`, `example` and `case_id`; `sweep.json` no longer holds the checker.

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

### arm64

The same protocol on arm64, 2026-11-17: one `patina` and one guest set built on an
`ubuntu-24.04-arm` runner from `c15ebe60` (static guests built `-static`, `tokio-mt` with
`crt-static`), copied unchanged to each host, 66 cells, 330 runs per host. The workflow took
6 minutes (bundle 2.5, each matrix job 3).

| Host | Image, kernel | CPU | Cells identical over 5 runs |
|---|---|---|---|
| GitHub `ubuntu-24.04-arm` (two concurrent jobs, two runners) | 24.04, 7.0.0-1017-azure | Neoverse-N2, SVE 128 bits | 66/66 each |
| GitHub `ubuntu-26.04-arm` | 26.04, 7.0.0-1019-azure | Neoverse-N2, SVE 128 bits | 66/66 |
| development VM (Tart) | 24.04, 7.0.0-43-generic | Apple M4, no SVE, SME | 66/66 |

Within each host every run of a cell has one digest; two counters outside the digest vary
(the supervisor's memory high-water mark, and in `go-static` the number of spin-probe steps,
whose arrival is not deterministic by design). Outcomes other than `ok`, the same on every
host: `sockets` and `sockets-static` with faults `all` (`failure`, an injected reset), and
`w6.sh` seeds 2-3 with faults `all` (`failure`, an injected error). Only the 26.04 runner adds
`w6.sh` seed 1 (`mktemp` fails to map `libgcc_s`, which 26.04's coreutils load, on an injected
`ENOMEM`) and CPython 3.14 seed 2 `liveness` (every thread blocked after an injected `ENOMEM`
in a thread): its `/usr` moves where the draws land.

Across hosts: the two 24.04 runners give equal digests in all 66 cells; every other pair
agrees on 12 (`hello-static` and `sockets-static`). First differing record (`patina log diff`)
and cause:

| What differed | Guests | Kind | Verdict |
|---|---|---|---|
| `fstat` of `/etc/ld.so.cache` (VM against runner); 24.04's loader calls `faccessat` (`ld.so.preload`) where 26.04's calls `uname` first | every dynamic guest, `python3`, `/bin/sh`; `tokio-mt-static` in its `seq` child | the host's loader and libc | allowed |
| `uname` release | `fs-tour-static` (the only difference between the 24.04 and 26.04 runners) | kernel version | allowed |
| `stat` of the host's `/usr/bin/sort` (Go's `os/exec` path search) | `go-static` | host programs | allowed |
| argument registers a call does not read: `mremap` without `MREMAP_FIXED` and `prctl(PR_GET_NAME)` called through `syscall()` carry a leftover `x4`, which static glibc's `memcpy` sets on the VM (its generic routine) and not on the runners (the SVE routine's short path) | `fs-tour-static`, `tokio-mt-static` (`futex` wake), VM against runner | CPU identity (SVE or not chooses the library routine) | fixed: the record keeps only the registers a call reads ("Unread argument registers", below) |

No new kind of difference within a host. What can be promised on arm64 is what x86_64
promises: a seed gives the same run on one host, repeated, across CPUs, ASLR and sandboxes;
across hosts a static guest that reads no host file gives the same run on CPUs with the same
features (and, since the change below, the leftover registers of a different library routine
no longer count). The `/proc/self/mountinfo` difference of
x86_64 did not appear: `go-static`'s first difference on every pair comes after its start-up
read of that file.

### Unread argument registers

A boundary record kept every argument register a call has, so one the call reads only under
some flag, command or non-NULL pointer reached the digest with whatever the program's code left
there. The record (and its hashes, the containment check and the hidden-descriptor check) now
keeps only the registers the call reads for the values of the others
(`proto::table::nargs::live`, `proto::table::cmds`). 2026-11-18, base `a9da5847`, head the
commit that made the change.

The same bytes on several hosts: one throwaway workflow built `patina` at base and at head and
six static guests once per architecture on a GitHub runner (`hello-static`, `fs-tour-static`,
`sockets-static` and the regression guest `deadargs` with `gcc -static`; `tokio-mt` with
`crt-static`; `go-static`), ran each at seeds 1-3, faults off and `all`, on eight hosted jobs,
and the arm64 bundle ran again on the development VM. Records compared one by one between hosts
(cells: 3 seeds x 2 fault settings per guest; a host pair, both builds):

| Hosts | Guest | Base: records that differ | Head: records that differ |
|---|---|---|---|
| Apple M4 VM (no SVE) / `ubuntu-24.04-arm` Neoverse-N2 (SVE) | `fs-tour-static` | `mremap` x4 (new address, no `MREMAP_FIXED`), `prctl(PR_GET_NAME)` x4, `uname`, the `write` that prints it | `uname`, the `write` that prints it |
| same | `tokio-mt-static` | `futex` wake/wait timeout, `uaddr2`, `val3` (4 records), then the host's `seq` child (its loader and libc) | the host's `seq` child only |
| same | `go-static` | `stat` of the host's `/usr/bin/sort`, then its schedule | the same |
| same | `hello-static`, `sockets-static`, `deadargs` | none | none |
| `ubuntu-24.04-arm` / `ubuntu-26.04-arm` (both Neoverse-N2) | all | `uname` (`fs-tour-static`), the host's loader (`tokio-mt-static`, `go-static`) | the same |
| `ubuntu-24.04` AMD EPYC 7763 / AMD EPYC 9V74 | `tokio-mt-static` | `prctl(PR_SET_NAME)` 3rd argument x12 (one per thread), then the host's `seq` | the host's `seq` only |
| `ubuntu-24.04` AMD EPYC 7763 / Intel Xeon 6975P-C | `tokio-mt-static` | thread stack and signal-frame addresses (XSAVE size), `prctl(PR_SET_NAME)` 3rd argument | the addresses only |
| x86 hosts pairwise (five jobs: AMD 7763 on 24.04 and 26.04, AMD 9V74, Intel 6975P-C on 24.04 and 26.04) | `fs-tour-static`, `go-static` | `uname` and the `write` that prints it; `go-static`: buffer addresses, then its schedule | the same |

With the change, no difference between two hosts of one architecture names an argument a call
did not read. What still differs: the kernel release (`uname`), the host's files (loader, libc,
programs a guest runs, `/usr/bin/sort`'s `stat`), addresses that follow the CPU's XSAVE size on
x86_64, signal-frame records that follow the CPU's features, and code paths a library chooses
by CPU feature when they make different system calls (not merely leave different registers).

Identity on one host: the 90 cells of the builder's ledger (`hello`, `fs-tour`, `sockets`,
signals, fork/exec, threads, instructions, UDP, tokio, Go, CPython, a shell pipeline; seeds 1-3,
faults off and `all`) at base and head on the development host, compared record by record:
every cell's digest changes, and every differing record differs only in arguments head records
as zero (and, for `epoll_ctl(EPOLL_CTL_DEL)`, its input hash): `mmap`'s descriptor of an
anonymous mapping (-1) in all 90; `futex` timeout, `uaddr2`, `val3` of wakes and waits; `ioctl`
and `fcntl` arguments of commands that read none (`FIOCLEX`, `F_GETFD`, `F_GETFL`); `prctl`'s
arguments after `PR_SET_NAME`'s; `clone`'s parent tid word without `CLONE_PARENT_SETTID`;
`epoll_ctl`'s event for `EPOLL_CTL_DEL`. The same on the arm64 development VM (60 cells with a
result): also `openat`'s mode without `O_CREAT`, `mremap`'s new address, `clone`'s TLS and
child tid, `ppoll`'s and `epoll_pwait`'s signal-set size without a set. No cell differs for
another reason.

Four valid calls the change makes answer as natively, which before answered an error because
of an unread register (`ptrprobe`'s `dead-` probes, `deadargs`): `epoll_ctl(EPOLL_CTL_DEL)`
with an event pointer into the runtime's region, `recvfrom` and `accept4` with no address and an
address-length pointer there (`EFAULT` before), and an anonymous `mmap` whose descriptor
argument is a hidden number (`EBADF` before). `mremap` without `MREMAP_FIXED` with a runtime
address in its fifth register was already answered correctly; it is checked too.

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

`tests/storage/12-f2.sh` (release tier, both architectures) is the standing check, on a journal
laid out so the window comes early: `FJ_VAL_SHIFT=289` shifts the harness's value lengths so
that batch 5 straddles the first 4 KiB block boundary between an item's `value_len` and its
`on_disk_value_len` (at the default layout the first such batch is about 800, which on the
4-core runners put seed 1's window at point 3,005 (x86_64) and 3,010 (arm64): 349 and 426 s
for that seed alone). `--seeds 1..3 --branch --crash machine --buggify --env FJ_N=100 --env
FJ_VAL_SHIFT=289 --max-findings 1 -j 4` must hold F2's group. 2026-11-17: on this host, four
CPUs (`taskset -c 0-3`), F2 at seed 1, point 241, after 724 of 2,615 points, 16 s; on the
runners 727 points, 33 s (x86_64) and 35 s (arm64). With `FJ_N=5` (the journal ends before
batch 5) all 1,053 points ran and nothing was found, so the check fails (23 s).

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

## arm64

What else was measured on arm64, 2026-11-17, besides the sections above ("Spin-waits ...
arm64", "Instruction sites on arm64", "Compute points ... arm64", "Second hosts ... arm64").
Hosts: GitHub `ubuntu-24.04-arm` runners (Neoverse-N2, 4 CPUs, 7.0.0-1017-azure), each check
run once from a throwaway branch, and the development VM (Apple M4, 4 CPUs, Linux 7.0).

**The quick tier** (`check-arm64`, every script but the branch-counter one, 115): 141, 149
and 123 s of wall time on three pushes (x86_64 `check` on the same pushes: 94 to 101 s). Every
script is under half its budget there.

**Areas.** `./check AREA` for every area once on the runner, with every `arch=x86_64` mark
removed but the branch-counter scripts, `insn/04-cpuid` and `insn/05-rdpid`: all pass but
three, each fixed or explained:

| Script | On the runner | Now |
|---|---|---|
| `insn/06-scanner-audit` | the census called four `isb` sites of `hello-rs` (std's `Mutex::lock_contended` and `RwLock::read_contended`, real code) data: it read the `$d` symbols of `.debug_aranges`, whose values are offsets in that section, as addresses | the census takes mapping symbols of loaded sections only |
| `sandbox/05-rows` | expected x86_64's 31 lines and its call names | arm64's table: 26 lines, `epoll_create1` and `clone` for `epoll_create` and `fork`, no `select`, `pause` or `alarm` |
| `storage/02-f1`, `05-f4` | over their 30 s budgets (each runs four sandboxes and declared one) | they declare four; F1 searches its seeds 25 at a time and stops at the first block with a confirmed seed (6.1 s; F4 17.2 s, F3 7.6 s) |
| `storage/03-f6` | its named seed (2001, found on x86_64) is `ok` | stays x86_64 only: the seed is the host's |

**Costs** (runner; VM in brackets). From whole runs, median of 5 seeds, the `costs` guest (`tests/guests/costs`):

| What | Cost |
|---|---|
| Trap answered in the runtime (`getppid`) | 3.0 us (VM 1.9 us); native 0.21 us (VM 0.13 us) |
| Counter-timer read (`clock_gettime`, trapped `CNTVCT_EL0`) | 2.7 us (VM 1.8 us) |
| `sched_yield` (a supervisor hand-off) | 8.7 to 13 us (VM 4.6 us) |
| A run of a static `true` (`wall_ms`) | 15 ms (VM 6 ms) |
| The `patina run` process, static `true` / `python3 -c pass` (`durability/evidence-costs`) | 116 ms (77 to 1,091) / 109 ms; native 1.6 ms / 32 ms |
| W1-W9 per run, faults off (`durability/evidence-costs`) | W1 31, W2 80, W3 36, W4 175, W5 152, W6 360, W7 306, W8 350, W9 69 ms |
| Runtimes (`runtimes/evidence-costs`), per run | Go 187 ms, CPython 162, tokio 86, tokio TCP 117, sh 395, bash 493 (natively 1.6 to 5.5 s: their sleeps) |
| Sweep throughput, `hello-static` (`sweep/evidence-throughput`) | 42 runs/s at `-j 1`, 131 at `-j 4`, 132 at `-j 8` (4 CPUs); 500 pipes at `-j 8`, 14 runs/s, all `ok` |

**Adopter checks** (runner; counts are per architecture, x86_64's in brackets):

| Check | Result |
|---|---|
| Examples, documented sweeps, seeds 1-20 (`examples/01`) | every bug found under its signature, every fixed variant `ok` 20/20: quickstart 15 (14), ledger 4 (4), journal-py 7 (11), acklog 2 (6), bank 11 (11), stats-cp 6 (8), serve 7 (5) |
| fjall F1, `--crash machine:3` / `process:3`, seeds 1-100 | 3 / 4 seeds (3 / 4), the native harness agreeing |
| fjall F3, seeds 1-100 | 3 `liveness` (2) |
| fjall F4, `fsync-error-at=50..80` x seeds 1-10 | first confirmed cell `fsync-error-at=63` seed 7 (x86_64: 67, seed 4) |
| fjall F5, seeds 1-10 | 3 of 10 |
| fjall F2, `storage/12-f2` (`sweep --branch`, seeds 1-3, early journal layout) | found at seed 1 after 727 crash points, 35 s (x86_64: 33 s); "Crash-point enumeration" |
| `testbeds/pubsub` (`sweep/03-pubsub`), 200 seeds | clean: no finding; lost-wakeup 200, drop-read-remainder 199, stale-timeout 165 of 200 |

**Not run on arm64**: the evidence scripts still marked `arch=x86_64` (the determinism matrix
`determinism/evidence-matrix`, the soaks and the time variant, the durability census,
operation log and workload sweeps, `faults/evidence-crashes`, the per-call costs of I/O rings,
networking and spawning, `storage/evidence-branch` and `evidence-crash-enum`); `insn/04-cpuid`, `insn/05-rdpid` (x86_64
instructions). Hosts not checked: bare-metal arm64, a host with 16 or 64 KiB pages, SVE above
128 bits, a heterogeneous (big.LITTLE) machine, and any Mac VM product but Tart.

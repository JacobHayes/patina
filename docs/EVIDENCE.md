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

## Load-time rewriting

### The plans, natively

The rewriter (ARCHITECTURE.md, "Load-time rewriting"), its plans checked by the separate
verifier, and each plan applied to a copy of its file (`patina __rewrite --standalone`) run
natively against the original, without Patina (under Patina: below).
Measured 2026-11-19 on the host above (Ubuntu 26.04), by `rewrite/evidence-corpus` (`./check
evidence evidence-corpus`, 622 s with 50 runs each and the census) and `rewrite/01-differential`
(quick). Back-edges before groups (single-instruction patches only) in parentheses.

| Program (rewritten with the shared libraries it loads) | Sites patched of found | Back-edges covered | Groups (interior boundaries) | Dark text | Rewrite | Plan (before groups) | 50 runs |
|---|---|---|---|---|---|---|---|
| ripgrep 15.2.0, musl static-PIE release (3.7 MB text), a regex count over the Go sources | 55,868 / 56,500 | 98.9% (85.4%) | 4,974 (5,333) | 0.3% | 0.26 s | 7 MB (6) | identical output and exit |
| gofmt, Go 1.27.3, static (1.3 MB), `-d -r` rewrite over `runtime` | 21,960 / 22,072 | 99.4% (84.5%) | 1,082 (1,099) | 0.0% | 0.06 s | 2 MB (2) | identical |
| CPython 3.14.4 (3.7 MB, non-PIE) and 4 libraries, a dict, sort, regex and json workload | 109,120 / 112,768 | 97.0% (87.2%) | 7,114 (7,887) | 0.0% | 0.24 s | 9 MB (8) | identical |
| clang 21 (86.1 MB) and 5 libraries, compiling `diff.cc` at -O2 to assembly | 1,452,922 / 1,468,196 | 98.2% (72.8%) | 162,395 (167,033) | 0.0% | 5.2 s | 176 MB (136) | identical |
| headless Chromium (Playwright's `chrome-headless-shell`, 170 MB) and 44 libraries, `--dump-dom` of a scripted page | 2,841,295 / 2,893,062 | 97.6% (74.9%) | 336,403 (366,270) | 22.4% | 9.7 s | 325 MB (248) | identical; 200 more runs identical, no crash |
| The quick tier's guests (C static and static-PIE, C++, Rust, Go): plan twice and compare, verify, objdump agrees on every patched instruction, 5 runs, and a copy with 1,000 events stops on its trap (`SIGILL`) | | 98.0 to 99.2% | | | | | identical |
| Census: every ELF file in `/usr/bin` and the system library directory, planned and verified | 1,142 files; 0 rejected by the verifier; 9 refused (relocatable objects) | | | | | | not run |

"Dark" is text no control flow or unwind extent reaches: Chromium's is mostly code reached only
through tables (no jump-table following, by design). Rewrite time is one thread with
verification excluded, before plans were made on several ("Making plans on several threads",
below); Chromium's peak memory was 1.1 GB. A site not patched is flags live (no point in its
block or run where the flags are dead), no room (no run of 5 bytes or more that no known branch
enters), or tainted (a span with a refusal). The CLI binary grows by 324 kB stripped (+5.4%)
with `iced-x86` (decoder and instruction info only); its clean build takes 2.3 to 2.8 s.

Red/green: a Jcc patch with its condition inverted is rejected by the verifier; with the
verifier skipped, the same plan's copy fails the differential (`SIGSEGV`). A branch into the
interior of an instruction once went unseen (the unit test for a jump into a would-be patch
caught it); an absolute read of data in non-PIE text not ending extent decode fails the unit
test for data in text. The verifier rejects every planted corruption in `rewrite::tests`, and
the plan reader a page mapped twice.

### Group patches

A short site with no single instruction to carry its count is merged with its straight-line
neighbours (ARCHITECTURE.md, "Group patches"); every interior boundary holds a faulting byte
and the runtime resumes a jump there at the instruction's copy. Measured 2026-11-19 on the host
above.

| Check | Result |
|---|---|
| `rewrite/04-interior` (quick): `rw-interior`, static and static-PIE assembly that enters every interior boundary of its 7 groups (12 boundaries, `int3` and port I/O bytes, one group across a page, one with a prefixed jump, one with a RIP-relative copy) through a table the rewriter does not read, by `call`, `jmp` and `ret` | the plan's interior boundaries are exactly the guest's labels; native, the rewritten copy and Patina print the same; seeds 1 and 2 identical under `--vary cpu,load,aslr,sandbox,repeat` with a point on every count; 24 interior entries resumed of 24 made |
| The same guest after mapping over the 64 MiB past its image (where its trampolines are) | the plan is dropped, native output |
| Chromium natively, the rewritten copy and its 44 libraries | 200 runs: output and exit identical to the original, no crash |
| Chromium under `--preempt points`, seeds 1 to 100 (warm plans) | 100 runs: output identical to native, no crash; 325 to 380,592 points a run (60,689 mean); seed 1 twice one digest; 49 of 49 images planned |
| Interior entries in the corpus runs | none in any run above (Patina's `interior` count, and natively `strace -f` of 3 Chromium runs shows no `SI_KERNEL` trap) |
| Direct branches into an interior boundary (objdump's linear sweep of Chromium's whole text against its 366,270 boundaries) | 3, each from code the rewriter does not reach (a case block reached through a table, as in the design's traced fault): `jmp`/`je` in font and allocator code at 0x268a81d, 0x5df6aed, 0x7c166d3. Each would trap and resume; none ran in these workloads |
| Cost of an interior entry (200,000 jumps into a group, against 200,000 entries at its start) | natively 0.6 µs each (a signal and `rt_sigreturn`); under Patina 0.66 µs each (the runtime's fault entry) |
| CPU time natively, 20 runs (user + sys; original / single-instruction plans / groups) | ripgrep 0.072 / 0.054 / 0.057 s; CPython 0.061 / 0.082 / 0.084 s; clang 0.391 / 0.501 / 0.550 s; Chromium 0.074 / 0.091 / 0.098 s. gofmt natively is 1.3 / 33.5 / 40.8 s: its threads contend for the one count cell (a cache line), which never happens under Patina (one thread at a time) |
| Plan size | +5 to +31% (trampolines whose address a boundary constrains sit 5 to 8 MiB past the image; only pages holding a trampoline are stored) |
| Runtime | 50 more lines of code (784 in all, below): the interior lookup and resume, the sparse trampoline mapping, a change to mapped trampolines dropping the plan, dropping inherited I/O permission; no decoder |

Red/green: with the runtime's resume disabled, `04-interior` c fails (output differs: the
guest dies at its first interior entry). Review found two defects, both fixed: a copied x87
instruction recorded the trampoline's address as its own (`fnstenv` showed it; x87
instructions are no longer copied), and a program mapping over its trampolines alone kept
patches that jumped into the new mapping and died of `SIGSEGV` (that now drops the plan;
`04-interior` d).

### Under Patina: `--preempt points`

The runtime applying the plans of a program and every library it maps, measured 2026-11-19 on
the host above by `rewrite/evidence-points` (`./check evidence evidence-points`) and the quick
tier's `rewrite/02-points` and `03-fidelity`. Each program's output is compared with its
native run's, and seed 1 is run twice with warm plans.

| Program (with its libraries) | Output, same seed twice | Wall: without points / cold / warm | Plans made | Points taken | Interior entries | The program's sites patched, back-edges, dark | Files planned; unplanned, dropped; `cpuid` answered |
|---|---|---|---|---|---|---|---|
| ripgrep 15.2.0 (musl static-PIE, run from `sh`), a regex count over the Go sources | native; identical | 378 / 835 / 389 ms | 0.46 s | 89 | 0 | 98.9% of 56,500; 98.9%; 0.3% | 4 of 4; 0, 0; 47 |
| gofmt (Go 1.27.3, static), `-d -r` over `runtime` | native; identical | 1,068 / 1,183 / 1,095 ms | 0.09 s | 6,227 | 0 | 99.5% of 22,072; 99.4%; 0.0% | 4 of 4; 0, 0; 49 |
| CPython 3.14.4, dict, sort, regex and json | native; identical | 90 / 920 / 150 ms | 0.80 s | 944 | 0 | 96.8% of 112,768; 97.0%; 0.5% | 9 of 9; 0, 0; 49 |
| headless Chromium, `--dump-dom` of a scripted page | native; identical | 563 / 15,188 / 898 ms | 14.1 s | 339 | 0 | 98.2% of 2,893,062; 97.6%; 22.5% | 49 of 49; 2, 0; 289 |
| PostgreSQL 18 (built from source; by hand, not in the script): start, the SERIALIZABLE bank workload of 3 clients, stop | the bank checker passes; 5 runs under `--vary cpu,load,aslr,sandbox,repeat` identical, cold and warm one digest | 555 / 1,858 / 568 ms | 1.18 s | 53 | - | `postgres`: 91.7% of 144,087; 87.0%; 0.0% | 19 of 19; 0, 0; 2,880 |

"Cold" makes and verifies every plan in the run (the files the program names before it
starts, the others when they are mapped; wall time only, so the digest is the warm runs');
"warm" reads them from the plan cache. Coverage is the program's own file. Chromium's
unplanned are memory it makes executable at run time. PostgreSQL is not installed system-wide
here, so the script skips it; its row is a build from source run by hand, before group
patches. The runtime adds
784 lines of code (`plans.rs` and its call sites, comments and blank lines aside) and no
decoder.

| Check | Result |
|---|---|
| Determinism: `verify --vary cpu,load,aslr,sandbox,repeat`, C static, C static-PIE, C++, Rust (lld), Go, 5 runs (seed 5) and in the release tier 3 runs of seeds 1 and 2 (the quick tier: C static and Go) | identical; seeds 1 and 2 differ |
| The same for the stock races `go-race-stock` (compute-gap 8, seeds 1-3, 6 runs) and `rs-race-stock` | identical |
| Without the `cpuid` sites, `go-race-stock` under `--vary cpu` | differs at the first point: `rbx` 0x0c180800 against 0x01180800, leaf 1's initial APIC id, which Go's `rt0_go` leaves in a register (below) |
| Schedules reached: `go-race-stock` (a check-then-act on atomics, no system call in the window), seeds 1-20 | without points 0 failures; points at the default gap 0; points with `compute-gap=2..64` 9 (GUIDE transcript) |
| `rs-race-stock`, seeds 1-40 | 5 failures at gap 1-2, 4 at gap 4, 0 at gap 8 |
| `stats-c` built stock (a lost update: a load and a store with no branch, call or atomic between) | 0 of 20 at the default gap and at `compute-gap=1..8`: out of reach by design (a rebuild finds it) |
| A timer due inside a loop with no system call (`deadline-stock`) | without points `compute-stall`; with them the handler runs at 10,003,018 virtual ns for a 10 ms timer |
| `spinpoints count` (a spin-wait whose iterations change state) | `ok` (without points `compute-stall`) |
| fork + execve of `/bin/true`, 300 in a run, per call (K5) | without points 0.73 to 0.79 ms; with warm plans 1.18 to 1.28 ms (0 to 2 points taken); seeds whose drawn gap is small took thousands of points (seed 3: 9,144, 1.7 ms per call): each point was a supervisor hand-off of about 17 µs, the search's cost, not the plans' (since, only points that can switch are taken: "The cost of a point", below). glibc's start runs `cpuid` 40 times per process, each answered in the runtime |
| Every run without the flag (90 cells of the stock workload ledger: outcome and digest) | identical to the build before |

Fidelity (`03-fidelity`, `rw-fid`, dynamic C): a fault in a relocated `lock xadd` is reported
at the instruction's address and `backtrace()` from the handler reaches `main`; a timer signal
taken at a point in a spin loop names an address in the loop; `/proc/self/maps` lines (perms,
offsets, paths) equal the native run's; a checksum of the program's own text differs from the
native one (reads see the patch) and is the same on two seeds; `mprotect` of the text puts
that page back and reads the native bytes; code copied into anonymous memory runs and is counted
unplanned; a fork child that execs the program applies plans of its own. `shlib-stock`
(`dlopen`/`dlclose` twice): every image planned, the closed library's plans dropped. Static,
static-PIE, dynamic and Go programs all run their native output (above).

**`cpuid`.** The register dump above led to a census on this host (Ryzen 9 9950X, 24 CPUs,
no `cpuid` faulting): the leaves and sub-leaves `cpuid` answers, read on every CPU, differ only
in leaf 1 `EBX[31:24]`, leaf 0xB `EDX` and leaf 0x8000001E `EAX`/`EBX`, each a core's id. A
patched `cpuid` answers them as core 0's (and the other topology ids of Intel and AMD the
same: ARCHITECTURE.md). The kernel's `cpuid` faulting (`ARCH_SET_CPUID`) would catch every
`cpuid`, dark code's too, but this host does not offer it (no `cpuid_fault` flag), so it could
not be tested here; plan sites work on every x86_64 host, and `cpuid_unpatched` reports the
pairs they leave.

Red/green: with the masking off, `02-points` d fails (`--vary cpu` differs); with signal
frames not translated (`shown`), `03-fidelity` b fails (the timer's address is in a
trampoline).

### On arm64

The same scripts on GitHub `ubuntu-24.04-arm` runners (4 CPUs, Ubuntu 24.04, Linux 7.0),
measured 2026-11-19. Every site is one word, so there are no groups and no interior entries.
The plans, natively (`rewrite/evidence-corpus`, 351 s with 50 runs each and the census):

| Program (rewritten with the shared libraries it loads) | Sites patched of found | Back-edges covered | Dark text | Rewrite | Plan | 50 runs |
|---|---|---|---|---|---|---|
| ripgrep 15.2.0, musl static release (3.1 MB text), a regex count over the Go sources | 42,409 / 42,560 | 99.5% | 4.0% | 0.08 s | 6 MB | identical output and exit |
| gofmt, Go 1.27.3, static (1.2 MB), `-d -r` rewrite over `runtime` | 20,951 / 21,443 | 93.2% | 0.0% | 0.02 s | 3 MB | identical |
| CPython 3.12 (3.0 MB) and 4 libraries, a dict, sort, regex and json workload | 89,851 / 89,851 | 100% | 4.8% | 0.07 s | 9 MB | identical |
| clang 18 (a 0.1 MB executable) and 17 libraries (`libLLVM`: 967,258 of 967,270 sites, 100% of back-edges, 116 MB plan), compiling `diff.cc` at -O2 to assembly | 2,102 / 2,103 | 99.8% | 0.1% | 0.00 s | 0.4 MB | identical |
| headless Chromium (Playwright's `chrome-headless-shell`, 166.9 MB) and 49 libraries, `--dump-dom` of a scripted page | 2,836,248 / 2,838,239 | 99.9% | 18.5% | 3.6 s | 346 MB | identical (the copy's plan: below) |
| The quick tier's guests (C static and static-PIE, C++, Rust, Go): plan twice and compare, verify, objdump agrees on every patched word, 5 runs, and a copy with 1,000 events stops on its trap | | 89.2 to 99.8% | | | | identical |
| Census: every ELF file in `/usr/bin` and the system library directory, planned and verified | 1,442 files; 0 rejected by the verifier; 12 refused (malformed headers) | | | | | not run |

Back-edges not covered are almost all `exclusive`: the way back from a failed store-exclusive
to its load (Go's and glibc's exclusive-pair fallbacks, unused where the CPU has LSE atomics;
gofmt 490, ripgrep 151, Chromium 69). Chromium has 1,913 back-branches out of a branch's reach
(`far`: its text spans 280 MiB, and these are more than 128 MiB from both ends). A rewritten copy cannot put
trampolines below its image, so the native copy of Chromium carries the after-only plan:
2,398,862 sites, 80.9% of back-edges (the rest out of reach). GNU objdump 2.42 aborts on
Chromium; its words are checked against LLVM's decode instead. The CLI binary grows by
110 kB stripped (+1.7%, x86_64 build): the word classifier is encoding masks, no decoder crate.

Under Patina (`rewrite/evidence-points`), and the quick tier (`02-points`, `03-fidelity`,
`04-interior`, all passing):

| Program (with its libraries) | Output, same seed twice | Wall: without points / cold / warm | Plans made | Points taken | The program's sites patched, back-edges, dark | Files planned; unplanned, dropped |
|---|---|---|---|---|---|---|
| ripgrep, from `sh` | native; identical | 744 / 1,090 / 832 ms | 0.26 s | 160 | 99.6% of 42,560; 99.5%; 4.0% | 4 of 4; 0, 0 |
| gofmt | native; identical | 1,264 / 1,744 / 1,675 ms | 0.07 s | 4,575 | 97.7% of 21,443; 93.2%; 0.0% | 4 of 4; 0, 0 |
| CPython | native; identical | 195 / 638 / 243 ms | 0.38 s | 435 | 100% of 89,851; 100%; 4.8% | 9 of 9; 0, 0 |
| headless Chromium | native; identical | 1,395 / 15,257 / 1,780 ms | 13.3 s | 324 | 99.9% of 2,838,239; 99.9%; 18.5% | 51 of 51; 4, 2 |

| Check | Result |
|---|---|
| Determinism: `verify --vary cpu,load,aslr,sandbox,repeat`, C static, C static-PIE, C++, Rust, Go, 3 runs of seeds 1 and 2 (`02-points` a); `shlib-stock` and `rw-fid`, seed 3 | identical; seeds 1 and 2 differ |
| ripgrep, 8 runs of seed 1 each (`--vary repeat`): one thread, from `sh`, and its own thread pool (8,221 switches a run) | identical |
| Schedules reached (`02-points` b): `go-race-stock`, `rs-race-stock` | found on seeds 1 and 24; without points neither race window holds a switch |
| A timer due inside a loop with no system call (`deadline-stock`, `02-points` c) | the handler runs at 10,003,027 virtual ns for a 10 ms timer |
| Fidelity (`03-fidelity`): a fault in a relocated `ldaddal`, a timer at a point, fork, code copied to anonymous memory; `/proc/self/maps`; `mprotect` of the text; `dlclose` | as natively (the fault's address is the instruction's, `backtrace()` reaches `main`); 7 maps lines as natively; the plan dropped and the native bytes read; both closed libraries' plans dropped |
| A program that maps over its trampolines (`04-interior` d) | the plan is dropped, native output |
| Every run without the flag (the 90 cells of the stock workload ledger) | identical to the build before, on the runner |
| x86_64 with the flag: the 11 guests of the rewrite checks, seeds 1 and 2, against the build before | the same digests and points; plans byte-identical but for the build id |
| The verifier against planted corruption (`rewrite::a64::tests`) | 25 kinds rejected, and a count inside a pair, on a pair's retry, on a weak compare-and-swap's way back, at a call inside a pair, at a word whose address is taken, beside a refused word, and an `x16` row to a label in the caller's function |

The runtime adds 34 lines of code (818 in all by the count above): the arm64 trap length,
machine number and `PROT_BTI` on trampolines, the room past `ld.so`'s reservation, the
allocator's cursor below trampolines before an image, and the site's original address from a
trampoline's `b`. Chromium's 4 unplanned are memory it makes executable at run time.

Red/green: without the way-back rule, ripgrep's musl build under points gave one seed two
digests (a store-exclusive failing natively by run, the loop around it going round once more
past a count); with it, 8 of 8 identical in each of the three workloads above. A copy of
Chromium with trampolines before its image (entered through a stub at its entry) died of
`SIGSEGV`: a library's constructor calls the executable's `malloc` before its entry runs; copies
now carry after-only plans. Chromium under Patina exited 127 when the allocator's cursor was
moved below its floor by an executable's trampolines (`libdl` could not be mapped); only
trampolines above the floor move it now. Review found, and tests now cover: a call inside an
exclusive pair (reached through a `b`) was patched, and the verifier, following pairs only in
address order, took it; a word whose address `adr` takes (which code can read) was patched; an
`x16` row for a call to a label inside the caller's own function, where `x16` may be live; the
verifier did not taint the span around a refused word, and missed trampoline bytes over the
image when the span started inside it.

### Making plans on several threads

The first run under `--preempt points` makes the plans of every file it maps (above: the
"cold" column). Plans are now made on up to 8 threads, with the same bytes. Measured
2026-11-19 on the host above and on a GitHub `ubuntu-24.04-arm` runner (4 CPUs), by hand:
`patina run --preempt points` with an empty plan cache, then again warm; wall seconds, the
least of 3 (the runs above: ripgrep, CPython, headless Chromium; clang compiling `diff.cc`),
before and after the change.

| Program | x86_64 cold, before / after (warm) | arm64 cold, before / after (warm) |
|---|---|---|
| ripgrep 15.2.0 | 1.39 / 0.70 s (0.54) | 0.33 / 0.17 s (0.06) |
| CPython (3.14 here, 3.12 on the runner) and 8 libraries | 0.96 / 0.54 s (0.13) | 0.72 / 0.53 s (0.26) |
| clang (21 here, 18 on the runner) and its libraries (7 files; 19) | 8.77 / 3.81 s (0.68) | 6.90 / 4.68 s (2.71) |
| headless Chromium (49 files; 57) | 16.60 / 6.62 s (1.75) | 22.10 / 7.67 s (3.40) |
| A cold sweep, `-j 8`, seeds 1..3, of Chromium: wall; plans its runs made | 17.6 / 6.9 s; 93 / 3 (46 before them) | 41.0 / 11.2 s; 59 / 6 (the rest before them) |
| The same of `rw-c` (x86_64), ripgrep (arm64) | 0.31 / 0.26 s; 3 / 0 (1 before them) | 0.59 / 0.28 s; 3 / 0 (1 before them) |

Same digests before and after in every row, and for `rw-cxx`, `rw-go`, `rw-rs` and `rw-races`
(seeds 1 and 2). Chromium's own plan (x86_64, 167 MB, 2.74 million patches) took 13.2 s on
one thread before: the rewriter's analysis 1.9 s, site selection 2.4, emission 1.9, `cpuid`
sites 1.3, the census 1.2, the verifier 4.0, and the file hashed up to five times and read
twice. Now 4.3 s in the run: selection, emission, the census and the verifier's checks run in
parts; the verifier's decodes run while the plan is made; the file is read and hashed once.
What stays on one thread is the analysis's control-flow descent (about 1.2 s) and patch
placement (0.4 s). A sweep made each plan once per run before (each run pinned to one CPU);
it now makes the programs' plans once on its job count before the runs start, and a file a
run meets later (a `dlopen`) is made by the first run to meet it while the others wait for it
(`rewrite/02-points` f).

Byte identity: Chromium's plan on 8 threads, on one, and from the build before are the same
bytes but for the build string in the header (x86_64 here; arm64's 282 MB headless shell on
the runner with 4 threads and one, and here); `rewrite/01-differential` plans every guest on 8
threads and on one and compares. Red/green: accepting a part's speculative choice without
checking the patches before it fails `01-differential` (`rw-c`'s two plans differ); without
the entry lock `02-points` f fails (the two runs do not wait); without the sweep's planning
first, its runs make plans.

### Walks: switches inside straight-line code

`--preempt points` switches only at its sites (backward branches and calls, indirect jumps,
atomics), so a window between two plain accesses with none of those in it (a counter loaded,
changed and stored) never holds a switch. Two ways to reach it were measured on x86_64 (the
host above) and arm64 (`ubuntu-24.04-arm`, Neoverse N2), 2026-11-19: a *walk* (a switch taken
a drawn number of instructions past its site, single-stepped: landed, ARCHITECTURE
"Load-time rewriting") and *every-block* sites (a site at every forward conditional branch
too: measured from a prototype, not landed). The guests: `races b` and `examples/stats-c`
stock, the Go and Rust check-then-act races (`go-race-stock`, `rs-race-stock`), and three new
stock C races (`tests/guests/rewrite/races.c`): `lms` (load, add, store through a pointer),
`publish` (a pointer published before the struct is filled in) and `dcl` (a flag set one store
before the data). Each cell is finds of 200 seeds and, in brackets, the CPU seconds of the
seeds up to the first find, x86_64 / arm64 (every-block: x86_64 only).

| Guest | points | points + walks | points + walks, W=16 | every-block |
|---|---|---|---|---|
| default gap (64 to 65,536): `lms` | 0 / 0 | 21 (0.17) / 15 (0.07) | | 0 |
| `stats-c` | 0 / 0 | 0 / 1 (2.6) | | 0 |
| `go-race-stock` | 2 (0.58) / 1 (5.1) | 0 / 1 (5.3) | | 4 (0.79) |
| `races b`, `rs-race-stock`, `publish`, `dcl` | 0 / 0 | 0 / 0 | | 0 |
| `compute-gap=2..64`: `lms` | 0 / 0 | 104 (0.25) / 101 (0.25) | 192 (0.03) / 175 (0.03) | 0 |
| `stats-c` | 0 / 0 | 2 (55.5) / 1 (23.4) | 8 (33.1) / 4 (52.1) | 0 |
| `go-race-stock` | 81 (0.15) / 76 (0.13) | 70 (0.40) / 73 (0.04) | 76 (0.25) / 68 (0.67) | 112 (0.27) |
| `rs-race-stock` | 5 (0.26) / 5 (1.1) | 4 (5.2) / 7 (1.5) | 6 (1.3) / 5 (2.0) | 5 (6.3) |
| `races b` | 0 / 0 | 0 / 0 | 1 (3.9) / 0 | 11 (0.37) |
| `publish`, `dcl` | 0 / 0 | 0 / 0 | 0 / 0 | 0 |

Walks reach what nothing else stock does: `lms`'s window is two instructions with no site
(and the store a few instructions after the nearest one), found on half the seeds at small
gaps and on 1 in 10 at the default; `stats-c`'s, further from a site, rarely. They cost the
atomic races a little (a switch walked past the atomic's window): `go-race-stock` 81 to 70 and
76 to 73. Every-block sites reach `races b` (its window holds a forward branch), which walks
do not, but they double the points (and every plan changes), cost 1.1 to 2.6 times the corpus
wall time, and find nothing in `lms`; with walks (an earlier walk at a higher rate, x86_64)
they found `lms` 198, `go-race-stock` 103 and `races b` 7 of 200. `publish` and `dcl` were
found by no mechanism here (their windows end in another thread's spin or a lock, which the
seed seldom puts there); the default walk is 2 in W switches walking up to W instructions,
W drawn from 4 to 512 per seed.

The cost (warm plan cache, wall ms of seeds 1 and 2, x86_64 / arm64; seed 2 draws a small
gap, so it is the point-heavy case):

| Program | traps | points | points + walks |
|---|---|---|---|
| ripgrep | 388, 366 / 738, 739 | 406, 1,114 / 818, 1,579 | 396, 1,479 / 817, 2,082 |
| gofmt | 1,058, 849 / 1,282, 1,262 | 1,113, 26,962 / 1,687, 18,364 | 1,074, 39,631 / 1,798, 26,298 |
| CPython | 91, 85 / 199, 198 | 139, 4,382 / 245, 1,934 | 144, 7,133 / 249, 2,876 |
| headless Chromium | 641, 574 / 1,386, 1,402 | 934, 3,321 / 1,760, 4,357 | 945, 4,726 / 1,772, 5,390 |

Walks add about one single-step per switch (a walk of `1..=W` on 2 switches in W): at seed 1
nothing measurable, at seed 2 1.2 to 1.6 times the points run (a step is a debug trap, 6.5
µs on this KVM host). Every run's output is the native one; seed 1 twice gives one digest on
both architectures.

| Check | Result |
|---|---|
| Determinism (`05-walks` b, both architectures): `verify --runs 3 --vary cpu,load,aslr,sandbox,repeat` of `lms` with walks, and of the C, C++, Rust and Go differential guests with hundreds of walks each; `patina replay` of the Go run | identical |
| Fidelity (`05-walks` c, both): a fault in a relocated atomic reached by walks from its count, a timer signal in a spin, fork and exec, system calls in a loop and a read that blocks (walks run into both and end there), `pushf`/`popf` (x86_64) | output as natively; walks taken in each, and cut by the fault and the system calls |
| Red: the x86_64 walk without its stop before `pushf` | `rw-races flags` killed by `SIGTRAP` on 4 of 4 seeds (a saved trap flag restored by `popf` after the walk) |
| Red: arm64 walks counting the whole span from an image's first trampoline to its last (Chromium has trampolines before and after its image) | a Chromium thread stepped for 10 s, `compute-stall`; walks now count only the mapped trampoline runs |
| Every run without `--preempt points` (the 90 cells of the stock workload ledger) | identical to the build before, on both architectures |
| With `--preempt points` | digests differ from the build before (walks change the schedule); with `--fault compute-walk=0` they are the build before's (`go-race-stock`, seed 3, x86_64) |

The 2 plans headless Chromium dropped on arm64 (the arm64 corpus table above) were both the
executable's own, once in each process that starts V8. V8 moves its embedded builtins (2.1
MiB of the executable's text) into its code range with `mremap(MREMAP_MAYMOVE | MREMAP_FIXED
| MREMAP_DONTUNMAP)`, so that its generated code reaches them with short branches. A move of
patched pages dropped the image's plan (the original pages went back first, so the moved copy
was the original code), and the rest of the executable had no points for the rest of the
process. Since, a change puts back only the patched pages it touches (ARCHITECTURE
"Load-time rewriting", "Changes"; on x86_64 grown to whole patches) and the rest keeps its
points. Headless Chromium on arm64 (`ubuntu-24.04-arm`, points with walks, warm plans; the
build before → after; the x86_64 Chromium moves nothing: 0 dropped, 0 restored in both):

| Seed | Plans dropped | Changes that put back part of a plan | Points taken | Wall ms |
|---|---|---|---|---|
| 1 | 2 → 0 | 0 → 2 | 145 → 200 | 1,611 → 1,647 |
| 2 | 2 → 0 | 0 → 2 | 32,313 → 35,462 | 3,058 → 3,232 |
| 3 | 2 → 0 | 0 → 2 | 34,708 → 35,476 | 2,814 → 2,874 |
| 4 | 2 → 0 | 0 → 2 | 264 → 388 | 1,594 → 1,648 |
| 5 | 2 → 0 | 0 → 2 | 15,789 → 19,123 | 2,404 → 2,685 |

Output is native in every run; `verify --vary cpu,load,aslr,sandbox,repeat` of seed 2 is
identical. Seeds 2 and 3 are held near the switch budget, so they gain fewer points.
`rewrite/06-textmove` (a static guest that moves one page of its text with the same `mremap`
flags, makes one page read-only and back, unmaps it, or unmaps it and maps it again from the
file, then computes in two threads) checks the native output, that part of the plan was put
back and none dropped, a point taken after the change in a page it did not touch (in the page
mapped again, for the last), and `--vary` identity, on both architectures. Red: with the range
marked but not mapped back, the moved copy (still patched, its jumps aimed at trampolines it
does not reach) dies of `SIGSEGV`, and `04-interior` d and `03-fidelity` e fail too.

### The cost of a point

Measured 2026-11-19 on the x86_64 host above (a KVM guest on a Ryzen 9 9950X, 24 CPUs) and on
GitHub `ubuntu-24.04-arm` runners (Neoverse N2, 4 CPUs), with the corpus programs above. `perf`
is not open to unprivileged users on the x86_64 host (`perf_event_paranoid` 4, left as it is),
so the profile is from `getrusage`, `strace -c`, the run's own counts and microbenchmarks.

**Before.** At seed 2 (mean gap 248 events), x86_64, warm plans:

| Program | Wall | Points taken | Threads |
|---|---|---|---|
| gofmt | 40.2 s (stock under Patina 0.9 s) | 1,376,266 | 1.02 million switches: 74% of points switched |
| CPython | 7.2 s (0.09 s) | 249,088 | one thread: 25 switches, every point a hand-over that picked the same thread |
| ripgrep | 1.5 s (0.36 s) | 35,392 | one thread |
| headless Chromium | 4.6 s (0.54 s) | 122,271 | 89,000 switches |

Where it went (CPython, seed 2): 7.35 s with walks, 6.06 s of it system time; 4.48 s with
`compute-walk=0`, so about 17 µs a point and 11 µs a walk's step. Each point was a trap (a
`SIGILL` at `ud2`), a `preempt` record, a `Yield` to the supervisor and its decision: 4 futex
calls, 2 clock reads by the supervisor, a `rt_sigreturn`, an `rt_sigpending` and about 2
context switches. A trap of each kind, in a loop (a microbenchmark not in the repository, µs a
round trip):

| Host | `ud2` (`SIGILL`) | `int3` | `hlt` (`SIGSEGV`) | trap-flag step | futex ping-pong, one CPU |
|---|---|---|---|---|---|
| x86_64, this KVM host (AMD) | 5.5 to 5.8 | 0.62 to 0.66 | 0.65 to 0.69 | 6.4 | 1.3 |
| x86_64, GitHub runner (EPYC 7763) | 2.83 | 2.86 | 3.05 | 3.85 | 6.1 |
| arm64, GitHub runner (Neoverse N2) | `udf` 1.28 | `brk` 1.24 | | | 2.25 |

KVM on AMD intercepts the invalid-opcode and debug exceptions, so `ud2` and the trap flag cost
about 9 times `int3` or `hlt` there; elsewhere the trap kinds cost about the same.

**What changed** (ARCHITECTURE "Compute points"): points that cannot switch are not taken (a
thread alone arms to its next deadline; points whose draw keeps the thread are passed, counted
`stays`); with the gap drawn by default, a run past 32,768 switches plus one per 8,192 events
draws its gaps with a mean of at least 8,192; the x86_64 trampoline traps with `hlt`.

**After.** Wall ms of seeds 1 to 5 (mean gaps 64,514, 248, 115, 34,864 and 514), warm plans,
points with walks at the default settings. Traps and after: the least of 3 runs; before: one
run of the build before (main at the sandbox landing). Points taken before → after:

| Program | Seed | x86_64: traps / before / after (after ÷ traps) | points | arm64: traps / before / after (after ÷ traps) | points |
|---|---|---|---|---|---|
| ripgrep | 1 | 316 / 376 / 312 (1.0) | 88 → 76 | 737 / 860 / 809 (1.1) | 144 → 107 |
| | 2 | 302 / 1,564 / 459 (1.5) | 35,392 → 10,015 | 741 / 2,196 / 1,037 (1.4) | 60,136 → 9,267 |
| | 3 | 300 / 2,642 / 553 (1.8) | 80,540 → 17,162 | 743 / 3,674 / 1,133 (1.5) | 133,258 → 14,808 |
| | 4 | 300 / 388 / 325 (1.1) | 177 → 119 | 739 / 852 / 804 (1.1) | 279 → 180 |
| | 5 | 315 / 897 / 415 (1.3) | 16,140 → 5,870 | 730 / 1,494 / 966 (1.3) | 27,957 → 6,026 |
| CPython | 1 | 87 / 148 / 115 (1.3) | 949 → 68 | 197 / 250 / 242 (1.2) | 457 → 57 |
| | 2 | 85 / 7,228 / 122 (1.4) | 249,088 → 305 | 198 / 3,052 / 257 (1.3) | 130,920 → 602 |
| | 3 | 86 / 14,682 / 122 (1.4) | 537,588 → 374 | 196 / 6,347 / 259 (1.3) | 281,711 → 788 |
| | 4 | 88 / 186 / 115 (1.3) | 1,738 → 74 | 196 / 270 / 241 (1.2) | 908 → 80 |
| | 5 | 84 / 3,386 / 125 (1.5) | 119,797 → 247 | 197 / 1,563 / 248 (1.3) | 62,740 → 419 |
| headless Chromium | 1 | 518 / 899 / 937 (1.8) | 350 → 214 | 1,190 / 1,563 / 1,548 (1.3) | 150 → 145 |
| | 2 | 538 / 4,588 / 1,656 (3.1) | 122,271 → 36,635 | 1,222 / 3,816 / 3,038 (2.5) | 60,185 → 32,313 |
| | 3 | 531 / 8,841 / 1,606 (3.0) | 266,984 → 36,632 | 1,185 / 6,002 / 2,791 (2.4) | 132,510 → 34,708 |
| | 4 | 531 / 894 / 951 (1.8) | 678 → 397 | 1,228 / 1,573 / 1,597 (1.3) | 291 → 264 |
| | 5 | 523 / 2,607 / 1,301 (2.5) | 57,925 → 18,967 | 1,222 / 2,697 / 2,340 (1.9) | 27,928 → 15,789 |
| gofmt | 1 | 1,037 / 1,373 / 1,003 (1.0) | 5,855 → 5,435 | 1,286 / 1,834 / 1,755 (1.4) | 5,228 → 4,462 |
| | 2 | 897 / 40,843 / 2,034 (2.3) | 1,376,266 → 74,885 | 1,259 / 27,453 / 3,204 (2.5) | 1,158,055 → 67,474 |
| | 3 | 1,110 / 83,083 / 2,015 (1.8) | 2,974,420 → 75,374 | 1,195 / 57,147 / 3,141 (2.6) | 2,480,834 → 67,754 |
| | 4 | 1,208 / 1,238 / 1,081 (0.9) | 10,012 → 8,214 | 1,252 / 1,859 / 1,880 (1.5) | 8,776 → 7,387 |
| | 5 | 960 / 20,169 / 2,024 (2.1) | 670,735 → 74,333 | 1,224 / 14,191 / 3,275 (2.7) | 555,653 → 67,689 |

The x86_64 "before" column is the walks build (main before the sandbox landing), whose
traps-mode runs took 360 to 380 ms for ripgrep, 85 to 92 for CPython, 532 to 568 for Chromium
and 900 to 1,210 for gofmt. The costliest seeds are Chromium's at small gaps, about 3 times
its traps-mode run on x86_64: its threads are in different processes, and a switch between
them costs about 30 µs with its walk. Chromium's 1.7 to 1.8 at the large gaps is the plans
themselves (the same before). ripgrep's points are switches with no runnable count: it emulates
`rdtsc` and serves calls in the runtime between hand-overs, and the runtime then draws one gap
as before (ARCHITECTURE).

Without the budget (alone and stays only), gofmt at seed 2 took 16.6 s on x86_64; with the
allowance at 65,536 and one switch per 4,096 events, 3.5 s. The allowance is set above the
points any race guest below takes at the default gap (the most: 3,751).

**Finds** (the walks table's guests, 200 seeds each, points with walks; before → after):

| Guest | x86_64 default gap | x86_64 `compute-gap=2..64` | arm64 default gap | arm64 `compute-gap=2..64` |
|---|---|---|---|---|
| `lms` | 21 → 16 | 106 → 109 | 15 → 15 | 101 → 105 |
| `stats-c` | 0 → 1 | 2 → 3 | 1 → 0 | 1 → 2 |
| `go-race-stock` | 0 → 2 | 70 → 74 | 1 → 4 | 73 → 91 |
| `rs-race-stock` | 0 → 0 | 7 → 3 | 0 → 0 | 7 → 4 |
| `races b`, `publish`, `dcl` | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| total | 206 → 208 | | 199 → 221 | |

No run of these guests reaches the budget (a gap the plan names is exempt from it), so the
differences are the schedules the stays draw. Over 4,000 seeds on x86_64, `lms` at the
default gap was found 357 times before and 336 after (p about 0.4), and `rs-race-stock` at
`2..64` 110 and 90 (p about 0.16): within chance, though `rs-race-stock` is lower on both
architectures. These rates were measured with the allowance at 32,768 and one switch per
4,096 events; the final constants (one per 8,192) change nothing below the allowance.

**Digests.** Without `--preempt points` every digest is unchanged: the 90 cells of the stock
workload ledger and 45 cells of compute-point guests (rebuilt code, with and without
`compute-gap=8`) are identical to main on x86_64 (both builds on one guest set) and on arm64
(a CI job). With it, digests change (fewer records, other schedules). `verify --vary
cpu,load,aslr,sandbox,repeat`: gofmt seed 2 (the budget engaged) and Chromium seed 3
identical on both architectures; the release tier's `rewrite/02-points` and `05-walks` cover the
C, C++, Rust and Go guests and `patina replay`.

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

## Branch counters under host load

Measured 2026-11-20 on the KVM guest (Linux 7.0, `perf_event_max_sample_rate` 6,000 at HZ
1,000: the kernel had lowered it from 100,000 after interrupts that took long, so it throttles
an event after 6 overflow interrupts in a tick). Each run is one N = 3,000 counter run of a
`tests/guests/counters/compute` program compared with its hops-only run (`05-exact`'s method;
8 runs at a time); load is busy loops started for the batch, the host's own load average was
2 to 10 besides. No bare-metal host was measured.

**Before** (the overflow entry had 3 conditional branches before its `rdpmc`; pmu-margin 512):

| Condition | Runs | Differ | Overshoot (fail closed) |
|---|---|---|---|
| quiet, load 1.5 | 200 | 2 | 4 |
| 16 busy loops at nice 19, load 6.4 | 200 | 1 | 0 |
| 24 busy loops at nice 0, load 13 | 200 | 0 | 0 |

Every difference was a stop exactly 3 branches late, at the same place in each (the first
preemption, in `ld.so`), so a run that differed gave the same wrong digest each time. A
scratch build that counted overflows whose counter had not moved since the interrupt found 5
in 400 runs and 10 in 600, each such run's stop 3 branches late. The cause: while a segment's
short period was left armed during runtime work, the runtime's own branches overflowed it
more than 6 times in a tick; the kernel throttled the event, stopping the counter at the next
overflow until its next tick, but still sent the signal, so the handler's first 3 branches
went uncounted. The arm64 runner's twice-repeated wrong digest (`05`, 3000-recur) fits the
same cause (2 branches before the read there) but was not reproduced: on the runners below
the rate stayed at 40,000 or more, no overflow found its counter stopped, and 440 runs of
the old build gave no difference.

Late interrupts, the other failure, are not load: branches from the programmed overflow to
the interrupted instruction, the largest per run: median 142 to 195 and 99th percentile 465
to 514 over batches with no added load, lower with busy loops on other CPUs (median 83 to
142, 99th percentile 242 to 324); the largest seen 704, with the runs on one CPU shared with
4 busy loops. The late ones come at the same instructions run after run (in `recur`, the
page faults that grow the stack): the interrupt waits for the next exit to the hypervisor.

**After** (no branch before the read, and the period programmed again at every overflow,
the long one while hopping):

| Condition | Runs | Equal | `pmu-late` | Overflows found stopped |
|---|---|---|---|---|
| margin 1024, four programs, no added load | 200 | 200 | 0 | 0 |
| the same, 16 loops at nice 10 | 200 | 200 | 0 | 0 |
| the same, runs pinned to one CPU with 4 loops on it | 200 | 200 | 0 | 0 |
| the same, 24 loops at nice 0, load 20 | 200 | 200 | 0 | 0 |
| margin 1024, `recur`, no added load | 1,000 | 1,000 | 0 | 0 |
| the same, 16 loops at nice 10, load 23 | 1,000 | 1,000 | 0 | 0 |
| the same, pinned to one CPU with 4 loops on it | 400 | 400 | 0 | 0 |
| margin 512, `recur`, no added load | 1,000 | 983 | 17 | 0 |
| bursts (N = 2,100), no added load | 200 | 200 | 0 | 8,264 |
| bursts, 16 loops at nice 10 | 200 | 200 | 0 | 10 |

`bursts` (an overflow every few microseconds) is where throttling happens now; fewer are found
stopped under load, as each switch of the CPU restarts the counter. At margin 512 the 17
late runs ended `internal`, stop `pmu-late`, 3 to 152 branches past the stop; the default and
the scripts' counter margin is 1,024.

arm64 (GitHub `ubuntu-24.04-arm`, Neoverse N2, `perf_event_max_sample_rate` 100,000 falling
to 40,000 during the job; one job per build, 4 runs at a time, "loaded" is 4 busy loops at
nice 10): `counters` passes with the change, with no overflow found stopped in `05` and
`08-load`, bursts included. Late interrupts happen there too, later than on x86_64:

| `recur`, N = 3,000 | Before | After |
|---|---|---|
| margin 512 | 118/120 equal, 2 overshoot (178 and 1,374 past the stop) | 118/120 equal, 2 `pmu-late` (127 and 513 past) |
| margin 1024 | 120/120 equal | 119/120 equal, 1 `pmu-late` (812 past: 1,836 after the overflow) |
| margin 1024, loaded | 120/120 equal | 120/120 equal |
| bursts, quiet and loaded | 80/80 equal | 80/80 equal, 0 stopped |

Red/green: with the old entry planted back (3 branches before the read, subtracted as
before), `05-exact` and `08-load` fail on bursts (the first differing record printed:
`preempt` at the same instruction with other registers: another pass of the loop, at record
304 and 625), and
pass with the change. On arm64 a planted branch before the read changed nothing on the runner:
no overflow was throttled there. The arm64 cost: with no branch before the read, every
SIGTRAP makes the read, a hop's breakpoint included (a failing `read()` there); `06-migrate`
took 149 s against 138 s before on the runner.

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
| Instruction scan, x86_64, of a stripped 170 MB text (headless Chromium, `--dump-dom` of a small page: 4 processes map it) | sweeps from the symbols alone 373 ms per mapping, the run 2.04 s; with the `.eh_frame_hdr` function starts too 54 ms, the run 0.77 s (2026-11-19). Verdicts of the two rules on every candidate of 3,405 x86_64 ELF files of this host (`/usr`, the toolchains, the guest set, Chromium; 18,239 candidates): identical; the guest ledger's 90 digests: identical |
| The same, each read-only file's mapping scanned once per run (verdicts kept for the other processes) | Chromium's run 0.77 s to 0.50 s, its digest and the ledger's identical (2026-11-19) |
| `--preempt branches` | 9.7 µs per trap, 1.7-2.3 ms per preemption, W1-W9 wall x0.6 to x6.5 (W1 x6.5, W2 x4.4, the rest under x2); arm64 (runner): 1.3 µs per trap, 2.6-3.4 ms per preemption, W1-W9 x0.66 to x2.0 |
| `--mount DIR:/guest:copy` copy into tmpfs | ~0.3 ms per MB |

## Known limits

Not implemented (run ends `unsupported` or the call is refused): `timer_create`,
`ITIMER_VIRTUAL`/`ITIMER_PROF`; System V semaphores and message queues and POSIX message
queues (`ENOSYS`); raw, netlink and packet sockets, UDP multicast and broadcast;
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
  `RLIMIT_NOFILE` is not enforced (`EMFILE` at the real limit: 4,027 descriptors of the
  program, the shadow stores holding the top 64). A launcher `RLIMIT_FSIZE` below the
  boundary log's size kills `patina` with no outcome.
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
- System V shared memory: permission bits are kept but not checked; `SHM_STAT`, `IPC_INFO` and
  `SHM_INFO` answer `EINVAL`; an `munmap` of part of an attachment does not end it; `shmat` in a
  vfork child ends the run.
- signalfd: the mask belongs to the process (a mask update through one process is not seen by
  another holding the same file); its `/proc/self/fd` link and `fdinfo` are an eventfd's; more
  than 7 signalfds kept open across one `execve` end the run.
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
  test hook corrupts keeps its outcome (`ok`; `violation` with its label and signature for
  `mapends violation`) and reports `self_check` `fail` with exit status 2; red/green: without
  the end-of-run check its `self_check` is absent and it exits 0 (1 for the violation).
- **Shared mappings at a process's end** (`tests/faults/18-mapends.sh`; 2026-11-19): a
  store through a `MAP_SHARED` work-file mapping (two pages and a partial one), then its
  process killed by `SIGKILL` (one that made the mapping, and one that inherited it by fork)
  or `SIGTERM`, left running at the end of the run, killed by its own vfork child, or the run
  ended by a violation (with and without `msync` first), the time limit, `munmap` or `exit`,
  or a `MAP_FIXED` mapping made over it: with no crash plane, `--crash machine` and `--crash
  process`, each ends as it should, its self-check passes, `patina log ops --check` passes,
  and the file reads as natively; branch sweeps of seeds 1..2 (every crash point) of the
  durability case (child stores and is killed, parent fsyncs the file and the directory, then
  a synced marker), of kill, the inherited mapping, vfork and orphan, and of the `MAP_FIXED`
  case (a flush of two records, cut between them by a crash point) under both crash kinds: no
  finding. Red/green: on the build before (main at `9196aa8b`) every mode but `msync`,
  `unmap`, `exit` and the inherited mapping (its parent's exit logs the child's stores too)
  fails `log ops --check` and ends `internal` under either crash plane (the violation and the
  liveness lost), and the durability sweep has 1 violation (`synced-store-kept`: the fsynced
  store lost) and 2 `internal` of 28 runs. The issue's own durability reproducer, seeds 1..3,
  `--branch --crash machine`: 94 failures and 3 `internal` of 222 runs before, 222 `ok` after.
  An `mremap` of the mapping's second page, then a store through it, now ends the run
  `unsupported`; before, the runtime faulted (`internal`, signal 11).
- **Shared mappings of two processes** (`tests/faults/19-mapshare.sh`): a store undone by
  another process's store (the first ended by exit or `SIGKILL`), two processes storing in turn,
  a store then another process's `pwrite` or `writev` on the page and a `pwrite` then a store, a
  truncation and extension under another's mapping, and 100 files mapped one after another: with
  no crash plane, `--crash machine` and `--crash process`, each ends `ok`, its self-check
  passes, `patina log ops --check` passes, and the file reads as natively. Branch sweeps (every
  crash point) under machine crashes: the store-then-`pwrite` case, seeds 1..20, never keeps the
  write without the stores; a store fsynced by another process before a synced marker, seeds
  1..2, always keeps it and loses a later unsynced one after some crash, and so does a store to
  the second page synced with `sync(2)` by a process mapping only the first. 65 files mapped at
  once end `unsupported`, stop `capacity`. Red/green: on the build before (main at `f516828f`)
  every mode of the first list but the store-then-write ones fails the self-check and `log ops
  --check` under both crash planes, and the fsync sweep has a violation (`synced-store-kept`).
  Without the flush before a write, the store-then-`pwrite` case keeps the write without the
  stores at 10 of 60 seeds; comparing only the caller's mapped range at `sync`, the `sync(2)`
  sweep loses the synced store (`synced-store-kept`, seed 2@12). `shadow_bytes`
  (`tests/files/12-sparsemap.sh`): 12 KiB for a 1 GiB sparse file with two pages written through
  a 2 GiB mapping, 4 KiB for a 1 GiB file mapped 48 times one after another. The x86_64 digest
  ledger (90 cells) is unchanged.
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

## Several machines

Nodes (`[node.NAME]`, GUIDE "Several machines"), measured 2026-11-19 on the host above and on
a GitHub `ubuntu-24.04-arm` runner.

**Runs without nodes are unchanged.** The digest ledger (90 cells: 15 guests and workloads,
seeds 1-3, faults off and `--faults all`) of the commit before nodes and of the commit with
them, on one guest set: identical on x86_64 (the host) and on arm64 (the runner, one run from
a throwaway branch, both builds on the runner). On each, the `--faults all` cells that end
`failure` or `liveness` (`sockets`, `shell`, `fork-exec`) end so in both builds.

**Isolation** (`tests/nodes/01-isolation.sh`, a driver and node `b`): each node has its own
hostname, work tree, `/tmp`, `/dev/shm`, System V shared memory and loopback; addresses are
`10.0.0.1` and `10.0.0.2` at both ends of a connection; `b`'s first process inherits the
driver's process state and has `PATINA_NODE=b`; `b`'s processes are `ESRCH` to the driver's
`kill` and absent from its `/proc`; `b`'s control call is `EPERM`, from Python and from C;
abstract `AF_UNIX` names are refused; `b` cannot change its view (`sethostname` is `EPERM`); a
connect across a cut does not complete, and after the heal it does. `verify`: 3 identical
runs. Crash, network faults, `restart` and the names `driver`, `rest` and `localhost` are
refused before the run, each named.

**A replicated store with a planted bug** (`tests/nodes/02-kv.sh`, `tests/guests/nodes/kv.py`):
a primary node that replicates every `SET` to a backup node before answering, and a driver that
writes three keys, cuts primary from backup, writes a fourth (the `SET` waits; the backup is
behind), heals, and checks both converge. Correct: `ok` on seeds 1-4 with 4 distinct
schedules; `verify` 3 identical runs. The planted bug (the primary answers before the backup
applies, which applies in batches): a stale read from the backup in 8 of seeds 1-8; seed 1
replays identically.

**PostgreSQL 18.7** (built from the release tarball, `--without-icu --without-readline`): node
`primary` and node `standby` (a streaming replica with `synchronous_standby_names`), each
started from its own copy of a data directory; the driver, a bash script, uses `psql` across
the node names and `patina ctl`.

| Step | What the driver saw |
|---|---|
| boot | `pg_stat_replication`: `standby`, `10.0.0.3`, `sync` |
| insert row 1 | the standby has row 1 |
| `patina ctl net cut primary standby`, insert row 2 | after 5 s the commit is still waiting (`SyncRep`, 1 backend); the standby has row 1 only; primary at `0/30055E0`, standby replayed `0/3005530` |
| `patina ctl net heal` | the commit returns; the standby has rows 1 and 2; both at the same position |

Seed 1 twice: digest `9d2872311dda6eb0` both times; `verify` (cpu, load, aslr, sandbox,
repeat): 3 identical runs; `replay` identical; seed 2: `60112f64f8c7c961`. About 0.4 s of
wall time per run (the cut's 5 s are virtual).

### Killing and restarting nodes

Measured 2026-11-20 on the same host and runner.

**Runs without nodes are unchanged.** The same 90-cell ledger, built at the commit before
kill and restart and at the commit with them: identical on x86_64 and on arm64.

**Kill and restart by the script** (`tests/nodes/05-kill.sh`, `tests/guests/nodes/kill.py`): 50
cycles of `node kill b --process` and `node start b`. Each kill ends both of `b`'s connections
(its first process's and a forked child's), connects to either port are refused while `b` is
down, a second kill and a start of a running node answer `EALREADY`, and each restart finds the
work tree the last left and its own `PATINA_INCARNATION`: 51 incarnations, one
`node/b/inc-K/` each, 50 `kill` and 50 restarting `start` events. `verify` (10 cycles): 3
identical runs. About 0.7 s of wall time for the 50 cycles. A node's own end: an exit outside
`ok-exit` ends the run `failure` and a `SIGSEGV` ends it `crash`, both naming the node; with
`ok-exit = 3`, `restart = "always"`, `max-incarnations = 3` and `count = 2`, nodes `w1` and
`w2` each print incarnations 0, 1 and 2.

**The quorum store under the seed's kills** (`tests/quorum/03-quorum-kills.sh`, the three-node
store of `01-quorum.sh` with `--crash process`, `crash-gap-ms=2000..10000`,
`down-ms=500..3000` beside the partitions): correct, seeds 1-16 with a 40 s driver: 16 ok, 16
distinct digests, 91 partitions, 144 kills and 144 restarts; `verify` of seeds 4 and 11 under
`--vary cpu,load,aslr,sandbox,repeat`: 4 identical runs each. The planted bug `amnesia` (a node
acknowledges a write before it is on its disk, so a kill and restart lose it): `failure` in
12 of seeds 1-16 and 20 of seeds 9-32; the sweep's replay of the group and an explicit
`replay` of another failing seed are identical. In CI the script takes 44-55 s of its 90 s
budget.

### Node disks and machine crashes

Measured 2026-11-20 on the same host and runner.

**Runs without nodes are unchanged.** The 90-cell ledger, built at the commit before node disks
and at each of the two commits that add them (disks and machine crashes; disk and memory faults
per node): identical on x86_64 and on arm64, no cell without a result.

**A machine crash by the script** (`tests/nodes/09-machine.sh`, `tests/guests/nodes/disk.py`):
every fsynced write kept, node b's unsynced write untouched by a's crashes, an established
connection silent until the restart and then reset at its next send, a connect while down timed
out; the unsynced write lost in some crashes and kept in others, as the seed draws. `verify`
of seed 4 (3 crashes) under `--vary cpu,load,aslr,sandbox,repeat`: 6 identical runs; `replay`
identical. Planted breaks, each red then green with the fix: the shadow table keyed by inode
alone (four nodes storing through shared mappings: the self-check fails on 4 of 4 seeds);
the wrong node's tree reverted at a crash (`disk.py` reports a lost fsynced write).

**Under the seed's crashes** (each with `--crash machine`, `down-ms=100..300` or `200..1000`):

| Workload | Correct | Planted bug |
|---|---|---|
| `q3.py` (three nodes, partitions beside the crashes, `crash-gap-ms=1000..4000`, 40 s) | ok on seeds 1-8, every node crashed in each run (72 crashes), self-check passed in all | `nosync` (answer before syncing): an acknowledged write lost in 7 of seeds 1-8 |
| `wal.py` (one node appending checksummed records, `crash-gap-ms=300..1500`, 12 boots) | ok on seeds 1-100, 1,100 crashes, a torn tail cut off in some boots | `nocheck` (recovery trusts each record's length): a record no node wrote, in 75 of seeds 1-100 |
| `ack-log` as a node with `fsync-error-permille=1` (`crash-gap-ms=1..4`, 8 boots) | ok on seeds 1-100 (268 crashes; restarted after it stops at an fsync error) | `retry` (retry a failed fsync, then acknowledge): an acknowledged record lost in 88 of seeds 1-100 |

Every failing group's first run replayed identically. `verify` of `q3.py` seed 2 with crashes
and partitions: 4 identical runs under the same `--vary`.

**Disk faults per node** (`tests/nodes/12-disk-faults.sh`): an unscoped `fsync-error-permille`
fails fsyncs on nodes a and b and never the driver's; `@a,driver` on a and the driver only;
`[node.b.faults]` on b only.

### PostgreSQL 18: failover under partitions and kills

PostgreSQL 18.7, built from the release tarball (`--without-icu --without-readline`), no
changes. Nodes `pg1` (primary) and `pg2` (a streaming standby of `pg1`,
`synchronous_standby_names = '*'`, `synchronous_commit = on`), each from its own copy of a
data directory made natively (`initdb`, then `pg_basebackup`). Each node's command is a small
agent: at its first start it starts its server as the data directory says; restarted, it
starts nothing and waits for the driver to say what it is. The driver (Python, libpq over
`ctypes`) is the clients, the health checker and the failover manager:

- three clients keep a connection open over `host=pg1,pg2` with
  `target_session_attrs=read-write` and commit two-row transactions for 30 s of virtual time;
- each second the driver asks the primary `select pg_is_in_recovery()`, and asks the standby
  whether its WAL receiver is streaming (a standby that answers but does not stream counts
  as a failure: the network between the two is faulted); two failures in a row fail over to
  the standby if it answers as one: fence the old primary (`node kill OLD --process`, the
  power switch), `pg_promote()`, `node start OLD`, and tell its agent to rejoin;
- a rejoining node that was a standby starts as it was; one that was a primary is rewound
  from the new primary with `pg_rewind` (a fresh `pg_basebackup` if that fails, since a
  failed rewind leaves the data directory unusable) and starts as its standby;
- after 30 s the clients stop and the driver settles: both nodes up, the standby replayed
  up to the primary's position, no commit waiting for it, then both nodes' contents.

Faults, after setup (`faults-after-setup=1`): `--faults net` with resets off and chunks of
1448 to 65536 bytes; partitions every 5-30 s for 1-8 s; `--crash process` (`crash-gap-ms`
10-60 s, `down-ms` 1-5 s, at most 3 kills a node). Each node's tmpfs is 1 GiB. The driver is
never faulted: partitions and link faults act between `pg1` and `pg2`. An outside checker
judges each run:

| Oracle | Fails when |
|---|---|
| acked-lost | a commit acknowledged without a warning is missing on the final primary |
| split-brain | a node acknowledged a commit sent after the other's promotion was decided, while no longer the harness's primary |
| two-primaries | both nodes accept writes at the end |
| divergence | the standby caught up, yet its rows differ from the primary's |
| partial-txn, phantom | a transaction with one row, or one no client attempted |
| not-settled | no settled moment within 120 s of virtual time |

Each failover's cause comes from the run's events: `kill` (the old primary was down after the
seed's kill) or `standby-view` (it was up; the standby had stopped streaming from it).

| Sweep (seeds) | Failovers | Findings |
|---|---|---|
| synchronous, fenced (1-300) | none 160 runs, kill 105, standby-view 26, several 9 (119 kill, 30 standby-view) | 1 not-settled; 0 of 118,957 acknowledged commits lost; no split-brain, divergence, partial or phantom transaction |
| the same with the primary checked only directly (1-300) | none 180, kill 113, several 7 (all 128 kill) | 1 not-settled; 0 of 120,537 lost |
| control: asynchronous (1-100) | none 59, kill 39, several 2 | acked-lost in 15 runs, 1,869 commits |
| control: no fencing, synchronous (1-100) | none 51, kill 39, standby-view 8, several 2 | two-primaries in 7 runs; no acknowledged commit lost or split, as synchronous replication blocks the old primary's commits |
| control: no fencing, asynchronous (1-100) | none 51, kill 40, standby-view 9 | acked-lost in 22 runs (3,711 commits), 1,371 split-brain acknowledgements, two-primaries in 1 |

The fenced 300 had 448 partitions, 357 kills by the seed and 30 fencing kills, and 387
restarts; 300 distinct digests, about 170 s of wall time at `-j 6`. **Determinism:** the whole
300 run again gave the same digest for every seed, the 140 with a failover included; `verify`
of seeds 4 (kill), 36 (standby-view) and 16 (several) under `--vary
cpu,load,aslr,sandbox,repeat`: 4 identical runs each, with the sweep's digest; `replay` of
seed 16 and of a two-primaries run identical, as was every sweep group's own replay.

**Triage**, in the order harness, Patina, configuration, documented behaviour, PostgreSQL:

- *Harness.* The first agent rewound every rejoining node. `pg_rewind` finishes a crashed
  target's recovery in single-user mode, which refuses standby mode, so the agent removed
  `standby.signal` first; that recovery then ended as a primary's and wrote WAL of its own
  where the primary's next records went, which the standby, restarted, reported as flushed.
  The oracles caught it: in the first 300 seeds, 3 acknowledged commits lost (seed 297) and
  14 divergences. A standby that went down now starts again as it was.
- *Harness.* After that, 11 runs (12 in the final sweep) first read the standby without
  commits the primary had: a hot standby that starts from a running-transactions record
  listing commits that still waited for it treats them as running until the next such record.
  The driver now logs one (`pg_log_standby_snapshot()`) and reads again; the rows are there
  every time. PostgreSQL's hot-standby design, not lost data.
- *Patina.* A control call's `mark` words are recorded as an `sdk` event (`op` `control`), not
  a `mark` event; the GUIDE said otherwise and now says this. `patina sweep --keep fail` kept
  the nodes' output of the runs it pruned; it now removes it with their logs.
- *Configuration.* With the default 256 MiB tmpfs and `wal_keep_size = 256MB`, recovery ran
  out of space (`ENOSPC`); the tmpfs is 1 GiB and `wal_keep_size` 64 MB. The net preset's
  resets (5 to 50 per 1000 chunks) end almost every `pg_basebackup` and `pg_rewind` of the data
  directory, so a rejoin never completes: resets are off. Chunks of a few bytes make a
  settle's large result fill the default 1 GiB log limit (the sweeps allow 2 GiB): chunks are 1448 bytes or more.
- *Not explained:* seed 73, in every synchronous sweep: the old primary's `pg_basebackup`
  from the new one does not finish within the agent's 120 s, so the run never settles. No data
  oracle fails; the run replays identically.

No PostgreSQL bug was found; nothing was filed.

### PostgreSQL on two nodes under machine crashes

Measured 2026-11-20 on the same host, at the commit that adds disk and memory faults per node.

PostgreSQL 18.7 from the release tarball (checksum checked, `--without-icu --without-readline`,
data checksums on, as `initdb` now defaults), no changes. Node `pg1` starts as the primary,
`pg2` as its synchronous standby (`synchronous_standby_names = '*'`), each from its own data
directory and on its own disk, with `fsync`, `full_page_writes` and `wal_log_hints` on. Each
node's first process is an agent that starts again at every boot: it removes the stale
`postmaster.pid` an operator would after a power loss (an empty one, from a crash while the
postmaster wrote it, turned up too), then asks the driver every second what to be: a primary
(crash recovery, then promote if still a standby), a standby of the other (a standby starts as
it was; a former primary is rewound with `pg_rewind`, or rebuilt with `pg_basebackup` when that
fails or a crash cut a rejoin short), or finished (clean stop, `pg_checksums`). The driver is
never faulted. It is the clients (three, over `host=pg1,pg2 target_session_attrs=read-write`,
committing two-row transactions for 30 s of virtual time, every call with a deadline, as a
crashed machine never answers), the health check (each second; two failures in a row fail
over) and the failover manager: fence the old primary with `node kill` (its machine's power),
`pg_promote()`, `node start` it again. Then it settles (both up, the standby streaming and
replayed past a `pg_log_standby_snapshot()` position, no commit waiting) and reads both nodes'
rows, `pg_amcheck --heapallindexed` (the primary also `--parent-check --rootdescend`) and
`pg_checksums`. Faults start after setup (`faults-after-setup=1`); the seed's machine crashes
are `--crash machine --fault crash-gap-ms=5000..20000 --fault down-ms=500..4000`; each node's
tmpfs is 768 MiB. Each sweep: `patina sweep --seeds 1..1700 -j 6 --keep fail --config nodes.toml
--tmpfs-bytes 805306368 --log-limit 2048 --mount PG --mount HARNESS:/g --fault
faults-after-setup=1 --check 'check.py --stats DIR' --env DUR=30 --crash machine --fault
crash-gap-ms=5000..20000 --fault down-ms=500..4000 -- python3 /g/driver.py`, with the scenario
(`--env SCEN=both|churn|rejoin|promote|ckpt`), the synchronous level (`--env SYNC=...`) and the
leg's faults added.

An outside checker judges each run with the oracles of the section above (acked-lost,
split-brain, two-primaries, divergence, partial-txn, phantom, not-settled) and also:
acked-missing (an acknowledged commit missing on the caught-up standby), checksum-fail
(`pg_checksums` finds a bad page), amcheck-fail (`pg_amcheck` exits 2), recovery-failed (a
node's last start failed), no-primary-content. It also records the cause of each failover:
the old primary's machine crash or process kill by the seed in the 6 s before the decision, a
partition (old primary alive), the driver's scenario, or other.

| Sweep (seeds) | Failovers | Findings |
|---|---|---|
| machine crashes, `synchronous_commit = on` (1-1700) | none 480 runs, crash 683, several 537 (1,871) | none; 0 of 939,277 acknowledged commits lost; 842 runs had both nodes down at once; timelines 1-5 |
| the same, `remote_apply` (1-300) | none 94, crash 116, several 90 | none; 0 of 166,919 lost |
| both machines crash within 50 ms (1-300) | 465 | none; 0 of 156,182 lost; both down in every run |
| a standby crashing 3-8 times (1-120) | 80 | none |
| a crash 0-80 ms into a rejoin's `pg_rewind` or `pg_basebackup` (1-120) | 181 | none |
| a crash of the node being promoted, 0-150 ms in (1-120) | 131 | 1 not-settled (below) |
| explicit checkpoints, 40% with a crash 0-6 ms in (1-150) | 120 | none |
| crashes and `--faults net`, partitions every 5-30 s for 1-8 s (1-200) | none 75, crash 94, partition 27, several 3, other 1 | 1 not-settled (below) |
| the same with `net-links=driver` (1-200) | none 62, crash 103, partition 25, several 6, other 4 | 5 no-primary-content, a harness bug (below) |
| process kills, `--faults net`, `net-links=driver` (1-150) | none 33, kill 86, partition 12, several 16, other 3 | none |
| `fsync-error-permille=1..5@pg1` (1-150) | 167 | 0 of 39,377 lost; recovery-failed 93, amcheck-fail 7 (below) |
| `fsync-error-permille=1..5@pg2` (1-100) | 49 | 0 lost; recovery-failed 35 |
| `--faults disk@pg2` (1-60) | 6 | 0 lost; recovery-failed 34, amcheck-fail 11 (below) |
| `enospc-after-bytes=20000000..120000000@pg2` (1-60) | 58 | 0 lost; not-settled 13, recovery-failed 10 (the disk stays full) |

**Controls**, each oracle seen to fail:

| Control (seeds) | Fired |
|---|---|
| `fsync = off` on `pg1`, down 200-1500 ms (1-60) | 51 runs: acked-lost 31 (2,328 commits), checksum-fail 11, amcheck-fail 4, divergence 2, recovery-failed 1 |
| `synchronous_commit = off` (1-30) | acked-lost in 30 (478 commits) |
| asynchronous replication (1-60) | acked-lost in 31 (843 commits) |
| no fencing, synchronous (1-60) | two-primaries in 40; nothing lost or split |
| no fencing, asynchronous (1-60) | split-brain in 39 (14,292 acknowledgements), acked-lost in 40, two-primaries in 40 |
| `full_page_writes = off`, timed checkpoints, 60 s (1-150) | recovery-failed in 1 (`invalid page in block 2 ... WAL redo`) |
| `remote_write`, both machines crash (1-250); with slow disks (260 more) | 0 |
| a recorded run's final rows changed (one txn row, an unattempted txn, a row off the standby) | partial-txn, phantom, acked-missing, once each |

`remote_write` and `full_page_writes = off` lose data only to a crash between a standby's reply
and its fsync, or inside a checkpoint's writes. Every system call costs about 1 µs of virtual
time, so those windows are microseconds wide against crash gaps of seconds: of A-on's 8,157
crashes, 273 found the server in a checkpoint and 14 came right after a WAL write. Slowing the
disk instead (`fs-delay-permille`) made the standby too slow to fail over to.

**Determinism.** Seeds 1-300 of the first sweep run again: 300 identical digests, 206 with a
failover. `verify` under `--vary cpu,load,aslr,sandbox,repeat`, 4 identical runs each with the
sweep's digest: no failover, a crash, several, both crashing, a partition with the driver's
links faulted, a process kill, the asynchronous control and an `amcheck-fail` run. `replay` of
an `acked-lost` run identical, as was every failing group's own replay. About 0.7 runs/s at
`-j 6` (median 8 s of wall time per run), 0.2-0.35 at `-j 4` under disk faults.

**Triage**, in the order harness, Patina, configuration, documented behaviour, PostgreSQL:

- *Harness.* With fsync errors on `pg1` an old primary's `pg_rewind` failed at its last fsync
  after rewriting the directory, and the agent ran it again: `no rewind required`, as the
  second run's single-user recovery finished the first's work and wrote a shutdown checkpoint
  of `pg1`'s own on the source's timeline. `pg1` then streamed as the synchronous standby, so
  the primary acknowledged commits `pg1` flushed but could never replay past its own record;
  promoted later, it ended recovery there: 3 acknowledged commits lost in each of 2 of 150
  runs. PostgreSQL's documentation says a `pg_rewind` that fails leaves the target unusable and
  a fresh backup is needed; the agent now rebuilds, and the same 150 seeds lose nothing. Also
  fixed: a rebuild given up when its source was only unreachable; final reads that met a
  partition right after the settle (the 5 no-primary-content).
- *Patina.* A `sync_file_range(..., SYNC_FILE_RANGE_WRITE)` gets the fsync-error fault: it
  returns `EIO` and the failure counts as reported, so the `fsync` that follows on a new
  descriptor returns 0 while the data stays not durable. `pg_basebackup` (as `SyncDataDirectory`)
  calls exactly that before fsyncing every file and ignores its error; it reported success, and
  after a machine crash relation files were empty (the 7 amcheck-fail with `fsync-error@pg1`:
  `read only 0 of 8192 bytes`). On Linux a write-only `sync_file_range` does not wait, so it
  cannot see a write-back error, and an unseen error is reported to a descriptor opened later:
  the fsync returns `EIO` and `pg_basebackup` fails. Not fixed here. Also: TCP keepalive probes
  are not modelled (a `recv` on a crashed peer's connection with `SO_KEEPALIVE` at 2/1/3 s
  never fails; Linux: `ETIMEDOUT` after about 5 s); this driver uses deadlines instead.
- *Configuration, under faults that stay.* `fsync` errors make PostgreSQL PANIC
  (`data_sync_retry = off`) at every restart while the fault keeps firing (recovery-failed);
  a full disk stops `postmaster.pid` and rebuilds. The 11 amcheck-fail with `--faults disk`
  are the injected faults themselves: 4 read errors, and 7 short reads of a relation file,
  which PostgreSQL 18's default asynchronous read path treats as a failed read (Linux local
  filesystems do not return such short reads).
- *Documented behaviour.* The 2 not-settled runs: a walreceiver that had just connected when
  its source's machine crashed waits for the server's answer with no timeout
  (`connect_timeout` covers the TCP connect, `wal_receiver_timeout` only streaming), and a
  silent crash sends no reset. The same holds for a `pg_basebackup` whose source crashed, very
  likely the unexplained seed 73 of the section above.

No PostgreSQL bug was found; nothing was filed.

### Pausing a node, each node's clock

Measured 2026-11-20 on the same host, x86_64, at the commit that adds them.

`tests/nodes/17-lease.sh` sweeps seeds 1-16 of two guests (`tests/guests/nodes`). `lease.py`
is a primary/backup service with a lease: a store that grants it and fences writes, and two
replicas that measure it on their monotonic clock with a margin. `lww.py` is a
last-writer-wins register on two nodes, stamped by a hybrid logical clock. Each planted bug is
found by its own fault class only:

| Sweep | Faults | Result |
|---|---|---|
| `lease.py`, correct | the seed's pauses of both replicas (gaps 1-8 s, 0.1-4 s long) | 16 of 16 ok |
| `lease.py`, correct | partitions, and the driver stepping a replica's clock back 2-6 s every 2-5 s | 16 of 16 ok |
| `nofence` (the store does not fence) | pauses | stale write in 16 of 16; without pauses in none |
| `realtime` (the lease measured on `time.time()`) | partitions and steps | stale read in 13 of 16; partitions without steps in none |
| `lww.py`, correct | `clock-skew-ms=0..2000` | 16 of 16 ok |
| `wallclock` (each node stamps with its own clock) | skew | lost update in 13 of 16; without skew in none |

Each failing sweep's first run replays identically. `tests/nodes/18-clock.sh` steps a node's
clock by +5 s and then -5 s (`clockstep.c`). Absolute realtime sleeps, condition-variable waits
and timerfds move with each step. Relative ones on any clock do not. A timerfd armed with
`TFD_TIMER_CANCEL_ON_SET` reads `ECANCELED` at the step. All of this is what
`clock_nanosleep(2)` and `timerfd_create(2)` describe. `tests/nodes/16-pause.sh` and
`tests/nodes/15-keepalive.sh` show what a pause looks like from inside and outside the node:
- a connection to a paused node survives;
- the node answers nothing until the resume, then at once;
- a peer's `TCP_USER_TIMEOUT` and keepalive fire as across a cut of the same length.

Runs with the seed's pauses, with skew and with steps are identical under `verify --vary
cpu,load,aslr,sandbox,repeat` and replay identically.

**Runs that do not use the new options are unchanged.** Both builds, at the commit before this
one and at this change, ran the same cells, each architecture on one guest build:
- **The 90-cell ledger** (no nodes): identical on x86_64 and on the hosted arm64 runner.
- **52 cells with nodes** (partitions, the net preset, process kills and machine crashes by
  the seed and by the script, disk faults, `swarm`): identical on both architectures except
  two groups.
  - The cells that ask for `--faults all` (12 cells; 11 changed). With nodes, `all` now adds
    pauses and skew, so it draws differently.
  - `iso.py` (4 cells). It runs `patina ctl` inside a node, and that binary's bytes are a run
    input. The records of every other process and every output are the same.

**Quick tier.** On the arm64 runner, `16-pause` takes about 6 s, `18-clock` about 8 s, and the
keepalive script's two pause cases about 1 s. `17-lease` (about 100 s there, 25 s here) is in
the area and release tiers.

### PostgreSQL on two nodes under pauses

Measured 2026-11-20 on the same host, at the commit that adds pausing a node.

The pair, agent, driver and checker of the section above, unchanged but for one more failover
cause: the old primary was paused (frozen, its machine up) in the 6 s before the decision. A
pause is what a long garbage collection or a stalled host does to a primary: its connections
stay open and nothing answers. The driver's health check sees two failures in a row and fails
over: it fences the old primary (`node kill`, which ends the pause and crashes its machine),
promotes the standby and starts the old primary again, which rejoins with `pg_rewind`. The
seed's pauses are `--fault pause-gap-ms=3000..15000 --fault pause-ms=200..8000` (each node its
own chain; `$PZ` below), with `--env DUR=30`; every sweep `-j 6 --keep none` (a rerun by seed
gives any run again).

| Sweep (seeds) | Pauses | Failovers by cause | Findings |
|---|---|---|---|
| pauses, `synchronous_commit = on` (1-300) | 1,597 (5,799 s paused; 288 ended by the fence) | 362: paused 351, other 10, standby view 1; runs: none 73, paused 111, several 109 | none; 0 of 150,393 acknowledged commits lost; timelines 1-5 |
| pauses and the seed's machine crashes (`--crash machine --fault crash-gap-ms=5000..20000 --fault down-ms=500..4000`; 1-150) | 908 (278 ended by a crash or the fence) | 217: machine crash 126, paused 85, standby view 4, other 2 | none; 0 of 52,654 lost; both nodes down at once in 76 runs |
| no faults (1-60) | 0 | 0 | none; 0 of 54,000 lost |

**Controls:**

| Control (seeds) | Fired |
|---|---|
| no fencing, synchronous (1-60) | nothing: a resumed old primary still takes writes, but every commit waits for a synchronous standby it no longer has, and the agent turns it into a standby of the new primary at its next ask; 0 of 28,527 lost |
| no fencing, asynchronous (1-60) | acked-lost in 21 (1,023 commits), split-brain in 9 (99 acknowledgements from the resumed old primary) |
| asynchronous replication, fenced (1-60) | acked-lost in 15 (1,080 commits) |

Unlike a machine crash, a pause leaves the old primary running: with fencing it is killed, and
without fencing and with asynchronous replication it acknowledges commits after the standby's
promotion that the new timeline never has. With synchronous replication those commits never
return, so the no-fencing control loses nothing; the two-primaries oracle of the section above
did not fire because the resumed node, unlike a restarted one, asks the driver at once and is
demoted.

**Determinism.** Seeds 1-100 of the first sweep run again: 100 identical digests. `verify`
under `--vary cpu,load,aslr,sandbox,repeat`, 4 identical runs each with the sweep's digest: a
run with only pause failovers (seed 9), one with pause and crash failovers (seed 9 of the
second sweep), and an `acked-lost` run of the asynchronous no-fencing control (seed 2), which
also replays identically. About 0.8 runs/s at `-j 6` (median 7 s of wall time per run).

**Patina.** Every run with a machine crash of a node failed the operation log's self-check (the
outcomes were the programs' own): PostgreSQL's Unix socket file `.s.PGSQL.5432`, in a synced
directory, is in the tree the crash leaves but not in the tree the next boot starts from, as a
work tree cannot hold a socket's inode and the restart drops it. The check now leaves such
inodes out of the comparison (`tests/nodes/09-machine.sh`); the commit before this one fails it
on any machine crash with a socket's synced file.

No PostgreSQL bug was found; nothing was filed.

### Every crash point of every node

`patina sweep --branch --crash machine` on runs with nodes: each seed once with crash points
counted and never firing, then once per point of each node, crashing that node's machine
there (`--crash machine-at:P@NODE`; each child reruns the whole run).
`tests/nodes/evidence-branch.sh` (`./check evidence evidence-branch`, under the evidence lock),
measured 2026-11-20 on the same host, x86_64, every sweep `-j 6 --keep fail`, run once; the
wall time is the sweep's.

| Workload | Seeds | Crash points (per node) | Runs | Wall | Correct | Planted bug |
|---|---|---|---|---|---|---|
| `ack2.py` (two nodes, 5 puts) | 1-8 | 368 (a 184, b 184) | 376 | 8 s | 0 failing | `early` (b answers before its fsync): an acknowledged put lost on b in 66 runs, all children of b, in every seed |
| `q3.py` (three nodes, 2 s) | 1-2 | 1,576 (n1 312, n2 632, n3 632) | 1,578 | 65 s | 0 failing | `nosync` (788 points, 32 s) and `early` (1,576 points, 63 s): 0 failing |
| `wal.py` (one node, 15 s) | 1-2 | 5,044 (a 5,044) | 5,046 | 106 s | 0 failing | `nocheck` (recovery trusts each record's length): a torn record recovered in 352 runs |

One crash per run finds what one crash can lose: b's unsynced acknowledgement, a's torn
record. `q3.py`'s planted bugs need more than one: a write two nodes acknowledged survives the
crash of any one of them (the others hold it), and `early`'s window needs the primary to lose
its quorum besides; the seed's repeated crashes find `nosync` (section above). Every point of every node was tried, and the correct versions are ok at all of
them. The two runs of the script, a binary apart (before and after the review fixes), gave the
same table.

**Determinism.** `tests/nodes/14-points-sweep.sh`: a run crashing both nodes at their points
(`machine:60`) is identical under `verify --vary cpu,load,aslr,sandbox,repeat` and replays
identically; every node disk passes `log ops --check`. A branch child's rerun line gives its
digest again (`tests/nodes/13-points.sh`). `minimize` of a failure under crashes of both
nodes at their points, net delays and duplicates and disk delays reduces to
`--crash machine-at:8@b` alone.

**Runs that do not use the new options are unchanged.** The 90-cell ledger (no crashes), and
52 more cells: one machine's `--crash machine:20`, `machine-at:3`, `process:30`,
`machine-at:1..20`, `ack-log` with disk faults; and runs with nodes under partitions and the
net preset, the seed's process kills, the seed's machine crashes (`q3.py nosync`, `wal.py`,
`ack-log` as a node), the script's machine crashes and kills, and disk faults with `swarm`:
built at the commit before and at this change, each architecture on one guest build:
identical on every cell on x86_64; on the hosted arm64 runner identical but for one cell, a
run with nodes, `--faults disk` and `swarm`. With `swarm`, a node's disk and memory classes
are now turned off by its own seed, so such a run draws differently once its faults fire: on
x86_64, seeds 1-16 of that cell differ in 4 with `swarm` and in none without it.

**PostgreSQL** (the pair of the section above) was not swept: one base run counts 9,702 crash
points (pg1 5,139, pg2 4,563) for 30 s of virtual time, and each child is a full run of about
7 s, about 19 CPU-hours per seed.

### Minimizing to one node's crash

`patina minimize` turns a failing run's crashes at crash points into one node's crash alone
(`--crash machine-at:N@NODE`). Before, it tried only each node's first crash; now each node's
first crash, then its later crashes at their places in a first boot that never crashed (the
points of the boots before plus its own, and either side), the most recent first, at most 6
per node within its 30 runs. `tests/nodes/evidence-minimize.sh` (`./check evidence
evidence-minimize`, under the evidence lock): seeds 1-200 of `ack2.py early` under crashes of
both nodes at 60 per mille, net delays and duplicates and disk delays, each failing run
minimized; measured 2026-11-20 on x86_64, the binaries before and after the change on one
guest build, run once each.

| Build | Failing seeds | Reduced to one crash | Minimize runs (mean, most) |
|---|---|---|---|
| before | 59 | 46 | 6.9, 12 |
| after | 59 | 58 | 7.4, 16 |

The seeds that reduced before reduce to the same crash with the same runs (every node's first
crash is still tried first). The one seed left keeps the crash at points: no single crash at
the places tried gives its failure.

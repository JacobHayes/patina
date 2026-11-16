# The syscall-trap engine

Patina runs a Linux x86_64 executable as it is. A small runtime inside every guest process
traps each system call; the real kernel does the work inside a per-run bwrap sandbox; one
supervisor decides order, time, randomness, faults and crashes from the seed. This file says
how, each part pointing at the module that implements it. What the design has been shown to
do, with numbers, is `docs/EVIDENCE.md`.

Three crates: `patina-proto` (no_std, everything the other two must agree on),
`patina-rt` (the runtime, no_std, built for `x86_64-unknown-none`), `patina-cli` (the
`patina` binary: launcher, supervisor, log tools). `patina-cli/build.rs` builds the runtime
and embeds it; at run time it is written once to `~/.cache/patina/rt-<hash>` and executed
from there (`launch::rt_file`). `PATINA_RT=path` runs another runtime build instead.

## Running it

```
patina run --seed 1 --out RUN --guest DIR -- /guest/prog args...
patina verify --seed 1 --runs 20 --vary cpu,load,aslr,sandbox --out DIR --guest DIR -- /guest/prog
patina log dump RUN/inc-0/boundary.log ; patina log diff A/inc-0/boundary.log B/inc-0/boundary.log
patina table
patina run ... --fault fs-error-permille=100 --crash machine:20 [--fs-model ext4-ordered|posix-strict] ...
patina oplog check RUN ; patina crash-states RUN --at SEQ --count N
```

`--guest DIR` is copied into the sandbox at `/guest`. A run directory holds `outcome.json`
and one `inc-K/` per incarnation (`boundary.log`, `oplog.meta`, `oplog.data`, `live.tree`,
`stdout`, `stderr`, `sandbox.log`, and `post-crash/` after a machine crash).

## Launcher (`launch.rs`, `launcher/`)

One sandbox per incarnation. The launcher sets the process state the run inherits to fixed
values (`sup/inherit.rs` lists every item fork and execve pass on, and how each is set or
checked), pins the run to one CPU, sets `ADDR_NO_RANDOMIZE`, creates the control region
(a memfd), the boundary log, the operation log files and the stdio memfds, and starts bwrap
with them inherited at hidden descriptor numbers 3000-3008 and 3020-3022
(`proto::layout`). The incarnation loop (`launcher/incarnations.rs`) restarts the guest after
a crash with the post-crash tree as its `/work`, continuing `seq` and virtual time.

## Sandbox

bwrap `--unshare-all`, uid and gid 1000, a new session, `--die-with-parent`. `/usr` is a
read-only bind; `/work` and `/tmp` are tmpfs; `/etc` is generated; the guest directory,
`ld.so.cache` and `/etc/alternatives` are copies, not binds (`sup/mod.rs`). Nothing in the
sandbox has a capability. The supervisor is PID 1.

## Supervisor (`sup/`)

One sequential program that owns the turn: exactly one guest thread runs at a time, and it
runs until it asks the supervisor for something (`proto::ctl::Op`) through its slot in the
control region (`patina-rt/src/sup.rs` is the runtime side). The scheduler
(`sup/sched.rs`) picks the next runnable slot with a keyed draw; futex queues
(`sup/futex.rs`), the virtual-time event queue (`sup/time.rs`, idle jumps when everything
sleeps), virtual signals (`sup/signal.rs`), processes and the exit barrier (`sup/proc.rs`),
I/O parks (`sup/io.rs`), the network wire (`sup/wire.rs`) and crash points (`sup/crash.rs`)
are all its state. A request that ends a process takes the exit barrier (the process's pidfd
is readable) before anything else of the step: the kernel closes an exiting process's files
after its last system call, and reading its sockets before then is a race.

The stall watchdog counts the turn holder's CPU time since its last trap
(`/proc/<tid>/schedstat`), with wall time as a 10x backstop. The verdict goes to the
launcher over a pipe; `outcome.rs` writes `outcome.json`.

## Runtime (`patina-rt`)

Started by `execveat` of the runtime descriptor with the guest's path. It loads the guest
image itself (`loader.rs`: ET_EXEC, ET_DYN, PT_INTERP, its own stack and auxv, seeded
`AT_RANDOM`, no vDSO), installs a seccomp filter that traps every system call whose
instruction pointer is outside the runtime's text (`entry.rs`; an inherited filter is kept
and this one stacks on it), and handles each trap in its SIGSYS handler: look up the row,
decide faults, run the handler, write the boundary record, return. It has no thread-local
storage; per-thread state sits at the base of each thread's alternate stack (`state.rs`).
Every `syscall` instruction of the runtime is in `raw.rs`. `execve` re-executes the runtime
with the new image (`exec.rs`); `fork` and `vfork` are real (`sys/proc.rs`); threads start
through a frame-copy trampoline (`sys/thread.rs`). Signals are virtual end to end: the
kernel never delivers one to guest code; the runtime builds kernel-layout frames at trap exit
(`sys/sig.rs`, `sigframe.rs`, `fault.rs`).

## The table and its row classes (`patina-proto/src/table/`)

Every syscall number has a row: a class, a strength and a reason (`patina table` prints
them). Numbers without a written row are `Stop`.

| Class | Meaning |
|---|---|
| `Pass` | the real kernel does it inside the sandbox; the result passes |
| `Virt` | answered by the runtime or supervisor; the kernel is not asked (clocks, randomness, futex, signals) |
| `Attempt` | a non-blocking attempt; if it would wait, park until the I/O generation moves, then try again |
| `Rewrite` | passed, then host-dependent fields rewritten (`stat` family, `/proc` reads) |
| `Place` | the runtime chooses every address the kernel would have chosen |
| `Deny(errno)` | refused with an errno and recorded in `outcome.refused` |
| `Stop` | the run ends `unsupported` |

Strength: C (deterministic by construction), A (by argument, then attacked), D (detected
only on replay). Open-ended query surfaces are deny-by-default: unlisted `ioctl`, `fcntl`,
`prctl`, socket options and `/proc`, `/sys`, `/dev` paths are refused and recorded. Path
arguments are resolved against that policy before any handler runs (`resolve.rs`,
`path.rs`). `table/nargs.rs` says which argument registers each call reads; only those are
logged. Host-dependent values are rewritten: virtual inode numbers (`vino.rs`), the virtual
time table for sandbox files (`vtime.rs`), synthesised `/proc` and `/sys` files
(`sys/procfs.rs`), host files owned by the overflow id, mount devices by index, a fixed CPU
count.

## Blocking I/O (`sys/io.rs`, `sys/poll.rs`, `sup/io.rs`)

Every call that can wait on a descriptor is a non-blocking attempt plus a park on the I/O
generation (`Ctl::io.gen`), which the runtime bumps after any call that can change
readiness. Pipe capacity and socket buffers are fixed at creation. Locks are try-locks plus
a park (`sys/lock.rs`); timerfd is a supervisor-driven eventfd (`sys/timerfd.rs`).

## The boundary log (`patina-proto/src/rec.rs`, `patina-rt/src/log.rs`)

A shared file mapping, appended under the turn: one fixed-size record per boundary event
(trap, decision, injected fault, preemption) with the call's arguments, result and a hash of
its outputs. The run's digest is the hash chain over the records. `patina log diff` names
the first record where two runs differ; `patina verify` repeats a seed under varied host
conditions (`--vary repeat,cpu,load,aslr,sandbox,parallel,env,time`) and compares
(`verify.rs`).

## Faults, the operation log and crash models

Faults are decided before the call (`patina-rt/src/inject.rs`; configuration in
`patina-proto/src/faults.rs`): error, short transfer, delay, `ENOSPC`, memory. Each is a
boundary record and an entry of `outcome.faults_injected`. Draws are keyed per fault class,
so turning one class on does not move another's draws.

The operation log records every mutating call on `/work` with its data, sync-class calls,
failed fsyncs and shared-mapping stores (`patina-proto/src/oplog.rs`,
`patina-rt/src/oplog.rs`). Crash points follow every operation record and precede every
sync-class call; the crash draw is consumed only when it fires, so the run before a crash
is identical to the run without `--crash`. A process crash restarts on the live tree; a
machine crash restarts on `materialise(oplog, seed, model)` (`durability/materialise.rs`),
a pure function of the log under `ext4-ordered` (`durability/model_ext4.rs`) or
`posix-strict` (`durability/model_posix.rs`). File contents are sparse copy-on-write images
(`durability/content.rs`); materialisation replays the log once and keeps a state at each
forced commit. `patina oplog check` replays the whole log and compares it with the exported
live tree (`durability/check.rs`).

## The network wire (`sup/wire.rs`, `patina-rt/src/sys/inet.rs`, `patina-proto/src/wire.rs`)

A guest `AF_INET`/`AF_INET6` stream socket is a real `AF_UNIX` stream socket whose kernel
peer is a hidden end the supervisor holds; listeners are real unix listeners on reserved
abstract names, so `accept` is the kernel's. The supervisor reads what guests sent into
per-direction queues, stamps each item with a seeded delivery time and delivers it in
virtual time. Network faults (`net-delay-ms`, `net-chunk-max`, `net-reset-permille`,
`net-connect-refuse-permille`, `net-connect-timeout-permille`, `net-partition`,
`net-halfclose-delay-ms`) are draws keyed per connection. `AF_UNIX` sockets are
pass-through kernel objects with attempt semantics (`sys/unixsock.rs`).

## Instruction channels (`patina-rt/src/insn/`, `patina-proto/src/insn.rs`)

`rdtsc` and `rdtscp` fault under `PR_SET_TSC` and are answered from virtual time
(`insn/tsc.rs`). `rdrand` and `rdseed` sites are found in every executable private mapping
(an x86-64 length decoder confirms each byte candidate), patched to `ud2`, and emulated
from the seed (`insn/scan.rs`, `insn/patch.rs`, `insn/emulate.rs`). Anonymous executable
memory (JIT) is not scanned and is counted (`unscanned_exec_mappings`). `cpuid` identity
fields, `rdpid` and `lsl` read the pinned core and are not controlled.

## Counter preemption (`patina-proto/src/pmu.rs`, `patina-rt/src/pmu.rs`, `launcher/pmu.rs`)

Trap points only preempt at system calls, so a syscall-free spin-wait whose partner was
preempted never yields. `patina run --pmu` preempts the turn holder after N retired
conditional branches of guest user code, N a keyed draw, at the instruction boundary right
after the N-th branch retires: one stop per N whatever the hardware did on the way. The
stop is treated like a trap: a boundary record (`preempt`, with the instruction pointer, N
and a hash of the registers), virtual time charged N x `--pmu-charge-ps`, a yield, and the
trap exit, where virtual signals are delivered (so Go's SIGURG reaches a thread inside
compute).

**Who opens the counters.** `perf_event_open` needs `CAP_PERFMON` in the initial user
namespace, which nothing in the sandbox has. The launcher (a `patina` given
`setcap cap_perfmon+ep`, or root) serves a broker on a `SOCK_SEQPACKET` pair (hidden
descriptor 3008). A guest thread sends a thread pidfd; the broker checks the task descends
from this incarnation's bwrap child and returns one counter for it with a fixed attribute
(pinned, user only, period 2^20, synchronous SIGTRAP on overflow, removed on exec).
Capabilities never enter the sandbox. Unprivileged, `--pmu` says why it is off and the run
goes on without it.

**Counting guest code only.** A segment is the guest code between two runtime entries.
Every runtime entry (trap, emulation, fault, the overflow handler's own work) ends one; each
return to guest code starts one and draws a fresh N. The overflow handler reads the counter
at its first and last instructions and counts the branches between by hand, so the guest's
count is exact.

**Reaching the exact stop**, with margin M (1,024, `--pmu-margin`):
- Hop (N <= M + 1,024): the runtime walks forward itself, planting `int3` at the next
  control transfer through `/proc/self/mem` and emulating it (conditional branches from the
  saved flags, counted; indirect transfers from registers and memory; anything else by one
  single step). Planted bytes stay until the next runtime entry.
- Mid (N < 2^20 + 2M): the period is set to N - M, then hops.
- Long: the counter runs at 2^20; each overflow reprograms or switches to hops for the last
  stretch. A skid past N cannot be repaired and ends the run `infra` ("pmu overshoot").
- An overflow delivered together with a SIGSYS or a fault from the same instruction is
  recognised by the interrupted address; the trapped syscall is re-executed after it.

**Policy.** With probability `--pmu-short-permille` (20) N is log-uniform in
`[1, --pmu-short-max]` (256), stops close to a trap where check-then-act windows sit;
otherwise log-uniform in `--pmu-slice` (2^20 + 2,048 .. 2^22). For races whose window is a
single branch boundary, `--pmu-short-permille 1000 --pmu-short-max 64` makes every segment
short. Counter preemption composes with trap-level `--preempt-permille`.

**Off by default.** It needs a capability, costs 10 to 23 µs per trap on a KVM guest
against 0.75 µs, and 3 to 6 ms per preemption. Turn it on for programs with syscall-free
waits (stock Go above two CPUs, spin locks) and for syscall-free races. Hazards: a guest
reading its own text while a segment hops sees `int3` bytes (private copy-on-write pages);
throttling (`perf_event_max_sample_rate`) stops counting and shows as an overshoot;
Intel's event (`0x01c4`, `BR_INST_RETIRED.CONDITIONAL`) counts on Intel hosts but the
engine's use of it is untested; AMD's is `0xd1`.

## Checks (`check`, `tests/`)

`./check quick` is the landing gate; `./check AREA` runs one directory under `tests/`;
`./check evidence NAME` runs a measurement by hand. Every script declares
`#@ tier=quick|area|evidence budget=SECONDS slots=N`; `tests/run.py` runs them in parallel
(at most 8 sandboxes, `CHECK_SLOTS`), kills a script at its budget, fails one that leaves a
process behind, and prints the total. Guests are built once per source change
(`tests/guests.sh`). Output goes under `target/patina-check/` (`PATINA_CHECK_DIR`). A
budget that is exceeded is cut, never raised; no script re-runs another area's scripts.

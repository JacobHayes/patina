# Architecture

How Patina runs a program deterministically, what that rests on, and where it stops. Each
part names the module that implements it. Measured results are in
[docs/EVIDENCE.md](docs/EVIDENCE.md).

## The parts

```
patina (patina-cli)
 ├─ launcher        one bwrap sandbox per incarnation; fixed process state; restart after a crash
 └─ supervisor      PID 1 in the sandbox: the turn, virtual time, signals, the network wire,
     │              crash points; answers the runtime over a shared control region
     └─ guest processes, each with the runtime (patina-rt) loaded first
          runtime   traps every system call (seccomp), decides faults, writes the boundary log
          program   unmodified; its system calls reach the kernel only through the runtime
```

Three crates: `patina-proto` (no_std; everything the runtime and the supervisor must agree
on: layouts, the syscall table, records, the fault and SDK wire), `patina-rt` (the runtime,
no_std, built for `x86_64-unknown-none`) and `patina-cli` (the `patina` binary). The SDK
crate `crates/patina` is separate and has no dependencies. `patina-cli/build.rs` builds the
runtime and embeds it; at run time it is written once to `~/.cache/patina/rt-<hash>` and
executed from there (`launch.rs`).

## The trap

The runtime is started by `execveat` with the program's path. It loads the program itself
(`loader.rs`: static or dynamic, its own stack and auxiliary vector, a seeded `AT_RANDOM`, no
vDSO), then installs a seccomp filter that traps every system call made from outside the
runtime's own code (`entry.rs`). Each trap lands in the runtime's SIGSYS handler: look up the
call's row, decide faults, do the call, write the boundary record, return.

`execve` loads the runtime again with the new program (`exec.rs`); `fork` is real
(`sys/proc.rs`). Signals are virtual: the kernel never delivers one to program code; the
runtime builds the signal frame on the way out of a trap (`sys/sig.rs`). The runtime has no
thread-local storage; each thread's state sits at the base of its alternate signal stack.

## The syscall table

Every system call number has a row in `patina-proto/src/table/` with a class, a strength and
a reason; `patina table` prints them.

| Class | What happens |
|---|---|
| `Pass` | the real kernel does it inside the sandbox |
| `Virt` | answered without the kernel: clocks, randomness, futex, signals |
| `Attempt` | a non-blocking try; if it would wait, the thread parks until something changes |
| `Rewrite` | passed, then host-dependent fields rewritten (`stat`, `/proc` reads) |
| `Place` | the runtime chooses every address the kernel would have chosen |
| `Deny(errno)` | refused with an errno and recorded in `result.json`'s `refused` |
| `Stop` | the run ends `unsupported` |

A number without a row is `Stop`. Open-ended interfaces (`ioctl`, `fcntl`, `prctl`, socket
options, paths under `/proc`, `/sys`, `/dev`) are refused unless listed. Path arguments are
checked against that policy before any handler runs (`resolve.rs`, `path.rs`). Host values
are replaced: inode numbers, file times, `/proc` contents, the CPU count (`--cpus`).

Blocking calls are a non-blocking attempt plus a park on an I/O generation counter that the
runtime bumps after any call that can change readiness (`sys/io.rs`, `sys/poll.rs`). Pipe and
socket buffer sizes are fixed at creation, so readiness is a function of the calls made.

## The sandbox

bwrap with every namespace unshared, uid and gid 1000, no capabilities. `/usr` is a
read-only bind; `/work` (or the path `--work DIR:GUEST` gives, `Config::work`) and `/tmp`
are tmpfs; `/etc` is generated; the program's directory is a read-only bind at the path it
was given by (`config::program`), and `:copy` mounts are copies (`sup/mod.rs`). A path the guest ran, opened or looked for and found missing is kept in
the control region; the launcher names those the host has (`launch::not_in_sandbox`).
The launcher fixes every piece of process state a child inherits (umask, rlimits, signal
dispositions, the CPU it is pinned to, address randomization off; `sup/inherit.rs` lists each).
As root, the launcher makes the user namespace and bwrap joins it (`launch::userns`): uid and
gid 1000 are the user sudo was run by, else `nobody`, and nothing else is mapped, as in
bwrap's own namespace for an ordinary user. Left to bwrap, root would be mapped in and parts of
/proc covered, and the guest would see who started the run.

## The supervisor

One sequential program that owns the turn: exactly one guest thread runs at a time, until it
asks the supervisor for something through its slot in the control region (`proto::ctl`). The
scheduler (`sup/sched.rs`) picks the next runnable thread with a draw from the seed. Futex
queues, the virtual clock and its timers, virtual signals, processes, parked I/O, the network
wire and crash points are all supervisor state (`sup/`).

Virtual time advances only by what the program does: each trap charges a fixed amount, and
when every thread sleeps the clock jumps to the next deadline (`sup/time.rs`). A run of a
program that sleeps an hour takes milliseconds.

## The boundary log

Every boundary event (a trap, a scheduling decision, an injected fault, a preemption) appends
one fixed-size record under the turn: the call, its arguments, its result and a hash of what
it wrote (`patina-proto/src/rec.rs`, `patina-rt/src/log.rs`). The run's digest is the hash
chain over the records. Replay runs the program again and compares record by record
(`replay.rs`); `patina log diff` names the first difference; `patina verify` repeats a seed
while changing the host and compares (`verify.rs`).

## Scheduling points

The scheduler can switch threads only where a thread enters the runtime. Those points are:

- **System calls.** Every trap is a point.
- **Pause points.** Every `pause` instruction (the hint in glibc's spin lock, Rust's
  `spin_loop`, Go's spinning) is patched to trap and yields (`insn/`).
- **Spin probes.** A thread that runs 20 ms of CPU time without a point is single-stepped
  until its loop repeats with nothing changed (registers, vector state, written pages). Such
  a loop waits for another thread, and its state there is the same in every run, so it
  yields there, and at each later arrival (`spin.rs`, `sup/stall.rs`).
- **Branch counters**, with `--preempt branches`: a preemption after a seed-chosen number of
  retired branches of program code, at an exact instruction (`pmu.rs`). Off by default.

`rdtsc`, `rdrand` and `rdseed` are answered from virtual time and the seed. Code generated
at run time (a JIT) is not scanned for them; such mappings are counted in `result.json`.

**compute-stall.** A thread that computes for 10 s of its own CPU time without a point,
while another thread could run, ends the run `unsupported` with stop `compute-stall` and
names the thread. The cause is a loop that changes state on each pass (a counter, a
timestamp it computes) and contains no system call or `pause`. The fix is `--preempt
branches`, where the host allows it. A thread computing alone is left to finish.

## Counter preemption

With `--preempt branches`, the turn holder is preempted right after its N-th retired
conditional branch of program code, N a draw from the seed. The stop is treated like a trap:
a boundary record, virtual time charged, a yield, and pending signals delivered.

`perf_event_open` needs `CAP_PERFMON`, which nothing in the sandbox has. The launcher (a
`patina` given the capability) serves a broker on a hidden socket: a guest thread sends its
pidfd, the broker checks the thread belongs to this run and returns one counter with a fixed
configuration (`launcher/pmu.rs`). Capabilities never enter the sandbox.

A segment is the program code between two runtime entries; each segment draws a fresh N. The
counter overflows a little before N; the runtime then walks forward itself, planting `int3`
at the next control transfer and emulating it, counting branches by hand until N is exact
(`patina-rt/src/pmu.rs`). An overshoot past N cannot be repaired and ends the run `internal`.

Most draws are long (about 1 to 4 million branches); 2% are short (up to 256), which lands
stops just after a system call, where check-then-act windows sit. `[sched] branches = "hunt"`
makes every segment short.

Only AMD family 0x1a (Zen 5) is accepted: on an Intel Xeon the conditional-branch event
stopped at different instructions for the same count. Other CPUs are refused with an error,
never silently run without counters.

## The fault plan

`--faults`, `--fault` and `--crash` give the plan (`faults.rs`). A value given as a range is
resolved from the seed by a draw keyed by the setting's name, so adding one setting never
moves another's value. The resolved plan is in `run.json`; replay refuses a run whose plan
resolves differently.

Each fault decision is a draw keyed by the call's sequence number and the fault class, made
before the call (`patina-rt/src/inject.rs`). Turning one class on does not move another's
draws. An injected errno is one Linux returns for that call on that object
(`faults::errnos`). Every injected fault is a boundary record naming its object, and
`result.json`'s `faults` counts per class the calls it could act on and the faults injected.

The network wire: a TCP socket in the guest is a real unix socket whose peer the supervisor
holds (`sup/wire.rs`). The supervisor reads what each side sent, stamps it with a seeded
delivery time, and delivers it in virtual time. Delays, splits, resets, refused connects and
partitions are draws keyed by the connection and what they act on: a reset is drawn on each
piece of data a guest sends (so a long-lived connection meets one), a refusal or timeout once
per connect, a delay or split per delivery.

## The crash model

The runtime records every change to `/work` with its data in an operation log, along with
every sync (`patina-proto/src/oplog.rs`). Crash points follow each change and precede each
sync; the crash draw is used only when it fires, so a run is identical to the run without
`--crash` up to the crash.

A process crash restarts the program on `/work` as it was. A machine crash restarts it on
what a filesystem would have kept: a pure function of the operation log, the seed and the
model, `ext4-ordered` (the default) or `posix-strict` (`durability/`). Every run with
`--crash` ends by replaying its whole operation log against the live tree; a difference ends
the run `internal`. `patina log ops` prints the log.

## The SDK channel

The SDKs make one reserved system call, `0x7061`. Outside Patina the kernel answers `ENOSYS`
and the SDK goes inert. Under Patina the runtime answers it (`sys/sdk.rs`): assertions count
into a site table shared by every process of the run, and fault points are draws keyed by
the seed and the label. A failed `always`, or a reached `unreachable`, ends the run
`violation`. Sites declared with a literal label are in an ELF section, so a site never reached
is still reported (an `unreachable` never reached is as it should be, and a sweep does not list
it).

## What is deterministic, and how we know

By construction: one thread runs at a time, and every input the program can observe passes
through a trap or an instruction Patina emulates. Time, randomness, scheduling, addresses,
inode numbers and faults come from the seed. Each table row says how its call is made
deterministic.

By test: whether everything observable really passes through the table is checked, not
proved. `patina verify` repeats a seed while moving it across CPUs, under load, with address
randomization on and in another sandbox; a sweep replays the first seed of each finding. The
measured record, with the thirteen differences found and closed, is in
[docs/EVIDENCE.md](docs/EVIDENCE.md). New kinds of difference were still appearing when the
last matrix ran, so a difference is a Patina bug to report, not noise.

Determinism holds for a cooperating program. A hostile program can corrupt the control
region it shares with the supervisor, or jump into the runtime's own system call
instruction; Patina does not contain it.

## Limits

- **Linux x86_64 only.** No macOS, no arm64. bwrap and unprivileged user namespaces are
  required.
- **A seed reproduces for the same program binary, on the same kind of host.** Replay checks
  the binary's hash. The kernel's own behaviour for passed calls is an input: a different
  kernel version or filesystem may change a run.
- **Branch counters** (`--preempt branches`) need `CAP_PERFMON`, a PMU, and an AMD family
  0x1a (Zen 5) CPU, the only one checked exact; their seeds reproduce on the same family only.
- **compute-stall**: without branch counters, a spin-wait whose iterations change state ends
  the run (above).
- **One machine.** All processes of a run share one sandbox, one disk and one clock. There is
  no simulation of several machines, and no network outside the run.
- **No UDP.** `socket(AF_INET[6], SOCK_DGRAM)` and raw sockets are refused with
  `ESOCKTNOSUPPORT` and listed in `result.json`'s `refused` (`socket:udp`); `patina run`
  prints them. DNS resolvers and QUIC therefore fail fast. Only TCP has a wire.
- Not modelled: `timer_create`, scheduling policy calls, `io_uring`; another process's
  `/proc/PID`. docs/EVIDENCE.md has the full list.

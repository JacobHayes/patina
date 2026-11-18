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
no_std, built for the host's bare target: `x86_64-unknown-none` or
`aarch64-unknown-none-softfloat`) and `patina-cli` (the `patina` binary). The SDK
crate `crates/patina` is separate and has no dependencies. `patina-cli/build.rs` builds the
runtime and embeds it; at run time it is written once to `~/.cache/patina/rt-<hash>` and
executed from there (`launch.rs`).

The architecture seam: in the runtime, `arch/x86_64/` and `arch/aarch64/` export the same names
(the trap frame and its accessors, the system-call stub, process entry, the signal frame, the
clone trampoline, instruction sites and their patch, the stepper of a spin probe, the counter
trap), and portable code names no register or instruction (`arch/mod.rs`). In `patina-proto`,
what both sides must agree on per architecture: system-call numbers (`nr/`), the structure
layouts and flags that differ (`abi.rs`), the instruction-site rules (`insn/`), and for arm64
the successor decoder (`step.rs`) and signal-frame records (`sigrec.rs`), compiled and tested
on every host. In `patina-cli`, the host checks (`host.rs`) and branch counters
(`launcher/pmu.rs`, x86_64 only). One build serves one architecture; seeds do not cross.

## The trap

The runtime is started by `execveat` with the program's path. It loads the program itself
(`loader.rs`: static or dynamic, its own stack and auxiliary vector, a seeded `AT_RANDOM`, no
vDSO), then installs a seccomp filter that traps every system call but those made by the
runtime's one system-call instruction (`syscall`; `svc #0` on arm64) (`entry.rs`, `raw.rs`,
`arch/`). Each trap lands in the runtime's SIGSYS handler: look up the
call's row, decide faults, do the call, write the boundary record, return.

What runs is resolved as the kernel's `execve` resolves it, for the first program and for every
`execve` alike (`exec.rs`, `resolve`): permission and file type, an ELF image of this
architecture and its interpreter, `#!` lines read as the kernel reads them (one optional
argument, the first 255 bytes, five nested interpreters; `proto::exec`); an interpreter's
symbolic links are checked against the paths Patina keeps from the program. A program that
cannot run ends the run `error`, stop `exec`, naming why and the kernel's errno (`unsupported`
when the kernel would run it and the runtime does not load it, as a 32-bit image); `execve`
returns that errno. `execve` loads the runtime again with the new program; `fork` is real
(`sys/proc.rs`). Signals are virtual: the kernel never delivers one to program code; the
runtime builds the signal frame on the way out of a trap (`sys/sig.rs`, the frame itself in
`arch/<arch>/sigframe.rs`), so a signal arrives only at a trap boundary: a system call, a
fault, a compute point, never in the middle of straight-line code. The frame is the kernel's
layout with its contents normalised to the registers, not to the kernel's history: no stale
fault code or address from an earlier fault (on arm64 the counter-timer reads and the
runtime's own faults leave none), unused fields and the tail zeroed. `rt_sigreturn` is
emulated: the runtime checks the frame the program hands back as the kernel does, and a
frame it would refuse ends in `SIGSEGV`, never in a fault of the runtime. On arm64 the frame
carries the records the host's kernel writes (FP/SIMD, the fault syndrome, SVE, `TPIDR2`, the
ZA header, `FPMR`, `POR_EL0`; `proto/src/sigrec.rs`); one Patina does not build (SME's
streaming mode or ZA contents, ZT, GCS, the extra record) ends the run `unsupported`, stop
`signal-context`, naming it. The
handler returns through a fixed page holding `rt_sigreturn` unless it gives its own restorer,
and is entered with `BTYPE` set for a branch-target host. The runtime has no thread-local
storage; each thread's state sits at the base of its alternate signal stack.

## The syscall table

Every system call number has a row in `patina-proto/src/table/` with a class, a strength and
a reason; `patina table` prints them. Rows, handlers and the runtime's own calls name a call
(`nr::OPENAT`), never its number: the numbers are per architecture, in `patina-proto/src/nr/`,
generated from the kernel's tables by `scripts/gen-syscalls.py`.

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
options, paths under `/proc`, `/sys`, `/dev`) are refused unless listed; the commands of
`ioctl`, `fcntl`, `prctl` and `arch_prctl` are listed with the arguments each reads
(`proto::table::cmds`), so none is let through without saying what it reads. Path arguments are
checked against that policy before any handler runs (`resolve.rs`, `path.rs`). Host values
are replaced: inode numbers, file times, `/proc` contents, the CPU count (`--cpus`).

Blocking calls are a non-blocking attempt plus a park on an I/O generation counter that the
runtime bumps after any call that can change readiness (`sys/io.rs`, `sys/poll.rs`). Pipe and
socket buffer sizes are fixed at creation, so readiness is a function of the calls made.

## The sandbox

bwrap with every namespace unshared, uid and gid 1000, no capabilities. `/usr` is a read-only
bind; `/work` (or the path `--work DIR:GUEST` gives, `Config::work`) and `/tmp` are tmpfs;
`/etc` is generated; the program's directory is a read-only bind at the path it was given by
(`config::program`), and `:copy` mounts are copies (`sup/mod.rs`). A path the guest ran, opened
or looked for and found missing is kept in the control region; the launcher names those the host
has (`launch::not_in_sandbox`). The launcher fixes every piece of process state a child inherits
(umask, rlimits, signal dispositions, the CPU it is pinned to, address randomization off;
`sup/inherit.rs` lists each). As root, the launcher makes the user namespace and bwrap joins it
(`launch::userns`): uid and gid 1000 are the user sudo was run by, else `nobody`, and nothing
else is mapped, as in bwrap's own namespace for an ordinary user. Left to bwrap, root would be
mapped in and parts of /proc covered, and the guest would see who started the run.

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
it wrote (`patina-proto/src/rec.rs`, `patina-rt/src/log.rs`). A record holds the arguments as
the program passed them (`Call::guest_args`), not a buffer of the runtime's that a handler
passed on instead (a resolved path, a shortened count), so no runtime address enters the log
and a change to the runtime's own layout does not move a digest. It holds only the arguments
the call reads, given the values of the others (`proto::table::nargs::live`): the count from
the kernel's trace events, less those a flag, a command or a NULL pointer leaves unread
(`mremap`'s new address without `MREMAP_FIXED` or `MREMAP_DONTUNMAP`, an anonymous `mmap`'s
descriptor, `open`'s mode without `O_CREAT` or `O_TMPFILE`, `mknod`'s device for anything but
a device node, `futex`'s by operation, `clone`'s tid words and TLS by flag, `epoll_ctl`'s event
for `EPOLL_CTL_DEL`, a signal set's size or an address length with no set or address, an
absolute `clock_nanosleep`'s remainder, the high half of `preadv`'s offset, `getcpu`'s unused
third, and for `fcntl`, `ioctl`, `prctl` and `arch_prctl` what the command's entry in
`proto::table::cmds` names). An unread register holds whatever the program's code left there,
which can differ between hosts where the program's behaviour does not (static glibc's
`memcpy` leaves another value in `x4` on an arm64 CPU with SVE than on one without). The run's digest is the hash
chain over the records.

A string the program passed that a checker needs in clear (an SDK call's label, a mark's text)
follows its call's record as `Str` records (`proto::RecKind::Str`): which string, its length,
the process, and 64 of its bytes per record, as many records as the string needs, appended
under the same turn right after the trap record, so they are in the digest and in replay's
comparison. The bytes are a copy of what the handler already read through the checked guest
copy (`sys/sdk.rs` keeps the label it was given until `log::trap` writes it), never a second
read of the program's memory. A call whose payload could not be read has none.

With `--log-paths` (`Config::log_paths`) a call's C-string arguments follow its record the
same way: each as the program passed it, read once (the bytes the input hash reads,
`log::trap_paths`), and the absolute path each walked argument resolved to, kept by the path
resolver (`resolve::prepare`) in the call's path buffers, which live in the trap entry's frame
until the record is written; `execve`'s arguments are read from the program's array, bounded
(`proto::rec::ARGV_MAX`, `ARGV_BYTES`, `PATH_BYTES`). The resolver's walk is in the
program's view of the file system, so no host path enters. Without the flag `log::trap`
takes one more branch and writes what it wrote before.

Replay runs the program again and compares record by record
(`replay.rs`); `patina log diff` names the first difference; `patina verify` repeats a seed
while changing the host and compares (`verify.rs`).

A `--check` command (`check.rs`) runs after a run that ended ok, on the host and outside the
sandbox, with the run directory as its argument; it is never part of the run. `run.json`
records its words, working directory, program and SHA-256 (`Config::check`); `result.json`
records its verdict (`check`), which can turn an ok run into a `violation` (stop `check`,
signed as an `always` is) or an `error`. Its output is not in the logs or the digest. A
replay whose logs equal the run's while the verdict differs ends `error`, stop
`check-unstable`, not `nondeterministic`.
A serving checker (`--check-serve`, `check::Server`) is started once per sweep job by the
sweep's worker thread, which lends its pipes to each `patina run` it starts (`PATINA_CHECK_SERVER`:
descriptors kept across that one exec, close-on-exec again at once in the child); the run
writes one request line and reads one verdict line, so the verdict is still made, recorded and
replayed by the run, as a per-run checker's is. A server that wrote out of turn, answered with
anything but one verdict line, or not within `--check-timeout`, is killed and the run is an
`error`; the worker starts another for its next run. A run with no lent server (`patina run`,
a replay, minimize), or whose server ended after its last answer, starts one for itself. Sending each run's verdict through its own `patina
run`, rather than judging in the sweep, keeps one code path for verdicts, `check.out` and
`pending`. Its cost decided the design: a Python checker started per run costs 2 to 4 times
the unchecked sweep, a server 1.0 to 1.2 times (docs/EVIDENCE.md, Oracles).
Judging again (`recheck.rs`) is the one exception: `recheck::rejudge` runs the checker on a
kept run directory (`check::run_on`, with a worker's server or none) and rewrites only what
follows from the verdict (`result::with_check` over the run's own end, `outcome::ok_end`),
writing `pending` first so an interrupted recheck never leaves the old verdict under the new
checker. `patina recheck` and a resumed sweep share it: the checker is not part of a sweep's
identity (`sweep::identity`); a run whose recorded checker differs (`recheck::same_checker`) or
whose verdict is `pending` is judged again from its logs, or run again when they were pruned
(`sweep::have`). The case (`Config::case`: id and line) is in `run.json`, so a replay and
`--config run.json` keep `PATINA_CASE_ID`.
A `--cases` line may give its own run settings before `--` (`sweep::case_line`, the flags of
`CASE_FLAGS` parsed by `patina run`'s parser); they follow the sweep's on the run's command
line. The whole line is the case's identity on resume (the `case` file); its id (its `--name`
or line number) names its directory and `--only-case` selects it; a checker, the report
and a known pattern see the line after its settings (`sweep::case_shown`), so a pattern
written for a case still matches once its line gains settings.
`--ok-exit` (`Config::ok_exit`, in `run.json`) is an input of `outcome::classify`: a guest
that exited with a listed status, not on a signal, ends `ok`, stop `ok-exit`, and the checker
judges it; the logs and digest are those of the run without the flag. Each incarnation's
final work tree is `inc-K/live.tree` (`durability::tree`); `patina log tree` writes it out.

`patina log events RUNDIR` (`events.rs`) is the stable export of a run directory for checkers:
one JSON line per boundary record, with each operation-log record after its call (same
`seq`; an operation whose call has no record, as when a crash point fired between the two,
goes before the first record later in virtual time) and named by replaying the namespace
(create, link, rename, unlink) as the operations go by, so a path is the one the file had at
that moment. An `Injected` record and its `Name` records become one `fault` event with the
fields `faults.recent` shows (`launcher::attribution::injected`, shared); a call's `Str`
records become fields of its event. It streams both
logs and keeps only the live names. Its fields are versioned (`v` in the header) and only
added to; `log dump` and `log ops` stay the text forms.

The logs of a run (this one and the operation log) are limited (`Config::log_limit`,
`--log-limit`): the append that would pass the limit ends the run instead, so the cut depends
on records, not time. The log file grows by `fallocate`, so a full host filesystem is a failed
call (`disk-full`), never a fault on a store through the mapping.

## Scheduling points

The scheduler can switch threads only where a thread enters the runtime. Those points are:

- **System calls.** Every trap is a point.
- **Pause points.** Every spin hint is patched to trap and yields (`insn/`): `pause` on
  x86_64 (glibc's spin lock, Rust's `spin_loop`, Go's spinning); on arm64 `yield`, `isb`
  (Rust's `spin_loop`, Go's `procyield`), `wfe` and `wfi`. glibc's arm64 spin lock has no hint.
- **Spin probes.** A thread that runs 20 ms of CPU time without a point is single-stepped
  until its loop repeats with nothing changed (registers, vector state, written pages). Such
  a loop waits for another thread, and its state there is the same in every run, so it
  yields there, and at each later arrival (`spin.rs`, `sup/stall.rs`). x86_64 steps with the
  trap flag, plants `int3` and finds written pages by soft-dirty bits. arm64 has neither a
  step bit a program may set nor soft-dirty bits: its stepper decodes the instruction's
  successor (the branches, with their conditions on the frame) and plants a `brk` there
  (`proto::step`, `arch/aarch64/step.rs`); an exclusive pair (`ldxr` to `stxr`) is stepped
  whole, as a stop inside it would fail the store every time; written pages are found by
  userfaultfd's asynchronous write-protection, set up when a probe starts and closed when it
  ends. A breakpoint goes only into private, read-only code: in writable code (a JIT) the
  program's own patch would be undone when the old word goes back. Where the host cannot make
  probes work (`patina doctor`, "spin probes": a container's seccomp profile, a kernel
  without userfaultfd or soft-dirty bits, `/proc/self/mem` closed to code writes), they are
  off, and a `compute-stall` says so.
- **Branch counters**, with `--preempt branches`: a preemption after a seed-chosen number of
  retired branches of program code, at an exact instruction (`pmu.rs`). Off by default.
- **Compute points**, in code rebuilt with the compilers' coverage flags: the hooks count
  events and enter the runtime when a seeded number has run (below).

`rdtsc`, `rdrand` and `rdseed` (arm64: the counter-timer reads, `RNDR` and `RNDRRS`) are
answered from virtual time and the seed. The counter faults wherever the code came from;
code generated at run time (a JIT) is not scanned for the others, and such mappings are
counted in `result.json` (`unscanned_exec_mappings`). `MADV_DONTNEED` over patched code drops
the patched copy of the page; the runtime patches its sites again.

On arm64 the scan is a compare under a mask of each aligned word of a file's executable
sections (`proto/src/insn/aarch64.rs`), and a site becomes `udf #0x7061`. A word that a
literal load of the same code reads is data and is left alone (`rejected_sites`); data in text
reached otherwise (a table addressed by `adr` in a stripped file) cannot be told from code,
and the census of every executable file on the dev VM and the CI runner found none that
matches (docs/EVIDENCE.md). `RNDR` is answered only where the host has it (`HWCAP2_RNG`);
elsewhere it raises `SIGILL` as it would without Patina (`[run] emulate-rndr` answers and
advertises it anyway, to test that path). `PACGA` is counted and labelled (`labels.pacga_sites`), not patched. An
`isb` that is not a spin hint loses nothing to the patch (the fault and the return from it
synchronize the context as `isb` does). No landing pad is ever patched and `udf` is not one,
so BTI checks fall where they would; an indirect branch to a site in a guarded page is the
program's fault, not emulated.

**compute-stall.** A thread that computes for 10 s of its own CPU time without a point,
while another thread could run, ends the run `unsupported` with stop `compute-stall` and
names the thread. The cause is a loop that changes state on each pass (a counter, a
timestamp it computes) and contains no system call or spin hint. The fix is `--preempt
branches`, where the host allows it, or rebuilding that code with compute points (its message
says both: the supervisor does not know whether the code is rebuilt). Rebuilt code does not
reach it while it stays in instrumented code: it yields at least every 2^22 events. A thread
computing alone is left to finish.

## Counter preemption

With `--preempt branches`, the turn holder is preempted right after its N-th retired
branch of program code (x86_64: conditional branches; arm64: every branch instruction), N a
draw from the seed. The stop is treated like a trap: a boundary record, virtual time charged,
a yield, and pending signals delivered.

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

Only CPUs whose counting was checked exact are accepted: AMD family 0x1a (Zen 5), and on
arm64 the Arm Neoverse N2 (by `MIDR_EL1` implementer and part, every core of the host;
`proto::pmu::ARM_CORES`). On an Intel Xeon the conditional-branch event stopped at different
instructions for the same count. Other CPUs are refused with an error, never silently run
without counters.

**arm64** (`arch/aarch64/pmu.rs`). The event is `BR_RETIRED` (0x21), every branch taken or
not, measured exact on the Neoverse N2 (docs/EVIDENCE.md, "Branch counters on arm64"). The
differences from x86_64:

- The counter is read with `read()` on its descriptor (user access to the PMU registers needs
  a host setting and, on the hosts measured, traps to the hypervisor at the same cost). Each
  read the count depends on is in assembly a fixed number of branches from program code: at
  the return to the program (the signal restorer and `sigreturn_to`, which read only when a
  segment asks and then `rt_sigreturn`) and at the head of the overflow handler. The kernel
  writes the value into the thread state, so no branch follows the read to keep it.
- No overflow is taken inside the runtime: with counters on, every runtime handler blocks
  SIGTRAP, so an overflow that comes while runtime code runs waits until `rt_sigreturn`
  restores the program's mask and is taken at the program's next instruction. The program's
  entry is a jump, not such a return: an image's first segment (from its entry point to its
  first trap) is not measured.
- Hops plant `brk` at the next branch; conditional and direct branches are taken in the frame
  (`proto::step`), indirect ones (`br`, `blr`, `ret`) and any branch reached with
  `PSTATE.BTYPE` set run natively to a breakpoint at their successor, so the CPU makes its own
  branch-target check.
- A store-exclusive natively fails now and then with no other writer (the host clears the
  exclusive monitor), and its retry loop counts two more branches, more or less often by run.
  With counters on, the scanner also patches every exclusive instruction (`ldxr`/`stxr` and
  their acquire, release and pair forms, and `clrex`) and the runtime emulates them with a
  monitor of its own: the store fails exactly when a boundary event (a trap, a preemption,
  a signal) came between the load and the store. Emulation is no boundary event (no record,
  no sequence number), but its SIGILL is a runtime entry like any other: the counted segment
  ends there and the next starts with a new N, so in code dense with exclusive pairs
  preemptions fall soon after one. (Keeping the segment across it was tried: a waiter
  spinning on an exclusive pair then needs a whole long N of emulated instructions, seconds,
  before its preemption, and the exclusive-pair spin locks stalled.) An access that would fault raises the fault the
  instruction would (SIGSEGV, SIGBUS for an unaligned address) with the site still emulated,
  so both halves of a pair stay on the one monitor; a process whose patch table is full when
  an exclusive instruction is found stops (`unsupported`, stop `capacity`), since one left
  native would fail at random. Without counters they are not patched.

## Compute points

Code rebuilt with the compilers' coverage flags calls a hook at each edge, and with clang and
Rust at each load and store; Go's `-d=libfuzzer` calls one at each comparison. The hooks are
`sdk/c/patina_compute.c` (C, C++, and Rust through the SDK's feature `compute`) and
`go/patina/compute`. Each call is an event. Stock code makes none of these calls and is not
touched.

- **The cell**: one word of the program's own memory per address space, at
  `proto::layout::COMPUTE_CELL`. Each event decrements it; at 0 the hook makes the SDK call
  `COMPUTE_POINT` (op 9).
- **Hello**: a hook's first event makes `COMPUTE_HELLO` (op 8), which maps the cell. The hooks
  are hidden symbols, so each executable and shared library keeps its own copy and says hello
  itself; all get the one cell. Each hello notes the image that made it (the file the kernel
  maps at its system call; the program's own path when that is the executable) in the control
  region's image table (`proto::ctl::ComputeTab`, 32 entries, `starts` counting each process's
  first hello, and a count of starts that did not fit), which `result.json`'s `compute`
  reports. Op 9 before any hello gets
  `EINVAL`. A fork child keeps its parent's cell; an exec starts without one.
- **Arming**: at every return to program code the runtime writes into the cell the smallest
  of a seeded gap (uniform in `1..2G-1`, G the run's mean from `--fault compute-gap`), the
  events until the next deadline is due (a timer, a timeout, the wire, the time limit), and
  2^22 (`proto::compute::arm`). The last is the refill: an instrumented spin-wait yields in
  every setting, `compute-gap=0` included.
- **Charge**: at every runtime entry the runtime reads back how many events ran and charges
  each 1 ns of virtual time, which thread and process CPU clocks count too.
- **The point**: a hook that finds the cell empty enters the runtime, which writes a `preempt`
  record (`nr` 3: the address, the armed value, why it ran out (switch, deadline, refill),
  the process's events, the drawn gap; a hash of the general registers) and yields, so the
  supervisor fires what is due and a pending signal is delivered on the way out
  (`compute.rs`).

There is no other way into the runtime: a point that switches needs a supervisor hand-off
anyway, so a direct call would save nothing. With `--preempt branches` the cell is never armed
and events charge nothing.

**Python** (3.12 and later) needs no rebuild: `python3 -m patina SCRIPT` runs the script with
the SDK file's hook (`sdk/python/patina.py`, `compute()`) registered through `sys.monitoring`.

- **Events**: `LINE` and `JUMP`. A line start is a point between any two lines; a jump is
  every pass of a loop, which a one-line loop or a comprehension makes without starting a
  line. Branch events add nothing these do not, and calls and returns would cost more for no
  new place. Each costs one pure-Python call, 50 to 100 ns, against about 13 ns for the work of
  a plain line natively: that call is the cost, not the cell (docs/EVIDENCE.md).
- **The cell**: `COMPUTE_HELLO` with kind `COMPUTE_LINE` answers its address; the hook reads
  and writes it through a `memoryview` over that address, and makes `COMPUTE_POINT` through
  ctypes when it reaches 0. The hello comes from libc's `syscall`, so for this kind the image
  table notes the program (the interpreter), not the image at the call.
- **Charge**: each event takes `LINE_EVENTS` = 15 from the cell, so it costs 15 ns of virtual
  time and a gap counts in the same units as for rebuilt code. 15 is a fixed constant, about
  what a line of plain Python takes natively; it is not calibrated per host.
- **The GIL**: ctypes releases the GIL around a foreign call, so at a point the other threads
  can take it; when the seed switches, the thread switched to runs Python code, and the one
  that yielded waits for the GIL when it runs again. Releasing the GIL may wake a waiter with
  a system call before the point; that call is a scheduling point of its own, which charges
  and re-arms the cell, and the point after it then finds the cell full and does nothing. CPython's own switch request (a thread
  waiting for the GIL longer than the switch interval, 5 ms) is a timed wait in virtual time:
  stock, a CPU-bound thread never makes time pass, so the waiter never asks and the holder
  runs to its end or to `compute-stall`; with points it asks after 5 ms of events, as
  natively, at a time the seed decides.
- **Signals**: a signal due at a point runs its Python handler inside the hook. An exception
  it raises from a line's hook reaches the program at that line; from a jump's hook CPython
  3.12 and 3.14 would let it skip the frame's handlers, so the hook keeps it and raises it from
  the next instruction of that code (local `INSTRUCTION` events) in that thread.
- **Inert**: outside Patina the hello fails and nothing is registered. Under `--preempt
  branches` the cell holds `NO_LIMIT` after the hello and nothing is registered either.

A generator or coroutine resuming gets no point of its own: its next line or jump has one, and
the order of asyncio tasks is the event loop's, which a point in one thread does not change.

## The fault plan

`--faults`, `--fault` and `--crash` give the plan (`faults.rs`). A value given as a range is
resolved from the seed by a draw keyed by the setting's name, so adding one setting never
moves another's value. The resolved plan is in `run.json`.

Each fault decision is a draw keyed by the call's sequence number and the fault class, made
before the call (`patina-rt/src/inject.rs`). Turning one class on does not move another's
draws. An injected errno is one Linux returns for that call on that object
(`faults::errnos`). Every injected fault is a boundary record naming its object, and
`result.json`'s `faults` counts per class the calls it could act on and the faults injected.

Path swaps (`path-swap-permille`, `path-swap-at`; `patina-rt/src/swap.rs`,
`proto::swap`) stand in for another process of the same uid that changes the work tree
between a program's check of a path and its use. Each process keeps the hashes of the work-tree
paths named by its last 16 checks (`stat`, `lstat`, `access`, `readlink`, `open`). A use (`open`,
`exec`, `chdir`, a creation, removal, rename, link or attribute change by name) whose path is a
checked path or lies below one is eligible; the decision is drawn, keyed by its seq, before the
use's paths are resolved, so the kernel's walk and the policy see the swap. The draws pick a
component of the checked path below the work root and one of three mutations: it becomes a
symlink (to `/etc/passwd` or the work root's parent, to another entry of its directory, or to
nothing), another entry of its directory is renamed into its place, or it is renamed away. A
displaced original goes to `.patina-swap-SEQ` in its directory. Half the swaps (none
before an `exec`) are put back right after the call, as far as the call left the entries the
swap made. A path with a `..` component is not eligible: the kernel resolves it through what
precedes it, which the swap does not follow. The runtime makes each
step with its own calls in the guest process, relative to the component's directory opened with
`RESOLVE_NO_SYMLINKS` and checked to be on the work tree: the kernel applies the guest's
permissions and the sticky bit, a mount point refuses, nothing outside the work tree changes,
and a target outside is only a name. Each step is recorded like the program's own name change
(virtual times, an operation record, a crash point after it), so inode numbers and times are
the run's, a machine crash may lose part of a swap like any unsynced rename, and replay is
exact. The swap is an `Injected` record (`INJ_PATH_SWAP`: the mutation, the checking call and
its seq) followed by `Name` records for the path and the target, written once the swap is made;
a crash between two of its steps leaves those steps in the operation log and no `Injected`
record, and a mutation the kernel refuses falls back to the next (none: no swap, though the use
was counted eligible, so `path-swap-at` can miss).
Path swaps are in no preset: they model a concurrent writer the program may not be meant to
withstand.

The network wire: a TCP socket in the guest is a real unix socket whose peer the supervisor
holds (`sup/wire.rs`). The supervisor reads what each side sent, stamps it with a seeded
delivery time, and delivers it in virtual time. Delays, splits, resets, refused connects and
partitions are draws keyed by the connection and what they act on: a reset is drawn on each
piece of data a guest sends (so a long-lived connection meets one), a refusal or timeout once
per connect, a delay or split per delivery.

Datagrams (`sup/udp.rs`, `rt/sys/udp.rs`): a UDP socket in the guest is a real unix
`SOCK_SEQPACKET` socket whose peer the supervisor holds, one per socket and never shared
between sockets. Ports, addresses, connection state and options live in the shared socket
table like TCP's; ephemeral ports count up from 32768 in a port space of their own. A send
puts the payload on the socket and then tells the supervisor, which reads exactly that packet,
so a datagram is stamped at the send's virtual time and never waits in a kernel buffer. The
supervisor draws its fate and a delivery time (the `net-delay-ms` range, each datagram on its
own, so datagrams reorder within the jitter), and at that time routes it to the bound socket
that matches best: a connected socket whose peer is the source, then a specific address, then
the socket's own family (a v6 wildcard receives v4 unless `IPV6_V6ONLY`). A `SO_REUSEPORT`
group picks by a hash of the source; otherwise the socket bound last wins. A delivery is a
16-byte header (source, length) and the payload; the runtime reads the header into its own
buffer, so the guest never sees a unix address or credentials. A receiver whose queue is past
its `SO_RCVBUF` (charged per datagram at least what the kernel charges) loses the datagram, as
Linux does; the runtime uncharges as the program reads. A datagram to a port nobody holds is
lost, and a connected sender gets `ECONNREFUSED` on its next call (`SO_ERROR` reports it),
as the kernel's ICMP handling gives on loopback. Drop, duplicate, reorder (an extra hold beyond
the jitter) and partition (a datagram due inside a partition window is lost) are draws on
their own stream keyed by the datagram's id and the class, so enabling one class moves no
other draw. Every send, delivery and close is a decision record; replay compares them.
Multicast and broadcast destinations fail with `ENETUNREACH` (`udp:multicast-or-broadcast`
in `refused`), as do addresses outside the run. Names resolve from the sandbox's `/etc/hosts`
only (`hosts: files`, no `resolv.conf`): glibc and Python answer `EAI_NONAME` for an unknown
name, Go's pure resolver "no such host"; no resolver sends a datagram.

## The crash model

The runtime records every change to `/work` with its data in an operation log, along with
every sync (`patina-proto/src/oplog.rs`). Crash points follow each change and precede each
sync; each is counted (its ordinal is what `-at:N` names and what `crashes[].point` reports)
and the crash draw is used only when it fires, so a run is identical to the run without
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
the seed and the label. The payload's hash is the trap record's `in_hash`, and its label (a
mark's text too) follows the record in clear. A failed `always`, or a reached `unreachable`,
ends the run `violation`. Sites declared with a literal label are in an ELF section, so a site never reached
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

## Containment

The runtime shares a process with the program, so program code can reach the runtime's
memory and code. Patina contains an accidental or curious program (a stray store, a corrupted
function pointer, a library poking at addresses it found): such a reach ends the run
`unsupported`, stop `containment`, naming what was reached, the same on every repeat. It does
not contain a program that sets out to defeat the runtime.

Enforced:
- **System calls.** The seccomp filter lets through one instruction address, the `syscall` of
  the runtime's stub (`raw.rs`). A `syscall` anywhere else, the runtime's text included,
  traps; one there reached from program code ends the run.
- **The stub.** It checks after the call that it ran on a runtime stack (every runtime stack
  lies in the runtime's region; a program cannot map there). Program code that jumps to the
  stub runs on its own stack: the call reaches the kernel once, and the stub stops at `ud2`
  (`udf` on arm64) before any program code sees the result; the fault entry ends the run. A
  call that does not return (`exit_group`, a successful `execve`, `rt_sigreturn`) is not
  stopped by the check; an accidental jump makes one of those with the slim chance that `rax`
  (`x8`) holds its number.
- **The control region and the boundary log.** Their published addresses
  (`proto::layout::CTL_ADDR`, `LOG_ADDR`) are inaccessible reservations. The runtime maps them
  read-write at addresses drawn from the host at each image start (`state::map_shared`), which
  nothing reports (`/proc/self/maps` hides the runtime's region). The supervisor and the
  launcher have their own mappings.
- **System call arguments.** To the program the runtime's region (`[RT_BASE, RT_REGION_END)`:
  image, private memory and alternate stacks, both reservations and both drawn windows) is
  address space nothing is mapped in, as above the top of user space, so the kernel never
  reads or writes it on the program's behalf. Before a call the table passes, rewrites or
  answers is served, every pointer the kernel would follow is checked against the region
  (`guest::names_runtime`): each buffer the boundary record hashes (`Row::ins`, `Row::outs`)
  and every other pointer the row lists (`Row::refs`: iovec arrays and segments, a `msghdr`
  and its name, iovecs and control buffer, `mmsghdr` arrays, socket addresses through their
  length pointers, `select` sets and `pselect6`'s mask pair, `futex` words and timeouts,
  `execve`'s vectors and strings, and the arguments of `fcntl`, `ioctl`, `prctl` and
  `arch_prctl` their command reads), with the extent the kernel may touch (the length argument
  for a transfer, clamped to `MAX_RW_COUNT`). Only arguments the call reads are checked, as
  pointers and as descriptors (`nargs::live`, above): a register the call ignores may hold
  anything, an address in the region or a hidden descriptor number included. One that reaches the region answers `EFAULT`, the
  kernel's answer for a hole; the record is the call's as the program made it. A length rule
  without a pre-call extent cannot be written (`Len`), and `ins`/`outs` take only rules the
  log can hash, so a buffer is never logged without being checked. A buffer that starts in
  program memory and runs into the region is refused whole, where the kernel would move the
  first part. The check is made before anything else of the call, so a call the kernel would
  first have failed for another reason (except a hidden descriptor's `EBADF`), waited on, or
  consumed input for (a datagram dequeued before the copy faults) answers `EFAULT` at once and
  consumes nothing. It is made again after a park and after an injected delay, when other
  threads have run and may have rewritten an iovec or `msghdr`; otherwise only one guest
  thread runs and signals arrive at trap exits, so nothing changes between the check and the
  call. Calls on ranges there answer as for unavailable address space: `mmap` with a fixed
  address ENOMEM, `mremap` to it EINVAL and from it EFAULT, `mprotect`, `pkey_mprotect`,
  `madvise`, `msync`, `mlock` and `PR_SET_VMA` ENOMEM, `munmap` EINVAL; `mincore` is refused
  for every range. A parent-tid pointer of `clone` there is ignored, as the kernel ignores
  one it cannot write. The SDK channel's own copies (`process_vm_readv`/`writev` on itself)
  refuse the region the same way; the program's `process_vm_*`, `ptrace`, `userfaultfd`,
  `io_uring`, `shmat` and `rseq` are refused, and no `mem` file under `/proc` is reachable,
  by path or through the `/proc/self/task` directory (names relative to it are policed as
  `/proc/self/task/...`, and it cannot become the working directory: `fchdir` to it EACCES).
  A signal frame that would land in the region (an alternate stack placed there) is SIGSEGV,
  as for a frame the kernel cannot write. The runtime's own reads and writes of program memory go through its guest
  copy (`guest.rs`), which refuses the region too, except reads of the calling thread's
  runtime stack, where handlers keep arrays they built; a pointer the program passes never
  reaches those, since the check refused the call first. Cost: a few comparisons per pointer,
  and for iovecs and `msghdr`s one fault-safe read per entry; a call with no pointer pays a
  slice-length test (`costs getppid` and `costs pipe` within run-to-run spread, EVIDENCE).
- **The compute-point cell** is program memory outside the runtime's region, read and written
  by the runtime only through its fault-safe guest copy. A program that writes it changes only
  when its own process's next compute point comes and how many events it is charged (at most
  the value last written, so at most 2^22 ns per runtime entry), the same in every run; one that
  unmaps or protects it ends the run `unsupported`, stop `compute-cell`. A system call that
  writes it (a `read` into it) is such a write. The arm64 signal restorer page is program
  memory too (read-execute, listed in `/proc/self/maps`): a call reading it reads its two
  instructions, one writing it gets `EFAULT` as for any read-only page.

Detected:
- A program access that faults in the runtime's region (at a published address, in an unmapped
  part, or a store into its text), and program code running runtime code (a jump into its
  text), end the run with the address, the instruction, and for the control region the field
  (`sup/contain.rs`). A program that probes addresses with its own SIGSEGV handler and walks
  into the runtime's region therefore ends the run there, where natively its handler would run.

Out of scope (a deliberate attack):
- Finding the read-write mappings (reading the runtime's memory with the program's own loads,
  or probing about 2^23 pages of each window) and storing there. Storing into the runtime's
  own data and per-thread state (its `.data`, and the base of its alternate stacks, which stay
  writable because the kernel writes signal frames there): they sit at fixed addresses no
  program is given. Reading the runtime's text and data with the program's own loads is not
  detected (a system call cannot read them for it: above).
- Pointing the stack pointer into the runtime's region before jumping to the stub, or
  `rt_sigreturn` through the stub with a forged frame.

Write protection that switches at every trap (`mprotect` on entry and exit) was measured and
rejected: 1.3 to 7.8 µs per pair against a trap of about 1 µs (docs/EVIDENCE.md).

## Limits

- **Linux x86_64 and arm64.** No macOS. bwrap and unprivileged user namespaces
  are required. arm64 needs Linux 6.12 or later (the counter-timer trap), 4 KiB pages, a
  48-bit address space and one CPU model among the CPUs a run may use; `patina doctor`
  refuses a host without them. Also refused there: an SVE vector length above 512 bits, and a
  run that uses SME's streaming mode or ZA (`signal-context`). A program cannot enable MTE or
  guarded control stacks (their `prctl`s answer `EINVAL` and are recorded) or allocate a
  protection key (`pkey_alloc` answers `ENOSYS`); `FPMR` and `POR_EL0` are carried through
  signal frames. On arm64 every system call is served as on x86_64 (the
  structure layouts and flags that differ are in `proto::abi`, the argument orders in `arch`);
  branch counters work on the Neoverse N2 only (above, "Counter preemption"), and
  `patina doctor` checks the host's arm64 requirements. Threads, fork,
  vfork, exec and signals work as on x86_64 (the clone trampoline is in
  `arch/aarch64/thread.rs`); so do the instruction channels, pause points and spin probes
  (above), and the
  four SDKs and compute points (the SDKs' raw call is `svc #0`; Go's hook is
  `go/patina/compute/compute_arm64.s`). The
  runtime's loader maps a BTI-marked static program, or the interpreter, `PROT_BTI` as the
  kernel does where the host has BTI; the interpreter does it for the program and its
  libraries. The runtime disables the pointer-authentication keys before
  anything else at every image start (`arch/aarch64`): the kernel enables and redraws them at
  each exec. `PR_SET_TSC` makes the counter-timer reads (`CNTVCT_EL0`, `CNTVCTSS_EL0`,
  `CNTFRQ_EL0`) fault, answered from virtual time; `CNTPCT_EL0` raises `SIGILL` natively and
  under Patina alike. CPU features reach the program as the host has them (`AT_HWCAP`,
  `AT_HWCAP2`, `AT_MINSIGSTKSZ`, the `Features` of `/proc/cpuinfo`), as `cpuid` does on x86_64:
  two hosts of the same kind give the same run. Three are hidden: `PACGA` (its key cannot be turned off and
  is redrawn at each exec; a program that executes it anyway is labelled, `pacga_sites`);
  SME (with its ZA storage and streaming mode), so a program that asks before using a feature
  never enters SME state, whose contents and vector length are host-dependent; and `CPUID`,
  the kernel's emulation of the ID registers, whose `MIDR_EL1` names the core a thread runs
  on. A program that executes SME instructions or reads ID registers without asking is not
  stopped. Seeds and digests are per architecture and per kind of host: the host's own
  libraries and `/etc/ld.so.cache` are inputs of a dynamic program's run.
- **A seed reproduces for the same program binary and the same Patina build, on the same kind
  of host.** `run.json` records both binaries' SHA-256 (`patina` is the version and the hash of
  the `patina` binary); replay, minimize and `run --config RUNDIR/run.json` refuse a run whose
  either one differs, and a sweep into a directory another build made starts over. The kernel's own behaviour for passed calls is an
  input: a different kernel version or filesystem may change a run.
- **Branch counters** (`--preempt branches`) need `CAP_PERFMON`, a PMU, and a CPU checked
  exact: AMD family 0x1a (Zen 5), or on arm64 the Arm Neoverse N2; their seeds reproduce on the
  same family (core) only; on arm64 the core's variant and revision are not checked (the
  evidence is from r0p0). On arm64 an image's first segment, up to its first trap, is never
  preempted; code the scanner does not see (a JIT) keeps its native exclusive pairs, whose
  spurious failures can change the count (a hop walk that meets one gives up for that
  segment); more than 4,096 patched sites in one process stop the run.
- **compute-stall**: in stock code without branch counters, a spin-wait whose iterations
  change state ends the run (above).
- **Interleaving at system calls, pause points and spin probes only** in stock code. A race on
  plain memory with none of these between the conflicting accesses runs in one order in every
  seed. Rebuilding the code with compute points switches inside it; so does
  `--preempt branches`, on the CPUs checked exact. Compute points do not split an atomic
  read-modify-write (a `lock`-prefixed instruction; on arm64 an LSE instruction, an
  exclusive load/store pair, or the compilers' out-of-line atomic helpers, which are not
  rebuilt), gcc gives edges only, and code not rebuilt (libc, the Go runtime,
  prebuilt libraries) has no points. A seed found on a stock build does not replay on a
  rebuilt one, or the reverse. In Python (`python3 -m patina`) the points are at line starts
  and jumps: inside a line only CPython's own switch request switches, a bytecode-atomic
  operation (`dict.setdefault`, `list.append`) is never split, and C extensions and the
  interpreter's own C code have none.
- **Stock computation does not advance virtual time**: a CPU-bound loop cannot be cut by
  `--time-limit` or a program's own deadline, only by `--timeout` (wall time). A loop that
  makes any system call (a clock read) advances it by the per-trap charge. Rebuilt code is
  charged 1 ns per event (Python under `python3 -m patina`, 15 ns per line and jump) and cut at
  the event where a deadline falls due; branch counters charge per branch.
- **One thread runs at a time**, so weak-memory behaviours (a store another CPU sees late)
  never happen.
- **One machine.** All processes of a run share one sandbox, one disk and one clock. There is
  no simulation of several machines, and no network outside the run.
- **TCP and UDP only.** Raw, packet and netlink sockets, and `SOCK_DGRAM` with a protocol
  other than UDP, are refused and listed in `result.json`'s `refused`; `patina run` prints
  them. On UDP: multicast and broadcast (and their membership options), ancillary data on send,
  options that ask for it on receive (`IP_PKTINFO`, `UDP_GRO`) or change segmentation
  (`UDP_SEGMENT`, `UDP_CORK`), `MSG_MORE`, more than 64 iovecs in one datagram and `sendfile`
  to a UDP socket are refused; a receive carries no ancillary data and `MSG_ERRQUEUE` finds
  nothing.
  `recvmmsg` returns once at least one datagram is there. Names resolve from `/etc/hosts` only.
- **Fixed tables.** The runtime keeps some state in fixed tables shared by the run: virtual
  inode numbers of pipes, sockets and timers (16,384 per run, never reused), shared writable
  work-tree mappings (128 per process), shared mappings (256 per process), injected fsync
  failures (4,096 files). Filling one ends the run `unsupported`, stop `capacity`, naming it.
  The table of changed files' times drops the entries of deleted files nothing holds open
  (`sup/vtgc.rs`), so only files still reachable count against it (65,536).
- Not modelled: `timer_create`, scheduling policy calls, `io_uring`; another process's
  `/proc/PID`. docs/EVIDENCE.md has the full list.

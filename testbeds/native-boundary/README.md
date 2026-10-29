# Native boundary acceptance guests

Rust integration tests in `crates/cargo-patina/tests/` compile these guests.
Each guest's internal assertions and its harness assertions form the proof.

| Cargo test target | Proof | Platforms |
|---|---|---|
| `native_abi` | Prefixed C crash/checkpoint and env protocol; POSIX fd/env/path ABI; C stdio at the edges of a run (teardown, a refusal, the first write, a failed `assert`), its buffering modes and its character and positioning calls (`stdio_chars_probe.c`) and every character entry point, called and inlined (`stdio_entry_probe.c`), and the C++ standard streams over it, after libstdc++'s own constructor ran through interposed calls (`cxx_stdio_probe.cc`), against the host; pipe/socketpair wakeups; reactor fields and exact virtual deadlines; a registration from another thread waking a parked reactor (`reactor_register_probe.rs`, against the host); an epoll interest outliving its registered number (`epoll_alias_probe.rs`, against the host, Linux) | Linux x86_64 + arm64, macOS; epoll/eventfd Linux-only, kqueue/nsec Darwin-only |
| `native_containment` | Import/instruction refusals (thread-pointer writes included, and their `arch_prctl`/`modify_ldt` doors, x86_64), host env/envp isolation, dlsym routing, SUD arming/refusal, auxv, SIGSYS, TSC, real faults and handler protection; containment before every constructor (a shared library constructor's inline syscall/counter read and rseq CPU, `dso_ctor_escape.c` + `dso_ctor_probe.c`; kernel calls no interposer sees reaching the virtual kernel through syscall-user-dispatch: glibc's internal `getloadavg` behind a weak import and behind a shared library, and a library's inline syscall, while the main thread's attributes (`pthread_getattr_np`, from the host's `/proc/self/maps`) still name its stack, `glibc_internal_probe.c` + `glibc_internal_library.c`, Linux; a guest preinit entry refused, `preinit_entry_probe.rs`); the fixed address layout across seeded runs, recordings, replay and inherited stack limits, a guest's raised stack limit reaching the host, the shim refusing a layout the host randomized, the `--allow-randomized-address-layout` opt-out under a Docker-like seccomp filter (run, record, replay, campaign), layout-less traces replaying only as randomized, and a host stack limit stopping the run as the host's refusal (`address_layout_probe.rs`) | Both OSes; SUD/auxv/early init Linux; TSC/vsyscall x86_64 Linux |
| `native_workloads` | std, the virtual realtime epoch and node name (defaults, `--realtime-epoch`, `--hostname`), the virtual CPU count on every surface that reads it, from a constructor before Patina's startup too (`--cpus`, `cpu_probe.rs`), and from a per-CPU global allocator while the runtime spawns threads (`cpu_allocator_probe.rs`), an allocator (global and C `malloc`) whose held libc calls, and raw system calls where syscall-user-dispatch traps them, nest in the runtime's own calls, the C library's formatter inside the runtime's `printf` among them (`syscall-allocator`, Linux), independent entropy sources, locks/timers (a timer and a wait ending at one instant: interval timer vs `nanosleep`, timer descriptor vs `poll`, Linux; a mutex relocked before the first thread is a deadlock, Linux), thread names independent of the binary's file name (Linux), UDP/TCP, tokio signal driver + parking_lot + product-selected rustix backend, tokio TCP on current-thread, two-worker and default multi-thread runtimes (a delayed segment ends the reactor's park; a registration from another worker wakes it; the default runtime starts a worker per virtual CPU); Linux keyutils credentials (empty per-run rings, host canaries, password lifecycle); a mapped file's page cache whole under filesystem short-read and error faults, at the first mapping and after an in-process crash (`mmap_short_read_probe.rs`, Linux); calls the kernel answers from the in-memory inode drawing no filesystem fault (`inode_read_fault_probe.rs`, Linux); the path walk drawing no filesystem fault, and a walked spelling drawing the stream a direct one does (`path_walk_fault_probe.rs`, Linux); calls that do no filesystem I/O answering alike with every filesystem operation faulted (`fault_plane_probe.rs`, Linux); path and directory calls racing another thread as one step (`path_race_probe.rs`, Linux); a timed wait's anchor recording no clock read, and a zero-timeout wait's deadline check recording one (`futex_anchor_probe.rs`, Linux); the sealed engine's host bindings all bound before `main` (`host_binding_probe.rs`) | Linux x86_64 + arm64, macOS |
| `native_raw` | Mixed raw/libc descriptor parity, legacy syscall aliases, exact virtual identity, soft refusals, prctl state/refusals, raw ppoll timeout writeback and pipe readiness | x86_64 Linux; unsupported SUD executes refusal assertions |
| `native_signals` | Linux C readiness EINTR/mask/timeout contracts, libc/raw signal state, sigwait retry and guest-abort finalization; Linux/macOS internal-panic ownership, catchable guest panics and process/sleep repeat/replay | Linux + macOS shared cases; interruption Linux-only; inline raw cases x86_64 Linux with SUD |
| `native_trace` | Whole-run std syscall containment and a planted host open through the same filter; explicit unsupported-ktrace policy | strace on both Linux architectures; static containment evidence on macOS |
| `end_to_end` | `text_metadata_probe.rs`: native-return assertion, declared executable-text metadata refusal, and absent trace facts in the libtest result; portable import-refusal companion. `address_leak_probe.rs`: a guest whose failure token or recorded file write comes from its host-randomized stack address (campaigns run it under `--allow-randomized-address-layout`), and deterministic twins, for campaign reproduction verification (`NONDETERMINISM`) | Metadata Linux x86_64; import refusal Linux + macOS; address leak Linux |

All seven targets run in `mise run check` and the workspace-test CI jobs:
Linux on both architectures and macOS, all on the pinned toolchain.

```sh
mise run check:native-abi
mise exec -- cargo test -p cargo-patina --test native_abi pipes_and_socketpairs_wake_alias_and_refuse_to_block
mise exec -- cargo test -p cargo-patina --test native_containment rdrand_is_refused_on_every_kernel
mise exec -- cargo test -p cargo-patina --test native_workloads condvar_waits_use_exact_virtual_deadlines
```

`check:native-abi` selects the ABI target; Cargo's test-name filter selects one
behaviour. `end_to_end::native_build_package_audits_records_and_fails_closed`
owns package/path-dependency/build-script/ambiguous-bin coverage in the full gate.

## Builds and assertions

`tests/common` owns CLI invocation, concurrent output capture with process-group
deadlines, compiler selection and shim-object compilation. `common/native.rs`
provides explicit assertion helpers. Record/replay checks compare full stdout,
two complete traces, flag-free replay, and a mismatched-fingerprint refusal.
Entropy sources vary independently. POSIX startup sees host canaries so an
empty guest `environ` demonstrates isolation, not an empty input environment.
`initial_stack_env.c` is the startup-layout class detector: it walks from argv
rather than trusting `environ`, compares the exact requested map and pointer
identity, then checks Linux auxv against libc or Darwin's apple-string vector.
The launcher tests cover empty, single-entry and many-entry maps, repeats and
flag-free replay. Direct reserved launches measure this binary's actual trailer
and exercise zero, one and many surplus slots. Short-capacity and invalid-marker
refusals have sufficient-capacity and valid-marker positive twins that exit 42.
An unreserved nonempty map refuses; the same map with a reservation succeeds.
`envp_probe.c` separately retains the unreserved direct protocol's empty-envp
contract (no initial-trailer guarantee). These tests are enabled on macOS;
macOS arm64 execution is pending landing verification.

`rand-rng/`, `tokio/`, `tokio-tcp/`, `raw/`, `syscall-allocator/`, and [`keyring-keyutils/`](keyring-keyutils/README.md) are locked standalone packages. The build
helper explicitly places their Cargo artifacts under the integration test's
target base, beside the profile (`native-guests/<package>/`), including plain
`cargo test` runs without an inherited `CARGO_TARGET_DIR`. No package-local
`target/` directory is used. Single-file guests inherit the caller's shim build
location without an override.
Tokio supplies no rustix configuration override: the product selects raw on
SUD targets and injects `rustix_use_libc` elsewhere.

`mise run check` and CI run the FIFO workload everywhere and the
rustix-default/cap-std/go-guest workloads on x86_64 Linux, where missing SUD
fails both the Rust tests and those testbeds.

### Polling on a sleeping peer

`poll_clock_probe.rs` polls a non-blocking UDP socket, reading the clock between
attempts, while its peer sleeps 1 ms and then sends. `poll_sleeper.rs` polls the
same way without reading the clock. Their result lines are the same natively and
under Patina, where every receive is charged and the empty ones are escalated,
so virtual time reaches the peer's deadline.
`yield_wait_probe.rs` only yields, waiting on a 10 µs sleeper and then on a 10 µs
`ITIMER_REAL`: each yield's scheduling point shows the time the yields cost.
`prof_park_probe.rs` (Patina only) blocks on the receive that completes a poll
streak with only an `ITIMER_PROF` pending: the escalation that receive earned
reaches the timer before it parks, and the signal interrupts it.

### Call-free compute

`compute_watchdog.rs` plants main- and worker-thread atomic spins with a runnable
peer, plus spins that hold the guest allocator with scalar-only, byte-bearing,
and overflowed recordings. They detect allocating or deallocating during stop
export, including base64 helpers and overflow-error construction. `overflow-held`
uses 25 eight-MiB results to exceed the real base64-encoded trace budget and must
report a named infrastructure refusal without inventing a replayable prefix.
`custom-spin` stops inside an open custom perform; replay must stop at the
committed prefix before requesting its missing outcome. `handler-loop` and
`handler-alloc` prove SIGABRT registration, then install hostile behavior which
private termination must never call. `sync-buffer` leaves C stdout buffered
before the custom begin that stops synchronously on replay; the refusal must
salvage it without enabling callback salvage on the asynchronous path. `single`
first spawns and joins a trivial peer to arm the observer. It and `parked` run
long compute with no runnable peer (the latter uses a mutex/condvar handshake,
never a synchronization sleep). `finite` keeps a peer runnable while doing
finite call-free work: it must complete below a bound as long as the test's
deadline, however loaded the host, but recording with a short bound and
replaying with a long bound must both stop. A partial stderr line before peer
creation pins fresh-line diagnostic framing even if the run stops as soon as
the peer exists. `native_workloads` requires named known-limit findings, a nonzero
interrupted PC or explicit sampling deadline, and valid eligible terminal traces.
Synchronous replay stops explicitly report an unsampled PC (`synchronous-stop`).
Repeated recordings agree on overlapping decisions; host timing can stop each
at a different prefix, including before the intended spin. Each recording must
replay its own exact task/prefix despite a much larger host bound. The runtime
unit pairing independently proves the open-custom-perform case.

Specialized modes emit lifecycle receipts only after entering their hazard;
at least one of each mode's two recordings must contain its receipt. Early
stops still replay correctly, but two such stops are not hazard coverage.
The guarded small-stack receipt is a write from the switched stack through SUD.
An isolated real-host sampler unit detector additionally requires an
authenticated nonzero PC; permanent delivery failure cannot pass as expiry.
A comparative 25/4,000 ms detector rejects fixed-timeout implementations without relying on a
generous absolute ceiling; replay retains a generous 12-second ceiling. The
Linux x86_64 `small-stack` mode exercises sampling on a guarded 2 KiB stack.
These are runtime-limit tests, not host-equivalence claims or proof that every
no-boundary interval is CPU computation.

### Self-signal delivery

`signals/self_raise.c` checks main/worker self targeting, ignored generations,
reset/nodefer handlers, modeled writes from handlers, default termination and
record/replay identity. `native_signals` pairs it with the Rust watchdog guest's
clean audit: an unrecorded host-only raise fails the generation-event assertion,
and a missing interposer leaves an import. Darwin additionally refuses deferred,
siginfo and reserved delivery; no host sender information is admitted. The
watchdog's `raise(6)` registration probe remains unchanged on both platforms.

### Libc timers

`signals/libc_timers.c` exercises Linux interval timers, POSIX timers and
timerfds through public libc names and the static glibc archive aliases. The
`native_abi` test requires virtual SIGALRM delivery, timerfd expiry, byte-identical
same-seed traces and replay. SIGEV_THREAD callbacks refuse by name. On Darwin
the same guest drives named refusals for setitimer, getitimer, alarm and ualarm;
there is no claim of virtual scheduled signal delivery there.

### Small signal stacks

The shim's signal frames are private (ARCHITECTURE, Private signal frames): a
delivery takes a fixed few bytes of the stack its handler runs on (x86_64: a
16-byte slot and a return address), and a trapped raw syscall none. `small_stack_probe.rs` makes raw syscalls with the
stack pointer at the top of a 2 KiB stack, on two threads, under `--record` and
replay, and reports every byte written below it. `signals/small_stack.c` runs
handlers sent from a 2 KiB stack on the alternate stacks they registered.
`signals/frame_size.h` measures what a delivery takes of a large, aligned
alternate stack (natively the kernel's frame) and restores the previous action,
mask, and registration; `segv_routing.c` and `counter_small.c` add their
intended headroom to that measurement, clamped to the kernel's `MINSIGSTKSZ`,
aligning the final top down. `AT_MINSIGSTKSZ` can include unrequested AMX tile
state and is only a diagnostic, not a sizing oracle. The `frame-size` and
`route-cost` cases and the CI test summary report the native and shim
measurements and CPU flags. The native runs prove the small handlers fit; the
shim runs must print the same.

## Executable-section metadata refusal

`text_metadata_probe.rs` places neutral REX-prefix-range bytes after a return
but **inside the function's declared `.size`**. Its native test calls `probe()`
and asserts the function returns 42; the Linux x86-64 instruction audit refuses
the unreachable data as `undecodable-instruction`. The `end_to_end` target's
`native_harness_audit_refusal_does_not_advertise_a_trace` test owns this limit
and asserts the result has no trace facts, even with an older file present.
Its portable class pairing is `native_harness_import_refusal_has_no_trace`.

Data outside declared functions is a different case: symbol-bearing ELF
sections may omit inter-function gaps. The positive counterpart is
`native_source_builds_preserve_auditable_code_boundaries`, which audits and runs
that layout, including an internal NOTYPE label bounded by its function's end.
Neither case justifies skipping undecodable bytes inside a range; see the
escape taxonomy for the metadata policy and residuals.

## Coverage boundaries

Syscall conformance owns host-equivalent fd/fs/readiness semantics, including
pipe alias lifetimes, duplex socketpairs, creation permissions, FIFO transfers,
and zero-flags epoll/eventfd readiness with exact userdata. The raw readiness
probe also runs explicitly in x86_64 Linux CI. Oracle expectations currently
exist only on x86_64 Linux; portable ABI tests, scheduler park/wake tests and
exact virtual deadlines remain separate. No pending or whole-probe divergence
is credited as native acceptance evidence.

The class-level checks are the import/instruction gates, the seal's gate,
`native_trace`'s planted whole-run escape, host-oracle probes and runtime
scheduler/clock/trace invariants. Patina-specific identity/ENOSYS/auxv pins do
not claim host equivalence.

The std tracing filter has a narrow loader contract. Cargo's injected
`LD_LIBRARY_PATH` is removed for direct guest exec; no extra directory accesses
are allowlisted. Conformance has its own broader signal/process filter.
A missing strace fails the Linux trace tests. macOS has no whole-run trace test
because ktrace lacks decoded paths and a usable initialization boundary. Unsupported tracing is visibly
reported, not claimed as runtime containment. Unsupported SUD/TSC capabilities
execute pre-run refusal assertions. The SUD-only vDSO property reports missing
evidence without building a substitute guest; requiring SUD makes absence fatal.

# Patina Implementation Plan

This plan turns the architecture into independently verifiable vertical slices. Status labels describe the repository, not the long-term design.

- **Complete**: implemented and covered by the corresponding `VALIDATION.md` gate.
- **Partial**: useful code exists, but the gate is not complete.
- **Planned**: no supported implementation exists yet.

| Slice | Scope | Acceptance | Status |
|---|---|---|---|
| 1 | deterministic Rust-level execution (drivers, trace, CLI) | V0–V1 | Complete |
| 2 | scheduler, SimNet, wrappers, branching, async executor | V2 | Complete |
| 3 | WASI Preview 1 target | V3 | Complete |
| 4 | native Rust target: interposition, audit gate, threads, reactors, yield-points, SUD | V4 | Partial |
| 5 | trace hardening/migration, crash FS, host capture, minimization, allocator support | V5 | Partial |
| 6 | cooperative-SUT (buggify) SDK, native + WASI parity | V6 | Partial (Milestone C) |
| 7 | directed exploration policies (PCT, swarm, starvation) | V7 | Partial (wave 12) |
| 8 | liveness/converge watchdog + `cargo patina campaign` | — | Partial (wave 13) |

Related: [`USAGE-MODES.md`](./USAGE-MODES.md) describes the three implemented
usage modes — the production-safe SDK (`patina-dst`), the shim-backed
application harness (`patina-dst-harness`), and the explicit-context API
(`patina-dst-runtime`).

## Slice 1: deterministic Rust-level execution — Complete

Acceptance level: V0 and V1.

### Workspace and contracts

- Create a Cargo workspace with separate ABI, driver API, driver, trace, runtime, facade, and CLI crates.
- Define serializable effect operations and outcomes in `patina-dst-abi`.
- Keep concrete construction APIs out of `patina-dst-driver-api`.
- Represent denied and missing effects with stable, typed error codes.

### Initial deterministic drivers

- Implement `SeededEntropy` with a specified SplitMix64 byte stream.
- Implement `VirtualClock` with monotonic and deterministic realtime clocks.
- Implement `MemFs` with deterministic handles, file contents, cursors, and errors.
- Do not add host passthrough fallback.

### Trace and replay

- Store versioned JSON trace bundles containing metadata and a `main` timeline.
- Record typed boundary operation/outcome pairs with contiguous sequence numbers.
- Reserve record paths and reject active or existing writers instead of combining or overwriting traces.
- Write bundles through a same-directory temporary file and atomic rename.
- Strictly reject malformed bundles, fingerprint mismatches, operation mismatches, deterministic outcome mismatches, and unconsumed events.
- In replay, return recorded entropy and clock observations; execute deterministic filesystem mutations and compare their outcomes with the trace.

### Runtime and facade

- Build a runtime from explicit configuration or the CLI environment protocol.
- Install deterministic default drivers for `patina_dst_runtime::run`.
- Expose primitive filesystem, clock, and entropy effects through `Context` plus `read_file`/`write_file` conveniences.
- Finalize recording/replay on both successful closures and closures returning a Patina error.
- Return errors when a requested capability has no installed driver.

### Cargo command

- Provide the `cargo-patina` binary.
- Support `run` and `test` (`--seed`, `--record`, seed-driven fault knobs) and the `replay` verb (strict or branch-append), forwarding all other `run`/`test` arguments to Cargo.
- Compute a SHA-256 compatibility fingerprint over Patina version, Rust identity, Cargo command arguments, workspace Rust/Cargo inputs, and `Cargo.lock`.
- Pass experiment settings to the child through documented `PATINA_*` variables.
- Add an independent-package end-to-end test and a runnable example.

## Slice 2: scheduler and richer simulation — Complete

Acceptance level: V2.

- Scheduler ABI operations route explicit spawn, choose, yield, park, wake, and completion through `DetScheduler`.
- `SimNet` provides bound datagram endpoints, delivery queues, timing, reorder, partition, routing, and close state. The seeded fault knobs (`--net-jitter-nanos`/`--net-drop-permille`) act on BOTH the datagram path (jitter reorders, drop loses — lossy UDP) and the TCP stream path (per-segment delivery jitter, and a "drop" as a reliable-transport retransmit — a bounded RTO-style delivery delay that never loses data and preserves in-stream byte order). A default-on vacuity diagnostic (`PATINA_NET_FAULT_REPORT`, the `NetDriver::fault_report` surface) fires a loud warning when the knobs could perturb delivery and fault-eligible traffic occurred yet no fault effect landed — catching the class where a fault knob is silently inert on a code path (the analogue of the vacuous-schedule diagnostic).
- Seeded fault and latency wrappers compose around the network data plane.
- `FaultFs` composes above `CrashFs` for rate-based filesystem errors
  (`--fs-error-permille`, choosing EIO/ENOSPC/EINTR per eligible op) and short
  read/write injection (`--fs-short-permille`), with a default-on
  `PATINA_FS_FAULT_REPORT` vacuity diagnostic that also breaks each class's
  applied effects down by the operation kind that absorbed them
  (`errors_by_op=`, `shorts_by_op=`). Filesystem latency
  (`--fs-latency-nanos MIN..MAX`) is applied instead by the `Context`, the one
  component that owns the clock, before each eligible operation executes; it
  reports its own vacuity class through the same line.
- DNS is a full fault domain with no driver: `Context::dns_resolve` resolves the
  run's `--dns-entry` host table as a recorded boundary operation, and
  `--dns-fail-permille` / `--dns-latency-nanos` act only on the names that table
  DEFINES (an undefined name is NXDOMAIN by semantics, so it is never a fault
  opportunity). Per-class vacuity is reported through `PATINA_DNS_FAULT_REPORT`,
  which the campaign classifier reads as `VACUOUS_DNS_FAULT`. The table has three
  entry points onto one `RuntimeConfig` field: the CLI `--dns-entry`, the harness
  builders (`dns_entry` pins a name, `dns_service` allocates `10.0.0.N` in
  registration order and skips addresses an explicit entry claims), and
  `campaign --dns-entry`, which records the table in the out-dir spec, forwards it
  to every generation, and is what makes the `--faults` DNS band non-inert.
  wasip1 has no resolution surface, so the WASI family refuses the `--dns-*`
  flags — a declared family exception, not an omission.
- Runtime traces cross scheduler, network, clock, filesystem, and entropy effects.
- Trace format 2 stores branch relationships and seeds, resolves inherited decisions, and supports exact-prefix/new-suffix execution.
- CLI controls replay timelines, branches, and step budgets.
- `cargo patina minimize` runs an external failure oracle against unbranched main timelines or leaf branch suffixes.
- `cargo patina minimize --generation N` reduces a recorded campaign generation, fault-knob vector first: each candidate is a fresh seeded `run` of the artifact the campaign swept, so the result is a standalone reproduction command written into the out-dir, and the trace phase then delta-debugs a trace recorded from that minimal-knob run. Its oracle is patina's own and its target is auto-derived: the campaign recorded which verdicts that generation reported (`campaign-state.json`, `patina.campaign.state/v2`), and a candidate still fails only when its replay reports every one of those failure verdicts by `(kind, label)` AND did not diverge. `--marker TEXT` overrides the target for a guest that reports nothing through the verdict ABI; a generation with neither is refused by name rather than reduced against a guess. That built-in oracle is what makes concurrent candidate evaluation (`--jobs`) sound: each replay is virtualized into its own temp directory, so two candidates cannot interact. An external oracle stays serial unless `--jobs` opts in.

CLI key/value parameters are exposed through `Context::param`, typed driver setup is available through `patina_dst_runtime::run_with`, and `cargo patina explore` runs bounded independent-process seed campaigns. Named scenario profiles remain a future experiment-plane convenience.

The `patina-dst-async` crate builds a deterministic single-threaded futures executor over these same recorded operations: `block_on`/`spawn`/`JoinHandle`/`yield_now`, virtual-time `sleep`/`sleep_for`/`sleep_until`/`timeout`, and async TCP and UDP futures. It adds no new boundary operations — task creation, interleaving, parking, waking, yielding, completion, clock reads, and every net effect route through the existing `Context` recorded ops, so record/replay stays byte-identical. The executor makes exactly one recorded scheduling decision per poll: leaf futures perform their recorded effect, register an interest or deadline on the current poll scope, and return `Pending`, while an executor-internal FIFO wake queue (deduplicated per task) is drained into recorded `TaskWake`/`TaskYield` at fixed points. Timer futures ride the virtual-clock timer queue and its deadlock rescue (`task_park_timed` plus rescued `SleepUntil`/`TaskWake`); net futures translate would-block outcomes into interest registration plus a `NetNextDelivery` timed park, so wrapper-added latency stays visible. The surface is used directly from `patina_dst_async` (`block_on`, `spawn`, the TCP/UDP futures) over a `patina_dst_runtime::Context`, and `crates/patina-async/examples/async_echo.rs` runs a seeded TCP echo. Native interposition of third-party async runtimes (tokio under the shim, via the interposed kqueue/epoll readiness reactors) is a separate concern delivered in Slice 4.

## Slice 3: WASI target boundary — Complete

Acceptance level: V3.

1. Pin the target/interface to Rust's `wasm32-wasip1` Preview 1 target.
2. Add WASI support to `cargo patina build --target wasi`, `audit`, and `run`.
3. Audit Wasm imports fail-closed against the host's explicit allowlist.
4. Implement every allowlisted Preview 1 import (46 functions): arguments, environment, virtual clocks, entropy, regular files/directories, hard links, symlinks, metadata and timestamp mutation, descriptor flag/rights mutation and renumbering, seek/positioned I/O, allocation/advice, polling, configured datagrams, captured stdio, yielding, and exit through Wasmi guest memory. File metadata reports real inode identity and link counts from the driver.
5. Preopened-directory policy: `run --preopen GUEST[:ro|:rw]` mounts guest directories with host-enforced read-only or read-write policy; the first explicit preopen replaces the implicit read-write root.
6. Unified fail-closed resource limits (memory pages, descriptors, preopens, path bytes, I/O bytes, iovecs) with `--max-*` CLI overrides; Wasm fuel and Patina boundary-operation budgets bound execution.
7. Fingerprint Wasm bytes plus guest argument, environment, socket, preopen, and overridden-limit configuration in domain-separated sections.
8. Verify real Rust filesystem/time, datagram, hard-link/symlink/readlink, and set-times probes across seeds, record/replay, and branching in `scripts/validate-wasi.sh`.

Deliberate semantic limitations (documented behavior, not open gaps):

- `sock_accept` and `proc_raise` return `NOSYS` by design: Preview 1 has no listen surface, and the native signal model is not exposed by the WASI host.
- Symlinks are inert leaf nodes: terminal follow is one hop (then `ELOOP`); intermediate-component traversal is a deterministic `NOTCAPABLE` error.
- Unlinking a file that is open is denied across all names of a multi-link inode (a documented POSIX deviation).
- `APPEND` set after open is honored through a traced seek-to-end before each `fd_write`; `fd_pwrite` ignores `APPEND`.
- Read-only mounts are host-enforced; descriptor rights masks are advisory defense-in-depth.
- Memory growth beyond the configured cap is a deterministic trap rather than a `-1` grow result.

## Slice 4: native Rust target — Partial macOS/Linux foundation

Acceptance level: V4 is not complete.

Completed foundations:

1. `cargo patina` injects `cfg(patina)` and `cfg(dst)` into Cargo builds.
2. `patina-dst-native-shim` exposes prefixed filesystem, clock, entropy, sleep, crash, captured-stdio, and lifecycle ABI calls.
3. The opt-in POSIX C layer exports `open/read/write/writev/readv/pread/pwrite/preadv/pwritev/close/dup/lseek/fsync/ftruncate`, `fcntl` record locks (and `flock`), namespace/stat calls (Linux `statfs`/`fstatfs` as one constant virtual volume), clock/sleep calls, and entropy calls (including Darwin's `CCRandomGenerateBytes` and `F_FULLFSYNC`) without host fallback. Startup snapshots the private `PATINA_*` control plane for shim configuration, then scrubs the ambient environment and publishes a deterministic `environ` built from the guest env map (empty unless `run --env` supplied values). Guest-visible `getenv` and direct `environ` iteration read that one map, and `setenv`/`unsetenv`/`clearenv` mutate it and republish `environ` so the two readers stay coherent; `putenv` fails closed with `ENOSYS` plus a `patina:` diagnostic because its entry would stay aliased to caller-owned memory.
4. Linked macOS and Linux Rust probes execute ordinary `std::fs`, metadata, `SystemTime`, `Instant`, `thread::sleep`, printing, and standard-library entropy through the shim with cross-process seed stability; Linux large-file/stat variants and Rust's startup descriptor probe are explicit.
5. The trace control plane is separated from the interposed data plane: a supervisor-provided `PATINA_TRACE_FD` descriptor carries trace bundles through non-interposed host read/write aliases, so the fully interposed probe records and replays traces.
6. `cargo patina audit` is a strict per-platform import allowlist: after alias normalization (`$NOCANCEL`, `__`-prefixes), an import passes only if it is an explicitly listed effect-free host-deferred symbol for the binary's format (Mach-O or ELF; other formats are rejected) or is `--allow`ed by the caller — anything else fails closed as `unknown-import`, with known host-effect names still categorized (filesystem, network-or-wait, unmanaged-sync, and so on) for error quality. AArch64/x86_64 syscall and clock/entropy instruction scanning is unchanged. The shim's own control-plane symbols (trace-fd read/write aliases; the thread vehicle — macOS `pthread_create_suspended_np`/`thread_resume`/Mach-semaphore batons, Linux the real glibc `pthread_create`/`sem_*` batons resolved through the `dlsym(RTLD_NEXT, ...)` host-alias table) are deliberately not on the static allowlist: validation scripts `--allow` them per audited binary so unmanaged binaries importing the same symbols still fail. `run` additionally enforces this audit as a pre-run default-deny gate *before* the guest executes: it bakes in the shim control-plane vehicle (so ordinary shim-linked binaries run without repeating `--allow`) and hard-errors, naming, categorizing, and grouping symbols by recovered provenance — crate and containing symbol, plus the defining archive member on formats that record it (ELF does not, for global symbols; see crates/patina-target/ESCAPE-CLASSES.md), if the guest reaches any other blocking/time/scheduling/effect symbol that is neither interposed nor known-safe — so a missed interposer is a refusal, not a silent escape. `--allow-unsupported-symbols <all|name,...>` downgrades matching denials to a loud warning (recorded in a sidecar beside a `--record` trace, qualifying the determinism claim) for programs carrying unsupported surface the scenario never reaches. The deny/interposed/known-safe lists are organized by an explicit escape-class taxonomy (blocking/scheduling, time, entropy, thread-lifecycle, process, fs/net, shared-memory/IPC, signals/timers) with a per-class detection test and a coverage matrix in `crates/patina-target/ESCAPE-CLASSES.md` that is honest about the residuals symbol audit cannot see (inlined syscall instructions — covered by the Linux `strace` pass, absent on macOS; commpage/vDSO time; instruction-level entropy; `mmap` `MAP_SHARED`). The gate is calibrated to not false-positive on ordinary arg-reading `std` guests: `__NSGetArgc`/`__NSGetArgv` are known-safe (supervisor-controlled argv) and `confstr` is interposed to a deterministic value.
7. Native C and Rust escape fixtures verify successful controlled imports and rejection of direct syscall assembly/unmanaged threads.
8. `scripts/smoke-cross-target.sh` builds one ordinary-`std` smoke program for wasm32-wasip1 and the native host and verifies identical seeded, recorded, and replayed output across targets.
9. `cargo patina build <SOURCE.rs>` packages the shim link/startup integration: it builds the shim static library with the embedded POSIX layer and compiles a single Rust source with `cfg(patina)`/`cfg(dst)` and the required link arguments; `cargo patina run <BIN>` supervises execution through the documented `PATINA_*` environment and the `PATINA_TRACE_FD` descriptor. `build <DIR|Cargo.toml>` extends the same recipe to whole Cargo packages: it drives the package's own build as `cargo rustc`, injecting the cfgs through `CARGO_ENCODED_RUSTFLAGS` so every crate compiled from source sees them, and the shim link arguments as `cargo rustc`'s trailing arguments so they reach the guest binary's final link and nothing else (a dependency declaring a `cdylib` crate type links on its own and must not receive the shim — see `docs/bugs/shim-link-args-reach-dependency-cdylibs.md`). An explicit host `--target` keeps the cfgs off build scripts and proc macros, which link for the host without them, so their host-side I/O never routes into an uninitialized runtime. `--package` selects a workspace member and `--bin` selects among multiple binaries; missing `--bin` on a multi-binary package fails closed rather than guessing, and the produced binary audits and record/replays identically to a single-source one. Path dependencies and build-script outputs reach the deterministic binary unchanged.
10. Auto-initialization: a C constructor initializes the runtime from the `PATINA_*` protocol and `atexit` finalizes it, so ordinary programs need no explicit init calls; running outside the supervisor aborts fail-closed.
11. Managed threads: `pthread_create` is interposed by a strong def, and the real host creator is reached through a distinct non-interposed path (macOS `pthread_create_suspended_np` plus mach `thread_resume`; Linux the genuine glibc `pthread_create` resolved through the host-alias table's `dlsym(RTLD_NEXT, ...)`, so no `-Wl,--wrap=pthread_create` — which would clash with libgcc's own `__wrap_pthread_create` on x86). Real host threads are gated one-at-a-time by `DetScheduler` through a per-thread OS-semaphore baton with atomics-based shim-internal locking. Interposed mutex/condvar operations route contention through the scheduler, so a lock held across a boundary operation cannot deadlock. On macOS the baton uses a *Mach* semaphore, not a libdispatch one: the shim also interposes `dispatch_semaphore_create`/`wait`/`signal`/`dispatch_time`/`dispatch_release` because std's Darwin thread `Parker` (`thread::park`/`park_timeout`, and the `mpsc`/`mpmc` `recv`/`recv_timeout`, `Once`, and channel paths built on it) blocks on a libdispatch semaphore — routing the wait through the scheduler and virtual clock, with a deterministic tie-break (a runnable unparker's signal always beats a same-instant timer, which fires only via the deadlock rescue). The baton uses a distinct Mach semaphore precisely so it does not recurse into its own interposer; before this fix the Parker shared the baton's `--allow`ed `dispatch_semaphore_*` audit entry and escaped both the scheduler and the virtual clock silently. `sched_yield` (std's `thread::yield_now`, reached by the `mpsc` backoff) is interposed to a deterministic scheduling point rather than a host yield. `pthread_rwlock_*` is a real deterministic reader/writer lock (replacing the former `ENOSYS` stubs): writer-preferring, FIFO among writers, with blocked readers batch-woken when a writer releases and no writer waits — every grant a recorded scheduler decision. std's own `RwLock` reaches this only via the parking `Parker` on the supported toolchains (its contended `write` path is `lock_contended → thread::park → dispatch_semaphore_wait`), so contended `std::sync::RwLock` acquisition is already deterministic through the Parker; the `pthread_rwlock_*` interposers serve C guests and any std that lowers to them.
12. Native networking over `SimNet`: UDP datagrams and TCP streams are interposed for `AF_INET` sockets, both applying the configured base link latency (`--net-latency-nanos`) to delivery. One wildcard-bind routing rule (`wildcard_bind_key`, shared by the driver and the shim because each resolves addresses independently — the driver to route, the shim to know which parked task to wake) makes a `0.0.0.0:PORT` listener reachable at any address on that port, with exact match always preferred. DNS forward lookup is modeled: `getaddrinfo` resolves through the run's `--dns-entry` host table into the recorded `DnsResolve` operation and returns one heap-allocated A record (`freeaddrinfo` really frees it); undefined names are NXDOMAIN, `localhost` and numeric literals resolve locally, and `gethostbyname`/`getnameinfo` stay refused. UDP covers `socket`/`bind`/`connect`/`send`/`sendto`/`recv`/`recvfrom`/`getsockname`; TCP covers `SOCK_STREAM`, `listen`/`accept`/`connect`/`read`/`write`/`send`/`recv`/`shutdown`/`getpeername`, with wrapper forwarding for latency/fault layers. Sockets are fully virtual (zero network host imports); blocking recv/accept/send paths park through the scheduler baton; non-blocking sockets return `EWOULDBLOCK`; the setsockopt allow-list admits deterministic no-op socket options including `TCP_NODELAY`; IPv6 and DNS (`getaddrinfo`) fail closed with explicit errors. The native gate verifies this with `NATIVE_TCP_RESULT`. Deterministic process-state constants cover `getuid`/`geteuid`/`getgid`/`getegid` and common `sysconf` values. Process spawning stays a non-goal, enforced in layers (VALIDATION.md V4 and `crates/patina-target/ESCAPE-CLASSES.md` row e): the spawn family a real guest links (`fork`/`posix_spawn*`/`waitpid`/…) is deny-trap interposed (a guest that reaches it aborts deterministically, naming the symbol), `kill` is a deterministic-model interposer (signal-0 liveness probes get an honest single-process answer), and the unlinked remainder (`vfork`/`exec*`/`system`/`popen`/`killpg`/…) stays uninterposed so the audit rejects it.

13. Linux futex routing: Rust `std` on Linux reaches `Mutex`/`Condvar`/thread parking through raw `SYS_futex` via libc's `syscall` wrapper (not pthread), so the shim interposes `syscall` — `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` checks the futex word and parks the caller on the word's address through the scheduler baton (value check and park are atomic under the baton, so no wakeup is lost); `FUTEX_WAKE`/`FUTEX_WAKE_BITSET` wakes up to N parked tasks; every other syscall number fails closed with `ENOSYS`. `dlsym` is interposed so dynamic lookup can never return a host symbol: it answers from one curated entropy routing table (`getrandom`, `getentropy` → the shim's own internal-linkage deterministic implementations, the same code the static linker would have bound the caller to) and NULL for every other name, so std's optional-symbol probe still falls back to defaults. The table is load-bearing rather than a convenience: the `getrandom` crate resolves its Linux backend through `dlsym(RTLD_DEFAULT, "getrandom")`, and reads a NULL as "this kernel has no getrandom", demoting every dependency RNG (`rand::rng()`, and so any `ThreadRng` user) to its `use_file` fallback, which opens and `poll()`s the unmodeled `/dev/random`. Timed futex waits park with their deadline on the virtual-clock timer queue (item 15) and return `ETIMEDOUT` when the deadline fires before a `FUTEX_WAKE`.

14. Directory, symlink, identity, descriptor, and environment containment: the dirent family (`opendir`/`readdir`/`readdir64`/`readdir_r`/`closedir`/`rewinddir`) iterates driver-ordered snapshots with deterministic synthetic inodes, so ordinary `std::fs::read_dir` works; `symlink`/`readlink` and symlink-aware `stat`/`lstat`/`fstatat`/`statx` follow MemFs semantics (leaf metadata without following, one terminal hop then `ELOOP`, `AT_SYMLINK_NOFOLLOW` honored); `gettid` (Linux) and `pthread_threadid_np` (macOS) return deterministic scheduler thread ids. `dup`/`fcntl(F_DUPFD*)` duplicate MemFs/CrashFs descriptors through the recorded `FsDup` operation, sharing cursor and access flags with deterministic monotonic fd numbers; unsupported targeted variants (`dup2`/`dup3` to a different number), captured stdio duplication, and socket duplication fail closed with `ENOSYS` plus captured `patina:` diagnostics. `__res_init` still fails closed. The deterministic environment starts empty and remains isolated from the host; guest `setenv`/`unsetenv`/`clearenv` calls mutate its guest-owned map. On Linux, `native_trace::std_whole_run_and_planted_openat_use_identical_filter` adds a whole-run `strace` containment pass: outside an exact loader/std-runtime prelude (shared-object loads, `/proc/self/maps` stack introspection, control-plane descriptors 0-3, process-local memory and signal setup), no file, network, clock, entropy, or descriptor syscall may appear anywhere in the run — the seeded probe's guest section reaches zero host syscalls. macOS has no equivalent runtime gate: calibration established that `ktrace` (the only root-capable, SIP-compatible whole-run tracer) cannot found a sound default-deny check, so the macOS path skips loudly and `PATINA_REQUIRE_KTRACE=1` hard-fails on Darwin rather than reporting a check that cannot fail, leaving static instruction scanning plus import audit as the macOS containment evidence. Three independent, on-host-reproduced blockers: `BSC_*` events carry only raw register values, not decoded paths, so a guest's raw `open`/`stat` is indistinguishable by argument from the loader's libSystem prelude; the deterministic runtime buffers all guest output (stdout and stderr) into a single flush at process exit, so there is no in-band boundary marker to separate the pre-main loader prelude from guest code; and the loader/runtime issues the same syscall names an escape would (`open`, `fcntl`, `getpid`, ...) with init interleaved into early guest execution, so a name-scoped default-deny is either vacuous or false-positives on clean runs — a planted post-init raw `getpid` (inline `svc`) lands among the runtime's own `getpid` events, name-identical and not temporally separable.

15. Virtual-clock timer queue: the runtime `Context` keeps a timer registry ordered by `(monotonic deadline, registration sequence)` with at most one live timer per task, registered through the recorded `TaskParkTimed` boundary operation (realtime deadlines convert to monotonic at registration). When the scheduler would otherwise deadlock and timers exist, `scheduler_next` rescues: it advances the virtual clock to the single earliest deadline through the recorded `SleepUntil` path, wakes every due task in `(deadline, sequence)` order through recorded `TaskWake` operations, and retries — so replay re-executes the rescue from the trace and an empty registry still deadlocks explicitly. Any earlier wake deregisters the task's timer. Consumers: `pthread_cond_timedwait` and timed futex waits park with their deadline and learn timeout-versus-signal from the wake cause (the rescue purges the waiter from its primitive's queue and marks it timed out; the mutex is re-acquired before `ETIMEDOUT` returns), `nanosleep`/`clock_nanosleep`/`mach_wait_until` park timed under managed threads so other runnable tasks execute during a sleep (single-threaded programs keep the identical direct clock jump; the WASI host and explicit facade are unchanged), and a blocking UDP `recv` on an empty queue consults the new recorded `NetDriver::next_delivery` operation and parks until the earliest pending delivery, which makes non-zero link latency work end to end: `cargo patina run --net-latency-nanos N` (environment `PATINA_NET_LATENCY_NANOS`, rejected fail-closed when malformed) configures `SimNet`, and the latency wrapper forwards `next_delivery` so wrapper-added latency stays visible to the parking deadline.

16. Deterministic preemption for atomics-only race windows, with vacuous-schedule detection first. The cooperative `DetScheduler` only switches at interposed boundaries, so a race whose window is pure atomics — the classic read-modify-write on a `std::sync::RwLock` whose uncontended fast path issues no interposed operation — runs to completion between two boundaries and is unreachable at every seed (a spawned worker parks once at spawn, then runs its whole loop with zero interposed boundaries before the next worker starts). Two parts address this. **(a) Detection (default-on).** `Context` counts each task's scheduling boundaries, split into voluntary yields (every touch of the interposed effect surface reschedules) and blocking parks, maintained identically on record and replay because every task-lifecycle op runs on both; `Context::finish` emits a machine-readable `PATINA_SCHEDULE_REPORT` line (per-task `Ny+Mp`) to stderr for any multi-task run, plus a loud `PATINA WARNING` when a spawned worker completes without exceeding the thread-lifecycle scaffolding yield floor (spawning/joining a std thread costs a small fixed number of yields on its own; a worker at or below it performed zero interposed operations, so any loop it ran was atomics-only and its interleavings are unreachable). The floor keys on yields because they are seed-invariant where parks are not, and is iteration-count-invariant — a `lost-update` worker sits at the scaffolding floor whether it loops twice or a thousand times, exactly because the loop is invisible to the runtime. This is the mechanism that stops "N seeds explored, all clean" from silently meaning "nothing was explorable". **(b) Reachability.** `cargo patina build --yield-points` (default off) compiles the guest with LLVM SanitizerCoverage trace-pc-guard at basic-block granularity (`-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-trace-pc-guard -Cllvm-args=-sanitizer-coverage-pc-table`) and links a cargo-patina-embedded hook object whose `__sanitizer_cov_trace_pc_guard` saturating-increments the guard word before routing into the shim's `patina_yield_point`, forwarding each guard hit's call site so a divergence diagnostic can name the exact instrumented guest location. The same hook registers guard ranges plus LLVM pc-table ranges for shutdown coverage reporting and `patina.covmap/v1` dumps. `-Cpasses`/`-Cllvm-args` are *stable* rustc codegen flags, so this needs no nightly toolchain and no `RUSTC_BOOTSTRAP` (an earlier `-Zinstrument-mcount` route was rejected — function-entry only, so inlined hot loops get no hook, and it is genuinely nightly-gated); the only version coupling is to LLVM's internal pass name (`sancov-module`) and coverage cl::opts, stable across the LLVM releases rustc ships but not a rustc stability guarantee. The instrumentation is surfaced prominently: a `--yield-points` build prints a `PATINA_NATIVE_BUILD_YIELD_POINTS` line naming the mechanism and the fingerprint suffix. At run time, yield-point binaries emit a default `PATINA_COVERAGE_REPORT` line (suppress with `PATINA_COVERAGE_REPORT=0`), and native `run`/`replay --coverage-out PATH` writes a supervisor-owned `patina.covmap/v1` counter map through `PATINA_COVERAGE_FD`; plain binaries refuse `--coverage-out` with a rebuild hint. `cargo patina coverage <binary> <map|campaign-out-dir>` resolves those maps offline from the `patina_yield_point` anchor, demangles symbols, and reuses the shared crate/module rollup. Campaigns over yield-point native binaries automatically fold per-generation maps into `<out-dir>/coverage/{meta.json,union.bits,hits.u64le,sites.i64le}` and report plateau with `--plateau-after`. Because level-3 instrumentation reaches loop backedges, every iteration of an atomics-only loop offers the seeded scheduler a preemption point; the seed still drives *which* task runs at each point, so exploration is genuinely seed-varying. The source stays 100% std-pure and the instrumentation is inserted only on the Patina path — a plain native build never links the hook, so a plain-std guest's native build passes bit-identically. Determinism and replay hold per `(seed, binary)`: yield decisions consume the recorded scheduler stream, and `run` detects the hook's embedded marker in the binary and folds `+yieldpoints` into the compatibility fingerprint, so a yield-point trace fails closed (fingerprint mismatch, nonzero exit) rather than silently replaying against a plain binary or the reverse — proven end to end by `native_yield_points_trace_fails_closed_against_plain_binary`; existing plain traces are unaffected. The Part-1 diagnostic is default-on independent of this flag. One correctness subtlety the instrumentation forced out: pthread thread-local destructors run *after* `thread_finish` has completed a task, and `std::sys::thread_local::…::destroy` is generic std code monomorphized into the guest crate, so under `--yield-points` it carries the hook and would take a scheduling point on an already-removed task. The shim marks a per-thread *completed* sentinel in `thread_finish` and no-ops `sched_point` on it — kept deliberately distinct from the never-registered state, which still fails loudly, so the fix does not trade a foreign-thread detection for silence. A second forced subtlety sits on the JOINER's side: after the managed join resolves, std drops its `Arc<thread::Inner>` while the worker's still-exiting host thread drops the same `Arc` in its TLS teardown; whichever lands last takes the deallocating slow path, so under `--yield-points` the joiner's guard-hit count depended on host load (the op-742/12623 divergence on x86 Linux; a ±2-root-yield record/replay divergence under load on Darwin). `patina_thread_join` therefore reaps the worker's real host thread (host-alias `pthread_join`) on **every** platform before returning, making the joiner's drop deterministically the last reference. The failure class also has standalone detection: a replay whose scheduler stream diverges at a `TaskYield` fails with a classified `yield-point replay divergence` diagnostic — per-task record-vs-replay yield accounting plus the divergent instrumented site (reported as a stable offset from `patina_yield_point`, symbolizable offline via `nm`/`atos`/`addr2line`) — never the bare "trace ended before operation N" cursor error (`classify_yield_divergence` in `patina-runtime`; proven by `native_yield_points_divergence_reports_accounting_and_site`). Result on a two-thread lost-update guest: the race — previously unreachable at ~300 seeds — now trips its `BUG_CAUGHT` oracle at every seed under `--yield-points` (e.g. seed 3, `--iters 2`, trace SHA-256 `697d8d49c967127d…` identical across three records, replays exactly); the `deadlock` mode (interposed mutex loop) is correctly *not* flagged vacuous, and the plain `lost-update` build *is* flagged. Overhead: negligible build cost and, at the small iteration counts needed to surface a race, run cost remains startup-dominated. A Wave-A threaded four-worker measurement saw yield-points with counters+pc-table at 0.233 s median versus 0.230 s for the same yield-point hook with counters disabled (+1.7% incremental; plain no-yieldpoints in the same harness was 0.045 s), while the per-boundary cost still scales linearly with instrumented work as expected for cooperative preemption. **(c) Cost, and splitting the two jobs the flag bundled.** `--yield-points` does two different things at once: it maintains the SanitizerCoverage edge counters (what `--coverage-out`, `cargo patina coverage`, and `campaign --guided` read) AND it takes a full scheduling point at every one of those guards. The second job is what costs — each hit crosses into the shim, sets a thread-local site, takes the scheduler spinlock, and runs a `reschedule`. On a toy two-thread atomics-only probe that is 8.5 s against 0.28 s plain (~28x); on a real tokio guest (turso's `turso_stress`) it is well past 200x, which puts coverage-guided campaigns against such a guest out of reach even though the counters themselves are nearly free. `cargo patina build --coverage-points[=<STRIDE>]` (native-only, mutually exclusive with `--yield-points`) links a second hook translation unit, `patina_cov.c`, with the same instrumentation and the scheduler call made optional and sampled: bare, it is counters ONLY (the guest keeps exactly the boundaries a plain build has, so `--coverage-out`/`--guided` work at counter cost — 0.28 s vs 0.33 s on the probe, i.e. in the noise); `=N` takes a scheduling point every N basic blocks a thread executes, which BOUNDS the guest basic blocks between consecutive preemption opportunities by N — the property a narrow atomics-only window actually needs — at 1/N of the yield cost (probe: 0.30 s, 14 067 decisions against yield-points' 8.52 s and 7 200 325, and at stride 512 it caught the probe's lost update at seed 7 where the dense mode did not). Determinism: the countdown is `_Thread_local`, never shared, so it cannot depend on host thread timing; a managed task's basic-block stream between two scheduling points is a pure function of the schedule Patina chose, so the sampled site set is a pure function of the seed and replays exactly (a single shared counter would NOT be safe — teardown code on a completed task runs outside the scheduler's serialization). Recording: the stride is baked in through `-DPATINA_YIELD_STRIDE` (so it cannot drift from the binary, and `shim_object_hash` gives each stride its own content-addressed object), and it is stamped into the hook's marker string, which `run` reads back out of the image and folds into the compatibility fingerprint as `+covpoints:<N>` — so a trace never cross-replays against a different stride, against `--yield-points`, or against a plain build. `--starve`'s liveness precondition is relaxed accordingly: a sampled stride bounds the aging delay by N blocks instead of eliminating it, which is enough, so starvation on a `--coverage-points=N` binary no longer warns. Non-goals unchanged: no signal/ptrace preemption (host-nondeterministic), no raw-atomic interposition (impossible at symbol level).

17. Native async-runtime interposition: deterministic readiness reactors on both platforms, so stock tokio binaries run under the shim. A reactor-neutral core (per-fd readiness predicates over the in-process pipe/socketpair channels and `SimNet` sockets, a multi-fd fan-in park primitive on the baton, and UNRECORDED runtime inspections — `net_readiness`, `monotonic_now_unrecorded` — that are pure functions of recorded history and the virtual clock, so record==replay holds with no new trace ops) carries two thin frontends: macOS `kqueue`/`kevent`/`kevent64` (EVFILT_READ/WRITE/USER/TIMER, EV_CLEAR edge latch, refcounted registry dup for mio's `F_DUPFD_CLOEXEC` selector clone) and Linux `epoll`/`eventfd` (kernel-faithful ctl errno, mio's edge-triggered EPOLLET honored by an arrival-sequence latch so an undrained eventfd Waker write still re-fires, eventfd as the in-process counter whose read waiters double as the epoll wake queue). Pipe/socketpair endpoints are refcount-dup-able (tokio's signal driver clones its wakeup pair; EOF/EPIPE fire on last-close of a side). Entry points are syscall-shaped (`patina_epoll_*`, `patina_eventfd`) for a future syscall-user-dispatch handler. Unmodeled filters/flags and readiness on real host descriptors fail closed loudly. Guest package builds inject `--cfg rustix_use_libc` so rustix's default raw-syscall Linux backend becomes interposable libc imports (`openat64` joins the LFS alias family; raw-syscall binaries otherwise still fail closed at the instruction scan). Acceptance: a tokio + parking_lot + rustix guest passes the pre-run gate with no allowances, runs byte-identical per seed, and converges under record + flag-free replay on both platforms, exercised in `native_workloads::tokio_signal_parking_lot_rustix_use_product_backend`.

18. Syscall-user-dispatch (SUD), slice 1, Linux/x86_64: a guest's raw inline `syscall`/`svc` instruction — rustix's default linux_raw backend, hand-written asm — is trapped into the deterministic runtime via a `SIGSYS` handler instead of being refused. The shim arms `PR_SET_SYSCALL_USER_DISPATCH` with the allowed region = glibc's single executable segment and a NULL selector (so every syscall instruction *outside* glibc text unconditionally traps; there is no guest-writable selector byte and zero selector-toggle sites), at exactly two sites — the `__libc_start_main` interposer (main thread, before guest constructors) and every managed thread's trampoline (the config does not survive `clone`, so each thread arms once). The region is discovered from `/proc/self/maps` (real glibc `open`/`read`/`close` resolved through the `dlsym` host alias, never the interposed FS defs), failing closed on any layout that is not exactly one executable libc segment. The `SIGSYS` handler is synchronous-by-construction — the kernel rolls the instruction back and delivers it on the faulting thread at the syscall's own IP, semantically identical to the guest having called an interposed `read()` — so it decodes the number and six argument registers from the `ucontext` and routes into the **same** `patina_*` entry points the C interposers use (a reentry guard is the standalone RED detector for the "shim never traps while holding a runtime lock" soundness invariant). Slice-1 dispatch table: the clock family (`clock_gettime`/`clock_getres`/`gettimeofday`/`nanosleep`/`clock_nanosleep`), `futex` (sharing the libc-`syscall()` interposer's op decode), `read`/`write`/`openat`(AT_FDCWD)/`close`/`lseek`, `getrandom`, `sched_yield`/`gettid`, `exit`/`exit_group`; process-local anonymous `mmap`/`munmap`/`mprotect`/`madvise`/`mremap`/`brk` pass through to the host kernel via the glibc `syscall(2)` host alias (file-backed `mmap` is refused loudly); `set_robust_list`/`rseq`/`membarrier` return a deterministic `-ENOSYS`; `rt_sigprocmask`/`sigaltstack` are success no-ops and `rt_sigaction(SIGSYS)` is fatal; **every other number is a named, deterministic fatal abort** (the process/escape class and any un-tabled number). The vDSO escape is closed by scrubbing `AT_SYSINFO_EHDR` to `AT_IGNORE` in the initial-stack auxv, so a vDSO-resolving crate finds no vDSO and falls back to a raw syscall SUD then traps. The audit **downgrades** a `direct-syscall` *instruction* finding from refuse→run iff the binary defines the `patina_sud_dispatch` marker AND a live `prctl` probe says the kernel has SUD, reporting it relabeled `direct-syscall (SUD-managed)` — never silent; `cpu-nondeterminism` register reads stay refused. On a no-SUD kernel (notably arm64) or a no-marker binary the run is refused exactly as before, with a hint pointing at `--cfg rustix_use_libc` / x86_64. New hardening: on Linux `sigaction`/`signal` are interposed to forward every non-SIGSYS registration to the real glibc call (preserving std's stack-overflow guard) and refuse SIGSYS — a guest may not re-register the dispatch handler. `--cfg rustix_use_libc` stays injected (belt-and-suspenders on x86_64, the only answer on arm64). Same-artifact record/replay is byte-identical (SUD routes into the same `patina_*` boundary, so the trace is identical whether an effect arrived via SIGSYS or a C interposer). Slice 1 defers to slice 2: the full FS/network rows, dirfd-relative resolution, `sendmsg`/`recvmsg`, uname/pid constants, the committed rustix-default testbed, and the `sud:on/off` trace-metadata field (via the `guest_argv` `RunMetadata` pattern, SUD-DESIGN.md §7.3). The metadata deferral is sound **because slice 1 has no independent SUD toggle**: arming is a pure function of the binary's `patina_sud_dispatch` marker and the kernel probe — no env var, flag, or hatch turns SUD off for a marker binary — so the binary identity replay already verifies subsumes the metadata byte, and the replay-refusal decision #6 promises is delivered by the pre-run gate instead: `replay` of a marker-carrying raw-syscall binary on a no-SUD kernel refuses **pre-exec** (before the trace is even opened), naming the situation ("this kernel lacks syscall-user-dispatch"), proven by the no-SUD refusal leg (now `native_containment::raw_syscalls_are_virtualized_or_refused_before_execution`) on the arm64 VM. Introducing any such toggle makes the metadata field mandatory in the same change. arm64 (slice 3) lights up by a probe flip when generic-entry kernels ship — the number table is already arch-complete. Verified: x86_64 CI runs the positive battery (SUD-managed audit, seed-stable run, byte-identical record/replay, per-thread arming, unmapped-syscall abort, auxv canary); the arm64 VM RED-proves the refusal leg and the kernel-independent SIGSYS-hijack and marker-gating legs; the full macOS and 8-gate Linux batteries stay green.

19. Syscall-user-dispatch (SUD), slice 2 + kernel-independent slice 3, Linux/x86_64: the dispatch table is completed and the `rustix_use_libc` workaround retired on SUD-capable targets. New rows (all routing into the SAME `patina_*` entries the C interposers use — a second caller, never a second implementation): the full filesystem surface — `pread64`/`pwrite64`, `readv`/`writev` (iovec loop), `fsync`/`fdatasync`, `ftruncate`, `flock`, `dup`/`dup3`, `fcntl` (`F_GETFL`/`F_SETFL(O_NONBLOCK)`/`F_DUPFD`/`F_GETFD`/`F_SETFD`, and the `F_GETLK`/`F_SETLK`/`F_SETLKW`/`F_OFD_*` record-lock arm mirroring the C interposer — else soft `ENOSYS`), `ioctl` (`FIONBIO`/`FIONREAD` on virtual sockets — else fatal), `pipe2`, `fstat`/`newfstatat`/`statx` (normalized to the same metadata record, one-hop terminal-symlink resolution mirroring the C `stat` path, arch-specific kernel `struct stat` + arch-independent `struct statx`), and `getdents64`; the raw `read`/`write`/`close` rows now do the same fd-class dispatch the C interposers do (socket/pipe/eventfd/epoll vs regular fd), so a raw call on a virtual socket records the identical op-stream. A raw caller (rustix `Dir` → `getdents64`) is served by a directory-fd model: a read-only `openat` on a directory yields a descriptor whose entries are snapshotted through the same `patina_read_dir` the interposed `opendir` uses, `getdents64` walks that snapshot into `linux_dirent64` records, `lseek(…,0,SEEK_SET)` rewinds it, and `close`/`fstat` recognize it. (Item 21 below later made that descriptor the runtime's own directory fd, shared with the C interposers, and added dirfd-relative `*at` resolution over it.) Network rows → `patina_net_*`: `socket`/`bind`/`listen`/`connect`/`accept`/`accept4`/`sendto`/`recvfrom`/`shutdown`/`getsockname`/`getpeername`/`setsockopt`/`getsockopt` (the option subset the C interposers accept) plus `sendmsg`/`recvmsg`, which mirror the C interposers' `ENOSYS` refusal exactly (the deterministic net layer models only sendto/recvfrom; a per-iovec send loop would fragment one datagram into N — silently-wrong, so it is fail-closed instead). Readiness rows call the landed epoll frontend: `epoll_create1`/`epoll_ctl`/`epoll_wait`/`epoll_pwait`/`epoll_pwait2` (timespec→ms, NULL sigmask only) and `eventfd2`. Process-state constants match the interposers exactly: `getpid`=1, `getppid`=2, `getuid`/`geteuid`/`getgid`/`getegid`=1000, `uname`=`-ENOSYS`. The `sud` trace-metadata field (slice 1's approved deferral) now lands: the shim records whether SUD armed for the run (`Some(true)` when armed, absent otherwise — so macOS and all pre-SUD traces stay byte-identical) via the `guest_argv` `RunMetadata` pattern, and `replay` reconciles it UP FRONT — a `sud:true` trace on a run that did not arm SUD, or the converse, is refused before the first op is replayed (never a mid-run divergence), with directional messages; unit tests RED-prove both directions. `AT_RANDOM` determinization (slice 3, kernel-independent): the same auxv walk that scrubs `AT_SYSINFO_EHDR` now REPLACES the 16 `AT_RANDOM` bytes in place with seed-derived deterministic bytes (replacement, not `AT_IGNORE`: glibc dereferences the pointer at startup for the stack canary), closing an entropy leak on every managed Linux run whether or not SUD arms. Vsyscall-page audit detection (slice 3): the x86_64 instruction scan now refuses a binary whose text materializes the legacy vsyscall page address `0xffffffffff600000` as a 64-bit immediate — kernel-emulated, no `syscall` instruction, invisible to SUD — as a non-downgradable `vsyscall` finding. No-cruft retirement: `cargo patina build` now DROPS `--cfg rustix_use_libc` on SUD-capable targets (x86_64 Linux), keeping it only where SUD is absent (aarch64 Linux; macOS uses libc anyway) — a single conditional, no dual path. The committed acceptance MRE is `testbeds/rustix-default/` — a std+rustix program on the default `linux_raw` backend exercising raw clocks/fs/getdents64/getrandom/sleep/SimNet; its `run-patina.sh` skips loudly and counted on non-SUD/non-Linux hosts and, under SUD, asserts audit→SUD-managed, seed-stable, and record/replay byte-identical. Verified: macOS `cargo test --workspace` + the 55-test e2e suite green; `cargo check --target x86_64-unknown-linux-gnu` typechecks the whole SUD Rust surface (I am on macOS arm64 — the positive SUD legs are x86_64-CI-only and reviewed by construction on the C side); the metadata-reconcile and vsyscall detectors are RED-proven by mutation. the native SUD coverage (now `native_containment` and `native_raw`) includes legs for the rustix MRE, raw epoll/eventfd, raw uname/pid constants, raw `sendmsg`/`recvmsg`, `AT_RANDOM` determinism (kernel-independent, RED-mutation documented), and vsyscall audit refusal (x86_64), and the `SUD_LEGS_RAN` marker's `legs=` list is extended.

20. Timestamp-counter trap (`rdtsc`/`rdtscp`), Linux/x86_64: a guest's inline timestamp-counter read — `core::arch::x86_64::{_rdtsc, __rdtscp}`, hand-written asm, a fast-clock crate — is trapped into the deterministic runtime instead of reading the host counter. The mechanism is `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)`, armed at the same two sites SUD uses (the `__libc_start_main` interposer before guest constructors, and every managed thread's trampoline — the TSC flag is per-thread), reusing the `/proc/self/maps` text span SUD already discovers. The instruction then raises a synchronous, thread-directed `SIGSEGV` at its own address; the handler validates the faulting `RIP` lies in the main executable's text, decodes it (`0f 31` rdtsc, `0f 01 f9` rdtscp — an exact-encoding test, never prefix-tolerant), and writes the counter into `EDX:EAX` (plus `IA32_TSC_AUX` = 0 in `ECX` for rdtscp) before stepping `RIP` past the instruction. **Interposer parity is structural, not asserted**: the value is the run's virtual monotonic clock read through the SAME `patina_clock_now` entry point every C interposer and SUD row calls, so a trapped counter read records the ordinary `clock_now` operation — an `rdtsc` and a `clock_gettime` are indistinguishable in the trace and replay from the identical recorded value. The frequency mapping is one tick per virtual nanosecond (a nominal 1 GHz invariant TSC), chosen so a guest that calibrates the counter against the clock derives exactly 1 GHz on every host; monotonicity is the virtual clock's, so two reads with nothing between them return the same tick exactly as two `clock_gettime` calls do. Any other faulting instruction falls through to the disposition the trap displaced — a genuine segmentation fault still kills the process at the true address, proven by a leg. Because Rust std installs its stack-overflow `SIGSEGV` handler only over `SIG_DFL` and the trap arms first, std's overflow *message* is lost while armed (the fault still kills); std's `SIGBUS` handler and altstacks are unaffected. Hardening mirrors SIGSYS: while armed, a guest `sigaction`/`signal` on SIGSEGV is refused (it would disable the containment) and `pthread_sigmask` cannot block the signal. The audit **downgrades** an `rdtsc`/`rdtscp` *instruction* finding from refuse→run iff (a) the binary defines the `patina_tsc_dispatch` marker AND (b) a live `prctl(PR_GET_TSC)` probe says the platform can arm the trap, reporting it relabeled `cpu-nondeterminism (TSC-trap-managed)` — never silent. The split is deliberately narrower than the category: findings now carry their decoded mnemonic, so `rdrand`/`rdseed` (hardware entropy) and arm64 `mrs CNTVCT_EL0` stay refusals on every platform, and the refusal text now NAMES both facts an operator could not previously infer — that an instruction finding has no symbol, so `--allow` can never clear one, and whether the class is trappable elsewhere or nowhere. Two scan gaps closed in the same change: `rdtscp` (group 7, `0f 01 f9`) was measured as an ordinary instruction and scanned straight past — a guest reading the host counter through it audited CLEAN — and `rdseed` (`0f c7 /7`) was unclassified one ModRM.reg over from `rdrand`. Arming is recorded in the trace's `tsc` metadata field (present only when armed, so every other trace stays byte-identical) and reconciled UP FRONT on replay: an armed trace replayed unarmed, or the converse, is refused before the first op, because the unarmed direction would read the host counter. Verified on an x86-64 Linux sandbox: the counter values ARE the virtual clock (three 5ms sleeps give exactly 0 / 5,000,000 / 10,000,000 / 15,000,000 ticks), same-seed runs and traces are byte-identical, record→replay is identical, seeded sleep jitter moves the counter and reproduces per seed, an `rdrand` guest stays refused on that same host, a genuine segfault still kills with `signal=11`, and a SIGSEGV-hijack attempt is refused; the pre-slice scanner is RED-proved to audit the same `rdtscp` guest clean. `native_containment` covers the TSC battery (x86-64 Linux; an unsupported-kernel refusal is asserted when PR_SET_TSC is absent), and the full battery — including the complete SUD positive branch — stays green with the trap armed on every managed run. Deferred by user decision: `cpuid` (a much larger surface); `rdrand`/`rdseed` and arm64 `CNTVCT` have no userspace trap and remain refusals by design.

21. Directory-descriptor-relative (`*at`) resolution, both entry paths. Capability-based filesystem guests (`cap-std`/`cap-primitives`, and anything else that opens a directory once and works relative to it) never issue a path-only call: they resolve each component themselves with `openat(dirfd, name, O_PATH|O_DIRECTORY|O_NOFOLLOW)`, `statx(dirfd, name)`, `readlinkat(dirfd, name)`, `faccessat2(dirfd, ".")`, `mkdirat`/`unlinkat`/`renameat`/`symlinkat`/`linkat` against a real descriptor, and `getdents64` over one derived by `fcntl(dirfd, F_GETFL)` + `openat(dirfd, ".")`. Every SUD `*at` row previously modeled `AT_FDCWD` only and refused a real descriptor with `-ENOSYS`, and the libc `open` refused `O_PATH` outright, so such a guest died on its FIRST call. Three things landed together. **One directory-descriptor table**: `patina_diropen` now owns the whole directory-open contract — the entry's own kind, `O_NOFOLLOW` → `ELOOP` on a symlink, trailing-symlink resolution through the shared virtual `realpath`, `ENOTDIR` otherwise — and both the C interposer and the SUD dispatcher call it, so a descriptor minted through libc resolves a raw `openat(dirfd, …)` and vice versa (which is exactly what `cap-std` needs: it opens its base directory through std and then uses raw syscalls). The SUD layer's private `0x6000_0000` descriptor space is retired; a directory fd is an ordinary deterministic-filesystem fd, so `fstat`, `fsync` (the namespace-durability barrier), `dup`, `fcntl` and `close` need no special case, and the `getdents64` snapshot becomes a side table keyed by that fd, taken by the first read and dropped by `lseek(…,0,SEEK_SET)`/`close`. **Resolution**: `(dirfd, path)` becomes `patina_dirpath(dirfd) + "/" + path`, and the absolute path is handed to the SAME `patina_*` entry the `AT_FDCWD` form uses — a second spelling of the path, never a second filesystem model. An absolute `path` ignores `dirfd` (POSIX) but only after the descriptor is validated, so a bogus fd is never honored; a descriptor the deterministic filesystem never issued as a directory fails closed with `ENOSYS`; and `.`/`//`/`..` are deliberately left to the driver's ONE path normalizer, which judges a dirfd-relative spelling exactly as it judges the same `AT_FDCWD` spelling (parent traversal is refused for both). `AT_EMPTY_PATH` names the descriptor itself for `newfstatat`/`statx` (`File::metadata()` on Linux). New rows: `faccessat` and `faccessat2` (both, because rustix probes the latter and falls back — a soft deny on `faccessat2` would print a diagnostic on every `..` a guest walks), the x86_64 legacy `access`, and `openat2` as a NAMED deny (its `RESOLVE_*` guarantees are a kernel-side sandbox that is not modeled, and `ENOSYS` is precisely what callers probe for before taking their component-wise `openat` fallback). **Symlink-on-open**: the deterministic filesystem has no descriptor for a symlink ENTRY, so an open whose final component is one was `EINVAL`; POSIX splits that in two and both halves are now modeled in `patina_open` (one place, both callers) — `ELOOP` with `O_NOFOLLOW` (what `cap-primitives` keys its manual symlink resolution off, and what std's `remove_dir_all` reads as "not a directory"), otherwise the link is resolved and the target opened. `O_NONBLOCK` joins the accepted open flags in both paths (it only changes the open of a FIFO/socket/device, none of which are modeled). C-side parity followed the same rule everywhere: `renameat`/`renameat2` gained dirfd resolution, `dup`/`fcntl` gained the directory-descriptor rows, and `open`/`openat` accept `O_PATH` (a non-directory `O_PATH` open is a named deny with the byte-identical string the SUD row emits). The committed acceptance MRE is `testbeds/cap-std-dirfd/` — a std+cap-std guest that creates, writes, reads, stats, lists, renames, symlinks and removes entirely through capabilities, with nested and cross-descriptor cases; its `run-patina.sh` skips loudly and counted off SUD and otherwise asserts audit→SUD-managed, byte-identical same-seed repeats on stdout AND the captured stderr, and record/replay identity, and the native ecosystem rung runs it as a leg. Independent evidence: the Monty repo's `monty-fs` crate (cap-std over a mount table) goes from 2/128 to 128/128 of its libtest suite passing under `cargo patina run`.

22. Permission bits, and descriptor identity for `*at` resolution. Two gaps a capability-based sandbox exercises together, found by running the Monty repo's `monty-fs` suite under Patina. **Modes.** The deterministic filesystem now stores a mode per entry: new files are `0o644` and new directories `0o755` (the POSIX creation modes under the fixed `0o022` umask this filesystem models), symlink leaves read the conventional `0o777` and have no mode of their own to set, and `FsMetadata` carries the permission bits alongside the kind so `stat`/`fstat`/`statx`/`newfstatat` report a real `st_mode` (type bits ORed with permission bits) instead of a fabricated constant. `chmod`/`fchmod`/`fchmodat` are interposed on both entry paths — C interposers plus the SUD rows `fchmod`, `fchmodat`, `fchmodat2` and the x86_64 legacy `chmod`, all routing into the same `patina_chmod`/`patina_fchmod` entries — and both changes are recorded boundary operations (`FsSetMode`, `FsSetFdMode`), so a mode survives record→replay and a modeled crash restart (the restart snapshot format goes to v2, rejecting a mode with bits outside `0o7777` rather than masking it). The bits are **enforced** against the single non-root identity the runtime already models (uid/gid 1000, what `getuid` reports), which owns every entry, so enforcement reads the owner triad: opening for read needs `r` and for write needs `w`; resolving a path THROUGH a directory needs `x` on it, checked before existence so an unsearchable directory answers `EACCES` for a name that is there and one that is not alike; listing a directory needs `r`; and creating, removing, or renaming a name inside one needs `w` and `x`. A descriptor opened while the mode allowed it keeps working, because the check belongs to `open`. `access`/`faccessat`/`faccessat2` answer from the same bits on both paths rather than from existence alone. `chmod` itself is an owner right, not a permission-bit right, so only reaching the entry is checked. One conflation is accepted and named: a directory open costs `x`, not `r`, because `O_PATH` is not part of the driver's flag vocabulary — the `r` a listing needs is charged at `read_directory`, which is where an `O_PATH`-opened descriptor would pay it too. Two divergences are accepted and named rather than papered over: a directory open costs `x`, not `r`, because `O_PATH` is not part of the driver's flag vocabulary (the `r` a listing needs is charged at `read_directory`, which is where an `O_PATH`-opened descriptor would pay it too); and a CREATION mode argument (`open`'s third argument, `mkdir`'s, `creat`'s) was still dropped, so every new entry got the fixed umasked creation mode for its kind. Honoring a creation mode means carrying it across the driver boundary, which changes the `FsOpen`/`FsCreateDirectory` operations themselves — item 24 does exactly that and closes this one; the directory-open conflation above stands. **Descriptor identity.** A directory descriptor names an INODE, not a name. `*at` resolution previously joined onto the path cached beside the descriptor when it was opened, so renaming the directory detached it and a symlink planted at the vacated name captured every later resolution through it — precisely the redirect a capability handle exists to prevent. `patina_dirpath` now asks the filesystem where the descriptor's node IS (`FsFdPath`, a recorded boundary operation with no modeled latency and no fault eligibility: it is the name lookup inside the `*at` call, not a second trip to storage), and the shim's directory table keeps only the one fact the filesystem cannot answer — WHICH descriptors are directory descriptors, which is what tells a dir fd apart from a socket/pipe/reactor endpoint in the shared virtual-fd space. `..` stays refused by the driver's one normalizer, so a dirfd-relative spelling and an `AT_FDCWD` spelling of the same path still get the same judgement. The committed acceptance MRE is the existing `testbeds/cap-std-dirfd/`, extended with a mode leg (creation modes, `chmod`/`fchmod` read back through `stat`, `EACCES` — distinguishable from `NotFound` — for read/write/traverse/list/create) and a pinning leg (open a capability, rename its directory, plant a symlink to a decoy at the old name, and prove reads and writes still land on the original node); the result line gains `modes=enforced pinned=node`. Both legs are RED-proven by mutation: neutering the owner-triad check fails the mode leg (`a 0o000 file must not be readable`), and dropping the rename bookkeeping that moves an open description with its node fails the pinning leg (`the descriptor must survive the rename: PermissionDenied`). `chmod`/`fchmod`/`fchmodat` move out of the symbol audit's "not interposed" filesystem bucket; `acct(2)` is the planted representative; `truncate` is modeled (item 28). Independent evidence: `monty-fs`'s six libtest harnesses go from 3 green (`fs` 128, `fs_security` 80, `monty_fs` 0) with 9 failures across `mount_confinement`/`mount_escape_repro`/`overlay_stale_ref` to all six green at seeds 0–4.

23. Named pipes (FIFOs), end to end. `mkfifo` was not interposed at all: a guest had to be forced through the audit with `--allow-unsupported-symbols`, and the call then escaped to the host and failed `ENOENT` on a path only the in-memory filesystem has. A FIFO is the one entry kind whose NAME is filesystem state while its BYTES are not, and modeling it means modeling both halves and keeping them apart. **The entry.** `FsEntryKind::Fifo` runs the whole stack — the ABI kind and its `PATINA_ENTRY_FIFO` wire value, a `fifos` table in `MemFs` (a name, an inode identity, and a mode; never contents), the restart snapshot (format v3, with its own section), the crash model's durable baseline and survival sets (the name is durable namespace state; the bytes in flight are process state a crash drops, as a real one does), `S_IFIFO` from `stat`/`fstat`/`statx`/`newfstatat` on both entry paths, `DT_FIFO` from `getdents64` and from the libc `readdir`, the WASI filetype map (Preview 1 has no FIFO filetype, so `unknown` — the honest answer rather than a kind it is not), and the trace viewer. Creation is one new recorded boundary operation, `FsMakeFifo`, and unlike `FsOpen`/`FsCreateDirectory` it CARRIES the caller's mode: the operation is new, so the mode crosses the boundary instead of being reconstructed from a per-kind constant, and the driver applies the modeled umask exactly as the kernel applies the process umask. Interposers: `mkfifo`/`mkfifoat` plus `mknod`/`mknodat` restricted to `S_IFIFO` (C interposers and the SUD rows `mknodat` and the x86_64 legacy `mknod`); a character or block device answers `EPERM` — what the one non-root identity this runtime models would get on a real kernel — and every other type is a loud named deny whose string the C and SUD spellings share under a gate. Permissions come from slice 22 unchanged: creating the name needs `w`+`x` on the directory, and the FIFO gets the umasked mode. **The transfer.** There is no second pipe implementation. A FIFO open reuses the shim's existing in-process `PipeChannel` — the same buffer, the same waiter deques, the same `try_read`/`try_write`, the same EOF/`EPIPE` rules the anonymous `pipe`/`socketpair` endpoints use — keyed by the FIFO's INODE, so two openers of one named pipe meet on one channel while a rename cannot split them and a fresh FIFO at a vacated name cannot inherit them. The endpoint is an ordinary virtual pipe fd, so `read`/`write`/`close`/`dup`/`fcntl` and the epoll/kqueue readiness reactors route it by table membership with no new dispatch anywhere; `fstat` is the single place that needed a FIFO leg. The channel's "reader side closed"/"writer side closed" latches became derived from the reference counts, because a FIFO's sides come BACK when it is opened again. **The rendezvous** is modeled the way the kernel models it (`fs/pipe.c:fifo_open`): an open registers its end, bumps that side's open counter, wakes anything parked on the channel, and then — unless it is `O_NONBLOCK` or `O_RDWR` — parks on the PARTNER COUNTER moving rather than on a partner being present, which is what lets a writer that opens and closes again still release a reader parked in `open(O_RDONLY)`. Parking is the scheduler's ordinary baton park, so another task's `open(O_WRONLY)` is deterministically what wakes the reader, and a FIFO nobody ever opens for writing surfaces as the runtime's deadlock report instead of a hung process. `O_NONBLOCK` splits the two directions the way POSIX does: a read-open succeeds at once, a write-open with no reader is `ENXIO` and never becomes a writer at all. Reads see the writers' bytes, end-of-file once the last writer closes, and `EAGAIN` on a non-blocking read with no data and a live writer; a write with no reader left is `EPIPE` and never a signal, exactly as the anonymous-pipe path already answered. Routing is one branch: the driver refuses to hand back a filesystem descriptor for a FIFO — AFTER judging existence, resolution and permissions, so a `0o000` FIFO is `EACCES` and stays distinguishable from `NotFound` — and `patina_open` reads the refused entry's kind on the failure path only, exactly as it already did to split a symlink open into `ELOOP`-or-follow. `unlink` of a FIFO is unconditional (no filesystem description holds one), and open descriptors keep the pipe alive because what they hold IS the pipe. Four divergences were accepted and named here; item 24 closes two of them. `fstat` on a FIFO descriptor answered from the identity the open bound to it, so a `chmod` of the entry after the open was not reflected there (closed: the descriptor reads the live entry by inode), and a hard link TO a FIFO was `NotFound` rather than a second name for the same node, because the driver's link table is inode-backed and a FIFO had no inode there (closed: the FIFO table is inode-backed too, and the shared inode is the shared pipe). Two stand: `mknod` models no special file but a FIFO; and the transfer half lives in the native shim, so an in-process (Cargo-family) or `wasm32-wasip1` guest can create, stat, list, link and unlink a FIFO but not open one — the driver refuses that open by name rather than handing back a descriptor with no pipe behind it. The committed acceptance MRE is `testbeds/fifo-ipc/` — a std + libc guest covering all three creation spellings, the entry kind through `stat`/`fstat`/`read_dir`, the non-blocking pair, a blocking reader woken by another task's writer, EOF, `EPIPE`, `EAGAIN`, `O_RDWR`, the `0o000` refusal and unlink-while-open — and it is portable rather than SUD-gated, because the guest reaches everything through libc; the raw `mknodat`/`mknod` rows have their own probe in `native_raw::raw_fifo_rows_transfer_and_refuse_consistently`. Independent evidence: the Monty repo's `monty-fs` `mount_confinement` harness now runs its two FIFO tests under Patina with no allowance flags — `fifo_in_the_mount_is_refused_promptly` (a host-planted FIFO opened `O_NONBLOCK` on a servicing thread, expecting a prompt `PermissionDenied` rather than a hang) and, under `--env MONTY_FS_SOAK=1 --fs-latency-nanos 1000000..10000000`, the soak that renames a FIFO over a regular file while a reader loops against a two-second virtual deadline.

24. Creation modes, and the last of the FIFO divergences. Slices 22 and 23 named four residual gaps and left them; this closes three of them and the crash-model consequences that fell out. **The mode a caller asks for.** `open(path, O_CREAT, mode)`, `openat`, `creat`, and `mkdir`/`mkdirat` dropped their mode argument, so every new entry got the fixed umasked default for its kind — which looks right for the `0o666`/`0o777` callers and is silently wrong for the caller who asked for `0o400`, and the slice-22 enforcement then judged every LATER open against the invented value. The mode now crosses the driver boundary on every creating operation: `OpenFlags` gains `mode` (POSIX `open`'s third argument, so `FsOpen` carries it), `FsCreateDirectory` gains one, and `FsMakeFifo` already had one. The driver applies the modeled `0o022` umask exactly where a kernel applies the process umask, so `0o666`/`0o777` still produce `0o644`/`0o755`, and an `open` of an EXISTING entry never touches that entry's mode — POSIX does not read the argument on that branch, so the shim records `0` there rather than whatever was in the register (the variadic mode is only fetched when the flags say `O_CREAT`). Both entry paths carry it: the C `open`/`open64`/`openat`/`openat64` interposers read the variadic argument, `creat` stops discarding its second, `mkdir` its second, and the SUD rows take it from the raw fourth argument (`openat`, `mkdirat`) or the second (`creat`, legacy `open`/`mkdir`). `mkdirat` becomes a C interposer in the same change — a libc-backend dirfd caller reached for it and found an uninterposed import. Trace format 6, with a v5→v6 migration that writes in exactly the request a format-5 recorder behaved as if it had made. **`fstat` on a FIFO descriptor** answered from the identity captured at open, so a `chmod` afterwards was invisible — a stale cache one field over from the cached path slice 22 removed. A FIFO endpoint holds a NODE, so it now asks the filesystem about that node through one new recorded operation, `FsInodeMetadata` (the same `fstat` the descriptor form is, addressed by inode: same latency, same fault eligibility). The captured copy answers in exactly one window, the one the filesystem genuinely cannot: after the last NAME is unlinked with the descriptor and its pipe still alive. **A hard link to a FIFO** was `NotFound`, because the link table is inode-backed and a FIFO had its own private metadata record instead of an inode. The FIFO table is now inode-backed like the file table, so `link`/`linkat` work, the two names share one mode and one link count, and — because the shim keys the pipe channel by inode — they share one pipe. Restart-snapshot format v4 carries that (a fifo section of inode ids, with the decoder refusing an inode named as both a file and a fifo, or a fifo inode carrying contents), and two latent bugs fell out of making the identity real: renaming a DIRECTORY did not carry the FIFOs beneath it, and renaming OVER a leaf dropped the name without releasing its node. **The crash model** followed: permission bits are durable metadata like a symlink's target, so a surviving entry comes back with the bits it had instead of being rebuilt at a per-kind constant (they are written from the leaves up, after the namespace, so a directory clamped to `0o500` cannot lock the walk out of its own children), hard-linked FIFOs are grouped by inode exactly as hard-linked files already were, and the durable baseline is enumerated through a new UNENFORCED `MemFs::inventory` — a crash journal is the storage layer, not a process, and walking the guest-facing `read_directory` made a `0o000` directory look empty, which would have deleted its children on the next crash. **Detection**: the `cap-std-dirfd` MRE gains creation-mode legs (a file created `0o400` is not writable through a second open, a directory created `0o500` refuses a name inside it, an existing file's mode is not rewritten by a later `open`, the umask still bites) and its result line becomes `modes=enforced+created`; `fifo-ipc` gains an `fstat`-after-`chmod` leg and a hard-link leg that writes through one name and reads through the other, and its line gains `fstat=live linked=2names,shared`; `native_raw::creation_modes_are_enforced_on_later_open` covers the raw creation-mode probe, the raw-syscall half of the same claim. Driver-level pairs live in `patina-dst-fs-mem` (creation modes honored and enforced, an existing mode untouched, hard-linked FIFOs, inode-addressed metadata, directory rename carrying FIFOs, rename-over releasing a node, linked FIFOs through a snapshot) and `patina-dst-fs-crash` (modes surviving a crash for every kind that owns one, a `0o000` directory keeping its children, hard-linked FIFOs coming back as one node). Two named divergences from slices 21-23 were deliberately NOT closed here and stayed named for item 25 to take: a directory open costs `x` rather than `r`, because `O_PATH` was still not part of the driver's flag vocabulary; and libc `symlinkat`/`readlinkat` remained uninterposed (fail-closed at the audit; their raw-syscall rows are modeled), which only bites a libc-backend dirfd guest. The FIFO transfer half lives in the native shim, so a Cargo-family or `wasm32-wasip1` guest can create, stat, list, link and unlink a FIFO but not open one; `mknod` still models no special file but a FIFO, by design — a device node is a host escape by construction.

25. Inode lifetime, `O_PATH`, and the libc `*at` link family — the last of the named filesystem divergences. **Inode lifetime.** The deterministic filesystem refused `unlink` on an open file outright (`InvalidState`, "cannot remove open virtual file"), because an open description was keyed by PATH: dropping the name would have left it pointing at nothing. No kernel refuses that — it removes the NAME and keeps the node alive for every descriptor that still holds it — so the refusal was a world the guest can never be tested against, and its FIFO counterpart was worse: the node vanished with its last name while the endpoint and its pipe stayed live, and `fstat` fell back to a copy taken when the descriptor was opened. Nodes are now reference-counted by names AND by descriptors, exactly as a kernel counts `i_nlink` and `i_count`. A description holds an `InodeId` rather than a path (which also deletes the rename bookkeeping that used to rewrite description paths — a descriptor moves with its node by construction now), the node carries its own kind so an unlinked entry still reports `S_IFIFO` or `S_IFREG` with no name to look it up by, and the node is freed only when its last name and its last descriptor are both gone. `fstat`, reads, writes and `fchmod` on an unlinked-but-open entry therefore answer from the live node with link count 0. The one descriptor class the filesystem hands back no handle for — a FIFO endpoint, whose bytes belong to the openers' pipe — takes its reference explicitly through two new recorded operations, `FsRetainInode`/`FsReleaseInode`, taken when the pipe channel comes into existence and dropped when it is reclaimed; `fchmod` through such an endpoint reaches the node through `FsSetInodeMode`, the mirror of the `FsInodeMetadata` slice 24 added. The open-time-copy fallback is deleted, not narrowed. The crash model followed: a description is re-bound to the node its NAME has in the rebuilt image, and one whose entry has no name at all — unlinked while open, so the journal (which enumerates names) never saw it — is re-bound to a fresh anonymous node carrying what the descriptor last held, never to a number an unrelated entry might reuse. Those bytes cross the crash unmerged, which is named rather than silent: the torn-write model works from the durable baseline of a NAME, and this node has none. **`O_PATH`.** A directory had exactly one open in the driver's vocabulary, so a capability guest's component walk and a real directory read were the same operation: the open charged `x` and handed back a readable handle, and the `r` a listing needs was charged at `read_directory` — where a `chmod` after the open could still reach a walk already under way. `OpenFlags` gains `path_only` (trace format 7, with a v6→v7 migration writing `false`, which is what every format-6 open was). A path-only open opens nothing: Linux charges nothing on the entry — only the `x` walk of the prefix, which resolution already did — and the descriptor resolves `*at` paths, answers `fstat`/`readlinkat`, dups and closes, while refusing every read, write, seek, `fsync`, `fchmod` and listing. A plain `O_RDONLY|O_DIRECTORY` open opens the directory for reading and charges `r`. Iteration therefore moved onto the descriptor: `patina_read_dir` takes an fd rather than a path (`FsReadDirectoryFd`, a new recorded operation), so the access is charged once at open, an `O_PATH` descriptor cannot list however permissive the directory's bits are, and the libc `opendir` mints its own descriptor first — which is what makes `dirfd()` on an `opendir` DIR a real descriptor rather than the `ENOTSUP` it used to be. The path-taking `read_directory` remains the fused `opendir`+`readdir` an in-process or WASI guest issues, and keeps charging its own `r`. `O_PATH` on a NON-directory stops being a named deny: the kernel gives a path-only descriptor for any kind, so a file or a FIFO gets one too (the FIFO case is the only FIFO open that never reaches the pipe), and the single remaining refusal is `O_PATH|O_NOFOLLOW` on a symlink — the one spelling that names the link ENTRY, which the deterministic filesystem has no descriptor for. `dup` of a directory descriptor stops reopening the path (a second open, re-resolving a name and re-charging permission) and shares the open description as POSIX `dup` does, through the new `patina_dirdup`. **libc `symlinkat`/`readlinkat`** are interposed, so a libc-backend dirfd guest no longer fails closed at the audit on two calls whose raw-syscall rows were already modeled; the symbol audit classifies both names as `filesystem`. **The trace viewer** renders `fs_open`'s flag word and its creation mode (`flags=read|create mode=0o644`), which the generic scalar scan could not see because both live inside the nested `flags` object — a reader who cannot see `O_PATH` in the trace cannot tell the two directory descriptors apart. **Detection**: `fifo-ipc` gains leg 13 (with the last name gone, `fstat` through the descriptor reports link count 0 and the live mode, and `fchmod` through it changes what the next `fstat` reads), result line `unlinked=nlink0+fchmod`; `cap-std-dirfd` gains the `O_PATH` leg — a `0o400` directory is listable but not traversable, a `0o100` one is traversable but not listable, and a `0o000` one still accepts an `O_PATH` open whose descriptor then refuses to be read — result line `opath=nocost,list=r,walk=x`; `native_abi::libc_at_calls_are_interposed_and_replayable` owns the `at-family` probe (a guest declaring `symlinkat`/`readlinkat` as ordinary imports audits CLEAN and resolves both through the same dirfd table the raw rows use; RED without the interposers, the audit refuses the binary and names both in the `filesystem` escape class). Writing that probe surfaced one unrelated bug and fixed it: SUD's region discovery matched glibc's legacy basename spelling as the bare prefix `libc-`, so a GUEST binary named `libc-*` counted as a second libc segment and the run refused to arm — the prefix now requires the version digit that follows it in `libc-2.31.so`. Driver-level pairs live in `patina-dst-fs-mem` (an unlinked file alive behind its descriptors and released with the last reference, a hard link removable while another name is open, an unlinked FIFO answering through its endpoint's reference, the two directory opens costing different bits, a path-only open of a file or FIFO) and `patina-dst-fs-crash` (a descriptor on an unlinked entry crossing a crash without capturing another node), with the v6→v7 migration pinned by its own fixture. Still named and not closed: the FIFO transfer half lives in the native shim, so a Cargo-family or `wasm32-wasip1` guest can create, stat, list, link and unlink a FIFO but not open one; `mknod` models no special file but a FIFO, by design; a directory descriptor is not itself inode-backed, so `rmdir` of an open directory leaves that descriptor answering `NotFound` rather than a live node; a hard link to a SYMLINK duplicates the link entry instead of sharing its inode (`linkat`'s no-`AT_SYMLINK_FOLLOW` behavior, whose link count is therefore 1 per name); and the host-capture driver (`HostCaptureFs`) has no directory descriptors at all — it refuses a directory open by design — so it answers the descriptor-form listing with its "does not support" refusal, which is reachable only if that driver is ever installed for a shim-linked guest (it is an in-process capture today, and the path form it does implement is what an in-process guest calls).

26. Self-sufficient installed binary: the shim source travels inside `cargo-patina`. The CLI used to bake its own source checkout path into the binary (`env!("CARGO_MANIFEST_DIR")`) and run `cargo build -p patina-dst-native-shim` there for every native `build`/`run`/`audit`/source-first `replay`, so only an in-tree build could build a native guest — a `cargo install`ed binary (from the registry or a git URL) or CI had no checkout to point at. The shim must still be compiled by the exact rustc that compiles the guest (the toolchain-identity check pins that), so a prebuilt staticlib was never an option; the source is what travels. **Discovery.** Each of the shim's twelve closure crates carries `links = "<package-name>"` and a build script that publishes its `CARGO_MANIFEST_DIR` as `cargo:src_dir`; cargo hands that to a direct dependent's build script as `DEP_<PKG>_SRC_DIR`, the one documented channel for learning a dependency's source directory, identical in-tree, from the registry checkout, and from a git checkout. `cargo-patina` depends directly on all twelve for that reason. **Packing.** `crates/cargo-patina/build.rs` embeds every file of every closure crate (`include_bytes!`, so rustc tracks them), normalizing each `Cargo.toml` on the way: workspace-inherited keys are resolved against the nearest `[workspace]` root (a no-op in the registry form, which carries none), closure dependencies are repointed to `{ version, path = "../<package-name>" }`, `[dev-dependencies]` is stripped (it reaches outside the closure), and the nearest `Cargo.lock` walking up from the crate is embedded to pin the third-party crates. The bundle is content-addressed by a digest over the embedded bytes. **Unpacking.** At guest-build time the bundle is written to `<cache>/shim-src/<digest>/` as a self-contained workspace (a generated root manifest listing the twelve members plus the lock) — staged into a temporary sibling and renamed into place, and never rewritten once present — under `$XDG_CACHE_HOME/patina`, else `~/.cache/patina` (Linux) or `~/Library/Caches/patina` (macOS); a missing `HOME` is a loud error. The staticlib builds there under `<cache>/shim-target/<toolchain identity>` (explicit `CARGO_TARGET_DIR` stays authoritative), and the toolchain-agreement probe runs in the unpacked directory, which carries no pin, so the ambient toolchain is what the shim half resolves. **Detection.** `crates/cargo-patina/tests/self_sufficient_binary.rs` reads the CLI binary and fails if any loadable section names the workspace root (class: installed binary depends on the source checkout); it was red on the baked path and is green now. The pre-existing source-workspace target dir under `target/patina-shim/` is gone; CI caches the new per-user directory.

27. One path resolver, the working directory, and the umask (syscall-conformance arc, foundation F3). Every `(dirfd, path)` a guest hands the native shim — through a libc interposer or a raw syscall row — now resolves through one Rust resolver (`crates/patina-native-shim/src/paths.rs`): the modeled working directory for `AT_FDCWD`, a directory descriptor's node otherwise, `.`/`..` applied to the resolved directory after symlink expansion, symlinks walked to the kernel's 40-hop `ELOOP`, `ENAMETOOLONG` at `PATH_MAX`/`NAME_MAX`, `ENOTDIR` for a component through a non-directory, and the trailing-slash rule; the driver keeps its canonical-only contract underneath. `getcwd`/`chdir`/`fchdir` are modeled process state (the working directory is a path-only driver handle, so a renamed ancestor moves it and an unlinked one answers `ENOENT`), `chdir` left the process-class deny-trap list, and native `run --cwd PATH` sets the starting directory (recorded into trace metadata, restored on replay, refused by name when it is not a directory in the image). The umask moved out of the drivers into the shim (`umask(2)` on both doors; the WASI host applies the fixed `0o022` itself), so the driver stores the post-umask mode the kernel would. The errno vocabulary gained `EPERM`/`ENODATA`/`ERANGE`/`E2BIG`/`EOPNOTSUPP`/`EBUSY`/`ESPIPE`/`EXDEV` (`ErrorCode::{NotPermitted, NoData, Range, TooBig, Unsupported, Busy, IllegalSeek, CrossDevice}`). Host-checked by the conformance scenario `fs/paths` through every vehicle; the `fs/open_rw`, `fs/dirs` and `fs/links` scenarios carry no gap for a component through a file, a trailing slash on a file, an empty path, `readlinkat` on a non-symlink or with a zero buffer, or `symlinkat` with an empty target.

28. Timestamps, ownership and sizes (syscall-conformance arc, fs family). **Timestamps.** The deterministic filesystem had two timestamps that nothing moved: `stat` reported `ctime` as a copy of `mtime`, `statx` never set `STATX_BTIME`, and a write, a truncation or a `chmod` left every time at zero. Every driver operation that reads or mutates now takes the virtual clock (`FsClock { now_nanos, atime }`, `crates/patina-abi`), read UNRECORDED by the runtime from its realtime clock driver — the value is a pure function of the recorded sleeps, so replay reproduces it and an fs operation costs no extra trace event — and `MemFs` stamps atime/mtime/ctime/btime by the kernel's rules: all four at creation (and the parent's mtime/ctime), mtime+ctime on a data change (write, truncation, allocation, a name appearing in or leaving a directory), ctime on a metadata change (mode, link count, rename, explicit times), atime on a read under `relatime` (Linux's `relatime_need_update`: not newer than mtime/ctime, or a day old; the runtime fixes this policy to relatime; strictatime/noatime remain driver-level `FsClock` inputs only, not unrecorded runtime configuration). `FsMetadata` carries all four; the snapshot format goes to v5 and the trace format to 8 (the v7→v8 migration writes `ctime = mtime`, `btime = 0`: what a format-7 run answered). The crash model stages fsynced times by inode and restores all four verbatim through storage-layer setters, including checkpointed and newly surviving symlinks. `utimensat`/`futimens`/`utimes`/`futimes`/`lutimes`/`utime`/`futimesat` are C interposers and SUD rows (`utimensat`, `utime`, `utimes`, `futimesat`) over two entries, `patina_utimensat`/`patina_futimens`: `UTIME_OMIT` leaves a time alone, `UTIME_NOW` resolves to the same instant the driver would stamp, both `OMIT` is the kernel's early success, an out-of-range `tv_nsec`/`tv_usec` is `EINVAL`, a descriptor-form `O_PATH` call is `EBADF` (the empty-path form supports it), `AT_SYMLINK_NOFOLLOW` names a link's own times; glibc's `utimensat` refuses a null path (`EINVAL`) and spells the descriptor shape `futimens`, which the C door mirrors while the raw row keeps the kernel's null-path form. `stat`/`fstat`/`fstatat`/`statx` report the modeled times, the identity's owner, the virtual volume's block geometry, and — `statx` — an honest mask (`STATX_BASIC_STATS` except unmodeled `STATX_BLOCKS`, plus `STATX_MNT_ID`; `STATX_BTIME` when asked); a directory's `st_nlink` is `2 + subdirectories`. **Ownership.** `st_uid`/`st_gid` come from ONE accessor (`patina_uid`/`patina_gid`, `registry::IDENTITY_UID`/`IDENTITY_GID`, which `getuid`/`geteuid`/`getgid`/`getegid` also answer from); `chown`/`fchown`/`lchown`/`fchownat` (C + SUD rows) are a comparison against it — its own ids or -1 succeed, killing the setuid bit and the setgid bit of a group-executable file on a non-directory and moving `ctime` through the one mode entry, any other id is the `EPERM` an unprivileged process gets; a symlink named itself moves its own ctime, and FIFO endpoints reach the retained inode even after unlink. Descriptors without a modeled inode refuse loudly rather than succeeding without an effect. `mkdir` drops setuid/setgid from its request, as `vfs_mkdir` does (found by the `fs/owner` probe). **Sizes.** `truncate`/`truncate64` (C + SUD row) are one new driver operation, `set_len_by_path` (`FsSetLengthByPath`); `fallocate`/`fallocate64`/`posix_fallocate` (C + SUD row) are one, `allocate` (`FsAllocate { zero, keep_size }`), so a gigabyte reservation or hole is one trace event: mode 0 and `KEEP_SIZE` reserve, `PUNCH_HOLE|KEEP_SIZE` and `ZERO_RANGE` zero, the range-shifting modes are `EOPNOTSUPP`, and the refusals come in the kernel's order (`EINVAL`, `EOPNOTSUPP`, `EBADF`, `ESPIPE`, `EISDIR`, `ENODEV`, `EFBIG` — with Linux 6.8's `EOPNOTSUPP` for the self-contradictory modes, host-checked). `ftruncate` on a directory or a read-only descriptor is `EINVAL` (`do_sys_ftruncate`); by name a directory is `EISDIR`. `access(X_OK)` honors the entry's `x` bit on both doors. All fs effects sample their clock after modeled latency; `FsTime::Now` is resolved at that same boundary before concrete values are recorded. A missing clock refuses by name. Zero-count I/O changes neither times nor size, and EOF reads preserve the cursor. Guest-sized growth uses fallible reservation, reporting ENOSPC instead of aborting; fallocate range overflow is EFBIG. Unsigned-nanosecond timestamps reject pre-epoch and overflowing seconds with EINVAL, an explicit registry gap rather than wrapping (Linux accepts and clamps wide positive values). **Gates.** The `fs-mem` unit tests (each RED against the two-timestamp filesystem), the trace migration test, and three conformance scenarios — `fs/times`, `fs/owner`, `fs/size` — host-checked through every vehicle; every check is a relation between two readings (never an absolute time) and none depends on the host mount's atime policy. The scenarios carry no owner, directory-link-count or birth-time gap; unmodeled allocation accounting keeps a narrow statx-mask gap. `truncate` stopped being the planted filesystem escape of the gate-level e2e; `acct(2)`, refused by decision, is the representative now.

29. Syscall conformance as live-oracle tests (syscall-conformance arc, step 2). The scenarios are plain functions in `crates/patina-conformance`, built into one probe binary; `crates/cargo-patina/tests/native_conformance.rs` runs each natively and under patina in the same test, through every vehicle the architecture has, and compares the observations with no committed expectation: exact but for the normalizations the scenario API declares at its call sites and each scenario's gaps. A gap is a strict expected failure — every differing field with its exact patina value, or the exact stop (event count, ending, diagnostic) — so a gap patina stops showing fails its test. Record/replay identity, recorded-trace facts, the strace leak run and the direct-termination check run on every completed patina run. Applicability is detected (a kernel too old for a covered row or implementing an asserted-absent one, SUD, strace) and reported as not run with its cause. Scenarios own a per-run temporary directory and reap forked children under a deadline. Each scenario declares the registry rows and symbols it covers; `mise run conformance:coverage` lists every entry no scenario or exclusion covers, and `PATINA_REQUIRE_HOST_ORACLE=1` (with the SUD and strace knobs, set in CI) makes not-run a failure. On arm64 the legacy rows keep their libc door and issue the generic table's kernel shape through `syscall(2)`.

30. Conformance gaps closed in the native shim. The dispatcher decodes raw open(2) and F_GETFL flag words with the target architecture's kernel values, from the kernel uapi headers (`linux-raw-sys`), instead of a table copied from x86_64: on arm64, `O_DIRECTORY`/`O_NOFOLLOW` opens stopped nine fs scenarios' `syscall` vehicle and F_GETFL reported x86_64's `O_LARGEFILE`; the C `fcntl(F_GETFL)` takes the same kernel bit (glibc spells the macro 0). The directory snapshot both doors read (`patina_read_dir`) lists `.` and `..`; glibc's `getdents64` is interposed by forwarding into the dispatcher's row, and a directory's position lives behind `patina_seek`, so the libc wrapper and a raw `getdents64` share one iteration; `lseek` on a directory answers as tmpfs does (`SEEK_SET`/`SEEK_CUR` move the position, `SEEK_END` is `EINVAL`) and `d_off` is a cookie it resumes from. `getrandom` validates flags, refuses a null buffer and clamps to `MAX_RW_COUNT` as the kernel does, in one entry both doors call (`patina_getrandom`). `newfstatat`/`statx`/`unlinkat` answer the kernel's `EINVAL` for a flag the kernel does not accept (they answered `ENOSYS`), judged before the descriptor in both doors, `flock` answers 0 to a `LOCK_MAND` request on an open descriptor, a directory renamed onto a non-directory is `ENOTDIR` and onto a non-empty directory `ENOTEMPTY`, and a hard link to a directory is `EPERM`. The dispatcher's remaining errno, `AT_*`, `S_IF*`, `DT_*`, `F_*`, `LOCK_*` and futex constants also come from the uapi crate. Each fix removed its gap declaration; the unit pins are `sud::tests::open_flags_decode_with_this_architectures_values` (libc-crate values as an independent oracle; RED on arm64 before), `sud::tests::flag_words_the_kernel_refuses_or_ignores`, `directory_iteration_tests` (the `.`/`..` listing and the directory seek), and fs-mem's `a_directory_moves_only_onto_a_directory_and_is_never_hard_linked`.

Remaining:

1. Non-zero TCP latency over `SimNet`.
2. Cross-machine stress and a usable macOS whole-run syscall trace if a future `ktrace`/OS version exposes enough path context for a default-deny gate.
3. Syscall-user-dispatch arm64 enablement once generic-entry kernels ship (slice 3's kernel-dependent half, a probe flip — the number table is already arch-complete; slice 2 and slice 3's kernel-independent parts are delivered in items 18–19 above).

Ordinary programs built through `cargo patina build` — a single Rust source or a whole Cargo package with dependencies and build scripts — now claim supported `std` calls use Patina, with threads managed on both platforms and both verified locally by the validation scripts (macOS directly; Linux in a VM). Scheduling granularity differs deterministically: on macOS every interposed lock operation is a scheduling point, while on Linux uncontended lock operations are pure userspace atomics, so scheduling points occur at futex contention — Linux interleaving is contention-granular, macOS is lock-granular; both are seed-stable and seed-varying.

## Slice 5: native ABI, capture, crash, and stability — Partial foundations

Acceptance level: V5 is not complete.

Completed foundations:

- trace file and timeline-event resource limits;
- corruption, structural mismatch, and unsupported-version rejection;
- trace schema migration: prior supported non-crash formats (v1, v2, v3, and v4) migrate losslessly in memory on load with fixtures for supported, unsupported, malformed, and structural inputs; bundles are never rewritten on disk and only the current format version is written;
- compact trace byte encoding (format 3): bundles are written as compact JSON with base64 byte payloads instead of pretty-printed number arrays, cutting the representative workload from ~344 to ~124 bytes/event; the file stays valid JSON, so `jq`/`python3 -m json.tool` still render it for humans;
- self-contained fault replay (format 4): a record run stores its fault configuration in trace metadata so replay needs no knobs re-supplied; the recorded config is authoritative, and a pre-format-4 trace keeps the historical re-supply behavior. Fresh-process filesystem crash restart is native-only: native `--fs-crash-at` and torn granularity record and replay across both incarnations, Cargo/WASI refuse them, and campaigns do not draw them. Other fs error/short-I/O/latency, sleep/net faults and base latency retain flag-free replay. The `replay` subcommand rejects re-supplied fault knobs up front;
- trace lifecycle protocol (format 5): operation events carry a global order and incarnation id, timelines carry lifecycle markers in the same order namespace, non-crash v1-v4 traces migrate to linear `Start(0)`/`End(0)` lifecycles, and legacy v1-v4 traces containing `Operation::FsCrash` fail closed with `LegacyCrashSemantics` rather than being reinterpreted as crash-restart;
- self-contained argv replay and a `replay` subcommand: `run --record` captures the guest arguments (`argv[1..]`, everything after `--`) into the trace metadata as an additive field, so a run recorded with non-default arguments reproduces them without the operator re-passing the `--` section — the fix for a real incident where a divergent default argv caused a confusing mid-run trace operation mismatch. `cargo patina replay <artifact|source|pkg> <trace>` is the sole replay entry point for all three families, routed by the same artifact inference as `run`: a WebAssembly module replays under WASI, a native binary under the native supervisor, and a directory/`Cargo.toml` (no `--target`) under the Cargo package family. It restores every semantic input (seed, fault knobs, and — native — buggify and guest argv; WASI — the `--arg` guest argv) from the trace and exposes no semantic flags — only each family's genuine host inputs (native: `--fingerprint`, `--mount` corpus re-supply, `--allow`/`--allow-unsupported-symbols`; WASI: `--fuel`/`--env`/`--socket`/`--preopen` and resource limits, verified through the fingerprint). The Cargo and WASI families also carry the timeline/branch controls (`--timeline ID`, or `--branch --from N --branch-seed S --branch-id ID [--parent ID]`); native traces are single-timeline. `run`/`test` and the WASI `run` no longer carry any replay/branch/timeline flag, and the seed-driven fault knobs plus (WASI) the `--arg` guest argv are recorded into the trace metadata so replay restores them flag-free across families. A `--` section passed to `replay` must match the recorded arguments byte-for-byte or the replay is refused up front naming both lists; a pre-argv trace (absent field) keeps taking its arguments from the command line. `argv[0]` is supervisor-normalized to a fixed name (`patina-guest`) so the host binary path never leaks into the guest's `std::env::args()` and traces stay portable across machines; the argument list is metadata, not a fingerprint input (the recorded op-stream already reflects any argv-dependent behavior);
- failure-oracle delta debugging for main timelines, leaf branch suffixes, and non-leaf branch trees (protected inherited prefix, reducible suffix), plus scenario/parameter/seed reducers (seed reduction is bounded ascending canonicalization);
- a whole-image checkpoint/rollback crash filesystem integrated with traces, with seeded torn writes (configurable granularity and probability), optional sub-block byte-granularity tearing of the final unsynced write (a partial page differing from both the durable and applied images), rename-atomicity on/off, directory-fsync durability, and in-process storage rollback that preserves open handles and their append-at-EOF semantics;
- explicit read-only host capture with path containment, replay without host I/O, and failure on branch misses;
- prefixed and opt-in POSIX native filesystem symbols with mixed C/Rust probes, plus managed pthread synchronization (Slice 4);
- bounded multi-process seed exploration;
- performance budgets in `patina-dst-bench`: a hard trace bytes-per-event gate runs in `cargo test`, structural gates always run, and generous timing ceilings are `#[ignore]`d opt-ins.

- schedule reducers: `reduce_schedule` rewrites recorded `SchedulerNext` outcomes toward a canonical schedule — longer runs per task (switch collapsing) and lowest-task-id-first at switch points — accepting a candidate only when the failure oracle confirms the failure survives; protected inherited prefixes are never rewritten, and the combined minimization entry points run pruning, suffix shrinking, and schedule reduction to a joint fixed point.

- native audit/run blocker resolution (three coupled gate fixes):
  1. **Source-first `--package`/`--bin` for `audit` and `run`.** The help advertises `audit <SOURCE.rs|DIR|Cargo.toml> [--package NAME] [--bin NAME]`, but `audit` (and, under `--target`, `run`) rejected the flags. A single routing-layer pair — `take_package_bin` (extract the selection from the head, before any `--` guest section) + `apply_package_selection` (thread it into the build-on-the-fly spec) — now wires workspace-member/binary selection into both verbs uniformly, exactly as the `build` verb does; a stray selection on a single `.rs` source or an already-built artifact fails closed with a precise message. (A bare directory/`Cargo.toml` `run` with no `--target` stays the Cargo package family, where Cargo owns `--package`/`--bin`.)
  2. **audit/run static-gate parity.** One `effective_native_allow` constructor builds the gate's effective allow set (the shim control-plane `dlsym` residue + the operator's `--allow`) and is called by BOTH the standalone `audit` and the pre-run `run` gate, so the static surface `audit` reports equals the surface `run` enforces — closing the reported disparity where `audit` flagged the control-plane `_dlsym (dynamic-loading)` that `run` silently permitted. Default-deny is unweakened: the only auto-tolerated symbol is the fixed control-plane residue; every real escape stays denied by both paths.
  3. **macOS CoreFoundation/Security classification, gate stays default-deny.** macOS CoreFoundation/Security symbols (`CF*`/`kCF*`/`Sec*` — the `rustls-native-certs` / native TLS trust-root surface) were bare `unknown-import`; they now classify as `macos-framework`, and the run refusal carries a determinism note naming the host-keychain/trust-store non-reproducibility and the `--allow-unsupported-symbols` allow path with its qualified-determinism caveat.

- custom `#[global_allocator]` support (jemalloc): the tikv-jemallocator blocker is fixed structurally so a custom global allocator runs deterministically rather than being refused. Root cause: the shim's synchronization interposers register each lock lazily through the *guest* allocator while holding the shim spinlock, so a custom allocator whose own init takes an interposed lock re-enters the half-initialized allocator (jemalloc: `malloc_init_hard` → `os_unfair_lock` → shim interposer → allocate → `malloc_init_hard`). Three structural pieces, in `patina-dst-native-shim`: (a) the interposer-reachable synchronization tables (`ThreadTable.mutexes/conds/rwlocks` + waiter deques) are backed by the real libc allocator via the host-alias table (`hostcoll` — a Rust `#[global_allocator]` replaces `__rust_alloc`, never the C `malloc` symbol, so `RTLD_NEXT` reaches libSystem/glibc, whose locks are not interposed), so the lock registration no longer touches the guest allocator; (b) a bootstrap window (`SHIM_BOOTSTRAP`, until the runtime is installed, before `main`) during which the allocator's own eager constructor-driven init runs its init-reachable interposers natively — `os_unfair_lock` on the real primitive, `readlink`/`mach_absolute_time` answered without allocating or requiring the runtime; (c) a reentrancy guard (`SPIN_DEPTH`) forwarding an allocator-internal `os_unfair_lock` reached reentrantly while the shim holds its spinlock (the scheduler path allocates through the guest allocator) to the real primitive. The two residual init symbols are resolved properly — `issetugid` interposed to a deterministic 0, `___chkstk_darwin` allowlisted as a pure stack probe — so the MRE audits clean and runs with no `--allow` flags, seed-stable and record→replay identical. The prior static `custom-global-allocator` refusal (and its detector/diagnostic/tests/doc rows) is deleted; with the default allocator none of this fires (libc's own locks are not interposed), so it is zero-impact for existing guests. Residuals (VALIDATION.md): no automated multi-threaded-jemalloc e2e; Linux jemalloc (`pthread_mutex`/futex) needs the analogous handling verified in the Linux VM.

Open hardening items for this area live in VALIDATION.md.

## Slice 6: cooperative-SUT SDK — Partial (Milestone C)

Acceptance level: V6 is not complete.

A FoundationDB-`BUGGIFY`- and Antithesis-style SDK lets a system-under-test
cooperate with the deterministic simulator. It lives in the existing `patina`
crate as a dependency-light SDK (the `buggify!`, `buggify_with_prob!`,
`buggify_delay!`, `buggify_knob!`, `always!`, `sometimes!`, `reachable!`, and
lifecycle macros plus `patina_dst::is_simulated()`/`patina_dst::rng()`). The
explicit-context API (`run`/`run_with`, `Context`, the ABI re-exports) lives in
the separate `patina-dst-runtime` crate, so the SDK carries no runtime
dependencies. A plain `cargo build` of an adopter links no runtime and every
macro is a no-op or a plain fallback, so instrumented code compiles and runs
normally outside Patina — no `cfg(patina)` appears in adopter code.

Completed foundations (Milestone A):

1. **Deterministic decisions, pure functions of the seed.** Per-run site
   *activation* derives from `(root_seed, label, activation_permille)` and
   per-evaluation *firing* from a counter-keyed splitmix PRF over
   `(seed, label_hash, eval_counter)`; nothing is recorded per evaluation, so the
   trace never bloats and replay re-derives every decision. FoundationDB defaults
   apply: activated sites fire at 25% per evaluation and ~25% of sites are active
   per run, both configurable.
2. **Site identity and uniqueness.** Labels are explicit strings; a label reused
   at a different call site (`file:line`) is a fatal duplicate that emits a
   `PATINA_BUGGIFY_DUPLICATE_LABEL` marker and aborts. Runtime counters still
   register lazily at first evaluation, but literal-label SDK macro calls also
   emit a dependency-free link-time table under `cfg(patina)`: native uses a
   linker section, WASI uses custom-section bytes, and both embedders declare the
   sites before execution. Declarations do not compute activation or enter trace
   metadata, but they make never-reached sites visible to reports. Verdict
   labels (below) share this namespace without being sites: a verdict registers
   nothing, so the duplicate rule does not apply to it and repeating a label is
   how verdicts aggregate.
3. **Damage-control cutoff.** A virtual-time cutoff (default 300 virtual seconds,
   configurable) after which firing stops, checked against the unrecorded
   monotonic clock read.
4. **Self-contained replay and fail-closed fingerprint.** The realized
   configuration, active-site set, and knob picks are recorded in the trace
   metadata (additive `buggify` field; old traces migrate clean, conflicting
   replay knobs fail closed exactly like the fault knobs). Enabling buggify folds
   a `+buggify` component into the run fingerprint, reconstructed at replay from
   the trace, so a buggify trace never cross-replays with a non-buggify build.
5. **`run --buggify[=permille]`** plus `--buggify-activation-permille`,
   `--buggify-cutoff-nanos`, and `--buggify-after-setup`, passed to the guest
   through the `PATINA_BUGGIFY*` control plane and recorded into the trace. The
   SDK reaches the runtime through two build-selected transports, both resolving
   to the *same* `patina-dst-runtime` buggify subsystem. On native, `build` injects an
   internal `--cfg patina_shim` (only on the shim-linked native paths) so the
   SDK's shim C ABI is referenced only where those symbols resolve. On WASI,
   `build --target wasi` injects `--cfg patina` (no `patina_shim`), under which the
   SDK lowers to a dedicated `patina_sdk` wasm import module (`buggify`,
   `buggify_delay`, `buggify_knob`, `always`, `sometimes`, `reachable`, `rng`,
   `is_simulated`, `lifecycle_setup_complete`, `lifecycle_event`) that
   `patina-dst-wasi-host` defines against the runtime. Without `cfg(patina)` — a plain
   `cargo build --target wasm32-wasip1` — the sites stay no-ops and the guest's
   import table grows *no* `patina_sdk` reference (proven by wasm inspection in a
   test), so adopters pay nothing.
6. **`PATINA_SDK_REPORT`** — one machine-parseable stderr line per run:
   declared-site count, registered/activated/fired counts, cutoff state,
   `declared_site=<label>|<kind>|@<file:line>` rows from the link-time table, and
   per-evaluated-site `sometimes`/`reachable` coverage, knob values, and
   `@file:line` identities, in the spirit of `PATINA_SCHEDULE_REPORT`. `cargo
   patina sites --exercised <stderr-file>` joins those rows to the static
   inventory.
7. **`patina_dst::rng()`** bridged to the root seed under Patina (a plainly-seeded
   fallback outside), as the hook for the property-based-testing wave.

Lifecycle gating is causal via the runner, not lookahead: with
`--buggify-after-setup` the runner *declares* that the guest calls
`setup_complete()`, so buggify stays inert until that call (intent comes from the
flag). If the flag is set and the guest never reaches `setup_complete()`, the run
records its trace and then fails loudly (`PATINA_BUGGIFY_SETUP_NEVER_CALLED` +
abort) — a declared-but-never-called gate is a harness bug, not a silent no-fault
run. Without the flag, buggify is armed from the start and `setup_complete()` is a
boundary/coverage marker.

Completed foundations (Milestone B):

8. **Causal setup gate.** `run --buggify-after-setup` lets the runner
   declare that the guest calls `patina_dst::lifecycle::setup_complete()`, so buggify
   stays inert until that call — a causal gate (intent from the flag, no
   lookahead) recorded in the trace metadata. A declared-but-never-called run
   records its trace and then fails loudly (`PATINA_BUGGIFY_SETUP_NEVER_CALLED` +
   abort): a silent no-fault run is a harness bug, not a pass.
9. **Campaign layer** (`testbeds/buggify-campaign.sh`, sourced by both sweeps):
   parses `PATINA_SDK_REPORT`, accumulates a cross-generation `campaign-state.json`
   (per-site kind/reached/activation/fire counts and sometimes-satisfaction), and
   adds two classes — `ALWAYS_VIOLATION` (per-gen, top severity, fires even on
   exit 0, never downgraded) and `SOMETIMES_UNMET` (campaign-level: a `sometimes!`
   site reached but never satisfied fails the campaign). A selftest proves both
   fireable and that `ALWAYS_VIOLATION` is not downgraded; it is wired into
   `testbeds/workq/fuzz-sweep.sh --selftest` without altering any existing gate
   priority. The live buggify demonstrator is `testbeds/workq` (durable work
   queue: fsync-skip/delay, ack-drop, and early-redelivery sites, `sometimes!`
   coverage on redelivery/dead-letter/dedup), whose buggify leg the shared
   campaign accumulator (`testbeds/buggify-campaign.sh`) drives directly.

Completed foundations (Milestone C — buggify on WASI):

10. **`patina_sdk` wasm import module.** The full cooperative-SUT surface reaches
    a `wasm32-wasip1` guest at parity with native. The `patina-dst` crate's macros
    lower, under `cfg(patina)` on wasm, to imports from a dedicated `patina_sdk`
    module; `patina-dst-wasi-host` defines that module against the **same**
    `patina-dst-runtime` buggify subsystem the native shim drives (activation, the
    counter-keyed firing PRF, the labels registry, the 300-virtual-second cutoff,
    the diagnostics report, and the lifecycle markers are reused, not
    reimplemented). `patina-dst-target`'s WASI audit allowlists exactly the eleven
    `patina_sdk` names alongside the Preview 1 surface. The fatal outcomes mirror
    the native shim: an `always!` violation reports its `violation` verdict and a
    duplicate label emits the `PATINA_BUGGIFY_DUPLICATE_LABEL` marker to the real
    process stderr, both trapping the guest, and the `--buggify-after-setup` gate
    emits `PATINA_BUGGIFY_SETUP_NEVER_CALLED` at finish. `patina_dst::rng()` routes
    through the host's `buggify_rng` draw (the seed-bridged buggify entropy
    stream), not the WASI `random_get` entropy, so it is not double-plumbed.
11. **CLI + fingerprint parity.** `cargo patina run <mod.wasm>` accepts
    `--buggify[=permille]`, `--buggify-activation-permille`, `--buggify-cutoff-nanos`,
    and `--buggify-after-setup`, applied to the in-process runtime through the
    shared `apply_buggify_env` accessor (the same path the fault knobs take). The
    buggify configuration records into the trace metadata (`BuggifyConfigRecord`)
    and is restored on a flag-free `replay`; enabling buggify folds a `+buggify`
    component into the WASI compatibility fingerprint (conditional, so a
    non-buggify run fingerprints unchanged), reconciled on replay from the trace,
    so a buggify trace never cross-replays with a plain one. `replay` refuses a
    re-supplied `--buggify` — the trace is authoritative.
12. **Sleep-jitter on WASI.** `Preview1Host::sleep_until` applies the seeded
    sleep-latency jitter at the single guest-facing sleep entry (which also backs
    `poll_oneoff` clock timeouts), so `--sleep-jitter-nanos` is now honored on a
    WASI `run` (the Milestone-B native-only rejection is removed). The draw is
    owned by the deterministic context, so a jittered run reproduces byte-for-byte
    on replay.
13. **WASI dogfood.** A buggify-instrumented `wasm32-wasip1` fixture
    (`testbeds/buggify-wasi`, several site kinds + a plantable `always!` violation)
    compiled through `build --target wasi` proves the full guest-side lowering:
    sites register and fire under `--buggify`, `PATINA_SDK_REPORT` is emitted and
    parseable by the shared `testbeds/buggify-campaign.sh`, record/replay is
    byte-identical, and cross-seed firing varies. `wasi-buggify-sweep.sh` runs a
    deterministic campaign (per-gen derived activation/fire, per-gen record→replay
    determinism check, fresh `out-wasi-buggify/` dir) reusing the campaign layer.

Completed foundations (point-solution DST arc, Wave B):

14. **`#[patina_dst::test]` under plain `cargo test`.** `patina-dst-macros`
    (directory `crates/patina-macros`, no external deps) provides the hand-rolled
    attribute, re-exported by `patina-dst` behind the default-off `macros`
    feature. The wrapper runs the body directly only when `patina_dst::is_simulated()`
    is true; otherwise it discovers `cargo-patina` through absolute `PATINA_CLI`
    or `PATH` and delegates to native harness mode: `cargo patina test <DIR|Cargo.toml> --harness-target NAME --exact MOD::test`.
    Missing CLI discovery is a test
    failure, never a skip. The adopter fixture `testbeds/patina-macro-adopter`
    proves a passing sweep, a seeded failure panic carrying the seed plus
    `cargo patina test`/`cargo patina replay` repro commands, a PATH-scrubbed
    refusal, double-run identical failure blocks, and the no-new-deps cargo tree.

Completed foundations (outcome-channel arc, Wave A — the verdict ABI):

15. **One verdict verb, kinds as data.** `patina_verdict(kind, label+len,
    detail+len)` in the native shim, the matching `patina_sdk` `verdict` import
    on wasip1, and `Context::verdict` in process; `patina_dst::verdict` is the
    SDK sugar over them. `VerdictKind` (`patina-dst-abi`) is a closed enum whose
    `u32` wire values are pinned by test on both sides of the FFI, and an
    unrecognized kind is refused (`EINVAL` natively, a trap on WASI) rather than
    defaulted. Every call records an `Operation::Verdict` boundary event, so a
    replay whose verdict stream diverges fails closed like any other operation
    mismatch; the format needs no version bump because serde tags variants by
    name. The runtime does no I/O of its own mid-run: it queues each verdict's
    `PATINA_VERDICT` line and the embedder drains it into captured stderr (so
    lines interleave with guest output and survive an abort's flush), while an
    in-process guest's undrained lines print at `Context::finish`. `--format
    json` folds them into the envelope as `verdicts[]` (`seq`, `kind`, `label`,
    `detail`), decoded by the same `patina-dst-abi` codec that renders them, with
    `label`/`detail` escaped so no guest byte can forge a second marker line. An
    `always!` violation lowers to a `VIOLATION` verdict on the invariant's label,
    and Wave B removed the embedders' legacy `PATINA_ALWAYS_VIOLATION` marker, so
    the verdict is the only announcement (`docs/arcs/outcome-channel.md`).

Completed foundations (custom-ops arc, Wave A — record/replay custom operations):

16. **Guest-declared custom operations.** `patina_custom_op_begin(label+len,
    key+len, fault_eligible, out_len)` returns "record", "replay", or "fault"
    (a seeded fault fired — Wave B); the guest then calls
    `patina_custom_op_record(result+len)` or
    `patina_custom_op_replay_result(out, out_cap)`. The `patina_sdk`
    `custom_op_begin`/`custom_op_replay_result`/`custom_op_record` imports mirror
    it on wasip1 and `Context::custom_op*` covers an in-process guest;
    `patina_dst::custom_op_bytes` is the zero-dependency SDK sugar and
    `patina_dst::custom_op` (default-off `custom-ops` feature) adds serde-typed
    keys and results, encoded with `serde_json` at the SDK — build-owned, not
    ABI-owned, since the boundary and the trace carry opaque bytes and a trace
    only replays against the binary that recorded it. Three verbs rather than one
    with a phase argument: the phases carry different argument shapes and
    directions, and the property the verdict doctrine protects (no new symbol per
    op class) holds anyway, because the class is the `label`. Each call records an
    `Operation::CustomOp { label, key }` with the result as `Outcome::Bytes`, so a
    replay whose label or key diverges is refused by name rather than answered
    from a recording of a different question; the format needs no version bump
    because serde tags variants by name. Refusals are fatal by design
    (`PATINA_CUSTOM_OP_REFUSED` + abort natively, a trap on WASI): a replay
    divergence, a nested or unclosed operation, or a *modeled* boundary operation
    performed between `begin` and `record` — the last caught at record time,
    naming the label and the count, because replay skips `perform` and could never
    reproduce those events. A custom op grants no audit exemption: `perform` runs
    for real on the record pass, so an un-modeled raw effect inside it refuses and
    audits exactly as it would anywhere else.

## Slice 7: exploration tier — Partial (wave 12)

Directed exploration policies that steer *which* interleavings and fault
combinations a seed reaches, layered over the deterministic drivers. Every policy
is default-off, seed-derived, recorded into the trace metadata as an additive
`Option` field (`RunMetadata::schedule_policy`, `RunMetadata::swarm`; both
`deny_unknown_fields`, so an older runtime reading a newer trace rejects the
unknown policy rather than silently ignoring it), reconciled authoritatively on
replay, and folded into the compatibility fingerprint (`+pct`/`+starve`/`+swarm`,
reconstructed from the trace on `replay`) so a policy trace never cross-replays
with a plain build. The default (uniform-random) scheduler path is byte-for-byte
unchanged — the canonical seed-7 sequence and every fault/buggify hash are
preserved — because the policies draw exclusively from their own
domain-separated `SplitMix64` streams and the default `choose` branch is the
original modulo draw verbatim.

1. **PCT scheduling policy** (`patina-dst-sched-det`): Probabilistic Concurrency
   Testing (Burckhardt/Musuvathi, PLDI 2010) as an alternative `DetScheduler`
   selection policy over yield-point boundaries. Each task draws a random
   priority from a high band; `d-1` seed-placed priority-change points demote the
   running task as the schedule advances; the highest-priority runnable task
   always runs (ties by lowest task id). `cargo patina run --sched-pct[=D]`
   (`PATINA_SCHED_PCT`, default depth 3) with `--sched-pct-steps N`
   (`PATINA_SCHED_PCT_STEPS`, the expected schedule length over which change
   points are distributed). `d=1` is priority-ordering with no preemption; `d>=2`
   introduces `d-1` preemptions. The policy affects only the record/seeded
   selection path (`next()`); replay consumes the recorded task stream through
   `select()`, so replay is byte-identical regardless of policy.

2. **Swarm fault-class selection** (`patina-dst-runtime`): `cargo patina run --swarm`
   (`PATINA_SWARM`) applies a seed-derived subset of the enabled fault classes
   this generation instead of always-all (swarm testing). At `build` time, for
   each enabled class (`crash`, `sleep_jitter`, `net_jitter`, `net_drop`,
   `net_latency`, `buggify`) a domain-separated per-class coin (seed ^ domain ^
   class-hash) decides keep/drop; the masked configuration is what every driver
   and the recorded `FaultConfigRecord` consume, so replay reproduces the subset
   verbatim, and a `SwarmConfigRecord` documents the candidate set and the
   selection so the trace is self-describing. Subsets vary across seeds; the
   always-all default (no `--swarm`) is unchanged. Dropping a class retracts
   everything that class declared — its configuration resets, and its
   compatibility-fingerprint component (`+buggify`, the only one today) is
   stripped — so a masked generation's fingerprint and metadata describe the run
   that happened. `PATINA_SWARM_REPORT` and `PATINA_SDK_REPORT`'s
   `swarm_deselected` field keep "swarm dropped it" distinguishable from "never
   requested". `--swarm` over a run with no fault class enabled has nothing to
   select: the report says `vacuous=1`, the runtime warns, and a campaign or
   sweep generation is classified `VACUOUS_SWARM` rather than counted clean —
   dropping every candidate of a non-empty set stays a legitimate draw. See
   [docs/bugs/swarm-buggify-fingerprint-coherence.md](./docs/bugs/swarm-buggify-fingerprint-coherence.md).

3. **Starvation intervals** (`patina-dst-sched-det`): `cargo patina run --starve[=N]`
   (`PATINA_SCHED_STARVE`, default 3 intervals) with `--starve-max-len M`
   (`PATINA_SCHED_STARVE_MAX_LEN`) and `--starve-window W`
   (`PATINA_SCHED_STARVE_WINDOW`). Bounded, seed-chosen intervals during which a
   seed-chosen residue-class subset of tasks is not selected, to surface
   starvation/liveness assumptions. **Liveness safety is guaranteed by aging**: a
   per-task consecutive-skip counter force-schedules any task once it has been
   deferred `aging_cap` (= `max_len`) decisions in a row, so no task is ever
   starved unboundedly (the "intervals must end" contract expressed in decision
   space; proven by `starvation_aging_bounds_consecutive_skips_guaranteeing_liveness`).
   A step that would starve *every* runnable task falls back to the full set and
   emits a loud `PATINA WARNING` (vacuous starvation), counted in
   `starve_vacuous`. **Documented limitation (native shim):** starvation is
   liveness-safe for guests whose synchronization is interposed
   (mutex/condvar/futex, and any `--yield-points` build for most configs), but a
   guest with an *invisible atomic spinlock* (e.g. std's queue `RwLock`/`Parker`
   fast path) held across a boundary can be driven into a mutual-spin livelock by
   adversarial deferral — the same atomics-only window the vacuous-schedule
   diagnostic flags as unreachable, forced to manifest. `run` emits a loud
   `PATINA WARNING` when `--starve` is used on a non-`--yield-points` binary, and
   the fuzz-sweep keeps starvation OPT-IN (`PATINA_SWEEP_STARVE=1`) so the
   always-on canary never wedges; PCT and swarm are always-on there. As a
   detection backstop (NOT a liveness guarantee), the uninterposed supervisor arms
   a generous real wall-clock stall detector *only* when `--starve` is set
   (default 60 s, `PATINA_STARVATION_STALL_SECS` override): an already-hung run is
   killed with a named `patina: starvation stall` fatal and a distinct nonzero
   exit (`111`), so a sweep classifies `STARVATION_STALL` instead of silently
   losing the generation. It never touches the recorded operation stream of a run
   that completes. It is an ELAPSED-TIME deadline, not a progress detector — the
   supervisor cannot see the scheduler's decision counter, so it cannot separate a
   wedge from a run that is merely slower than the deadline — which is why a
   campaign reports `STARVATION_STALL` but does NOT count it as a distinct bug
   found: the backstop arms only under `--starve`, so the wedge is patina's own
   injector meeting the limitation above, not a verdict on the guest. A guest that
   livelocks on its own, where the scheduler still has decisions to make, is the
   liveness watchdog's `LIVENESS`, which is counted.

4. **Bug-depth metrics**: an active exploration policy emits a machine-readable
   `PATINA_SCHEDULE_POLICY` stderr line at finalization (via the new
   `SchedulerDriver::policy_report`) — PCT depth, change points placed and *hit*,
   starvation events and vacuous hits, decision count, and a `bug_depth` estimate
   (priority-change points hit + starvation exclusions). `fuzz-sweep.sh` parses
   it to annotate each generation (`policy(<mode> bug_depth=N ...)`), extending
   the `life=`/`cause=` scheme, so a found failure carries an estimate of how deep
   an interleaving its schedule required; a vacuous starvation configuration is
   surfaced loudly.

The fuzz-sweep SCHEDULE tier gains a seed-derived policy overlay (PCT by default,
starvation opt-in) on the yield-points binary, and the BREADTH/TRAFFIC tiers gain
a seed-derived `--swarm` overlay when >=2 fault classes are enabled. The
`--selftest` covers `PATINA_SCHEDULE_POLICY` parsing (bug-depth extraction) and
vacuous-starvation detection.

## Slice 8: liveness watchdog + campaign — Partial (wave 13)

A deterministic, virtual-time-only liveness detector and a first-class product
surface (`cargo patina campaign`) generalizing the shell campaign machinery.

1. **Liveness watchdog** (`patina-dst-runtime`): a no-progress detector that reports a
   structured, classifiable violation on a single stderr line — the interface
   contract `PATINA_VIOLATION liveness detail=no-progress vtime_ns=<n> budget_ns=<n>`
   (and `PATINA_VIOLATION converge detail=did-not-converge vtime_ns=<n> budget_ns=<n>
   last_fault_vtime_ns=<n>` for heal-then-converge) — rather than letting a wedged
   run advance virtual time to a silent budget. It reads virtual time and
   the scheduler's policy state ONLY — no wall clock in the detection path (the
   wall-clock `STARVATION_STALL` supervisor backstop stays separate and unchanged).
   "Progress" is defined by boundary-op class: the pure scheduling/time/wait ops
   (`SchedulerNext`, `SleepUntil`, `ClockNow`, `TaskYield/Park/ParkTimed/Wake`,
   `NetNextDelivery`) are non-progress; every genuine effect (filesystem, entropy,
   task spawn/complete, network data) resets the no-progress clock. An arm fires
   when the run has churned (`>= 4` consecutive non-progress ops, so a single long
   legitimate sleep can never trip it) for more than the configured budget of
   virtual nanoseconds without progress — so a run that COMPLETED, or that reached
   genuine quiescence (idle/blocked with no timers, virtual time frozen), never
   fires, while a pure timer/park churn wedge does. Documented limitation: a system
   that keeps doing real I/O but never reaches an application goal counts its I/O
   as progress; that needs an application-level oracle. Detection is
   record/seeded-only (like the policy report); replay consumes the authoritative
   trace.

   **Critical coupling to the exploration policies:** the watchdog consults the
   scheduler through a new `SchedulerDriver::liveness_deferring()` — true whenever
   the most recent decision deliberately withheld a runnable task (a starvation
   interval excluding a runnable task, or PCT priority ordering deferring a
   strictly-lower-priority runnable task). While the scheduler is deferring, the
   no-progress clock is reset, so a deliberate starvation interval or a PCT
   priority deferral is never misreported as a liveness violation; only genuine
   no-progress beyond policy-explained deferral trips it.

   **Heal-then-converge oracle** (`--converge-within[=NANOS]`): a second watchdog
   arm that arms at the fault-window end — the buggify damage-control cutoff when
   buggify is enabled, else run start, overridable with `--heal-after NANOS` — and
   requires the guest to converge (complete or fall quiescent) within a
   convergence budget of virtual time. It generalizes what testbed sweep scripts
   assert ad hoc.

   **Replay discipline:** the watchdog config records into the trace metadata as an
   additive `RunMetadata::watchdog` field (`deny_unknown_fields`), but is
   deliberately NOT a fingerprint input and NOT reconciled fail-closed on replay,
   because it is schedule-invariant: it only ADDS a possible violation report and
   never records a boundary op or perturbs selection. Proven by a runtime test that
   records a healthy run with and without the watchdog and asserts a byte-identical
   recorded op stream (the metadata differs only by the informational field). The
   native shim aborts fail-closed on a `RuntimeError::Liveness` (flushing the
   captured marker first) so a wedged guest cannot ignore the errno and spin on.
   Knobs travel the shared `PATINA_LIVENESS_WATCHDOG_NANOS` /
   `PATINA_CONVERGE_WITHIN_NANOS` / `PATINA_HEAL_AFTER_NANOS` control plane and are
   applied by native `run`, WASI `run`, and the in-process runtime through
   `RuntimeConfig::apply_liveness_env`. A default-on `PATINA_LIVENESS_REPORT` line
   at a clean finish proves the watchdog was armed and did not fire (non-vacuity).

2. **`cargo patina campaign`** (`crates/cargo-patina/src/campaign.rs`): a
   config-driven, deterministic sweep. Each generation is an independent child
   `cargo patina run --record` whose seed and every randomized knob (buggify,
   swarm, PCT, fault knobs, the liveness budgets) are a pure function of
   `SHA-256("patina-campaign-<seed_base>-<gen>")` — no wall clock, no `$RANDOM`,
   exactly the fuzz-sweep scheme — so a re-run reproduces identical outcomes and
   signatures. The spec is a JSON file (`--spec`, `deny`-unknown-keys) and/or flags.
   A pure classifier assigns one of fourteen outcome classes — `OK` / `VIOLATION` /
   `LIVENESS` / `VACUOUS_FS_FAULT` / `VACUOUS_DNS_FAULT` / `VACUOUS_NET_FAULT` /
   `VACUOUS_ENTROPY_FAULT` / `VACUOUS_CLOCK_FAULT` / `VACUOUS_SWARM` /
   `GUEST_ABORT` / `FAIL_CLOSED_ABORT` / `STARVATION_STALL` / `INFRA` /
   `UNCLASSIFIED` — from each generation's `patina.result/v1` envelope alone
   (the child runs `--format json`), with fuzz-sweep's strictness: an explicit
   finding is never downgraded, exit 111 is `STARVATION_STALL`, a generation that
   asked for `--swarm` with no fault class to select from is `VACUOUS_SWARM` (an
   inert exploration knob is a coverage failure, not a clean run), a Patina
   fail-closed refusal (the envelope's `refusal` record) is its own class distinct
   from an unattributed guest abort (`GUEST_ABORT`), a child that produced no
   envelope at all is `INFRA`, and any nonzero exit matching no class lands LOUDLY
   in `UNCLASSIFIED` rather than being silently OK or mislabeled. Nothing in the
   classifier reads guest output: violations come from `verdicts[]`, liveness from
   `runtime_findings[] source=liveness`, and per-plane vacuity from
   `fault_reports{}`. A guest that never calls the verdict ABI declares its own
   rules in the campaign spec (`classify.patterns` / `classify.exit_codes`), the
   only path from output text to a class, and one that can only ADD a finding
   where the envelope reached none. A per-failure signature (class +
   digit-collapsed finding shape + policy bug-depth annotation) is
   accumulated into `signatures.json` in the output dir: repeats dedup, novel
   signatures are flagged with their first-seen generation and a reproduce command
   (`cargo patina replay <trace>` when a valid trace exists, else a deterministic
   re-run — a liveness/always abort writes no trace). A per-generation wall-clock
   `--timeout-secs` backstop kills a generation that hangs in a way the virtual-time
   watchdog cannot see (an uninterposed atomics-only busy loop), classifying it
   INFRA so one hung generation cannot wedge the whole campaign. Output is
   summary-first: a human report (novel/failing generations plus a periodic
   `--progress-every` heartbeat) or a `patina.campaign/v2` JSON envelope (class
   counts, deduped signatures, per-run detail for novel/failing generations, a
   `sdk_sites` summary, coverage gate details, and pointers to the full on-disk
   artifacts — the `patina.result/v1` family extended). Every generation's
   `PATINA_SDK_REPORT` is folded into `<out-dir>/sites.json` (schema
   `patina.campaign.sites/v1`, with `generations_observed` for continuation
   watermarks). A WASI campaign additionally accumulates **depth** — the family's
   honest stand-in for edge coverage, since `wasm32-wasip1` has no sancov: every
   run emits `PATINA_DEPTH_REPORT family=wasi fuel_consumed=... hostcalls_total=...`
   plus one `name=count` row per imported function actually called (counted in
   `Preview1Host`, surfaced through `WasiExecution::hostcalls` and the run
   envelope's `depth` object; suppress with `PATINA_DEPTH_REPORT=0`, which a
   campaign overrides for its own children). The campaign folds those lines into
   `<out-dir>/depth/meta.json` (schema `patina.depth.campaign/v1`): fuel high-water
   mark, cumulative hostcall sums, and a `depth_plateaued` flag from the same
   `--plateau-after` window over the weaker novelty signal "a new hostcall kind or
   a new fuel high-water mark". Depth is report-only — never part of a trace,
   fingerprint, or canonical hash — and never conflated with coverage in output.
   Both aux stores share the `generations_applied` watermark contract, so a resume
   that re-runs an interrupted generation contributes nothing rather than
   double-counting the non-idempotent sums. `--guided` closes the measurement loop:
   a generation's single 32-byte derivation input (which feeds its seed AND every
   knob) may be a mutation of the input of an earlier generation that opened new
   coverage or depth — ~75% of the bytes inherited from a fitness-proportionately
   chosen ancestor, the rest fresh — with the exploitation share decaying from
   700 to a 200 permille floor as the novelty drought approaches the plateau
   window, so a stuck campaign broadens rather than grinding. Guidance reads the
   novelty log truncated to entries BELOW the generation being derived, which
   makes it prefix-deterministic: a resumed campaign whose store sits one
   generation ahead of the cursor re-derives that generation identically. It is
   refused outright when no novelty signal exists (never downgraded to unguided),
   is part of the persisted spec so it cannot be toggled on a continuation, and
   reports its per-generation decision on `PATINA_CAMPAIGN_GEN`
   (`guided=exploit:<gen>|explore|none`) plus a `PATINA_CAMPAIGN_GUIDED_VACUOUS`
   line when it never steered anything. Missing depth is refused, not folded as
   zero: a cleanly finished generation without a depth line aborts the campaign
   naming the generation, a run whose fuel accounting reports 0 is refused
   outright, and a campaign where no generation reported depth prints
   `PATINA_CAMPAIGN_DEPTH_VACUOUS`. `sometimes!`/`reachable!` oracles that are never satisfied —
   including link-time-declared rows with `registered_gens=0` — fail the campaign
   by default unless `--allow-unmet-sometimes[=MIN_GENS]` explicitly waives the
   gate. `--selftest` proves every class reachable, the coverage gate classes,
   malformed-row rejection, the signature dedup/novelty logic, and the native
   coverage / WASI depth store detectors (fingerprint mismatch, plateau exactness,
   watermark idempotency, missing-depth refusal) and the guided-scheduling
   detectors (no-ancestor fallback, stream actually changes, ancestor inheritance,
   prefix-determinism, drought decay),
   mirroring the fuzz-sweep classifier selftest. The existing
   `fuzz-sweep.sh` and `buggify-campaign.sh` are untouched and remain the
   battle-tested reference.

3. **Dogfood** (`testbeds/liveness-campaign`): a buggify-gated planted-bug guest —
   when `buggify!("liveness-wedge")` fires the node never converges (an unbounded
   virtual-time retry churn), else it completes. An end-to-end test builds it and
   sweeps it: the campaign catches the planted `LIVENESS` bug on the generations
   that fire it, deduplicates the one signature across them, records a working
   reproduce command, and produces byte-identical outcomes, signatures, and
   `sites.json` coverage stores on a deterministic re-run.

4. **Repository config** (`.patina/config.toml`): `cargo-patina` discovers the
   nearest repo config, applies `[groups.*]` to `sites` rollups, and layers
   `[defaults.<verb>]` under explicit flags and `PATINA_*` env defaults. Defaults
   are validated through the help registry's value grammars, applied values are
   provenanced in JSON (and config-file defaults emit `PATINA_CONFIG`),
   `[defaults.replay]` is refused to preserve trace-authoritative replay, and
   campaign child runs receive `--no-config` plus run-default env scrubbing. The
   `.patina/out/` cache path is ignored via `.patina/.gitignore` on first write.

## Slice 9: advance-on-spin — Complete

The virtual clock's third advance mechanism, alongside a guest wait and the
deadlock rescue. It closes the *runnable clock-churn* gap: a guest that is
runnable and doing nothing but reading the clock observed frozen virtual time
forever, which is exactly the startup-calibration shape (`fastant`/`minstant`/
`quanta` busy-wait for a fixed window of monotonic progress inside a pre-`main`
constructor) and hung before `main` at 100% CPU.

1. **Advance-on-spin** (`patina-dst-runtime`): after 1024 consecutive
   clock-observation boundary ops at unchanged virtual time with no intervening
   progress op (`operation_is_progress`, the same predicate the liveness watchdog
   uses), the runtime advances the monotonic clock through a recorded
   `SleepUntil` — the deadlock rescue's mechanism — by a token that starts at
   1 µs and doubles per rescue to a 1 ms ceiling. The advance is clamped so it
   never steps over a still-future timer deadline. Scheduling/wait ops are
   neutral (they neither count toward the streak nor break it), so a spinning
   thread in a multi-task run still accumulates; a progress op, or virtual time
   moving for any reason the rescue did not cause, ends the episode and its
   escalation. The trigger is a pure function of the recorded op stream and the
   driver's monotonic value, so it re-fires at the same operation on replay and
   the trace is byte-identical.
2. **Frozen-clock churn backstop**: 256 rescues that bought no genuine progress
   is a loop ignoring the clock rather than waiting for it. The run stops with
   `PATINA_VIOLATION liveness detail=frozen-clock-churn vtime_ns=<n> rescues=<n>
   advanced_ns=<n> clock_ops_per_rescue=<n>` plus a prose diagnostic naming the
   pattern, a matching `runtime_findings` entry on the facts channel, and a
   flushed trace — a named abort, never a hang. Because virtual time now moves
   during a spin, the generic liveness watchdog also regains traction on this
   class; whichever mechanism trips first stops the run.
3. **Truncated-trace preservation**: a runtime-initiated stop (step-budget
   exhaustion, frozen-clock churn) writes the recording as it stands before
   returning, so the artifact that explains a wedge survives. At most one write
   per run — the native trace transport is an append-only descriptor — and
   `Context::finish` skips its own write afterwards. A guest that calls `abort()`
   itself is untouched and still leaves no trace.
4. **Audit/gate wording**: the TSC-managed notes keep *manageable* and *runnable*
   distinct instead of asserting the guest is runnable, and name both outcomes a
   calibrating guest can now reach.

## Slice 10: the guest descriptor table — Complete

The native shim owns one descriptor table (`crates/patina-native-shim/src/fdtable.rs`), shaped like the kernel's, in place of the number-range scheme it replaced (deterministic-filesystem numbers from the driver counter, sockets/pipes/eventfds/reactors from a `0x4000_0000` counter, `/dev/urandom` from a 64-slot bitmap, and the literal numbers 1 and 2 for the captured streams). Guest numbers are allocated lowest-free with holes and refcount an open file description — kind, class handle, status flags — with `FD_CLOEXEC` on the number; `dup`/`dup2`/`dup3`/`F_DUPFD[_CLOEXEC]` bind a second number to one description (`F_DUPFD` honors its minimum, `dup2`/`dup3` bind a chosen number and close what it named), `close_range` covers a range or marks it close-on-exec, `EMFILE` falls at `RLIMIT_NOFILE` (1024, the one number `getrlimit`, `sysconf(_SC_OPEN_MAX)` and the table share), and `F_GETFL`/`F_SETFL` (access mode, `O_APPEND`, `O_NONBLOCK`, `O_LARGEFILE` on open(2)-minted descriptions) and `F_GETPIPE_SZ`/`F_SETPIPE_SZ` (page-rounded power of two, `EBUSY` below the buffered bytes) are modeled. Every descriptor operation is one universal `patina_*` entry that resolves the number once and dispatches on its kind (a pipe's `lseek` is `ESPIPE`, its `fsync`/`ftruncate` `EINVAL`, an empty slot `EBADF`); the C interposers and the SUD rows call that entry and decide nothing by class, `patina_fd_kind` being the single oracle for the calls whose meaning depends on the kind (`ENOTSOCK`, a `*at` dirfd — now `EBADF`/`ENOTDIR` rather than `ENOSYS` — and `mmap`'s `ENODEV`). Every deny the old scheme forced is gone: `dup2`/`dup3` to a chosen number, `dup`/`F_DUPFD` of a standard stream, a socket or an eventfd, a minimum above the counter, `flock` on a socket. Standard input is a kind (EOF, never a terminal); `dup2(fd, 2)` redirects a standard stream and `close(2)` then `open` gives number 2 to a file, while the runtime's own diagnostics write to the capture sinks directly; the advisory `flock` table is keyed by description, so a dup of the holder releases it; a file-backed mapping holds a hidden description reference, so its writeback survives the guest closing the number; epoll interests are keyed by description (a reused number never reads a stale interest, and the interest drops with the description's last reference), `epoll_ctl` answers the kernel's `EBADF`/`EPERM`/`EINVAL` in the kernel's order and models `EPOLLONESHOT`; the SUD `pipe2` refuses unknown flags like the C one; and both fatal paths flush the captured streams before aborting so a dying probe leaves its event stream. Traces are unchanged: driver handles are recorded exactly as before, a guest number is a pure function of the deterministic call sequence and is never recorded, and a `dup` is table bookkeeping rather than a driver operation. **Detection**: the conformance scenario `fd/table` (allocation and reuse, the `dup` family, `FD_CLOEXEC` versus status flags, the `RLIMIT_NOFILE` bounds and `EMFILE`, `close_range`, non-file kinds, stream redirection and reopening, stdin at EOF, `EBADF`) passes natively and under patina, record/replay and strace through every vehicle, with `crates/cargo-patina/tests/native_conformance.rs` (`pin_process_state`) pinning stdin to `/dev/null`, `RLIMIT_NOFILE` to 1024 and the inherited descriptors so the oracle and the virtual kernel start from one process state; `fd/pipes`, `fs/open_rw` and `readiness/epoll` carry no descriptor-numbering gap; `fdtable.rs` carries the allocation and refcount rules as unit tests; `native_abi::posix_descriptors_and_environment_are_virtualized` asserts the new `dup2`/`F_DUPFD`/`dup(1)` answers. Named and not closed: a directory opened by a plain `open(path, O_RDONLY)` (no `O_DIRECTORY`) is a `File` description and not a `*at` dirfd — the F3 resolver, which knows the entry kind at open, owns it; the two ends of one anonymous pipe are separate `flock` identities; `fstat` on a socket, eventfd or epoll description is still `EBADF` (the fs family's `S_IFSOCK`/anon-inode rows); the epoll reactor delivers ready events in fd order where the kernel delivers them in ready-list order (declared, readiness family); and `fsync`/`ftruncate` on non-file kinds are modeled but not yet probed.

## Signals family: shared state and process answers

One Linux Rust signal model serves libc and SUD: per-process dispositions/shared
pending, per-task masks/private pending, kernel-owned alternate stacks, mask inheritance, standard
coalescing, realtime FIFO and recorded generation (including ignored signals).
The kernel constructs handler frames only after the runtime lock is released.
Production-entry tests pin oldact/oldset, delivery-before-return, batched host
unblocking, altstack execution, pending order and reserved containment masks.
Childless waits return ECHILD, prctl process answers remain virtual, and
waitpid/waitid share the raw wait core rather than forwarding to the host.
The family's scenarios run with the native acceptance tests in the full landing
battery.
Unsupported timer/IPC/clone surfaces are named refusals, not host fallbacks.
Nested kernel delivery preserves the enclosing SIGSYS frame's dirty mask and
stack bits; unit and raw-boundary detectors cover inner-frame consumption.

## Signals family: blocking waits

The Linux shim registers interruptible parks and delivers on resume, including
per-call restart rules and per-door sleep remainder handling. Signalfd uses the
unified descriptor table. Poll/ppoll and select/pselect share the readiness wait
core and temporary-mask mechanism; no host readiness object is introduced.
The six blocking-wait probes (`signal/mask`, `signal/eintr`, `signal/wait`, `signal/block`,
`signal/one_wake`, `thread/futex`) and the collateral `readiness/ppoll` probe have
no pending declarations. Required unit tests drive real managed threads,
queues, kernel handlers, recorded wakes and virtual timer rescue; the C readiness
adapter guest lives in `testbeds/native-boundary/signals/` and runs through the
typed `cargo-patina/tests/native_signals.rs` integration target. Focused cases
also cover libc/raw prctl sharing, handler and mask visibility, sigwait retry,
and guest-abort versus internal-fatal trace completion. `native_containment`
owns reserved-signal registration refusals; `native_raw` owns raw ppoll timeout
writeback/readiness and prctl option acceptance/refusal. All share the native
compiler and bounded-output helpers in `cargo-patina/tests/common`.
Pthread parks retain their semantic queues while handlers run and resume the
original wait/deadline. A handler attempting a nested blocking pthread wait fails
with a named diagnostic before altering those queues; uncontended locks are
allowed. Child-process tests cover timed/untimed waits with and without a pending
outer grant.

## Signals family: default termination and threads

Default Term/Core signals finalize before dying through the real host signal;
`guest_exit.core` reflects the observed wait status rather than a signal table.
SIGPIPE from pipe writes and socket sends is recorded before EPIPE, with
MSG_NOSIGNAL suppression and ignored-signal dropping. SA_RESETHAND resets only
the handler, preserving the flags, mask and restorer observable by either door.
Stop-class defaults fail with a named trap; installed handlers still run.
Only explicit guest abort finalizes before using the host alias; internal fatal
paths bypass the public abort interposer and leave an incomplete trace.
POSIX startup installs an ownership-scoped Rust panic hook using host diagnostics
and private abort. Guest callbacks suspend ownership, preserving caught guest
panics; unwind and abort backstops protect trace integrity after hook replacement.
The native panic detector plants a panic in a scratch copy of the real clock ABI
entry, before locks, and requires an unloadable trace under both panic strategies.
No production fault-injection export or guest-specific branch is present.

Thread-directed delivery runs on the named task. The Linux wrappers have strong
definitions and registry rows; set_tid_address stores a per-task guest word and
thread completion clears it and wakes its futex. Raw main-thread exit leaves
workers alive; exit_group finalizes without atexit. Termination and thread tests
exercise real handlers, queues, wait statuses and recorded/replayed traces,
including the cargo-patina termination/core-envelope e2e tests. The family's
conformance scenarios and the full landing battery are the whole-family
acceptance criteria.

## Dependency order

```text
patina-dst-abi
  -> patina-dst-driver-api
      -> concrete drivers
patina-dst-abi
  -> patina-dst-trace
concrete drivers + patina-dst-trace
  -> patina-dst-runtime
      -> patina-dst-async (explicit-boundary futures executor)
          -> patina facade
              -> cargo-patina (process configuration)
```

Target hosts and native shims depend on the runtime boundary; they do not redefine it.

## Deliberate limitations of the complete slice

V1-V2 remain end-to-end at the explicit Rust API boundary. WASI executes the full audited Preview 1 surface. Native programs — single Rust sources and whole Cargo packages — build and run through `cargo patina build`/`run` with managed threads, UDP datagrams and TCP streams over `SimNet` (both with deterministic timed waits and non-zero link latency through the virtual-clock timer queue), the interposed kqueue/epoll readiness reactors (stock tokio runs under the shim on both platforms), deterministic process-state constants, and a strict fail-closed import audit — but arbitrary FFI and unrelated direct host APIs remain outside Patina's control.

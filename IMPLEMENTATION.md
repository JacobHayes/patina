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
- Runtime traces cross scheduler, network, clock, filesystem, and entropy effects.
- Trace format 2 stores branch relationships and seeds, resolves inherited decisions, and supports exact-prefix/new-suffix execution.
- CLI controls replay timelines, branches, and step budgets.
- `cargo patina minimize` runs an external failure oracle against unbranched main timelines or leaf branch suffixes.

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

- `sock_accept` and `proc_raise` return `NOSYS` by design: Preview 1 has no listen surface and Patina has no signal model.
- `MemFs` timestamps change only through explicit set-times operations; writes do not auto-update mtime.
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
3. The opt-in POSIX C layer exports `open/read/write/writev/readv/close/dup/lseek/fsync/ftruncate`, namespace/stat calls, clock/sleep calls, and entropy calls (including Darwin's `CCRandomGenerateBytes` and `F_FULLFSYNC`) without host fallback. Startup snapshots the private `PATINA_*` control plane for shim configuration, then scrubs the live environment; guest-visible `getenv` and direct `environ` iteration see an empty immutable environment, and mutation (`setenv`/`unsetenv`/`putenv`) fails closed with `ENOSYS` plus a `patina:` diagnostic.
4. Linked macOS and Linux Rust probes execute ordinary `std::fs`, metadata, `SystemTime`, `Instant`, `thread::sleep`, printing, and standard-library entropy through the shim with cross-process seed stability; Linux large-file/stat variants and Rust's startup descriptor probe are explicit.
5. The trace control plane is separated from the interposed data plane: a supervisor-provided `PATINA_TRACE_FD` descriptor carries trace bundles through non-interposed host read/write aliases, so the fully interposed probe records and replays traces.
6. `cargo patina audit` is a strict per-platform import allowlist: after alias normalization (`$NOCANCEL`, `__`-prefixes), an import passes only if it is an explicitly listed effect-free host-deferred symbol for the binary's format (Mach-O or ELF; other formats are rejected) or is `--allow`ed by the caller — anything else fails closed as `unknown-import`, with known host-effect names still categorized (filesystem, network-or-wait, unmanaged-sync, and so on) for error quality. AArch64/x86_64 syscall and clock/entropy instruction scanning is unchanged. The shim's own control-plane symbols (trace-fd read/write aliases; the thread vehicle — macOS `pthread_create_suspended_np`/`thread_resume`/Mach-semaphore batons, Linux the real glibc `pthread_create`/`sem_*` batons resolved through the `dlsym(RTLD_NEXT, ...)` host-alias table) are deliberately not on the static allowlist: validation scripts `--allow` them per audited binary so unmanaged binaries importing the same symbols still fail. `run` additionally enforces this audit as a pre-run default-deny gate *before* the guest executes: it bakes in the shim control-plane vehicle (so ordinary shim-linked binaries run without repeating `--allow`) and hard-errors, naming, categorizing, and grouping symbols by recovered object/archive-member provenance, if the guest reaches any other blocking/time/scheduling/effect symbol that is neither interposed nor known-safe — so a missed interposer is a refusal, not a silent escape. `--allow-unsupported-symbols <all|name,...>` downgrades matching denials to a loud warning (recorded in a sidecar beside a `--record` trace, qualifying the determinism claim) for programs carrying unsupported surface the scenario never reaches. The deny/interposed/known-safe lists are organized by an explicit escape-class taxonomy (blocking/scheduling, time, entropy, thread-lifecycle, process, fs/net, shared-memory/IPC, signals/timers) with a per-class detection test and a coverage matrix in `crates/patina-target/ESCAPE-CLASSES.md` that is honest about the residuals symbol audit cannot see (inlined syscall instructions — covered by the Linux `strace` pass, absent on macOS; commpage/vDSO time; instruction-level entropy; `mmap` `MAP_SHARED`). The gate is calibrated to not false-positive on ordinary arg-reading `std` guests: `__NSGetArgc`/`__NSGetArgv` are known-safe (supervisor-controlled argv) and `confstr` is interposed to a deterministic value.
7. Native C and Rust escape fixtures verify successful controlled imports and rejection of direct syscall assembly/unmanaged threads.
8. `scripts/smoke-cross-target.sh` builds one ordinary-`std` smoke program for wasm32-wasip1 and the native host and verifies identical seeded, recorded, and replayed output across targets.
9. `cargo patina build <SOURCE.rs>` packages the shim link/startup integration: it builds the shim static library with the embedded POSIX layer and compiles a single Rust source with `cfg(patina)`/`cfg(dst)` and the required link arguments; `cargo patina run <BIN>` supervises execution through the documented `PATINA_*` environment and the `PATINA_TRACE_FD` descriptor. `build <DIR|Cargo.toml>` extends the same recipe to whole Cargo packages: it drives the package's own `cargo build`, injecting the cfgs and shim link arguments through `CARGO_ENCODED_RUSTFLAGS` while an explicit host `--target` isolates them to the final binary (rlib compiles ignore link arguments; build scripts and proc macros link for the host without the flags, so their host-side I/O never routes into an uninitialized runtime). `--package` selects a workspace member and `--bin` selects among multiple binaries; missing `--bin` on a multi-binary package fails closed rather than guessing, and the produced binary audits and record/replays identically to a single-source one. Path dependencies and build-script outputs reach the deterministic binary unchanged.
10. Auto-initialization: a C constructor initializes the runtime from the `PATINA_*` protocol and `atexit` finalizes it, so ordinary programs need no explicit init calls; running outside the supervisor aborts fail-closed.
11. Managed threads: `pthread_create` is interposed by a strong def, and the real host creator is reached through a distinct non-interposed path (macOS `pthread_create_suspended_np` plus mach `thread_resume`; Linux the genuine glibc `pthread_create` resolved through the host-alias table's `dlsym(RTLD_NEXT, ...)`, so no `-Wl,--wrap=pthread_create` — which would clash with libgcc's own `__wrap_pthread_create` on x86). Real host threads are gated one-at-a-time by `DetScheduler` through a per-thread OS-semaphore baton with atomics-based shim-internal locking. Interposed mutex/condvar operations route contention through the scheduler, so a lock held across a boundary operation cannot deadlock. On macOS the baton uses a *Mach* semaphore, not a libdispatch one: the shim also interposes `dispatch_semaphore_create`/`wait`/`signal`/`dispatch_time`/`dispatch_release` because std's Darwin thread `Parker` (`thread::park`/`park_timeout`, and the `mpsc`/`mpmc` `recv`/`recv_timeout`, `Once`, and channel paths built on it) blocks on a libdispatch semaphore — routing the wait through the scheduler and virtual clock, with a deterministic tie-break (a runnable unparker's signal always beats a same-instant timer, which fires only via the deadlock rescue). The baton uses a distinct Mach semaphore precisely so it does not recurse into its own interposer; before this fix the Parker shared the baton's `--allow`ed `dispatch_semaphore_*` audit entry and escaped both the scheduler and the virtual clock silently. `sched_yield` (std's `thread::yield_now`, reached by the `mpsc` backoff) is interposed to a deterministic scheduling point rather than a host yield. `pthread_rwlock_*` is a real deterministic reader/writer lock (replacing the former `ENOSYS` stubs): writer-preferring, FIFO among writers, with blocked readers batch-woken when a writer releases and no writer waits — every grant a recorded scheduler decision. std's own `RwLock` reaches this only via the parking `Parker` on the supported toolchains (its contended `write` path is `lock_contended → thread::park → dispatch_semaphore_wait`), so contended `std::sync::RwLock` acquisition is already deterministic through the Parker; the `pthread_rwlock_*` interposers serve C guests and any std that lowers to them.
12. Native networking over `SimNet`: UDP datagrams and zero-latency TCP streams are interposed for `AF_INET` sockets. UDP covers `socket`/`bind`/`connect`/`send`/`sendto`/`recv`/`recvfrom`/`getsockname`; TCP covers `SOCK_STREAM`, `listen`/`accept`/`connect`/`read`/`write`/`send`/`recv`/`shutdown`/`getpeername`, with wrapper forwarding for latency/fault layers. Sockets are fully virtual (zero network host imports); blocking recv/accept/send paths park through the scheduler baton; non-blocking sockets return `EWOULDBLOCK`; the setsockopt allow-list admits deterministic no-op socket options including `TCP_NODELAY`; IPv6 and DNS (`getaddrinfo`) fail closed with explicit errors. The native gate verifies this with `NATIVE_TCP_RESULT`. Deterministic process-state constants cover `getuid`/`geteuid`/`getgid`/`getegid` and common `sysconf` values. Process spawning stays a non-goal, enforced in layers (VALIDATION.md V4 and `crates/patina-target/ESCAPE-CLASSES.md` row e): the spawn family a real guest links (`fork`/`posix_spawn*`/`waitpid`/…) is deny-trap interposed (a guest that reaches it aborts deterministically, naming the symbol), `kill` is a deterministic-model interposer (signal-0 liveness probes get an honest single-process answer), and the unlinked remainder (`vfork`/`exec*`/`system`/`popen`/`killpg`/…) stays uninterposed so the audit rejects it.

13. Linux futex routing: Rust `std` on Linux reaches `Mutex`/`Condvar`/thread parking through raw `SYS_futex` via libc's `syscall` wrapper (not pthread), so the shim interposes `syscall` — `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` checks the futex word and parks the caller on the word's address through the scheduler baton (value check and park are atomic under the baton, so no wakeup is lost); `FUTEX_WAKE`/`FUTEX_WAKE_BITSET` wakes up to N parked tasks; every other syscall number fails closed with `ENOSYS`. `dlsym` is interposed to resolve nothing, so std's optional-symbol probe falls back to defaults and dynamic lookup can never return a host symbol. Timed futex waits park with their deadline on the virtual-clock timer queue (item 15) and return `ETIMEDOUT` when the deadline fires before a `FUTEX_WAKE`.

14. Directory, symlink, identity, descriptor, and environment containment: the dirent family (`opendir`/`readdir`/`readdir64`/`readdir_r`/`closedir`/`rewinddir`) iterates driver-ordered snapshots with deterministic synthetic inodes, so ordinary `std::fs::read_dir` works; `symlink`/`readlink` and symlink-aware `stat`/`lstat`/`fstatat`/`statx` follow MemFs semantics (leaf metadata without following, one terminal hop then `ELOOP`, `AT_SYMLINK_NOFOLLOW` honored); `gettid` (Linux) and `pthread_threadid_np` (macOS) return deterministic scheduler thread ids. `dup`/`fcntl(F_DUPFD*)` duplicate MemFs/CrashFs descriptors through the recorded `FsDup` operation, sharing cursor and access flags with deterministic monotonic fd numbers; unsupported targeted variants (`dup2`/`dup3` to a different number), captured stdio duplication, and socket duplication fail closed with `ENOSYS` plus captured `patina:` diagnostics. `__res_init` still fails closed. The deterministic environment is empty and immutable after startup. On Linux, `scripts/validate-native-shim.sh` adds a whole-run `strace` containment pass: outside an exact loader/std-runtime prelude (shared-object loads, `/proc/self/maps` stack introspection, control-plane descriptors 0-3, process-local memory and signal setup), no file, network, clock, entropy, or descriptor syscall may appear anywhere in the run — the seeded probe's guest section reaches zero host syscalls. macOS has no equivalent runtime gate: calibration established that `ktrace` (the only root-capable, SIP-compatible whole-run tracer) cannot found a sound default-deny check, so the macOS path skips loudly and `PATINA_REQUIRE_KTRACE=1` hard-fails on Darwin rather than reporting a check that cannot fail, leaving static instruction scanning plus import audit as the macOS containment evidence. Three independent, on-host-reproduced blockers: `BSC_*` events carry only raw register values, not decoded paths, so a guest's raw `open`/`stat` is indistinguishable by argument from the loader's libSystem prelude; the deterministic runtime buffers all guest output (stdout and stderr) into a single flush at process exit, so there is no in-band boundary marker to separate the pre-main loader prelude from guest code; and the loader/runtime issues the same syscall names an escape would (`open`, `fcntl`, `getpid`, ...) with init interleaved into early guest execution, so a name-scoped default-deny is either vacuous or false-positives on clean runs — a planted post-init raw `getpid` (inline `svc`) lands among the runtime's own `getpid` events, name-identical and not temporally separable.

15. Virtual-clock timer queue: the runtime `Context` keeps a timer registry ordered by `(monotonic deadline, registration sequence)` with at most one live timer per task, registered through the recorded `TaskParkTimed` boundary operation (realtime deadlines convert to monotonic at registration). When the scheduler would otherwise deadlock and timers exist, `scheduler_next` rescues: it advances the virtual clock to the single earliest deadline through the recorded `SleepUntil` path, wakes every due task in `(deadline, sequence)` order through recorded `TaskWake` operations, and retries — so replay re-executes the rescue from the trace and an empty registry still deadlocks explicitly. Any earlier wake deregisters the task's timer. Consumers: `pthread_cond_timedwait` and timed futex waits park with their deadline and learn timeout-versus-signal from the wake cause (the rescue purges the waiter from its primitive's queue and marks it timed out; the mutex is re-acquired before `ETIMEDOUT` returns), `nanosleep`/`clock_nanosleep`/`mach_wait_until` park timed under managed threads so other runnable tasks execute during a sleep (single-threaded programs keep the identical direct clock jump; the WASI host and explicit facade are unchanged), and a blocking UDP `recv` on an empty queue consults the new recorded `NetDriver::next_delivery` operation and parks until the earliest pending delivery, which makes non-zero link latency work end to end: `cargo patina run --net-latency-nanos N` (environment `PATINA_NET_LATENCY_NANOS`, rejected fail-closed when malformed) configures `SimNet`, and the latency wrapper forwards `next_delivery` so wrapper-added latency stays visible to the parking deadline.

16. Deterministic preemption for atomics-only race windows, with vacuous-schedule detection first. The cooperative `DetScheduler` only switches at interposed boundaries, so a race whose window is pure atomics — the classic read-modify-write on a `std::sync::RwLock` whose uncontended fast path issues no interposed operation — runs to completion between two boundaries and is unreachable at every seed (a spawned worker parks once at spawn, then runs its whole loop with zero interposed boundaries before the next worker starts). Two parts address this. **(a) Detection (default-on).** `Context` counts each task's scheduling boundaries, split into voluntary yields (every touch of the interposed effect surface reschedules) and blocking parks, maintained identically on record and replay because every task-lifecycle op runs on both; `Context::finish` emits a machine-readable `PATINA_SCHEDULE_REPORT` line (per-task `Ny+Mp`) to stderr for any multi-task run, plus a loud `PATINA WARNING` when a spawned worker completes without exceeding the thread-lifecycle scaffolding yield floor (spawning/joining a std thread costs a small fixed number of yields on its own; a worker at or below it performed zero interposed operations, so any loop it ran was atomics-only and its interleavings are unreachable). The floor keys on yields because they are seed-invariant where parks are not, and is iteration-count-invariant — a `lost-update` worker sits at the scaffolding floor whether it loops twice or a thousand times, exactly because the loop is invisible to the runtime. This is the mechanism that stops "N seeds explored, all clean" from silently meaning "nothing was explorable". **(b) Reachability.** `cargo patina build --yield-points` (default off) compiles the guest with LLVM SanitizerCoverage trace-pc-guard at basic-block granularity (`-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-trace-pc-guard -Cllvm-args=-sanitizer-coverage-pc-table`) and links a cargo-patina-embedded hook object whose `__sanitizer_cov_trace_pc_guard` saturating-increments the guard word before routing into the shim's `patina_yield_point`, forwarding each guard hit's call site so a divergence diagnostic can name the exact instrumented guest location. The same hook registers guard ranges plus LLVM pc-table ranges for shutdown coverage reporting and `patina.covmap/v1` dumps. `-Cpasses`/`-Cllvm-args` are *stable* rustc codegen flags, so this needs no nightly toolchain and no `RUSTC_BOOTSTRAP` (an earlier `-Zinstrument-mcount` route was rejected — function-entry only, so inlined hot loops get no hook, and it is genuinely nightly-gated); the only version coupling is to LLVM's internal pass name (`sancov-module`) and coverage cl::opts, stable across the LLVM releases rustc ships but not a rustc stability guarantee. The instrumentation is surfaced prominently: a `--yield-points` build prints a `PATINA_NATIVE_BUILD_YIELD_POINTS` line naming the mechanism and the fingerprint suffix. At run time, yield-point binaries emit a default `PATINA_COVERAGE_REPORT` line (suppress with `PATINA_COVERAGE_REPORT=0`), and native `run`/`replay --coverage-out PATH` writes a supervisor-owned `patina.covmap/v1` counter map through `PATINA_COVERAGE_FD`; plain binaries refuse `--coverage-out` with a rebuild hint. `cargo patina coverage <binary> <map|campaign-out-dir>` resolves those maps offline from the `patina_yield_point` anchor, demangles symbols, and reuses the shared crate/module rollup. Campaigns over yield-point native binaries automatically fold per-generation maps into `<out-dir>/coverage/{meta.json,union.bits,hits.u64le,sites.i64le}` and report plateau with `--plateau-after`. Because level-3 instrumentation reaches loop backedges, every iteration of an atomics-only loop offers the seeded scheduler a preemption point; the seed still drives *which* task runs at each point, so exploration is genuinely seed-varying. The source stays 100% std-pure and the instrumentation is inserted only on the Patina path — a plain native build never links the hook, so a plain-std guest's native build passes bit-identically. Determinism and replay hold per `(seed, binary)`: yield decisions consume the recorded scheduler stream, and `run` detects the hook's embedded marker in the binary and folds `+yieldpoints` into the compatibility fingerprint, so a yield-point trace fails closed (fingerprint mismatch, nonzero exit) rather than silently replaying against a plain binary or the reverse — proven end to end by `native_yield_points_trace_fails_closed_against_plain_binary`; existing plain traces are unaffected. The Part-1 diagnostic is default-on independent of this flag. One correctness subtlety the instrumentation forced out: pthread thread-local destructors run *after* `thread_finish` has completed a task, and `std::sys::thread_local::…::destroy` is generic std code monomorphized into the guest crate, so under `--yield-points` it carries the hook and would take a scheduling point on an already-removed task. The shim marks a per-thread *completed* sentinel in `thread_finish` and no-ops `sched_point` on it — kept deliberately distinct from the never-registered state, which still fails loudly, so the fix does not trade a foreign-thread detection for silence. A second forced subtlety sits on the JOINER's side: after the managed join resolves, std drops its `Arc<thread::Inner>` while the worker's still-exiting host thread drops the same `Arc` in its TLS teardown; whichever lands last takes the deallocating slow path, so under `--yield-points` the joiner's guard-hit count depended on host load (the op-742/12623 divergence on x86 Linux; a ±2-root-yield record/replay divergence under load on Darwin). `patina_thread_join` therefore reaps the worker's real host thread (host-alias `pthread_join`) on **every** platform before returning, making the joiner's drop deterministically the last reference. The failure class also has standalone detection: a replay whose scheduler stream diverges at a `TaskYield` fails with a classified `yield-point replay divergence` diagnostic — per-task record-vs-replay yield accounting plus the divergent instrumented site (reported as a stable offset from `patina_yield_point`, symbolizable offline via `nm`/`atos`/`addr2line`) — never the bare "trace ended before operation N" cursor error (`classify_yield_divergence` in `patina-runtime`; proven by `native_yield_points_divergence_reports_accounting_and_site`). Result on a two-thread lost-update guest: the race — previously unreachable at ~300 seeds — now trips its `BUG_CAUGHT` oracle at every seed under `--yield-points` (e.g. seed 3, `--iters 2`, trace SHA-256 `697d8d49c967127d…` identical across three records, replays exactly); the `deadlock` mode (interposed mutex loop) is correctly *not* flagged vacuous, and the plain `lost-update` build *is* flagged. Overhead: negligible build cost and, at the small iteration counts needed to surface a race, run cost remains startup-dominated. A Wave-A threaded four-worker measurement saw yield-points with counters+pc-table at 0.233 s median versus 0.230 s for the same yield-point hook with counters disabled (+1.7% incremental; plain no-yieldpoints in the same harness was 0.045 s), while the per-boundary cost still scales linearly with instrumented work as expected for cooperative preemption. Non-goals unchanged: no signal/ptrace preemption (host-nondeterministic), no raw-atomic interposition (impossible at symbol level).

17. Native async-runtime interposition: deterministic readiness reactors on both platforms, so stock tokio binaries run under the shim. A reactor-neutral core (per-fd readiness predicates over the in-process pipe/socketpair channels and `SimNet` sockets, a multi-fd fan-in park primitive on the baton, and UNRECORDED runtime inspections — `net_readiness`, `monotonic_now_unrecorded` — that are pure functions of recorded history and the virtual clock, so record==replay holds with no new trace ops) carries two thin frontends: macOS `kqueue`/`kevent`/`kevent64` (EVFILT_READ/WRITE/USER/TIMER, EV_CLEAR edge latch, refcounted registry dup for mio's `F_DUPFD_CLOEXEC` selector clone) and Linux `epoll`/`eventfd` (kernel-faithful ctl errno, mio's edge-triggered EPOLLET honored by an arrival-sequence latch so an undrained eventfd Waker write still re-fires, eventfd as the in-process counter whose read waiters double as the epoll wake queue). Pipe/socketpair endpoints are refcount-dup-able (tokio's signal driver clones its wakeup pair; EOF/EPIPE fire on last-close of a side). Entry points are syscall-shaped (`patina_epoll_*`, `patina_eventfd`) for a future syscall-user-dispatch handler. Unmodeled filters/flags and readiness on real host descriptors fail closed loudly. Guest package builds inject `--cfg rustix_use_libc` so rustix's default raw-syscall Linux backend becomes interposable libc imports (`openat64` joins the LFS alias family; raw-syscall binaries otherwise still fail closed at the instruction scan). Acceptance: a tokio + parking_lot + rustix guest passes the pre-run gate with no allowances, runs byte-identical per seed, and converges under record + flag-free replay on both platforms, exercised on every `validate-native-shim.sh` run.

18. Syscall-user-dispatch (SUD), slice 1, Linux/x86_64: a guest's raw inline `syscall`/`svc` instruction — rustix's default linux_raw backend, hand-written asm — is trapped into the deterministic runtime via a `SIGSYS` handler instead of being refused. The shim arms `PR_SET_SYSCALL_USER_DISPATCH` with the allowed region = glibc's single executable segment and a NULL selector (so every syscall instruction *outside* glibc text unconditionally traps; there is no guest-writable selector byte and zero selector-toggle sites), at exactly two sites — the `__libc_start_main` interposer (main thread, before guest constructors) and every managed thread's trampoline (the config does not survive `clone`, so each thread arms once). The region is discovered from `/proc/self/maps` (real glibc `open`/`read`/`close` resolved through the `dlsym` host alias, never the interposed FS defs), failing closed on any layout that is not exactly one executable libc segment. The `SIGSYS` handler is synchronous-by-construction — the kernel rolls the instruction back and delivers it on the faulting thread at the syscall's own IP, semantically identical to the guest having called an interposed `read()` — so it decodes the number and six argument registers from the `ucontext` and routes into the **same** `patina_*` entry points the C interposers use (a reentry guard is the standalone RED detector for the "shim never traps while holding a runtime lock" soundness invariant). Slice-1 dispatch table: the clock family (`clock_gettime`/`clock_getres`/`gettimeofday`/`nanosleep`/`clock_nanosleep`), `futex` (sharing the libc-`syscall()` interposer's op decode), `read`/`write`/`openat`(AT_FDCWD)/`close`/`lseek`, `getrandom`, `sched_yield`/`gettid`, `exit`/`exit_group`; process-local anonymous `mmap`/`munmap`/`mprotect`/`madvise`/`mremap`/`brk` pass through to the host kernel via the glibc `syscall(2)` host alias (file-backed `mmap` is refused loudly); `set_robust_list`/`rseq`/`membarrier` return a deterministic `-ENOSYS`; `rt_sigprocmask`/`sigaltstack` are success no-ops and `rt_sigaction(SIGSYS)` is fatal; **every other number is a named, deterministic fatal abort** (the process/escape class and any un-tabled number). The vDSO escape is closed by scrubbing `AT_SYSINFO_EHDR` to `AT_IGNORE` in the initial-stack auxv, so a vDSO-resolving crate finds no vDSO and falls back to a raw syscall SUD then traps. The audit **downgrades** a `direct-syscall` *instruction* finding from refuse→run iff the binary defines the `patina_sud_dispatch` marker AND a live `prctl` probe says the kernel has SUD, reporting it relabeled `direct-syscall (SUD-managed)` — never silent; `cpu-nondeterminism` register reads stay refused. On a no-SUD kernel (notably arm64) or a no-marker binary the run is refused exactly as before, with a hint pointing at `--cfg rustix_use_libc` / x86_64. New hardening: on Linux `sigaction`/`signal` are interposed to forward every non-SIGSYS registration to the real glibc call (preserving std's stack-overflow guard) and refuse SIGSYS — a guest may not re-register the dispatch handler. `--cfg rustix_use_libc` stays injected (belt-and-suspenders on x86_64, the only answer on arm64). Same-artifact record/replay is byte-identical (SUD routes into the same `patina_*` boundary, so the trace is identical whether an effect arrived via SIGSYS or a C interposer). Slice 1 defers to slice 2: the full FS/network rows, dirfd-relative resolution, `sendmsg`/`recvmsg`, uname/pid constants, the committed rustix-default testbed, and the `sud:on/off` trace-metadata field (via the `guest_argv` `RunMetadata` pattern, SUD-DESIGN.md §7.3). The metadata deferral is sound **because slice 1 has no independent SUD toggle**: arming is a pure function of the binary's `patina_sud_dispatch` marker and the kernel probe — no env var, flag, or hatch turns SUD off for a marker binary — so the binary identity replay already verifies subsumes the metadata byte, and the replay-refusal decision #6 promises is delivered by the pre-run gate instead: `replay` of a marker-carrying raw-syscall binary on a no-SUD kernel refuses **pre-exec** (before the trace is even opened), naming the situation ("this kernel lacks syscall-user-dispatch"), proven by a `validate-native-shim.sh` leg on the arm64 VM. Introducing any such toggle makes the metadata field mandatory in the same change. arm64 (slice 3) lights up by a probe flip when generic-entry kernels ship — the number table is already arch-complete. Verified: x86_64 CI runs the positive battery (SUD-managed audit, seed-stable run, byte-identical record/replay, per-thread arming, unmapped-syscall abort, auxv canary); the arm64 VM RED-proves the refusal leg and the kernel-independent SIGSYS-hijack and marker-gating legs; the full macOS and 8-gate Linux batteries stay green.

19. Syscall-user-dispatch (SUD), slice 2 + kernel-independent slice 3, Linux/x86_64: the dispatch table is completed and the `rustix_use_libc` workaround retired on SUD-capable targets. New rows (all routing into the SAME `patina_*` entries the C interposers use — a second caller, never a second implementation): the full filesystem surface — `pread64`/`pwrite64`, `readv`/`writev` (iovec loop), `fsync`/`fdatasync`, `ftruncate`, `flock`, `dup`/`dup3`, `fcntl` (`F_GETFL`/`F_SETFL(O_NONBLOCK)`/`F_DUPFD`/`F_GETFD`/`F_SETFD` — else fatal), `ioctl` (`FIONBIO`/`FIONREAD` on virtual sockets — else fatal), `pipe2`, `fstat`/`newfstatat`/`statx` (normalized to the same metadata record, one-hop terminal-symlink resolution mirroring the C `stat` path, arch-specific kernel `struct stat` + arch-independent `struct statx`), and `getdents64`; the raw `read`/`write`/`close` rows now do the same fd-class dispatch the C interposers do (socket/pipe/eventfd/epoll vs regular fd), so a raw call on a virtual socket records the identical op-stream. Because the deterministic FS refuses to open a directory as an fd (EISDIR), a raw caller (rustix `Dir` → `getdents64`) is served by a SUD-layer directory-fd model: a read-only `openat` on a directory snapshots it through the same `patina_read_dir` the interposed `opendir` uses and returns a SUD-private descriptor that `getdents64` walks into `linux_dirent64` records, `lseek(…,0,SEEK_SET)` rewinds, and `close`/`fstat` recognize. Network rows → `patina_net_*`: `socket`/`bind`/`listen`/`connect`/`accept`/`accept4`/`sendto`/`recvfrom`/`shutdown`/`getsockname`/`getpeername`/`setsockopt`/`getsockopt` (the option subset the C interposers accept) plus `sendmsg`/`recvmsg`, which mirror the C interposers' `ENOSYS` refusal exactly (the deterministic net layer models only sendto/recvfrom; a per-iovec send loop would fragment one datagram into N — silently-wrong, so it is fail-closed instead). Readiness rows call the landed epoll frontend: `epoll_create1`/`epoll_ctl`/`epoll_wait`/`epoll_pwait`/`epoll_pwait2` (timespec→ms, NULL sigmask only) and `eventfd2`. Process-state constants match the interposers exactly: `getpid`=1, `getppid`=0, `getuid`/`geteuid`/`getgid`/`getegid`=1000, `uname`=`-ENOSYS`. The `sud` trace-metadata field (slice 1's approved deferral) now lands: the shim records whether SUD armed for the run (`Some(true)` when armed, absent otherwise — so macOS and all pre-SUD traces stay byte-identical) via the `guest_argv` `RunMetadata` pattern, and `replay` reconciles it UP FRONT — a `sud:true` trace on a run that did not arm SUD, or the converse, is refused before the first op is replayed (never a mid-run divergence), with directional messages; unit tests RED-prove both directions. `AT_RANDOM` determinization (slice 3, kernel-independent): the same auxv walk that scrubs `AT_SYSINFO_EHDR` now REPLACES the 16 `AT_RANDOM` bytes in place with seed-derived deterministic bytes (replacement, not `AT_IGNORE`: glibc dereferences the pointer at startup for the stack canary), closing an entropy leak on every managed Linux run whether or not SUD arms. Vsyscall-page audit detection (slice 3): the x86_64 instruction scan now refuses a binary whose text materializes the legacy vsyscall page address `0xffffffffff600000` as a 64-bit immediate — kernel-emulated, no `syscall` instruction, invisible to SUD — as a non-downgradable `vsyscall` finding. No-cruft retirement: `cargo patina build` now DROPS `--cfg rustix_use_libc` on SUD-capable targets (x86_64 Linux), keeping it only where SUD is absent (aarch64 Linux; macOS uses libc anyway) — a single conditional, no dual path. The committed acceptance MRE is `testbeds/rustix-default/` — a std+rustix program on the default `linux_raw` backend exercising raw clocks/fs/getdents64/getrandom/sleep/SimNet; its `run-patina.sh` skips loudly and counted on non-SUD/non-Linux hosts and, under SUD, asserts audit→SUD-managed, seed-stable, and record/replay byte-identical. Verified: macOS `cargo test --workspace` + the 55-test e2e suite green; `cargo check --target x86_64-unknown-linux-gnu` typechecks the whole SUD Rust surface (I am on macOS arm64 — the positive SUD legs are x86_64-CI-only and reviewed by construction on the C side); the metadata-reconcile and vsyscall detectors are RED-proven by mutation. `validate-native-shim.sh`'s SUD section gains legs for the rustix MRE, raw epoll/eventfd, raw uname/pid constants, raw `sendmsg`/`recvmsg`, `AT_RANDOM` determinism (kernel-independent, RED-mutation documented), and vsyscall audit refusal (x86_64), and the `SUD_LEGS_RAN` marker's `legs=` list is extended.

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
- trace schema migration: prior supported formats (v1, v2, and v3) migrate losslessly in memory on load with fixtures for supported, unsupported, and malformed inputs; bundles are never rewritten on disk and only the current format version is written;
- compact trace byte encoding (format 3): bundles are written as compact JSON with base64 byte payloads instead of pretty-printed number arrays, cutting the representative workload from ~344 to ~124 bytes/event; the file stays valid JSON, so `jq`/`python3 -m json.tool` still render it for humans;
- self-contained fault replay (format 4): a record run stores its full fault configuration (crash point + torn granularity, sleep/net jitter, drop, base net latency) in the trace metadata, so a replay reproduces the faults with no knobs re-supplied; the recorded config is authoritative, and a pre-format-4 trace keeps the historical re-supply behavior. For native runs the `replay` subcommand rejects a re-supplied fault knob up front (the trace is authoritative); the runtime-level reconcile still fails closed on any conflicting knob supplied through the `run`/`test` replay path;
- self-contained argv replay and a `replay` subcommand: `run --record` captures the guest arguments (`argv[1..]`, everything after `--`) into the trace metadata as an additive field, so a run recorded with non-default arguments reproduces them without the operator re-passing the `--` section — the fix for a real incident where a divergent default argv caused a confusing mid-run trace operation mismatch. `cargo patina replay <artifact|source|pkg> <trace>` is the sole replay entry point for all three families, routed by the same artifact inference as `run`: a WebAssembly module replays under WASI, a native binary under the native supervisor, and a directory/`Cargo.toml` (no `--target`) under the Cargo package family. It restores every semantic input (seed, fault knobs, and — native — buggify and guest argv; WASI — the `--arg` guest argv) from the trace and exposes no semantic flags — only each family's genuine host inputs (native: `--fingerprint`, `--mount` corpus re-supply, `--allow`/`--allow-unsupported-symbols`; WASI: `--fuel`/`--env`/`--socket`/`--preopen` and resource limits, verified through the fingerprint). The Cargo and WASI families also carry the timeline/branch controls (`--timeline ID`, or `--branch --from N --branch-seed S --branch-id ID [--parent ID]`); native traces are single-timeline. `run`/`test` and the WASI `run` no longer carry any replay/branch/timeline flag, and the seed-driven fault knobs plus (WASI) the `--arg` guest argv are recorded into the trace metadata so replay restores them flag-free across families. A `--` section passed to `replay` must match the recorded arguments byte-for-byte or the replay is refused up front naming both lists; a pre-argv trace (absent field) keeps taking its arguments from the command line. `argv[0]` is supervisor-normalized to a fixed name (`patina-guest`) so the host binary path never leaks into the guest's `std::env::args()` and traces stay portable across machines; the argument list is metadata, not a fingerprint input (the recorded op-stream already reflects any argv-dependent behavior);
- failure-oracle delta debugging for main timelines, leaf branch suffixes, and non-leaf branch trees (protected inherited prefix, reducible suffix), plus scenario/parameter/seed reducers (seed reduction is bounded ascending canonicalization);
- a whole-image checkpoint/rollback crash filesystem integrated with traces, with seeded torn writes (configurable granularity and probability), optional sub-block byte-granularity tearing of the final unsynced write (a partial page differing from both the durable and applied images), rename-atomicity on/off, directory-fsync durability, and crash/restart recomputation with stale-handle rejection;
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

Remaining: nothing for this slice's current scope; broader hardening items live in VALIDATION.md.

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
   `PATINA_BUGGIFY_DUPLICATE_LABEL` marker and aborts. Registration is lazy at
   first evaluation — a compile-time inventory (`ctor`/`linkme`) was rejected (it
   adds a dependency to the dependency-light default and constructor order is not
   a determinism guarantee), so a never-reached site is invisible within one run;
   the campaign layer closes this across generations.
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
   registered/activated/fired counts, cutoff state, and per-site
   `sometimes`/`reachable` coverage, knob values, and `@file:line` site
   identities, in the spirit of `PATINA_SCHEDULE_REPORT`. `cargo patina sites
   --exercised <stderr-file>` joins those rows to the static inventory.
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
    reimplemented). `patina-dst-target`'s WASI audit allowlists exactly the ten
    `patina_sdk` names alongside the Preview 1 surface. The fatal outcomes mirror
    the native shim: an `always!` violation and a duplicate label emit their
    markers (`PATINA_ALWAYS_VIOLATION` / `PATINA_BUGGIFY_DUPLICATE_LABEL`) to the
    real process stderr and trap the guest, and the `--buggify-after-setup` gate
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
   always-all default (no `--swarm`) is unchanged.

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
   that completes and is unreachable on any healthy run.

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
   A pure classifier assigns one of seven outcome classes — `OK` / `VIOLATION` /
   `LIVENESS` / `FAIL_CLOSED_ABORT` / `STARVATION_STALL` / `INFRA` /
   `UNCLASSIFIED` — with fuzz-sweep's strictness: an explicit finding is never
   downgraded, exit 111 is `STARVATION_STALL`, a Patina fail-closed refusal (a
   shim fatal stderr line or a bare SIGABRT carrying no SUT finding) is its own
   class distinct from a generic failure, and any nonzero exit matching no class
   lands LOUDLY in `UNCLASSIFIED` rather than being silently OK or mislabeled. It
   generalizes the per-testbed result/violation and `PATINA_SDK_REPORT` conventions
   to the harness-agnostic `PATINA_RESULT` / `PATINA_VIOLATION` markers and parses
   the watchdog's `PATINA_VIOLATION liveness`/`converge` contract lines (one format
   everywhere — no legacy marker parsing). A per-failure signature (class +
   digit-collapsed violation-detail shape + policy bug-depth annotation) is
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
   watermarks); registered `sometimes!` sites that are never satisfied fail the
   campaign by default unless `--allow-unmet-sometimes[=MIN_GENS]` explicitly
   waives the gate. `--selftest` proves every class reachable, the coverage gate
   classes, malformed-row rejection, and the signature dedup/novelty logic,
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

V1-V2 remain end-to-end at the explicit Rust API boundary. WASI executes the full audited Preview 1 surface. Native programs — single Rust sources and whole Cargo packages — build and run through `cargo patina build`/`run` with managed threads, UDP datagrams over `SimNet` (including deterministic timed waits and non-zero link latency through the virtual-clock timer queue), zero-latency TCP streams, the interposed kqueue/epoll readiness reactors (stock tokio runs under the shim on both platforms), deterministic process-state constants, and a strict fail-closed import audit — but non-zero TCP latency, arbitrary FFI, and unrelated direct host APIs remain outside Patina's control.

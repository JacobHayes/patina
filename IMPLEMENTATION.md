# Patina Implementation Plan

This plan turns the architecture into independently verifiable vertical slices. Status labels describe the repository, not the long-term design.

- **Complete**: implemented and covered by the corresponding `VALIDATION.md` gate.
- **Partial**: useful code exists, but the gate is not complete.
- **Planned**: no supported implementation exists yet.

## Slice 1: deterministic Rust-level execution — Complete

Acceptance level: V0 and V1.

### Workspace and contracts

- Create a Cargo workspace with separate ABI, driver API, driver, trace, runtime, facade, and CLI crates.
- Define serializable effect operations and outcomes in `patina-abi`.
- Keep concrete construction APIs out of `patina-driver-api`.
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
- Install deterministic default drivers for `patina::run`.
- Expose primitive filesystem, clock, and entropy effects through `Context` plus `read_file`/`write_file` conveniences.
- Finalize recording/replay on both successful closures and closures returning a Patina error.
- Return errors when a requested capability has no installed driver.

### Cargo command

- Provide the `cargo-patina` binary.
- Support `run` and `test`, `--seed`, `--record`, and `--replay`, forwarding all other arguments to Cargo.
- Compute a SHA-256 compatibility fingerprint over Patina version, Rust identity, Cargo command arguments, workspace Rust/Cargo inputs, and `Cargo.lock`.
- Pass experiment settings to the child through documented `PATINA_*` variables.
- Add an independent-package end-to-end test and a runnable example.

## Slice 2: scheduler and richer simulation — Complete

Acceptance level: V2.

- Scheduler ABI operations route explicit spawn, choose, yield, park, wake, and completion through `DetScheduler`.
- `SimNet` provides bound datagram endpoints, delivery queues, timing, reorder, partition, routing, and close state.
- Seeded fault and latency wrappers compose around the network data plane.
- Runtime traces cross scheduler, network, clock, filesystem, and entropy effects.
- Trace format 2 stores branch relationships and seeds, resolves inherited decisions, and supports exact-prefix/new-suffix execution.
- CLI controls replay timelines, branches, and step budgets.
- `cargo patina minimize` runs an external failure oracle against unbranched main timelines or leaf branch suffixes.

CLI key/value parameters are exposed through `Context::param`, typed driver setup is available through `patina::run_with`, and `cargo patina explore` runs bounded independent-process seed campaigns. Named scenario profiles remain a future experiment-plane convenience.

The `patina-async` crate builds a deterministic single-threaded futures executor over these same recorded operations: `block_on`/`spawn`/`JoinHandle`/`yield_now`, virtual-time `sleep`/`sleep_for`/`sleep_until`/`timeout`, and async TCP and UDP futures. It adds no new boundary operations — task creation, interleaving, parking, waking, yielding, completion, clock reads, and every net effect route through the existing `Context` recorded ops, so record/replay stays byte-identical. The executor makes exactly one recorded scheduling decision per poll: leaf futures perform their recorded effect, register an interest or deadline on the current poll scope, and return `Pending`, while an executor-internal FIFO wake queue (deduplicated per task) is drained into recorded `TaskWake`/`TaskYield` at fixed points. Timer futures ride the virtual-clock timer queue and its deadlock rescue (`task_park_timed` plus rescued `SleepUntil`/`TaskWake`); net futures translate would-block outcomes into interest registration plus a `NetNextDelivery` timed park, so wrapper-added latency stays visible. The `patina` facade re-exports the surface as `patina::rt` (plus `patina::block_on`), and `crates/patina-async/examples/async_echo.rs` runs a seeded TCP echo. Native interposition of third-party async runtimes (tokio/async-std under the shim) is a separate concern tracked in Slice 4.

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
2. `patina-native-shim` exposes prefixed filesystem, clock, entropy, sleep, crash, captured-stdio, and lifecycle ABI calls.
3. The opt-in POSIX C layer exports `open/read/write/writev/readv/close/dup/lseek/fsync/ftruncate`, namespace/stat calls, clock/sleep calls, and entropy calls (including Darwin's `CCRandomGenerateBytes` and `F_FULLFSYNC`) without host fallback. Startup snapshots the private `PATINA_*` control plane for shim configuration, then scrubs the live environment; guest-visible `getenv` and direct `environ` iteration see an empty immutable environment, and mutation (`setenv`/`unsetenv`/`putenv`) fails closed with `ENOSYS` plus a `patina:` diagnostic.
4. Linked macOS and Linux Rust probes execute ordinary `std::fs`, metadata, `SystemTime`, `Instant`, `thread::sleep`, printing, and standard-library entropy through the shim with cross-process seed stability; Linux large-file/stat variants and Rust's startup descriptor probe are explicit.
5. The trace control plane is separated from the interposed data plane: a supervisor-provided `PATINA_TRACE_FD` descriptor carries trace bundles through non-interposed host read/write aliases, so the fully interposed probe records and replays traces.
6. `cargo patina audit` is a strict per-platform import allowlist: after alias normalization (`$NOCANCEL`, `__`-prefixes), an import passes only if it is an explicitly listed effect-free host-deferred symbol for the binary's format (Mach-O or ELF; other formats are rejected) or is `--allow`ed by the caller — anything else fails closed as `unknown-import`, with known host-effect names still categorized (filesystem, network-or-wait, unmanaged-sync, and so on) for error quality. AArch64/x86_64 syscall and clock/entropy instruction scanning is unchanged. The shim's own control-plane symbols (trace-fd read/write aliases; the thread vehicle — macOS `pthread_create_suspended_np`/`thread_resume`/Mach-semaphore batons, Linux `__real_pthread_create`/`sem_*` batons) are deliberately not on the static allowlist: validation scripts `--allow` them per audited binary so unmanaged binaries importing the same symbols still fail. `run` additionally enforces this audit as a pre-run default-deny gate *before* the guest executes: it bakes in the shim control-plane vehicle (so ordinary shim-linked binaries run without repeating `--allow`) and hard-errors, naming and categorizing the symbols, if the guest reaches any other blocking/time/scheduling/effect symbol that is neither interposed nor known-safe — so a missed interposer is a refusal, not a silent escape. `--allow-unsupported-symbols <all|name,...>` downgrades matching denials to a loud warning (recorded in a sidecar beside a `--record` trace, qualifying the determinism claim) for programs carrying unsupported surface the scenario never reaches. The deny/interposed/known-safe lists are organized by an explicit escape-class taxonomy (blocking/scheduling, time, entropy, thread-lifecycle, process, fs/net, shared-memory/IPC, signals/timers) with a per-class detection test and a coverage matrix in `crates/patina-target/ESCAPE-CLASSES.md` that is honest about the residuals symbol audit cannot see (inlined syscall instructions — covered by the Linux `strace` pass, absent on macOS; commpage/vDSO time; instruction-level entropy; `mmap` `MAP_SHARED`). The gate is calibrated to not false-positive on ordinary arg-reading `std` guests: `__NSGetArgc`/`__NSGetArgv` are known-safe (supervisor-controlled argv) and `confstr` is interposed to a deterministic value.
7. Native C and Rust escape fixtures verify successful controlled imports and rejection of direct syscall assembly/unmanaged threads.
8. `scripts/smoke-cross-target.sh` builds one ordinary-`std` smoke program for wasm32-wasip1 and the native host and verifies identical seeded, recorded, and replayed output across targets.
9. `cargo patina build <SOURCE.rs>` packages the shim link/startup integration: it builds the shim static library with the embedded POSIX layer and compiles a single Rust source with `cfg(patina)`/`cfg(dst)` and the required link arguments; `cargo patina run <BIN>` supervises execution through the documented `PATINA_*` environment and the `PATINA_TRACE_FD` descriptor. `build <DIR|Cargo.toml>` extends the same recipe to whole Cargo packages: it drives the package's own `cargo build`, injecting the cfgs and shim link arguments through `CARGO_ENCODED_RUSTFLAGS` while an explicit host `--target` isolates them to the final binary (rlib compiles ignore link arguments; build scripts and proc macros link for the host without the flags, so their host-side I/O never routes into an uninitialized runtime). `--package` selects a workspace member and `--bin` selects among multiple binaries; missing `--bin` on a multi-binary package fails closed rather than guessing, and the produced binary audits and record/replays identically to a single-source one. Path dependencies and build-script outputs reach the deterministic binary unchanged.
10. Auto-initialization: a C constructor initializes the runtime from the `PATINA_*` protocol and `atexit` finalizes it, so ordinary programs need no explicit init calls; running outside the supervisor aborts fail-closed.
11. Managed threads: `pthread_create` is interposed (macOS `pthread_create_suspended_np` plus mach `thread_resume`; Linux `-Wl,--wrap=pthread_create`), and real host threads are gated one-at-a-time by `DetScheduler` through a per-thread OS-semaphore baton with atomics-based shim-internal locking — no `dlsym` anywhere. Interposed mutex/condvar operations route contention through the scheduler, so a lock held across a boundary operation cannot deadlock. On macOS the baton uses a *Mach* semaphore, not a libdispatch one: the shim also interposes `dispatch_semaphore_create`/`wait`/`signal`/`dispatch_time`/`dispatch_release` because std's Darwin thread `Parker` (`thread::park`/`park_timeout`, and the `mpsc`/`mpmc` `recv`/`recv_timeout`, `Once`, and channel paths built on it) blocks on a libdispatch semaphore — routing the wait through the scheduler and virtual clock, with a deterministic tie-break (a runnable unparker's signal always beats a same-instant timer, which fires only via the deadlock rescue). The baton uses a distinct Mach semaphore precisely so it does not recurse into its own interposer; before this fix the Parker shared the baton's `--allow`ed `dispatch_semaphore_*` audit entry and escaped both the scheduler and the virtual clock silently. `sched_yield` (std's `thread::yield_now`, reached by the `mpsc` backoff) is interposed to a deterministic scheduling point rather than a host yield. `pthread_rwlock_*` is a real deterministic reader/writer lock (replacing the former `ENOSYS` stubs): writer-preferring, FIFO among writers, with blocked readers batch-woken when a writer releases and no writer waits — every grant a recorded scheduler decision. std's own `RwLock` reaches this only via the parking `Parker` on the supported toolchains (its contended `write` path is `lock_contended → thread::park → dispatch_semaphore_wait`), so contended `std::sync::RwLock` acquisition is already deterministic through the Parker; the `pthread_rwlock_*` interposers serve C guests and any std that lowers to them.
12. Native networking over `SimNet`: UDP datagrams and zero-latency TCP streams are interposed for `AF_INET` sockets. UDP covers `socket`/`bind`/`connect`/`send`/`sendto`/`recv`/`recvfrom`/`getsockname`; TCP covers `SOCK_STREAM`, `listen`/`accept`/`connect`/`read`/`write`/`send`/`recv`/`shutdown`/`getpeername`, with wrapper forwarding for latency/fault layers. Sockets are fully virtual (zero network host imports); blocking recv/accept/send paths park through the scheduler baton; non-blocking sockets return `EWOULDBLOCK`; the setsockopt allow-list admits deterministic no-op socket options including `TCP_NODELAY`; IPv6 and DNS (`getaddrinfo`) fail closed with explicit errors. The native gate verifies this with `NATIVE_TCP_RESULT`. Deterministic process-state constants cover `getuid`/`geteuid`/`getgid`/`getegid` and common `sysconf` values; `fork`/`exec`-family/`posix_spawn`/`kill`/`waitpid` are deliberately absent so the audit rejects them as unmanaged imports.

13. Linux futex routing: Rust `std` on Linux reaches `Mutex`/`Condvar`/thread parking through raw `SYS_futex` via libc's `syscall` wrapper (not pthread), so the shim interposes `syscall` — `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` checks the futex word and parks the caller on the word's address through the scheduler baton (value check and park are atomic under the baton, so no wakeup is lost); `FUTEX_WAKE`/`FUTEX_WAKE_BITSET` wakes up to N parked tasks; every other syscall number fails closed with `ENOSYS`. `dlsym` is interposed to resolve nothing, so std's optional-symbol probe falls back to defaults and dynamic lookup can never return a host symbol. Timed futex waits park with their deadline on the virtual-clock timer queue (item 15) and return `ETIMEDOUT` when the deadline fires before a `FUTEX_WAKE`.

14. Directory, symlink, identity, descriptor, and environment containment: the dirent family (`opendir`/`readdir`/`readdir64`/`readdir_r`/`closedir`/`rewinddir`) iterates driver-ordered snapshots with deterministic synthetic inodes, so ordinary `std::fs::read_dir` works; `symlink`/`readlink` and symlink-aware `stat`/`lstat`/`fstatat`/`statx` follow MemFs semantics (leaf metadata without following, one terminal hop then `ELOOP`, `AT_SYMLINK_NOFOLLOW` honored); `gettid` (Linux) and `pthread_threadid_np` (macOS) return deterministic scheduler thread ids. `dup`/`fcntl(F_DUPFD*)` duplicate MemFs/CrashFs descriptors through the recorded `FsDup` operation, sharing cursor and access flags with deterministic monotonic fd numbers; unsupported targeted variants (`dup2`/`dup3` to a different number), captured stdio duplication, and socket duplication fail closed with `ENOSYS` plus captured `patina:` diagnostics. `__res_init` still fails closed. The deterministic environment is empty and immutable after startup. On Linux, `scripts/validate-native-shim.sh` adds a whole-run `strace` containment pass: outside an exact loader/std-runtime prelude (shared-object loads, `/proc/self/maps` stack introspection, control-plane descriptors 0-3, process-local memory and signal setup), no file, network, clock, entropy, or descriptor syscall may appear anywhere in the run — the seeded probe's guest section reaches zero host syscalls. macOS has no equivalent runtime gate: calibration established that `ktrace` (the only root-capable, SIP-compatible whole-run tracer) cannot found a sound default-deny check, so the macOS path skips loudly and `PATINA_REQUIRE_KTRACE=1` hard-fails on Darwin rather than reporting a check that cannot fail, leaving static instruction scanning plus import audit as the macOS containment evidence. Three independent, on-host-reproduced blockers: `BSC_*` events carry only raw register values, not decoded paths, so a guest's raw `open`/`stat` is indistinguishable by argument from the loader's libSystem prelude; the deterministic runtime buffers all guest output (stdout and stderr) into a single flush at process exit, so there is no in-band boundary marker to separate the pre-main loader prelude from guest code; and the loader/runtime issues the same syscall names an escape would (`open`, `fcntl`, `getpid`, ...) with init interleaved into early guest execution, so a name-scoped default-deny is either vacuous or false-positives on clean runs — a planted post-init raw `getpid` (inline `svc`) lands among the runtime's own `getpid` events, name-identical and not temporally separable.

15. Virtual-clock timer queue: the runtime `Context` keeps a timer registry ordered by `(monotonic deadline, registration sequence)` with at most one live timer per task, registered through the recorded `TaskParkTimed` boundary operation (realtime deadlines convert to monotonic at registration). When the scheduler would otherwise deadlock and timers exist, `scheduler_next` rescues: it advances the virtual clock to the single earliest deadline through the recorded `SleepUntil` path, wakes every due task in `(deadline, sequence)` order through recorded `TaskWake` operations, and retries — so replay re-executes the rescue from the trace and an empty registry still deadlocks explicitly. Any earlier wake deregisters the task's timer. Consumers: `pthread_cond_timedwait` and timed futex waits park with their deadline and learn timeout-versus-signal from the wake cause (the rescue purges the waiter from its primitive's queue and marks it timed out; the mutex is re-acquired before `ETIMEDOUT` returns), `nanosleep`/`clock_nanosleep`/`mach_wait_until` park timed under managed threads so other runnable tasks execute during a sleep (single-threaded programs keep the identical direct clock jump; the WASI host and explicit facade are unchanged), and a blocking UDP `recv` on an empty queue consults the new recorded `NetDriver::next_delivery` operation and parks until the earliest pending delivery, which makes non-zero link latency work end to end: `cargo patina run --net-latency-nanos N` (environment `PATINA_NET_LATENCY_NANOS`, rejected fail-closed when malformed) configures `SimNet`, and the latency wrapper forwards `next_delivery` so wrapper-added latency stays visible to the parking deadline.

16. Deterministic preemption for atomics-only race windows, with vacuous-schedule detection first. The cooperative `DetScheduler` only switches at interposed boundaries, so a race whose window is pure atomics — the classic read-modify-write on a `std::sync::RwLock` whose uncontended fast path issues no interposed operation — runs to completion between two boundaries and is unreachable at every seed (a spawned worker parks once at spawn, then runs its whole loop with zero interposed boundaries before the next worker starts). Two parts address this. **(a) Detection (default-on).** `Context` counts each task's scheduling boundaries, split into voluntary yields (every touch of the interposed effect surface reschedules) and blocking parks, maintained identically on record and replay because every task-lifecycle op runs on both; `Context::finish` emits a machine-readable `PATINA_SCHEDULE_REPORT` line (per-task `Ny+Mp`) to stderr for any multi-task run, plus a loud `PATINA WARNING` when a spawned worker completes without exceeding the thread-lifecycle scaffolding yield floor (spawning/joining a std thread costs a small fixed number of yields on its own; a worker at or below it performed zero interposed operations, so any loop it ran was atomics-only and its interleavings are unreachable). The floor keys on yields because they are seed-invariant where parks are not, and is iteration-count-invariant — a `lost-update` worker sits at the scaffolding floor whether it loops twice or a thousand times, exactly because the loop is invisible to the runtime. This is the mechanism that stops "N seeds explored, all clean" from silently meaning "nothing was explorable". **(b) Reachability.** `cargo patina build --yield-points` (default off) compiles the guest with LLVM SanitizerCoverage trace-pc-guard at basic-block granularity (`-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 -Cllvm-args=-sanitizer-coverage-trace-pc-guard`) and links a cargo-patina-embedded hook object whose `__sanitizer_cov_trace_pc_guard` routes into the shim's existing `patina_sched_yield`. `-Cpasses`/`-Cllvm-args` are *stable* rustc codegen flags, so this needs no nightly toolchain and no `RUSTC_BOOTSTRAP` (an earlier `-Zinstrument-mcount` route was rejected — function-entry only, so inlined hot loops get no hook, and it is genuinely nightly-gated); the only version coupling is to LLVM's internal pass name (`sancov-module`) and coverage cl::opts, stable across the LLVM releases rustc ships but not a rustc stability guarantee. The instrumentation is surfaced prominently: a `--yield-points` build prints a `PATINA_NATIVE_BUILD_YIELD_POINTS` line naming the mechanism and the fingerprint suffix. Because level-3 instrumentation reaches loop backedges, every iteration of an atomics-only loop offers the seeded scheduler a preemption point; the seed still drives *which* task runs at each point, so exploration is genuinely seed-varying. The source stays 100% std-pure and the instrumentation is inserted only on the Patina path — a plain native build never links the hook, so `testbeds/buggy-smoke/run-native.sh` passes bit-identically. Determinism and replay hold per `(seed, binary)`: yield decisions consume the recorded scheduler stream, and `run` detects the hook's embedded marker in the binary and folds `+yieldpoints` into the compatibility fingerprint, so a yield-point trace fails closed (fingerprint mismatch, nonzero exit) rather than silently replaying against a plain binary or the reverse — proven end to end by `native_yield_points_trace_fails_closed_against_plain_binary`; existing plain traces are unaffected. The Part-1 diagnostic is default-on independent of this flag. One correctness subtlety the instrumentation forced out: pthread thread-local destructors run *after* `thread_finish` has completed a task, and `std::sys::thread_local::…::destroy` is generic std code monomorphized into the guest crate, so under `--yield-points` it carries the hook and would take a scheduling point on an already-removed task. The shim marks a per-thread *completed* sentinel in `thread_finish` and no-ops `sched_point` on it — kept deliberately distinct from the never-registered state, which still fails loudly, so the fix does not trade a foreign-thread detection for silence. Result on the `buggy-smoke` canary: `lost-update` — previously unreachable at ~300 seeds — now trips `BUG_CAUGHT` at every seed under `--yield-points` (e.g. seed 3, `--iters 2`, trace SHA-256 `697d8d49c967127d…` identical across three records, replays exactly); the `deadlock` mode (interposed mutex loop) is correctly *not* flagged vacuous, and the plain `lost-update` build *is* flagged. Overhead: negligible build cost and, at the small iteration counts needed to surface a race, run cost at parity with a plain Patina run (process-startup-dominated); the per-boundary cost scales linearly with instrumented work as expected for cooperative preemption. Non-goals unchanged: no signal/ptrace preemption (host-nondeterministic), no raw-atomic interposition (impossible at symbol level).

Remaining:

1. Native async-runtime interposition (a shim-level epoll/kqueue/eventfd readiness reactor mapped onto `SimNet`) and non-zero TCP latency over `SimNet`. The explicit-API async executor (`patina-async`, Slice 2) is complete; native tokio/async-std under the shim stays a deliberate non-goal until such a reactor exists.
2. Cross-machine stress and a usable macOS whole-run syscall trace if a future `ktrace`/OS version exposes enough path context for a default-deny gate.

Ordinary programs built through `cargo patina build` — a single Rust source or a whole Cargo package with dependencies and build scripts — now claim supported `std` calls use Patina, with threads managed on both platforms and both verified locally by the validation scripts (macOS directly; Linux in a VM). Scheduling granularity differs deterministically: on macOS every interposed lock operation is a scheduling point, while on Linux uncontended lock operations are pure userspace atomics, so scheduling points occur at futex contention — Linux interleaving is contention-granular, macOS is lock-granular; both are seed-stable and seed-varying.

## Slice 5: native ABI, capture, crash, and stability — Partial foundations

Acceptance level: V5 is not complete.

Completed foundations:

- trace file and timeline-event resource limits;
- corruption, structural mismatch, and unsupported-version rejection;
- trace schema migration: prior supported formats (v1, v2, and v3) migrate losslessly in memory on load with fixtures for supported, unsupported, and malformed inputs; bundles are never rewritten on disk and only the current format version is written;
- compact trace byte encoding (format 3): bundles are written as compact JSON with base64 byte payloads instead of pretty-printed number arrays, cutting the representative workload from ~344 to ~124 bytes/event; the file stays valid JSON, so `jq`/`python3 -m json.tool` still render it for humans;
- self-contained fault replay (format 4): a record run stores its full fault configuration (crash point + torn granularity, sleep/net jitter, drop, base net latency) in the trace metadata, so a replay reproduces the faults with no knobs re-supplied; the recorded config is authoritative, and a pre-format-4 trace keeps the historical re-supply behavior. For native runs the `replay` subcommand rejects a re-supplied fault knob up front (the trace is authoritative); the runtime-level reconcile still fails closed on any conflicting knob supplied through the `run`/`test` replay path;
- self-contained argv replay and a `replay` subcommand: `run --record` captures the guest arguments (`argv[1..]`, everything after `--`) into the trace metadata as an additive field, so a run recorded with non-default arguments reproduces them without the operator re-passing the `--` section — the fix for a real incident where a divergent default argv caused a confusing mid-run trace operation mismatch. `cargo patina replay <bin> <trace>` is the sole native replay entry point: it restores every semantic input (seed, fault knobs, buggify, guest argv) from the trace and exposes no semantic flags — only host/build inputs the trace cannot carry (`--fingerprint`, `--mount` corpus re-supply, `--allow`/`--allow-unsupported-symbols`). `run` itself no longer has a `--replay` flag. A `--` section passed to `replay` must match the recorded arguments byte-for-byte or the replay is refused up front naming both lists; a pre-argv trace (absent field) keeps taking its arguments from the command line. `argv[0]` is supervisor-normalized to a fixed name (`patina-guest`) so the host binary path never leaks into the guest's `std::env::args()` and traces stay portable across machines; the argument list is metadata, not a fingerprint input (the recorded op-stream already reflects any argv-dependent behavior);
- failure-oracle delta debugging for main timelines, leaf branch suffixes, and non-leaf branch trees (protected inherited prefix, reducible suffix), plus scenario/parameter/seed reducers (seed reduction is bounded ascending canonicalization);
- a whole-image checkpoint/rollback crash filesystem integrated with traces, with seeded torn writes (configurable granularity and probability), optional sub-block byte-granularity tearing of the final unsynced write (a partial page differing from both the durable and applied images), rename-atomicity on/off, directory-fsync durability, and crash/restart recomputation with stale-handle rejection;
- explicit read-only host capture with path containment, replay without host I/O, and failure on branch misses;
- prefixed and opt-in POSIX native filesystem symbols with mixed C/Rust probes, plus managed pthread synchronization (Slice 4);
- bounded multi-process seed exploration;
- performance budgets in `patina-bench`: a hard trace bytes-per-event gate runs in `cargo test`, structural gates always run, and generous timing ceilings are `#[ignore]`d opt-ins.

- schedule reducers: `reduce_schedule` rewrites recorded `SchedulerNext` outcomes toward a canonical schedule — longer runs per task (switch collapsing) and lowest-task-id-first at switch points — accepting a candidate only when the failure oracle confirms the failure survives; protected inherited prefixes are never rewritten, and the combined minimization entry points run pruning, suffix shrinking, and schedule reduction to a joint fixed point.

Remaining: nothing for this slice's current scope; broader hardening items live in VALIDATION.md.

## Slice 6: cooperative-SUT SDK — Partial (Milestone A)

Acceptance level: V6 is not complete.

A FoundationDB-`BUGGIFY`- and Antithesis-style SDK lets a system-under-test
cooperate with the deterministic simulator. It lives in the existing `patina`
crate under a feature inversion: default features are the dependency-light SDK
(the `buggify!`, `buggify_with_prob!`, `buggify_delay!`, `buggify_knob!`,
`always!`, `sometimes!`, `reachable!`, and lifecycle macros plus
`patina::is_simulated()`/`patina::rng()`); the explicit-boundary facade
(`run`/`run_with`, `Context`, `rt`, the ABI re-exports) moved behind a new
`runtime` feature. A plain `cargo build` of an adopter links no runtime and every
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
   through the `PATINA_BUGGIFY*` control plane and recorded into the trace.
   `build` injects an internal
   `--cfg patina_shim` (only on the shim-linked native paths, never on
   `run`/`test`/`build --target wasi`) so the SDK's shim FFI is referenced only where those
   symbols resolve.
6. **`PATINA_SDK_REPORT`** — one machine-parseable stderr line per run:
   registered/activated/fired counts, cutoff state, and per-site
   `sometimes`/`reachable` coverage and knob values, in the spirit of
   `PATINA_SCHEDULE_REPORT`.
7. **`patina::rng()`** bridged to the root seed under Patina (a plainly-seeded
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
   declare that the guest calls `patina::lifecycle::setup_complete()`, so buggify
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
   `raft-harness/fuzz-sweep.sh --selftest` without altering any existing gate
   priority.
10. **Vendored `redb` fork** (`testbeds/redb-fork`, redb 4.1.0, clearly marked)
    with real sites in the commit/recovery paths: `buggify!` forcing 2-phase and
    quick-repair commits, a `buggify_delay!` before the durability flush,
    `sometimes!`/`reachable!` coverage on the two-phase path, full-repair entry,
    and torn-slot checksum rejection, and an `always!` on the quick-repair⇒2-phase
    invariant. A plain `cargo build` of the fork behaves exactly like upstream
    redb (every site is a no-op). The redb harness marks its setup boundary with
    one `setup_complete()` call.
11. **Dogfood campaign** (`testbeds/redb-harness/buggify-sweep.sh`, 350
    generations, per-gen derived buggify activation/fire + crash geometry, fresh
    `out-buggify/` dir): 350/350 `OK`, zero durability violations, zero
    `ALWAYS_VIOLATION`, zero crashes; buggify fired thousands of commit-path
    faults and every invariant held. One correctly-detected `SOMETIMES_UNMET`
    (torn-slot checksum rejection never satisfied — redb's two-slot commit design
    kept the committed slot intact under the crash geometry; torn data surfaced as
    fail-closed `OPEN_ERR` instead), which the campaign reports as a coverage gap
    with a nonzero exit exactly as specified.

## Dependency order

```text
patina-abi
  -> patina-driver-api
      -> concrete drivers
patina-abi
  -> patina-trace
concrete drivers + patina-trace
  -> patina-runtime
      -> patina-async (explicit-boundary futures executor)
          -> patina facade
              -> cargo-patina (process configuration)
```

Target hosts and native shims depend on the runtime boundary; they do not redefine it.

## Deliberate limitations of the complete slice

V1-V2 remain end-to-end at the explicit Rust API boundary. WASI executes the full audited Preview 1 surface. Native programs — single Rust sources and whole Cargo packages — build and run through `cargo patina build`/`run` with managed threads, UDP datagrams over `SimNet` (including deterministic timed waits and non-zero link latency through the virtual-clock timer queue), deterministic process-state constants, and a strict fail-closed import audit — but TCP, async runtimes, arbitrary FFI, and unrelated direct host APIs remain outside Patina's control. (Deterministic async at the explicit Rust boundary is supported separately through `patina-async`; the limitation here is native interposition of third-party async runtimes under the shim.)

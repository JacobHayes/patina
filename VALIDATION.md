# Patina Validation

This document defines how an implementation of Patina is tested and what evidence is required before a capability is described as working. The checks are layered so the current Rust-level vertical slice can be verified without implying that the eventual deterministic target boundary already exists.

## Validation principles

1. **Test observable contracts, not implementation details.** Seeds, traces, replay failures, virtual effects, and CLI behavior are public contracts.
2. **Make nondeterminism failures visible.** A missing driver, malformed trace, incompatible fingerprint, mismatched operation, or unconsumed replay event must fail the run.
3. **Use independent repetitions.** Reproducibility means separate processes produce the same result, not merely that one object can be queried twice.
4. **Keep replay stricter than seed reruns.** Replay verifies the exact ordered boundary-operation stream and rejects compatibility mismatches.
5. **Do not overstate boundary coverage.** Until custom targets and shims are validated, tests using `std` directly are host operations and are outside Patina's deterministic boundary.

## Capability levels

A level is complete only when all its required checks pass. Higher levels do not weaken lower-level checks.

### V0: workspace quality

Required:

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo doc --workspace --no-deps`
- `cargo +1.86.0 test --workspace`
- `scripts/validate-wasi.sh` when validating V3
- `scripts/validate-native-shim.sh` when validating native foundations
- `scripts/smoke-cross-target.sh` when validating cross-target determinism

These checks must run without network access after dependencies have been
fetched. For local development, `mise run setup` installs the Rust
toolchains/targets needed by these gates, and `mise run check` runs the
root-workspace checks plus the core WASI/native smoke scripts. The mise workflow
intentionally excludes heavyweight standalone testbed setup such as raft and
redb.

### V1: deterministic Rust-level vertical slice

This is the currently implemented acceptance level. The application explicitly enters `patina_dst_runtime::run` and performs effects through `patina_dst_runtime::Context`.

| Contract | Verification |
| --- | --- |
| Seed stability | Two fresh `cargo patina run --seed N` processes produce the same application summary. |
| Seed variation | At least one entropy-dependent result differs for distinct seeds. |
| Virtual time | Sleeping advances virtual nanoseconds without waiting for equivalent wall-clock time. |
| Seeded entropy | The generator has a fixed known-answer test and stable chunking behavior. |
| In-memory filesystem | Open/read/write/close behavior, cursor movement, truncation, and explicit errors have unit tests. |
| Driver boundary | Runtime effects are expressed as typed ABI operations and use narrow driver traits. |
| Missing capability | A runtime built without a requested driver returns `missing_driver`; it never falls through to the host. |
| Record | `--record` reserves a new path, refuses active/existing writers, and writes one parseable trace bundle atomically after a successful or application-error run that reaches finalization. |
| Replay | The `replay` verb reproduces recorded results and consumes every event. |
| Strict matching | Changed operation kind, arguments, event sequence, trailing events, malformed format, and changed fingerprint are errors. |
| CLI transport | `cargo-patina` forwards Cargo arguments and passes mode, seed, trace path, and fingerprint through the documented environment protocol. |

Automated evidence:

- crate unit tests cover ABI serialization, each concrete driver, trace validation, runtime modes, and CLI parsing;
- `crates/cargo-patina/tests/end_to_end.rs` creates an independent fixture package and verifies seeded runs plus record/replay through separate child processes;
- the `patina-dst-runtime` examples provide a manual smoke path.

Manual smoke test from the repository root:

```sh
cargo build -p cargo-patina
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina-dst-runtime --example deterministic --seed 123
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina-dst-runtime --example deterministic --seed 123 --record /tmp/demo.patina
PATH="$PWD/target/debug:$PATH" cargo patina replay . /tmp/demo.patina -p patina-dst-runtime --example deterministic
```

Expected:

- all three commands print the same `PATINA_RESULT` line;
- the first two use seed `123`;
- replay succeeds without contacting a host-backed effect driver;
- changing the example source before replay causes a fingerprint error.

### V2: cooperative scheduling and simulation drivers

This acceptance level is implemented at the explicit Context boundary:

- `patina-dst-sched-det` has a scheduler known-answer test and repeats spawn/choose/park/wake/yield ordering across 1,000 seeds;
- deadlock, invalid transition, running-task, and no-task outcomes are explicit;
- `patina-dst-net-sim` tests delivery, delay, reorder, partition, bind/route, and close state, plus seeded TCP-stream fault injection: per-segment delivery jitter and a reliable-transport drop-retransmit (a bounded RTO-style delay) that delays but never loses data and preserves in-stream byte order, reproducible per seed and varying across seeds, and the `NetFaultReport::is_vacuous` predicate backing the silent-inertness diagnostic;
- `patina-dst-wrapper-fault` tests seeded loss and duplication decisions;
- `patina-dst-wrapper-latency` tests fixed delay, seeded jitter, and packet reorder;
- runtime record/replay crosses scheduler, clock, network, filesystem, and entropy operations;
- trace format 2 resolves parent timelines, replays an exact prefix, records a seeded suffix, and replays named branches;
- CLI end-to-end tests create and replay a branch in separate processes;
- `--budget` bounds boundary operations and fails before an operation beyond the budget;
- repeated `--param KEY=VALUE` controls fingerprinted parameters exposed through `Context::param`;
- `patina-dst-async` drives a deterministic single-threaded futures executor over those same scheduler, network, and clock operations, and its suite asserts seed-stable and seed-varying executor polling order, exact virtual-time timer rescue and `timeout` ties, async TCP echo over `SimNet` with a real park/peer-wake ordering, async UDP echo under `LatencyNet` advancing to exact delivery deadlines, TCP backpressure, and byte-identical record/replay with strict divergence rejection — all under the workspace `cargo test`, with no new boundary operations and no dedicated validation script.

This level controls Patina's cooperative task state machine, which now also drives the `patina-dst-async` explicit-boundary futures executor; it does not itself intercept native Rust threads or interpose third-party async runtimes such as tokio (native thread interception and native async-runtime interposition — the kqueue/epoll readiness reactors — are validated under V4). This level's async determinism evidence is at the explicit-API level.

### V3: WASI Patina target

**Implemented for the entire audited Preview 1 surface.** The repository provides `cargo patina build --target wasi`, fail-closed import auditing, and Wasmi execution. All 46 allowlisted imports are implemented: arguments, environment, clocks, entropy, virtual regular files/directories, hard links, symlinks, timestamp mutation, descriptor flag/rights mutation and renumbering, seek, positioned I/O, metadata with real inode/link-count identity, polling, configured connected datagrams, captured stdout/stderr, yielding, and process exit. CLI controls include fuel, arguments, environment, socket descriptors, read-only/read-write preopens (`--preopen GUEST[:ro|:rw]`), resource-limit overrides (`--max-memory-pages`, `--max-descriptors`, `--max-preopens`, `--max-path-bytes`, `--max-io-bytes`, `--max-iovecs`), the seed-driven fault knobs (including `--sleep-jitter-nanos`, applied at the host's single sleep entry and thus covering `poll_oneoff` timeouts), the cooperative-SUT `--buggify*` knobs, record/replay, and trace branching. Beyond the 46 Preview 1 imports, the audit allowlists one further module — `patina_sdk` — the ten-function cooperative-SUT surface a `cfg(patina)` wasm build lowers its `patina_dst::` macros to (see V6); a plain build imports neither. The audit's security posture is unchanged by this addition: the `patina_sdk` effect surface is a strict subset of what Preview 1 already grants — `rng` is the same seeded entropy as `random_get`, and every other function only mutates sandboxed SDK state (site registries, assertion counters, lifecycle marks) with no host effect.

Automated evidence:

- host unit tests execute guest-memory bridges, fuel exhaustion, memory-growth trapping, mount-policy enforcement, network delivery, and record/replay;
- `scripts/validate-wasi.sh` compiles real Rust `wasm32-wasip1` filesystem/time, datagram, hard-link/symlink/readlink, and set-times probes;
- fresh processes verify seed stability/variation, strict record/replay, and seeded branch suffixes;
- `cargo-patina` end-to-end tests cover preopen/limit flag plumbing, including an `EROFS` probe against a read-only preopen;
- no host directory or socket is inherited: the filesystem is `MemFs`, and datagrams require `--socket FD=BIND->PEER`;
- unsupported imports fail audit before instantiation.

Documented semantic limitations: `sock_accept`/`proc_raise` return `NOSYS` (Preview 1 has no listen surface; Patina has no signal model — Preview 1 itself has no general socket-creation API, so the supported socket surface uses configured descriptors); `MemFs` timestamps change only via explicit set-times (writes do not auto-update mtime); symlinks are inert leaf nodes (one-hop terminal follow then `ELOOP`; intermediate traversal is a deterministic `NOTCAPABLE`); unlink-while-open is denied across all names of a multi-link inode; `APPEND` set after open works through a traced seek-to-end per `fd_write`; read-only mounts are host-enforced with descriptor rights as advisory defense-in-depth; memory growth past the cap is a deterministic trap.

### V4: native Rust Patina target

**Partial macOS/Linux linked-shim foundation with packaged single-source and whole-package builds and managed threads.** `cargo patina` injects `cfg(patina)` and `cfg(dst)`. `patina-dst-native-shim` exports a documented prefixed C ABI, while `c/patina_posix.c` provides an opt-in POSIX symbol layer. `cargo patina build <SOURCE.rs>` packages the shim build, link, and startup integration for a single Rust source (and `build <DIR|Cargo.toml>` for a whole Cargo package), and `cargo patina run <BIN>` supervises execution through the documented `PATINA_*` environment and `PATINA_TRACE_FD` descriptor; a C constructor auto-initializes from that protocol and `atexit` finalizes, so probes contain no explicit init calls and standalone execution aborts fail-closed. On macOS and Linux, `scripts/validate-native-shim.sh` uses that packaged path for ordinary Rust programs and verifies `std::fs`, filesystem metadata, `SystemTime`, `Instant`, `thread::sleep`, captured stdio, and standard-library entropy (including Darwin's CommonCrypto path) without corresponding host-effect imports. `std::thread` spawn/join and mutex/condvar contention — including a lock held across a boundary operation — run deterministically on both platforms: real host threads are gated one-at-a-time by `DetScheduler` via a per-thread OS-semaphore baton. On macOS, std lowers synchronization to the interposed pthread symbols (`pthread_create_suspended_np` + mach `thread_resume` create the managed vehicle), and std's thread `Parker` — `thread::park`/`park_timeout` and the `mpsc`/`mpmc` `recv`/`recv_timeout`, `Once`, and channel paths on it — blocks on a libdispatch semaphore, so the shim interposes `dispatch_semaphore_create`/`wait`/`signal`/`dispatch_time`/`dispatch_release` and routes the wait through the scheduler and virtual clock (the execution baton uses the *same* canonical libdispatch semaphore — matching the native primitive — reached through the shim's host-alias table, where `dlsym(RTLD_NEXT, ...)` resolves libdispatch's real entry rather than the shim's interposer, so the baton's vehicle never enters the guest import table and never recurses into any interposer; `sched_yield` is interposed to a scheduling point). Two threads communicating over `mpsc::recv_timeout` produce a byte-identical delivery/timeout schedule across repeated runs at multiple seeds and reproduce it under strict record/replay. On Linux (where `pthread_create` is interposed by a strong def whose real glibc creator is resolved through the host-alias `dlsym(RTLD_NEXT, ...)` table, needing no `-Wl,--wrap=pthread_create`), Rust `std` instead reaches `Mutex`/`Condvar`/parking through raw `SYS_futex` via libc's `syscall` wrapper, so the shim interposes `syscall`: futex waits park the caller on the futex word's address through the baton (value check and park are atomic, so no wakeup is lost), futex wakes release up to N parked tasks, and every other syscall number fails closed. `dlsym` is interposed to resolve nothing — dynamic symbol lookup can never return a host symbol. Scheduling granularity differs deterministically: macOS takes a scheduling point at every interposed lock operation, while Linux takes one at futex contention (uncontended lock operations are userspace atomics), so Linux interleaving is contention-granular; the probes assert seed stability and cross-seed variation over a seed range on both platforms. Cross-process seed stability, seed variation, byte-identical repeated record traces, strict replay, and fingerprint rejection are verified for the fully interposed probe through the supervisor-provided `PATINA_TRACE_FD` descriptor. Linux large-file/stat symbols and Rust's startup descriptor probe are handled explicitly. `dup`/`fcntl(F_DUPFD*)` duplicate deterministic file descriptors through recorded `FsDup`, sharing open-file descriptions; unsupported targeted/socket/stdio duplication fails closed with captured `patina:` diagnostics. Startup snapshots the private `PATINA_*` control plane for the shim, scrubs live environ, and leaves the guest-visible environment empty and immutable (`setenv`/`unsetenv`/`putenv` fail closed). `run` resolves the binary to an absolute path before exec and clears the child environment except for the supervisor protocol, so path-based invocations keep working while bare-name child-side `PATH` lookup is unsupported. Ordinary `std::fs::read_dir` iterates driver-ordered snapshots with deterministic synthetic inodes through the interposed dirent family; `symlink`/`read_link`/`symlink_metadata` and stat-through-symlink follow MemFs semantics (one terminal hop then `ELOOP`, `AT_SYMLINK_NOFOLLOW` honored), and the probe asserts the exact listing and symlink behavior in its deterministic output. Thread identity is deterministic (`gettid` on Linux, `pthread_threadid_np` on macOS return scheduler ids); `__res_init` still fails closed; `socket` validates its protocol argument and `setsockopt`/`getsockopt` reject non-socket descriptors.

`cargo patina audit` is a strict per-format import allowlist over Mach-O/ELF (other formats rejected): after alias normalization (`$NOCANCEL`, underscore prefixes), an import passes only if it is an explicitly listed effect-free host-deferred symbol or `--allow`ed by the caller, and anything unknown fails closed as `unknown-import` — this is what catches the missed-interposer class structurally (a `clock_nanosleep`-style escape now fails the audit instead of passing silently). Known host-effect names keep their categories (filesystem, unmanaged-sync `os_unfair_lock`/`__ulock`/`psynch`, direct-syscall, and so on) for error quality, and instruction scanning still rejects raw syscall/clock/entropy assembly. The shim's control-plane symbols are `--allow`ed per audited binary by the scripts rather than statically allowlisted, so unmanaged binaries importing them still fail; under the host-alias doctrine (ARCHITECTURE.md) the shim resolves its host vehicles at runtime through `dlsym(RTLD_NEXT, ...)`, so on both platforms that set collapses to the single `dlsym` primitive (the trace-fd/baton/thread-creation vehicle names no longer appear in the guest import table at all — on Linux `__read`/`__write`/`sem_*`/`pthread_create` are each interposed by a strong def whose real vehicle is resolved through the same `dlsym(RTLD_NEXT, ...)` table); the scripts also prove the negative cases (audit without `--allow` fails, an unknown benign import fails, escape fixtures fail). `run` enforces the same audit as a **pre-run default-deny gate** before the guest executes — it bakes in the control-plane vehicle so ordinary binaries need no repeated `--allow`, and hard-errors (naming and categorizing the symbols) on any other blocking/time/scheduling/effect symbol that is neither interposed nor known-safe, so a missed interposer becomes a refusal rather than a silent escape. This is what structurally closed the macOS Parker escape: std's `Parker` and the shim's own baton both used `dispatch_semaphore_*`, so the baton's per-binary `--allow` covered the Parker too; the dispatch semaphores are interposed (hence *defined*, not imported) and the baton reaches the *real* libdispatch semaphore through the host-alias table (`dlsym(RTLD_NEXT, ...)`) rather than a named import, so no vehicle symbol sits in the guest import table for a shared allowance to cover — the collision is eliminated structurally, which is exactly why the baton can safely use the same canonical primitive std does rather than one std happens not to use. The escape hatch `--allow-unsupported-symbols <all|name,...>` downgrades matching denials to a loud warning recorded in a sidecar beside a `--record` trace (visibly qualifying the determinism claim); the native gate proves the gate can fail — a planted Mach `semaphore_wait` binary is refused, named, and runs only under the hatch with the warning (`os_unfair_lock` served this role until it gained an interposer; its probe is now an acceptance-plus-misuse leg) — and that a partial allow list still fails closed. Pure libm math (`pow`/`powf`, `exp`/`log`, the trig/hyperbolic families, `sqrt`/`cbrt`/`hypot`, `fma`, the rounding family, `fabs`/`copysign`/`fmin`/`fmax`, ...) is known-safe on both formats — an explicit list, never a prefix match, so an effectful math-adjacent symbol (`random`, `system`) stays denied — because each is a function of its floating-point operands with no boundary effect (errno/FP-flag side effects are not host effects Patina models); this clears the `_pow` `unknown-import` an ordinary numeric guest surfaces, so it no longer needs `--allow` at every run. Because only a *shim-linked* binary shows the post-interposition residual, `audit` is **source-first**: auditing a `SOURCE.rs`/`DIR`/`Cargo.toml` (or a Patina-built artifact) links the shim first and reports the true handful of escapes, whereas a stock `cargo build` output lists the whole libc surface the shim interposes as unsatisfied imports — the opposite of the truth. `cargo patina audit <prebuilt-binary>` therefore **fails closed** on a binary that does not define the shim control-plane marker (`patina_init_from_env`), directing the caller to the source-first form or a Patina-built artifact; `--raw` overrides the gate and runs the full audit anyway (instruction scan and escape categories included) under a loud `PATINA_RAW_AUDIT` stderr banner marking the import findings as pre-interposition; the validation scripts use it for their deliberately-unlinked planted-escape probes.

The deny/interposed/known-safe lists are organized by an explicit escape-class taxonomy, and every class has a permanent test that proves its detection is not vacuous. The full per-class breakdown with symbol lists lives in `crates/patina-target/ESCAPE-CLASSES.md`; the coverage matrix is:

| Escape class | Detection mechanism | Fixture / test (red-before, green-after) | Residual the symbol audit cannot see |
|---|---|---|---|
| Blocking / scheduling (`__ulock`/`__psynch`/dispatch/mach-sem; `poll`/`select`; interposed `os_unfair_lock` and the `kqueue`/`kevent` + `epoll`/`eventfd` readiness reactors) | import audit | `native_run_prerun_gate_refuses_every_escape_class` (`semaphore_wait`, `select`); planted-`semaphore_wait` e2e; `os_unfair_lock` acceptance + misuse-abort legs; `recv_timeout` & `rwlock` determinism; reactor legs (raw kqueue/epoll edge+timeout+waker, tokio ping-pong on both platforms) | an inlined `__ulock_wait` `svc` — Linux `strace`; **honestly absent on macOS** |
| Time | import audit **+** instruction scan (aarch64 `mrs CNTVCT_EL0`, x86 `rdtsc`) | `native_run_prerun_gate_refuses_every_escape_class` (`time`) | the **Darwin commpage** time path: `mach_absolute_time`/`gettimeofday` fast paths read a kernel-mapped page with an ordinary `ldr`, **not** an `mrs`, so the instruction scan does **not** catch it — coverage comes from *interposing* `mach_absolute_time`/`clock_gettime`/`gettimeofday` (what libc/std actually call); a hand-rolled commpage reader that bypasses libc is an uncaught residual |
| Entropy | import audit **+** instruction scan (x86 `rdrand`, aarch64 `RNDR`) | `native_run_prerun_gate_refuses_every_escape_class` (`arc4random`) | `rdseed`/novel entropy instruction encodings |
| Thread lifecycle | import audit | C `escape_probe` (audit rejects `pthread_create` as `unmanaged-thread`) + classifier unit | `pthread_create` is interposed, so a shim-linked guest can only reach uninterposed thread creation through non-exported private stubs (not linkable) |
| Process | import audit (uninterposed members) **+** runtime deny-trap (the spawn family a guest links) | `native_run_prerun_gate_refuses_every_escape_class` (`kill`, uninterposed); `native_run_deny_trap_aborts_a_guest_that_actually_spawns` (a guest reaching shim-defined `fork` aborts deterministically, naming it); package off-allowlist binary fails closed | the spawn family (`fork`/`posix_spawn*`/`waitpid`/`pipe`/`setsid`/`setgid`/`setuid`/`setpgid`/`setgroups`/`chdir`/`chroot`) is now shim-defined so it is a runtime abort, not an import — a reachability audit could not clear it (statically wired, runtime-flag-dormant) |
| Filesystem / network | import audit | `native_run_prerun_gate_refuses_every_escape_class` (`link`, `gethostbyname`) | an inlined `open`/`stat` `svc` — Linux `strace`; absent on macOS |
| Shared memory / IPC | import audit | `native_run_prerun_gate_refuses_every_escape_class` (`shm_open`) | `mmap(MAP_SHARED)` — the flag is invisible to a symbol audit and `mmap` is allowlisted as process-local memory |
| Signals / timers | import audit | `native_run_prerun_gate_refuses_every_escape_class` (`setitimer`) | — |
| Environment | **interposition** (`getenv`→NULL, `setenv`/`unsetenv`/`putenv` fail closed) | classifier unit test | fully interposed — no uninterposed member exists to plant end to end |
| Dynamic loading | import audit; `dlopen`/`dlclose` denied. `dlsym`: Linux interposed to resolve nothing (deterministic NULL); macOS is the shim's host-alias resolution primitive (`dlsym(RTLD_NEXT,...)`), baked into `shim_control_plane_symbols` | `native_run_prerun_gate_refuses_every_escape_class` (`dlopen`) | **macOS guest `dlsym` call** reaches the real resolver (not interposed — a strong-def interposer would capture the shim's own resolver calls); residual **stays**. #18 investigated a build-time redirect (`objcopy --redefine-sym` on guest objects) and **did not implement it, by measurement**: on macOS nothing but the shim references `dlsym` — the guest user object has no `_dlsym`, no sysroot rlib (`libstd`/`libcore`/…) references it, so std never dynamically resolves a symbol, and the only `_dlsym` in a linked guest is the shim's `dlsym(RTLD_NEXT,...)` resolver. A call needs the reference, so the shim is the sole caller; the residual only manifests for a guest that **hand-writes `dlsym(...)` itself**, and closing that would mean a manual-relink pipeline (plus the non-default `llvm-tools` objcopy) — real risk for zero measured benefit. Honest/adversarial-shaped, measurably unreachable by any ordinary std guest |
| Direct syscall (by name) | import audit (`syscall`) **+** instruction scan (`svc`/`syscall` opcodes) | `native_run_prerun_gate_refuses_every_escape_class` (`syscall`) | — |

Two general residual classes cut across the table: **interposed-but-unsupported** symbols (e.g. `pthread_cancel`) are *defined*, so they pass the pre-run symbol gate but fail closed loudly with `ENOSYS` at call time — which is why `pthread_rwlock_*` was made a real deterministic implementation rather than left an `ENOSYS` stub; and **inlined raw instructions**, caught by the aarch64/x86 text scan for `svc`/`syscall`/`rdtsc`/`rdrand`/`RNDR`/`CNTVCT` but with the honest macOS whole-run gap above. The plain-`std` guests that legitimately run today (`std`-probe, thread-probe, `recv_timeout`, `rwlock`, and arg-reading guests) pass the gate with **zero** allowances: `__NSGetArgc`/`__NSGetArgv` are known-safe (supervisor-controlled argv) and `confstr` is interposed to a deterministic value. Interposed-and-supported surfaces never appear as imports and so are never flagged — this includes the dispatch-semaphore Parker, `sched_yield`, `confstr`, and `setsockopt`/`SO_RCVTIMEO` (whose deterministic recv deadline applies at `patina_sleep_until`, distinct from the deadlock-rescue clock path, and uses the same delivery-wins-ties tie-break as the Parker).

The gate deliberately audits the guest's **flat import list**, not a static call graph. We evaluated making it call-graph-aware — clearing a flagged import when no path from an entrypoint reaches it, so a binary that merely *links* an escape symbol without a live path need not carry an allowance — against a real-world file-walking CLI we audited (whose old allow list named 28 subprocess-spawn and host-query symbols) and rejected it: a **sound** reachability pass clears **zero** of them, so it is all cost and no benefit. Two reasons, each verified on the built guest (arm64 Mach-O; `otool -Iv` stub map + `objdump -d` call-graph BFS). (1) The dormant code is statically wired: the guest's subprocess spawn is reachable from the Rust entry by **direct calls alone** — an unbroken `bl` chain from `main` through the search worker and a command-reader builder into `std::process::Command::spawn` and on to `bl _fork/_posix_spawnp` — and only a *runtime* flag selects it, which static analysis cannot prove is never set. (2) Sound indirect-call handling swallows the program: any reachable indirect call may reach any address-taken function, and in a Rust binary `main` itself is address-taken (handed to `lang_start`), so the conservative closure admits the whole live call graph. The honest fix is therefore per-symbol *interposition*, not reachability: the guest's spawn family becomes shim **deny-traps** that abort deterministically if reached (so a genuine spawn fails loud + reproducible instead of escaping silently), its host-state queries return fixed deterministic values, its pure-compute members (`memset_pattern4/8/16`, the `sigset_t` bit ops) are known-safe, and `dlsym` is the shim's own host-alias control-plane primitive — each drops off the import table or the allow list, emptying the allowance entirely while the gate stays fail-closed for any new import. Full analysis and per-symbol disposition: `crates/patina-target/ESCAPE-CLASSES.md` ("Why symbol-reachability, not static call-graph reachability").

On Linux the script adds a whole-run `strace` containment pass: every traced file, network, clock, entropy, and descriptor syscall in the entire run must match an exact loader/std-runtime prelude shape (shared-object loads, `/proc/self/maps` stack-bounds introspection, control-plane descriptors 0-3, process-local memory/signal setup, glibc's nonblocking startup `getrandom`) — the seeded probe's guest section performs zero host syscalls, and a planted `clock_nanosleep`, host `openat`, or `socket` anywhere in the run fails the gate. vDSO time reads never enter `strace` and are covered by the libc-interposition probes. macOS has no equivalent runtime gate: calibration established that `ktrace` (the only root-capable, SIP-compatible whole-run tracer) cannot found a sound default-deny check, so the macOS path skips loudly and leaves static instruction scanning plus import audit as the macOS containment evidence — and `PATINA_REQUIRE_KTRACE=1` hard-fails on Darwin rather than reporting a check that cannot fail. Three independent blockers, each reproduced on-host: `ktrace` BSD-syscall (`BSC_*`) events carry only raw register values, not decoded paths, so a guest's raw `open`/`stat` is indistinguishable by argument from the loader's libSystem prelude; the deterministic runtime buffers all guest output (stdout and stderr) into a single flush at process exit, so there is no in-band "first write to stdout" boundary to separate the pre-main loader prelude from guest code (an early unbuffered stderr marker is observed emitted only at the end of the trace); and the loader/runtime legitimately issues the same syscall names an escape would (`open`, `stat64`, `fcntl`, `getpid`, ...) while its init interleaves with early guest execution, so a name-scoped default-deny is either vacuous or false-positives on every clean run — a planted post-init raw `getpid` (inline `svc`) lands among the runtime's own `getpid` events, name-identical and not temporally separable. Mach traps are outside the BSD syscall class and remain the scheduler-baton scope analogue of Linux futex allowances. The strace path allowances are shape-based (they audit our probes, not adversarial binaries).

`scripts/smoke-cross-target.sh` builds one ordinary-`std` smoke program for wasm32-wasip1 and the native host, runs seeded smoke tests with recorded and replayable traces on both, and requires the deterministic program output to be byte-identical across targets.

Native UDP datagrams and zero-latency TCP streams run over `SimNet` through ordinary `std::net`: sockets are fully virtual (the probe binaries carry zero network host imports), blocking receives/accepts/writes park through the deterministic scheduler, latency/fault wrappers forward TCP operations, deterministic no-op socket options such as `TCP_NODELAY` are allow-listed, and the script verifies seed-stable/seed-varying multi-thread datagram ordering plus byte-identical TCP record/replay on both platforms (`NATIVE_TCP_RESULT`). Timed waits are deterministic through the virtual-clock timer queue: `Condvar::wait_timeout` (pthread cond on macOS, futex timeouts on Linux) returns timed-out exactly at its virtual deadline when unsignalled and 0 when signalled first, `thread::sleep` in a multi-thread program yields to runnable tasks and advances virtual time only when nothing else can run, and a blocking UDP receive under `cargo patina run --net-latency-nanos N` parks until the virtual clock reaches send-time-plus-latency — the script's timer gates assert the exact virtual elapsed values, seed stability, and byte-identical record/replay for all three. TCP IPv6 and DNS paths fail closed with explicit errors, process-state reads return deterministic constants, and process spawning stays denied by the audit. On Linux, `pthread_create` is interposed by a strong def and reaches the real glibc creator through the host-alias `dlsym(RTLD_NEXT, ...)` table, so it leaves the guest import table entirely — no `-Wl,--wrap=pthread_create` and no per-binary allowance (an unmanaged `pthread_create` import stays denied). `build` also builds whole Cargo packages: it drives the package's own `cargo build`, injecting the cfgs and shim link arguments through `CARGO_ENCODED_RUSTFLAGS` while an explicit host `--target` isolates them to the final binary (rlib compiles ignore link arguments; build scripts and proc macros link for the host without the flags). The script's package gate builds an ordinary-`std` package with a path dependency and a build script, then audits, runs, and record/replays the product exactly like a single-source binary — the build-script env and the dependency's output appear in the deterministic result — and confirms multi-binary ambiguity without `--bin` and an off-allowlist binary both fail closed. All gates run locally on macOS and in a Linux VM. This is not yet a packaged custom Rust target: the guest is compiled with the stock host target and prebuilt `std`, not a recompiled deterministic `std`.

Syscall-user-dispatch (SUD), slice 1, traps a guest's raw inline `syscall`/`svc` instruction into the deterministic runtime via a `SIGSYS` handler, so a rustix-default (or hand-asm) binary runs in-model on x86_64 Linux instead of being refused. The `validate-native-shim.sh` SUD section branches on a live kernel probe (`prctl(PR_SYS_DISPATCH_OFF)` — 0 on a SUD kernel, `EINVAL` where absent) so it is never vacuous: a SUD kernel runs the positive battery, a non-SUD kernel prints a loud, counted `sud: SKIPPED` line and runs the refusal plus kernel-independent legs. Positive battery (x86_64 CI): a `raw_syscall_probe` (inline `syscall`/`svc` for the clock/filesystem/entropy families plus a three-thread fanout that each read the raw monotonic clock) audits as `direct-syscall (SUD-managed)` rather than refusing, runs, is byte-identical across two same-seed runs and across record→replay, varies its raw `getrandom` across seeds, and the fanout proves every thread observed **virtual** (not wall) time — the per-thread trampoline arming; a raw `getpid` (un-tabled in slice 1) traps to a **named, deterministic abort** (`SUD trapped unsupported syscall`), not a silent escape; and after the auxv scrub `getauxval(AT_SYSINFO_EHDR)` reads 0 (the vDSO is unfindable, so a vDSO-resolving crate falls back to a trappable raw syscall). Refusal + kernel-independent legs (the arm64 VM proves these for real): the same marker-carrying `raw_syscall_probe` is **refused** on the no-SUD kernel with the extended hint (`--cfg rustix_use_libc` / x86_64) — for `run` AND for `replay`, where the refusal fires **pre-exec, before the trace is opened**, naming the situation ("this kernel lacks syscall-user-dispatch"); a guest `sigaction(SIGSYS,…)` is **refused** loudly (the symbol-door hardening, independent of SUD arming — RED before it landed, the old allowlist let it succeed silently); and a NON-shim-linked binary with a planted raw syscall and no `patina_sud_dispatch` marker is **still refused** by `audit --raw` (the downgrade is conditional on the marker, never unconditional). The replay-refusal decided in SUD-DESIGN.md #6 (`sud` trace metadata + upfront mismatch refusal) is delivered in slice 1 by this pre-run gate rather than a metadata field: sound because slice 1 has **no independent SUD toggle** — arming is a pure function of the binary marker × kernel probe, so the binary identity replay already pins subsumes the metadata byte; the explicit `sud` `RunMetadata` field lands in slice 2 (§7.3), and any future toggle makes it mandatory in the same change. Detection-before-fixes: the refusal (run and replay), the unmapped-syscall abort, the SIGSYS-hijack refusal, and the marker gating are each proved to fire.

Required before claiming general native `std` control:

- non-zero TCP latency over `SimNet` (native async-runtime interposition is delivered: the interposed kqueue/epoll readiness reactors run stock tokio under the shim on both platforms, exercised by the tokio + parking_lot + rustix `validate-native-shim.sh` leg — seed-stable, replay-identical, no allowances);
- cross-machine stress and a usable macOS whole-run syscall trace if a future `ktrace`/OS version exposes enough path context for a default-deny gate;
- deterministic stress across fresh processes and machines.

### V5: native ABI shim and production-hardening

**Partial.** Implemented foundations include:

- trace file/event limits and hostile structural-input rejection;
- trace schema migration: supported prior formats (v1, v2, and v3) migrate losslessly in memory on load, with fixtures for prior, unsupported (0/99), malformed, and noncontiguous inputs (per prior version) covering migrate/validate/replay; bundles are never rewritten on disk and only the current format version is written;
- compact trace byte encoding (format 3): compact JSON with base64 byte payloads replaces pretty-printed number arrays, dropping the representative workload from ~344 to ~124 bytes/event under the `patina-dst-bench` gate; the tolerant reader still accepts the legacy number-array form so v1/v2 bundles migrate without a per-payload rewrite, and the file remains valid JSON for `jq`/`python3 -m json.tool`;
- self-contained fault replay (format 4): a record run captures its full fault configuration (crash point + torn granularity, sleep/net jitter, drop, base net latency) into the trace metadata, so a replay reproduces the faults with no knobs re-supplied; the stored config is authoritative, conflicting explicit knobs fail closed before any driver is built, and a pre-format-4 trace (no such metadata) keeps the historical re-supply contract — covered by `patina-dst-runtime` reconcile unit tests, flag-free record/replay round-trips (including a byte-granularity torn image), and the v3→v4 migration fixture. The native `replay` subcommand exposes no fault knobs at all and refuses one up front, naming the flag;
- failure-oracle delta debugging for unbranched main timelines, leaf branch suffixes, and non-leaf branch trees (inherited prefix protected, suffix reducible), exposed by `cargo patina minimize` through isolated candidate files and `PATINA_MINIMIZE_TRACE`, plus scenario/parameter reducers and bounded ascending seed canonicalization;
- schedule reducers: `reduce_schedule` canonicalizes recorded `SchedulerNext` outcomes (switch collapsing toward longer per-task runs, lowest-task-id-first at switch points) under the same failure oracle, never rewriting a protected inherited prefix; the combined entry points and `cargo patina minimize` run pruning, suffix shrinking, and schedule reduction to a joint fixed point;
- `CrashFs` whole-image checkpoints, synchronized durability, crash rollback, stale-handle rejection, and cross-trace replay tests, with seeded torn writes (configurable granularity/probability against the durable baseline), sub-block byte-granularity tearing of the final unsynced write (a partial page that differs from both the durable and fully-applied images, exercised over positional `write_at`), rename atomicity on/off, directory-fsync durability, and crash/restart recomputation — evidenced by the `patina-dst-fs-crash` unit suite and a runtime record/replay torn-write test;
- read-only allowlisted `HostCaptureFs`, symlink/traversal containment, replay without host access, and failure on branch capture miss;
- mixed Rust/C symbol tests for the documented prefixed ABI and POSIX filesystem shim;
- bounded multi-process seed campaigns through `cargo patina explore`;
- performance budgets in `crates/patina-bench` (`cargo run -p patina-dst-bench --release`): a hard trace bytes-per-event ceiling and structural gates (one event per boundary operation, linear trace growth) run in `cargo test`; generous wall-clock ceilings are `#[ignore]`d opt-ins for quiet machines.

Required before claiming broad libc/POSIX compatibility or stable traces:

- broader libc network/process symbol *coverage* (modeling more behavior): the remaining items are either a documented non-goal (process/spawn symbols, which the audit rejects) or tracked in Slice 4 (non-zero TCP latency; the async readiness reactors are delivered). Unsupported-symbol *diagnostics* are complete — the strict audit default-denies any unmodeled import as `unknown-import`, interposed-but-unsupported operations fail closed at runtime through `patina_posix_deny` (ENOSYS plus a loud `patina: … failing closed` line), and the `unknown_import_probe` gate proves the rejection fires.

`CrashFs` modeling simplifications stated honestly: directory renames are always atomic (no subtree tearing); directory-durability loss covers explicitly created entries, not implicitly created parents; defaults preserve the prior conservative behavior (4096-byte granularity, torn probability 1.0, atomic renames, directory durability off).

### V6: cooperative-SUT SDK

**Partial (Milestone A).** The `patina` crate ships a FoundationDB-`BUGGIFY`- and Antithesis-style SDK as its whole dependency-light surface; the explicit-context API (`run`/`run_with`, `Context`) lives in the separate `patina-dst-runtime` crate. Every SDK macro (`buggify!`, `buggify_with_prob!`, `buggify_delay!`, `buggify_knob!`, `always!`, `sometimes!`, `reachable!`, `lifecycle::event!`) plus `is_simulated()`/`rng()` is a no-op or plain fallback outside a Patina build, and no `cfg(patina)` appears in adopter code.

Automated evidence:

- `patina-dst-runtime` unit tests cover activation as a deterministic function of seed and label (with the ~25% realized fraction), firing-PRF determinism and seed variation, the damage-control cutoff, duplicate-label detection, knob determinism and range, the disabled/inert path, `rng()` determinism, the trace-metadata reconcile contract, and byte-identical record/replay of buggify decisions without re-supplying flags;
- `patina-dst-trace` covers the additive `buggify` metadata round-trip and its absence from a buggify-free trace, and the additive `guest_argv` metadata round-trip (including the empty-list-vs-absent distinction so a zero-argument run stays distinguishable from a pre-argv trace);
- guest-argv replay is proven end to end (`native_replay_restores_guest_argv_and_normalizes_argv0`): a run recorded with non-default `-- ARGS` is reproduced byte-identically by a bare `cargo patina replay <bin> <trace>`, a mismatched `--` section is refused up front naming both argv lists, an old trace without the field still replays with explicit arguments, and `argv[0]` is pinned to the normalized `patina-guest` (the host binary path never leaks into the guest);
- the `patina` crate's own tests, built WITHOUT `cfg(patina)`, prove every macro is inert (a consumer's plain `cargo build` behavior);
- `cargo-patina` end-to-end tests build a whole package depending on the SDK, run it under `run --buggify`, assert the `PATINA_SDK_REPORT` line and nonzero firings, replay a recorded trace byte-identically without re-supplying `--buggify`, and prove a duplicate label aborts with the `PATINA_BUGGIFY_DUPLICATE_LABEL` marker;
- the flag-off invariance is verified on a real testbed: a rebuilt guest (now compiled with the internal `--cfg patina_shim`) reproduces its canonical seed-7 result hash with buggify disabled, so the SDK is zero behavior change when off;
- **buggify on WASI** (Milestone C) is at full parity with native. `patina-dst-wasi-host` tests drive the `patina_sdk` module directly (a site fires and the diagnostics are recorded) and prove the sleep-jitter fix is deterministic and reproduces on replay; `cargo-patina` end-to-end tests run hand-written `patina_sdk`-importing modules to prove firing + a parseable `PATINA_SDK_REPORT`, the `PATINA_ALWAYS_VIOLATION`/`PATINA_BUGGIFY_DUPLICATE_LABEL`/`PATINA_BUGGIFY_SETUP_NEVER_CALLED` markers with a nonzero exit, flag-free record/replay byte-identity (with a re-supplied `--buggify` refused), and cross-seed variation; and a full-stack test compiles a buggify-instrumented Rust guest both plain (asserting its wasm imports **no** `patina_sdk` module — the no-leakage contract) and through `build --target wasi` (asserting it does), runs it under `--buggify`, reproduces its digest on replay, and trips the `always!` oracle via `--arg violate`.

Determinism and fail-closed guarantees: buggify decisions are pure functions of the seed and site label and are never recorded per evaluation (no trace bloat); the realized config, active-site set, and knob picks are recorded in the trace metadata and are authoritative on replay (conflicting replay knobs fail closed like the fault knobs); enabling buggify folds a `+buggify` fingerprint component, reconstructed at replay from the trace, so a buggify trace never cross-replays with a non-buggify build.

Lifecycle gating is causal through the runner: `run --buggify-after-setup` declares that the guest calls `setup_complete()`, so buggify stays inert until that call, and a declared-but-never-called run fails loudly (`PATINA_BUGGIFY_SETUP_NEVER_CALLED` + abort) after recording its trace — verified by a `cargo-patina` end-to-end test. Without the flag, buggify is armed from the start and `setup_complete()` is a boundary/coverage marker.

Honest limitation: sites register lazily at first evaluation, so a never-reached site is invisible to a single run's `PATINA_SDK_REPORT` (the campaign layer accumulates coverage across generations).

The campaign layer (`testbeds/buggify-campaign.sh`) adds two classes on top of the existing sweep classifier without changing any existing gate priority: `ALWAYS_VIOLATION` (per-gen, top severity, fires even on exit 0, never downgraded) and `SOMETIMES_UNMET` (campaign-level: a `sometimes!` site reached but never satisfied fails the campaign). Both are proven fireable — plus a not-downgraded check — by a selftest wired into `testbeds/workq/fuzz-sweep.sh --selftest`. The same campaign layer drives the `workq` testbed's buggify leg (`testbeds/workq/run-patina.sh`) and backs a WASI dogfood (`testbeds/buggify-wasi/wasi-buggify-sweep.sh`, fresh `out-wasi-buggify/`): a buggify-instrumented `wasm32-wasip1` fixture compiled through `build --target wasi`, run under per-generation-derived activation/fire with a per-generation record→replay determinism check, proving the `patina_sdk` guest path parses into the identical `PATINA_SDK_REPORT` classifier the native sweeps use.

### V7: exploration tier (directed schedule/fault steering)

**Partial (wave 12).** Four default-off, seed-derived exploration policies steer
which interleavings and fault combinations a seed reaches, each recorded into the
trace metadata, reconciled authoritatively on replay, and folded into the
compatibility fingerprint so a policy trace fails closed against a plain build.
The default uniform scheduler path is byte-for-byte unchanged (canonical seed-7
sequence and every fault/buggify hash preserved).

- **PCT** (`--sched-pct[=D]` / `--sched-pct-steps N`): a `DetScheduler` selection
  policy — random task priorities plus `d-1` seed-placed priority-change points
  that preempt the running task over yield-point boundaries. `patina-dst-sched-det`
  unit tests cover determinism per seed, `d=1` no-preemption, a live change point
  actually preempting (`change_points_hit`), and the default policy reporting no
  metrics. `patina-dst-runtime` proves record→replay reproduces the exact selection
  order and records the policy metadata, and that a conflicting supplied policy
  fails closed on replay. Demonstrated end to end on a two-thread lost-update
  guest: PCT preempts with `pct_change_points_hit>0` and never hangs across many
  seeds/depths.
- **Swarm** (`--swarm`): a seed-derived per-class coin masks the enabled fault
  classes to a subset (swarm testing); the masked config is what the drivers and
  the recorded `FaultConfigRecord` consume, and a `SwarmConfigRecord` documents
  the candidate set and selection. `patina-dst-runtime` proves the candidate/selected
  sets round-trip, the applied config matches the selection, and subsets vary
  across seeds. `patina-dst-trace` covers the additive `swarm` and `schedule_policy`
  metadata round-trips and their absence from a plain trace.
- **Starvation intervals** (`--starve[=N]` / `--starve-max-len M` /
  `--starve-window W`): bounded seed-chosen intervals not scheduling a residue
  subset. Liveness is guaranteed at the scheduler level by *aging* — a per-task
  consecutive-skip cap force-schedules a deferred task, proven by
  `starvation_aging_bounds_consecutive_skips_guaranteeing_liveness`; a
  would-starve-everyone step falls back and warns (`starve_vacuous`).
  **Documented native-shim limitation:** an uninstrumented atomic critical
  section (std's queue `RwLock`/`Parker` fast path — std is not yield-point
  instrumented, so a spinner reaches no yield edge) can livelock under adversarial
  deferral. Mitigations: a loud `PATINA WARNING` on non-`--yield-points` builds; a
  supervisor wall-clock **stall backstop** armed only under `--starve` (default
  60 s, `PATINA_STARVATION_STALL_SECS`) that kills an already-hung run with a
  named `patina: starvation stall` fatal and a distinct exit `111`, classified as
  `STARVATION_STALL` (a fuzz-sweep `--selftest` case); and starvation kept OPT-IN
  in the sweep (`PATINA_SWEEP_STARVE=1`) so the always-on canary never wedges.
- **Bug-depth metrics**: an active policy emits a machine-readable
  `PATINA_SCHEDULE_POLICY` stderr line (`SchedulerDriver::policy_report`) carrying
  a `bug_depth` estimate (priority-change points hit + starvation exclusions),
  which `fuzz-sweep.sh` parses into a per-generation `policy(<mode> bug_depth=N)`
  annotation extending the `life=`/`cause=` scheme. The `--selftest` covers the
  `PATINA_SCHEDULE_POLICY` field parsing and vacuous-starvation detection.

The fuzz-sweep SCHEDULE tier gains a seed-derived PCT overlay (starvation
opt-in) on the yield-points binary; the BREADTH/TRAFFIC tiers gain a seed-derived
`--swarm` overlay when ≥2 fault classes are enabled. All new `--selftest` cases
pass; the default-path canonical seed-7 fault/buggify hashes are unchanged.

## Trace oracle

A valid `.patina` bundle has:

- the supported format version;
- a root seed, decision-policy identifier, and non-empty compatibility fingerprint;
- an unbranched `main` timeline followed by uniquely named branch timelines;
- an existing earlier parent, in-range prefix sequence, and branch seed for every branch;
- contiguous event sequence numbers relative to each timeline's prefix;
- typed operation and outcome pairs within file and event-count limits.

Strict replay performs these checks in order:

1. parse and structural validation;
2. compatibility fingerprint equality;
3. operation equality at each boundary call;
4. deterministic-driver outcome equality where the driver is executed during replay;
5. no events left at finalization.

Any failure aborts replay. There is no permissive fallback and no record-on-miss behavior.

## Reproducibility matrix

Before a release, run the V2 end-to-end fixture for:

- debug and release profiles;
- the minimum supported Rust version and the repository toolchain;
- Linux and macOS when CI is available;
- seeds `0`, `1`, `u64::MAX`, and at least 100 generated seeds.

The repository runs these gates in `.github/workflows/ci.yml` as one platform matrix: stable and Rust 1.86 across Linux (x86_64 and aarch64) and macOS. Every stable/MSRV matrix row executes the WASI, native-shim, and cross-target smoke probes; Linux rows install `strace` and set `PATINA_REQUIRE_STRACE=1` so the syscall-containment pass cannot silently skip. Stable rows additionally run the `workq` testbed's full self-checking battery, and stable Linux rows run formatting, clippy, docs, runtime-feature checks, and the fuzz-sweep and campaign classifier selftests; a strict `audit` job runs RustSec advisories over the root and every testbed lockfile with no ignores; and a nightly job (cron + manual dispatch, ubuntu + macos) runs a 200-generation randomized fault-combination campaign over the `workq` testbed (including its schedule-fuzz tier). (`cargo package --workspace --locked` is the pre-publish packaging check, run deliberately as part of publish prep rather than in CI.)

A failure report must retain the command, seed, trace bundle when one exists, Patina version, Rust version, target triple, and compatibility fingerprint.

## Current boundary of confidence

Passing V0-V2 proves the CLI-to-runtime-to-driver-to-trace loop for explicit `patina_dst_runtime::Context` effects. V3 proves the entire audited Preview 1 surface with preopen policy and resource limits, within the documented semantic limitations. The native script proves a controlled slice of ordinary `std` behavior — filesystem (including directory listing and symlinks), time, sleep, entropy, stdio, threads, and UDP datagrams — and mixed C ABI calls, built through the packaged `build`/`run` path with auto-initialization and record/replay over the descriptor trace channel — for single Rust sources and whole Cargo packages (path dependencies and build scripts included), though not yet a packaged native target with a recompiled deterministic `std`. Containment is enforced from two directions: the strict import allowlist fails closed on any unknown symbol, and the Linux `strace` pass shows the probe's guest section performing zero host syscalls over the whole run. Both platforms are verified locally: macOS directly, Linux in a VM (pthread interposition on macOS; futex-level `syscall` interposition on Linux). The cross-target smoke script proves one ordinary-`std` program behaves identically under seeds, record, and replay on wasm32-wasip1, native macOS, and native Linux. Crash models, trace migration, host capture, minimization reducers, and performance budgets have focused evidence.

One record path still represents one finalized context; multi-test aggregation is unsupported. Native IPv6/DNS, non-zero TCP latency, process spawning, arbitrary FFI, dynamic loading, and full POSIX compatibility remain outside the confidence boundary (the explicit-boundary `patina-dst-async` executor and native tokio under the interposed readiness reactors are inside it).
## Gate taxonomy: point pins vs class detectors

Every validation gate in Patina is one of two kinds. A **class-level detector** is
structural: a *new, never-before-seen* bug of the same family trips it (a
default-deny audit, a single-choke-point invariant, a distinct-sentinel check, a
fail-closed reconcile contract, a per-class taxonomy sweep). A **point-level pin**
reproduces one specific past defect and would not catch a sibling variant. Point
pins are legitimate — a reproducer is cheap insurance — but a point pin that is
the *only* defense for a bug class is a latent gap: the next variant escapes.

The "detection before fixes" doctrine has kept the ratio healthy: of ~72
regression assertions in `crates/`, only 3 are true point pins, and each is
already paired with a class-level invariant. The residual risk is not in the
unit suite — it is in the handful of **structurally unpaired classes** below
(escape paths with a known-absent detector).

### Taxonomy — gates by family

| Gate | Location | Motivating bug (if known) | Kind | Class pairing / coverage limit |
|---|---|---|---|---|
| Pre-run default-deny import audit (per-format allowlist, fail-closed on `unknown-import`) | `crates/patina-target/src/lib.rs` (`native_allowlisted_import`, `native_escape_category`); enforced in `cargo-patina` `run` | macOS Parker escape (a missed interposer passed silently) | **Class** | Catches any new uninterposed blocking/time/effect symbol. Limit: flat import list only, not inlined instructions or flag-dependent behavior. |
| Per-class escape taxonomy + non-vacuity test | `patina-target` `every_escape_class_is_detected_and_denied`; e2e `native_run_prerun_gate_refuses_every_escape_class` | Escape-class rot | **Class** | One representative symbol per class must be named; a new class member trips it. |
| Instruction scan (`scan_forbidden_instructions`: aarch64 `svc`/`mrs CNTVCT`/`RNDR`, x86 `syscall`/`rdtsc`/`rdrand`) | `patina-target/src/lib.rs`; `walks_past_forbidden_bytes_embedded_in_operands`, `fails_closed_on_undecodable_bytes`, `refuses_binaries_of_undecodable_architectures` | Old byte-slide false-positive on operand-embedded bytes; silent pass on undecodable architectures | **Class** | Boundary-aware; discriminates operand bytes from real opcodes; undecodable *architectures* refuse loudly (`UnsupportedNativeArchitecture`, no escape hatch). Limit: known encodings only — `rdseed`, commpage `ldr` time reads are residual. |
| Linux whole-run `strace` containment | `scripts/validate-native-shim.sh` (Linux branch) + planted-`openat` filter selftest | Inlined raw syscall (no import) | **Class** | Whole-run default-deny; planted escape proves non-vacuity. Linux-only; `PATINA_REQUIRE_STRACE=1` (set on all Linux CI jobs, which install strace) turns the missing-tool soft-skip into a hard failure. |
| macOS whole-run containment | — | — | **NONE** | Honestly absent: `ktrace` cannot ground a sound gate. `PATINA_REQUIRE_KTRACE=1` hard-fails rather than reporting a vacuous check. Only static scan + import audit on macOS. |
| Shim host-alias object scan | `cargo-patina` `tests/shim_host_alias.rs` (`shim_objects_name_no_undeclared_host_escape` + `planted_leak_is_caught`) | Dispatch-semaphore Parker sharing the baton's `--allow` | **Class** | Scans shim's own objects for undeclared host escapes; planted leak keeps it honest. |
| Fingerprint fail-closed (`+yieldpoints`/`+buggify`/`+pct`/`+starve`/`+swarm`, reconstructed from trace) | `patina-runtime`, `patina-trace`; `native_yield_points_trace_fails_closed_against_plain_binary`, `reconcile_replay_*_enforces_the_authoritative_trace_contract` | Cross-replay of incompatible build/policy | **Class** | Any capability mismatch fails closed; `deny_unknown_fields` rejects unknown policy in older runtime. |
| Vacuous-schedule diagnostic (`PATINA_SCHEDULE_REPORT` + `PATINA WARNING`) | `patina-runtime/src/lib.rs` (`SCAFFOLDING_YIELD_FLOOR`); `vacuous_worker_that_never_yields_is_flagged` | "N seeds clean" hiding zero exploration (atomics-only window) | **Class (calibration-coupled)** | Mechanism is structural, but the floor is a tuned constant (macOS 4 / Linux 0). A std-scaffolding cost change could mis-calibrate it silently. |
| Net-fault vacuity diagnostic (`PATINA_NET_FAULT_REPORT` + `PATINA WARNING: net fault knobs inert`) | `patina-runtime/src/lib.rs` (`emit_net_fault_report`); `patina-dst-driver-api` `NetFaultReport::is_vacuous`; `patina-net-sim` `fault_report_is_vacuous_exactly_on_the_silent_inertness_signature`; e2e `native_tcp_stream_faults_are_deterministic_replayable_and_non_vacuous`; `testbeds/pubsub/fuzz-sweep.sh` `VACUOUS_NET_FAULT` selftest | `--net-jitter`/`--net-drop` silently inert on the SimNet TCP stream path (a datagram-only implementation) — "clean under faults" hiding zero perturbation (task #37) | **Class** | Fires when the knobs could perturb (nonzero drop or jitter ceiling) and fault-eligible traffic occurred yet ZERO fault effects landed. RED-proven: with the TCP fault application disabled, the runtime `faults.rs` TCP test fails AND the warning fires (`vacuous=1`). The `pubsub` gate's fault leg additionally proves non-vacuity by trace-diff (fault vs no-fault at the same seed). |
| Liveness watchdog (`PATINA_VIOLATION liveness`/`converge`; virtual-time only) | `patina-runtime` (`LIVENESS_MIN_STALL_OPS=4`, 600s budget); `liveness_watchdog_is_schedule_invariant_when_no_violation_fires` | Wedged run silently advancing vtime to budget | **Class** | Schedule-invariant (proven byte-identical op stream); non-vacuity via default-on `PATINA_LIVENESS_REPORT`. Limit: real-I/O-but-no-goal needs an app oracle. |
| Starvation stall backstop (exit 111, wall-clock, `--starve`-only) | native supervisor; fuzz-sweep `STARVATION_STALL` selftest | Uninterposed atomic spinlock livelock under adversarial deferral | **Class** | Detection backstop (not liveness guarantee); armed only under `--starve` so the always-on canary never wedges. |
| Teardown yield-point silencing | `patina-native-shim` `completed_sentinel_is_distinct_from_never_registered` + `main_returned_silences_the_root_task_scheduling_point` | `--yield-points` TLS destructor ran hook on removed task; main-thread root-task trailing yield | **Class** | Paired reproducers (`native_yield_points_survive_thread_local_teardown`, `..._main_thread_tls_teardown_is_deterministic`) are point pins; the mechanism invariants are the class pairing. |
| Yield-accounting divergence diagnostic (classified `yield-point replay divergence` + divergent guard site) | `patina-runtime` `classify_yield_divergence`; `native_yield_points_divergence_reports_accounting_and_site` | Load-dependent guard-hit count (joiner-vs-worker `Arc<thread::Inner>` teardown race, Darwin under load) surfacing as an unexplained "trace ended before operation N" | **Class** | Any `TaskYield`-adjacent replay divergence reports per-task record-vs-replay yield counts plus the instrumented site of the unmatched yield (stable `patina_yield_point`-relative offset). The known cause is removed structurally: `patina_thread_join` reaps the worker's host thread on every platform, so the joiner's drop is deterministically the last reference. |
| Fail-closed binary yield-point detection | `cargo-patina` `yield_point_detection_streams_and_fails_closed` | Yield-point trace replayed against plain binary; ENOMEM fail-open in whole-file read | **Class** | Streaming scan errors loudly on any I/O failure; cross-replay fails closed. |
| Single-choke-point CrashFs construction | `patina-runtime` `fs_image_choke_point_honors_configured_torn_granularity`; shim `native_fs_torn_granularity_byte_reaches_the_guest`, `native_fs_crash_image_is_seed_live_and_deterministic` | Shim pre-installed default-policy CrashFs, ignoring `torn_granularity` + pinning seed 0 | **Class** | Any regression reintroducing a shim-side CrashFs (bypassing fault config) trips byte≠block and seed-liveness. |
| Byte-granularity torn-write geometry | `patina-fs-crash` `byte_granularity_tears_the_final_write...` (+3 siblings) | Whole-block model can't produce sub-block tear (sub-block crash campaign) | **Class** | Property family over the tear geometry. |
| Trace op-tag stability | `patina-abi` `operation_variant_tags_are_pinned_by_name_not_declaration_order` | Variant insertion renumbering existing tags | **Class + point edge** | Class intent (name- not order-based tagging); the literal tag strings are point-ish for those variants. |
| Trace strict-replay + migration safety | `patina-trace` `rejects_fingerprint_operation_and_trailing_event_mismatches`, `migration_never_rewrites_the_source_file`, version floor/ceiling | Malformed/hostile trace, lossy migration | **Class** | Fail-closed on any structural mismatch; migration never rewrites disk. |
| Guest-argv replay | `cargo-patina` `native_replay_restores_guest_argv_and_normalizes_argv0`; wasi sibling | Real incident: divergent default argv → mid-run op mismatch | **Class** | Structural round-trip; argv[0] normalized so host path never leaks. |
| Fuzz-sweep classifier (13 classes) + planted selftest (37 cases) | `testbeds/workq/fuzz-sweep.sh` (`classify`, `assert_class`) | — | **Class** | Planted findings never downgraded; each class has a canned selftest. Selftest runs per-push in CI (stable job); full sweeps run nightly and local/manual. |
| Campaign classifier (7 classes) + selftest | `crates/cargo-patina/src/campaign.rs` (`classify`, `CampaignClass`) | — | **Class** | UNCLASSIFIED-loud on any unrecognized nonzero exit. CLI-level `--selftest` runs per-push in CI; real campaigns remain local/manual. |
| Buggify SDK classes | `testbeds/buggify-campaign.sh` (`ALWAYS_VIOLATION` per-gen top severity; `SOMETIMES_UNMET` campaign-level) + selftest | — | **Class** | `ALWAYS_VIOLATION` fires even on exit 0, never downgraded. Selftest covered by the per-push fuzz-sweep selftest; real campaigns local. |
| Cross-target byte-identity + canonical pins | `scripts/smoke-cross-target.sh` (`SMOKE_RESULT` cmp across wasi/native/record/replay + canonical `entropy_hash` literal) | Differential-only smoke let a both-targets-consistent entropy drift pass silently | **Class (differential) + canonical anchor** | Cross-target/record `cmp` catches divergence on exercised paths; the pinned literal catches consistent drift. Intentional entropy changes must update the literal deliberately. |

### Unpaired / thin-coverage classes, ranked by risk

1. **macOS inlined raw syscall (post-init) — no runtime detector.** The Linux
   `strace` gate has no macOS equivalent (documented: `ktrace` cannot ground a
   sound check). Static instruction scan misses commpage `ldr` time reads and
   novel encodings. Highest structural residual; honestly stated, not closeable
   today.
2. **Vacuous-schedule floor + `SCHEDULE_MIN_BOUNDARIES=5000` are tuned constants.**
   The detector mechanism is structural but its calibration is a magic number; a
   std thread-scaffolding cost change could produce silent false negatives. Wants
   a calibration guard that pins the measured scaffolding yield cost.
3. **macOS guest `dlsym` of a non-deny-trapped blocked symbol** (e.g. `kill`).
   Measured unreachable for any std guest, but no detector — relies on a guest not
   hand-writing `dlsym`. Low risk by measurement, unpaired in principle.
4. **`mmap(MAP_SHARED)` / instruction-level `rdseed`.** Invisible to the symbol
   audit and instruction scan; no detector.

Closed 2026-07-28 (previously ranked here): CI-absent `strace` (now installed +
`PATINA_REQUIRE_STRACE=1` on every Linux job), classifier selftests absent from
CI (fuzz-sweep + campaign selftests per-push; workq fuzz-sweep campaign nightly +
dispatch), and the missing canonical `entropy_hash` literal in the cross-target
smoke (now pinned).

### Maintenance rule

**Every new point-level regression pin must name its class-level pairing in a
comment, or be flagged in review.** A reproducer that pins one past bug is
welcome, but it must sit beside a structural invariant (choke-point, distinct
sentinel, default-deny audit, fail-closed reconcile) that a *new variant of the
same family* would also trip. A tuned constant in a detector (a yield floor, a
boundary threshold) is a calibration point-pin: it must carry a comment stating
what it is calibrated against and how a drift would surface. When a class-level
detector exists but does not run in CI, that gap is itself a tracked item — a
detector that "would fire" is only evidence if it actually executes.

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
- `cargo +1.85.0 test --workspace`
- `scripts/validate-wasi.sh` when validating V3
- `scripts/validate-native-shim.sh` when validating native foundations
- `scripts/smoke-cross-target.sh` when validating cross-target determinism

These checks must run without network access after dependencies have been fetched.

### V1: deterministic Rust-level vertical slice

This is the currently implemented acceptance level. The application explicitly enters `patina::run` and performs effects through `patina::Context`.

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
| Replay | `--replay` reproduces recorded results and consumes every event. |
| Strict matching | Changed operation kind, arguments, event sequence, trailing events, malformed format, and changed fingerprint are errors. |
| CLI transport | `cargo-patina` forwards Cargo arguments and passes mode, seed, trace path, and fingerprint through the documented environment protocol. |

Automated evidence:

- crate unit tests cover ABI serialization, each concrete driver, trace validation, runtime modes, and CLI parsing;
- `crates/cargo-patina/tests/end_to_end.rs` creates an independent fixture package and verifies seeded runs plus record/replay through separate child processes;
- the `patina` example provides a manual smoke path.

Manual smoke test from the repository root:

```sh
cargo build -p cargo-patina
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina --example deterministic --seed 123
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina --example deterministic --seed 123 --record /tmp/demo.patina
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina --example deterministic --replay /tmp/demo.patina
```

Expected:

- all three commands print the same `PATINA_RESULT` line;
- the first two use seed `123`;
- replay succeeds without contacting a host-backed effect driver;
- changing the example source before replay causes a fingerprint error.

### V2: cooperative scheduling and simulation drivers

This acceptance level is implemented at the explicit Context boundary:

- `patina-sched-det` has a scheduler known-answer test and repeats spawn/choose/park/wake/yield ordering across 1,000 seeds;
- deadlock, invalid transition, running-task, and no-task outcomes are explicit;
- `patina-net-sim` tests delivery, delay, reorder, partition, bind/route, and close state;
- `patina-wrapper-fault` tests seeded loss and duplication decisions;
- `patina-wrapper-latency` tests fixed delay, seeded jitter, and packet reorder;
- runtime record/replay crosses scheduler, clock, network, filesystem, and entropy operations;
- trace format 2 resolves parent timelines, replays an exact prefix, records a seeded suffix, and replays named branches;
- CLI end-to-end tests create and replay a branch in separate processes;
- `--budget` bounds boundary operations and fails before an operation beyond the budget;
- repeated `--param KEY=VALUE` controls fingerprinted parameters exposed through `Context::param`;
- `patina-async` drives a deterministic single-threaded futures executor over those same scheduler, network, and clock operations, and its suite asserts seed-stable and seed-varying executor polling order, exact virtual-time timer rescue and `timeout` ties, async TCP echo over `SimNet` with a real park/peer-wake ordering, async UDP echo under `LatencyNet` advancing to exact delivery deadlines, TCP backpressure, and byte-identical record/replay with strict divergence rejection — all under the workspace `cargo test`, with no new boundary operations and no dedicated validation script.

This level controls Patina's cooperative task state machine, which now also drives the `patina-async` explicit-boundary futures executor; it does not itself intercept native Rust threads or interpose third-party async runtimes such as tokio (native thread interception is validated under V4, and native async-runtime interposition remains out of scope there). The async determinism evidence is at the explicit-API level only.

### V3: WASI Patina target

**Implemented for the entire audited Preview 1 surface.** The repository provides `cargo patina build --target wasi`, fail-closed import auditing, and Wasmi execution. All 46 allowlisted imports are implemented: arguments, environment, clocks, entropy, virtual regular files/directories, hard links, symlinks, timestamp mutation, descriptor flag/rights mutation and renumbering, seek, positioned I/O, metadata with real inode/link-count identity, polling, configured connected datagrams, captured stdout/stderr, yielding, and process exit. CLI controls include fuel, arguments, environment, socket descriptors, read-only/read-write preopens (`--preopen GUEST[:ro|:rw]`), resource-limit overrides (`--max-memory-pages`, `--max-descriptors`, `--max-preopens`, `--max-path-bytes`, `--max-io-bytes`, `--max-iovecs`), record/replay, and trace branching.

Automated evidence:

- host unit tests execute guest-memory bridges, fuel exhaustion, memory-growth trapping, mount-policy enforcement, network delivery, and record/replay;
- `scripts/validate-wasi.sh` compiles real Rust `wasm32-wasip1` filesystem/time, datagram, hard-link/symlink/readlink, and set-times probes;
- fresh processes verify seed stability/variation, strict record/replay, and seeded branch suffixes;
- `cargo-patina` end-to-end tests cover preopen/limit flag plumbing, including an `EROFS` probe against a read-only preopen;
- no host directory or socket is inherited: the filesystem is `MemFs`, and datagrams require `--socket FD=BIND->PEER`;
- unsupported imports fail audit before instantiation.

Documented semantic limitations: `sock_accept`/`proc_raise` return `NOSYS` (Preview 1 has no listen surface; Patina has no signal model — Preview 1 itself has no general socket-creation API, so the supported socket surface uses configured descriptors); `MemFs` timestamps change only via explicit set-times (writes do not auto-update mtime); symlinks are inert leaf nodes (one-hop terminal follow then `ELOOP`; intermediate traversal is a deterministic `NOTCAPABLE`); unlink-while-open is denied across all names of a multi-link inode; `APPEND` set after open works through a traced seek-to-end per `fd_write`; read-only mounts are host-enforced with descriptor rights as advisory defense-in-depth; memory growth past the cap is a deterministic trap.

### V4: native Rust Patina target

**Partial macOS/Linux linked-shim foundation with packaged single-source and whole-package builds and managed threads.** `cargo patina` injects `cfg(patina)` and `cfg(dst)`. `patina-native-shim` exports a documented prefixed C ABI, while `c/patina_posix.c` provides an opt-in POSIX symbol layer. `cargo patina build <SOURCE.rs>` packages the shim build, link, and startup integration for a single Rust source (and `build <DIR|Cargo.toml>` for a whole Cargo package), and `cargo patina run <BIN>` supervises execution through the documented `PATINA_*` environment and `PATINA_TRACE_FD` descriptor; a C constructor auto-initializes from that protocol and `atexit` finalizes, so probes contain no explicit init calls and standalone execution aborts fail-closed. On macOS and Linux, `scripts/validate-native-shim.sh` uses that packaged path for ordinary Rust programs and verifies `std::fs`, filesystem metadata, `SystemTime`, `Instant`, `thread::sleep`, captured stdio, and standard-library entropy (including Darwin's CommonCrypto path) without corresponding host-effect imports. `std::thread` spawn/join and mutex/condvar contention — including a lock held across a boundary operation — run deterministically on both platforms: real host threads are gated one-at-a-time by `DetScheduler` via a per-thread OS-semaphore baton. On macOS, std lowers synchronization to the interposed pthread symbols (`pthread_create_suspended_np` + mach `thread_resume` create the managed vehicle), and std's thread `Parker` — `thread::park`/`park_timeout` and the `mpsc`/`mpmc` `recv`/`recv_timeout`, `Once`, and channel paths on it — blocks on a libdispatch semaphore, so the shim interposes `dispatch_semaphore_create`/`wait`/`signal`/`dispatch_time`/`dispatch_release` and routes the wait through the scheduler and virtual clock (the execution baton uses the *same* canonical libdispatch semaphore — matching the native primitive — reached through the shim's host-alias table, where `dlsym(RTLD_NEXT, ...)` resolves libdispatch's real entry rather than the shim's interposer, so the baton's vehicle never enters the guest import table and never recurses into any interposer; `sched_yield` is interposed to a scheduling point). Two threads communicating over `mpsc::recv_timeout` produce a byte-identical delivery/timeout schedule across repeated runs at multiple seeds and reproduce it under strict record/replay. On Linux (`-Wl,--wrap=pthread_create`), Rust `std` instead reaches `Mutex`/`Condvar`/parking through raw `SYS_futex` via libc's `syscall` wrapper, so the shim interposes `syscall`: futex waits park the caller on the futex word's address through the baton (value check and park are atomic, so no wakeup is lost), futex wakes release up to N parked tasks, and every other syscall number fails closed. `dlsym` is interposed to resolve nothing — dynamic symbol lookup can never return a host symbol. Scheduling granularity differs deterministically: macOS takes a scheduling point at every interposed lock operation, while Linux takes one at futex contention (uncontended lock operations are userspace atomics), so Linux interleaving is contention-granular; the probes assert seed stability and cross-seed variation over a seed range on both platforms. Cross-process seed stability, seed variation, byte-identical repeated record traces, strict replay, and fingerprint rejection are verified for the fully interposed probe through the supervisor-provided `PATINA_TRACE_FD` descriptor. Linux large-file/stat symbols and Rust's startup descriptor probe are handled explicitly. `dup`/`fcntl(F_DUPFD*)` duplicate deterministic file descriptors through recorded `FsDup`, sharing open-file descriptions; unsupported targeted/socket/stdio duplication fails closed with captured `patina:` diagnostics. Startup snapshots the private `PATINA_*` control plane for the shim, scrubs live environ, and leaves the guest-visible environment empty and immutable (`setenv`/`unsetenv`/`putenv` fail closed). `run` resolves the binary to an absolute path before exec and clears the child environment except for the supervisor protocol, so path-based invocations keep working while bare-name child-side `PATH` lookup is unsupported. Ordinary `std::fs::read_dir` iterates driver-ordered snapshots with deterministic synthetic inodes through the interposed dirent family; `symlink`/`read_link`/`symlink_metadata` and stat-through-symlink follow MemFs semantics (one terminal hop then `ELOOP`, `AT_SYMLINK_NOFOLLOW` honored), and the probe asserts the exact listing and symlink behavior in its deterministic output. Thread identity is deterministic (`gettid` on Linux, `pthread_threadid_np` on macOS return scheduler ids); `__res_init` still fails closed; `socket` validates its protocol argument and `setsockopt`/`getsockopt` reject non-socket descriptors.

`cargo patina audit` is a strict per-format import allowlist over Mach-O/ELF (other formats rejected): after alias normalization (`$NOCANCEL`, underscore prefixes), an import passes only if it is an explicitly listed effect-free host-deferred symbol or `--allow`ed by the caller, and anything unknown fails closed as `unknown-import` — this is what catches the missed-interposer class structurally (a `clock_nanosleep`-style escape now fails the audit instead of passing silently). Known host-effect names keep their categories (filesystem, unmanaged-sync `os_unfair_lock`/`__ulock`/`psynch`, direct-syscall, and so on) for error quality, and instruction scanning still rejects raw syscall/clock/entropy assembly. The shim's control-plane symbols are `--allow`ed per audited binary by the scripts rather than statically allowlisted, so unmanaged binaries importing them still fail; under the host-alias doctrine (ARCHITECTURE.md) the shim resolves its host vehicles at runtime through `dlsym(RTLD_NEXT, ...)`, so on macOS that set collapses to the single `dlsym` primitive (the trace-fd/baton/thread-creation vehicle names no longer appear in the guest import table at all) while Linux still names `__read`/`__write`/wrapped `pthread_create`/`sem_*` pending its VM-pass sweep; the scripts also prove the negative cases (audit without `--allow` fails, an unknown benign import fails, escape fixtures fail). `run` enforces the same audit as a **pre-run default-deny gate** before the guest executes — it bakes in the control-plane vehicle so ordinary binaries need no repeated `--allow`, and hard-errors (naming and categorizing the symbols) on any other blocking/time/scheduling/effect symbol that is neither interposed nor known-safe, so a missed interposer becomes a refusal rather than a silent escape. This is what structurally closed the macOS Parker escape: std's `Parker` and the shim's own baton both used `dispatch_semaphore_*`, so the baton's per-binary `--allow` covered the Parker too; the dispatch semaphores are interposed (hence *defined*, not imported) and the baton reaches the *real* libdispatch semaphore through the host-alias table (`dlsym(RTLD_NEXT, ...)`) rather than a named import, so no vehicle symbol sits in the guest import table for a shared allowance to cover — the collision is eliminated structurally, which is exactly why the baton can safely use the same canonical primitive std does rather than one std happens not to use. The escape hatch `--allow-unsupported-symbols <all|name,...>` downgrades matching denials to a loud warning recorded in a sidecar beside a `--record` trace (visibly qualifying the determinism claim); the native gate proves the gate can fail — a planted `os_unfair_lock` binary is refused, named, and runs only under the hatch with the warning — and that a partial allow list still fails closed.

The deny/interposed/known-safe lists are organized by an explicit escape-class taxonomy, and every class has a permanent test that proves its detection is not vacuous. The full per-class breakdown with symbol lists lives in `crates/patina-target/ESCAPE-CLASSES.md`; the coverage matrix is:

| Escape class | Detection mechanism | Fixture / test (red-before, green-after) | Residual the symbol audit cannot see |
|---|---|---|---|
| Blocking / scheduling (`os_unfair_lock`/`__ulock`/`__psynch`/dispatch/mach-sem; `poll`/`select`/`kqueue`) | import audit | `native_run_prerun_gate_refuses_every_escape_class` (`os_unfair_lock_lock`, `select`); planted-`os_unfair_lock` e2e; `recv_timeout` & `rwlock` determinism | an inlined `__ulock_wait` `svc` — Linux `strace`; **honestly absent on macOS** |
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

Two general residual classes cut across the table: **interposed-but-unsupported** symbols (e.g. `pthread_cancel`) are *defined*, so they pass the pre-run symbol gate but fail closed loudly with `ENOSYS` at call time — which is why `pthread_rwlock_*` was made a real deterministic implementation rather than left an `ENOSYS` stub; and **inlined raw instructions**, caught by the aarch64/x86 text scan for `svc`/`syscall`/`rdtsc`/`rdrand`/`RNDR`/`CNTVCT` but with the honest macOS whole-run gap above. The plain-`std` guests that legitimately run today (`std`-probe, thread-probe, `recv_timeout`, `rwlock`, and arg-reading guests like buggy-smoke) pass the gate with **zero** allowances: `__NSGetArgc`/`__NSGetArgv` are known-safe (supervisor-controlled argv) and `confstr` is interposed to a deterministic value. Interposed-and-supported surfaces never appear as imports and so are never flagged — this includes the dispatch-semaphore Parker, `sched_yield`, `confstr`, and `setsockopt`/`SO_RCVTIMEO` (whose deterministic recv deadline applies at `patina_sleep_until`, distinct from the deadlock-rescue clock path, and uses the same delivery-wins-ties tie-break as the Parker).

The gate deliberately audits the guest's **flat import list**, not a static call graph. We evaluated making it call-graph-aware — clearing a flagged import when no path from an entrypoint reaches it, so a binary that merely *links* an escape symbol without a live path need not carry an allowance — against the real ripgrep testbed (whose old allow list named 28 subprocess-spawn and host-query symbols) and rejected it: a **sound** reachability pass clears **zero** of them, so it is all cost and no benefit. Two reasons, each verified on the built `rg` (arm64 Mach-O; `otool -Iv` stub map + `objdump -d` call-graph BFS). (1) The dormant code is statically wired: ripgrep's spawn is reachable from the Rust entry by **direct calls alone** — the `bl` chain `rg::main → rg::run → SearchWorker::<W>::search → grep_cli::process::CommandReaderBuilder::build → std::process::Command::spawn → bl _fork/_posix_spawnp` — and only a *runtime* flag (`--pre`/`-z`) selects it, which static analysis cannot prove is never set. (2) Sound indirect-call handling swallows the program: any reachable indirect call may reach any address-taken function, and in a Rust binary `main` itself is address-taken (handed to `lang_start`), so the conservative closure admits the whole live call graph. The honest fix is therefore per-symbol *interposition*, not reachability: ripgrep's spawn family becomes shim **deny-traps** that abort deterministically if reached (so a genuine spawn fails loud + reproducible instead of escaping silently), its host-state queries return fixed deterministic values, its pure-compute members (`memset_pattern4/8/16`, the `sigset_t` bit ops) are known-safe, and `dlsym` is the shim's own host-alias control-plane primitive — each drops off the import table or the allow list, emptying the allowance entirely while the gate stays fail-closed for any new import. Full analysis and per-symbol disposition: `crates/patina-target/ESCAPE-CLASSES.md` ("Why symbol-reachability, not static call-graph reachability") and `testbeds/ripgrep/PATINA-RESULTS.md` ("Pre-run audit").

On Linux the script adds a whole-run `strace` containment pass: every traced file, network, clock, entropy, and descriptor syscall in the entire run must match an exact loader/std-runtime prelude shape (shared-object loads, `/proc/self/maps` stack-bounds introspection, control-plane descriptors 0-3, process-local memory/signal setup, glibc's nonblocking startup `getrandom`) — the seeded probe's guest section performs zero host syscalls, and a planted `clock_nanosleep`, host `openat`, or `socket` anywhere in the run fails the gate. vDSO time reads never enter `strace` and are covered by the libc-interposition probes. macOS has no equivalent runtime gate: calibration established that `ktrace` (the only root-capable, SIP-compatible whole-run tracer) cannot found a sound default-deny check, so the macOS path skips loudly and leaves static instruction scanning plus import audit as the macOS containment evidence — and `PATINA_REQUIRE_KTRACE=1` hard-fails on Darwin rather than reporting a check that cannot fail. Three independent blockers, each reproduced on-host: `ktrace` BSD-syscall (`BSC_*`) events carry only raw register values, not decoded paths, so a guest's raw `open`/`stat` is indistinguishable by argument from the loader's libSystem prelude; the deterministic runtime buffers all guest output (stdout and stderr) into a single flush at process exit, so there is no in-band "first write to stdout" boundary to separate the pre-main loader prelude from guest code (an early unbuffered stderr marker is observed emitted only at the end of the trace); and the loader/runtime legitimately issues the same syscall names an escape would (`open`, `stat64`, `fcntl`, `getpid`, ...) while its init interleaves with early guest execution, so a name-scoped default-deny is either vacuous or false-positives on every clean run — a planted post-init raw `getpid` (inline `svc`) lands among the runtime's own `getpid` events, name-identical and not temporally separable. Mach traps are outside the BSD syscall class and remain the scheduler-baton scope analogue of Linux futex allowances. The strace path allowances are shape-based (they audit our probes, not adversarial binaries).

`scripts/smoke-cross-target.sh` builds one ordinary-`std` smoke program for wasm32-wasip1 and the native host, runs seeded smoke tests with recorded and replayable traces on both, and requires the deterministic program output to be byte-identical across targets.

Native UDP datagrams and zero-latency TCP streams run over `SimNet` through ordinary `std::net`: sockets are fully virtual (the probe binaries carry zero network host imports), blocking receives/accepts/writes park through the deterministic scheduler, latency/fault wrappers forward TCP operations, deterministic no-op socket options such as `TCP_NODELAY` are allow-listed, and the script verifies seed-stable/seed-varying multi-thread datagram ordering plus byte-identical TCP record/replay on both platforms (`NATIVE_TCP_RESULT`). Timed waits are deterministic through the virtual-clock timer queue: `Condvar::wait_timeout` (pthread cond on macOS, futex timeouts on Linux) returns timed-out exactly at its virtual deadline when unsignalled and 0 when signalled first, `thread::sleep` in a multi-thread program yields to runnable tasks and advances virtual time only when nothing else can run, and a blocking UDP receive under `cargo patina run --net-latency-nanos N` parks until the virtual clock reaches send-time-plus-latency — the script's timer gates assert the exact virtual elapsed values, seed stability, and byte-identical record/replay for all three. TCP IPv6 and DNS paths fail closed with explicit errors, process-state reads return deterministic constants, and process spawning stays denied by the audit. On Linux, the one `pthread_create` import that `-Wl,--wrap` leaves behind is the shim's own managed host-thread vehicle and is explicitly allowlisted for packaged binaries. `build` also builds whole Cargo packages: it drives the package's own `cargo build`, injecting the cfgs and shim link arguments through `CARGO_ENCODED_RUSTFLAGS` while an explicit host `--target` isolates them to the final binary (rlib compiles ignore link arguments; build scripts and proc macros link for the host without the flags). The script's package gate builds an ordinary-`std` package with a path dependency and a build script, then audits, runs, and record/replays the product exactly like a single-source binary — the build-script env and the dependency's output appear in the deterministic result — and confirms multi-binary ambiguity without `--bin` and an off-allowlist binary both fail closed. All gates run locally on macOS and in a Linux VM. This is not yet a packaged custom Rust target: the guest is compiled with the stock host target and prebuilt `std`, not a recompiled deterministic `std`.

Required before claiming general native `std` control:

- native async-runtime interposition (a shim-level readiness reactor for tokio/async-std) and non-zero TCP latency over `SimNet` — the explicit-boundary `patina-async` executor is already validated under V2;
- cross-machine stress and a usable macOS whole-run syscall trace if a future `ktrace`/OS version exposes enough path context for a default-deny gate;
- deterministic stress across fresh processes and machines.

### V5: native ABI shim and production-hardening

**Partial.** Implemented foundations include:

- trace file/event limits and hostile structural-input rejection;
- trace schema migration: supported prior formats (v1, v2, and v3) migrate losslessly in memory on load, with fixtures for prior, unsupported (0/99), malformed, and noncontiguous inputs (per prior version) covering migrate/validate/replay; bundles are never rewritten on disk and only the current format version is written;
- compact trace byte encoding (format 3): compact JSON with base64 byte payloads replaces pretty-printed number arrays, dropping the representative workload from ~344 to ~124 bytes/event under the `patina-bench` gate; the tolerant reader still accepts the legacy number-array form so v1/v2 bundles migrate without a per-payload rewrite, and the file remains valid JSON for `jq`/`python3 -m json.tool`;
- self-contained fault replay (format 4): a record run captures its full fault configuration (crash point + torn granularity, sleep/net jitter, drop, base net latency) into the trace metadata, so a replay reproduces the faults with no knobs re-supplied; the stored config is authoritative, conflicting explicit knobs fail closed before any driver is built, and a pre-format-4 trace (no such metadata) keeps the historical re-supply contract — covered by `patina-runtime` reconcile unit tests, flag-free record/replay round-trips (including a byte-granularity torn image), and the v3→v4 migration fixture. The native `replay` subcommand exposes no fault knobs at all and refuses one up front, naming the flag;
- failure-oracle delta debugging for unbranched main timelines, leaf branch suffixes, and non-leaf branch trees (inherited prefix protected, suffix reducible), exposed by `cargo patina minimize` through isolated candidate files and `PATINA_MINIMIZE_TRACE`, plus scenario/parameter reducers and bounded ascending seed canonicalization;
- schedule reducers: `reduce_schedule` canonicalizes recorded `SchedulerNext` outcomes (switch collapsing toward longer per-task runs, lowest-task-id-first at switch points) under the same failure oracle, never rewriting a protected inherited prefix; the combined entry points and `cargo patina minimize` run pruning, suffix shrinking, and schedule reduction to a joint fixed point;
- `CrashFs` whole-image checkpoints, synchronized durability, crash rollback, stale-handle rejection, and cross-trace replay tests, with seeded torn writes (configurable granularity/probability against the durable baseline), sub-block byte-granularity tearing of the final unsynced write (a partial page that differs from both the durable and fully-applied images, exercised over positional `write_at`), rename atomicity on/off, directory-fsync durability, and crash/restart recomputation — evidenced by the `patina-fs-crash` unit suite and a runtime record/replay torn-write test;
- read-only allowlisted `HostCaptureFs`, symlink/traversal containment, replay without host access, and failure on branch capture miss;
- mixed Rust/C symbol tests for the documented prefixed ABI and POSIX filesystem shim;
- bounded multi-process seed campaigns through `cargo patina explore`;
- performance budgets in `crates/patina-bench` (`cargo run -p patina-bench --release`): a hard trace bytes-per-event ceiling and structural gates (one event per boundary operation, linear trace growth) run in `cargo test`; generous wall-clock ceilings are `#[ignore]`d opt-ins for quiet machines.

Required before claiming broad libc/POSIX compatibility or stable traces:

- broader libc network/process symbol *coverage* (modeling more behavior): the remaining items are either a documented non-goal (process/spawn symbols, which the audit rejects) or tracked in Slice 4 (async reactor, non-zero TCP latency). Unsupported-symbol *diagnostics* are complete — the strict audit default-denies any unmodeled import as `unknown-import`, interposed-but-unsupported operations fail closed at runtime through `patina_posix_deny` (ENOSYS plus a loud `patina: … failing closed` line), and the `unknown_import_probe` gate proves the rejection fires.

`CrashFs` modeling simplifications stated honestly: directory renames are always atomic (no subtree tearing); directory-durability loss covers explicitly created entries, not implicitly created parents; defaults preserve the prior conservative behavior (4096-byte granularity, torn probability 1.0, atomic renames, directory durability off).

### V6: cooperative-SUT SDK

**Partial (Milestone A).** The `patina` crate ships a FoundationDB-`BUGGIFY`- and Antithesis-style SDK under a feature inversion: default features are the dependency-light SDK, and the explicit facade (`run`/`run_with`, `Context`, `rt`) is behind the `runtime` feature. Every SDK macro (`buggify!`, `buggify_with_prob!`, `buggify_delay!`, `buggify_knob!`, `always!`, `sometimes!`, `reachable!`, `lifecycle::event!`) plus `is_simulated()`/`rng()` is a no-op or plain fallback outside a Patina build, and no `cfg(patina)` appears in adopter code.

Automated evidence:

- `patina-runtime` unit tests cover activation as a deterministic function of seed and label (with the ~25% realized fraction), firing-PRF determinism and seed variation, the damage-control cutoff, duplicate-label detection, knob determinism and range, the disabled/inert path, `rng()` determinism, the trace-metadata reconcile contract, and byte-identical record/replay of buggify decisions without re-supplying flags;
- `patina-trace` covers the additive `buggify` metadata round-trip and its absence from a buggify-free trace, and the additive `guest_argv` metadata round-trip (including the empty-list-vs-absent distinction so a zero-argument run stays distinguishable from a pre-argv trace);
- guest-argv replay is proven end to end (`native_replay_restores_guest_argv_and_normalizes_argv0`): a run recorded with non-default `-- ARGS` is reproduced byte-identically by a bare `cargo patina replay <bin> <trace>`, a mismatched `--` section is refused up front naming both argv lists, an old trace without the field still replays with explicit arguments, and `argv[0]` is pinned to the normalized `patina-guest` (the host binary path never leaks into the guest);
- the `patina` crate's own tests, built WITHOUT `cfg(patina)`, prove every macro is inert (a consumer's plain `cargo build` behavior);
- `cargo-patina` end-to-end tests build a whole package depending on the SDK, run it under `run --buggify`, assert the `PATINA_SDK_REPORT` line and nonzero firings, replay a recorded trace byte-identically without re-supplying `--buggify`, and prove a duplicate label aborts with the `PATINA_BUGGIFY_DUPLICATE_LABEL` marker;
- the flag-off invariance is verified on the raft testbed: a rebuilt harness (now compiled with the internal `--cfg patina_shim`) reproduces the seed-7 `applied_hash` `bbb54b74e959aa0e91aa75728055911b40f44f529e5d4e3b9477bebc7e00caf4` with buggify disabled, so the SDK is zero behavior change when off.

Determinism and fail-closed guarantees: buggify decisions are pure functions of the seed and site label and are never recorded per evaluation (no trace bloat); the realized config, active-site set, and knob picks are recorded in the trace metadata and are authoritative on replay (conflicting replay knobs fail closed like the fault knobs); enabling buggify folds a `+buggify` fingerprint component, reconstructed at replay from the trace, so a buggify trace never cross-replays with a non-buggify build.

Lifecycle gating is causal through the runner: `run --buggify-after-setup` declares that the guest calls `setup_complete()`, so buggify stays inert until that call, and a declared-but-never-called run fails loudly (`PATINA_BUGGIFY_SETUP_NEVER_CALLED` + abort) after recording its trace — verified by a `cargo-patina` end-to-end test. Without the flag, buggify is armed from the start and `setup_complete()` is a boundary/coverage marker.

Honest limitation: sites register lazily at first evaluation, so a never-reached site is invisible to a single run's `PATINA_SDK_REPORT` (the campaign layer accumulates coverage across generations).

The campaign layer (`testbeds/buggify-campaign.sh`) adds two classes on top of the existing sweep classifier without changing any existing gate priority: `ALWAYS_VIOLATION` (per-gen, top severity, fires even on exit 0, never downgraded) and `SOMETIMES_UNMET` (campaign-level: a `sometimes!` site reached but never satisfied fails the campaign). Both are proven fireable — plus a not-downgraded check — by a selftest wired into `raft-harness/fuzz-sweep.sh --selftest`, and the sweep runs clean end to end (the buggify accumulation is inert for the buggify-free raft harness). A vendored, clearly-marked `redb` 4.1.0 fork (`testbeds/redb-fork`) carries real cooperative-SUT sites in its commit/recovery paths (forced 2-phase/quick-repair commits, a delay before the durability flush, two-phase/full-repair/torn-slot coverage oracles, and a quick-repair⇒2-phase invariant); a plain `cargo build` of the fork behaves exactly like upstream redb. A 350-generation dogfood campaign (`testbeds/redb-harness/buggify-sweep.sh`, fresh `out-buggify/`) exercised thousands of commit-path faults with every invariant holding and zero durability violations, and correctly reported one `SOMETIMES_UNMET` coverage gap (torn committed-slot rejection was never produced by the harness's crash geometry — a wide probe confirmed redb's two-slot commit design keeps the committed slot intact, torn data surfacing as fail-closed `OPEN_ERR`).

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

The repository runs these gates in `.github/workflows/ci.yml` on stable Linux, Rust 1.85, and stable macOS. Stable Linux executes the WASI, native-shim, and cross-target smoke probes; macOS executes the native-shim, ordinary-`std` interposition, and cross-target smoke probes.

A failure report must retain the command, seed, trace bundle when one exists, Patina version, Rust version, target triple, and compatibility fingerprint.

## Current boundary of confidence

Passing V0-V2 proves the CLI-to-runtime-to-driver-to-trace loop for explicit `patina::Context` effects. V3 proves the entire audited Preview 1 surface with preopen policy and resource limits, within the documented semantic limitations. The native script proves a controlled slice of ordinary `std` behavior — filesystem (including directory listing and symlinks), time, sleep, entropy, stdio, threads, and UDP datagrams — and mixed C ABI calls, built through the packaged `build`/`run` path with auto-initialization and record/replay over the descriptor trace channel — for single Rust sources and whole Cargo packages (path dependencies and build scripts included), though not yet a packaged native target with a recompiled deterministic `std`. Containment is enforced from two directions: the strict import allowlist fails closed on any unknown symbol, and the Linux `strace` pass shows the probe's guest section performing zero host syscalls over the whole run. Both platforms are verified locally: macOS directly, Linux in a VM (pthread interposition on macOS; futex-level `syscall` interposition on Linux). The cross-target smoke script proves one ordinary-`std` program behaves identically under seeds, record, and replay on wasm32-wasip1, native macOS, and native Linux. Crash models, trace migration, host capture, minimization reducers, and performance budgets have focused evidence.

One record path still represents one finalized context; multi-test aggregation is unsupported. Native async-runtime interposition, native TCP/IPv6/DNS, process spawning, arbitrary FFI, dynamic loading, and full POSIX compatibility remain outside the confidence boundary (the explicit-boundary `patina-async` executor is inside it, under V2).

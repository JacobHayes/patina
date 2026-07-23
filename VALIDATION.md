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
| Alias | `cargo-dst` runs the same entry point and argument parser as `cargo-patina`. |

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

**Implemented for the entire audited Preview 1 surface.** The repository provides `cargo patina wasi-build`, fail-closed import auditing, and Wasmi execution. All 46 allowlisted imports are implemented: arguments, environment, clocks, entropy, virtual regular files/directories, hard links, symlinks, timestamp mutation, descriptor flag/rights mutation and renumbering, seek, positioned I/O, metadata with real inode/link-count identity, polling, configured connected datagrams, captured stdout/stderr, yielding, and process exit. CLI controls include fuel, arguments, environment, socket descriptors, read-only/read-write preopens (`--preopen GUEST[:ro|:rw]`), resource-limit overrides (`--max-memory-pages`, `--max-descriptors`, `--max-preopens`, `--max-path-bytes`, `--max-io-bytes`, `--max-iovecs`), record/replay, and trace branching.

Automated evidence:

- host unit tests execute guest-memory bridges, fuel exhaustion, memory-growth trapping, mount-policy enforcement, network delivery, and record/replay;
- `scripts/validate-wasi.sh` compiles real Rust `wasm32-wasip1` filesystem/time, datagram, hard-link/symlink/readlink, and set-times probes;
- fresh processes verify seed stability/variation, strict record/replay, and seeded branch suffixes;
- `cargo-patina` end-to-end tests cover preopen/limit flag plumbing, including an `EROFS` probe against a read-only preopen;
- no host directory or socket is inherited: the filesystem is `MemFs`, and datagrams require `--socket FD=BIND->PEER`;
- unsupported imports fail audit before instantiation.

Documented semantic limitations: `sock_accept`/`proc_raise` return `NOSYS` (Preview 1 has no listen surface; Patina has no signal model — Preview 1 itself has no general socket-creation API, so the supported socket surface uses configured descriptors); `MemFs` timestamps change only via explicit set-times (writes do not auto-update mtime); symlinks are inert leaf nodes (one-hop terminal follow then `ELOOP`; intermediate traversal is a deterministic `NOTCAPABLE`); unlink-while-open is denied across all names of a multi-link inode; `APPEND` set after open works through a traced seek-to-end per `fd_write`; read-only mounts are host-enforced with descriptor rights as advisory defense-in-depth; memory growth past the cap is a deterministic trap.

### V4: native Rust Patina target

**Partial macOS/Linux linked-shim foundation with packaged single-source and whole-package builds and managed threads.** `cargo patina` injects `cfg(patina)` and `cfg(dst)`. `patina-native-shim` exports a documented prefixed C ABI, while `c/patina_posix.c` provides an opt-in POSIX symbol layer. `cargo patina native-build <SOURCE.rs>` packages the shim build, link, and startup integration for a single Rust source (and `native-build <DIR|Cargo.toml>` for a whole Cargo package), and `cargo patina native-run <BIN>` supervises execution through the documented `PATINA_*` environment and `PATINA_TRACE_FD` descriptor; a C constructor auto-initializes from that protocol and `atexit` finalizes, so probes contain no explicit init calls and standalone execution aborts fail-closed. On macOS and Linux, `scripts/validate-native-shim.sh` uses that packaged path for ordinary Rust programs and verifies `std::fs`, filesystem metadata, `SystemTime`, `Instant`, `thread::sleep`, captured stdio, and standard-library entropy (including Darwin's CommonCrypto path) without corresponding host-effect imports. `std::thread` spawn/join and mutex/condvar contention — including a lock held across a boundary operation — run deterministically on both platforms: real host threads are gated one-at-a-time by `DetScheduler` via a per-thread OS-semaphore baton. On macOS, std lowers synchronization to the interposed pthread symbols (`pthread_create_suspended_np` + mach `thread_resume` create the managed vehicle). On Linux (`-Wl,--wrap=pthread_create`), Rust `std` instead reaches `Mutex`/`Condvar`/parking through raw `SYS_futex` via libc's `syscall` wrapper, so the shim interposes `syscall`: futex waits park the caller on the futex word's address through the baton (value check and park are atomic, so no wakeup is lost), futex wakes release up to N parked tasks, and every other syscall number fails closed. `dlsym` is interposed to resolve nothing — dynamic symbol lookup can never return a host symbol. Scheduling granularity differs deterministically: macOS takes a scheduling point at every interposed lock operation, while Linux takes one at futex contention (uncontended lock operations are userspace atomics), so Linux interleaving is contention-granular; the probes assert seed stability and cross-seed variation over a seed range on both platforms. Cross-process seed stability, seed variation, byte-identical repeated record traces, strict replay, and fingerprint rejection are verified for the fully interposed probe through the supervisor-provided `PATINA_TRACE_FD` descriptor. Linux large-file/stat symbols and Rust's startup descriptor probe are handled explicitly. `dup`/`fcntl(F_DUPFD*)` duplicate deterministic file descriptors through recorded `FsDup`, sharing open-file descriptions; unsupported targeted/socket/stdio duplication fails closed with captured `patina:` diagnostics. Startup snapshots the private `PATINA_*` control plane for the shim, scrubs live environ, and leaves the guest-visible environment empty and immutable (`setenv`/`unsetenv`/`putenv` fail closed). `native-run` resolves the binary to an absolute path before exec and clears the child environment except for the supervisor protocol, so path-based invocations keep working while bare-name child-side `PATH` lookup is unsupported. Ordinary `std::fs::read_dir` iterates driver-ordered snapshots with deterministic synthetic inodes through the interposed dirent family; `symlink`/`read_link`/`symlink_metadata` and stat-through-symlink follow MemFs semantics (one terminal hop then `ELOOP`, `AT_SYMLINK_NOFOLLOW` honored), and the probe asserts the exact listing and symlink behavior in its deterministic output. Thread identity is deterministic (`gettid` on Linux, `pthread_threadid_np` on macOS return scheduler ids); `__res_init` still fails closed; `socket` validates its protocol argument and `setsockopt`/`getsockopt` reject non-socket descriptors.

`cargo patina native-audit` is a strict per-format import allowlist over Mach-O/ELF (other formats rejected): after alias normalization (`$NOCANCEL`, underscore prefixes), an import passes only if it is an explicitly listed effect-free host-deferred symbol or `--allow`ed by the caller, and anything unknown fails closed as `unknown-import` — this is what catches the missed-interposer class structurally (a `clock_nanosleep`-style escape now fails the audit instead of passing silently). Known host-effect names keep their categories (filesystem, unmanaged-sync `os_unfair_lock`/`__ulock`/`psynch`, direct-syscall, and so on) for error quality, and instruction scanning still rejects raw syscall/clock/entropy assembly. The shim's control-plane symbols (trace-fd aliases; macOS `pthread_create_suspended_np`/`thread_resume`/dispatch-semaphore batons; Linux `__real_pthread_create`/`sem_*` batons) are `--allow`ed per audited binary by the scripts rather than statically allowlisted, so unmanaged binaries importing them still fail; the scripts also prove the negative cases (audit without `--allow` fails, an unknown benign import fails, escape fixtures fail).

On Linux the script adds a whole-run `strace` containment pass: every traced file, network, clock, entropy, and descriptor syscall in the entire run must match an exact loader/std-runtime prelude shape (shared-object loads, `/proc/self/maps` stack-bounds introspection, control-plane descriptors 0-3, process-local memory/signal setup, glibc's nonblocking startup `getrandom`) — the seeded probe's guest section performs zero host syscalls, and a planted `clock_nanosleep`, host `openat`, or `socket` anywhere in the run fails the gate. vDSO time reads never enter `strace` and are covered by the libc-interposition probes. macOS has no equivalent runtime gate: calibration established that `ktrace` (the only root-capable, SIP-compatible whole-run tracer) cannot found a sound default-deny check, so the macOS path skips loudly and leaves static instruction scanning plus import audit as the macOS containment evidence — and `PATINA_REQUIRE_KTRACE=1` hard-fails on Darwin rather than reporting a check that cannot fail. Three independent blockers, each reproduced on-host: `ktrace` BSD-syscall (`BSC_*`) events carry only raw register values, not decoded paths, so a guest's raw `open`/`stat` is indistinguishable by argument from the loader's libSystem prelude; the deterministic runtime buffers all guest output (stdout and stderr) into a single flush at process exit, so there is no in-band "first write to stdout" boundary to separate the pre-main loader prelude from guest code (an early unbuffered stderr marker is observed emitted only at the end of the trace); and the loader/runtime legitimately issues the same syscall names an escape would (`open`, `stat64`, `fcntl`, `getpid`, ...) while its init interleaves with early guest execution, so a name-scoped default-deny is either vacuous or false-positives on every clean run — a planted post-init raw `getpid` (inline `svc`) lands among the runtime's own `getpid` events, name-identical and not temporally separable. Mach traps are outside the BSD syscall class and remain the scheduler-baton scope analogue of Linux futex allowances. The strace path allowances are shape-based (they audit our probes, not adversarial binaries).

`scripts/smoke-cross-target.sh` builds one ordinary-`std` smoke program for wasm32-wasip1 and the native host, runs seeded smoke tests with recorded and replayable traces on both, and requires the deterministic program output to be byte-identical across targets.

Native UDP datagrams and zero-latency TCP streams run over `SimNet` through ordinary `std::net`: sockets are fully virtual (the probe binaries carry zero network host imports), blocking receives/accepts/writes park through the deterministic scheduler, latency/fault wrappers forward TCP operations, deterministic no-op socket options such as `TCP_NODELAY` are allow-listed, and the script verifies seed-stable/seed-varying multi-thread datagram ordering plus byte-identical TCP record/replay on both platforms (`NATIVE_TCP_RESULT`). Timed waits are deterministic through the virtual-clock timer queue: `Condvar::wait_timeout` (pthread cond on macOS, futex timeouts on Linux) returns timed-out exactly at its virtual deadline when unsignalled and 0 when signalled first, `thread::sleep` in a multi-thread program yields to runnable tasks and advances virtual time only when nothing else can run, and a blocking UDP receive under `cargo patina native-run --net-latency-nanos N` parks until the virtual clock reaches send-time-plus-latency — the script's timer gates assert the exact virtual elapsed values, seed stability, and byte-identical record/replay for all three. TCP IPv6 and DNS paths fail closed with explicit errors, process-state reads return deterministic constants, and process spawning stays denied by the audit. On Linux, the one `pthread_create` import that `-Wl,--wrap` leaves behind is the shim's own managed host-thread vehicle and is explicitly allowlisted for packaged binaries. `native-build` also builds whole Cargo packages: it drives the package's own `cargo build`, injecting the cfgs and shim link arguments through `CARGO_ENCODED_RUSTFLAGS` while an explicit host `--target` isolates them to the final binary (rlib compiles ignore link arguments; build scripts and proc macros link for the host without the flags). The script's package gate builds an ordinary-`std` package with a path dependency and a build script, then audits, runs, and record/replays the product exactly like a single-source binary — the build-script env and the dependency's output appear in the deterministic result — and confirms multi-binary ambiguity without `--bin` and an off-allowlist binary both fail closed. All gates run locally on macOS and in a Linux VM. This is not yet a packaged custom Rust target: the guest is compiled with the stock host target and prebuilt `std`, not a recompiled deterministic `std`.

Required before claiming general native `std` control:

- native async-runtime interposition (a shim-level readiness reactor for tokio/async-std) and non-zero TCP latency over `SimNet` — the explicit-boundary `patina-async` executor is already validated under V2;
- cross-machine stress and a usable macOS whole-run syscall trace if a future `ktrace`/OS version exposes enough path context for a default-deny gate;
- deterministic stress across fresh processes and machines.

### V5: native ABI shim and production-hardening

**Partial.** Implemented foundations include:

- trace file/event limits and hostile structural-input rejection;
- trace schema migration: supported prior formats (v1 and v2) migrate losslessly in memory on load, with fixtures for prior, unsupported (0/99), malformed, and noncontiguous inputs (per prior version) covering migrate/validate/replay; bundles are never rewritten on disk and only the current format version is written;
- compact trace byte encoding (format 3): compact JSON with base64 byte payloads replaces pretty-printed number arrays, dropping the representative workload from ~344 to ~124 bytes/event under the `patina-bench` gate; the tolerant reader still accepts the legacy number-array form so v1/v2 bundles migrate without a per-payload rewrite, and the file remains valid JSON for `jq`/`python3 -m json.tool`;
- failure-oracle delta debugging for unbranched main timelines, leaf branch suffixes, and non-leaf branch trees (inherited prefix protected, suffix reducible), exposed by `cargo patina minimize` through isolated candidate files and `PATINA_MINIMIZE_TRACE`, plus scenario/parameter reducers and bounded ascending seed canonicalization;
- schedule reducers: `reduce_schedule` canonicalizes recorded `SchedulerNext` outcomes (switch collapsing toward longer per-task runs, lowest-task-id-first at switch points) under the same failure oracle, never rewriting a protected inherited prefix; the combined entry points and `cargo patina minimize` run pruning, suffix shrinking, and schedule reduction to a joint fixed point;
- `CrashFs` whole-image checkpoints, synchronized durability, crash rollback, stale-handle rejection, and cross-trace replay tests, with seeded torn writes (configurable granularity/probability against the durable baseline), rename atomicity on/off, directory-fsync durability, and crash/restart recomputation — evidenced by the `patina-fs-crash` unit suite and a runtime record/replay torn-write test;
- read-only allowlisted `HostCaptureFs`, symlink/traversal containment, replay without host access, and failure on branch capture miss;
- mixed Rust/C symbol tests for the documented prefixed ABI and POSIX filesystem shim;
- bounded multi-process seed campaigns through `cargo patina explore`;
- performance budgets in `crates/patina-bench` (`cargo run -p patina-bench --release`): a hard trace bytes-per-event ceiling and structural gates (one event per boundary operation, linear trace growth) run in `cargo test`; generous wall-clock ceilings are `#[ignore]`d opt-ins for quiet machines.

Required before claiming broad libc/POSIX compatibility or stable traces:

- broader libc network/process symbol *coverage* (modeling more behavior): the remaining items are either a documented non-goal (process/spawn symbols, which the audit rejects) or tracked in Slice 4 (async reactor, non-zero TCP latency). Unsupported-symbol *diagnostics* are complete — the strict native-audit default-denies any unmodeled import as `unknown-import`, interposed-but-unsupported operations fail closed at runtime through `patina_posix_deny` (ENOSYS plus a loud `patina: … failing closed` line), and the `unknown_import_probe` gate proves the rejection fires.

`CrashFs` modeling simplifications stated honestly: directory renames are always atomic (no subtree tearing); directory-durability loss covers explicitly created entries, not implicitly created parents; defaults preserve the prior conservative behavior (4096-byte granularity, torn probability 1.0, atomic renames, directory durability off).

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

Passing V0-V2 proves the CLI-to-runtime-to-driver-to-trace loop for explicit `patina::Context` effects. V3 proves the entire audited Preview 1 surface with preopen policy and resource limits, within the documented semantic limitations. The native script proves a controlled slice of ordinary `std` behavior — filesystem (including directory listing and symlinks), time, sleep, entropy, stdio, threads, and UDP datagrams — and mixed C ABI calls, built through the packaged `native-build`/`native-run` path with auto-initialization and record/replay over the descriptor trace channel — for single Rust sources and whole Cargo packages (path dependencies and build scripts included), though not yet a packaged native target with a recompiled deterministic `std`. Containment is enforced from two directions: the strict import allowlist fails closed on any unknown symbol, and the Linux `strace` pass shows the probe's guest section performing zero host syscalls over the whole run. Both platforms are verified locally: macOS directly, Linux in a VM (pthread interposition on macOS; futex-level `syscall` interposition on Linux). The cross-target smoke script proves one ordinary-`std` program behaves identically under seeds, record, and replay on wasm32-wasip1, native macOS, and native Linux. Crash models, trace migration, host capture, minimization reducers, and performance budgets have focused evidence.

One record path still represents one finalized context; multi-test aggregation is unsupported. Native async-runtime interposition, native TCP/IPv6/DNS, process spawning, arbitrary FFI, dynamic loading, and full POSIX compatibility remain outside the confidence boundary (the explicit-boundary `patina-async` executor is inside it, under V2).

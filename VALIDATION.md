# Patina Validation

This document defines how an implementation of Patina is tested and what evidence is required before a capability is described as working. The checks are layered so the current Rust-level vertical slice can be verified without implying that the eventual deterministic target boundary already exists.

Lookup map — the capability levels and the cross-cutting sections:

| Section | Scope | Status |
|---|---|---|
| [V0](#v0-workspace-quality) | workspace quality gates (fmt/clippy/tests/docs/MSRV + validation scripts) | standing |
| [V1](#v1-deterministic-rust-level-vertical-slice) | deterministic vertical slice at the explicit `Context` boundary | complete |
| [V2](#v2-cooperative-scheduling-and-simulation-drivers) | cooperative scheduling, SimNet, wrappers, branching, async executor | complete |
| [V3](#v3-wasi-patina-target) | WASI Preview 1 target | complete (entire audited surface) |
| [V4](#v4-native-rust-patina-target) | native linked-shim target (interposition, audit gate, SUD) | partial |
| [V5](#v5-native-abi-shim-and-production-hardening) | trace hardening, crash models, capture, minimization, budgets | partial |
| [V6](#v6-cooperative-sut-sdk) | cooperative-SUT (buggify) SDK, native + WASI | partial (Milestone C) |
| [V7](#v7-exploration-tier-directed-schedulefault-steering) | directed exploration policies (PCT, swarm, starvation) | partial (wave 12) |
| [Trace oracle](#trace-oracle) | what a valid `.patina` bundle must satisfy; strict-replay check order | — |
| [Reproducibility matrix](#reproducibility-matrix) | pre-release matrix and what CI actually runs | — |
| [Current boundary of confidence](#current-boundary-of-confidence) | the honest summary of what is and is not proven | — |
| [Gate taxonomy](#gate-taxonomy-point-pins-vs-class-detectors) | class detectors vs point pins, unpaired classes, maintenance rule | — |

## Validation principles

1. **Test observable contracts, not implementation details.** Seeds, traces, replay failures, virtual effects, and CLI behavior are public contracts.
2. **Make nondeterminism failures visible.** A missing driver, malformed trace, incompatible fingerprint, mismatched operation, or unconsumed replay event must fail the run.
3. **Use independent repetitions.** Reproducibility means separate processes produce the same result, not merely that one object can be queried twice.
4. **Keep replay stricter than seed reruns.** Replay verifies the exact ordered boundary-operation stream and rejects compatibility mismatches.
5. **Do not overstate boundary coverage.** Until custom targets and shims are validated, tests using `std` directly are host operations and are outside Patina's deterministic boundary.

## Capability levels

A level is complete only when all its required checks pass. Higher levels do not weaken lower-level checks.

### V0: workspace quality

Required locally before landing (`mise run check`):

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings` (plus the same run with
  `--target x86_64-unknown-linux-gnu`, `--target aarch64-unknown-linux-gnu` and
  `--target aarch64-apple-darwin`, so Linux-cfg, per-architecture and Darwin-cfg
  code lint from any host)
- `cargo doc --workspace --no-deps`
- `cargo test --workspace` on the stable toolchain, including the
  `cargo-patina` `end_to_end` integration-test binary
- `scripts/check-flag-drift.sh` (CLI flag drift gate over the user-facing docs and every shell script)
- packaging (`cargo package --workspace --no-verify`) so manifest/readme/include
  drift fails before release work
- local MSRV compatibility: `cargo +1.86.0 check --workspace --all-targets`, the
  `cargo-patina` self-sufficient-binary rodata detector, and the `patina-dst`
  macros feature test
- `scripts/validate-wasi.sh` when validating V3
- `mise run check:native-abi` for focused native ABI feedback; the full native acceptance tests and ecosystem testbeds are included in `mise run check`
- `scripts/smoke-cross-target.sh` when validating cross-target determinism
- the workq/pubsub/macro-adopter and FIFO/rustix-default/cap-std testbeds; the
  syscall conformance scenarios run with the native acceptance tests

`mise run check:fast` is the inner loop: fmt, the four clippy passes, every workspace
test except cargo-patina's e2e/native execution targets (conformance among them),
the cheap selftests, CLI flag drift, MSRV `cargo check`, WASI validation, and
cross-target smoke. It is intentionally not landing evidence.

`mise run msrv` executes the complete Rust 1.86 workspace suite and the macros
feature test. That full MSRV suite is CI/final-gate evidence rather than part of
the ordinary local landing gate; the local gate covers the measured MSRV-only
classes seen so far (compile compatibility, the self-sufficient-binary rodata
detector, and the macros feature surface).

These checks must run without network access after dependencies have been
fetched. For local development, `mise run setup` installs the Rust
toolchains/targets needed by these gates. After cheap failure checks, the full
local gate runs the e2e-heavy stable workspace test rung alone, then overlaps
runtime/testbed rungs with independent scratch/output paths. Successful rung logs
are retained with commands and timings; the console shows one overall result
and the log directory, plus a failed rung's complete log.
`scripts/check.sh --selftest` is the output-contract class detector: planted
serial and parallel children prove success silence, retained logs/counts, and
failure status/diagnostic propagation.
The mise workflow intentionally excludes the audit corpus from the local landing
gate; run `mise run audit-corpus` or let CI/final gates cover it.

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
| Record | `--record` reserves a new path with an advisory lock the kernel releases when the recorder exits or dies (a crashed recording never locks its path), refuses active/existing writers, and writes one parseable trace bundle atomically after a successful or application-error run that reaches finalization. |
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

Documented semantic limitations: `sock_accept`/`proc_raise` return `NOSYS` (Preview 1 has no listen surface; the native signal model is not exposed by the WASI host — Preview 1 itself has no general socket-creation API, so the supported socket surface uses configured descriptors); symlinks are inert leaf nodes (one-hop terminal follow then `ELOOP`; intermediate traversal is a deterministic `NOTCAPABLE`); an unlinked-but-open entry stays fully alive behind its descriptors (link count 0) and is released with its last reference, exactly as a kernel releases an inode; `APPEND` set after open works through a traced seek-to-end per `fd_write`; read-only mounts are host-enforced with descriptor rights as advisory defense-in-depth; memory growth past the cap is a deterministic trap.

### V4: native Rust Patina target

Native toolchain propagation has a class-level e2e detector:
`a_hostile_per_directory_proxy_builds_with_the_guest_compiler` makes ambient
shim-directory rustc and PATH Cargo fail, so native metadata, compiler probes,
and both builds must use the materialized guest invocation. The real rustup
pairing, `a_rust_toolchain_pin_builds_with_the_guest_compiler`, builds an
MSRV-pinned guest against a different ambient default (loudly skipped when
rustup/MSRV is unavailable). Both failed before propagation and pass with it.
`an_unverifiable_guest_compiler_is_refused_before_the_link` and
`unmaterializable_guest_toolchains_refuse_without_fallback` plant identity
mismatches in each verification directory, failed guest queries, an empty
sysroot, and missing binaries; every case must refuse before linking with a
concrete remedy. Absolute and relative explicit tool paths remain covered.
Success and refusal legs assert the bundle gains no mutable toolchain pin.

**Partial macOS/Linux linked-shim foundation with packaged single-source and
whole-package builds and managed threads.** Native acceptance is ordinary Rust
integration testing, with reviewable guests in `testbeds/native-boundary/`:

- `native_abi`: prefixed C ABI crash/checkpoint + `PATINA_TRACE` env protocol,
  POSIX descriptors/environment/paths, std cloning, pipes/socketpairs, and
  platform reactor fields, wakeups and exact virtual deadlines.
- `native_workloads`: ordinary std, independent entropy sources, Mutex/Condvar,
  FFI locks, exact virtual deadlines and network exchanges. Tokio enables the
  signal driver and uses parking_lot and the product-selected rustix backend;
  the test supplies no backend override. Replay checks compare complete output,
  two complete traces, flag-free replay and a changed-fingerprint refusal.
- `native_conformance`: every syscall conformance scenario natively and under
  patina (record/replay, strace, direct termination), one test per scenario, and
  the planted strace escape; see the conformance rows below.
- `native_containment`: planted raw/unknown-import/IPC escapes, the original
  `envp` array and ambient canaries, dlsym routing, live SUD arming or pre-exec
  refusal, SIGSYS protection, AT_RANDOM, vsyscall, and TSC containment.
- `native_raw`: live mixed-door parity, legacy syscall aliases, exact identity
  constants, soft ENOSYS refusals, scrubbed prctl auxv and modeled/unsupported/
  privileged prctl options. Raw ppoll pins remaining-time writeback and pipe
  readiness before/after a write. Patina-specific identity/refusal pins are not
  claims of host equivalence.
- `native_signals`: Linux C readiness interruption, temporary masks and timeout
  contracts; x86_64 Linux libc/raw prctl sharing, handler/mask visibility, sigwait
  retry, and complete guest-abort versus incomplete internal-fatal traces; Linux
  per-thread kernel registrations: a thread's exit walks the robust list it
  registered (`a_thread_exit_walks_its_robust_list`), and glibc's rseq areas
  read the virtual CPU and keep a sentinel across a handled signal, which a
  live host registration would overwrite (`rseq_areas_are_never_written_by_the_host`). Shared
  Linux/macOS cases check internal panic ownership, catchable guest panics, and
  process answers plus uninterrupted virtual sleep with repeat/replay identity.
- `native_trace`: the whole-run std strace detector with a planted escape on
  both Linux architectures; explicit unsupported ktrace policy on macOS.
- `shim_host_alias`: compiled-object doctrine scan and planted leak.

The seven native targets run in the full `check` workspace-test rung, in
both Linux CI architectures on stable and MSRV, and in the stable macOS job.
`check:fast` retains the cheap `shim_host_alias` object scan, not native execution.
`mise run check:native-abi` selects just `native_abi`; a libtest filter selects an
individual proof. The guest/build/gate map is in
`testbeds/native-boundary/README.md`. The independent host-oracle scenarios
live in `crates/patina-conformance`; a scenario that is not run on a host, or a
declared gap, does not substitute for native acceptance on that platform.

`native_build_package_audits_records_and_fails_closed` in `end_to_end` owns the
package/path-dependency/build-script/ambiguous-bin proof, including full stdout
identity. Native builds inject `cfg(patina)`/`cfg(dst)` and link the shim below
stock host std; this is not a custom target with recompiled deterministic std.
Startup snapshots its private control plane before scrubbing host environment;
`native_abi::posix_descriptors_and_environment_are_virtualized` pins coherent C getters and
`environ` under supplied host canaries, insertion order, in-place overwrite,
invalid names, putenv aliasing and platform clearenv (`environ` NULL).
`native_containment::dlsym_routes_the_shim_definitions_and_no_host_name` pins
the routing table on both platforms (the linked `getpid` on Linux, the entropy
pair on macOS, NULL for host, escape and unmodeled names) and the real
wrapped-dlsym round trip on Linux.

`cargo patina audit` is a strict per-format import allowlist over Mach-O/ELF (other formats rejected): after alias normalization (`$NOCANCEL`, underscore prefixes), an import passes only if it is an explicitly listed effect-free host-deferred symbol or `--allow`ed by the caller, and anything unknown fails closed as `unknown-import` — this is what catches the missed-interposer class structurally (a `clock_nanosleep`-style escape now fails the audit instead of passing silently). Known host-effect names keep their categories (filesystem, unmanaged-sync `os_unfair_lock`/`__ulock`/`psynch`, direct-syscall, and so on) for error quality, and instruction scanning still rejects raw syscall/clock/entropy assembly. The shim's control-plane symbols are `--allow`ed per audited binary by the scripts rather than statically allowlisted, so unmanaged binaries importing them still fail; under the host-alias doctrine (ARCHITECTURE.md) the shim resolves its host vehicles at runtime through `dlsym(RTLD_NEXT, ...)`, so on both platforms that set collapses to the single `dlsym` primitive (the trace-fd/baton/thread-creation vehicle names no longer appear in the guest import table at all — on Linux `__read`/`__write`/`sem_*`/`pthread_create` are each interposed by a strong def whose real vehicle is resolved through the same `dlsym(RTLD_NEXT, ...)` table); `native_containment::{audit_rejects_unlinked_raw_syscall_or_thread_escape,audit_rejects_unknown_import,audit_rejects_shared_memory_import}` proves the independent import refusals; `native_workloads::std_runs_seeded_and_replayable_but_not_standalone` audits the shim-linked std guest with AND without an explicit dlsym allowance. `run` enforces the same audit as a **pre-run default-deny gate** before the guest executes — it bakes in the control-plane vehicle so ordinary binaries need no repeated `--allow`, and hard-errors (naming, categorizing, and grouping symbols by recovered provenance — crate and containing symbol, plus the defining archive member on formats that record it (ELF does not, for global symbols; see crates/patina-target/ESCAPE-CLASSES.md)) on any other blocking/time/scheduling/effect symbol that is neither interposed nor known-safe, so a missed interposer becomes a refusal rather than a silent escape. This is what structurally closed the macOS Parker escape: std's `Parker` and the shim's own baton both used `dispatch_semaphore_*`, so the baton's per-binary `--allow` covered the Parker too; the dispatch semaphores are interposed (hence *defined*, not imported) and the baton reaches the *real* libdispatch semaphore through the host-alias table (`dlsym(RTLD_NEXT, ...)`) rather than a named import, so no vehicle symbol sits in the guest import table for a shared allowance to cover — the collision is eliminated structurally, which is exactly why the baton can safely use the same canonical primitive std does rather than one std happens not to use. The escape hatch `--allow-unsupported-symbols <all|name,...>` downgrades matching denials to a loud warning recorded in a sidecar beside a `--record` trace (visibly qualifying the determinism claim); the native gate proves the gate can fail — a planted Mach `semaphore_wait` binary is refused, named, and runs only under the hatch with the warning (`os_unfair_lock` served this role until it gained an interposer; its probe is now an acceptance-plus-misuse leg) — and that a partial allow list still fails closed. Pure libm math (`pow`/`powf`, `exp`/`log`, the trig/hyperbolic families, `sqrt`/`cbrt`/`hypot`, `fma`, the rounding family, `fabs`/`copysign`/`fmin`/`fmax`, ...) is known-safe on both formats — an explicit list, never a prefix match, so an effectful math-adjacent symbol (`random`, `system`) stays denied — because each is a function of its floating-point operands with no boundary effect (errno/FP-flag side effects are not host effects Patina models); this clears the `_pow` `unknown-import` an ordinary numeric guest surfaces, so it no longer needs `--allow` at every run. Because only a *shim-linked* binary shows the post-interposition residual, `audit` is **source-first**: auditing a `SOURCE.rs`/`DIR`/`Cargo.toml` (or a Patina-built artifact) links the shim first and reports the true handful of escapes, whereas a stock `cargo build` output lists the whole libc surface the shim interposes as unsatisfied imports — the opposite of the truth. `cargo patina audit <prebuilt-binary>` therefore **fails closed** on a binary that does not define the shim control-plane marker (`patina_init_from_env`), directing the caller to the source-first form or a Patina-built artifact; `--raw` overrides the gate and runs the full audit anyway (instruction scan and escape categories included) under a loud `PATINA_RAW_AUDIT` stderr banner marking the import findings as pre-interposition; `native_containment::audit_rejects_unlinked_raw_syscall_or_thread_escape` uses it for deliberately-unlinked C fixtures.

The deny/interposed/known-safe lists are organized by an explicit escape-class taxonomy, and every class has a permanent test that proves its detection is not vacuous. The full per-class breakdown with symbol lists lives in `crates/patina-target/ESCAPE-CLASSES.md`; the coverage matrix is:

| Escape class | Detection mechanism | Fixture / test (red-before, green-after) | Residual the symbol audit cannot see |
|---|---|---|---|
| Blocking / scheduling (`__ulock`/`__psynch`/dispatch/mach-sem; `poll`/`select`; interposed `os_unfair_lock` and the `kqueue`/`kevent` + `epoll`/`eventfd` readiness reactors) | import audit | `native_run_prerun_gate_refuses_every_escape_class` (`semaphore_wait`, `select`); planted-`semaphore_wait` e2e; `os_unfair_lock` acceptance + misuse-abort legs; `recv_timeout` & `rwlock` determinism; reactor legs (raw kqueue/epoll edge+timeout+waker, tokio ping-pong on both platforms) | an inlined `__ulock_wait` `svc` — Linux `strace`; **honestly absent on macOS** |
| Time | import audit **+** instruction scan (aarch64 `mrs CNTVCT_EL0`, x86 `rdtsc`/`rdtscp`; on x86_64 Linux the two x86 forms are trap-managed rather than refused — `prctl(PR_SET_TSC)`, answered from the virtual clock, proved by `native_containment::tsc_reads_answer_from_virtual_clock`) | `native_run_prerun_gate_refuses_every_escape_class` (`time`) | the **Darwin commpage** time path: `mach_absolute_time`/`gettimeofday` fast paths read a kernel-mapped page with an ordinary `ldr`, **not** an `mrs`, so the instruction scan does **not** catch it — coverage comes from *interposing* `mach_absolute_time`/`clock_gettime`/`gettimeofday` (what libc/std actually call); a hand-rolled commpage reader that bypasses libc is an uncaught residual |
| Entropy | import audit **+** instruction scan (x86 `rdrand`/`rdseed`, aarch64 `RNDR`) | `native_run_prerun_gate_refuses_every_escape_class` (`arc4random`); `classifies_rdtscp_and_rdseed` (patina-target); `native_containment::rdrand_is_refused_on_every_kernel` proves an `rdrand` guest stays refused on the very x86_64 Linux host where `rdtsc` runs trap-managed | novel entropy instruction encodings (no mechanism traps a hardware entropy read, so these are refuse-only — never downgradable) |
| Thread lifecycle | import audit | `native_containment::audit_rejects_unlinked_raw_syscall_or_thread_escape` (raw/pthread C refusal) + unmanaged-thread classifier unit | `pthread_create` is interposed, so a shim-linked guest can only reach uninterposed thread creation through non-exported private stubs (not linkable) |
| Process | import audit (uninterposed members) **+** runtime deny-trap (the spawn family a guest links) **+** deterministic model (`kill`) | `native_run_prerun_gate_refuses_every_escape_class` (`killpg`, uninterposed); `native_run_deny_trap_aborts_a_guest_that_actually_spawns` (a guest reaching shim-defined `fork` aborts deterministically, naming it); `kill_and_if_nametoindex_are_deterministic_errors` (macOS/Linux e2e — `kill(self,0)`→alive, a pid no process has→`ESRCH`, byte-identical); package off-allowlist binary fails closed | the spawn family (`fork`/`posix_spawn*`/`waitpid`/`pipe`/`chdir`) is now shim-defined so it is a runtime abort, not an import (`chroot` is a privileged row answered from the virtual credential); `setsid`/`setgid`/`setuid`/`setpgid`/`setgroups` are modeled against the one unprivileged identity (conformance `cred/ids`, `cred/groups`, `proc/ids`) — a reachability audit could not clear it (statically wired, runtime-flag-dormant). `kill` is now a deterministic-model interposer instead (the guest is pid 2, child of the pid namespace's init, pid 1): a signal-0 probe reports self alive / other pid `ESRCH`, a real self-signal is loud fail-closed — an honest existence-check result, not an abort. `killpg` and other non-linked members stay uninterposed and import-audited |
| Filesystem / network | import audit | `native_run_prerun_gate_refuses_every_escape_class` (`link`, `gethostbyname`) | an inlined `open`/`stat` `svc` — Linux `strace`; absent on macOS |
| Shared memory / IPC | import audit (libc members) **+** interposition and the one-process IPC model (Linux `mmap` family and the System V / POSIX message queue rows) | `native_run_prerun_gate_refuses_every_escape_class` (`shm_open`); the `mem/*` and `ipc/*` conformance scenarios | macOS `mmap(MAP_SHARED)` — the flag is invisible to a symbol audit and `mmap` is allowlisted as process-local memory there |
| Signals / timers | import audit | `native_run_prerun_gate_refuses_every_escape_class` (`setitimer`) | — |
| Environment | **interposition** (glibc's `getenv`/`setenv`/`unsetenv`/`putenv`/`clearenv` over the process's own `environ`, which starts as the deterministic startup map) | classifier unit test; `native_guest_env_mutation_is_coherent_and_replays` (e2e, red-before/green-after: pre-change the guest died on the `setenv` refusal); `native_abi::posix_descriptors_and_environment_are_virtualized` and `native_containment::host_environment_canaries_never_enter_guest_or_replay` | fully interposed — no uninterposed member exists to plant end to end |
| Dynamic loading | import audit; `dlopen`/`dlclose` denied. `dlsym`: Linux interposed, resolving every name the shim defines as a libc contract to that definition (a hidden alias, so the address the program links) and deterministic NULL for every other name — never a host symbol — with glibc's `dlerror`; macOS is the shim's host-alias resolution primitive (`dlsym(RTLD_NEXT,...)`), baked into `shim_control_plane_symbols` | `native_run_prerun_gate_refuses_every_escape_class` (`dlopen`); `native_containment::dlsym_routes_the_shim_definitions_and_no_host_name` (both platforms); `posix_source_lints::dlsym_routes_are_the_registry_definitions` (the table is the registry's definitions, red on a planted missing name); conformance `proc/dl` | **macOS guest `dlsym` call** reaches the real resolver (not interposed — a strong-def interposer would capture the shim's own resolver calls); residual **stays**. #18 investigated a build-time redirect (`objcopy --redefine-sym` on guest objects) and **did not implement it, by measurement**: on macOS nothing but the shim references `dlsym` — the guest user object has no `_dlsym`, no sysroot rlib (`libstd`/`libcore`/…) references it, so std never dynamically resolves a symbol, and the only `_dlsym` in a linked guest is the shim's `dlsym(RTLD_NEXT,...)` resolver. A call needs the reference, so the shim is the sole caller; the residual only manifests for a guest that **hand-writes `dlsym(...)` itself**, and closing that would mean a manual-relink pipeline (plus the non-default `llvm-tools` objcopy) — real risk for zero measured benefit. Honest/adversarial-shaped, measurably unreachable by any ordinary std guest |
| Direct syscall (by name) | import audit (`syscall`) **+** instruction scan (`svc`/`syscall` opcodes) | `native_run_prerun_gate_refuses_every_escape_class` (`syscall`) | — |
| macOS frameworks (CoreFoundation / Security) | enumerated symbols split between **deterministic model** and **deny-trap** at call time (the `rustls-native-certs` `CF*`/`Sec*`/`kCF*` + `chrono` `CFTimeZone*` surface: a strong shim def binds the reference so a binary that LINKS the optional TLS-trust / timezone path RUNS, and where the API admits an honest answer it RETURNS it — `SecTrustSettingsCopyCertificates`→`errSecNoTrustSettings` so `load_native_certs()` yields 0 certs; the `CFTimeZone*`/`CFStringGetCStringPtr` path reports `UTC`; the empty-`CFArray` helpers are honest — while the per-cert / string-builder helpers those returns make unreachable stay deny-traps that abort naming the symbol); the non-enumerated remainder + any prebuilt non-shim binary → import audit → `macos-framework` (Apple-reserved prefixes `CF`/`kCF`/`Sec`/`kSec`), still refused with a determinism note (host keychain/trust store is mutable per-machine state) and the `--allow-unsupported-symbols` allow path | `native_trust_root_surface_is_deterministically_empty` (macOS e2e: `certs=0 errors=0`, byte-identical); `local_timezone_surface_reports_utc` (macOS e2e: `tz=UTC`, byte-identical); `native_run_deny_trap_lets_a_guest_with_a_dormant_framework_path_run` (macOS e2e: a dormant certs-shaped path runs allowance-free); `native_gate_classifies_and_refuses_a_security_framework_symbol` (macOS e2e: a non-enumerated `SecTrustEvaluateWithError` is refused, class + note named, `audit` agrees); `classifies_known_native_escape_symbols` (unit) | classification is unchanged and stays load-bearing for the still-refused remainder / prebuilt-raw binaries; conversion only turns exercised paths deterministic and never relaxes a decision (chrono MRE audits CLEAN; the real `rustls-native-certs` MRE runs to completion `certs=0 errors=0`) |
| Host introspection (macOS Mach/BSD/IOKit) | enumerated members split between **deterministic model** and **deny-trap** at call time. The inventory entry points return honest fixed values (`mach_host_self`→synthetic port; `host_statistics64`→8 GiB VM stats; `host_processor_info`→1-CPU load so `cpus().len()==1`; `proc_listallpids`→the guest and init; `proc_pidpath`/`proc_pidinfo`/`proc_pid_rusage`→the guest's fixed identity / graceful degradation, `EPERM` for init; `IOServiceMatching`→`NULL`; `vm_deallocate`→no-op; fixed-value data symbols `mach_task_self_`/`vm_page_size`/`kIOMasterPortDefault`), so a `sysinfo`-shaped path RUNS whether dormant or live. The IOKit registry-walk helpers the `NULL` `IOServiceMatching` makes unreachable (`IOServiceGetMatchingServices`/`IOIterator*`/`IOObject*`/`IORegistry*`) stay deny-traps that abort naming the symbol. The **live-path** members a normal startup reaches (`sysctl`/`sysctlbyname`/`getrusage`/`task_info`) + any prebuilt non-shim binary → import audit → `host-introspection` (exact Mach/BSD names + IOKit entry-point prefixes), still refused with a determinism note (reads host CPU/memory/hardware/process state — nondeterministic; interpose-or-refuse, never allowlist) and the `--allow-unsupported-symbols` path | `host_inventory_surface_is_deterministic` (macOS e2e — `vm=0 cpu=0 ncpu=1 pids=2 iokit_null=true`, byte-identical); `native_run_deny_trap_aborts_a_guest_that_reaches_host_introspection` (macOS e2e — the still-trapped `IOServiceGetMatchingServices` call aborts, byte-identical); `classifies_ecosystem_audit_symbol_batch` (unit — Mach/BSD/IOKit sample classifies; `sysctlbyname` stays denied; a user `IOWidget` does NOT match the IOKit prefixes; `strtoul` stays `unknown-import`); the real `sysinfo` MRE runs to completion (`cpus=1`) with only its live-path audit residual (`sysctl`/`sysctlbyname`) | classification is unchanged and stays load-bearing for the still-refused live-path members / prebuilt-raw binaries; conversion only turns exercised paths deterministic and never relaxes a decision; the IOKit match is namespace-prefix-scoped (not a bare `IO`) |
| Custom global allocator (supported, macOS + Linux) | the shim's synchronization tables are **host-libc-backed** (`hostcoll`, never the guest allocator), and an allocator's own `os_unfair_lock` runs natively during the bootstrap window (`SHIM_BOOTSTRAP`) and reentrantly under a held spinlock (`SPIN_DEPTH`), so a custom `#[global_allocator]`'s init can never re-enter the shim and deadlock. Its init-reachable libc surface is classified per-symbol: interposed to deterministic values (`issetugid`→0, `mach_absolute_time`/clock→bootstrap-0, `readlink`→bootstrap-ENOENT; Linux `sched_getcpu`→0, `sched_setaffinity`→no-op, `secure_getenv`→NULL, `creat`→deterministic FS, `pthread_getname_np`→empty, `pthread_sigmask`→SIGSYS-safe forward) or allowlisted as pure/process-local (`___chkstk_darwin`, `mmap`/`sbrk`, `strcpy`/`strncpy`, `__ctype_b_loc`, `__sched_cpucount`), so it audits clean with no flags on both platforms | `native_run_supports_a_custom_global_allocator` (macOS e2e — audits clean, runs, seed-stable, interposed `os_unfair_lock` in the alloc path); `classifies_linux_jemalloc_audit_surface` (unit — the Linux 12-import classification); the real tikv-jemallocator MRE runs deterministically with no flags on macOS AND Linux (coordinator-verified in the VM: two same-seed runs byte-identical), macOS RED-proven (reverting the fix aborts/hangs) | multi-threaded jemalloc is covered by `SPIN_DEPTH` reasoning but has no automated multi-threaded-jemalloc e2e; the Linux C interposers are compile-verified on the Linux build (the shim's C layer is compiled on-target, not by cross-clippy) |

**audit/run parity and source-first package selection** (native audit/run blockers). The standalone `audit` and the pre-run `run` gate build their effective allow set through the single `effective_native_allow` constructor, so the static surface `audit` reports is exactly the surface `run` enforces — the reported disparity (`audit` flagged the control-plane `_dlsym (dynamic-loading)` that `run` silently permits) is closed and asserted two ways: `audit_and_run_agree_on_the_shim_control_plane_symbol` (e2e — a plain guest audits clean with no `--allow` and runs) and `native_workloads::std_runs_seeded_and_replayable_but_not_standalone` (a shim-linked std probe audits clean without `--allow`, replacing the old "audit denies the control-plane alias" check — a change in the parity direction, not a weakening: the only auto-tolerated symbol is the fixed `dlsym` residue and every real escape stays denied). Source-first `audit`/`run` now honor `--package`/`--bin` against a workspace manifest (the form the help advertises), proven by `audit_and_run_select_workspace_member_with_package_and_bin` (a virtual workspace forces the selection; a stray selection on a prebuilt artifact fails closed) and the `source_first_package_selection_threads_into_the_build_spec` unit.

**Custom global allocators are supported, not refused.** A custom `#[global_allocator]` (jemalloc first) initializes off the guest allocator without re-entering the shim, so it runs deterministically. Three structural pieces make this sound: (1) the shim's interposer-reachable synchronization tables (`ThreadTable.mutexes/conds/rwlocks` + waiter deques) are backed by the real libc allocator through the host-alias table (`hostcoll`: a Rust `#[global_allocator]` replaces `__rust_alloc`, never the C `malloc` symbol, so this reaches libSystem/glibc, whose locks are not interposed) — the lazy per-lock registration that used to allocate through the guest allocator no longer does; (2) a **bootstrap window** (`SHIM_BOOTSTRAP`, true until the runtime is installed, before `main`) during which the allocator's own eager, constructor-driven init runs its init-reachable interposers natively — `os_unfair_lock` on the real primitive, `readlink`/`mach_absolute_time` answered without allocating or requiring the runtime — so the allocator's init cannot re-enter a half-initialized shim; (3) a **reentrancy guard** (`SPIN_DEPTH`) that, after bootstrap, forwards an allocator-internal `os_unfair_lock` reached reentrantly while the shim holds its spinlock (the scheduler path allocates through the guest allocator) to the real primitive rather than deadlocking on the held lock. The two residual init symbols are resolved properly: `issetugid` is interposed to a deterministic 0 and `___chkstk_darwin` is allowlisted as a pure stack probe, so the MRE audits clean with no `--allow` flags. Evidence: the tikv-jemallocator MRE prints `jemalloc mre`, is seed-stable and record→replay identical, and RED-proves the fix (reverting any load-bearing piece aborts/hangs it). Residuals: multi-threaded jemalloc is covered by `SPIN_DEPTH` reasoning but has no automated multi-threaded e2e; Linux jemalloc (which uses `pthread_mutex`/futex rather than `os_unfair_lock`) needs the analogous bootstrap/reentrancy handling verified in the Linux VM. With the DEFAULT allocator none of this fires (libc's own locks are not interposed), so it is zero-impact for existing guests.

Two general residual classes cut across the table: **interposed-but-unsupported** symbols (e.g. `pthread_cancel`) are *defined*, so they pass the pre-run symbol gate but fail closed loudly with `ENOSYS` at call time — which is why `pthread_rwlock_*` was made a real deterministic implementation rather than left an `ENOSYS` stub; and **inlined raw instructions**, caught by the aarch64/x86 text scan for `svc`/`syscall`/`rdtsc`/`rdrand`/`RNDR`/`CNTVCT` but with the honest macOS whole-run gap above. The plain-`std` guests that legitimately run today (`std`-probe, thread-probe, `recv_timeout`, `rwlock`, and arg-reading guests) pass the gate with **zero** allowances: `__NSGetArgc`/`__NSGetArgv` are known-safe (supervisor-controlled argv) and `confstr` is interposed to a deterministic value. Interposed-and-supported surfaces never appear as imports and so are never flagged — this includes the dispatch-semaphore Parker, `sched_yield`, `confstr`, and `setsockopt`/`SO_RCVTIMEO` (whose deterministic recv deadline applies at `patina_sleep_until`, distinct from the deadlock-rescue clock path, and uses the same delivery-wins-ties tie-break as the Parker).

The gate deliberately audits the guest's **flat import list**, not a static call graph. We evaluated making it call-graph-aware — clearing a flagged import when no path from an entrypoint reaches it, so a binary that merely *links* an escape symbol without a live path need not carry an allowance — against a real-world file-walking CLI we audited (whose old allow list named 28 subprocess-spawn and host-query symbols) and rejected it: a **sound** reachability pass clears **zero** of them, so it is all cost and no benefit. Two reasons, each verified on the built guest (arm64 Mach-O; `otool -Iv` stub map + `objdump -d` call-graph BFS). (1) The dormant code is statically wired: the guest's subprocess spawn is reachable from the Rust entry by **direct calls alone** — an unbroken `bl` chain from `main` through the search worker and a command-reader builder into `std::process::Command::spawn` and on to `bl _fork/_posix_spawnp` — and only a *runtime* flag selects it, which static analysis cannot prove is never set. (2) Sound indirect-call handling swallows the program: any reachable indirect call may reach any address-taken function, and in a Rust binary `main` itself is address-taken (handed to `lang_start`), so the conservative closure admits the whole live call graph. The honest fix is therefore per-symbol *interposition*, not reachability: the guest's spawn family becomes shim **deny-traps** that abort deterministically if reached (so a genuine spawn fails loud + reproducible instead of escaping silently), its host-state queries return fixed deterministic values, its pure-compute members (`memset_pattern4/8/16`, the `sigset_t` bit ops) are known-safe, and `dlsym` is the shim's own host-alias control-plane primitive — each drops off the import table or the allow list, emptying the allowance entirely while the gate stays fail-closed for any new import. Full analysis and per-symbol disposition: `crates/patina-target/ESCAPE-CLASSES.md` ("Why symbol-reachability, not static call-graph reachability").

On both Linux architectures, `native_trace::std_whole_run_and_planted_openat_use_identical_filter` performs the whole-run `strace` containment pass: every traced file, network, clock, entropy, and descriptor syscall in the entire run must match an exact loader/std-runtime prelude shape (shared-object loads, `/proc/self/maps` stack-bounds introspection, control-plane descriptors 0-3, process-local memory/signal setup, glibc's nonblocking startup `getrandom`, and the shim's guest-memory copies — `process_vm_readv`/`process_vm_writev` naming the traced process itself, while one naming any other process is an escape; the conformance leak run's filter, `crates/patina-conformance/src/leak.rs`, applies the same rule) — the seeded probe's guest section performs zero host syscalls, and a planted `clock_nanosleep`, host `openat`, or `socket` anywhere in the run fails the gate. vDSO time reads never enter `strace` and are covered by the libc-interposition probes. macOS has no equivalent runtime gate: calibration established that `ktrace` (the only root-capable, SIP-compatible whole-run tracer) cannot found a sound default-deny check, so the macOS path skips loudly and leaves static instruction scanning plus import audit as the macOS containment evidence — and `PATINA_REQUIRE_KTRACE=1` hard-fails on Darwin rather than reporting a check that cannot fail. Three independent blockers, each reproduced on-host: `ktrace` BSD-syscall (`BSC_*`) events carry only raw register values, not decoded paths, so a guest's raw `open`/`stat` is indistinguishable by argument from the loader's libSystem prelude; the deterministic runtime buffers all guest output (stdout and stderr) into a single flush at process exit, so there is no in-band "first write to stdout" boundary to separate the pre-main loader prelude from guest code (an early unbuffered stderr marker is observed emitted only at the end of the trace); and the loader/runtime legitimately issues the same syscall names an escape would (`open`, `stat64`, `fcntl`, `getpid`, ...) while its init interleaves with early guest execution, so a name-scoped default-deny is either vacuous or false-positives on every clean run — a planted post-init raw `getpid` (inline `svc`) lands among the runtime's own `getpid` events, name-identical and not temporally separable. Mach traps are outside the BSD syscall class and remain the scheduler-baton scope analogue of Linux futex allowances. The strace path allowances are shape-based (they audit our probes, not adversarial binaries).

`scripts/smoke-cross-target.sh` builds one ordinary-`std` smoke program for wasm32-wasip1 and the native host, runs seeded smoke tests with recorded and replayable traces on both, and requires the deterministic program output to be byte-identical across targets.

`native_workloads` pins threaded UDP arrival variation, duplex TCP shutdown/EOF
and the exact peer port, an IPv6 loopback bind, DNS NXDOMAIN and localhost resolution. Its timer
checks assert 25 ms signalled / 100 ms unsignalled Condvar waits, five deliveries
and five receive timeouts across seeds 5/6/7, 100 ms sleep with a runnable worker,
and exactly 250 ms versus zero UDP latency. Replay compares full output and
trace bytes.

`native_containment` separates the kernel contracts into individually runnable
checks: `audit_reports_sud_marker_and_kernel_requirement`,
`unmarked_raw_syscall_is_refused`,
`raw_syscalls_are_virtualized_or_refused_before_execution`,
`unmapped_raw_syscall_aborts_with_named_diagnostic`, and `sud_scrubs_vdso_auxv`.
No-SUD execution is refused before opening an invalid replay trace. SIGSYS
protection and AT_RANDOM seeding are kernel-independent. TSC checks separately
cover exact clock values and trace metadata (`tsc_reads_answer_from_virtual_clock`),
seeded jitter (`tsc_sleep_jitter_moves_counter`), genuine faults
(`genuine_segv_is_not_swallowed`) and handler protection
(`sigsegv_handler_hijack_is_refused`). `rdrand_is_refused_on_every_kernel` builds
no TSC guest and requires no TSC capability. Unsupported capabilities execute
named refusal assertions; the SUD-only vDSO check reports missing evidence.
`PATINA_REQUIRE_SUD=1` makes missing SUD fatal in tests and the ecosystem wrapper;
x86_64 Linux CI requires it.

`testbeds/rustix-default/run-patina.sh` owns the default-linux_raw ecosystem
proof (audit SUD-managed, clocks/fs/directory iteration/entropy/SimNet, repeat,
variation and replay). It and cap-std-dirfd run from the full landing gate's
`native ecosystem testbeds` rung and every Linux CI row; unsupported hosts
must print the expected counted skips. `scripts/check-native-testbeds.sh`
probes the kernel independently and requires each exact `branch=sud` receipt
on capable hosts: a child's false-negative capability result is a failure.
Compile errors and abnormal probe exits are fatal. The wrapper selftest plants
a false-negative child, duplicate receipts and a failed child.
`native_raw` pins process constants, two-iovec sendmsg/recvmsg ENOSYS, live
scrubbed PR_GET_AUXV and denied prctl, legacy filesystem spellings, FIFO rows,
creation-mode enforcement and raw/libc fcntl parity. Raw eventfd/epoll semantics
live in the conformance scenario `readiness/epoll`, including the exact
zero-creation-flags / 0xC0FFEE userdata case through the raw vehicle (not one of
its declared HUP gaps), which every x86_64 CI row runs, stable and MSRV.

Directory-descriptor-relative (`*at`) resolution is proved by a second committed MRE, `testbeds/cap-std-dirfd/` — a std + `cap-std` guest. `cap-std` is the capability-based filesystem API: it opens ONE directory through std (libc → the C interposer) and then resolves every path component itself against that descriptor with raw `openat(dirfd, name, O_PATH|O_DIRECTORY|O_NOFOLLOW)`, `statx(dirfd, name)`, `readlinkat(dirfd, name)`, `faccessat2(dirfd, ".")`, `mkdirat`/`unlinkat`/`renameat`/`symlinkat`, and `getdents64` over a descriptor derived by `fcntl(dirfd, F_GETFL)` + `openat(dirfd, ".")`. One guest therefore exercises BOTH entry paths on the SAME descriptor, which is exactly the property under test: the two only agree because they share one directory-descriptor table in the runtime (`patina_diropen`/`patina_dirpath`). Its `run-patina.sh` skips **loudly and counted** (`cap-std-dirfd: SKIPPED 1 …`) on non-SUD/non-Linux hosts and, under SUD, asserts audit→`SUD-managed`, byte-identical same-seed repeats on **stdout AND the captured stderr** (a refusal diagnostic lands on the latter, so comparing stdout alone would not notice a nondeterministic deny), and byte-identical record→replay, printing `CAPSTD_LEGS_RAN branch=sud …`; the full landing gate runs it in `native ecosystem testbeds`, and every Linux CI row runs it through the receipt-checking wrapper. RED before the resolution landed: with every `*at` row modeling `AT_FDCWD` only and the libc `open` refusing `O_PATH`, the guest dies on its FIRST call — `Dir::open_ambient_dir: Function not implemented (os error 38)`. It also carries the `O_PATH` leg (`opath=nocost,list=r,walk=x`): a `0o400` directory is listable but not traversable, a `0o100` one is traversable but not listable, and a `0o000` one still accepts a path-only open whose descriptor then refuses to be read — RED when both directory opens were the same open, which charged `x` and handed back a readable handle. The deny-string parity rule the SUD layer depends on (a raw guest and a libc guest must record the same captured stderr for the same refusal) is itself gated: a unit test extracts the C `O_PATH` deny macro from `patina_posix.c` and compares it byte-for-byte with the SUD constant, and is RED-proven by perturbing either spelling.

The same MRE carries the acceptance legs for permission bits and descriptor identity, and its result line names both (`modes=enforced+created pinned=node`). The mode leg reads back the creation modes, changes them with `chmod` and `fchmod`, and requires `PermissionDenied` — distinguishable from `NotFound`, which is the whole reason to model them — for reading and writing a `0o000` file, resolving through a directory with no `x`, listing one with no `r`, and creating a name in one with no `w`. It also proves the CREATION mode is the caller's and is judged later: a file created `0o400` reads back `0o400` and its next write-open is `PermissionDenied`, a directory created `0o500` refuses a new name inside it, an `open` of an existing file leaves that file's mode alone whatever third argument it carries, and the `0o666`/`0o777` requests still land at `0o644`/`0o755` under the modeled umask. The pinning leg opens a capability on a directory, renames the directory out from under its name, plants a symlink to a decoy at the vacated name, and requires that reads AND writes through the descriptor still land on the original node while the decoy stays untouched. All are RED-proven by mutation rather than asserted: neutering the owner-triad check fails the mode leg at `a 0o000 file must not be readable`, dropping the creation mode on the driver side fails it at `a creation mode must be the caller's`, and removing the rename bookkeeping that moves an open description with its node fails the pinning leg at `the descriptor must survive the rename: PermissionDenied`. The raw-syscall half is pinned by `native_raw::creation_modes_are_enforced_on_later_open`: `openat(..., O_CREAT, 0o400)`, the x86_64 legacy `open`/`creat` aliases and `mkdirat`/`mkdir` each carry their mode, the umask is applied to the request, and the resulting bits are enforced (`EACCES` on the second write-open and inside a `0o500` directory). `patina-dst-fs-mem` carries the driver-level pairs (creation modes honored and enforced on reopen, an existing entry's mode untouched by a later `open`, per-operation enforcement, mode survival across a restart snapshot, and a descriptor following its node through nested renames while a planted symlink does not recapture it), and `patina-dst-fs-crash` pins that permission bits are metadata a crash keeps — a `0o604` file, a `0o700` directory and a `0o640` FIFO all come back with their bits — and that a `0o000` directory's children are NOT dropped, because the crash journal reads the image through an unenforced inventory rather than through the guest-facing calls.

Named pipes are proved by a third committed MRE, `testbeds/fifo-ipc/` — a std + libc guest. It is deliberately NOT SUD-gated: every call it makes goes through libc, so it runs on every platform the native shim supports, and the raw-syscall `mknodat` row (plus the x86_64 legacy `mknod` alias, `S_IFIFO` from raw `fstat`/`newfstatat`, `DT_FIFO` from raw `getdents64`, the `ENXIO` write-open, and raw transfer through the returned endpoint) is pinned by `native_raw::raw_fifo_rows_transfer_and_refuse_consistently`. The guest covers all three creation spellings (`mkfifo`, `mkfifoat`, `mknod(S_IFIFO)`) and a refused character device, the entry kind through `stat`/`fstat`/`read_dir`, a non-blocking read-open with no writer paired with an `ENXIO` non-blocking write-open, a blocking reader released by another task's `open(O_WRONLY)` across a real thread, end-of-file when the last writer closes, `EPIPE` on a reader-less write, `EAGAIN` on a non-blocking read with a live writer, `O_RDWR` opening without waiting, `PermissionDenied` (distinguishably from `NotFound`) on a `0o000` FIFO, `fstat` on an open FIFO descriptor reflecting a `chmod` made AFTER that open (the descriptor reads the live entry by inode, as on Linux), a hard link to a FIFO being a second name for the same node — same inode, link count 2 — and therefore the same pipe (bytes written through one name are read through the other), unlink-while-open keeping the pipe alive while a surviving link keeps the node, and — with the LAST name unlinked — `fstat` through the descriptor still reporting the live node (link count 0, real mode) and `fchmod` through it still changing what the next `fstat` reads, because the endpoint holds a reference on the node rather than a copy of it. Its `run-patina.sh` asserts a CLEAN pre-run audit — no `--allow-unsupported-symbols`, and the mkfifo/mknod family appearing nowhere in the audit, which is the class-level proof that they left the "not interposed" bucket — the expected `FIFO_RESULT`, byte-identical same-seed repeats on **stdout AND the captured stderr**, byte-identical record→replay, and the same result across four seeds, then prints `FIFO_LEGS_RAN …`. RED before the model landed: the guest could not be audited at all (`mkfifo` was an unsupported-symbol refusal in the `filesystem` escape class), and forcing it through only moved the failure to the host, where `mkfifo` failed `ENOENT` on a path that exists only inside the in-memory filesystem. `patina-dst-fs-mem` carries the driver-level pairs (the umasked creation mode and the entry kind, an unlinked FIFO answering through the reference its endpoint holds and released with it, per-operation permission enforcement on a FIFO open, listing/rename/unlink parity with every other kind, a hard link making one node out of two names — shared mode, link count 2, and `NotFound` only once the last name goes — an inode-addressed metadata read seeing a later `chmod`, a directory rename carrying the FIFOs beneath it, and mode plus inode identity surviving a restart snapshot, hard links included); `patina-dst-fs-crash` pins the crash-model half (an fsynced parent commits the name so reconstruction rebuilds a FIFO as a FIFO with its mode, hard-linked names come back as ONE node, and an uncommitted creation is lost like any other name); `patina-dst-native-shim` pins the channel state machine (a FIFO channel is born with no ends and derives its closed-ness from the reference counts, so a side comes back when it is opened again) and gates the shared C/SUD deny strings — now both the `O_PATH` and the `mknod`-type refusals — byte for byte.

Required before claiming general native `std` control:

- cross-machine stress and a usable macOS whole-run syscall trace if a future `ktrace`/OS version exposes enough path context for a default-deny gate;
- deterministic stress across fresh processes and machines.

### V5: native ABI shim and production-hardening

**Partial.** Implemented foundations include:

- trace file/event limits and hostile structural-input rejection;
- one trace format version: only `TRACE_FORMAT_VERSION` is written or read; a bundle declaring any other version, older or newer, is refused as `UnsupportedVersion` before its body is interpreted (`any_other_format_version_is_refused`), and the checked-in current-format fixtures load, validate and re-encode byte-for-byte;
- compact trace byte encoding (format 3): compact JSON with base64 byte payloads replaces pretty-printed number arrays, dropping the representative workload from ~344 to ~124 bytes/event under the `patina-dst-bench` gate; a number-array payload is refused, and the file remains valid JSON for `jq`/`python3 -m json.tool`;
- self-contained fault replay (format 4): record captures replayable fault configuration in trace metadata, with authoritative reconciliation. Fresh-process filesystem crash restart is native-only: native `--fs-crash-at` and torn granularity record and replay flag-free across both incarnations, Cargo/WASI refuse them, and campaigns do not draw them. Other fs error/short-I/O/latency, sleep/net/DNS faults retain flag-free replay. The `replay` subcommand exposes no fault knobs and refuses one up front;
- trace lifecycle protocol (format 5): operation events carry global order and incarnation ids, lifecycle markers share the same order namespace, branch suffix lifecycle/orders are validated against inherited prefix orders, and crash-restart traces are represented as `Start(0)`, triggering operation, `Crash(0,digest)`, `Restart(0->1,digest)`, `Start(1)`, fresh-incarnation operations, and `End(1)`;
- creation modes on the boundary (format 6): every creating filesystem operation carries the mode its caller asked for — `fs_open`'s flags gain `mode` (POSIX `open`'s third argument, `0` when the call cannot create), `fs_create_directory` gains one, and `fs_make_fifo` already had one — so a mode survives record→replay instead of being reconstructed from a per-kind constant. The restart snapshot goes to v4 in the same change, making a FIFO inode-backed like a file so a hard link to one is a second name for the same node across a restart;
- the four timestamps on the boundary (format 8): every recorded metadata outcome carries `ctime_nanos` and `btime_nanos` beside `atime_nanos`/`mtime_nanos`, now that the deterministic filesystem stamps all four by the kernel's rules from the virtual clock the runtime hands each driver operation;
- signal generation (format 9): `signal_generated` records sequence, signal, process/task target, siginfo code and payload. `signal_operations_fixture_decodes_and_replays` pins the canonical encoding with the `format-12-signals.patina` feature fixture.
- `O_PATH` on the boundary (format 7): `fs_open`'s flags gain `path_only`, the flag that distinguishes a directory descriptor that NAMES a location from one that OPENED the directory — different permission cost, different capability — so a capability guest's component walk and a real directory read are no longer the same recorded operation. Two new recorded operations carry inode lifetime across the boundary (`fs_retain_inode`/`fs_release_inode`, the reference a FIFO endpoint holds on a node the filesystem hands back no handle for), plus `fs_read_directory_fd` (iteration through a descriptor rather than a name) and `fs_set_inode_mode` (`fchmod` through that same endpoint); all four are additive serde-tagged variants, so they need no version bump of their own;
- the filesystem and memory families' operations (format 10): `fs_sync_all`, `fs_make_node`, `fs_rename_whiteout`, `fs_exchange`, the four xattr operations, and the page cache's and anonymous files' `fs_write_back_at` (what a shared mapping stored, written into its file; not refused by write seals, counted as a write for crash injection), `fs_create_anonymous` (`memfd_create`, with its hugetlb page size), `fs_seals` and `fs_add_seals` (`F_GET_SEALS`/`F_ADD_SEALS`), with the `socket` and `char_device` entry kinds. `format-12-memory.patina` pins the memory operations' canonical encoding; the `mem/mmap_file` and `mem/memfd` conformance scenarios record and replay them on every vehicle;
- the realtime epoch and the node name in the run configuration (format 11): `RunMetadata::realtime_epoch_nanos` and `RunMetadata::hostname` are required fields, stated by every caller of `RunMetadata::new`. The epoch is the Unix time the virtual realtime clock read at monotonic zero (default 2026-07-22T23:00:09Z, `run --realtime-epoch` on every family); replay adopts it before the default clock is built, because filesystem timestamps are stamped from realtime without a recorded read, and a conflicting explicit epoch or an installed clock on another epoch is refused. The node name is what `uname`/`gethostname` report (default `patina`, `run --hostname` on the native and Cargo families, at most 64 bytes and no NUL); replay adopts it and refuses a conflicting explicit name. `replay` refuses both flags outright. Evidence: `a_current_bundle_must_state_its_run_facts` (a bundle missing either field does not parse), the runtime's `realtime_epoch` and `hostname` suites (default, override, control-plane validation, flag-free replay and branch — the epoch through an unrecorded filesystem-clock read — conflict refusal), and end-to-end record/replay tests on the Cargo, WASI (epoch) and native families;
- the network family's operations (format 12): `net_bind_shared` (one member of an `SO_REUSEPORT` group), `net_connect` (a datagram socket pinned to its peer, `None` releasing it), `net_mark` (the type of service and the `IP_PKTINFO` source a socket's sends carry), a datagram's `dialed` address and `tos` mark (omitted when empty or zero), and the `unreachable` send disposition for a datagram nothing is bound to take. `network_operations_fixture_decodes_and_replays` pins their canonical encoding with the `format-12-network.patina` feature fixture, which must equal what a recording of the same decisions writes;
- failure-oracle delta debugging for unbranched main timelines, leaf branch suffixes, and non-leaf branch trees (inherited prefix protected, suffix reducible), exposed by `cargo patina minimize` through isolated candidate files and `PATINA_MINIMIZE_TRACE`, plus scenario/parameter reducers and bounded ascending seed canonicalization;
- fault-knob reduction: `cargo patina minimize --generation N` delta-debugs the fault-knob vector a campaign generation drew, each candidate a fresh seeded `run` spelled by the campaign's own generation runner, and writes the surviving standalone reproduction command into the out-dir before the trace phase shrinks a trace recorded from it. Its oracle is patina-owned and its target is the campaign's own recognition of the generation: the verdicts recorded for it in `campaign-state.json` (`patina.campaign.state/v2`), so no failure text has to be hand-written. A candidate preserves the failure only when its replay reports every target failure verdict by `(kind, label)` AND did not diverge (no `patina native shim fatal`), which closes the fail-open direction a target-only oracle leaves open. `--marker TEXT` overrides the target for a guest that reports nothing structurally, and a generation with no failure verdict and no `--marker` is refused by name — never reduced against a guessed target, and never against a target the unmodified seed run does not itself reproduce. Because that oracle replays each candidate into its own temp directory with the guest's filesystem, clock, network and entropy virtualized, candidates are evaluated concurrently (`--jobs`) without a shared path between them; an external oracle command is opaque to patina and stays serial unless `--jobs` opts in. Parallelism is throughput-only by construction: a reducer offers the oracle the window of candidates a one-at-a-time scan would try next and keeps only the FIRST accept in scan order, so a widened window cannot move the result. Any oracle that reports the failure surviving in a candidate with every reducible decision deleted is refused by name (inverted exit polarity) rather than obeyed;
- schedule reducers: `reduce_schedule` canonicalizes recorded `SchedulerNext` outcomes (switch collapsing toward longer per-task runs, lowest-task-id-first at switch points) under the same failure oracle, never rewriting a protected inherited prefix; the combined entry points and `cargo patina minimize` run pruning, suffix shrinking, and schedule reduction to a joint fixed point;
- `CrashFs` whole-image checkpoints, synchronized durability, crash rollback with open-handle preservation, and cross-trace replay tests, with seeded torn writes (configurable granularity/probability against the durable baseline), sub-block byte-granularity tearing of the final unsynced write (a partial page that differs from both the durable and fully-applied images, exercised over positional `write_at` and append-at-EOF writes), rename atomicity on/off, directory-fsync durability, and crash/restart recomputation — evidenced by the `patina-dst-fs-crash` unit suite and a runtime record/replay torn-write test;
- `FaultFs` wraps the default `CrashFs` at the driver choke point and injects seed-derived EIO/ENOSPC/EINTR plus short read/write results. The runtime emits `PATINA_FS_FAULT_REPORT` and warns on per-class vacuity, and the campaign classifies a vacuous generation as `VACUOUS_FS_FAULT`. Vacuity is judged per class only once the configured rate over the opportunities the class actually saw expected at least five firings, and a short I/O counts as applied only when the truncation bound the result — so the warning marks a knob that is inert on the exercised I/O path rather than a low rate that ordinarily drew zero. Native and WASI end-to-end tests prove observable errno/short-I/O outcomes, same-seed trace identity, and flag-free replay; wrapper unit tests pin both vacuity legs (a genuinely inert short knob over big-buffer reads fires it; ten draws at one per-mille do not);
- the error and short classes each report WHICH operation kinds absorbed their effects (`errors_by_op=open:1,read:2`, `shorts_by_op=write:3`, `-` for none), sub-class coverage the scalar counts cannot express: a knob that is non-vacuous because every one of its fires landed on `open` leaves every post-open failure path untested, and a short class that only ever bound reads says nothing about the write path a torn-record bug lives on. The breakdown is rendered from dense per-kind counters in a fixed op order, never from map iteration, so the line stays byte-identical across repeats of a run. Evidence: a runtime test on the pure report line asserting the fixed rendering order and the empty-class sentinel (RED before the fields existed), a `patina-dst-driver-api` test that arrival order cannot change the rendering and that nested reports merge per kind, and a wrapper test driven off the op-kind table that runs EVERY fault-eligible operation at rate 1000 and requires each to attribute to its own kind with the breakdown summing to the scalar count — proven RED twice, by a mis-mapped kind (`read_at` reported as `read`) and by an applied short counted without an attribution;
- `--fs-latency-nanos MIN..MAX` delays every fault-eligible filesystem operation by a seeded draw BEFORE it executes, applied at exactly one site — the `Context`, which owns the clock — so both families see the same virtual-time cost and neither doubles it. `close`/`dup`/`seek`/`crash` are outside the eligible set and are never delayed. The delay is an ordinary recorded sleep, so flag-free replay reproduces the timing without re-supplying the knob, and a re-supplied knob is refused. The latency class joins `PATINA_FS_FAULT_REPORT` with its own vacuity verdict, judged against the eligible-op count the DRIVER observed independently, so eligible traffic that never reached the Context choke point reads as vacuity rather than silence; a range whose draws are all zero is inert by construction and never diagnoses. Evidence: native and WASI end-to-end tests where the GUEST measures the virtual-time delta across one fs op (RED without the Context wiring: zero delay, and the report's latency verdict is never diagnosable), runtime tests pinning the exact five-eligible-op delay, seed determinism and seed variation, flag-free replay identity, and a unit test firing the vacuity verdict on the bypass shape while proving it stays silent below the expected-firings floor;
- DNS is modeled against a per-run host table: `--dns-entry NAME=ADDR` defines the names a guest can resolve and every other name is NXDOMAIN — semantics at rate 1.0, not an injected fault, so an undefined lookup is never counted as a fault opportunity. `localhost` and dotted-quad literals resolve without the table and are fault-exempt. Resolution is the recorded `DnsResolve` boundary operation, so a flag-free replay reproduces it (including an injected failure) from the trace and a re-supplied table is refused. `--dns-fail-permille` fails a defined name with a seeded NXDOMAIN or transient timeout, `--dns-latency-nanos` delays it Context-side (the same single-site rule fs latency follows), and both report per-class vacuity through `PATINA_DNS_FAULT_REPORT`. The native `getaddrinfo` interposer returns a single heap-allocated A record and `freeaddrinfo` really frees it; `gethostbyname`/`getnameinfo` stay refused by the audit, and wasip1 — which has no resolution surface at all — refuses the `--dns-*` flags rather than accepting knobs that could never fire. Evidence: runtime tests for the table, the built-ins, both knobs, seed variation, flag-free replay and fail-closed conflict; a native end-to-end guest that resolves through ordinary `std` name lookup and observes the address, the NXDOMAIN, the injected failure and the injected latency, then replays flag-free; and a harness end-to-end guest proving `HarnessBuilder::dns_entry`/`dns_service` reach the SAME host table (RED with the overlay dropped: every name goes NXDOMAIN), that `dns_service` allocates the documented `10.0.0.N`, and that the in-process overlay and the authoritative trace reconcile on flag-free replay rather than conflict;
- the campaign carries the DNS domain end to end: `campaign --dns-entry NAME=ADDR` records the host table in the out-dir spec and forwards it to every generation, `--faults` then draws `--dns-fail-permille` in [0, 100]‰ and `--dns-latency-nanos` up to 2.55 ms from the generation hash, and a vacuous generation is classified `VACUOUS_DNS_FAULT` — its own class rather than a shared vacuity bucket, so the report names which fault plane went inert. The band is emitted ONLY when the spec defines names: with no defined name every lookup is NXDOMAIN by semantics and the knobs could not fire, and a knob that provably cannot fire is worse than an absent one because the report reads clean. A WASI artifact carrying a host table is refused outright. Evidence: classifier selftest fixtures for both vacuity verdicts and the warning line, plus per-plane attribution fixtures (a vacuous DNS run alongside a healthy fs report is NOT filed under the fs class, and vice versa) — RED before the classify rule was wired; unit tests that the band rides on the table, never reaches WASI, varies both knobs across generations, and round-trips through the recorded spec; and a 20-generation campaign over an unretried-startup-lookup guest that caught the bug in one generation and replayed it flag-free;
- every seed-derived campaign band draws from a byte of the 32-byte generation hash that it CLAIMS in one table (`gen_byte` in `campaign.rs`), and reads it through that claim rather than a literal index. Two bands sharing a byte would silently correlate their knobs — the campaign would sweep a diagonal of the pair's space instead of the square, so a bug needing an off-diagonal combination stays unreachable at every generation while every report reads clean — and no run surfaces it. Paired gates: `generation_byte_claims_are_disjoint` rejects a duplicate, out-of-range, or seed-overlapping claim, and `every_generation_hash_read_goes_through_a_claim` scans the derivation source and rejects a literal index that bypassed the table. The scan asserts its own coverage (it must reach `derive_flags`), so a future edit that moves its bound fails loudly instead of shrinking the gate to nothing — the failure mode that was caught and fixed while writing it. Both proven RED by a planted collision and a planted literal index;
- one wildcard-bind routing rule spans BOTH layers that resolve a virtual address: a listener bound to `0.0.0.0:PORT` receives traffic dialed at any address on that port with no exact-match binding, and exact match always wins. It is shared code (`wildcard_bind_key`) because the network driver routes the packet while the native shim independently decides which blocked task to WAKE — a rule applied to only one of them delivers a datagram that nothing ever wakes for. Evidence: SimNet unit tests for delivery, exact-match precedence and the rule never inventing a route (a bare label, a port with no wildcard listener, a datagram bind that is not a TCP listener); plus a native end-to-end guest whose receiver PARKS before the traffic arrives, red-proven in both directions — removing the driver-side rule fails the send with `NoRoute`, removing the shim-side rule delivers the datagram and then deadlocks into the fail-closed abort;
- every fault knob is accepted by `run` and `test` in all three families and refused by `replay`, proven per knob by a table-driven test that carries each registered flag to its control-plane variable in each family; the CLI's knob table is gated against the flag registry, so a knob that one family would silently drop fails the build's tests rather than a campaign's assumptions;
- read-only allowlisted `HostCaptureFs`, symlink/traversal containment, replay without host access, and failure on branch capture miss;
- mixed Rust/C symbol tests for the documented prefixed ABI and POSIX filesystem shim;
- bounded multi-process seed campaigns through `cargo patina explore`;
- performance budgets in `crates/patina-bench` (`cargo run -p patina-dst-bench --release`): a hard trace bytes-per-event ceiling and structural gates (one event per boundary operation, linear trace growth) run in `cargo test`; generous wall-clock ceilings are `#[ignore]`d opt-ins for quiet machines.

Required before claiming broad libc/POSIX compatibility or stable traces:

- broader libc network/process symbol *coverage* (modeling more behavior): the remaining items are a documented non-goal (process/spawn symbols, which the audit rejects); non-zero TCP latency and the async readiness reactors are delivered. Unsupported-symbol *diagnostics* are complete — the strict audit default-denies any unmodeled import as `unknown-import`, interposed-but-unsupported operations fail closed at runtime through `patina_posix_deny` (ENOSYS plus a loud `patina: … failing closed` line), and the `unknown_import_probe` gate proves the rejection fires.

`CrashFs` modeling simplifications stated honestly: directory renames are always atomic (no subtree tearing); directory-durability loss covers explicitly created entries, not implicitly created parents; defaults are conservative (4096-byte granularity, torn probability 1.0, atomic renames, and namespace changes lost unless the governing directory is fsynced).

### V6: cooperative-SUT SDK

**Partial (Milestone C).** The `patina-dst` crate ships a FoundationDB-`BUGGIFY`- and Antithesis-style SDK as its whole dependency-light surface; the explicit-context API (`run`/`run_with`, `Context`) lives in the separate `patina-dst-runtime` crate. Every SDK macro (`buggify!`, `buggify_with_prob!`, `buggify_delay!`, `buggify_knob!`, `always!`, `sometimes!`, `reachable!`, `lifecycle::event!`) plus `is_simulated()`/`rng()` is a no-op or plain fallback outside a Patina build, and no `cfg(patina)` appears in adopter code.

Automated evidence:

- `patina-dst-runtime` unit tests cover activation as a deterministic function of seed and label (with the ~25% realized fraction), firing-PRF determinism and seed variation, the damage-control cutoff, duplicate-label detection, knob determinism and range, the disabled/inert path, `rng()` determinism, the trace-metadata reconcile contract, and byte-identical record/replay of buggify decisions without re-supplying flags;
- `patina-dst-trace` covers the additive `buggify` metadata round-trip and its absence from a buggify-free trace, and the additive `guest_argv` metadata round-trip (including the empty-list-vs-absent distinction so a zero-argument run stays distinguishable from a pre-argv trace);
- guest-argv replay is proven end to end (`native_replay_restores_guest_argv_and_normalizes_argv0`): a run recorded with non-default `-- ARGS` is reproduced byte-identically by a bare `cargo patina replay <bin> <trace>`, a mismatched `--` section is refused up front naming both argv lists, an old trace without the field still replays with explicit arguments, and `argv[0]` is pinned to the normalized `patina-guest` (the host binary path never leaks into the guest);
- the `patina-dst` crate's own tests, built WITHOUT `cfg(patina)`, prove every macro is inert (a consumer's plain `cargo build` behavior);
- `cargo-patina` end-to-end tests build a whole package depending on the SDK, run it under `run --buggify`, assert the `PATINA_SDK_REPORT` line, its required `@file:line` site identities, link-time `declared_site` rows, and nonzero firings, join that report through `cargo patina sites --exercised` with `unmatched_runtime_labels == 0`, replay a recorded trace byte-identically without re-supplying `--buggify`, prove a never-called `reachable!` appears in campaign `sites.json` with `registered_gens=0` and fails the coverage gate, and prove a duplicate label aborts with the `PATINA_BUGGIFY_DUPLICATE_LABEL` marker — with literal labels the link-time table catches the reuse at install, before either site is evaluated, and runtime/WASI-host unit tests pin that a conflicting declaration surfaces that same named marker rather than a generic initialization failure;
- the flag-off invariance is verified on a real testbed: a rebuilt guest (now compiled with the internal `--cfg patina_shim`) reproduces its canonical seed-7 result hash with buggify disabled, so the SDK is zero behavior change when off;
- **buggify on WASI** (Milestone C) is at full parity with native. `patina-dst-wasi-host` tests drive the `patina_sdk` module directly (a site fires and the diagnostics are recorded) and prove the sleep-jitter fix is deterministic and reproduces on replay; `cargo-patina` end-to-end tests run hand-written `patina_sdk`-importing modules to prove firing + a parseable Wave 2 `PATINA_SDK_REPORT`, an `always!` violation's `violation` verdict plus the `PATINA_BUGGIFY_DUPLICATE_LABEL`/`PATINA_BUGGIFY_SETUP_NEVER_CALLED` markers with a nonzero exit, flag-free record/replay byte-identity (with a re-supplied `--buggify` refused), and cross-seed variation; and a full-stack test compiles a buggify-instrumented Rust guest both plain (asserting its wasm imports **no** `patina_sdk` module — the no-leakage contract) and through `build --target wasi` (asserting it does), runs it under `--buggify`, joins the emitted report through `cargo patina sites --exercised` with zero unmatched runtime labels, reproduces its digest on replay, and trips the `always!` oracle via `--arg violate`.

Determinism and fail-closed guarantees: buggify decisions are pure functions of the seed and site label and are never recorded per evaluation (no trace bloat); the realized config, active-site set, and knob picks are recorded in the trace metadata and are authoritative on replay (conflicting replay knobs fail closed like the fault knobs); enabling buggify folds a `+buggify` fingerprint component, reconstructed at replay from the trace, so a buggify trace never cross-replays with a non-buggify build.

Lifecycle gating is causal through the runner: `run --buggify-after-setup` declares that the guest calls `setup_complete()`, so buggify stays inert until that call, and a declared-but-never-called run fails loudly (`PATINA_BUGGIFY_SETUP_NEVER_CALLED` + abort) after recording its trace — verified by a `cargo-patina` end-to-end test. Without the flag, buggify is armed from the start and `setup_complete()` is a boundary/coverage marker.

Literal-label SDK macro sites are declared through a dependency-free link-time table under `cfg(patina)`: the native shim reads the native linker section and the WASI host reads the wasm custom section before the guest runs. Declarations do not register/evaluate a site, compute activation, or enter trace metadata, so replay fingerprints and buggify decisions are unchanged; dynamic labels and hand-written `patina_sdk` imports still require runtime evaluation to appear.

The first-class `cargo patina campaign` layer parses every generation's `PATINA_SDK_REPORT`, pins every end-of-run report on for its children (they are classifier inputs, so an inherited `PATINA_*_REPORT=0` must never blind a generation), writes `<out-dir>/sites.json` (`patina.campaign.sites/v1`, including `generations_observed`), surfaces `sdk_sites`/coverage summaries in human output, heartbeats, and JSON envelopes, and fails by default when any `sometimes!`/`reachable!` oracle is never satisfied (including declared-but-never-registered rows with `registered_gens=0`). `--allow-unmet-sometimes[=MIN_GENS]` is the explicit waiver. The campaign selftest proves met, unmet, declared-unreached, waived-bare, waived-under-threshold, enforced-at-threshold, and malformed-row coverage classes; the end-to-end suite plants never-satisfied and never-called oracles as RED detectors and extends deterministic reruns to byte-compare `sites.json`.

The shell campaign layer (`testbeds/buggify-campaign.sh`) still adds two classes on top of the existing sweep classifier without changing any existing gate priority: `ALWAYS_VIOLATION` (per-gen, top severity, fires even on exit 0, never downgraded) and `SOMETIMES_UNMET` (campaign-level: a `sometimes!` site reached but never satisfied fails the campaign). Both are proven fireable — plus a not-downgraded check — by a selftest wired into `testbeds/workq/fuzz-sweep.sh --selftest`. The same campaign layer drives the `workq` testbed's buggify leg (`testbeds/workq/run-patina.sh`) and backs a WASI dogfood (`testbeds/buggify-wasi/wasi-buggify-sweep.sh`, fresh `out-wasi-buggify/`): a buggify-instrumented `wasm32-wasip1` fixture compiled through `build --target wasi`, run under per-generation-derived activation/fire with a per-generation record→replay determinism check, proving the `patina_sdk` guest path parses into the identical `PATINA_SDK_REPORT` classifier the native sweeps use.

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

  Masking is coherent end to end: a dropped class is retracted from everything
  that declared it, including the compatibility fingerprint (`+buggify` is the
  only fingerprint-folding swarm class today) and the class's own configuration,
  which resets entirely so a masked run leaves no residue. A dropped class stays
  distinguishable from one that was never requested — it appears in
  `candidate_classes` but not `selected_classes`, `PATINA_SDK_REPORT` carries
  `swarm_deselected=1`, and the default-on `PATINA_SWARM_REPORT` line names every
  candidate with its per-class decision. `TraceBundle::validate` enforces that the
  selection is a duplicate-free subset of the candidates, so the derived
  "deselected" complement is always meaningful. Replay and branch adopt the
  recording's swarm record, so a replayed generation reports the same decision.
  End-to-end tests
  (`swarm_deselection_stays_coherent_with_fingerprint_and_metadata`,
  `campaign_with_swarm_and_buggify_has_no_coherence_aborts`) prove a masked
  generation runs and is distinguishable, an unmasked one keeps `+buggify`, a
  `--buggify --swarm` campaign has no coherence aborts while exercising both
  outcomes, and genuine incoherence still refuses. See
  [docs/bugs/swarm-buggify-fingerprint-coherence.md](./docs/bugs/swarm-buggify-fingerprint-coherence.md).

  `--swarm` is also non-vacuous or loud. A run that arms swarm with no
  swarm-maskable fault class has an empty candidate set: the draw keeps and drops
  nothing and the run explores the plain configuration. The report carries
  `vacuous=1`, the runtime warns (`PATINA WARNING: swarm fault-class selection
  inert`), a campaign generation is classified `VACUOUS_SWARM`, and the workq
  sweep promotes a would-be-clean swarm generation the same way — so the sweep's
  own fault-knob count drifting from the runtime's class table surfaces as a
  failure rather than as swarm coverage that never happened. Dropping every
  candidate of a NON-empty set stays a legitimate draw (`vacuous=0`), which both
  selftests pin.
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
  `STARVATION_STALL` (a fuzz-sweep `--selftest` case) — reported, but NOT counted
  as a distinct bug found, because the backstop arms only under `--starve` and
  measures elapsed wall clock rather than scheduler progress, so it cannot tell
  this limitation from a guest livelock; and starvation kept OPT-IN in the sweep
  (`PATINA_SWEEP_STARVE=1`) so the always-on canary never wedges. `campaign
  --starve-scale-permille N` is the dial that makes the injector rare enough for a
  long workload to finish.
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

The routine push/pull-request matrix in `.github/workflows/ci.yml` runs stable and Rust 1.86 across Linux x86_64 and aarch64. Every row executes the workspace tests (including all native acceptance tests) plus the WASI/cross-target checks and FIFO/rustix-default/cap-std testbeds; each row's workspace suite runs as two parallel `cargo nextest` partitions (plus its doctests) beside one job for the row's other gates, and every test job installs `strace` and sets `PATINA_REQUIRE_STRACE=1` so the syscall-containment pass cannot silently skip. Stable rows additionally run the `workq` and `pubsub` testbeds, while stable Linux runs formatting, clippy, docs, the flag-drift gate, the audit corpus, and the fuzz-sweep and campaign classifier selftests. A strict `audit` job checks RustSec advisories over the root and every testbed lockfile with no ignores.

Stable macOS runs as a clean-host safety net daily and on manual dispatch, not on every locally validated push. It executes the workspace tests (including the Darwin native legs), WASI/cross-target probes, FIFO/workq/pubsub testbeds, and the macOS audit corpus; the full Rust 1.86 suite remains covered on both Linux architectures and by explicit local `mise run msrv` final-gate runs. The ordinary local landing gate runs only the measured MSRV compile/detector/macros rungs. The 200-generation randomized `workq` campaign runs nightly on Linux and on manual dispatch, without a duplicate hosted-macOS campaign. (`cargo package --workspace --locked` is included in the local landing gate and is also the pre-publish packaging check.)

A failure report must retain the command, seed, trace bundle when one exists, Patina version, Rust version, target triple, and compatibility fingerprint.

## Current boundary of confidence

Passing V0-V2 proves the CLI-to-runtime-to-driver-to-trace loop for explicit `patina_dst_runtime::Context` effects. V3 proves the entire audited Preview 1 surface with preopen policy and resource limits, within the documented semantic limitations. The named native tests above prove a controlled slice of ordinary `std` behavior — filesystem (including directory listing and symlinks), time, sleep, entropy, stdio, threads, and UDP datagrams — and mixed C ABI calls, built through the packaged `build`/`run` path with auto-initialization and record/replay over the descriptor trace channel — for single Rust sources and whole Cargo packages (path dependencies and build scripts included), though not yet a packaged native target with a recompiled deterministic `std`. Containment is enforced from two directions: the strict import allowlist fails closed on any unknown symbol, and the Linux `strace` pass shows the probe's guest section performing zero host syscalls over the whole run. Platform execution evidence is platform-local: the Linux matrix covers both architectures; the macOS job covers pthread/kqueue/Darwin lowering. A Linux-only local run does not verify the Darwin legs. The cross-target smoke script proves one ordinary-`std` program behaves identically under seeds, record, and replay on wasm32-wasip1, native macOS, and native Linux. Low-level storage rollback, native crash→fresh-incarnation restart (seeded, and record→replay across both incarnations with the handoff checked against its recorded digest), trace format-version refusal, host capture, minimization reducers, and performance budgets have focused evidence. The crash-restart confidence boundary is native only: WASI and cargo-family `--fs-crash-at` refuse by name.

One record path still represents one finalized context; multi-test aggregation is unsupported. Arbitrary host DNS, process spawning, arbitrary FFI, dynamic loading, and full POSIX compatibility remain outside the confidence boundary (the explicit-boundary `patina-dst-async` executor and native tokio under the interposed readiness reactors are inside it).
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
| Instruction scan (`scan_instruction_classes`: aarch64 `svc`/`mrs CNTVCT`/`RNDR`, x86 `syscall`/`rdtsc`/`rdtscp`/`rdrand`/`rdseed`) | `patina-target/src/lib.rs`; `walks_past_forbidden_bytes_embedded_in_operands`, `fails_closed_on_undecodable_bytes`, `refuses_binaries_of_undecodable_architectures` | Old byte-slide false-positive on operand-embedded bytes; silent pass on undecodable architectures | **Class** | Boundary-aware; discriminates operand bytes from real opcodes; undecodable *architectures* refuse loudly (`UnsupportedNativeArchitecture`, no escape hatch). Limit: known encodings only — commpage `ldr` time reads are residual; `cpuid` is decoded but deliberately visible-not-refused (host-identity class). |
| Bootstrap-window init-error reachability | e2e `native_replay_init_error_reaches_every_bootstrap_window_entry_point` (one leg per answering entry point, deadline-bounded) + `bootstrap_window_lints` in `crates/patina-native-shim/src/lib.rs` (single `SHIM_BOOTSTRAP` reader; enumerated call-site table) | Replay init errors swallowed for clock-only guests — a 100% CPU spin instead of the named abort (`docs/bugs/replay-init-error-swallowed-for-clock-only-guests.md`); second swallow: `println!`-only guest exited 0 with output dropped | **Class** | The class is "any interposed entry point that can answer without reaching `ensure_runtime`"; the window itself is covered by construction (one guarded predicate, lint-pinned). Residual: the ~100 non-window C-ABI entry points that reach the runtime through helpers await a call-graph audit. |
| Linux whole-run `strace` containment | `native_trace::std_whole_run_and_planted_openat_use_identical_filter` (both Linux architectures) | Inlined raw syscall (no import) | **Class** | Whole-run default-deny; planted escape proves non-vacuity. Linux-only; `PATINA_REQUIRE_STRACE=1` (set on all Linux CI jobs, which install strace) turns the missing-tool soft-skip into a hard failure. |
| Syscall conformance against the live host kernel (`crates/patina-conformance`, `cargo-patina/tests/native_conformance.rs`) | forty-nine scenarios, each one `#[test]`, through every vehicle the architecture has (libc / `syscall(2)` / inline `syscall` on x86_64): the native run (the oracle: every check holds, a non-zero exit or a signal death only when announced) agrees with the first vehicle's, and the patina run is compared field by field under the call sites' typed normalizations; the patina run judged is the recorded one (`recording_changes_no_observation`: a plain run of the same seed observes the same streams and endings, on one fs, one net and one signal scenario), and a completed one is replayed (identical streams and endings; the scenario's recorded-trace facts — its exact `signal_generated` sequence, at most one `task_wake` per generation where declared) and run directly under strace (default-deny leak filter; the one allowance is a signal to the calling thread); a native signal death is re-checked on the shim-linked binary's own wait status. Unit tests in `patina-dst-conformance` (`compare`, `leak`, `catalog`, `host`) plant every refusal; `strace_leak_filter_flags_a_planted_escape` plants a host `openat("/etc/hostname")` under the real strace invocation | A guest "bug" that is really a patina≠kernel divergence (docs/arcs/syscall-conformance.md §1); a virtual kernel that exits where the real one dies by a signal; a BEHAVIOUR-ONLY pass (process-global signal state, a host signal fired at generation, no trace op) that turns every single-threaded scenario green | **Class** | Exact by default: an undeclared difference fails, and a gap (`Failure::Differs` with the exact patina values, `Failure::Stops` with the exact event count, ending and diagnostic) that stops matching fails until it is removed, so the gaps are always exactly the current gap. RED-proven: planted differences, stale gaps, a wrong pinned value, count drift both ways, a termination or core-flag change, a missing or wrong stop diagnostic, an unannounced native death or non-zero exit, documented alternatives that must not absorb ENOTDIR, masks that keep in-mask bits, the self-signal allowance's bounds, trace facts missing a generation or waking twice, a host kernel too old for a covered row or implementing an asserted-absent one. Pinned system: the scenarios assert Ubuntu 24.04 — its GA kernel (Ubuntu's 6.8, `VIRTUAL_ABI`) and its glibc (2.39, `host::PINNED_GLIBC`) — and only a host with both is authoritative; elsewhere (GitHub's 6.17 runners, or a 6.8 host with another glibc) a failed native check, a native-versus-patina difference or a stale gap prints `DIVERGES (host H, pinned P)` and joins `$GITHUB_STEP_SUMMARY` without failing (`PATINA_REQUIRE_PINNED_KERNEL=1` judges any host strictly), while disagreeing native vehicles, replay, trace facts, strace and crashes fail everywhere — `off_the_pinned_kernel_differences_only_report` plants both sides on a faked 6.17 host and a faked other glibc, `host::tests::only_the_virtual_abi_series_is_pinned` and `only_the_pinned_glibc_is_pinned` the matches. Limit: Linux only (the rows are the Linux ABI); an unmet host need prints `NOT RUN` with its reason (`PATINA_REQUIRE_HOST_ORACLE=1`/`PATINA_REQUIRE_SUD=1`/`PATINA_REQUIRE_STRACE=1`, all set on the Linux CI jobs, make an unsuitable kernel, SUD or strace absence a failure); the core flag of a Core-class death is what this host's core sink does. |
| Filesystem timestamps, ownership and sizes (`FsClock` on every reading/mutating driver op; runtime atime fixed to `relatime` (other policies are driver-only clock inputs), mtime+ctime on a data change, ctime on a metadata change, btime at creation; directory `st_nlink = 2 + subdirectories`; `chown` as a comparison against the one identity with the setuid/setgid kill; `truncate`/`fallocate` as single recorded operations) | `patina-dst-fs-mem` `creation_stamps_all_four_times_and_the_parent_directory`, `data_changes_move_mtime_and_ctime_and_leave_atime_and_btime`, `relatime_refreshes_atime_after_a_data_change_or_a_day_and_not_otherwise`, `metadata_changes_move_ctime_only`, `a_directory_link_count_is_two_plus_its_subdirectories`, `truncation_by_descriptor_and_by_name_answer_the_kernels_errnos`, `allocate_grows_keeps_or_zeroes_and_answers_the_kernels_errnos`, `zero_io_preserves_times_size_and_cursor`, `read_after_truncate_past_cursor_returns_eof_without_rewinding`, `impossible_capacity_is_a_storage_error_not_a_process_abort`; CrashFs `crash_restores_newly_synced_times_and_symlink_times`; runtime `filesystem_attribute_latency_repeats_and_replays` and `filesystem_mutations_sample_after_latency`; conformance scenarios `fs/times`, `fs/owner`, `fs/size` (host-checked through every vehicle; every check is a relation between two readings, never an absolute time, and none depends on the oracle mount's atime policy) | Stat reporting `ctime` as a copy of `mtime`, no birth time, `st_uid` 0 beside `getuid()` 1000, a directory link count of 1, `X_OK` refused on an executable file, `truncate` a planted host escape | **Class** | Every rule is a unit-level detector RED against the two-timestamp filesystem; the scenarios diff the model against the kernel per field. Limit: the oracle host mounts `/tmp` `noatime`, so the relatime rule itself is proven by the unit tests, not by the kernel diff. |
| Time, timers, scheduling and identity (one clock-id decode; virtual CPU time = the modeled startup cost plus the advance-on-spin rescues charged to the baton holder; timers expiring at boundaries and by idle advance, a rescued waiter settled before same-instant expiries; the two-process pid namespace; the unprivileged identity; per-thread scheduling attributes on one CPU) | runtime `cpu_time_is_the_spin_rescues_charged_to_the_baton_holder`, `the_spin_rescue_stops_at_an_alarm`, `a_cpu_alarm_is_reached_in_whole_rescues_without_the_ramp`, `idle_time_advances_to_an_alarm_ahead_of_every_parked_deadline`; shim `clocks::tests`, `identity::tests`, `thread::sched::tests`, `thread::timers::tests`, `thread::signals::tests::lifecycle_tests::generation_validates_typed_targets_before_recording`; `native_workloads` `an_interval_timer_and_a_sleep_ending_together_wake_the_sleeper_once`, `a_timerfd_and_a_poll_ending_together_wake_the_poller_once`; conformance scenarios `time/*`, `sched/*`, `cred/*`, `sys/{uname,sysinfo,personality,rlimit,hostname}`, `proc/{pgrp,ids}` (host-checked through every vehicle; CPU time must be positive at start and advance across a bounded spin, CPU timers must fire, remaining times drop across a sleep, expiration and overrun counts reach the periods measured since arming) | Every clock but `REALTIME`/`MONOTONIC` `EINVAL`; every timer, credential, capability, scheduling and `uname` row a named trap or `ENOSYS`; the C `sched_getaffinity` answering a pid it never looked at; a timer and a sleep ending at one instant aborting on a double wake | **Class** | The scenarios diff each row against the kernel per field; a model answering constants fails them. Limits: `proc/ids` declares `kill(-1, 0)` a by-design difference (the host's oracle has other processes); CPU time is charged only through clock observation, so a compute loop that never reads the clock fires no CPU-time timer. |
| Privileged rows answered from the virtual credential (each row's pre-capability checks in the kernel's order, then its declared capability: the kernel's refusal without it, a named fatal with it; host-configuration rows from the declared `KERNEL_CONFIG`, never the host's sysctls) | shim `sud::privileged::tests::every_declaring_row_is_gated_on_its_declaration` (every registry row that declares capabilities has a case, or is listed unreachable; each case against a credential holding every capability but the row's declared ones — refused — and one holding just those — the granted fatal, at a declared capability; each declared capability changes some case's answer) and the bpf table test; `patina-dst-syscalls` `tests::capability_rows_are_routed`; conformance scenarios `fs/{mount,mount_api,open_tree}`, `sys/{admin,quota,ioport,root,hostname}`, `proc/{ptrace,namespaces}` through every vehicle, the libc one through the shim's own wrappers (`c/posix/privileged.c`), and `sys/{perf,bpf}`, `mem/userfaultfd` and `ipc/sysv_sem`'s undo through the kernel vehicles | Every privileged row a fatal `Trap(privileged)`, so a guest probing `mount`, `unshare` or `bpf` for support died where the kernel answers `EPERM`; the libc leg could not even resolve glibc's wrappers | **Class** | The declaration test fails a declaring row without a case, a check that consults a capability the row does not declare or lets a caller past without it, and a declared capability no case's answer depends on. It cannot catch a check and declaration that agree but are both wrong against the kernel; the scenarios can, for the unprivileged caller only. The conformance scenarios pin the answers and their order against the host kernel (authoritative on the pinned 6.8). Limits: the named fatals where the model ends (unsharing shared state from other threads, a user-mode `userfaultfd` descriptor, non-array BPF map types, detaching a BPF program, `PTRACE_TRACEME`) are gaps where a scenario reaches them; `proc/namespaces` stops at `/proc/self/ns/uts`, which the virtual filesystem lacks, before `setns`'s namespace checks; the keyring, Landlock, LSM, `seccomp`, `statmount`/`listmount` rows stay traps. |
| The libc layer's userspace semantics over the virtual kernel (stdio buffering, the environment, local time, the passwd database, the internal clock spellings, `tcgetattr`, `getentropy`; wait4's option check; `dlsym`'s answers and `dlerror`) | conformance `fd/stdio` (full buffering onto a pipe, the `st_blksize` buffer and a write past it, the error at the flush, the writers' answers), `proc/exit` (events left in `stdout`'s buffer reach the stream only through the flush `exit` makes) and `proc/environ` (insertion order, in-place overwrite, `getenv` answering the entry's own bytes, `putenv` aliasing and bare-name removal, an assigned `environ` honoured, `clearenv` leaving it NULL), `time/localtime` (a POSIX `TZ` rule at both transitions, `EOVERFLOW`), and the shim's `localtime::tests` (19 rule strings × 20 instants against the host glibc, the missing-file fallbacks, the zoneinfo-file refusal), `sys/nss` (root in the caller's struct and buffer, `ERANGE`, a missing uid, the `getpwent` walk and its rewind, `__res_init`) with `patina-dst-syscalls`' `the_passwd_database_holds_root_and_the_identity`, `time/libc_clocks` (`clock_getres`, `__clock_gettime`, `__gettimeofday` zeroing its time zone) `fd/termios` (`ENOTTY` on a pipe, `EBADF` closed), and `entropy/getentropy` (`EIO` past 256 bytes, the buffer untouched; `EFAULT` for NULL) with `entropy/getentropy_fault` (`EFAULT` for a read-only page), and `proc/wait` on every vehicle (`EINVAL` for an unknown or waitid-only option bit, `ESRCH` for `INT_MIN`), and `proc/dl` (the linked definitions' very addresses for `getentropy` and `getpid`, through `RTLD_DEFAULT` and `RTLD_NEXT`; `dlerror` naming a missing symbol once); `native_abi` `stdio_lifecycle` (an atexit `printf` beside a parked printing thread across 8 seeds, and an atexit `setenv` beside a parked `setenv` loop, errno after the first write against the host, the buffered output a refusal keeps, a failed `assert()` against the host's message and signal, and every buffering mode's flushes on a pipe against the host's) | stdout unbuffered with `fflush` a no-op; a buffer lost at exit; an environment rebuilt sorted from a map, `getenv` answering a per-thread copy, `putenv` refused; `localtime_r` UTC whatever `TZ` said, a year past `int` truncated; "no such user" for every uid and no `getpwent` walk; the clock spellings and `tcgetattr` undefined; `getentropy` serving any length, `EINVAL` for NULL and a guest `SIGSEGV` for a read-only buffer; `wait4` `ECHILD` whatever its options; `dlsym` NULL for a defined `getpid` and an internal twin's address for `getentropy`, no `dlerror` | **Point** | Pairs with the conformance class row above: the native run is the oracle. A planted missing exit flush fails `proc/exit` (the patina stream loses its last two events). The `stdio_lifecycle` tests were red before their fixes (the post-main scheduling refusal, errno 9, an empty stdout, SIGSEGV for the assert and for `setvbuf`). |
| Conformance coverage and catalog consistency (every scenario covers a row; its covered rows are in the virtual ABI and its asserted-absent rows are `Absent`; its symbols are registry rows; its gaps name vehicles it has and a stop gap is alone; exclusions are unique and uncovered; every scenario has exactly one test) | `patina-dst-conformance` `catalog::tests`, `coverage::tests`; `native_conformance::every_scenario_has_one_test`; `mise run conformance:coverage` lists every syscall and symbol row of the target no scenario covers and no exclusion accounts for | A scenario claiming a row it cannot exercise; a scenario nobody runs; a registry entry nobody host-checks | **Class** | The metadata tests fail by name. The coverage report is a local command, not a gate: it exits 1 while any entry is uncovered, and its count is the measure of the gap until every entry has a scenario or a reasoned exclusion. |
| Virtual ABI level (`registry::VIRTUAL_ABI`, the pinned kernel: Ubuntu 24.04's GA 6.8; a row whose `since` is newer is `Absent` → `ENOSYS`, and only such rows are `Absent`) | `patina-dst-syscalls` `tests::{since_newer_than_virtual_abi_is_exactly_the_absent_rows, rows_are_well_formed}` (the predicate is planted with dated/undated/undatable rows); conformance scenario `abi/newer_than_virtual` (one table row per number past the level: `mseal`, the `*xattrat` rows, `file_getattr`/`file_setattr`, `fchroot`) asserts `ENOSYS` through the kernel vehicles natively, under patina, on replay, and under strace, with arguments a kernel implementing the row would refuse — on a kernel that implements a row, its native answer is the declared `ENOSYS` (`host::tests` plant both directions) | A number newer than the declared kernel trapping as `unmodeled` (an abort a real 6.8 kernel would not produce), or a host newer than the virtual level oracling semantics patina never claimed | **Class** | Raising `VIRTUAL_ABI` fails the rule test by naming every row it passes, so each is re-dispositioned deliberately; the scenarios' asserted-absent rows are checked against the registry's `Absent` disposition, so a scenario can never disagree with the level. |
| macOS whole-run containment | — | — | **NONE** | Honestly absent: `ktrace` cannot ground a sound gate. `PATINA_REQUIRE_KTRACE=1` hard-fails rather than reporting a vacuous check. Only static scan + import audit on macOS. |
| Shim host-alias object scan | `cargo-patina` `tests/shim_host_alias.rs` (`shim_objects_name_no_undeclared_host_escape` + `planted_leak_is_caught`) | Dispatch-semaphore Parker sharing the baton's `--allow` | **Class** | Scans shim's own objects for undeclared host escapes; planted leak keeps it honest. |
| Syscall registry completeness (every vendored-table number has exactly one row; every row's numbers are in the table under its name; the `Removed` family is exactly the table's entry-less numbers; routed rows bind exactly one handler, trap rows none) | `patina-dst-syscalls` `tests::{every_native_entry_has_exactly_one_support_row, removed_rows_are_exactly_the_tables_unimplemented_numbers, rows_are_well_formed, symbol_rows_reference_real_rows}` over active generated metadata in `crates/patina-syscalls/`; `compile_contract.rs` rejects foreign IDs and missing classifications; native Darwin `darwin::validate_associations` checks every symbol association against generated variants at compile time, paired with `darwin::tests` and a planted unknown binding in `compile_contract.rs`; `scripts/test-refresh-syscalls.py` detects source-to-Rust number/guard mutations and mocked latest-release ordering errors (Linux RC/final/trailing-zero/downgrade/malformed versions; independent XNU tags); `sud::build_dispatch` (compile-time) + `sud::tests::bindings_match_the_registry_rows` (by name) | Every un-routed raw syscall number answered by one generic `unmapped` abort; C-only interposers (statfs, getcwd, umask, sched_getaffinity) with no link to the rows they serve | **Class** | A kernel number added upstream, a mistyped number, a deleted row, or a routed row without a handler fails by name (or fails to compile). Limit: the dispositions encode today's behavior; a WRONG disposition is caught only by the conformance probes (docs/arcs/syscall-conformance.md §4), which land with the testbed. |
| Symbol registry ↔ shim objects ↔ `patina-target` (every defined public symbol has a row; every non-`Absent` row is defined on its platform; no `Absent` row is defined; `Deny` rows = the deny-trap list = the C trap sites; live interposers are rows) | `cargo-patina` `tests/syscall_registry.rs` (`every_defined_public_symbol_has_a_row_and_every_row_is_defined`, `deny_rows_agree_with_patina_target_and_the_c_trap_sites`, planted `planted_gaps_are_reported`, `c_trap_parser_recognizes_every_trap_shape`) | The deny-trap list pinned by a C parse alone; known glibc spellings the shim leaves undefined (`__clock_gettime`, `clock_getres`) reaching the host with nothing naming the gap | **Class** | A new interposer without a row, a definition lost from the link, a trap converted without moving the list, or an `Absent` alias quietly gaining a definition all fail by name; the planted-gap test keeps each direction non-vacuous. Limit: Darwin rows are checked only when the gate runs on macOS. |
| Fingerprint fail-closed (`+yieldpoints`/`+buggify`/`+pct`/`+starve`/`+swarm`, reconstructed from trace) | `patina-runtime`, `patina-trace`; `native_yield_points_trace_fails_closed_against_plain_binary`, `reconcile_replay_*_enforces_the_authoritative_trace_contract` | Cross-replay of incompatible build/policy | **Class** | Any capability mismatch fails closed; `deny_unknown_fields` rejects unknown policy in older runtime. |
| Fingerprint/buggify metadata coherence (`+buggify` requires armed config) | `patina-trace` `buggify_fingerprint_requires_buggify_metadata`; `patina-runtime` `buggify_fingerprint_requires_enabled_config`; e2e `native_buggify_sdk_reports_records_and_replays` | Campaign value-form buggify vacuity: fingerprint claimed SDK buggify while trace metadata was absent | **Class** | Any parser/env-plumbing variant that stamps `+buggify` without arming the SDK fails before recording/replay can certify coverage. Limit: WASI fingerprints fold buggify into a hash rather than a textual suffix, so the invariant is one-way (`+buggify` ⇒ metadata). |
| Swarm deselection coherence (a dropped class retracts its fingerprint component) | `patina-runtime` `swarm_deselecting_buggify_retracts_the_fingerprint_component`, `swarm_class_table_declares_every_fingerprint_component`; `patina-trace` `swarm_record_partitions_candidates_into_selected_and_deselected`; e2e `swarm_deselection_stays_coherent_with_fingerprint_and_metadata`, `campaign_with_swarm_and_buggify_has_no_coherence_aborts` | SlateDB item 9: a `--swarm` generation that dropped buggify kept declaring `+buggify`, first as silent phantom coverage and then (post-guard) as an abort of a legitimate run | **Class** | The class table pins which swarm classes fold a fingerprint component, so adding one without registering its retraction fails the test rather than resurrecting the incoherence. |
| Vacuous-schedule diagnostic (`PATINA_SCHEDULE_REPORT` + `PATINA WARNING`) | `patina-runtime/src/lib.rs` (`SCAFFOLDING_YIELD_FLOOR`); `vacuous_worker_that_never_yields_is_flagged` | "N seeds clean" hiding zero exploration (atomics-only window) | **Class (calibration-coupled)** | Mechanism is structural, but the floor is a tuned constant (macOS 4 / Linux 0). A std-scaffolding cost change could mis-calibrate it silently. |
| Net-fault vacuity diagnostic (`PATINA_NET_FAULT_REPORT` + `PATINA WARNING: net fault knobs inert`) | `patina-runtime/src/lib.rs` (`emit_net_fault_report`); `patina-dst-driver-api` `NetFaultReport::is_vacuous`; `patina-net-sim` `fault_report_is_vacuous_exactly_on_the_silent_inertness_signature`; e2e `native_tcp_stream_faults_are_deterministic_replayable_and_non_vacuous`; `testbeds/pubsub/fuzz-sweep.sh` `VACUOUS_NET_FAULT` selftest | `--net-jitter-nanos`/`--net-drop-permille` silently inert on the SimNet TCP stream path (a datagram-only implementation) — "clean under faults" hiding zero perturbation (task #37) | **Class** | Fires when the knobs could perturb (nonzero drop or jitter ceiling) and fault-eligible traffic occurred yet ZERO fault effects landed. RED-proven: with the TCP fault application disabled, the runtime `faults.rs` TCP test fails AND the warning fires (`vacuous=1`). The `pubsub` gate's fault leg additionally proves non-vacuity by trace-diff (fault vs no-fault at the same seed). |
| Swarm vacuity diagnostic (`PATINA_SWARM_REPORT vacuous=1` + `PATINA WARNING: swarm fault-class selection inert`) | `patina-trace` `SwarmConfigRecord::is_vacuous` + `swarm_record_is_vacuous_exactly_when_there_were_no_candidates`; `patina-runtime` `swarm_with_no_enabled_fault_class_reports_vacuous`; `cargo patina campaign --selftest` `VACUOUS_SWARM` cases; `testbeds/workq/fuzz-sweep.sh --selftest` `swarm_check`/`swarm_field` cases; e2e `swarm_with_zero_candidate_classes_is_reported_and_classified_vacuous` | `--swarm` requested with no fault class enabled: the draw selects nothing, the generation explores the plain configuration, and the run still reads as swarm coverage | **Class** | Fires exactly on an EMPTY candidate set; a draw that dropped every candidate of a non-empty set is legitimate and must not fire. RED-proven three ways: `is_vacuous` forced false fails the e2e fixture, and neutering either classifier fails its own selftest. Warning at run level, classified failure at campaign/sweep level — the fs/net inert-knob tiering. |
| Liveness watchdog (`PATINA_VIOLATION liveness`/`converge`; virtual-time only) | `patina-runtime` (`LIVENESS_MIN_STALL_OPS=4`, 600s budget); `liveness_watchdog_is_schedule_invariant_when_no_violation_fires` | Wedged run silently advancing vtime to budget | **Class** | Schedule-invariant (proven byte-identical op stream); non-vacuity via default-on `PATINA_LIVENESS_REPORT`. Limit: real-I/O-but-no-goal needs an app oracle. |
| Advance-on-spin + frozen-clock churn abort (`PATINA_VIOLATION liveness detail=frozen-clock-churn`) | `patina-runtime` (`SPIN_RESCUE_CLOCK_OPS=1024`, token 1 µs→1 ms, `SPIN_CHURN_ABORT_RESCUES=256`); `advance_on_spin_converges_a_clock_busy_wait_in_tens_of_rescues`, `advance_on_spin_leaves_virtual_time_alone_below_the_trigger`, `a_progress_op_ends_the_spin_episode_so_a_working_run_never_rescues`, `a_guest_sleep_ends_the_spin_episode_so_a_polling_loop_never_rescues`, `advance_on_spin_records_and_replays_byte_identically`, `frozen_clock_churn_aborts_a_loop_that_ignores_the_clock`, `the_liveness_watchdog_fires_first_on_a_spin_that_advance_on_spin_feeds`; e2e `native_calibration_busy_wait_converges_and_replays_identically` | A pre-`main` calibration busy-wait (`fastant`) hung forever at 100% CPU under virtual time, invisible to every detector — the liveness watchdog's window is measured in virtual ns, which a frozen clock never supplies | **Class** | Structural, not pattern-matched on any crate: the trigger is *any* K consecutive clock observations at frozen virtual time with no progress op, so a new calibrating dependency is carried without a rule for it. RED-proven by disabling the rescue (the e2e guest runs >118 s without completing). Non-vacuity is pinned from both sides: one test asserts the clock does NOT move one read short of the trigger, and two assert a working run and a poll-and-sleep loop never rescue at all — so K cannot be silently lowered into perturbing real workloads. The backstop's own non-vacuity is the churn test (it fires) paired with the watchdog test (a smaller budget trips first, cleanly). Limit: the token schedule is tuned constants; a guest whose calibration window exceeds ~250 ms of virtual time would hit the churn abort as a false positive, which the diagnostic names explicitly (rescues + advanced_ns) rather than leaving to inference. |
| Starvation stall backstop (exit 111, wall-clock, `--starve`-only) | native supervisor; fuzz-sweep `STARVATION_STALL` selftest; `a_starvation_stall_is_reported_but_is_not_counted_as_a_bug_found` | Uninterposed atomic spinlock livelock under adversarial deferral | **Class** | Detection backstop (not liveness guarantee); armed only under `--starve` so the always-on canary never wedges. Measured on `turso_stress`: two holds of at most four decisions wedge a run that completes in 26 s with starvation off, and it is still wedged 15 minutes later — so the class is surfaced and deduped but does NOT spend the novel-signature budget, and `campaign --starve-scale-permille N` dials how often the injector fires at all. |
| Teardown yield-point silencing | `patina-native-shim` `completed_sentinel_is_distinct_from_never_registered` + `main_returned_silences_the_root_task_scheduling_point` | `--yield-points` TLS destructor ran hook on removed task; main-thread root-task trailing yield | **Class** | Paired reproducers (`native_yield_points_survive_thread_local_teardown`, `..._main_thread_tls_teardown_is_deterministic`) are point pins; the mechanism invariants are the class pairing. |
| Yield-accounting divergence diagnostic (classified `yield-point replay divergence` + divergent guard site) | `patina-runtime` `classify_yield_divergence`; `native_yield_points_divergence_reports_accounting_and_site` | Load-dependent guard-hit count (joiner-vs-worker `Arc<thread::Inner>` teardown race, Darwin under load) surfacing as an unexplained "trace ended before operation N" | **Class** | Any `TaskYield`-adjacent replay divergence reports per-task record-vs-replay yield counts plus the instrumented site of the unmatched yield (stable `patina_yield_point`-relative offset). The known cause is removed structurally: `patina_thread_join` reaps the worker's host thread on every platform, so the joiner's drop is deterministically the last reference. |
| Report-knob liveness (every suppressor works, on every family, without touching the trace) | `patina-runtime` `source_lints::{report_table_covers_every_declared_suppression_variable, no_report_knob_is_read_from_the_process_environment, report_config_parses_the_documented_spellings}`, `report_suppression_does_not_reach_a_recorded_byte`; `cargo-patina` `every_report_knob_is_documented_in_the_environment_registry`; e2e `native_report_knobs_suppress_every_report_without_touching_the_trace`, `wasi_depth_report_is_suppressed_by_its_knob` | Eight documented suppressors silently inert across the WHOLE native family: the supervisor forwarded only `PATINA_COVERAGE_REPORT` into the cleared guest environment, and the runtime read the rest through `std::env` at `Context::finish`, where the interposed `getenv` returns NULL — so every knob read as unset | **Class** | Two structural halves. The source lints pin the *cause*: a `*_REPORT` variable read from the process environment fails the build, and a declared variable missing from the `Report` table fails too, so a new emitter cannot recreate the habit. The e2e pins the *effect* per family and asserts default-on first, so the suppression assertion cannot pass vacuously. Trace byte-identity (knobs on vs off, plus a cross-suppression replay) is what keeps suppression out of the fingerprint and out of reconciliation. RED-proven on each half independently: reverting either the supervisor forwarding or the shim's config carry fails the e2e; planting a stray env read or an untabled variable fails the lints. |
| Fail-closed binary yield-point detection | `cargo-patina` `yield_point_detection_streams_and_fails_closed` | Yield-point trace replayed against plain binary; ENOMEM fail-open in whole-file read | **Class** | Streaming scan errors loudly on any I/O failure; cross-replay fails closed. |
| Single-choke-point CrashFs construction | `patina-runtime` `fs_image_choke_point_honors_configured_torn_granularity`; shim `native_fs_torn_granularity_byte_reaches_the_guest`, `native_fs_crash_image_is_seed_live_and_deterministic` | Shim pre-installed default-policy CrashFs, ignoring `torn_granularity` + pinning seed 0 | **Class** | Any regression reintroducing a shim-side CrashFs (bypassing fault config) trips byte≠block and seed-liveness. |
| Byte-granularity torn-write geometry | `patina-fs-crash` `byte_granularity_tears_the_final_write...` (+3 siblings) | Whole-block model can't produce sub-block tear (sub-block crash campaign) | **Class** | Property family over the tear geometry. |
| Trace op-tag stability | `patina-abi` `operation_variant_tags_are_pinned_by_name_not_declaration_order` | Variant insertion renumbering existing tags | **Class + point edge** | Class intent (name- not order-based tagging); the literal tag strings are point-ish for those variants. |
| Trace strict-replay + version safety | `patina-trace` `rejects_fingerprint_operation_and_trailing_event_mismatches`, `any_other_format_version_is_refused` | Malformed/hostile trace, a bundle of another format version | **Class** | Fail-closed on any structural mismatch or foreign format version. |
| Guest-argv replay | `cargo-patina` `native_replay_restores_guest_argv_and_normalizes_argv0`; wasi sibling | Real incident: divergent default argv → mid-run op mismatch | **Class** | Structural round-trip; argv[0] normalized so host path never leaks. |
| Fuzz-sweep classifier + planted selftest (a canned case per class) | `testbeds/workq/fuzz-sweep.sh` (`classify`, `is_infra`, `assert_class`) | A `cargo-patina:` refusal read as an environment failure hid every recorded fs-crash generation as `INFRA_ERROR` | **Class** | Planted findings never downgraded; each class has a canned selftest. Only host resource exhaustion on the tool's own error line is `INFRA_ERROR`; any other `cargo-patina:` error is `TOOL_ERROR`, an unreached crash selector is `VACUOUS_CRASH`, and an exit-2 fail-closed abort is `UNEXPECTED_ABORT` in every generation, fs-crash included, all failures (the same infra rule in `testbeds/pubsub/fuzz-sweep.sh`). Selftest runs per-push in CI (stable job); full sweeps run nightly and local/manual. |
| Crash-restart record/replay (one lifecycle trace; replay re-derives the handoff and checks its recorded digest) | `patina-trace` `crash_restart::tests`; `patina-runtime` `crash_writes_the_incarnation_recording_ending_with_the_trigger`, `restarted_incarnation_never_fires_the_crash_selector`; `cargo-patina` `crash_restart_replay_plan_refuses_a_crash_lifecycle_without_a_selector`; e2e `native_fs_crash_restart_record_replays_both_incarnations`, `native_fs_crash_restart_records_are_byte_identical`, `native_fs_crash_restart_swarm_dropped_crash_records_and_replays_one_incarnation` and the `native_fs_crash_restart_replay_refuses_*` family (forged handoff digest, crash at a different operation, a crash the recording never had, a divergence in the restarted incarnation) | Native `--fs-crash-at` refused `--record`/`replay`, so every recorded crash generation failed | **Class** | A divergence anywhere across the restart (crash point, recovered filesystem, either incarnation's operations, incarnation metadata) fails closed by name; the snapshot itself is never trusted from the trace. |
| Campaign classifier (14 classes, envelope-only) + selftest | `crates/cargo-patina/src/campaign.rs` (`classify`, `built_in_class`, `CampaignClass`, `ClassifyRules`) | Guest text deciding a built-in class; an abort blamed on patina that the guest performed itself | **Class** | Every class is proven fireable from structured envelope facts, each paired with a RED twin that removes the one deciding fact; a class-coverage gate fails if any `CampaignClass::ALL` member never fires. `built_in_class` takes a text-free `RunFacts`, so guest output structurally cannot classify. UNCLASSIFIED-loud on any unrecognized nonzero exit. CLI-level `--selftest` runs per-push in CI; real campaigns remain local/manual. |
| Buggify SDK classes | `testbeds/buggify-campaign.sh` (`ALWAYS_VIOLATION` per-gen top severity; `SOMETIMES_UNMET` campaign-level) + selftest | — | **Class** | `ALWAYS_VIOLATION` fires even on exit 0, never downgraded. Selftest covered by the per-push fuzz-sweep selftest; real campaigns local. |
| Campaign aux-store folds (native edge coverage + WASI depth) | `cargo patina campaign --selftest` detectors in `crates/cargo-patina/src/coverage.rs` and `src/depth.rs` (fingerprint mismatch, plateau exactness at N/not N-1/0-disables, watermark idempotency, missing-depth refusal); e2e `campaign_extend_reproduces_aux_store_bytes_for_sites_and_coverage`, `campaign_extend_reproduces_aux_store_bytes_for_wasi_depth`, `campaign_resume_after_a_depth_checkpoint_tear_does_not_double_fold` | Resume double-folding non-idempotent sums; accumulating onto state from a different binary/policy; a depth report that cannot tell "no data" from "zero depth" | **Class** | Every detector is RED-proven: disabling the watermark skip fails both the selftest and the tear e2e. Per-push in CI via the campaign selftest. |
| Coverage-guided scheduling (`campaign --guided`) | `cargo patina campaign --selftest` detectors in `crates/cargo-patina/src/guided.rs` (no-ancestors fallback, stream actually changes, exploit inherits ancestor bytes, prefix-determinism, drought decay); e2e `campaign_guided_steers_reproducibly_and_differs_from_unguided`, `campaign_guided_extend_matches_a_fresh_guided_campaign`, `campaign_guided_resume_after_a_tear_re_derives_the_same_generation`, `campaign_guided_refuses_without_a_novelty_signal` | Guidance that silently matches the unguided stream (inert knob); a resumed guided campaign re-deriving a DIFFERENT generation than it is resuming; steering with no signal to steer by | **Class** | RED-proven both ways: replacing the mutation with a fresh hash fails the inertness detector and the e2e; dropping the below-generation truncation fails the prefix-determinism detector and the campaign tear e2e. The tear e2e searches seed bases for a generation that is both novel and exploited, because either condition alone makes the truncation a no-op and the test vacuous. |
| WASI depth counter completeness | `patina-dst-wasi-host` `depth_source_lints::every_wasi_import_wrapper_counts_its_own_hostcall`, `hostcall_counters_record_every_import_call_exactly`, `zero_fuel_depth_is_refused_rather_than_reported_as_zero` | A newly added WASI import silently missing from the depth report; fuel accounting reporting 0 for a guest that ran | **Class** | The source lint pairs every `func_wrap` name with a `count_hostcall` of the SAME name in definition order, so a new import cannot drop out of depth; RED-proven by deleting one counting line. |
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
3. **macOS guest `dlsym` of a non-deny-trapped blocked symbol** (e.g. `killpg`).
   Measured unreachable for any std guest, but no detector — relies on a guest not
   hand-writing `dlsym`. Low risk by measurement, unpaired in principle.
4. **macOS `mmap(MAP_SHARED)`.** Invisible to the symbol audit (the flag is not
   in the import table); no detector. On Linux `mmap` is interposed and a shared
   mapping is process-local memory or a view of a modeled file's page cache. (`rdseed` no longer belongs here: the TSC
   slice added its decode row, and `classifies_rdtscp_and_rdseed` pins it as a
   refuse-only cpu-nondeterminism finding.)

Closed 2026-07-28 (previously ranked here): CI-absent `strace` (now installed +
`PATINA_REQUIRE_STRACE=1` on every Linux job), classifier selftests absent from
CI (fuzz-sweep + campaign selftests per-push; workq fuzz-sweep campaign nightly +
dispatch), and the missing canonical `entropy_hash` literal in the cross-target
smoke (now pinned).

### Registry/conformance migration acceptance

The [revised syscall contract](docs/arcs/syscall-conformance.md#revised-contract-supersedes-conflicting-decisions-below)
supersedes the historical foreign-inventory and blessed-host acceptance model.
The registry and the live-oracle scenarios are in place (arc checkpoint); a
passing registry build is still not exhaustive conformance evidence. Inherited
coverage debt stays visible: `mise run conformance:coverage` lists every entry
without a scenario or a reasoned exclusion and exits 1 while any remain, and
nothing turns an entry into an accepted pending state or a blanket exclusion.

Proven-red controls: the comparison's unit tests (differential false positives
and negatives, precise expected-failure mismatches, unexpected passes, the
rename errno and statx validity-mask relations with their negative controls),
the catalog and coverage tests (missing identities, disposition mismatches,
unknown symbols, malformed gaps, a scenario without a test), the host
applicability tests (a kernel too old, a kernel implementing an asserted-absent
row), and strict record/replay identity. An unmet host need is reported as not
run with its cause (absent, permission denied, sandboxed, present) and never
disables the patina run's comparison where the native oracle ran. Raw
observations are retained run artifacts. Cross-compilation checks active-target
type boundaries; runtime claims require execution on that OS/architecture.

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

### Filesystem fixup confidence boundary

The conformance comparison accepts Linux-permitted host alternatives only where
the scenario API declares them: `Probe::renameat` records EEXIST/ENOTEMPTY as
alternatives for a nonempty destination (never ENOTDIR, never another
operation), and `Probe::statx` compares the returned mask through the requested
bits plus the validity bits of every field it records. Raw observations and
record/replay identity are unchanged. The comparison's unit tests pair both with
negative controls (a value outside the alternatives, a lost in-mask bit);
filesystem allocation and directory-onto-file gaps remain declared, not waived.

The fs scenarios cover missing-path/closed-fd OMIT, AT_EMPTY_PATH, symlink chown,
retained FIFO timestamps/ownership, zero I/O, EOF after truncation, fallocate
overflow and truthful allocation masks across all three vehicles. Planted dropped
inode effects, early-return/flag regressions, wrapping conversions, BLOCKS claims
and ZERO_RANGE refusal fail those scenarios. Allocation-capacity, crash durability
and positive-latency sampling also have independent red-before-green unit tests.
Runtime repeat/strict-replay tests include NOW and inode-addressed setters with
positive filesystem latency. The runtime has no configurable atime policy.

Remaining intentional gaps: unsigned nanoseconds cannot represent pre-epoch or
wide timestamps; out-of-range conversion returns EINVAL while Linux can clamp.
Allocation extents are not modeled, so statx omits BLOCKS; traditional stat's
length-derived blocks are not an allocation inventory. Anonymous descriptors
without filesystem inodes refuse metadata mutation loudly.

### Signal-wait confidence boundary

The signals-family wait tests pair the host-oracle interruption scenarios with
real managed-thread unit tests in `thread/signals/tests.rs`: recipient choice,
queue unlinking before wake, no extra interruption, restart versus EINTR, mask
restoration, remaining-time writes and signalfd consumption/readiness. Runtime
tests independently record/replay park→wake→next and prove an early wake cancels
its timer. Additional readiness tests distinguish one signal consumer from
multiple deduplicated signalfd reactor notifications, including private-pending
and nonmatching-mask controls. The typed `cargo-patina/tests/native_signals.rs`
integration test compiles `testbeds/native-boundary/signals/blocking_readiness.c`
to check actual libc poll/ppoll/select/pselect/epoll_pwait adapters under SA_RESTART
and verify libc timeout preservation. These detectors
pair with the scenarios' recorded-trace facts; none substitutes for the
conformance tests or for cross-platform execution evidence.

### Signals evidence and residual scope

The family's 22 recorded-trace facts are scenario declarations checked on every
recorded patina run; its 39 unit-test obligations are ordinary tests of their
crates, run by the workspace suite.
`native_signals` and `native_containment` compile the real C layer through
`cargo-patina/tests/common` with guests in `testbeds/native-boundary/signals/`.
They exercise libc and inline SUD, including prctl sharing, reserved masks/actions,
tgkill/tkill, sigwait retry and internal-fatal versus guest-abort finalization;
glibc's `_FORTIFY_SOURCE` file failures (each of the five `_chk` reads past
its buffer, each of the four `__open*_2` needing a mode) are guest aborts too:
glibc's exact diagnostic line, SIGABRT and a finalized trace
(`native_signals::raw::fortify_failures_are_guest_aborts`; a shim definition
removed binds glibc's, which aborts without finalizing, and a misspelled
message fails its line).
The isolated-test harness rejects a missing filter and a planted child failure.
Mixed-batch default death, handler-time pending visibility, transparent
join/mutex/cond handler delivery and no-pending syscall transport cost have
separate unit detectors. Sync queues are retained during handlers to preserve
ownership and notification, unlike interrupted syscall queues. Nested pthread
parking from such a handler is a named fatal refusal before queue mutation or
condvar unlock, not an inner/outer wait-stack model. Child-process detectors cover
timed and untimed waits, including an already-arrived outer grant; uncontended
locks are allowed.

Nested-frame detectors require both mask and stack fixups to survive an inner
handler's frame consumption. A raw C unblock/handler/raw-query test independently
checks that the enclosing SIGSYS return cannot restore the old blocked mask.
The native internal-panic detector injects a panic into a scratch copy of a real
Rust ABI entry, after ownership entry but before locks. Its RED control loads and
validates the incorrectly finalized trace; its passing cases require SIGABRT and
an unloadable trace for unwind and abort strategies, with original and replaced
hooks. On macOS, replaced-hook panic=abort uses libc directly (there is no
public guest-abort interposer), so that case asserts SIGABRT and an incomplete
trace without requiring the Linux interposer's diagnostic. An export-scope audit
and portable nested-scope/thread-isolation unit test pair with the behavioral
detector. Positive controls catch guest panics in main and pthread start on both
platforms, plus pthread once and signal callbacks on Linux, then validate complete
traces. The Rust/C detector links its C object as a native static library so
rustc orders it before the compiler and system runtimes; late link-argument
objects can leave libc or architecture-specific atomic helpers unresolved.
The production hook and guard backstops apply to
POSIX-interposed binaries; alias-free prefixed-C links and libtest retain their
own panic handling.

Startup and locked-diagnostic detectors require that signal/altstack
registration and immediate poll queries must not activate the scheduler or mark
a boundary before harness installation; a context-locked custom-op refusal after
thread activation must emit its diagnostic and abort, not recursively schedule
through captured stdio. The custom-op replay and liveness e2e failure legs have
process-group deadlines. The C custom-op header includes the Rust entry's
fault-eligibility parameter, exercised by the linked C refusal guest.

Poll/select/pselect6 remain network+readiness-owned despite being implemented to
support signal interruption; their dedicated host-conformance oracle has not
landed. A guest restorer's `rt_sigreturn` returns through the host kernel's
(`signal/restorer`, both vehicles and both arches), and `restart_syscall` answers
`EINTR` since no restart is ever pending (`signal/restart`); pidfd signal
sending remains a process trap (no virtual pidfds), a stated deviation from the
signals spec's self-pidfd mention. Ambient host signals and siglongjmp escape from
a handler remain outside verified deterministic behavior.

The portable `native_signals` process/sleep detector checks waitpid's ECHILD
answer without modifying status, getppid=1 (the pid namespace's init), and exact virtual-time sleep, including
byte-identical records and strict replay. Linux interruption/frame semantics
remain cfg-bounded; these portable checks do not promise Linux signal delivery on
macOS. Guest abort finalization is Linux-only; internal fatalities on both
platforms must bypass the public interposer and leave incomplete traces.

The two-axis stateful/schedule minimization test pairs with
`two_axis_replay_oracle_requires_exact_failure_code_and_marker`: planted replay
outcomes distinguish the exact guest failure from success, other failures, and a
replay abort *after* the failure marker. The integration case checks the original
strict replay before reduction and the final replay afterward. The macOS
per-escape-class gate plants `tzset` for time; modeled `time` cannot exercise an
undefined-import refusal.

The realpath registry rows name the actual per-platform exports: `realpath` on
Linux and `realpath$DARWIN_EXTSN` on Darwin (the SDK's `_DARWIN_C_SOURCE` ABI).
The compiled-object registry gate pairs with
`native_abi::realpath_buffer_conventions_agree` and the native canonicalize e2e:
both caller-buffer and allocated-result paths must resolve virtual filesystem
entries. Darwin's legacy plain `realpath` remains uninterposed and audit-refused;
the registry does not normalize it into the supported extended ABI.

Scenario rows are the registry's typed `Syscall` identities: a row the
architecture lacks does not exist to be issued. `signal/wait`'s legacy
`signalfd`, `proc/traps`' `fork` and `proc/absent`'s thirteen x86_64-only
removed numbers are x86_64-only sections; `chown`/`lchown`/`access`/`utime`/
`utimes`/`futimesat`/`pause`/`dup2`/`epoll_wait` keep their libc door on arm64
and issue the generic table's kernel shape through `syscall(2)`. Missing numbers
never become synthetic ENOSYS observations.

### Darwin kernel-entry inventory (source-only)

`registry::darwin::tests` checks BSD/Mach/ARM64 namespace coverage against pinned
XNU sources without executing a kernel. Malformed syntax, duplicate numbers,
lost conditional alternatives, dropped inventory rows, and altered identity or
status are planted failures. A test-only line/guard projection independently
checks every BSD/Mach variant's number, name, condition and status; production
Guard condition substitution must fail this detector. Platform case blocks bind
subcodes to handler statements and preserve removed 0/1 fallthrough to default
logging and return (not panic); planted handler swaps and fallthrough changes
must fail the source checker. `symbol_rows_reference_real_rows` binds explicit
Darwin symbol associations to parsed entries; `syscalls::tests` checks the shared
v2 common field types, status-count summaries and namespace-qualified identities
on all three supported targets, unsupported selectors, and the separation of
source declarations from raw interposition and Linux runtime metadata. These are
inventory gates, not Darwin runtime conformance or containment evidence.

# Testbeds

Guests for exercising Patina end to end. Most harness binaries are ordinary
`std` Rust — no `cfg(patina)`, no runtime dependency — so the same source runs
both natively and under Patina with identical arguments. Where a testbed uses
the cooperative-SUT SDK (`patina-dst`), every macro is inert outside a Patina
build, so the guest still builds and runs as a plain program. The
`checkout-retry-idempotency` testbed is the explicit-context exception: it is a
simulator that depends on the Patina runtime crates directly.

| Testbed | Program under test | Shape | Patina phase exercised |
|---|---|---|---|
| [`workq/`](workq/) | itself — a single-process durable work queue (WAL segments + loopback UDP + worker/producer threads) | guest: server, workers, producers, and invariant checks in one process | WAL crash-recovery, SimNet drop/reorder/jitter, virtual-time visibility timeouts + retries, cooperative buggify faults, fail-closed recovery |
| [`pubsub/`](pubsub/) | itself — a single-process tokio pub-sub broker (TcpListener fan-in over loopback TCP, credit-window backpressure, heartbeat timers) | guest: broker core actor, subscriber, and publisher tasks on one current-thread runtime, plus an exact-delivery audit | the deterministic readiness reactor (kqueue on macOS / epoll on Linux) under real tokio, virtual-time heartbeats + liveness timeouts, schedule-seed exploration, planted async bugs (lost wakeup, short-read framing, stale timeout) |
| [`checkout-retry-idempotency/`](checkout-retry-idempotency/) | an ordinary checkout idempotency ledger called from a deterministic simulator | explicit-context virtual client/service actors over SimNet UDP; a virtual timeout forces one retry | component-level retry/idempotency testing: no host sockets or wall-clock sleeps, non-vacuous retry evidence, planted double-charge selftest |
| [`audit-corpus/`](audit-corpus/) | twenty minimal reproducers, one per widely-used crate (rand, parking_lot, rayon, sysinfo, …) | strict-xfail gate: per-crate, per-platform pinned expectations of the residual unsupported imports | the symbol-classification / interposition surface: `cargo patina audit` over the real ecosystem, drift caught in both directions |
| [`liveness-campaign/`](liveness-campaign/) | a small buggify-gated planted-bug fixture | guest: a deterministic bug the liveness/converge watchdog must catch | liveness/heal-then-converge oracles, buggify activation, `cargo patina campaign` classification + signature dedup |
| [`buggify-wasi/`](buggify-wasi/) | a small `wasm32-wasip1` buggify fixture | guest: several buggify site kinds + a plantable `always!` violation | guest-side buggify lowering on WASI (`patina_sdk` imports), `PATINA_SDK_REPORT` parsing, record/replay determinism |
| [`patina-macro-adopter/`](patina-macro-adopter/) | a standalone crate using `#[patina_dst::test]` as an adopter would | plain `cargo test` drives the macro; the macro re-enters `cargo-patina` for the shim-linked guest | point-solution DST attribute: passing sweep, seeded failure block with repros, PATH-scrubbed missing-CLI refusal, no macro deps |
| [`guided-efficacy/`](guided-efficacy/) | a three-stage "staircase" fixture whose deeper stages unlock only under specific fault-knob bytes | measurement gate: guided vs unguided campaigns race to full edge coverage over N seed bases; exits 1 if `--guided` is slower on any base | the `--guided` selection policy's EFFICACY (not correctness): the acceptance bar for task #31's ancestor-weighting fix; records the measured no-advantage result that blocks any efficacy claim |
| [`cap-std-dirfd/`](cap-std-dirfd/) | itself — a std + `cap-std` program driving a capability-based filesystem | guest: one directory opened through std, then create/read/stat/list/rename/symlink/remove entirely relative to that descriptor (plus nested and cross-descriptor cases) | directory-descriptor-relative (`*at`) resolution: raw `openat`/`statx`/`readlinkat`/`faccessat2`/`mkdirat`/`unlinkat`/`renameat`/`symlinkat` against a real dirfd and `getdents64` over it, proving the libc and SUD paths share one directory-descriptor table; `openat2` as a named deny. Also the permission-bit model (creation modes carried through `open`/`mkdir` and enforced on a later open, `chmod`/`fchmod`, and `EACCES` for read/write/traverse/list/create) and descriptor identity (rename the directory, plant a symlink at the old name, and the descriptor still serves its original node), and the two directory opens' different costs (`O_PATH` charges nothing on the entry and cannot be read; a plain read-only open charges `r`, which is a different bit from the `x` a traversal costs). SUD-only — skips loudly off x86_64-Linux/SUD |
| [`fifo-ipc/`](fifo-ipc/) | itself — a std + libc program driving a named pipe end to end | guest: `mkfifo`/`mkfifoat`/`mknod`, the entry kind through `stat`/`fstat`/`read_dir`, a non-blocking read-open and an `ENXIO` write-open, a blocking reader woken by another task's writer, EOF on the last writer's close, `EPIPE`, `EAGAIN`, `O_RDWR` without waiting, a `0o000` refusal, `fstat` on the descriptor seeing a later `chmod`, a hard link sharing the node and the pipe, unlink-while-open, and an unlinked-but-open FIFO still answering `fstat` (link count 0) and `fchmod` through its descriptor | the FIFO model: the entry in the deterministic filesystem and the transfer over the same in-process pipe machinery `pipe(2)` uses, with blocking opens that park and wake through the scheduler. Clean audit (no allowance), seed-stable on stdout AND captured stderr, record/replay identity, same result across four seeds. Portable — libc only, so it is not SUD-gated |
| [`rustix-default/`](rustix-default/) | itself — a std + rustix program on rustix's DEFAULT (`linux_raw`) backend | guest: raw-syscall clocks / fs / directory iteration / getrandom / SimNet in one process | the syscall-user-dispatch (SUD) acceptance MRE: raw inline syscalls trapped into the runtime; audit downgrade to SUD-managed; getdents64 over a directory fd; seed-stable + record/replay. SUD-only — skips loudly off x86_64-Linux/SUD |
| [`syscall-conformance/`](syscall-conformance/) | the host kernel — forty-nine self-checking probes over the Linux rows (open/read/write/lseek, fstat/newfstatat/statx, mkdirat/renameat/unlinkat, getdents64, symlinkat/readlinkat/linkat, the four timestamps and the utimensat family, ownership and permissions, sizes, the working directory and path resolution, pipe2/dup/fcntl/flock, the descriptor table, clocks and sleeps, getrandom, UDP and TCP over loopback, epoll/eventfd, ppoll, futex, a number past the virtual ABI level answering ENOSYS, and the signals + threads + process family: kill/tkill/tgkill/rt_sigqueueinfo generation, rt_sigaction on both doors, per-thread masks and pending sets, dequeue order, sigaltstack and SA_ONSTACK, handler masks/SA_NODEFER/SA_RESETHAND, delivery on unmask with stacked frames, pause/sigsuspend/sigtimedwait/signalfd waits that must not return early, the per-call restart rule with nanosleep `rem`, SIGPIPE, default termination by the real signal with the core flag, thread-directed delivery pinned to the thread, pthread_kill, set_tid_address clear + futex wake, main-thread raw exit, prctl validation, childless wait, removed numbers), each issued through three vehicles (libc symbol, `syscall(2)`, inline-asm `syscall`) | host-oracle harness: every leg supervised in its own process group under a wall-clock timeout with the observed process outcome appended as the `__termination` event; every probe runs natively (typed JSONL events blessed per `<os>-<arch>` with the oracle kernel in the header), under `cargo patina run` (every difference must be declared in `divergences.toml` with a reason — `pending`, `abort` with a pinned diagnostic, `probe`, or a field — and every declaration must still diverge), under `replay` (byte-identical), and directly under `strace` (no host syscall escapes; the one signal allowance is a self-directed tgkill/tkill/rt_tgsigqueueinfo). `--selftest` plants a divergence, a stale divergence, event-count drift, a wrong/missing termination, a stale abort/probe/pending declaration, both host-gate refusals, a manifest naming a non-row, a raw `openat("/etc/hostname")` leak, the self-signal allowance's bounds and a never-returning process group, and requires each to be refused. The signals family is a FROZEN oracle (`frozen.toml`, `gate.sh --family signals`, one gate: no uncommitted change under the oracle's paths, no declaration outside the frozen set and no pending one left, fmt/clippy/registry gate/full run, and the design obligations — required unit tests and facts from the recorded traces — with the remaining work printed as plain lines; `gate.sh --selftest` proves each mechanism can refuse; spec `docs/arcs/syscall-conformance-signals.md`). The manifest (`probes.toml`) is cross-gated against the registry's `probe` ids; the virtual ABI level and each row's first kernel come from `cargo patina syscalls --format json`. Linux-only; `raw` is x86_64 + SUD; `--fast` (libc vehicle, native + patina) is the `check:fast` tier |

`workq` is the flagship: `workq/run-patina.sh` runs its full self-checking
battery (determinism, record/replay, net/fs faults, crash-recovery, buggify
sweep) on every routine Linux CI run and the daily/manual macOS run.
`workq/fuzz-sweep.sh` is the home of the randomized-but-deterministic
fault-combination campaign (including its schedule-fuzz tier) that runs nightly
on Linux. `liveness-campaign` and `buggify-wasi`
are small fixtures. `buggify-campaign.sh` (this directory) is the shared
campaign layer — Wave 2 `PATINA_SDK_REPORT` parsing, one-run
`cargo patina sites --exercised` join checks, cross-generation coverage
accumulation, the `ALWAYS_VIOLATION`/`SOMETIMES_UNMET` classes — sourced by the
workq, pubsub, and buggify-wasi sweeps.

Conventions:

- Testbed scripts build through Cargo's normal `CARGO_TARGET_DIR`. When the
  variable is unset, the Patina-maintained scripts default to a per-testbed
  directory under the repository target base, such as
  `target/testbeds/workq/patina/workq`; when the local check ladder runs them in
  parallel, `scripts/check.sh` gives each rung its own target directory under
  `target/check/parallel/`. A script must not create a real `testbeds/*/target`
  tree; temporary run data belongs in `mktemp` directories or under its assigned
  target directory.
- The local ladder has one testbed path per tier: `mise run check:fast` runs the
  cheap classifier/gate selftests plus syscall-conformance `run.sh --fast`; the
  full local gate runs the workq/pubsub/macro-adopter `run-patina.sh` batteries,
  WASI/cross smoke, native-shim validation, and the syscall-conformance frozen
  gate (which owns the full conformance run). The audit corpus and full MSRV
  suite are CI/final-gate breadth.
- The sweep/campaign scripts (`fuzz-sweep.sh`, `wasi-buggify-sweep.sh`,
  `audit-corpus/run.sh`) take `--help`, and classifier-carrying ones take
  `--selftest`, proving every outcome class can fire. The `run-patina.sh` gates
  take no arguments: run them and read the legs they print.
- Oracles live inside the guest binaries, and they **report through the verdict
  ABI** (`patina_dst::verdict`), not through printed markers: a self-detected
  breach is a `Violation` under the invariant's label, a deliberate fail-closed
  stop is an `AbortIntent` before the exit, and a clean run is a `Pass` whose
  detail carries the outcome digest. So a violation under Patina is a
  deterministic failing run that `explore`/`minimize` can bisect, and every
  consumer — the campaign classifier, the sweep scripts, a minimize oracle —
  reads the run's `patina.result/v1` envelope (`verdicts[]`, `fault_reports{}`)
  or the ABI's own `PATINA_VERDICT` wire lines. The `WORKQ_*`/`PUBSUB_*` lines
  the guests still print are a human echo; **nothing downstream needs them**, and
  no guest string is baked into patina (a guest that only prints its findings
  declares `classify.patterns` in its campaign spec instead — the level-1 escape
  hatch of `docs/arcs/outcome-channel.md` §4.3).
- Two things the verdict channel deliberately does not carry. **Liveness**: the
  ABI has no liveness kind, and whether a run *should* have converged depends on
  the injected fault configuration the guest cannot see, so a guest's own
  convergence timeout stays a printed diagnostic (`WORKQ_FAILURE` /
  `PUBSUB_FAILURE`) and Patina's liveness watchdog is the structural channel.
  **Which SDK surface reported it**: `always!` lowers to the same `Violation`
  verdict a guest's own audit reports, so a sweep that keeps those classes apart
  scopes its rule to the guest's own label set (`WORKQ_VERDICT_LABELS` /
  `PUBSUB_VERDICT_LABELS`) and leaves every other violation label to the shared
  buggify layer's `ALWAYS_VIOLATION`.
- Every harness's failure path has been demonstrated (corrupted baseline /
  divergent logs / stress-tripped race) — none of these gates is unable to fail.
- Versions are pinned exactly (`=x.y.z` deps), and each testbed is its own
  cargo workspace (an empty `[workspace]` table) so it never touches the root
  manifest.

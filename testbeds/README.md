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
| [`rustix-default/`](rustix-default/) | itself — a std + rustix program on rustix's DEFAULT (`linux_raw`) backend | guest: raw-syscall clocks / fs / directory iteration / getrandom / SimNet in one process | the syscall-user-dispatch (SUD) acceptance MRE: raw inline syscalls trapped into the runtime; audit downgrade to SUD-managed; getdents64 over a SUD directory fd; seed-stable + record/replay. SUD-only — skips loudly off x86_64-Linux/SUD |

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

- The sweep/campaign scripts (`fuzz-sweep.sh`, `wasi-buggify-sweep.sh`,
  `audit-corpus/run.sh`) take `--help`, and classifier-carrying ones take
  `--selftest`, proving every outcome class can fire. The `run-patina.sh` gates
  take no arguments: run them and read the legs they print.
- Oracles live inside the guest binaries (nonzero exit + a machine-parseable
  line: `WORKQ_RESULT …` / `WORKQ_VIOLATION …`, `PUBSUB_RESULT …` /
  `PUBSUB_VIOLATION …`, and so on per testbed), so a violation under Patina is
  a deterministic failing run that `explore`/`minimize` can bisect.
- Every harness's failure path has been demonstrated (corrupted baseline /
  divergent logs / stress-tripped race) — none of these gates is unable to fail.
- Versions are pinned exactly (`=x.y.z` deps), and each testbed is its own
  cargo workspace (an empty `[workspace]` table) so it never touches the root
  manifest.

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

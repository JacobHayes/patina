# Patina

**Weather your Rust into a fine protective patina — before production does.**

Patina is a deterministic simulation testing (DST) runtime for Rust. It runs
*ordinary* `std` programs — no framework, no simulator-aware rewrite — under a
deterministic OS personality: clocks, sleeps, entropy, the filesystem, the
network, threads, and scheduling all route through a seeded virtual runtime
instead of the host OS. Same seed, same run, byte for byte. Different seed,
different schedule and different faults — a reproducible searchlight for the
bugs that normally only show up in production.

```sh
cargo patina run ./my-server --seed 42                       # a deterministic run
cargo patina run ./my-server --seed 42 --record run.patina   # record it
cargo patina replay ./my-server run.patina                   # reproduce it exactly, flag-free
cargo patina explore run ./my-server --seeds 1000            # hunt for a failing seed
```

Patina is **experimental**. It is developed in the open, validated hard (see
[VALIDATION.md](./VALIDATION.md)), and not yet published to crates.io — build it
from source. APIs and the trace format will change.

## Why

Distributed systems, storage engines, and concurrent code fail under schedules
and fault timings that ordinary tests almost never produce and never reproduce.
The FoundationDB / Antithesis lineage showed the fix: make the whole world —
time, randomness, I/O, scheduling — a pure function of a seed, then search seeds
for disasters and replay the ones you find. No more flaky tests: a failure is a
seed, and a seed is a repro.

Existing Rust DST tools (MadSim, Turmoil) prove the value but ask your code and
every dependency to use simulator-aware libraries. Deterministic hypervisors
(Antithesis) attack it from the other side by controlling the entire machine.
Patina sits between: it puts the deterministic boundary at the *Rust platform
layer*, below your application and dependencies, using link-time interposition —
so plain `std::fs`, `std::net`, `std::thread`, `SystemTime`, and seeded entropy
just work deterministically, and stock async runtimes like tokio run unmodified
over interposed kqueue/epoll reactors.

```text
your app and its dependencies      (unchanged)
  -> std / libc-compatible shims
  -> Patina deterministic ABI
  -> virtual drivers + deterministic scheduler + trace
```

The boundary **fails closed**: an effect Patina does not model is a loud,
pre-run refusal — never a silent escape to the host.

## Quickstart

Requires stable Rust (MSRV 1.86) and a C compiler.

```sh
git clone https://github.com/JacobHayes/patina
cd patina
cargo build --release -p cargo-patina
export PATH="$PWD/target/release:$PATH"    # `cargo patina` now resolves
```

Save this as `lottery.rs` — plain `std`, nothing Patina-specific:

```rust
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn main() {
    let start = Instant::now();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write(b"lottery");
    let ticket = h.finish() % 1_000_000;
    std::thread::sleep(std::time::Duration::from_secs(3600)); // costs no wall time
    println!(
        "ticket={ticket:06} epoch={}s elapsed={}s",
        now.as_secs(),
        start.elapsed().as_secs()
    );
}
```

Run it under the deterministic runtime (`run` builds sources on the fly):

```sh
$ cargo patina run lottery.rs --seed 1
ticket=817442 epoch=0s elapsed=3600s
$ cargo patina run lottery.rs --seed 1
ticket=817442 epoch=0s elapsed=3600s      # identical: entropy is seeded
$ cargo patina run lottery.rs --seed 2
ticket=361331 epoch=0s elapsed=3600s      # a different world
```

The hour-long sleep finished instantly — time is virtual — yet `elapsed` still
reads 3600 seconds, and `RandomState` (normally fresh OS entropy per process)
is a pure function of the seed.

Now record a run, replay it byte-for-byte, and sweep seeds:

```sh
cargo patina build lottery.rs --output lottery       # build once for run-many stability
cargo patina run ./lottery --seed 1 --record run.patina
cargo patina replay ./lottery run.patina             # no flags: the trace is authoritative
cargo patina explore run ./lottery --seeds 100       # per-seed outcomes, stops at first failure
```

From here, the [tutorial](./TUTORIAL.md) walks a small program from
instrumentation to a caught, replayed, HTML-rendered bug in about ten minutes.

## How to use it

One CLI, three artifact families, inferred automatically: a **Cargo
package/test** (directory or `Cargo.toml`, run in-process), a **native binary**
(Mach-O/ELF, linked against the deterministic shim), and a **WASI module**
(`wasm32-wasip1`, run under a deterministic host). `run`, `audit`, and `replay`
are source-first: hand them a `.rs` file, a directory, or a `Cargo.toml` and
they build through the same pipeline as `build` first. `test` also has a
source-first native libtest harness mode for one exact test target.

| Verb | What it does | Example |
|---|---|---|
| `run` | Build (if needed) and run an artifact deterministically. | `cargo patina run app.rs --seed 7` |
| `test` | Run Cargo-family tests, or rebuild one libtest harness shim-linked and sweep an exact test. | `cargo patina test . --harness-target my_crate --exact tests::case --seeds 20` |
| `build` | Build the shim-linked native binary (default) or a wasip1 package. | `cargo patina build ./pkg --output app` |
| `audit` | Report the true residual effect surface of a binary; default-deny. | `cargo patina audit app.rs` |
| `replay` | Reproduce a recorded trace; seed/faults/argv restored from it. | `cargo patina replay ./app run.patina` |
| `trace` | Inspect an existing trace's metadata, events, stats, or diff. | `cargo patina trace info run.patina` |
| `explore` | Sweep a seed range, reporting per-seed outcomes. | `cargo patina explore run ./app --seeds 500` |
| `campaign` | Config-driven fault-and-schedule sweep with failure dedup, SDK oracle coverage gate, and native edge-coverage accumulation for yield-point binaries. | `cargo patina campaign ./app --gens 200 --buggify --out-dir out/` |
| `coverage` | Symbolize and roll up a `patina.covmap/v1` map or campaign coverage store. | `cargo patina coverage ./app out/` |
| `sites` | Inventory assertion/oracle instrumentation; optionally join a run or campaign SDK report. | `cargo patina sites --exercised out/` |
| `minimize` | Shrink a failing trace (or seed/params) against an oracle. | `cargo patina minimize bug.patina --output small.patina -- ./oracle` |

Native harness mode is the tight point-solution loop: `cargo patina test
<DIR|Cargo.toml> --harness-target NAME --exact MOD::test --seeds N` runs the
same Cargo libtest target under the native shim with a single libtest thread.
The first failing seed is immediately re-run with `--record`; artifacts land under
`target/patina/dst/...`, and the failure block includes both `cargo patina test`
and `cargo patina replay` repro commands.

For an adopter-shaped guardrail, enable `patina-dst`'s default-off `macros`
feature in dev-dependencies and write `#[patina_dst::test]` on a zero-argument
Rust test function. Plain `cargo test` then discovers `cargo-patina` through
`PATINA_CLI` (absolute path) or `cargo-patina` on `PATH`, rebuilds the same
libtest target shim-linked, and sweeps the test (20 seeds by default). Missing
CLI discovery is a test failure, never a skip.

Every verb has `--help`, and `--help --format json` emits a machine-readable
registry (schema `patina.help/v2`) with progressive disclosure: bare
`cargo patina --help --format json` is a compact index (every verb's summary and
usage forms, the global flags, and the environment protocol), while
`cargo patina <verb> --help --format json` returns that one verb's full flag
detail — handy for scripts and AI agents. Results are available as JSON via
`--format json` (usually a single `patina.result/v1` envelope; `coverage` emits
`patina.coverage/v1`; `trace events` streams `patina.trace.events/v1` JSON Lines;
`trace info|stats|diff` nest their trace payloads in the normal result envelope),
and `--render out.html` writes a self-contained HTML timeline of any traced run.

Repository config lives at `.patina/config.toml`: `[groups.<name>]` tags `sites`
rows by path/label globs, and `[defaults.<verb>]` supplies verb defaults. The
precedence is explicit flag > `PATINA_*` env default > `.patina/config.toml` >
built-in default; applied config is reported via `PATINA_CONFIG ...` and JSON
`config` provenance. Use `--no-config` to ignore the file for a hermetic run.
Replay refuses `[defaults.replay]` because traces are authoritative.

### Fault injection and schedule exploration

Faults are seed-driven, default-off, and recorded into the trace so replay
reproduces them flag-free:

- **Filesystem faults**: `--fs-crash-at open|write|sync|close[:N]` with
  block- or byte-granularity torn writes (`--fs-torn-granularity`), plus
  rate-based `--fs-error-permille` (seeded EIO/ENOSPC/EINTR),
  `--fs-short-permille` (short reads/writes), and `--fs-latency-nanos MIN..MAX`
  (seeded delay before every eligible fs op, so slow I/O reorders against timers
  and peers).
- **Network faults**: `--net-drop-permille`, `--net-jitter-nanos MIN..MAX`,
  `--net-latency-nanos` (base delivery latency, on datagrams and TCP alike).
- **DNS** (native and Cargo families; wasip1 has no resolution surface):
  `--dns-entry NAME=ADDR` defines the host table a guest can resolve — every
  other name is NXDOMAIN — and `--dns-fail-permille` / `--dns-latency-nanos`
  inject seeded resolution failures and delays against the defined names. A
  server that binds `0.0.0.0:PORT` is reachable at any address on that port, so
  ordinary `INADDR_ANY` server code is reached by a resolved name with no
  service-side registration.
- **Timing**: `--sleep-jitter-nanos MIN..MAX` on every guest sleep.
- **Schedule exploration** (native): `--sched-pct` (PCT priority scheduling),
  `--starve` (bounded starvation intervals), `--swarm` (seed-derived fault-class
  subsets). Pair with `cargo patina build --yield-points`, which instruments
  basic blocks so even atomics-only race windows become schedulable.
- **Liveness oracles**: `--liveness-watchdog` (virtual-time no-progress
  detector) and `--converge-within` (heal-then-converge budget).

### The buggify SDK

For faults the runtime cannot inject from outside — "what if this batch path
ran?", "what if this retry fired?" — instrument your code with the
cooperative-SUT SDK, in the style of FoundationDB's `BUGGIFY` and Antithesis
assertions:

```rust
if patina_dst::buggify!("batch-commit") {
    // rare path, taken only under Patina on seed-chosen runs
}
patina_dst::always!(invariant_holds(), "ledger-sorted");   // fatal if ever false
patina_dst::sometimes!(cache_hit, "cache-hit-seen");       // coverage oracle
```

The `patina-dst` crate is dependency-light and every macro is a no-op outside a
Patina build — adopters ship it unconditionally, with no `cfg(patina)` in their
code. Enable at run time with `cargo patina run --buggify`; decisions are pure
functions of the seed, and a `PATINA_SDK_REPORT` line proves sites actually
fired (no vacuous "all clean"). Literal-label SDK macro calls also declare a
link-time site table under Patina, so never-reached `sometimes!`/`reachable!`
oracles appear in reports with `registered_gens=0`. Each row carries
`@file:line`, so `cargo patina sites --exercised <stderr-file>` can join a run
back to the static inventory. `cargo patina campaign` also folds every generation
into `<out-dir>/sites.json` (`patina.campaign.sites/v1`) and fails by default
when a `sometimes!`/`reachable!` oracle is never satisfied; use
`--allow-unmet-sometimes[=MIN_GENS]` only as an explicit waiver. The same store
loads through `cargo patina sites --exercised <out-dir>`.

### Record, replay, branch

`--record` captures every boundary decision into a compact JSON `.patina` trace
(inspect with `jq` or `cargo patina trace info|events`). Replay is strict: the
trace carries the seed, fault knobs, buggify config, guest argv, and native
`--env` values, and any mismatch — changed binary, changed
config, diverging operation — fails closed rather than lying. Cargo and WASI
traces also support *branch timelines*: replay a recorded prefix, then explore a
different seeded suffix from that moment
(`replay … --branch --from N --branch-seed S --branch-id ID`).

### Debug vs release guest builds

Guests build **debug by default**, and debug is the right profile for *finding*
bugs — release is for measuring a guest you already trust. The profile applies to
whichever guest Patina builds on the fly (`run`, `test`); an already-built
artifact carries the profile it was built with.

Why debug finds more bugs:

- **Free failure oracles.** `debug_assert!` in your guest *and every dependency*,
  plus arithmetic overflow checks, are live in debug and compiled out in release.
  They are extra invariants the same seed sweep can trip, so a release build finds
  strictly fewer bugs on the identical seeds.
- **Sharper triage.** Un-inlined frames and exact line numbers keep the
  minimize → replay → backtrace loop pointed at the real culprit instead of an
  optimized-away frame.
- **Denser schedule exploration.** `cargo patina build --yield-points` plants a
  scheduling point at each basic-block coverage guard; optimization collapses
  basic blocks, so a release guest hands the seeded scheduler *fewer* windows to
  preempt an atomics-only race. Yield-point binaries also emit
  `PATINA_COVERAGE_REPORT`; use `run`/`replay --coverage-out PATH` to save a
  `patina.covmap/v1` edge-counter map, then inspect it with
  `cargo patina coverage <binary> <map>`. Campaigns over yield-point native
  binaries persist the union under `<out-dir>/coverage/`, and the offline
  coverage report refuses a campaign store if `<binary>` does not hash to the
  recorded campaign artifact. Campaigns report plateau with `--plateau-after`.
  WASI has no sancov, so that family reports *depth* instead of coverage: every
  run emits `PATINA_DEPTH_REPORT` (fuel plus per-import hostcall counts) and a
  campaign accumulates it under `<out-dir>/depth/`, plateauing on the same
  `--plateau-after` window.
  `campaign --guided` closes the loop: generations are biased toward
  configurations that previously found new coverage or depth, while staying a
  pure function of the seed base and the persisted novelty log.
- **Faster inner loop.** Debug compiles quicker, which dominates when you rebuild
  between every edit.

When release earns its place:

- **Performance measurement.** Timing and throughput numbers are only meaningful
  on an optimized build.
- **Long campaigns.** Debug guests are slow; a multi-thousand-generation sweep or
  a soak run finishes far sooner on a release guest once the bug hunt is over.
- **Release-only codegen.** Optimization changes which code paths — and even which
  machine instructions — the guest takes, so a bug can live only on the release
  path. Release also surfaces CPU-feature backends the audit's instruction scanner
  must handle (the `sha2` crate's x86 SSSE3/SHA-NI path — `pshufb`,
  `sha256rnds2`, … — is the in-repo example).

Build release with `cargo patina run --release <source|package>` (the on-the-fly
guest is compiled optimized), or in two steps — `cargo patina build --release …`
then `run` the resulting artifact.

## Supported today

- **Seeded determinism** for ordinary `std`: filesystem (including directories
  and symlinks), virtual clocks (`SystemTime`/`Instant`/sleeps), entropy,
  UDP datagrams and TCP over a simulated network (both honor the configured
  base link latency), threads with
  mutex/condvar/parking gated one-at-a-time through a deterministic scheduler,
  and deterministic process-state constants.
- **Stock tokio** on macOS and Linux: kqueue/epoll readiness reactors are
  interposed over virtual sockets, pipes, and the virtual clock.
- **Record/replay** with byte-identical traces, trace-format migration, branch
  timelines (Cargo/WASI), and failure-oracle **trace minimization**.
- **Default-deny audit gate**: before a native guest runs, every externally
  resolved symbol must be interposed or provably effect-free; unknown imports
  and raw syscall/clock/entropy instructions are refusals
  (`--allow-unsupported-symbols` is the loud, recorded escape hatch).
- **WASI Preview 1**: the entire 46-function audited import surface, with
  read-only/read-write preopens, resource limits, fuel, sockets via configured
  descriptors, record/replay, and branching.
- **Campaigns**: deterministic multi-generation sweeps with a seven-class
  outcome classifier, failure-signature dedup, and per-failure repro commands.
- **Three adoption modes** (see [USAGE-MODES.md](./USAGE-MODES.md)): SDK-only
  (`patina-dst`), a configure-then-run harness (`patina-dst-harness`), and the
  explicit-context simulator API (`patina-dst-runtime`, with deterministic
  async in `patina-dst-async`; see `testbeds/checkout-retry-idempotency` for a
  user-facing checkout retry/idempotency example).

### Platforms

| Platform | Status |
|---|---|
| macOS | Supported; static instruction scan + import audit for containment. |
| Linux x86_64 | Supported; adds syscall-user-dispatch, which traps raw inline syscalls (e.g. rustix's default `linux_raw` backend) into the runtime, plus a whole-run `strace` containment gate in CI. |
| Linux arm64 | Supported for libc-path binaries; arm64 kernels lack syscall-user-dispatch, so raw-inline-syscall binaries are *refused* (fail closed), not run. |
| `wasm32-wasip1` | Supported via the deterministic WASI host. |

If you use [mise](https://mise.jdx.dev/): `mise run setup` installs toolchains
and targets, `mise run check` runs the validation battery, `mise run demo` runs
a small end-to-end demo.

## What Patina is not (yet)

Honesty is a feature. Current limits, all of which fail loudly rather than
silently:

- **Experimental**: APIs, CLI, and the trace format are unstable; traces are
  tied to the exact binary and config that produced them (by design).
- **Not on crates.io**: build from source. The workspace crates are published
  under `patina-dst-*` names; the SDK crate is `patina-dst`, used as
  `patina_dst::` in code.
- **No process spawning**: `fork`/`posix_spawn` and friends are denied
  (a guest that reaches them aborts deterministically). One process per run.
- **IPv6 and DNS fail closed**. TCP and UDP over the simulated network both
  honor `--net-latency-nanos` and the seeded jitter/drop knobs.
- **Not a hypervisor**: unsupported FFI, dynamic loading, inline assembly
  reading clocks/entropy, and direct host APIs are refused, not virtualized.
  Patina makes *mostly-Rust* programs deterministic; it does not promise to run
  arbitrary native code.
- Host-facing escape hatches (allowlisted host file capture, `--mount`) are
  explicit, read-only, and fingerprinted — never ambient.

## Going deeper

- [TUTORIAL.md](./TUTORIAL.md) — hands-on: instrument, sweep, catch, replay,
  and render a planted bug.
- [USAGE-MODES.md](./USAGE-MODES.md) — the three adoption levels and crate map.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — system design: targets, drivers,
  wrappers, traces, the native shim, and the WASI host.
- [INTENTS.md](./INTENTS.md) — goals, non-goals, trade-offs, and the niche
  Patina occupies.
- [VALIDATION.md](./VALIDATION.md) — claim-by-claim acceptance gates and the
  honest boundary of confidence.
- [IMPLEMENTATION.md](./IMPLEMENTATION.md) — completed and planned slices.
- [AGENTS.md](./AGENTS.md) — guidance for coding agents working in this repo.
- `llms.txt` — a compact machine-oriented map of the CLI and SDK.
- `testbeds/` — real dogfooding targets (`workq`, a durable work queue, is the
  flagship end-to-end demonstration).

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

Requires Rust 1.99 and a C compiler. The repository pins Rust 1.99.1 in
`rust-toolchain.toml`, which rustup installs on first use.

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

One CLI, two artifact families, inferred automatically: a **Cargo
package/test** (directory or `Cargo.toml`, run in-process) and a **native
binary** (Mach-O/ELF, linked against the deterministic shim). `run`, `audit`,
and `replay` are source-first: hand them a `.rs` file, a directory, or a
`Cargo.toml` and they build through the same pipeline as `build` first. `test` also has a
source-first native libtest harness mode for one exact test target.

| Verb | What it does | Example |
|---|---|---|
| `run` | Build (if needed) and run an artifact deterministically. | `cargo patina run app.rs --seed 7` |
| `test` | Run Cargo-family tests, or rebuild one libtest harness shim-linked and sweep an exact test. | `cargo patina test . --harness-target my_crate --exact tests::case --seeds 20` |
| `build` | Build the shim-linked native binary, or a Go main package (`--go`, Linux). | `cargo patina build ./pkg --output app` |
| `audit` | Report the true residual effect surface of a binary; default-deny. | `cargo patina audit app.rs` |
| `replay` | Reproduce a recorded trace; seed/faults/argv restored from it. | `cargo patina replay ./app run.patina` |
| `trace` | Inspect an existing trace's metadata, events, stats, or diff. | `cargo patina trace info run.patina` |
| `explore` | Sweep a seed range, reporting per-seed outcomes. | `cargo patina explore run ./app --seeds 500` |
| `campaign` | Config-driven fault-and-schedule sweep with failure dedup, reproduction-verified findings (a failure that does not reproduce is `NONDETERMINISM`), SDK oracle coverage gate, and native edge-coverage accumulation for `--instrument` binaries. | `cargo patina campaign ./app --gens 200 --buggify --out-dir out/` |
| `coverage` | Symbolize and roll up a `patina.covmap/v1` map or campaign coverage store. | `cargo patina coverage ./app out/` |
| `sites` | Inventory assertion/oracle instrumentation; optionally join a run or campaign SDK report. | `cargo patina sites --exercised out/` |
| `minimize` | Reduce a failing campaign generation (fault knobs first, then its trace), a failing trace, or the seed/params. A generation needs no oracle: the campaign already recorded which verdicts it reported, and those are what the reduction preserves. | `cargo patina minimize --generation 14 --out-dir out/` |
| `syscalls` | Print the native shim's syscall registry: every kernel number with its disposition and reasoning, and the libc symbols that serve it (including the ABI spellings the shim does not define). | `cargo patina syscalls` |

Native harness mode is the tight point-solution loop: `cargo patina test
<DIR|Cargo.toml> --harness-target NAME --exact MOD::test --seeds N` runs the
same Cargo libtest target under the native shim with a single libtest thread.
Use `lib:NAME`, `bin:NAME` or `test:NAME` when target kinds share a name. A
failing seed is re-run with `--record`, and the failure block carries the repro
commands.

For an adopter-shaped guardrail, enable `patina-dst`'s default-off `macros`
feature in dev-dependencies and write `#[patina_dst::test]` on a zero-argument
Rust test function. Plain `cargo test` then discovers `cargo-patina` through
`PATINA_CLI` (absolute path) or `cargo-patina` on `PATH`, rebuilds the same
libtest target shim-linked, and sweeps the test (20 seeds by default). Missing
CLI discovery is a test failure, never a skip.

Any flag can be defaulted from the environment as `PATINA_<FLAG>` (`--seed` ->
`PATINA_SEED`, `--format` -> `PATINA_FORMAT`); a typed flag still wins, and help
shows each flag's variable. `PATINA_RT_*` is reserved for the runtime's internal
control plane.

Every verb has `--help`, and `--help --format json` emits a machine-readable
registry (schema `patina.help/v2`) with progressive disclosure: bare
`cargo patina --help --format json` is a compact index (every verb's summary and
usage forms, the global flags, and the environment protocol), while
`cargo patina <verb> --help --format json` returns that one verb's full flag
detail — handy for scripts and AI agents. Results are available as JSON via
`--format json` (usually a single `patina.result/v1` envelope; `coverage` emits
`patina.coverage/v1`; `syscalls` emits `patina.syscalls/v3`; `trace events`
streams `patina.trace.events/v1` JSON Lines;
`trace info|stats|diff` nest their trace payloads in the normal result envelope),
and `--render out.html` writes a self-contained HTML timeline of any traced run.

### Fault injection and schedule exploration

Faults are seed-driven and default-off. Fault configurations are recorded
into the trace so replay reproduces them flag-free.

- **Crash restart**: at every successful operation a peer or the disk sees (a
  filesystem change, a network send, a TCP connect, accept or close), native
  `--machine-crash-permille N` takes the machine down with N per-mille odds,
  else `--process-crash-permille M` kills the process with M per-mille odds;
  the first hit terminates the incarnation and restarts it once. A process
  crash keeps the page cache. A machine crash restarts from what the disk
  holds, as ext4 leaves it: metadata rolls back to the last journal commit (an
  `fsync` of a changed inode, `sync`/`syncfs`, or every 5 virtual seconds),
  a file is the prefix that commit recorded, and each block overwritten in
  place since keeps its old or new bytes. The Cargo family refuses crash
  restart.
- **Filesystem faults**: rate-based `--fs-error-permille` (seeded EIO/ENOSPC/EINTR),
  `--fs-short-permille` (short reads/writes), and `--fs-latency-nanos MIN..MAX`
  (seeded delay before every eligible fs op, so slow I/O reorders against timers
  and peers). `--fs-error-at KIND:N[:ERRNO]` fails the Nth op of a kind (as the
  fs fault report names it: `sync`, `sync_all`, `write`, ...) at any seed, so a
  regression check needs no pinned seed; one that never landed makes the run's
  fs fault report vacuous. An `fsync`, `sync` or `syncfs` failed with EIO or
  ENOSPC is a failed writeback, as on Linux: the dirty pages stay readable but
  are marked clean, so a retried `fsync` that succeeds makes none of them
  durable, a machine crash loses them, and `posix_fadvise(DONTNEED)` drops them
  so a re-read sees the disk. The error is reported once per open description
  (`errseq`): by `fsync` (and a `WAIT`ing `sync_file_range`) for the file, by
  `syncfs` for the volume; `sync(2)` reports nothing.
- **Network faults**: `--net-drop-permille`, `--net-jitter-nanos MIN..MAX`,
  `--net-latency-nanos` (base delivery latency, on datagrams and TCP alike).
- **DNS**:
  `--dns-entry NAME=ADDR` defines the host table a guest can resolve — every
  other name is NXDOMAIN — and `--dns-fail-permille` / `--dns-latency-nanos`
  inject seeded resolution failures and delays against the defined names. A
  server that binds `0.0.0.0:PORT` is reachable at any address on that port, so
  ordinary `INADDR_ANY` server code is reached by a resolved name with no
  service-side registration — and a harness can name its own services with
  `HarnessBuilder::dns_service`, which allocates the virtual address for you.
  `campaign --dns-entry` hands the table to a sweep, which then bands both knobs
  per generation and classifies an inert one as `VACUOUS` with the dns plane in its signature.
- **Entropy**: `--entropy-fail-permille` models a guest that starts before the
  kernel's random pool is initialized: a `GRND_NONBLOCK` `getrandom` answers
  `EAGAIN` until a read shows the pool ready. No other entropy API can fail, so
  a guest that makes no such read (any Darwin guest, and Rust's std)
  gets no entropy report. The knob is undiagnosable there, not vacuous.
- **Timing**: `--sleep-jitter-nanos MIN..MAX` on every guest sleep.
- **Schedule exploration** (native): `--sched-pct` (PCT priority scheduling),
  `--starve` (bounded starvation intervals), `--swarm` (seed-derived fault-class
  subsets). `campaign --sched-pct` and `campaign --starve` sweep those policies
  per generation. To make atomics-only race windows schedulable, build with
  `cargo patina build --instrument` and run with `--yield-stride N`: a
  scheduling point every N edges a thread executes, 1 being every edge (densest,
  and by far the most expensive). The stride is a run setting recorded in the
  trace; at the default 0 the same binary keeps only its edge counters, so
  `--coverage-out` and `campaign --guided` work without paying for preemption.
  `campaign --yield-stride` sweeps strides from 1 to 1024 per generation.
- **Liveness oracles**: `--liveness-watchdog` (virtual-time no-progress
  detector) and `--converge-within` (heal-then-converge budget).
  Native call-free compute that starves another managed thread stops by name
  after 10 host seconds (`--compute-watchdog-ms MS`): a known cooperative-runtime
  limit, not a guest bug ([details](ARCHITECTURE.md#native-compute-only-starvation)).

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
patina_dst::verdict(patina_dst::VerdictKind::Violation,    // structured outcome
    "ledger-sorted", "{\"row\": 12}");
```

The `patina-dst` crate is dependency-light and every macro is a no-op outside a
Patina build — adopters ship it unconditionally, with no `cfg(patina)` in their
code. `verdict()` is the machine-readable outcome channel: one ABI verb whose
kind is data, recorded as a trace event (so replay reproduces the verdict stream
and a divergent one fails closed) and surfaced in `--format json` as `verdicts[]`
rather than as text to grep; an `always!` violation reports one automatically.
Enable at run time with `cargo patina run --buggify`; decisions are pure
functions of the seed, and the run's `sdk` facts (and its human
`PATINA_SDK_REPORT` line) prove sites actually fired (no vacuous "all clean").
Literal-label SDK macro calls also declare a link-time site table under
Patina, so never-reached `sometimes!`/`reachable!` oracles appear in reports
with `registered_gens=0`. Each row carries `@file:line`. `cargo patina
campaign` folds every generation into `<out-dir>/sites.json` (`patina.campaign.sites/v1`) and fails by default
when a `sometimes!`/`reachable!` oracle is never satisfied; use
`--allow-unmet-sometimes[=MIN_GENS]` only as an explicit waiver. The same store
loads through `cargo patina sites --exercised <out-dir>`.

### Record, replay, branch

`--record` captures every boundary decision into a compact JSON `.patina` trace
(inspect with `jq` or `cargo patina trace info|events`). Replay is strict: the
trace carries the seed, fault knobs, buggify config, guest argv, and native
`--env` values, and any mismatch — changed binary, changed
config, diverging operation — fails closed rather than lying. A native trace
names its binary by digest, so replaying it against one that differs by a
single byte is refused before the guest starts, naming what differs. Cargo
traces also support *branch timelines*: replay a recorded prefix, then explore a
different seeded suffix from that moment
(`replay … --branch --from N --branch-seed S --branch-id ID`).

### Debug vs release guest builds

Guests build **debug by default**: `debug_assert!` and overflow checks in the
guest and every dependency are extra oracles, frames stay exact for triage,
and `--yield-stride` sees more edges to preempt.
Use `--release` (on `run`, or `build --release` then `run`) for performance
measurement, long campaigns once the hunt is over, and release-only codegen
paths. `--instrument` binaries emit edge coverage (`--coverage-out`,
`cargo patina coverage`), which campaigns accumulate and `campaign --guided`
uses to bias generations toward new coverage.

### proptest

Stock `proptest` needs no adapter under the native shim (`run`, or `test`
harness mode): its RNG seed comes from the run seed, so the cases a property
draws, the failure it hits and what its shrinker reduces that failure to are
all a function of the seed, and a recorded failure replays to the same minimal
case. Two things differ from plain `cargo test`:

- **Failure persistence does nothing.** The guest filesystem is in-memory and
  fresh for every run, and no host directory is visible unless you pass
  `--mount` (read-only), so `proptest-regressions/` files are neither read nor
  written. The seed is the regression record: keep the failing seed (or its
  trace) instead.
- **Stateful tests:** use `proptest-state-machine` for model-based tests of a
  stateful system; it runs on the same seeded runner.

## Supported today

- **Seeded determinism** for ordinary `std`: filesystem (including directories,
  symlinks, permission bits, and named pipes), virtual clocks (`SystemTime`/`Instant`/sleeps), entropy,
  UDP datagrams and TCP over a simulated network (both honor the configured
  base link latency), threads with
  mutex/condvar/parking gated one-at-a-time through a deterministic scheduler,
  and deterministic process-state constants.
- **Stock tokio** on macOS and Linux: kqueue/epoll readiness reactors are
  interposed over virtual sockets, pipes, and the virtual clock.
- **Record/replay** with byte-identical traces, branch timelines
  (Cargo), and failure-oracle **trace minimization**.
- **Default-deny audit gate**: before a native guest runs, every externally
  resolved symbol must be interposed or provably effect-free; unknown imports
  and raw syscall/clock/entropy instructions are refusals
  (`--allow-unsupported-symbols` is the loud, recorded escape hatch).
- **Campaigns**: deterministic multi-generation sweeps with an outcome
  classifier (finding, harness, vacuity and catch-all classes),
  failure-signature dedup, and per-failure repro commands.
- **Three adoption modes** (see [USAGE-MODES.md](./USAGE-MODES.md)): SDK-only
  (`patina-dst`), a configure-then-run harness (`patina-dst-harness`), and the
  explicit-context simulator API (`patina-dst-runtime`, with deterministic
  async in `patina-dst-async`).

### Platforms

| Platform | Status |
|---|---|
| macOS | Supported; static instruction scan + import audit for containment. |
| Linux x86_64 | Supported; adds syscall-user-dispatch, which traps raw inline syscalls (e.g. rustix's default `linux_raw` backend) into the runtime, plus a whole-run `strace` containment gate in CI. |
| Linux arm64 | Supported for libc-path binaries; arm64 kernels lack syscall-user-dispatch, so raw-inline-syscall binaries are *refused* (fail closed), not run. |

On Linux the virtual kernel is pinned to Ubuntu 24.04's 6.8 kernel and glibc
2.39 (`cargo patina --version` names it): `uname` reports 6.8 and a syscall
added later answers `ENOSYS`. The conformance scenarios are authoritative only
on a host running that pin.

If you use [mise](https://mise.jdx.dev/): `mise run check` is
the local landing gate, and `mise run demo` runs a small end-to-end demo. For focused shim ABI
feedback, use `mise run check:native-abi`; the individually selectable native test
targets and their platform coverage are listed in
[testbeds/native-boundary](testbeds/native-boundary/README.md).

## What Patina is not (yet)

Honesty is a feature. Current limits, all of which fail loudly rather than
silently:

- **Experimental**: APIs, CLI, and the trace format are unstable; traces are
  tied to the exact binary and config that produced them (by design), and a
  trace from another format version is refused rather than upgraded.
- **Not on crates.io**: build from source. The workspace crates are published
  under `patina-dst-*` names; the SDK crate is `patina-dst`, used as
  `patina_dst::` in code.
- **No process spawning**: `fork`/`posix_spawn` and friends are denied
  (a guest that reaches them aborts deterministically). One process per run.
- **The network is virtual**: IPv4, IPv6, Unix-domain and netlink sockets see
  one virtual host (`lo`, `eth0` at 10.0.0.1/24, no default route) and names
  resolve only through the run's `--dns-entry` table. TCP and UDP over the
  simulated network both honor `--net-latency-nanos` and the seeded
  jitter/drop knobs.
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
  wrappers, traces, and the native shim.
- [INTENTS.md](./INTENTS.md) — goals, non-goals, trade-offs, and the niche
  Patina occupies.
- [docs/SCOPE.md](./docs/SCOPE.md) — who Patina serves first and the rules new
  surface must meet.
- [VALIDATION.md](./VALIDATION.md) — what is validated, the guarantees and
  their oracles, and known gaps.
- [docs/skills/patina-dst.md](./docs/skills/patina-dst.md) — a tool-agnostic
  agent skill: what Patina is, what it can do, and how to discover the current
  CLI and SDK surface from the generated registry instead of from memory.
- [AGENTS.md](./AGENTS.md) — guidance for coding agents working in this repo.
- `llms.txt` — a compact machine-oriented map of the CLI and SDK.
- `testbeds/` — real dogfooding targets (`workq`, a durable work queue, is the
  flagship end-to-end demonstration).

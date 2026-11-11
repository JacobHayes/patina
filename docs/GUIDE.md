# Patina guide

Reference notes for using Patina: installing it for a team or a CI job, the
commands, fault injection, the SDK, recording and replay, and current limits.
Start with the [README](../README.md) and the [tutorial](../TUTORIAL.md);
`patina <command> --help` is the authority on flags.

## Installing

`install.sh` takes `--version 0.3.0` to choose a release and `--prefix DIR` to
install `DIR/bin/patina`:

```sh
curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh -s -- --version 0.3.0
```

The binary carries everything it links into a guest, as source it compiles with
your toolchain on first use (cached under `~/.cache/patina`, or
`~/Library/Caches/patina` on macOS). From the machine it needs:

| To build | The machine needs |
|---|---|
| Rust guests | Rust 1.99 or newer (`cargo`, `rustc`), a C compiler (`cc`), and crates.io for the runtime's dependencies on the first build |
| Go guests (Linux x86_64) | the same, and Go |
| Python guests (Linux) | the same, and `make`, `curl` and `tar`; the first build downloads the pinned CPython source unless `--python-source` names a copy |

A project takes the SDK from the same release as the tool:

```toml
# Cargo.toml
[dev-dependencies]
patina-dst = { git = "https://github.com/JacobHayes/patina", tag = "v0.3.0", features = ["macros"] }
```

```sh
go get github.com/JacobHayes/patina/go/patina@v0.3.0    # Go
```

The tool and the SDK must share a release line (`0.3.x` with `0.3.x`); a
package build that finds another names both and how to match them. Python
guests need no dependency: the tool carries the `patina` module.

In CI, install the tool before the tests. For GitHub Actions:

```yaml
- run: curl -fsSL https://github.com/JacobHayes/patina/releases/latest/download/install.sh | sh -s -- --version 0.3.0
- run: cargo test    # #[patina_dst::test] finds patina on PATH
```

Inside a container, a guest needs the `personality` system call, which
Docker's default seccomp profile refuses: Patina turns address-space
randomization off for every guest. Run the container with
`--security-opt seccomp=unconfined` (or a profile that permits it), or pass
`--allow-randomized-address-layout` for qualified determinism.

On another platform, or to build it yourself:
`cargo install --locked --git https://github.com/JacobHayes/patina --tag v0.3.0 cargo-patina`.

## The commands

One CLI over one kind of artifact: a **native binary** (Mach-O/ELF, linked
against the deterministic shim), run interposed. `run`, `audit`, and `replay`
are source-first: hand them a `.rs` file, a package directory, or a
`Cargo.toml` and they build through the same pipeline as `build` first. `test` runs a
package's own libtest suite, one simulated run per test.

| Verb | What it does | Example |
|---|---|---|
| `run` | Build (if needed) and run an artifact deterministically. | `patina run app.rs --seed 7` |
| `test` | Run a package's own test suite, each test in a simulated world of its own. | `patina test . --seeds 20` |
| `build` | Build the shim-linked native binary, a Go main package (`--go`, Linux), or a Python application frozen into CPython (`--python`, Linux). | `patina build ./pkg --output app` |
| `audit` | Report the true residual effect surface of a binary; default-deny. | `patina audit app.rs` |
| `replay` | Reproduce a recorded trace; seed/faults/argv restored from it. | `patina replay ./app run.patina` |
| `trace` | Inspect an existing trace's metadata, events, stats, or diff. | `patina trace info run.patina` |
| `campaign` | Config-driven fault-and-schedule sweep with failure dedup, reproduction-verified findings (a failure that does not reproduce is `nondeterministic`), SDK oracle coverage gate, and native edge-coverage accumulation for `--instrument` binaries. | `patina campaign ./app --gens 200 --buggify --out-dir out/` |
| `coverage` | Symbolize and roll up a `patina.covmap/v1` map or campaign coverage store. | `patina coverage ./app out/` |
| `minimize` | Reduce a failing campaign generation's fault knobs (and record the minimal-knob trace), or a failing run's `--param` set. A generation needs no oracle: the campaign already recorded which verdicts it reported, and those are what the reduction preserves. | `patina minimize --generation 14 --out-dir out/` |
| `syscalls` | Print the native shim's syscall registry: every kernel number with its disposition and reasoning, and the libc symbols that serve it (including the ABI spellings the shim does not define). | `patina syscalls` |

`patina test [DIR|Cargo.toml]` runs an existing test suite unmodified, with
`cargo test`'s selection (`-p`, `--workspace`, `--lib`, `--bin NAME`,
`--test NAME`, a trailing filter and `--exact`); `--skip PATTERN` leaves
tests out as libtest's own `--skip` does, and `--skip-target NAME` leaves out a
whole target. Each target is built shim-linked once; each test then runs on
each seed (`--seed N`, `--seeds N`) as its own run, `--jobs` at a time
(default: half the CPUs the process may use, so a shared machine keeps room),
and ends in one outcome. A finding is
re-run recorded, and its block carries the `rerun:` and `replay:` commands.
`--no-run` builds and prints where each target's guest is staged
(`target/patina/dst/PACKAGE/KIND/TARGET/guest`). A test that reaches
something Patina does not model is `unsupported` (exit 2), never a pass;
`--accept-unsupported TEXT` lets such a test, when its stop names TEXT, not
fail CI while it still reports as `unsupported`.

For an adopter-shaped guardrail, enable `patina-dst`'s default-off `macros`
feature in dev-dependencies and write `#[patina_dst::test]` on a zero-argument
Rust test function. Plain `cargo test` then discovers `patina` through
`PATINA_CLI` (absolute path) or `patina` on `PATH` and runs `patina test`
for that one test (20 seeds by default). A
missing tool is a test failure that prints the install line, never a skip.

Any flag can be defaulted from the environment as `PATINA_<FLAG>` (`--seed` ->
`PATINA_SEED`, `--format` -> `PATINA_FORMAT`); a typed flag still wins, and help
shows each flag's variable. `PATINA_RT_*` is reserved for the runtime's internal
control plane.

Every verb has `--help`, and `--help --format json` emits a machine-readable
registry (schema `patina.help/v2`) with progressive disclosure: bare
`patina --help --format json` is a compact index (every verb's summary and
usage forms, the global flags, and the environment protocol), while
`patina <verb> --help --format json` returns that one verb's full flag
detail — handy for scripts and AI agents. Results are available as JSON via
`--format json` (usually a single `patina.result/v2` envelope; `coverage` emits
`patina.coverage/v1`; `syscalls` emits `patina.syscalls/v3`; `trace events`
streams `patina.trace.events/v1` JSON Lines;
`trace info|stats|diff` nest their trace payloads in the normal result envelope),
and `--render out.html` writes a self-contained HTML timeline of a run or a
replay, recorded or not.

A `run` that does not end clean prints the command that repeats it
(`patina: reproduce: ...`, and `reproduce` in the JSON): the replay of its
recording when it kept one, else the same `run` with its seed spelled out.

A campaign keeps its state in `--out-dir` (default `patina-campaign-out`). The
same command given again continues that campaign: it finishes an interrupted
one, runs the missing generations when `--gens` is larger, and otherwise runs
nothing and reports the recorded result. A command for another artifact or
other settings is refused. `--extend N` and `--resume` continue the recorded
campaign without repeating its command.

The outcomes and exit codes of every command are the table in the
[README](../README.md#outcomes-and-exit-codes).

## Fault injection and schedule exploration

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
  place since keeps its old or new bytes.
- **Filesystem faults**: rate-based `--fs-error-permille` (seeded EIO/ENOSPC/EINTR,
  and on procfs, which has no storage, only ENOMEM),
  `--fs-short-permille` (short reads/writes, procfs's reads too), and `--fs-latency-nanos MIN..MAX`
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
  service-side registration.
  `campaign --dns-entry` hands the table to a sweep, which then bands both knobs
  per generation and classifies an inert one as `vacuous` with the dns plane in its signature.
- **Entropy**: `--entropy-fail-permille` models a guest that starts before the
  kernel's random pool is initialized: a `GRND_NONBLOCK` `getrandom` answers
  `EAGAIN` until a read shows the pool ready. No other entropy API can fail, so
  a guest that makes no such read (any Darwin guest, and Rust's std)
  gets no entropy report. The knob is undiagnosable there, not vacuous.
- **Timing**: `--sleep-jitter-nanos MIN..MAX` on every guest sleep.
- **Schedule exploration** (native): `--sched-pct` (PCT priority scheduling) and
  `--swarm` (seed-derived fault-class subsets). `campaign --sched-pct` sweeps
  PCT per generation. To make atomics-only race windows schedulable, build with
  `patina build --instrument` and run with `--yield-stride N`: a
  scheduling point every N edges a thread executes, 1 being every edge (densest,
  and by far the most expensive). The stride is a run setting recorded in the
  trace; at the default 0 the same binary keeps only its edge counters, so
  `--coverage-out` and `campaign --guided` work without paying for preemption.
  `campaign --yield-stride` sweeps strides from 1 to 1024 per generation.
- **Liveness oracles**: `--liveness-watchdog` (virtual-time no-progress
  detector) and `--converge-within` (heal-then-converge budget).
  A native guest that goes 10 host seconds without a call that reaches the
  runtime stops by name (`--compute-watchdog-ms MS`), as a `timeout`: a known
  cooperative-runtime limit, not a finding
  ([details](../ARCHITECTURE.md#native-compute-only-starvation)).

## The SDK

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
Effects Patina does not model (RPC, S3, devices) go through
`patina_dst::custom_op` / `custom_op_faultable`: recorded, replayed without
re-running, and, for the faultable form, failed on demand with
`--custom-op-fail-permille`.
Enable at run time with `patina run --buggify`; decisions are pure
functions of the seed, and the run's `sdk` facts (and its human
`PATINA_SDK_REPORT` line) prove sites actually fired (no vacuous "all clean").
Literal-label SDK macro calls also declare a link-time site table under
Patina, so never-reached `sometimes!`/`reachable!` oracles appear in reports
with `registered_gens=0`. Each row carries `@file:line`. `patina
campaign` folds every generation into `<out-dir>/sites.json` (`patina.campaign.sites/v1`) and fails by default
when a `sometimes!`/`reachable!` oracle is never satisfied; use
`--allow-unmet-sometimes[=MIN_GENS]` only as an explicit waiver. The same store
is the source of truth for which sites the build declares. A declared `always!` that no generation evaluates is listed as `UNEVALUATED` (and under `always_unevaluated` in the JSON); it is reported, not gated.

## Record and replay

`--record` captures every boundary decision into a compact JSON `.patina` trace
(inspect with `jq` or `patina trace info|events`). Replay is strict: the
trace carries the seed, fault knobs, buggify config, guest argv, and native
`--env` and `--param` values, and any mismatch — changed binary, changed
config, diverging operation — fails closed rather than lying. A native trace
names its binary by digest, so replaying it against one that differs by a
single byte is refused before the guest starts, naming what differs.

## Debug and release builds

Guests build **debug by default**: `debug_assert!` and overflow checks in the
guest and every dependency are extra oracles, frames stay exact for triage,
and `--yield-stride` sees more edges to preempt.
Use `--release` (on `run`, or `build --release` then `run`) for performance
measurement, long campaigns once the hunt is over, and release-only codegen
paths. `--instrument` binaries and Go guests emit edge coverage
(`--coverage-out`, `patina coverage`), which campaigns accumulate and
`campaign --guided` uses to bias generations toward new coverage.

## proptest

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

## What is modelled

- **Seeded determinism** for ordinary `std`: filesystem (including directories,
  symlinks, permission bits, and named pipes), virtual clocks (`SystemTime`/`Instant`/sleeps), entropy,
  UDP datagrams and TCP over a simulated network (both honor the configured
  base link latency), threads with
  mutex/condvar/parking gated one-at-a-time through a deterministic scheduler,
  and deterministic process-state constants.
- **Stock tokio** on macOS and Linux: kqueue/epoll readiness reactors are
  interposed over virtual sockets, pipes, and the virtual clock.
- **Record/replay** with byte-identical traces, and failure-preserving
  **knob and parameter minimization**.
- **Default-deny audit gate**: before a native guest runs, every externally
  resolved symbol must be interposed or provably effect-free; unknown imports
  and raw syscall/clock/entropy instructions are refusals
  (`--allow-unsupported-symbols` is the loud, recorded escape hatch).
- **Campaigns**: deterministic multi-generation sweeps that file each
  generation under one outcome, group failures by signature, and print a
  reproduce command for each.
- **The SDK** (see [USAGE-MODES.md](../USAGE-MODES.md)): `patina-dst`, with
  run parameters through `patina_dst::param`.

## Limits

Current limits. Each fails loudly rather than silently:

- **Experimental**: APIs, CLI, and the trace format are unstable; traces are
  tied to the exact binary and config that produced them (by design), and a
  trace from another format version is refused rather than upgraded.
- **Not on crates.io**: the tool comes from GitHub releases and the SDK from
  the release's git tag (see [Installing](#installing)). The SDK crate is
  `patina-dst`, used as `patina_dst::` in code.
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
- Host-facing escape hatches (allowlisted host files via `--mount`) are
  explicit, read-only, and fingerprinted — never ambient.

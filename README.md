# Patina

**Weather your Rust into a fine protective patina - before production does.**

Patina is an experimental deterministic execution and simulation-testing system for Rust.

The goal is to compile Rust programs for a deterministic OS personality: standard platform effects such as filesystem access, networking, clocks, randomness, process state, and scheduling route through Patina instead of escaping directly to the host OS.

```sh
cargo patina test --seed 123
cargo patina test --seed 123 --record trace.patina
cargo patina test --replay trace.patina
```

`cargo dst` is an alias for `cargo patina`.

## Status

Patina is experimental. V1 and V2 are implemented end-to-end at the **explicit Rust API boundary**, V3 covers the **entire audited WASI Preview 1 surface**, and V4/V5 have substantial foundations:

- `cargo-patina` and `cargo-dst` configure seeded, record, replay, named-timeline, branch, budgeted, parameterized, and multi-seed exploration runs;
- both `cfg(patina)` and `cfg(dst)` are injected into Cargo builds;
- seeded entropy, virtual time, in-memory and crash-checkpoint filesystems, cooperative scheduling, and virtual datagrams are available through `patina::Context`;
- deterministic async is available at the explicit boundary through `patina-async` (re-exported as `patina::rt`, plus `patina::block_on`): a single-threaded `block_on`/`spawn` executor with virtual-time `sleep`/`timeout` and async TCP/UDP futures, all riding the existing recorded scheduler, network, and clock operations so runs stay record/replay byte-identical (`crates/patina-async/examples/async_echo.rs`);
- fault and latency wrappers model packet loss, duplication, delay, jitter, reorder, and partitions;
- trace format 2 strictly matches operations/outcomes and stores exact-prefix, seeded-suffix branch timelines;
- failure-oracle delta debugging minimizes main timelines and leaf branch suffixes;
- explicitly allowlisted read-only host files can be captured, then replayed without host access; branch capture misses fail closed;
- WASI Preview 1 execution supports the entire audited import surface (46 functions) — arguments, environment, clocks, entropy, virtual files/directories with hard links, symlinks, and timestamp mutation, descriptor flag/rights mutation and renumbering, polling, configured datagrams, stdio, and exit — plus read-only/read-write preopens, fail-closed resource limits, fuel, record/replay, and branching;
- a prefixed native C ABI and an opt-in POSIX symbol layer route filesystem, clock, sleep, entropy, captured-stdio, and pthread calls into Patina;
- `cargo patina native-build`/`native-run` package the shim build/link/startup path for single-source Rust programs, with constructor auto-initialization from the `PATINA_*` protocol (no explicit init calls in application code);
- native threads are managed deterministically on macOS and Linux: real host threads are gated one-at-a-time through the deterministic scheduler (interposed pthread symbols on macOS; interposed `syscall`/`SYS_futex` routing on Linux, where Rust `std` sync bypasses pthread), so locks held across boundary operations cannot deadlock;
- native UDP datagrams and zero-latency TCP streams flow through `SimNet` via ordinary `std::net::{UdpSocket,TcpListener,TcpStream}` — sockets are fully virtual, blocking receives/accepts/writes park through the scheduler, and IPv6/DNS fail closed; process-state reads return deterministic constants while process spawning stays denied;
- macOS and Linux probes verify ordinary `std::fs` (including `read_dir` over driver-ordered deterministic listings, and symlink create/read/stat with one-hop terminal follow), `SystemTime`, `Instant`, sleep, printing, threads with deterministic thread ids, and standard-library entropy through that linked shim, including cross-process seed stability and record/replay through a supervisor-provided trace descriptor (`PATINA_TRACE_FD`);
- one ordinary-`std` smoke program builds for wasm32-wasip1, native macOS, and native Linux and produces byte-identical deterministic output on all three;
- `native-audit` is a strict per-platform import allowlist: any import that is not an explicitly listed effect-free host-deferred symbol (or caller-`--allow`ed control plane) fails closed as unknown, so a missed interposer is an audit failure rather than a silent escape; alias forms (`$NOCANCEL`, `__`-prefixes) are normalized, known host-effect names keep descriptive categories, and direct syscall / CPU clock/entropy instructions are still rejected by scanning. `native-run` enforces this audit as a pre-run default-deny gate before the guest executes and hard-errors, naming the symbols, on any unmodeled blocking/time/scheduling surface (with `--allow-unsupported-symbols` as a loud, recorded escape hatch); on macOS std's thread `Parker` blocks on a libdispatch semaphore, which the shim interposes and routes through the scheduler and virtual clock so `thread::park`/`recv_timeout` stay deterministic;
- a Linux `strace` containment pass verifies the validation probe performs zero file/network/clock/entropy syscalls outside an exact loader/runtime prelude across the whole run (vDSO reads are covered by the libc-interposition probes instead);
- crash-consistency models cover seeded torn writes, rename atomicity, directory durability, and crash/restart; traces migrate from prior supported formats in memory; `patina-bench` gates trace bytes per event in CI;
- a cooperative-SUT SDK (FoundationDB `BUGGIFY`- and Antithesis-style) lives in the `patina` crate under a feature inversion — default features are the dependency-light SDK, and the explicit facade (`run`/`run_with`, `Context`, `rt`) is behind the `runtime` feature. `buggify!`/`buggify_with_prob!`/`buggify_delay!`/`buggify_knob!` inject seed-deterministic faults at labeled sites, `always!`/`sometimes!`/`reachable!` are assertion and coverage oracles, and `patina::rng()` bridges to the run seed. Every macro is a no-op or plain fallback outside a Patina build (no `cfg(patina)` in adopter code). `cargo patina native-run --buggify[=permille]` enables it; decisions are pure functions of the seed (never recorded per evaluation), the active-site set/knobs/cutoff go in the trace metadata for self-contained replay, and a `+buggify` fingerprint keeps buggify traces from cross-replaying with a non-buggify build. A `PATINA_SDK_REPORT` line reports registered/activated/fired sites and coverage.

Native interposition of third-party async runtimes and non-zero TCP latency over SimNet remain unfinished. Calling host APIs directly without the controlled shim remains outside Patina. APIs and the trace format are expected to change.

See [VALIDATION.md](./VALIDATION.md) for claim-by-claim acceptance gates and [IMPLEMENTATION.md](./IMPLEMENTATION.md) for completed and planned slices.

## Try the vertical slice

```sh
cargo build -p cargo-patina
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina --example deterministic --seed 123
rm -f /tmp/demo.patina
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina --example deterministic --seed 123 --record /tmp/demo.patina
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina --example deterministic --replay /tmp/demo.patina
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina --example deterministic --branch /tmp/demo.patina --from 1 --branch-seed 456 --branch-id branch-456
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina --example deterministic --replay /tmp/demo.patina --timeline branch-456
PATH="$PWD/target/debug:$PATH" cargo patina run -p patina --example simulation --seed 321
PATH="$PWD/target/debug:$PATH" cargo patina explore run --seeds 10 -p patina --example deterministic
```

Applications in this slice deliberately perform controlled effects through the context:

```rust
patina::run(|ctx| {
    let bytes = ctx.entropy_bytes(16)?;
    ctx.write_file("/state/value", &bytes)?;
    ctx.sleep_for(1_000_000)?;
    Ok(())
})?;
```

A changed source/Cargo input, Rust toolchain, command shape, event argument, event order, or deterministic driver outcome makes strict replay fail rather than fall back. Record mode also refuses an existing trace path or active recorder; the current implementation does not aggregate multiple `patina::run` contexts into one bundle.

WASI foundation commands:

```sh
rustup target add wasm32-wasip1
cargo patina wasi-build --manifest-path path/to/guest/Cargo.toml
cargo patina wasi-audit path/to/guest.wasm
cargo patina wasi-run path/to/guest.wasm --seed 123
cargo patina wasi-run path/to/guest.wasm --seed 123 --preopen /data:ro --preopen /scratch:rw --max-memory-pages 64
cargo patina wasi-run path/to/guest.wasm --seed 123 --record /tmp/wasi.patina
cargo patina wasi-run path/to/guest.wasm --replay /tmp/wasi.patina
cargo patina wasi-run path/to/guest.wasm --branch /tmp/wasi.patina --from 0 --branch-seed 456 --branch-id branch-456
scripts/validate-wasi.sh
```

The audit and runner reject non-WASI modules and Preview 1 imports outside the explicit host allowlist. Filesystem and polling work over Patina drivers; `--preopen GUEST[:ro|:rw]` mounts virtual directories with host-enforced write policy, and `--max-*` flags override the fail-closed resource limits (both are part of the replay fingerprint). Preview 1 datagrams use explicitly configured `--socket 'FD=BIND->PEER'` descriptors; ambient host sockets are never inherited.

Native shim and audit validation, plus the cross-target smoke test:

```sh
scripts/validate-native-shim.sh
scripts/smoke-cross-target.sh
cargo patina native-build path/to/program.rs --output /tmp/program
cargo patina native-run /tmp/program --seed 123 --record /tmp/native.patina
cargo patina native-audit path/to/native-binary
```

Failure-oracle minimization writes each candidate to `PATINA_MINIMIZE_TRACE`; the oracle exits nonzero only when the selected failure is preserved:

```sh
cargo patina minimize failure.patina --output reduced.patina -- ./failure-oracle
cargo patina minimize branches.patina --timeline failing-leaf \
  --output reduced.patina -- ./failure-oracle
```

`native-build` compiles a single Rust source against the packaged shim (embedding the POSIX layer and injecting `cfg(patina)`/`cfg(dst)`), and `native-run` supervises the binary with seeded, record, or replay modes — application code needs no Patina-specific calls. The native validation script builds its ordinary-`std` probes through that packaged path, compiles mixed C/Rust fixtures for the prefixed and POSIX symbols, executes ordinary macOS/Linux `std` filesystem/directory/symlink/time/entropy/stdio/thread/UDP calls through Patina — including mutex/condvar contention with a lock held across a boundary operation and multi-thread datagram exchange with scheduler-decided arrival order — records and replays the fully interposed probes through `PATINA_TRACE_FD`, audits the resulting binaries against the strict allowlist, verifies rejection of direct-syscall/unmanaged-thread and unknown-import fixtures, and on Linux runs the whole-run `strace` containment pass. Linux large-file/stat variants and deterministic startup checks are covered. The smoke script builds one ordinary-`std` program for wasm32-wasip1 and the native host and requires identical seeded, recorded, and replayed output. Beyond single sources, `native-build` also compiles whole Cargo packages through the same packaged path, audited, recorded, and replayed under the `cargo-patina` end-to-end package test.

## Why Patina exists

Distributed systems, storage systems, concurrent code, and I/O-heavy programs fail under schedules and faults that are hard to reproduce with ordinary tests.

Existing Rust deterministic simulation tools prove the value of simulated runtimes and virtual environments, but they usually require applications and dependencies to use simulator-aware libraries. Deterministic hypervisors, such as Antithesis, solve this from the other direction by controlling the whole machine boundary.

Patina targets the layer between those approaches: less intrusive than rewriting code around simulator-aware libraries, but Rust-specific and toolchain-integrated rather than a full VM. It puts the deterministic boundary at the Rust platform layer:

```text
Rust app and dependencies
  -> std / runtime / shims
  -> Patina deterministic ABI
  -> virtual drivers and deterministic scheduler
```

The user should not need to audit every dependency to check whether it used the correct mockable interface. If code uses `std::fs`, `std::net`, clocks, entropy, or compatible native APIs, those effects should flow through Patina’s deterministic boundary.

## What Patina is designed to provide

The complete design combines several related capabilities:

- **Deterministic execution**: rerun with the same seed and get the same behavior.
- **Simulation testing**: explore adverse schedules, network behavior, filesystem faults, time, crashes, and randomness.
- **Replay**: reproduce a previous run from a trace.
- **Branching from traces**: replay to a recorded moment, then explore a different deterministic suffix from there.
- **Trace bundles**: store the seed, decision policy metadata, decision logs, and branch relationships in a `.patina` file.
- **Explicit host capture**: record permitted host I/O for exact replay. Open-ended exploration requires deterministic drivers.
- **Fail-closed enforcement**: unsupported nondeterminism errors instead of silently reaching the host.
- **Pluggable drivers**: swap virtual filesystems, networks, clocks, entropy sources, and schedulers.

## Design summary

Patina separates three concerns:

1. **Data plane**: small stable interfaces for effects like fs, net, time, entropy, and scheduling.
2. **Construction plane**: typed Rust code configures concrete drivers and scenario topology.
3. **Experiment plane**: CLI/runtime parameters control seeds, traces, budgets, record/replay modes, and simple knobs.

Driver-specific behavior is code-first. For example, a simulated network driver may expose route registration or fake HTTP handlers, but those methods do not belong to the core network interface.

A seed is interpreted by deterministic decision policies: scheduler, network, filesystem, and exploration logic that choose outcomes for sources of nondeterminism. Record, replay, fault injection, and latency are wrapper drivers that compose around concrete drivers such as `MemFs`, `CrashFs`, `SimNet`, `VirtualClock`, and `SeededEntropy`.

## Target model

Patina is Rust-first.

It targets:

- **WASI Patina**: a clean target where host effects are explicit imports;
- **native Linux/macOS Rust Patina**: the primary long-term target for mostly Rust programs;
- **native ABI shims**: compatibility layers for libc/POSIX-style dependencies.

Patina is not a deterministic hypervisor and does not promise to make arbitrary native applications deterministic. Unsupported FFI, direct syscalls, inline assembly, dynamic loading, and CPU nondeterminism are denied unless explicitly supported.

## Documentation

- [INTENTS.md](./INTENTS.md): project intent, goals, non-goals, trade-offs, and niche.
- [ARCHITECTURE.md](./ARCHITECTURE.md): system architecture, crate layout, interfaces, wrappers, tracing, and target model.
- [VALIDATION.md](./VALIDATION.md): acceptance levels and verification commands.
- [IMPLEMENTATION.md](./IMPLEMENTATION.md): implementation slices, status, and dependency order.
- [AGENTS.md](./AGENTS.md): guidance for coding agents working in this repository.


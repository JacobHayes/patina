# Patina

**Weather your Rust into a fine protective patina - before production does.**

Patina is an experimental deterministic execution and simulation-testing system for Rust.

The goal is to compile Rust programs for a deterministic OS personality: standard platform effects such as filesystem access, networking, clocks, randomness, process state, and scheduling route through Patina instead of escaping directly to the host OS.

```sh
cargo patina test --seed 123
cargo patina test --record trace.patina
cargo patina test --replay trace.patina
```

`cargo dst` is an alias for `cargo patina`.

## Status

Patina is experimental. The repository currently captures the intended design and architecture. APIs, crate layout, target support, trace format, and CLI behavior are expected to change.

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

## What Patina provides

Patina combines several related capabilities:

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
- [AGENTS.md](./AGENTS.md): guidance for coding agents working in this repository.


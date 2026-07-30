# Patina Intent

**Patina**: Weather your Rust into a fine protective patina — before production does.

Patina is a deterministic execution and simulation-testing system for Rust programs. It builds code for a deterministic OS personality, routes platform effects through a virtual runtime, and lets tests explore time, scheduling, storage, networking, entropy, crashes, and other production-shaped failures under seed control.

The primary user interface is `cargo patina`.

## Core idea

Patina is not an application mocking framework. The user should not need to audit every dependency to confirm that it uses the "right" traits or test doubles. Ordinary Rust platform APIs such as filesystem access, networking, clocks, randomness, process state, and thread coordination flow through Patina's deterministic boundary.

Patina's boundary sits below application code and above the real OS:

```text
Rust application and dependencies
  -> std / runtime / libc-compatible shims
  -> Patina deterministic ABI
  -> virtual drivers, wrappers, scheduler, trace
  -> optional host access under explicit policy
```

This gives Rust code a deterministic OS personality rather than asking every library to become simulator-aware.

## Goals

Patina exists to make these workflows normal:

- Run a Rust program repeatedly with the same seed and get the same behavior.
- Explore many scheduler, timing, network, filesystem, and crash interleavings quickly, with directed policies (priority-based preemption, starvation, fault-subset swarms) when uniform exploration is not enough.
- Reproduce a failure from a seed and trace.
- Record boundary effects from one run and replay them later.
- Fail loudly when code escapes the deterministic boundary.
- Let application code cooperate with the simulator — seed-driven fault sites (`buggify!`) and `always!`/`sometimes!` oracles — while shipping the same instrumentation inert in production builds.
- Sweep seeds and run multi-generation fault campaigns with classified, deduplicated, reproducible failures.
- Swap virtual drivers without rewriting application logic.
- Let users write code-first simulation topology without a config-based DSL.

## Non-goals

Patina does not try to be a general deterministic hypervisor. It is for programs written primarily in Rust and compiled into Patina's world.

Patina does not promise to make arbitrary native code deterministic. Native libraries, dynamic loading, inline assembly, direct syscalls, CPU entropy instructions, GPUs, and OS-specific behavior are supported only when they pass through an explicit Patina shim or are allowed by policy.

Patina does not remove the need for good models. A simulated filesystem, network, or external service is only as useful as its semantics. Patina provides the boundary and composition model; users and driver authors still choose what production behavior matters.

## The niche

Existing Rust DST tools such as MadSim and Turmoil demonstrate the value of deterministic runtimes, virtual time, simulated networking, and failure injection. However, they require code and dependencies to use simulator-compatible libraries.

Whole-system simulation systems such as Antithesis attack the problem from the other side: place the entire workload in a deterministic machine boundary. While these support black box testing, this adds significant overhead and runtime.

Patina occupies the middle between application-level simulator libraries and deterministic hypervisors:

- below application-level mocks and simulator-aware libraries;
- above a full machine or hypervisor boundary;
- Rust-first;
- compiler/toolchain-aware;
- fail-closed;
- pluggable at the Rust platform boundary.

The intended result is closer to "compile this Rust program for a deterministic platform" than "rewrite this app around testing traits."

## Determinism, replay, and simulation

Patina treats deterministic execution, replay, and simulation as related capabilities rather than separate products.

- **Deterministic execution** means every source of nondeterminism is controlled by a seed, a configured decision policy, a driver model, or a replay trace.
- **Simulation testing** means those controlled decisions are varied intentionally to explore adverse schedules and failures.
- **Replay** means a previous decision log is consumed to reproduce a run.
- **Branching** means replaying to a recorded moment and then exploring a different deterministic suffix from that point.
- **Host capture** means explicitly permitted host I/O is recorded for exact replay.

A decision policy is deterministic logic that uses the seed, current simulated state, and configuration to choose what happens next: which task runs, whether a packet is dropped, how long an operation takes, or whether a filesystem fault occurs.

A seed alone is enough when code, runtime, drivers, decision policies, and configuration are unchanged and all effects remain inside deterministic drivers. Patina still records traces as they are debuggable, shareable, minimizable, robust against decision-policy changes, and useful for exploring around an observed failure.

Trace replay is tied to the build and environment that produced it. Patina traces include the seed, decision-policy metadata, decision logs, branch relationships, and compatibility fingerprints for the binary, crate graph, compiler, target, runtime, drivers, and configuration. Mismatches are errors by default.

Replay of real external I/O is useful, but narrower than simulation. It reproduces one observed execution. If a run replays captured host I/O and then reaches an unrecorded host effect, Patina fails by default instead of recording from a host whose state may not match the replayed prefix. Open-ended exploration requires deterministic drivers for those external resources.

## Fail-closed boundary

Patina prefers explicit failure over silent nondeterminism.

Unsupported effects are pre-run refusals when they can be detected statically (the default-deny import audit and instruction scan) and loud runtime errors otherwise. Examples include:

- unsupported FFI and un-interposed host symbols;
- inline assembly that reads clocks or entropy;
- native thread operations not routed through the scheduler;
- host filesystem or network access without explicit policy;
- CPU instructions such as `rdtsc` or `rdrand` when not virtualized.

Raw inline syscalls follow the same rule with one deepening: where the platform allows it (syscall-user-dispatch on x86_64 Linux), they are trapped *into* the deterministic runtime instead of refused; everywhere else they remain a refusal. Either way, never a silent escape.

`cfg(patina)` and `cfg(dst)` exist as escape hatches for code that genuinely needs deterministic replacements, but they are secondary mechanisms. The primary mechanism is the deterministic platform boundary.

## Code-first topology, small runtime config

Patina avoids large declarative configuration languages for service topology. Runtime configuration controls experiment-level concerns: seeds, budgets, trace paths, record/replay modes, selected named profiles, and simple parameters.

Typed Rust code configures driver-specific behavior:

- virtual network routes;
- fake HTTP services;
- filesystem mounts;
- crash semantics;
- invariants;
- domain-specific models.

This keeps the core ABI small and lets concrete drivers expose rich APIs without polluting the common interface. It also keeps service topology type-checked and modular: one simulated network can expose routing APIs, while another network driver may expose different ones.

## Trade-offs

Patina chooses a Rust/toolchain boundary over a hypervisor boundary. This makes the system more integrated with Rust and easier to expose through Cargo, but less universal than a VM.

Patina chooses code-first topology over configuration-first topology. This preserves type safety and modularity, but means some scenario changes require recompilation.

Patina chooses fail-closed enforcement over permissive fallback. This makes early adoption less frictionless, but prevents false confidence.

Patina chooses pluggable drivers over one canonical simulation model. This keeps Patina useful across storage systems, distributed systems, CLIs, servers, and libraries, but places responsibility on driver authors to model the right semantics.

## Design principles

1. **The boundary is below the application.** Application code should not carry most of the testing burden.
2. **Every source of nondeterminism is accounted for.** It is seeded, simulated, replayed, recorded, or rejected.
3. **Core interfaces stay minimal.** Driver-specific capabilities belong on concrete builders and extension crates.
4. **Topology is code.** Rich service and environment behavior is expressed in Rust, not sprawling config.
5. **Experiments are externally controlled.** Seeds, traces, replay policies, and budgets are CLI/runtime concerns.
6. **Unsupported effects fail loudly.** Patina does not silently fall back to the host OS.
7. **Rust comes first.** Native ABI compatibility extends the system but does not define it.
8. **The shim's own host access is invisible to the guest.** The interposition layer reaches real host primitives by private, resolved-at-runtime aliases, never by naming a symbol the guest could import; allowing the shim its vehicle must never grant the guest an escape. A guest is judged on what it can reach, not on a name the shim happens to share.
9. **Output is progressively disclosed.** Every output surface — human or machine — leads with an index (counts, classes, summaries) and offers detail on demand (a flag, a per-item command, a named on-disk artifact). Aggregation is lossless: the summary always says where the full detail lives, and nothing becomes unreachable. Firehoses are opt-in, never the default; consumers (especially agents) should be able to triage from the index alone.

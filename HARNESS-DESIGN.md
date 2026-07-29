# Patina SDK, harness, and explicit-context design

Status: design proposal. This document describes intended crate/API boundaries for
an implementer. It does not describe behavior that is fully implemented today.

## Problem

The current `patina-dst` crate combines two different ideas:

1. a production-safe cooperative-SUT SDK (`buggify!`, `always!`, `sometimes!`,
   `rng()`, lifecycle markers), available with default features; and
2. an explicit `runtime` feature exposing `run`, `run_with`, `Context`,
   `RuntimeBuilder`, async `rt`, and ABI types.

That second surface is easy to misread as "the way users run applications under
Patina." It is not. Today, `patina_dst::run` creates a private `Context`; ordinary
`std::fs`, `std::net`, clock, thread, and other platform calls in the rest of the
application do not automatically use that context. The native shim and WASI host
instead use a process/global runtime context installed by the Patina build/run
path.

This creates confusing ergonomics:

- production code should be able to depend on the SDK without linking the runtime;
- application harnesses should be able to configure Patina and then run normal
  application code through the same shims/interposers as transparent runs;
- the low-level explicit `Context` API is still useful, but it should not be
  presented as the main application harness API.

## Goals

1. Keep the SDK dependency-light and safe for production builds.
2. Provide a user-facing harness crate for tests/simulations that configure
   Patina and then call normal application code while ordinary platform effects
   are interposed by the native shim or WASI host.
3. Ensure a harness uses exactly the same runtime context as the shims. There
   must not be one context for explicit calls and another for `std` calls.
4. Make execution requirements clear: a shim-backed harness must run through a
   Patina build/run path, not plain `cargo run`.
5. Preserve fail-closed behavior. If a harness expects Patina but no shim/global
   runtime is installed, it must fail loudly instead of running against the host.
6. Reframe the current explicit `Context` surface as a lower-level simulator API,
   not the primary way to run ordinary applications.

## Non-goals

- Do not make the SDK's default dependency graph include the explicit runtime.
- Do not silently fall back to host effects when a Patina harness is run without
  Patina.
- Do not make hidden Cargo feature injection the primary ergonomic solution.
- Do not introduce two live runtime contexts in one process.
- Do not solve unsupported transparent surfaces here, such as third-party native
  async-runtime interposition or unmodeled host APIs.
- Do not require heavyweight standalone testbeds to work for ordinary local
  development of this API.

## Usage modes

### 1. SDK-only transparent application code

Production code can depend on `patina-dst` with default features and use SDK
markers directly:

```rust
if patina_dst::buggify!("drop-after-write") {
    // rare, seed-deterministic path under Patina; false outside Patina
}
patina_dst::always!(state.is_valid(), "state-valid");
std::fs::write("state", b"value")?;
```

Normal production builds do not link the explicit runtime. Under `cargo patina
build/run`, the native shim or WASI host supplies the deterministic runtime below
ordinary application code.

### 2. Shim-backed harness for normal application code

A harness configures Patina and then calls normal application code:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    patina_dst_harness::run_with(
        |harness| {
            harness
                .net_topology(/* ... */)
                .fault_policy(/* ... */)
                .scheduler_policy(/* ... */)
        },
        || my_app::run(),
    )?;
    Ok(())
}
```

The application body may use ordinary `std::fs`, `std::net`, clocks, threads, and
SDK markers. Those effects are controlled by Patina because the harness binary is
built and run through Patina's native shim or WASI host.

This is the main user-facing API for "configure the test context, then drive my
real application."

### 3. Explicit-context simulator code

Some tests and examples intentionally call Patina's virtual APIs directly:

```rust
patina_dst_context::run(|ctx| {
    ctx.write_file("/state/value", b"value")?;
    ctx.sleep_for(1_000_000)?;
    Ok(())
})
```

This is useful for core driver tests, small simulator-native examples, and
low-level experiments. It does not make unrelated `std` calls use the same
context. It should be documented as a separate, advanced API.

## Proposed crate boundaries

### `patina-dst`

Production-safe SDK crate.

Responsibilities:

- SDK macros and helpers: `buggify!`, `buggify_with_prob!`, `buggify_delay!`,
  `buggify_knob!`, `always!`, `sometimes!`, `reachable!`, `rng()`,
  `is_simulated()`, lifecycle markers.
- Default features remain dependency-light.
- Bridges to the native shim or WASI host under Patina cfgs.
- No explicit `Context` harness API in the default surface.

### `patina-dst-harness`

User-facing shim/global harness crate.

Responsibilities:

- Configure the same process/global runtime context used by native/WASI shims.
- Run a user closure that calls ordinary application code.
- Finalize/report the run explicitly when possible, while remaining compatible
  with the existing `atexit` finalizer for normal exits.
- Fail loudly when not running under a compatible Patina build/run path.
- Avoid exposing a separate private `Context` in the first API. Configuration
  should be through a builder/spec, not through direct effect calls.

This crate is for integration tests, simulation binaries, and application
harnesses. It is not required by production binaries that only carry SDK markers.

### `patina-dst-context` (optional public crate)

Lower-level explicit-context simulator facade.

Responsibilities:

- Own the current `patina-dst` `runtime` feature surface if it remains public:
  `run`, `run_with`, `Context`, `RuntimeBuilder`, `RuntimeConfig`, async `rt`,
  and selected ABI types.
- Be named and documented so users understand it creates/uses an explicit
  context. It is not the transparent shim harness.

If this surface is only needed internally, it can remain as crate-internal tests
and helper APIs instead of becoming a prominent public crate. If it is public,
`patina-dst-context` is a clearer name than `runtime` because it describes the
programming model.

### `patina-dst-runtime`

Low-level runtime implementation crate.

Responsibilities:

- Continue to own core runtime types and mechanics: `Context`, drivers, record,
  replay, branch, metadata reconciliation, scheduling, faults.
- Serve as an implementation dependency of the native shim, WASI host, harness,
  and optional explicit-context facade.
- Not be the primary user-facing application harness API by itself.

## Harness execution model

A shim-backed harness must be run through Patina, not plain Cargo:

```sh
cargo patina run path/to/harness/Cargo.toml --target native --seed 123
cargo patina run path/to/harness/Cargo.toml --target native --record trace.patina
cargo patina replay path/to/harness/Cargo.toml trace.patina --target native
```

Plain `cargo run` should not silently execute the harness against host effects.
The harness crate should return a clear error such as `NotUnderPatina` or
`NoInstalledRuntime`.

The current cargo-family `cargo patina test` path is not enough by itself if it
only forwards environment/RUSTFLAGS and does not link the native shim. Either use
the source-first native build/run path, or extend `cargo patina test --target
native` to build tests through the same shim pipeline before advertising harness
use in test binaries.

## Harness API sketch

The exact names can change, but the first stable shape should keep a clear
separation between configuration and application execution:

```rust
pub fn run<E>(entry: impl FnOnce() -> Result<(), E>) -> Result<(), HarnessError>
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>;

pub fn run_with<E>(
    configure: impl FnOnce(HarnessBuilder) -> Result<HarnessBuilder, HarnessError>,
    entry: impl FnOnce() -> Result<(), E>,
) -> Result<(), HarnessError>
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>;
```

`HarnessBuilder` should describe desired runtime configuration without granting a
second effect context. Candidate configuration areas:

- scheduler policy: default, PCT, starvation, liveness watchdog;
- fault policy: filesystem crash point/torn granularity, sleep/network jitter,
  packet drop, buggify activation/firing;
- virtual network topology and socket configuration;
- initial virtual filesystem image or synthetic files;
- resource limits and replay-reconciliation policy;
- output/report controls.

CLI and trace metadata remain authoritative for record/replay identity. If a
harness configuration conflicts with a replay trace, the run must fail closed.

## Runtime ownership rules

1. There is one process/global runtime context for a shimmed run.
2. Interposed `std`/POSIX/WASI operations and SDK markers use that same context.
3. `patina-dst-harness` configures or installs that same context before the
   application body starts.
4. If any deterministic boundary operation has already occurred before the
   harness configures the context, configuration must fail. Replacing drivers
   after events have been recorded would make replay semantics ambiguous.
5. The harness should finalize the context after the application closure returns.
   The existing native `atexit` path remains a backup/idempotent finalizer for
   ordinary `main` return and explicit `exit` paths.

## Native startup implementation concern

Today the packaged native constructor captures the `PATINA_*` control plane,
initializes the runtime when `PATINA_MODE` is present, registers finalization,
and scrubs the guest environment before `main` runs.

That means the harness cannot simply construct a private context in `main` and
expect interposers to use it. Implement one of these patterns:

### Option A: reconfigure-before-first-boundary

- Keep constructor initialization as-is.
- Add a native-shim ABI for `patina-dst-harness` to apply a `HarnessConfig` to
  the installed context before the first deterministic boundary operation.
- Track whether any boundary event has occurred. If yes, reconfiguration fails.
- This avoids a new CLI mode but needs careful replacement/reconciliation logic.

### Option B: deferred harness initialization

- Add a control-plane flag such as `PATINA_DEFER_INIT=1`, set by a future
  `cargo patina run --harness` or equivalent source-first harness mode.
- The constructor captures/scrubs the control plane and registers finalization,
  but does not install the context.
- `patina-dst-harness::run_with` builds and installs the global context, then
  calls the application closure.
- If any interposed effect occurs before installation, it fails closed.

Option B gives the harness cleaner ownership of setup. Option A may be easier to
fit into the current CLI. Either way, the harness must configure the same global
context the shims use.

## What to do with the current `runtime` feature

The current `patina-dst/runtime` feature should not be the main user path for
ordinary applications. It is an explicit-context API.

Recommended migration:

1. Introduce `patina-dst-harness` for shim/global harnesses.
2. Move examples that are meant to demonstrate explicit `Context` effects either
   to `patina-dst-context` or label them as low-level explicit-context examples.
3. Move or re-export the current `runtime` feature surface through
   `patina-dst-context` if it remains public.
4. Keep `patina-dst/runtime` temporarily as a compatibility re-export, with docs
   that direct application harness users to `patina-dst-harness` instead.
5. Avoid adding hidden automatic runtime-feature injection to `cargo-patina` as
   the main fix. It solves the wrong problem: application harnesses should use
   the shim/global runtime, not a private explicit context.

## Validation gates for an implementation

A minimal implementation of `patina-dst-harness` should prove:

1. Plain `cargo run` of a harness fails loudly before running application code
   against host effects.
2. `cargo patina run <harness> --target native` succeeds and ordinary
   `std::fs`, clocks, entropy, threads, and supported networking are interposed.
3. A harness-configured option affects the same operations observed through
   ordinary application code. For example, configured virtual filesystem state is
   read through `std::fs`, or configured packet policy affects `std::net`.
4. Record/replay is byte-identical for a harness-driven application.
5. Replaying with conflicting harness configuration fails closed.
6. Attempting to configure after a boundary operation fails closed.
7. `patina-dst` default-feature builds remain dependency-light and do not link
   the explicit runtime for SDK-only users.
8. The low-level explicit-context API, if retained publicly, is tested separately
   and documented as not controlling unrelated `std` calls.

## Open questions

- Should the CLI grow an explicit `cargo patina harness` or `cargo patina run
  --harness` mode to set deferred initialization, or should the first version use
  reconfigure-before-first-boundary?
- Should shimmed Rust test binaries be supported through `cargo patina test
  --target native`, or should harnesses initially be ordinary binaries/examples?
- Which harness configuration belongs in code versus CLI flags? CLI/trace inputs
  should remain visible and fingerprinted; code configuration is useful for
  topology and app-specific fixtures.
- Should in-process host fixture capture be supported, or should host directory
  capture remain a supervisor/CLI concern via `--mount`?
- How much of the current explicit-context API should remain public after the
  shim-backed harness exists?

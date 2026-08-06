# Patina usage modes

Patina supports three ways for code to meet the deterministic runtime. They are
separable adoption levels of one system: every mode drives the same
process-global runtime context, the same seed/config surface, and the same
record/replay machinery. A workspace can mix them (an SDK-instrumented library
inside a harness-configured binary is the expected shape).

| You want to… | Mode | Crate |
|---|---|---|
| instrument application code with fault sites and oracles, shipped inert | 1 — SDK-only | `patina-dst` |
| configure a run in code, then execute ordinary `std` code under full interposition | 2 — harness | `patina-dst-harness` |
| write simulator/test code that owns its world through an explicit context | 3 — explicit context | `patina-dst-runtime` (+ `patina-dst-async`) |

## 1. SDK-only transparent application code — `patina-dst`

Ordinary application code instrumented with the cooperative-SUT SDK:
`buggify!`/`buggify_with_prob!`/`buggify_delay!`/`buggify_knob!` fault sites,
`always!`/`sometimes!`/`reachable!` oracles, the `lifecycle` markers
(`setup_complete()`, `event!`), and `patina_dst::rng()`/`is_simulated()`. The
crate is dependency-free by default; every macro is a no-op or plain fallback
outside a Patina build, so adopters ship it unconditionally with no `cfg(patina)`
in their code. The default-off `macros` feature re-exports
`#[patina_dst::test]` for dev-dependency use: plain `cargo test` discovers
`cargo-patina` through `PATINA_CLI` or `PATH`, then rebuilds the same libtest
target shim-linked and runs the annotated body under the native harness. The
runtime otherwise enters through `cargo patina build`/`run` (the shim),
`cargo patina test <DIR|Cargo.toml> --harness-target NAME --exact MOD::test`
(the source-first native libtest harness for one point-solution test), or
`build --target wasi` (the `patina_sdk` host imports), or not at all.

Native startup has one important adopter rule: static constructors (`#[ctor]`,
link-section constructors, C++ global constructors) must not perform interposed
Patina effects. They can run before the shim's own startup constructor has
installed the deterministic runtime, so effectful APIs fail closed with a
ctor-specific diagnostic (pre-startup `getenv` is hidden and returns NULL rather
than reading host state; a pre-startup `setenv` gets no such exception and takes
the abort, since a dropped write would desynchronize the guest's view of the
environment for the whole run). Gate such constructors out of DST builds (for example
`#[cfg(not(patina))]` / `#[cfg(not(dst))]`) and move environment/logging/filesystem
setup into `main` or the harness closure.

## 2. Shim-backed harness for normal application code — `patina-dst-harness`

A harness binary configures the run in code, then executes ordinary application
code under the full shim interposition surface:

```rust
patina_dst_harness::run_with(
    |harness| Ok(harness.step_budget(1_000_000).net_drop_permille(30)),
    || app_main(), // ordinary std code; returns Result<(), E>
)
```

Built and run through `cargo patina build` / `cargo patina run --harness`
(replays of harness binaries also need `--harness`). Startup is *Option B:
deferred init* (the name code comments reference): the flag sets
`PATINA_DEFER_INIT=1`, the shim's C constructor still
captures the control plane, registers finalization, and scrubs the
environment, but leaves the runtime uninstalled; `patina_harness_install`
applies the harness configuration as a control-plane overlay and installs
through the same parsers `cargo patina run` uses, so there is no second config
surface and no new fingerprint component. Fail-closed edges: an interposed
effect before install aborts loudly (the runtime never auto-inits under
defer); install after an effect boundary, double install, or running the
binary outside `cargo patina run` are each distinct loud errors.
Fingerprinted knobs (buggify, schedule exploration, fault families) work from
the harness for seeded runs but need the matching CLI flag on record/replay.

The harness can also name services: `dns_service(name)` allocates a virtual
address and inserts the DNS host-table entry, while `dns_entry(name, addr)` pins
a name explicitly. Application code then resolves the name through plain `std`,
and a server binding `0.0.0.0:PORT` receives traffic addressed to any address on
that port, so the service body stays ordinary `INADDR_ANY` code. That is one
host-table entry per name, not a topology model — network topology stays out of
scope for v1.

Application code may spawn threads: they become managed tasks on the same
deterministic scheduler as under a transparent run, so a service's listener can
run on its own thread inside the closure. The deterministic body ends when the
closure returns, exactly as it ends when `main` returns under the supervisor —
a worker still running at that point is cut off there.

## 3. Explicit-context simulator code — `patina-dst-runtime`

Simulator-shaped code that owns its world: `run`/`run_with` build a `Context`
(seeded RNG, virtual clock, deterministic FS, SimNet) and the code performs
effects through it explicitly. Nothing is interposed — `std` calls made by the
same program do not go through Patina — so this mode is for tests and
simulators written against the runtime API, not for running unmodified
programs. Ordinary code called from this mode may be tested as-is only while it
stays deterministic from the simulator's inputs. If that code internally opens
host sockets/files, reads host time or randomness, spawns real threads whose
schedule matters, calls tokio's reactor, or reaches FFI/syscalls, those effects
are outside the explicit `Context`; refactor them behind injected interfaces or
use the shim/harness mode instead. `patina-dst-async` layers the deterministic
futures executor (`block_on`, `spawn`, virtual-time timers, TCP/UDP futures)
over the same `Context`.

A user-facing example is `testbeds/checkout-retry-idempotency`: ordinary
checkout ledger code is called from an explicit-context virtual client/service
simulation. The virtual network latency and virtual client timeout force a
retry, and the test asserts that the idempotency key prevents a duplicate
charge. That is the intended shape for mode 3: model a small world around a
component or protocol when the whole application is not the thing under test.

## Crate map

Package names are `patina-dst-*`; the workspace directories drop the `-dst-`
(e.g. `crates/patina-runtime`). See ARCHITECTURE.md for the full layout.

| Crate | Directory | Role |
|---|---|---|
| `patina-dst` | `crates/patina` | mode-1 SDK; dependency-free by default; used as `patina_dst::` |
| `patina-dst-macros` | `crates/patina-macros` | default-off `#[patina_dst::test]` proc macro; no external deps |
| `patina-dst-harness` | `crates/patina-harness` | mode-2 configure-then-run harness (deps: `patina-dst-runtime`, `serde_json`) |
| `patina-dst-runtime` | `crates/patina-runtime` | mode-3 explicit-context API; also the runtime every other mode drives |
| `patina-dst-async` | `crates/patina-async` | explicit-boundary futures executor over mode 3 |

There is no separate context crate and no compatibility re-exports: mode-3
symbols live in `patina-dst-runtime` directly.

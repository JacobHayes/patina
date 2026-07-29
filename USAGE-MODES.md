# Patina usage modes

Patina supports three ways for code to meet the deterministic runtime. They are
separable adoption levels of one system: every mode drives the same
process-global runtime context, the same seed/config surface, and the same
record/replay machinery. A workspace can mix them (an SDK-instrumented library
inside a harness-configured binary is the expected shape).

## 1. SDK-only transparent application code — `patina-dst`

Ordinary application code instrumented with the cooperative-SUT SDK:
`buggify!`/`buggify_with_prob!`/`buggify_delay!`/`buggify_knob!` fault sites,
`always!`/`sometimes!`/`reachable!` oracles, `patina_dst::rng()`. The crate is
dependency-free; every macro is a no-op or plain fallback outside a Patina
build, so adopters ship it unconditionally with no `cfg(patina)` in their code.
The runtime enters through `cargo patina build`/`run` (the shim), or not at all.

## 2. Shim-backed harness for normal application code — `patina-dst-harness`

A harness binary configures the run in code, then executes ordinary application
code under the full shim interposition surface:

```rust
patina_dst_harness::run_with(
    |harness| harness.step_budget(1_000_000).net_drop_permille(30),
    || app_main(),
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

## 3. Explicit-context simulator code — `patina-dst-runtime`

Simulator-shaped code that owns its world: `run`/`run_with` build a `Context`
(seeded RNG, virtual clock, deterministic FS, SimNet) and the code performs
effects through it explicitly. Nothing is interposed — `std` calls made by the
same program do not go through Patina — so this mode is for tests and
simulators written against the runtime API, not for running unmodified
programs. `patina-dst-async` layers the deterministic futures executor over
the same `Context`.

## Crate map

| Crate | Role |
|---|---|
| `patina-dst` | mode-1 SDK; dependency-free |
| `patina-dst-harness` | mode-2 configure-then-run harness (deps: `patina-dst-runtime`, `serde_json`) |
| `patina-dst-runtime` | mode-3 explicit-context API; also the runtime every other mode drives |
| `patina-dst-async` | explicit-boundary futures executor over mode 3 |

There is no separate context crate and no compatibility re-exports: mode-3
symbols live in `patina-dst-runtime` directly.

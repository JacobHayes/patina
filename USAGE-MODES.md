# Patina usage modes

Patina runs a program interposed: its `std` (and libc) effects go through the
deterministic runtime, whether the artifact is a prebuilt binary or a package
path `cargo patina run` builds on the fly. Code meets that runtime in two ways.
They are separable adoption levels of one system: both drive the same
process-global runtime context, the same seed/config surface, and the same
record/replay machinery. A workspace can mix them (an SDK-instrumented library
inside a harness-configured binary is the expected shape).

| You want to… | Mode | Crate |
|---|---|---|
| instrument application code with fault sites, oracles and run parameters, shipped inert | 1 — SDK-only | `patina-dst` |
| configure a run in code, then execute ordinary `std` code under full interposition | 2 — harness | `patina-dst-harness` |

## 1. SDK-only transparent application code — `patina-dst`

Ordinary application code instrumented with the cooperative-SUT SDK:
`buggify!`/`buggify_with_prob!`/`buggify_delay!`/`buggify_knob!` fault sites,
`always!`/`sometimes!`/`reachable!` oracles, `verdict()` for structured run
outcomes, the `lifecycle` markers (`setup_complete()`, `event!`),
`patina_dst::param()` run parameters, `patina_dst::rng()`/`is_simulated()`, and
`custom_op`/`custom_op_faultable` to route an unmodeled effect (RPC, S3, a
device) through Patina so it is recorded, replayed, and optionally faulted. The
crate links no runtime and depends only on serde for typed custom ops; every
macro is a no-op or plain fallback
outside a Patina build, so adopters ship it unconditionally with no `cfg(patina)`
in their code. The default-off `macros` feature re-exports
`#[patina_dst::test]` for dev-dependency use: plain `cargo test` discovers
`cargo-patina` through `PATINA_CLI` or `PATH`, then rebuilds the same libtest
target shim-linked and runs the annotated body under the native harness. The
runtime otherwise enters through `cargo patina build`/`run` (the shim),
`cargo patina test <DIR|Cargo.toml> --harness-target NAME --exact MOD::test`
(the source-first native libtest harness for one point-solution test), or not
at all.

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

### Go guests

Go code uses the Go SDK, `github.com/JacobHayes/patina/go/patina` (`go/patina`,
no dependencies). Go has no macros and cannot emit the link-time site table, so
a site is a value declared once at package level, which declares it to the
run (at its `file:line`) before `main`, through the shim's
`patina_declare_site`:

```go
var sorted = patina.Always("ledger-sorted")
var retried = patina.Sometimes("request-retried")

func settle(l []int) { sorted.Check(slices.IsSorted(l)) }
```

Under Patina, `Always`, `Sometimes` and `Reachable` sites, `IsSimulated`, `Rng`
and `Param` behave as their Rust counterparts do. `cargo patina build --go` adds the `patina`
build tag, which links them to the shim; any other build gets inert stand-ins
with no cgo, so code ships the SDK unconditionally.

### Native startup environment

Use `cargo patina run --env KEY=VALUE` to supply a native guest's startup map.
The supervisor reserves initial-stack space before exec; the shim publishes the
map there so an argv-based environment walk, `main`'s envp and `environ` agree.
Replay restores the map and its reservation from the trace without resupplying
flags. The platform trailer remains available after envp's NULL (ELF auxv on
Linux, the apple-string vector on Darwin).

A direct native `PATINA_RT_*` protocol launch without the supervisor's reservation
may only start with an empty deterministic map. A nonempty map aborts at startup
with the named `unreserved initial-stack environment` refusal; use the supervisor
rather than publishing a map only through `environ`. Direct empty-map launches
still scrub the host environment but do not support argv → envp → trailer
traversal. A deferred harness starts empty, and its later runtime installation
replaces `environ` normally without rebuilding the initial stack.

## 2. Shim-backed harness for normal application code — `patina-dst-harness`

A harness binary configures the run in code, then executes ordinary application
code under the full shim interposition surface:

```rust
patina_dst_harness::run_with(
    |harness| Ok(harness.step_budget(1_000_000).net_drop_permille(30)),
    || app_main(), // ordinary std code; returns Result<(), E>
)
```

Built and run through `cargo patina build` / `cargo patina run`; replays and
campaigns need no flag. A harness binary carries a `PATINA_HARNESS_V1` marker
(the same pattern as `PATINA_INSTRUMENTED_V1`), and the supervisor sets
`PATINA_RT_DEFER_INIT=1` when it finds it. Startup is *Option B:
deferred init* (the name code comments reference): the shim's startup
constructor still captures the control plane, registers finalization, and
scrubs the environment, but leaves the runtime uninstalled;
`patina_harness_install` applies the harness configuration as a control-plane
overlay and installs through the same parsers `cargo patina run` uses, so there
is no second config surface. The runtime computes the fingerprint's policy
suffix (`+buggify`, `+pct`, `+swarm`, `+yieldstride`) from the configuration it
installed, so knobs set in the harness record and replay without matching CLI
flags. Fail-closed edges: an interposed
effect before install aborts loudly (the runtime never auto-inits under
defer); install after an effect boundary, double install, or running the
binary outside `cargo patina run` are each distinct loud errors.

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

## Run parameters

A run parameter is a named input the program reads through
`patina_dst::param(key) -> Option<String>`: `None` outside Patina, so the
lookup ships inert like the rest of the SDK. Supply one with
`cargo patina run --param KEY=VALUE` (or `test --param`, which forwards it to
every seed's run); a harness's `.param(key, value)` sets a default the CLI value
overrides for the same key. The run records the merged set in its trace and a
replay restores it, so `replay` takes no `--param`. A parameter is not a
fingerprint input: the recorded operation stream already reflects it.

`cargo patina minimize --params -- cargo patina run <BINARY> --param K=V ...`
reduces a failing run's parameters: it drops and shrinks them while the run
keeps failing the way the original did, and prints the reduced command.

## Crate map

Package names are `patina-dst-*`; the workspace directories drop the `-dst-`
(e.g. `crates/patina-runtime`). See ARCHITECTURE.md for the full layout.

| Crate | Directory | Role |
|---|---|---|
| `patina-dst` | `crates/patina` | mode-1 SDK; depends only on serde/serde_json; used as `patina_dst::` |
| `patina-dst-macros` | `crates/patina-macros` | default-off `#[patina_dst::test]` proc macro; no external deps |
| `patina-dst-harness` | `crates/patina-harness` | mode-2 configure-then-run harness (deps: `patina-dst-runtime`, `serde_json`) |
| `patina-dst-runtime` | `crates/patina-runtime` | the deterministic runtime both modes drive (through the native shim) |
| Go SDK (Go module) | `go/patina` | mode-1 SDK for Go guests; no dependencies; shim-backed under the `patina` build tag |

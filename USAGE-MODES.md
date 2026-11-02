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

Under Patina the Go SDK, and the Python SDK (see Python guests below), lower to
the same shim entry points as the Rust one, and each piece behaves as its Rust
counterpart does:

| Rust (`patina-dst`) | Go (`go/patina`) | Python (`patina`) |
|---|---|---|
| `always!` / `sometimes!` / `reachable!`, and their `*_family!` | `Always(l).Check(cond, detail...)` / `Sometimes(l).Check(cond)` / `Reachable(l).Mark()`: every declared site is a family, and an `Always` detail names the failing instance in its violation verdict | `Always(l).check(cond, detail)` / `Sometimes(l).check(cond)` / `Reachable(l).mark()`, families alike |
| `buggify!` / `buggify_with_prob!` | `Buggify(l).Fires()` / `.FiresWithProb(p)` | `Buggify(l).fires()` / `.fires(p)` |
| `buggify_delay!` / `buggify_knob!` | `BuggifyDelay(l).Delay()` / `Knob(l, def, lo, hi).Value()` | `BuggifyDelay(l).delay()` / `Knob(l, default, low, high).value()` |
| `verdict`, `VerdictKind` | `Verdict(kind, label, detail)`, `Violation`/`Pass`/`AbortIntent` | `verdict(kind, label, detail)`, `Verdict.VIOLATION`/`PASS`/`ABORT_INTENT` |
| `custom_op_bytes[_faultable]` | `CustomOpBytes` / `CustomOpBytesFaultable` | `custom_op_bytes(label, key, perform, on_fault=None)` |
| `custom_op[_faultable]` (serde JSON) | `CustomOp[T]` / `CustomOpFaultable[T]` (`encoding/json`) | `custom_op(label, key, perform, on_fault=None)` (`json`, keys sorted) |
| `lifecycle::setup_complete`, `lifecycle::event!` | `SetupComplete()`, `LifecycleEvent(label)` | `setup_complete()`, `lifecycle_event(label)` |
| `is_simulated`, `rng`, `param` | `IsSimulated`, `Rng`, `Param` | `is_simulated()`, `rng()`, `param(key)` (None when absent) |
| `#[patina_dst::test]` | none: a Go DST target is a main package, or a package's test binary (`build --go --go-test`), swept with `cargo patina run`/`campaign` | none: a Python DST target is an application, swept with `cargo patina run`/`campaign` |

`cargo patina build --go` adds the `patina` build tag, which links them to the
shim; any other build gets inert stand-ins with no cgo, so code ships the SDK
unconditionally. Keep a guest's own assertion wrappers inert natively the same
way, behind the `patina` tag. Put an expensive observer (one that re-walks a
tree or snapshots state to check an assertion) behind a separate tag that the
`patina` tag implies, such as `//go:build patina || myapp_observe`: every Patina
build carries it, and a native build opts in. A guest's own `-tags` pass through
`build --go`.

### Python guests

`cargo patina build app.py --python --output app` (or a directory with a
`__main__.py`) builds a Python application as a native guest, on Linux
(x86_64 and aarch64; on macOS CPython reaches C library calls the shim does
not yet model on Darwin, so the build refuses). Patina builds
CPython statically by its own recipe, from the pinned release (fetched once,
checked against its digest and cached with its build) or the
`--python-source` tarball or tree, and freezes the standard library and the
application into the executable: the interpreter imports nothing from a
filesystem and ignores the environment, so a run imports the same code
everywhere. Arguments after `--` on `run` are `sys.argv[1:]`.

Third-party pure-Python packages come in with `--python-path DIR`, once per
root, earlier roots shadowing later ones as on `sys.path`; a virtualenv's
dependencies are its site-packages directory:

```sh
cargo patina build app/ --python --python-path .venv/lib/python3.14/site-packages --output app
```

A directory without an `__init__.py` is a namespace package. What a Python
guest does not have: extension modules (a compiled module under a root refuses
the build, by name), package data (files beside the modules are not carried),
`ssl` (the recipe builds no TLS library), and child processes (`subprocess`
and `os.fork` stop the run with the process refusal). The `hashlib` digests
are CPython's built-in HACL\* implementations, and `zlib` (with `gzip`,
`zipfile` and `tarfile` compression) is the pinned zlib release, fetched and
digest-checked as CPython's is, built into the interpreter.

Python code uses the Python SDK, the `patina` package, which every Python guest
has (frozen beneath the application's roots, so a `patina` of the
application's own shadows it), over `_patina`, the interpreter's builtin
binding to the shim. Sites are values declared once at module level, which
declares them to the run at their `file:line`; the table under Go guests maps
each piece to its Rust and Go counterpart:

```python
import patina

ordered = patina.Always("ledger-sorted")
retried = patina.Sometimes("request-retried")

def settle(ledger):
    ordered.check(ledger == sorted(ledger), f"ledger={ledger}")
```

Under plain Python, with `crates/cargo-patina/python/sdk` on the path, the
package is inert: no site fires, a check returns its condition, a knob its
default, `rng()` draws a fixed-seed stream and a custom op just performs.

A custom op's `perform` runs on the record pass and not on its replay, so the
interpreter's compute meter is held across it: its computation takes no
scheduling point and charges no virtual time, and both passes leave the op
with the meter restarted at a full stride. Before the op begins, the thread
hands the interpreter lock to any thread waiting for it, so the handover never
falls inside the op, where modeled synchronization is refused. Interpreter
teardown runs unmetered too.

Tracked gap: the meter counts CPython's own comparisons, and `perform` changes
interpreter state the replay never does (its allocations, the caches and
specializations it warms), so the code after an op can count a few
comparisons differently on the two passes. Restarting at a full stride makes
that unlikely to move a scheduling point, but it can, and the replay then
stops with a yield-point divergence rather than run a different schedule. A
`perform` that does little in Python (one call out, its result returned) is
the least exposed. The cure is a meter that counts the program's own control
flow rather than the interpreter's comparisons.

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
| Python SDK (package) | `crates/cargo-patina/python/sdk` | mode-1 SDK for Python guests; the `patina` package every Python guest has, over the builtin `_patina`; inert under plain Python |

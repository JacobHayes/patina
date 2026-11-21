# SDK: assertions and fault points in Rust, C, Go and Python

Without the SDK, Patina finds what makes a program exit nonzero, die, hang or deadlock, and what
a `--check` script sees. The SDK adds invariants checked where they hold, fault points in the
program's own rare paths, and marks. It is one reserved system call: outside Patina it fails at
once and every call is a load and a branch, so it ships in production builds without flags.

| Language | Add |
|---|---|
| Rust | `patina-dst = { git = "https://github.com/JacobHayes/patina", tag = "vX.Y.Z" }` in `Cargo.toml` (Rust 1.85 or later) |
| C, C++ | `#include "patina.h"`, one header: `cc -I PATINA/sdk/c` |
| Go | `go get github.com/JacobHayes/patina/go/patina@vX.Y.Z`, pure Go |
| Python | `sdk/python/patina.py`, one file: copy it beside the program or put its directory on `PYTHONPATH` |

Use the tag of the installed version (`patina --version`). Rust and C check a literal label at
each call site; Go and Python declare a site once and call its method:

| Call | Rust | C | Go | Python |
|---|---|---|---|---|
| always | `always!(c, "l", ...)` | `PATINA_ALWAYS(c, "l", d)` | `Always("l").Check(c, ...)` | `Always("l").check(c, d)` |
| unreachable | `unreachable!("l", ...)` | `PATINA_UNREACHABLE("l", d)` | `Unreachable("l").Reached(...)` | `Unreachable("l").reached(d)` |
| sometimes | `sometimes!(c, "l")` | `PATINA_SOMETIMES(c, "l")` | `Sometimes("l").Check(c)` | `Sometimes("l").check(c)` |
| reachable | `reachable!("l")` | `PATINA_REACHABLE("l")` | `Reachable("l").Hit()` | `Reachable("l").hit()` |
| buggify | `buggify!("l")` | `PATINA_BUGGIFY("l")` | `Buggify("l").Fires()` | `Buggify("l").fires()` |
| knob | `knob!("l", d, lo, hi)` | `PATINA_KNOB("l", d, lo, hi)` | `Knob("l", d, lo, hi).Value()` | `Knob("l", d, lo, hi).value()` |
| delay | `delay!("l", max)` | `PATINA_DELAY("l", ns)` | `Delay("l").Delay(ns)` | `Delay("l").delay(ns)` |
| mark | `mark(s)` | `patina_mark(s)` | `Mark(s)` | `mark(s)` |
| setup, faults done | `setup_complete()`, `faults_done()` | `patina_setup_complete()`, `patina_faults_done()` | `SetupComplete()`, `FaultsDone()` | `setup_complete()`, `faults_done()` |
| control | `control(w)` | `patina_control(w)` | `Control(w)` | `control(w)` |
| under Patina? | `is_simulated()` | `patina_is_simulated()` | `IsSimulated()` | `is_simulated()` |

Rust's are in `patina_dst` (`patina_dst::always!`), Go's in package `patina`, Python's in module
`patina`. In Rust, `violation(label, detail)` is for a label made at run time, and
`always_family!` for one site many callers share.

```rust
patina_dst::always!(ledger.is_sorted(), "ledger-sorted", "after {entry}");
if patina_dst::buggify!("batch-commit") && !ledger.is_empty() { /* the rare path */ }
```

## What each does

- **`always`** must hold and **`unreachable`** must not be reached: either ends the run
  `violation`, named by its label, with the detail as the example.
- **`sometimes`** and **`reachable`** must hold or be reached in at least one run of a sweep,
  or the sweep ends `vacuous`. Put one where the interesting state is (a retry taken, a
  recovery run, a leader changed): a sweep that never got there found nothing there.
- **`buggify`** is a fault point: under `--faults buggify` each point is on in about a quarter
  of the seeds and fires on about a quarter of its evaluations. Take the rare path there (a
  retry, an early timeout, a slow branch) only where the real program can. `--fault
  buggify:LABEL=1000` fires one point at every evaluation; without the class, only the points
  named fire. A point that never fired makes the sweep `vacuous` when that was unlikely: no run
  of 20 or more reached it, or it was reached often enough that it should have fired. In a
  smaller sweep, or after a few evaluations, it is only noted.
- **`knob`** is a seed-chosen value in `lo..hi` under `--faults buggify` (`d` otherwise);
  **`delay`** sleeps a seed-chosen virtual time on drawn evaluations.
- **`mark`** records a label in the run's log, in clear (`mark("ack 17")`): a checker reads it
  from `patina log events` to check a promise was backed (`patina guide checks`).
  `setup_complete()` and `faults_done()` bound when faults act (`patina guide faults`).
- **`control`** is a control call, as `patina ctl` (`patina guide nodes`).

A label is the finding's name, so make it say what broke (`acked-records-kept`). A library's
sites that a program does not reach would make its sweeps `vacuous`: give them a prefix and
allow it once, `--allow-unmet 'lib-*'` or in `patina.toml`:

```toml
[sweep]
allow-unmet = ["lib-*"]
```

A driver that runs one scenario of several gives each scenario's labels a prefix and allows the
others'. Other languages can speak the wire directly: `sdk/c/patina.h` documents it.
